"""App-Fabrik: Middleware, Lebenszyklus, Enrollment-API, Steuerkanal, Weboberfläche."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import rendezvous
from .config import Settings, load_settings
from .control import CLOSE_TOKEN_INVALID, Hub
from .db import Database, Device, Instance, User, audit
from .security import (
    Limiter,
    RateCounter,
    client_ip,
    hash_password,
    needs_rehash,
    new_token,
    normalize_code,
    token_hash,
    verify_password,
)
from . import oidc, web

log = logging.getLogger("roi")
MAX_BODY = 64 * 1024


class EnrollIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    instance_code: str = Field(max_length=32)
    password: str = Field(max_length=256)
    user: str = Field(default="", max_length=64)  # veraltet, wird ignoriert (Kompatibilität mit 1.5.0)
    server_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    server_name: str = Field(default="", max_length=100)
    version: str = Field(default="", max_length=32)


def ensure_admin(db: Database, settings: Settings) -> None:
    """Admin aus den Umgebungsvariablen anlegen bzw. aktualisieren. Es gibt genau einen lokalen Admin.
    OIDC-Benutzer bleiben unberührt."""
    if not settings.admin_user:
        return  # ROI_AUTH_MODES=oidc
    with db.session() as s:
        admins = list(s.scalars(select(User).where(User.is_admin.is_(True), User.auth_source == "local")))
        user = next((u for u in admins if u.username == settings.admin_user), None)
        for other in admins:
            if other is not user:
                s.delete(other)
        if user is None:
            s.add(User(username=settings.admin_user, password_hash=hash_password(settings.admin_password),
                       is_admin=True))
            audit(s, "admin_created", actor="system", user=settings.admin_user)
        elif not verify_password(user.password_hash, settings.admin_password) or needs_rehash(user.password_hash):
            user.password_hash = hash_password(settings.admin_password)
            audit(s, "admin_password_updated", actor="system", user=settings.admin_user)
        s.commit()
    settings.admin_password = None  # nicht länger im Speicher halten als nötig


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.db_url)
    ensure_admin(db, settings)
    hub = Hub(settings, db)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        transports = []
        if settings.rendezvous_enabled:
            transports = await rendezvous.start(settings.rendezvous_bind, settings.rendezvous_ports, hub.responder)
        hub.start()
        try:
            yield
        finally:
            await hub.stop()
            for t in transports:
                t.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    if settings.oidc_active:
        # Nur für state/nonce während der OIDC-Anmeldung. SameSite=Lax, weil der Rücksprung vom
        # Anmeldedienst eine seitenübergreifende Navigation ist; die Admin-Sitzung bleibt Strict.
        app.add_middleware(SessionMiddleware, secret_key=settings.secret_key.decode(),
                           session_cookie="roi_oidc", max_age=600, same_site="lax",
                           https_only=settings.cookie_secure)
    app.state.settings = settings
    app.state.db = db
    app.state.hub = hub
    app.state.login_ip = Limiter(max_failures=10, window=900, lock_seconds=900)
    app.state.login_user = Limiter(max_failures=5, window=900, lock_seconds=900)
    app.state.enroll_ip = Limiter(max_failures=10, window=900, lock_seconds=900)
    app.state.enroll_code = Limiter(max_failures=10, window=900, lock_seconds=900)
    app.state.enroll_rate = RateCounter(limit=20, window=60)

    https = settings.public_url.startswith("https://")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY):
            return JSONResponse({"error": "TOO_LARGE"}, status_code=413)
        response: Response = await call_next(request)
        h = response.headers
        h["Content-Security-Policy"] = ("default-src 'none'; style-src 'self'; img-src 'self'; "
                                        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        h["X-Frame-Options"] = "DENY"
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        if https:
            h["Strict-Transport-Security"] = "max-age=31536000"
        if not request.url.path.startswith("/static/"):
            h["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc):
        return JSONResponse({"error": "BAD_REQUEST"}, status_code=400)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "NOT_FOUND" if exc.status_code == 404 else "ERROR"},
                                status_code=exc.status_code)
        return web.error_page(request, exc.status_code)

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        log.exception("Unbehandelter Fehler bei %s", request.url.path)
        return JSONResponse({"error": "INTERNAL"}, status_code=500)

    @app.get("/healthz")
    async def healthz():
        return Response(status_code=204)

    # -------------------------------------------------------------- Enrollment

    @app.post("/api/v1/enroll")
    async def enroll(body: EnrollIn, request: Request):
        ip = client_ip(request, settings.trusted_proxies)
        code = normalize_code(body.instance_code)
        code_key = code or "-"
        retry = app.state.enroll_rate.hit(ip) or max(app.state.enroll_ip.retry_after(ip),
                                                      app.state.enroll_code.retry_after(code_key))
        if retry:
            with db.session() as s:
                audit(s, "enroll_rate_limited", ip=ip, code=code_key)
                s.commit()
            return JSONResponse({"error": "RATE_LIMITED", "retry_after": retry}, status_code=429,
                                headers={"Retry-After": str(retry)})

        # Anmeldung mit Instanz-Code + Instanz-Passwort oder Admin-Passwort. Beide Hashes werden immer
        # geprüft (gleiche Laufzeit, egal ob Code oder Passwort falsch ist).
        with db.session() as s:
            instance = s.scalar(select(Instance).where(Instance.code == code)) if code else None
            admin = s.scalar(select(User).where(User.is_admin.is_(True), User.auth_source == "local"))
            inst_hash = instance.password_hash if instance else None
            admin_hash = admin.password_hash if admin and settings.local_login_enabled else None
            admin_name = admin.username if admin else ""
        inst_ok = await run_in_threadpool(verify_password, inst_hash, body.password)
        admin_ok = await run_in_threadpool(verify_password, admin_hash, body.password)
        ok = inst_ok or admin_ok
        who = "instance" if inst_ok else f"admin:{admin_name}"

        if not ok or instance is None:
            app.state.enroll_ip.fail(ip)
            app.state.enroll_code.fail(code_key)
            with db.session() as s:
                audit(s, "enroll_failed", ip=ip, code=code_key, server_name=body.server_name)
                s.commit()
            return JSONResponse({"error": "INVALID_CREDENTIALS"}, status_code=401)

        app.state.enroll_code.success(code_key)  # IP-Zähler bleibt bewusst stehen
        if not instance.enabled:
            with db.session() as s:
                audit(s, "enroll_disabled", actor=who, ip=ip, instance=instance.name)
                s.commit()
            return JSONResponse({"error": "INSTANCE_DISABLED"}, status_code=403)

        token = new_token()
        with db.session() as s:
            device = s.scalar(select(Device).where(Device.instance_id == instance.id,
                                                   Device.server_id == body.server_id))
            replaced = device is not None
            if device is None:
                device = Device(instance_id=instance.id, server_id=body.server_id)
                s.add(device)
            device.server_name = _printable(body.server_name, 100) or device.server_name or body.server_id
            device.version = _printable(body.version, 32)
            device.token_hash = token_hash(token)
            device.revoked_at = None
            device.enrolled_by = who
            device.last_ip = ip
            s.flush()
            device_id = device.id
            audit(s, "enroll", actor=who, ip=ip, instance=instance.name, device_id=device_id,
                  server_name=device.server_name, replaced=replaced)
            s.commit()
        if replaced:
            await hub.kick_device(device_id, CLOSE_TOKEN_INVALID, "token_replaced")
        return {"device_token": token, "device_id": device_id,
                "instance": {"id": instance.id, "name": instance.name}}

    # -------------------------------------------------------------- Steuerkanal

    @app.websocket("/api/v1/control")
    async def control(ws: WebSocket):
        await hub.handle(ws)

    # -------------------------------------------------------------- Weboberfläche

    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    app.include_router(web.router)
    app.include_router(oidc.router)
    web.install_handlers(app)
    return app


def _printable(text: str, maxlen: int) -> str:
    return "".join(ch for ch in text if ch.isprintable()).strip()[:maxlen]
