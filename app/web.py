"""Weboberfläche für den Admin: Login, Instanzen, Geräte, Sitzungen, Audit-Log."""

from __future__ import annotations

import json
import os
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, func, select
from starlette.concurrency import run_in_threadpool

from .control import CLOSE_INSTANCE_DISABLED, CLOSE_TOKEN_INVALID
from .db import AuditLog, Device, Instance, Share, StreamSession, User, WebSession, audit, utcnow
from .security import (
    client_ip,
    csrf_ok,
    csrf_token,
    decrypt_secret,
    encrypt_secret,
    format_code,
    hash_password,
    new_instance_code,
    new_password,
    new_token,
    token_hash,
    verify_password,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_TZ = ZoneInfo(os.environ.get("ROI_TIMEZONE", "Europe/Vienna"))


def _dt(value: datetime | None) -> str:
    if value is None:
        return "–"
    return value.replace(tzinfo=timezone.utc).astimezone(_TZ).strftime("%d.%m.%Y %H:%M:%S")


def _size(n: int | None) -> str:
    if n is None:
        return "–"
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return str(n)


def _duration(start: datetime | None, end: datetime | None) -> str:
    if start is None:
        return "–"
    secs = int(((end or utcnow()) - start).total_seconds())
    h, rest = divmod(secs, 3600)
    m, s = divmod(rest, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


templates.env.filters["dt"] = _dt
templates.env.filters["size"] = _size
templates.env.filters["code"] = format_code
templates.env.globals["duration"] = _duration
templates.env.globals["version"] = os.environ.get("ROI_VERSION", "dev")  # nur für angemeldete Admins sichtbar


class LoginRequired(Exception):
    pass


def _cookie_name(request: Request) -> str:
    return "__Host-roi_session" if request.app.state.settings.cookie_secure else "roi_session"


def _login_cookie_name(request: Request) -> str:
    return "__Host-roi_login" if request.app.state.settings.cookie_secure else "roi_login"


def _set_cookie(request: Request, response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, path="/", httponly=True, samesite="strict",
                        secure=request.app.state.settings.cookie_secure)


def _current(request: Request) -> tuple[User, str] | None:
    token = request.cookies.get(_cookie_name(request))
    if not token:
        return None
    settings = request.app.state.settings
    now = utcnow()
    with request.app.state.db.session() as s:
        ws = s.scalar(select(WebSession).where(WebSession.token_hash == token_hash(token)))
        if ws is None:
            return None
        if (now - ws.last_seen > timedelta(minutes=settings.session_idle_minutes)
                or now - ws.created_at > timedelta(hours=settings.session_max_hours)):
            s.delete(ws)
            s.commit()
            return None
        user = s.get(User, ws.user_id)
        if user is None or not user.is_admin:
            return None
        # Anmeldeart inzwischen abgeschaltet (ROI_AUTH_MODES geändert): Sitzung gilt nicht mehr
        if (user.auth_source == "oidc" and not settings.oidc_active) or \
                (user.auth_source == "local" and not settings.local_login_enabled):
            return None
        ws.last_seen = now
        s.commit()
        return user, token


def render(request: Request, name: str, ctx: dict | None = None, status: int = 200, session_token: str = ""):
    ctx = dict(ctx or {})
    secret = request.app.state.settings.secret_key
    if session_token:
        ctx.setdefault("csrf", csrf_token(secret, "session:" + session_token))
    ctx.setdefault("user", None)
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def error_page(request: Request, status: int):
    texts = {403: "Zugriff verweigert", 404: "Nicht gefunden", 405: "Methode nicht erlaubt"}
    return render(request, "error.html", {"status": status, "text": texts.get(status, "Fehler")}, status=status)


async def admin(request: Request, *, post: bool = False):
    """Prüft Sitzung und bei POST das CSRF-Token. Liefert (user, token, form)."""
    cur = _current(request)
    if cur is None:
        raise LoginRequired()
    user, token = cur
    form = None
    if post:
        form = await request.form()
        if not csrf_ok(request.app.state.settings.secret_key, "session:" + token, form.get("csrf")):
            raise _Forbidden()
    return user, token, form


class _Forbidden(Exception):
    pass


def _ip(request: Request) -> str:
    return client_ip(request, request.app.state.settings.trusted_proxies)


def _audit(request: Request, action: str, actor: str = "", **detail) -> None:
    with request.app.state.db.session() as s:
        audit(s, action, actor=actor, ip=_ip(request), **detail)
        s.commit()


def _back(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _slug(name: str) -> str:
    value = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    value = re.sub(r"[^a-z0-9]+", ".", value).strip(".")
    return value[:24] or "instanz"


# ------------------------------------------------------------------ Login


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if _current(request) is not None:
        return _back("/")
    return _login_page(request)


def _login_page(request: Request, error: str = "", status: int = 200):
    settings = request.app.state.settings
    value = secrets.token_urlsafe(24)
    resp = render(request, "login.html", {
        "error": error, "local": settings.local_login_enabled, "oidc": settings.oidc_active,
        "oidc_label": settings.oidc_button_label,
        "csrf": csrf_token(settings.secret_key, "login:" + value)}, status=status)
    _set_cookie(request, resp, _login_cookie_name(request), value, 900)
    return resp


@router.post("/login")
async def login(request: Request):
    settings = request.app.state.settings
    app = request.app
    if not settings.local_login_enabled:
        return error_page(request, 403)
    form = await request.form()
    pre = request.cookies.get(_login_cookie_name(request), "")
    if not csrf_ok(settings.secret_key, "login:" + pre, form.get("csrf")):
        return _login_page(request, "Formular abgelaufen, bitte erneut versuchen.", 403)

    ip = _ip(request)
    username = str(form.get("username", ""))[:64].strip().lower()
    password = str(form.get("password", ""))[:256]
    retry = max(app.state.login_ip.retry_after(ip), app.state.login_user.retry_after(username))
    if retry:
        _audit(request, "login_locked", actor=username)
        return _login_page(request, f"Zu viele Fehlversuche. Bitte in {retry // 60 + 1} Minuten erneut versuchen.",
                           429)

    with app.state.db.session() as s:
        user = s.scalar(select(User).where(User.username == username, User.is_admin.is_(True),
                                           User.auth_source == "local"))
        pw_hash = user.password_hash if user else None
        user_id = user.id if user else None
    ok = await run_in_threadpool(verify_password, pw_hash, password)
    if not ok:
        app.state.login_ip.fail(ip)
        app.state.login_user.fail(username)
        _audit(request, "login_failed", actor=username)
        return _login_page(request, "Benutzer oder Passwort falsch.", 401)

    app.state.login_user.success(username)
    resp = _back("/")
    start_session(request, resp, user_id, username, "login")
    return resp


def start_session(request: Request, resp: Response, user_id: int, actor: str, action: str) -> None:
    """Neue Admin-Sitzung anlegen und das Cookie auf `resp` setzen."""
    settings = request.app.state.settings
    ip = _ip(request)
    token = new_token()
    now = utcnow()
    with request.app.state.db.session() as s:
        cutoff = now - timedelta(hours=settings.session_max_hours)
        s.execute(delete(WebSession).where(WebSession.created_at < cutoff))
        s.add(WebSession(token_hash=token_hash(token), user_id=user_id, ip=ip, created_at=now, last_seen=now))
        audit(s, action, actor=actor, ip=ip)
        s.commit()
    _set_cookie(request, resp, _cookie_name(request), token, settings.session_max_hours * 3600)
    resp.delete_cookie(_login_cookie_name(request), path="/")


@router.post("/logout")
async def logout(request: Request):
    user, token, _ = await admin(request, post=True)
    with request.app.state.db.session() as s:
        s.execute(delete(WebSession).where(WebSession.token_hash == token_hash(token)))
        audit(s, "logout", actor=user.username, ip=_ip(request))
        s.commit()
    resp = _back("/login")
    resp.delete_cookie(_cookie_name(request), path="/")
    return resp


# ------------------------------------------------------------------ Instanzen


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user, token, _ = await admin(request)
    hub = request.app.state.hub
    with request.app.state.db.session() as s:
        rows = list(s.scalars(select(Instance).order_by(Instance.name)))
        counts = dict(s.execute(select(Device.instance_id, func.count()).where(Device.revoked_at.is_(None))
                                .group_by(Device.instance_id)).all())
    items = [{"i": i, "devices": counts.get(i.id, 0), "online": len(hub.online(i.id)),
              "streams": len(hub.active_sessions(i.id))} for i in rows]
    return render(request, "index.html", {"user": user, "items": items}, session_token=token)


@router.post("/instances")
async def create_instance(request: Request):
    user, token, form = await admin(request, post=True)
    name = " ".join(str(form.get("name", "")).split())[:100]
    if not name:
        return _back("/?error=1")
    password = new_password()
    pw_hash = await run_in_threadpool(hash_password, password)
    with request.app.state.db.session() as s:
        while True:
            code = new_instance_code()
            if s.scalar(select(Instance.id).where(Instance.code == code)) is None:
                break
        inst = Instance(name=name, code=code, username="", password_hash=pw_hash,
                        password_enc=encrypt_secret(request.app.state.settings.secret_key, password))
        s.add(inst)
        s.flush()
        audit(s, "instance_created", actor=user.username, ip=_ip(request), instance_id=inst.id, name=name)
        s.commit()
        inst_id = inst.id
    return render(request, "credentials.html", {
        "user": user, "title": "Instanz angelegt", "instance_id": inst_id, "name": name,
        "code": code, "password": password}, session_token=token)


def _get_instance(request: Request, instance_id: int) -> Instance:
    with request.app.state.db.session() as s:
        inst = s.get(Instance, instance_id)
    if inst is None:
        raise _NotFound()
    return inst


class _NotFound(Exception):
    pass


@router.get("/instances/{instance_id}", response_class=HTMLResponse)
async def instance_detail(request: Request, instance_id: int):
    user, token, _ = await admin(request)
    inst = _get_instance(request, instance_id)
    hub = request.app.state.hub
    online = hub.online(instance_id)
    with request.app.state.db.session() as s:
        devices = list(s.scalars(select(Device).where(Device.instance_id == instance_id)
                                 .order_by(Device.revoked_at.is_not(None), Device.server_name)))
        shares = s.execute(select(Share, Device).join(Device, Share.device_id == Device.id)
                           .where(Device.instance_id == instance_id, Device.revoked_at.is_(None))
                           .order_by(Device.server_name, Share.stick_id)).all()
        sessions = list(s.scalars(select(StreamSession).where(StreamSession.instance_id == instance_id)
                                  .order_by(StreamSession.created_at.desc()).limit(50)))
    active = {x.id: x for x in hub.active_sessions(instance_id)}
    password = decrypt_secret(request.app.state.settings.secret_key, inst.password_enc)
    return render(request, "instance.html", {
        "user": user, "inst": inst, "devices": devices, "online": online, "shares": shares,
        "sessions": sessions, "active": active, "password": password}, session_token=token)


def _attachment(filename: str) -> dict:
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


@router.get("/instances/{instance_id}/zugangsdaten.txt")
async def credentials_file(request: Request, instance_id: int):
    user, token, _ = await admin(request)
    inst = _get_instance(request, instance_id)
    settings = request.app.state.settings
    password = decrypt_secret(settings.secret_key, inst.password_enc)
    text = "\r\n".join([
        f"rtl.over.internet – Zugangsdaten für „{inst.name}“",
        "",
        f"Server:        {settings.public_url}",
        f"Instanz-Code:  {format_code(inst.code)}",
        f"Passwort:      {password or '(nicht gespeichert – in der Weboberfläche „Neues Passwort“ erzeugen)'}",
        "",
        "Im rtltcp.server unter „Instanz hinzufügen“ eintragen.",
        "Das Passwort wird dort nicht gespeichert, der Server bekommt ein eigenes, widerrufbares Token.",
        "",
    ])
    _audit(request, "instance_credentials_downloaded", actor=user.username, instance_id=instance_id)
    return Response(text.encode("utf-8"), media_type="text/plain; charset=utf-8",
                    headers=_attachment(f"zugangsdaten-{_slug(inst.name)}.txt"))


def _iso(value: datetime | None) -> str | None:
    return value.replace(tzinfo=timezone.utc).isoformat() if value else None


@router.get("/export.json")
async def export_all(request: Request):
    """Alle Daten für den Admin (inkl. Instanz-Passwörter). Token-Hashes bleiben draußen, sie nützen nichts."""
    user, token, _ = await admin(request)
    settings = request.app.state.settings
    hub = request.app.state.hub
    with request.app.state.db.session() as s:
        instances = list(s.scalars(select(Instance).order_by(Instance.id)))
        devices = list(s.scalars(select(Device).order_by(Device.id)))
        shares = list(s.scalars(select(Share).order_by(Share.device_id, Share.stick_id)))
        sessions = list(s.scalars(select(StreamSession).order_by(StreamSession.created_at)))
        audit_rows = list(s.scalars(select(AuditLog).order_by(AuditLog.id)))
    data = {
        "exported_at": _iso(utcnow()),
        "public_url": settings.public_url,
        "version": templates.env.globals["version"],
        "instances": [{
            "id": i.id, "name": i.name, "code": format_code(i.code),
            "password": decrypt_secret(settings.secret_key, i.password_enc), "enabled": i.enabled,
            "max_streams": i.max_streams, "notes": i.notes, "created_at": _iso(i.created_at),
        } for i in instances],
        "devices": [{
            "id": d.id, "instance_id": d.instance_id, "server_id": d.server_id, "server_name": d.server_name,
            "version": d.version, "enrolled_by": d.enrolled_by, "online": d.id in hub.conns,
            "created_at": _iso(d.created_at), "last_seen": _iso(d.last_seen), "last_ip": d.last_ip,
            "revoked_at": _iso(d.revoked_at),
        } for d in devices],
        "shares": [{
            "device_id": sh.device_id, "stick_id": sh.stick_id, "name": sh.name, "tuner": sh.tuner,
            "state": sh.state, "compression": sh.compression, "updated_at": _iso(sh.updated_at),
        } for sh in shares],
        "sessions": [{
            "id": x.id, "instance_id": x.instance_id, "provider_device_id": x.provider_device_id,
            "client_device_id": x.client_device_id, "provider_name": x.provider_name,
            "client_name": x.client_name, "stick_id": x.stick_id, "stick_name": x.stick_name,
            "state": x.state, "result": x.result, "reason": x.reason, "path": x.path,
            "nat_server": x.nat_server, "nat_client": x.nat_client, "bytes_server": x.bytes_server,
            "bytes_client": x.bytes_client, "created_at": _iso(x.created_at),
            "connected_at": _iso(x.connected_at), "ended_at": _iso(x.ended_at),
        } for x in sessions],
        "audit_log": [{
            "ts": _iso(a.ts), "action": a.action, "actor": a.actor, "ip": a.ip,
            "detail": json.loads(a.detail) if a.detail else {},
        } for a in audit_rows],
    }
    _audit(request, "export_downloaded", actor=user.username)
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    return JSONResponse(data, headers=_attachment(f"rtl-over-internet-{stamp}.json"))


@router.post("/instances/{instance_id}/edit")
async def edit_instance(request: Request, instance_id: int):
    user, token, form = await admin(request, post=True)
    name = " ".join(str(form.get("name", "")).split())[:100]
    notes = str(form.get("notes", ""))[:4000]
    max_raw = str(form.get("max_streams", "")).strip()
    if not name or (max_raw and not max_raw.isdigit()):
        return _back(f"/instances/{instance_id}?error=1")
    with request.app.state.db.session() as s:
        inst = s.get(Instance, instance_id)
        if inst is None:
            raise _NotFound()
        changes = {}
        for field, value in (("name", name), ("notes", notes),
                             ("max_streams", int(max_raw) if max_raw else None)):
            if getattr(inst, field) != value:
                changes[field] = value if field != "notes" else "(geändert)"
                setattr(inst, field, value)
        if changes:
            audit(s, "instance_updated", actor=user.username, ip=_ip(request), instance_id=instance_id,
                  **changes)
        s.commit()
    return _back(f"/instances/{instance_id}")


@router.post("/instances/{instance_id}/enable")
async def enable_instance(request: Request, instance_id: int):
    return await _set_enabled(request, instance_id, True)


@router.post("/instances/{instance_id}/disable")
async def disable_instance(request: Request, instance_id: int):
    return await _set_enabled(request, instance_id, False)


async def _set_enabled(request: Request, instance_id: int, enabled: bool):
    user, token, form = await admin(request, post=True)
    with request.app.state.db.session() as s:
        inst = s.get(Instance, instance_id)
        if inst is None:
            raise _NotFound()
        inst.enabled = enabled
        audit(s, "instance_enabled" if enabled else "instance_disabled", actor=user.username, ip=_ip(request),
              instance_id=instance_id, name=inst.name)
        s.commit()
    if not enabled:
        await request.app.state.hub.kick_instance(instance_id, CLOSE_INSTANCE_DISABLED, "instance_disabled")
    return _back(f"/instances/{instance_id}")


@router.post("/instances/{instance_id}/code")
async def regenerate_code(request: Request, instance_id: int):
    user, token, form = await admin(request, post=True)
    revoke_all = form.get("revoke_tokens") == "1"
    with request.app.state.db.session() as s:
        inst = s.get(Instance, instance_id)
        if inst is None:
            raise _NotFound()
        while True:
            code = new_instance_code()
            if s.scalar(select(Instance.id).where(Instance.code == code)) is None:
                break
        inst.code = code
        if revoke_all:
            _revoke_devices(s, instance_id)
        audit(s, "instance_code_regenerated", actor=user.username, ip=_ip(request), instance_id=instance_id,
              tokens_revoked=revoke_all)
        s.commit()
    if revoke_all:
        await request.app.state.hub.kick_instance(instance_id, CLOSE_TOKEN_INVALID, "token_revoked")
    return _back(f"/instances/{instance_id}")


def _revoke_devices(s, instance_id: int) -> None:
    now = utcnow()
    for dev in s.scalars(select(Device).where(Device.instance_id == instance_id, Device.revoked_at.is_(None))):
        dev.revoked_at = now
        dev.token_hash = None


@router.get("/instances/{instance_id}/password", response_class=HTMLResponse)
async def password_confirm(request: Request, instance_id: int):
    user, token, _ = await admin(request)
    inst = _get_instance(request, instance_id)
    with request.app.state.db.session() as s:
        devices = s.scalar(select(func.count()).select_from(Device)
                           .where(Device.instance_id == instance_id, Device.revoked_at.is_(None)))
    return render(request, "password_confirm.html", {"user": user, "inst": inst, "devices": devices},
                  session_token=token)


@router.post("/instances/{instance_id}/password")
async def regenerate_password(request: Request, instance_id: int):
    user, token, form = await admin(request, post=True)
    revoke_all = form.get("revoke_tokens") == "1"
    password = new_password()
    pw_hash = await run_in_threadpool(hash_password, password)
    with request.app.state.db.session() as s:
        inst = s.get(Instance, instance_id)
        if inst is None:
            raise _NotFound()
        inst.password_hash = pw_hash
        inst.password_enc = encrypt_secret(request.app.state.settings.secret_key, password)
        if revoke_all:
            _revoke_devices(s, instance_id)
        audit(s, "instance_password_regenerated", actor=user.username, ip=_ip(request), instance_id=instance_id,
              tokens_revoked=revoke_all)
        s.commit()
        name, code = inst.name, inst.code
    if revoke_all:
        await request.app.state.hub.kick_instance(instance_id, CLOSE_TOKEN_INVALID, "token_revoked")
    return render(request, "credentials.html", {
        "user": user, "title": "Neues Passwort", "instance_id": instance_id, "name": name, "code": code,
        "password": password}, session_token=token)


@router.get("/instances/{instance_id}/delete", response_class=HTMLResponse)
async def delete_confirm(request: Request, instance_id: int):
    user, token, _ = await admin(request)
    inst = _get_instance(request, instance_id)
    return render(request, "delete.html", {"user": user, "inst": inst}, session_token=token)


@router.post("/instances/{instance_id}/delete")
async def delete_instance(request: Request, instance_id: int):
    user, token, form = await admin(request, post=True)
    inst = _get_instance(request, instance_id)
    if form.get("confirm_name", "") != inst.name:
        return _back(f"/instances/{instance_id}/delete?error=1")
    await request.app.state.hub.kick_instance(instance_id, CLOSE_TOKEN_INVALID, "instance_deleted")
    with request.app.state.db.session() as s:
        inst = s.get(Instance, instance_id)
        if inst is not None:
            s.delete(inst)
            audit(s, "instance_deleted", actor=user.username, ip=_ip(request), instance_id=instance_id,
                  name=inst.name)
            s.commit()
    return _back("/")


# ------------------------------------------------------------------ Geräte und Sitzungen


def _device(request: Request, device_id: int) -> Device:
    with request.app.state.db.session() as s:
        dev = s.get(Device, device_id)
    if dev is None:
        raise _NotFound()
    return dev


@router.post("/devices/{device_id}/disconnect")
async def disconnect_device(request: Request, device_id: int):
    user, token, form = await admin(request, post=True)
    dev = _device(request, device_id)
    await request.app.state.hub.kick_device(device_id, 1000, "disconnected_by_admin")
    _audit(request, "device_disconnected", actor=user.username, device_id=device_id, name=dev.server_name)
    return _back(f"/instances/{dev.instance_id}")


@router.post("/devices/{device_id}/revoke")
async def revoke_device(request: Request, device_id: int):
    user, token, form = await admin(request, post=True)
    dev = _device(request, device_id)
    with request.app.state.db.session() as s:
        row = s.get(Device, device_id)
        row.revoked_at = utcnow()
        row.token_hash = None
        audit(s, "device_revoked", actor=user.username, ip=_ip(request), device_id=device_id,
              name=row.server_name, instance_id=row.instance_id)
        s.commit()
    hub = request.app.state.hub
    await hub.kick_device(device_id, CLOSE_TOKEN_INVALID, "token_revoked")
    await hub.broadcast_shares(dev.instance_id)
    return _back(f"/instances/{dev.instance_id}")


@router.post("/devices/{device_id}/delete")
async def delete_device(request: Request, device_id: int):
    user, token, form = await admin(request, post=True)
    dev = _device(request, device_id)
    if dev.revoked_at is None:
        return _back(f"/instances/{dev.instance_id}")
    with request.app.state.db.session() as s:
        row = s.get(Device, device_id)
        s.delete(row)
        audit(s, "device_deleted", actor=user.username, ip=_ip(request), device_id=device_id,
              name=dev.server_name)
        s.commit()
    return _back(f"/instances/{dev.instance_id}")


@router.post("/sessions/{session_id}/end")
async def end_session(request: Request, session_id: str):
    user, token, form = await admin(request, post=True)
    with request.app.state.db.session() as s:
        row = s.get(StreamSession, session_id)
    if row is None:
        raise _NotFound()
    if await request.app.state.hub.end_session(session_id, "ended_by_admin"):
        _audit(request, "session_ended_by_admin", actor=user.username, session=session_id)
    return _back(f"/instances/{row.instance_id}")


@router.get("/audit", response_class=HTMLResponse)
async def audit_log(request: Request):
    user, token, _ = await admin(request)
    with request.app.state.db.session() as s:
        rows = list(s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(300)))
    entries = []
    for r in rows:
        try:
            detail = json.loads(r.detail) if r.detail else {}
        except ValueError:
            detail = {"text": r.detail}
        entries.append({"r": r, "detail": ", ".join(f"{k}={v}" for k, v in detail.items())})
    return render(request, "audit.html", {"user": user, "entries": entries}, session_token=token)


def install_handlers(app) -> None:
    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc):
        return _back("/login")

    @app.exception_handler(_Forbidden)
    async def _forbidden(request: Request, exc):
        return error_page(request, 403)

    @app.exception_handler(_NotFound)
    async def _not_found(request: Request, exc):
        return error_page(request, 404)
