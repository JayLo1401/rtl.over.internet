"""Anmeldung über OpenID Connect (z. B. authentik), wie bei order.manager.

Jede OIDC-Anmeldung hat Admin-Rechte. Deshalb darf nur hinein, wer in ROI_OIDC_ALLOWED_EMAILS steht
oder einer Gruppe aus ROI_OIDC_ALLOWED_GROUPS angehört (Claim "groups", bei authentik im Scope "profile").
"""

from __future__ import annotations

import logging

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from .db import User, audit
from . import web

log = logging.getLogger("roi.oidc")
router = APIRouter()


def _require_active(request: Request) -> None:
    if not request.app.state.settings.oidc_active:
        raise web._NotFound()


def get_client(request: Request):
    settings = request.app.state.settings
    client = getattr(request.app.state, "oidc_client", None)
    if client is None:
        oauth = OAuth()
        oauth.register(
            "oidc",
            client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret,
            server_metadata_url=settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
        )
        client = request.app.state.oidc_client = oauth.oidc
    return client


@router.get("/login/oidc")
async def oidc_start(request: Request):
    _require_active(request)
    client = get_client(request)
    settings = request.app.state.settings
    try:
        return await client.authorize_redirect(request, settings.oidc_redirect_uri)
    except (httpx.HTTPError, OAuthError) as exc:
        log.error("OIDC: Anmeldedienst nicht erreichbar (%s): %s", settings.oidc_issuer, exc)
        return web._login_page(request, "Der Anmeldedienst ist gerade nicht erreichbar.", 502)


@router.get("/login/oidc/callback")
async def oidc_callback(request: Request):
    _require_active(request)
    client = get_client(request)
    app = request.app
    settings = app.state.settings
    ip = web._ip(request)
    if app.state.login_ip.retry_after(ip):
        return web._login_page(request, "Zu viele Fehlversuche. Bitte später erneut versuchen.", 429)
    try:
        token = await client.authorize_access_token(request)
        info = token.get("userinfo") or await client.userinfo(token=token)
    except (OAuthError, httpx.HTTPError) as exc:
        log.warning("OIDC-Anmeldung fehlgeschlagen: %s", exc)
        app.state.login_ip.fail(ip)
        web._audit(request, "oidc_failed", detail=str(exc)[:200])
        return web._login_page(request, "Anmeldung über den Anmeldedienst fehlgeschlagen.", 400)
    finally:
        request.session.clear()

    email = str(info.get("email") or "").strip().lower()
    groups = info.get("groups") or []
    if "@" not in email:
        return web._login_page(request, "Der Anmeldedienst hat keine E-Mail-Adresse übermittelt.", 400)
    if not settings.oidc_allowed(email, groups):
        app.state.login_ip.fail(ip)
        web._audit(request, "oidc_denied", actor=email)
        return web._login_page(request, f"Kein Zugriff für {email}.", 403)

    with app.state.db.session() as s:
        user = s.scalar(select(User).where(User.username == email, User.auth_source == "oidc"))
        if user is None:
            # Kein Passwort: das Konto ist nur über OIDC nutzbar ("!" ist kein gültiger Argon2-Hash)
            user = User(username=email, password_hash="!oidc", is_admin=True, auth_source="oidc")
            s.add(user)
            audit(s, "oidc_user_created", actor=email, ip=ip)
            s.commit()
        user_id = user.id

    # Weiterleitung per Seite statt 303: Nach dem seitenübergreifenden Rücksprung würde der Browser das
    # SameSite=Strict-Cookie beim direkten Redirect noch nicht mitschicken.
    resp = web.render(request, "redirect.html", {"target": "/"})
    web.start_session(request, resp, user_id, email, "login_oidc")
    return resp
