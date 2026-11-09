from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from app import oidc
from app.config import ConfigError, load_settings
from app.db import AuditLog, User
from app.main import create_app
from tests.conftest import ADMIN_PW, INST_PW, login, make_instance


def _configure(settings, mode="all", emails=("jay@jaycloud.at",), groups=()):
    settings.auth_modes = mode
    settings.oidc_issuer = "https://auth.test/application/o/rtl/"
    settings.oidc_client_id = "client"
    settings.oidc_client_secret = "secret"
    settings.oidc_allowed_emails = frozenset(emails)
    settings.oidc_allowed_groups = frozenset(groups)
    return settings


@pytest.fixture
def fake(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(oidc, "get_client", lambda request: client)
    return client


def _callback(c, fake, email, groups=None):
    info = {"email": email, "name": "Jay"}
    if groups is not None:
        info["groups"] = groups
    fake.authorize_access_token = AsyncMock(return_value={"userinfo": info})
    return c.get("/login/oidc/callback", follow_redirects=False)


def test_button_hidden_without_config(client):
    assert "/login/oidc" not in client.get("/login").text
    assert client.get("/login/oidc").status_code == 404
    assert client.get("/login/oidc/callback").status_code == 404


def test_allowed_email_logs_in(settings, fake):
    with TestClient(create_app(_configure(settings))) as c:
        page = c.get("/login").text
        assert "Mit authentik anmelden" in page and 'name="password"' in page  # beide Anmeldearten
        r = _callback(c, fake, "Jay@JayCloud.at")
        assert r.status_code == 200
        assert 'http-equiv="refresh"' in r.text
        assert "roi_session=" in r.headers["set-cookie"] and "SameSite=strict" in r.headers["set-cookie"]
        assert c.get("/", follow_redirects=False).status_code == 200
        audit = c.get("/audit").text
        assert "login_oidc" in audit and "oidc_user_created" in audit
        # zweite Anmeldung legt keinen weiteren Benutzer an
        _callback(c, fake, "jay@jaycloud.at")
        with c.app.state.db.session() as s:
            assert s.query(User).filter_by(auth_source="oidc").count() == 1


def test_denied_email(settings, fake):
    with TestClient(create_app(_configure(settings))) as c:
        r = _callback(c, fake, "fremd@example.com")
        assert r.status_code == 403 and "Kein Zugriff" in r.text
        assert c.get("/", follow_redirects=False).status_code == 303
        with c.app.state.db.session() as s:
            assert s.query(AuditLog).order_by(AuditLog.id.desc()).first().action == "oidc_denied"


def test_allowed_group(settings, fake):
    with TestClient(create_app(_configure(settings, emails=(), groups=("rtl-admins",)))) as c:
        assert _callback(c, fake, "x@example.com", groups=["andere"]).status_code == 403
        assert _callback(c, fake, "x@example.com", groups=["rtl-admins"]).status_code == 200
        assert c.get("/", follow_redirects=False).status_code == 200


def test_provider_unreachable(settings, fake):
    fake.authorize_redirect = AsyncMock(side_effect=httpx.ConnectError("no route"))
    with TestClient(create_app(_configure(settings))) as c:
        r = c.get("/login/oidc", follow_redirects=False)
        assert r.status_code == 502 and "nicht erreichbar" in r.text


def test_redirect_uri_uses_public_url(settings, fake):
    from fastapi.responses import RedirectResponse

    fake.authorize_redirect = AsyncMock(return_value=RedirectResponse("https://auth.test/authorize"))
    with TestClient(create_app(_configure(settings))) as c:
        c.get("/login/oidc", follow_redirects=False)
        assert fake.authorize_redirect.call_args.args[1] == "http://testserver/login/oidc/callback"


def test_oidc_only_mode(settings, fake):
    with TestClient(create_app(_configure(settings, mode="oidc"))) as c:
        page = c.get("/login").text
        assert 'name="password"' not in page and "Mit authentik anmelden" in page
        assert c.post("/login", data={"username": "admin", "password": ADMIN_PW}).status_code == 403
        # Admin-Passwort gilt nicht mehr für das Enrollment, das Instanz-Passwort schon
        inst = make_instance(c.app)
        body = {"instance_code": inst.code, "server_id": "s1"}
        assert c.post("/api/v1/enroll", json={**body, "password": ADMIN_PW}).status_code == 401
        assert c.post("/api/v1/enroll", json={**body, "password": INST_PW}).status_code == 200
        assert _callback(c, fake, "jay@jaycloud.at").status_code == 200


def test_internal_mode_ignores_oidc(settings, fake):
    with TestClient(create_app(_configure(settings, mode="internal"))) as c:
        assert "/login/oidc" not in c.get("/login").text
        assert c.get("/login/oidc").status_code == 404
        assert login(c).status_code == 303


def test_local_admin_kept_besides_oidc_user(settings, fake):
    s = _configure(settings)
    app = create_app(s)
    with TestClient(app) as c:
        _callback(c, fake, "jay@jaycloud.at")
    from app.main import ensure_admin

    s.admin_password = ADMIN_PW
    ensure_admin(app.state.db, s)  # Neustart: lokaler Admin wird abgeglichen, OIDC-Benutzer bleibt
    with app.state.db.session() as db:
        assert {(u.username, u.auth_source) for u in db.query(User)} == {("admin", "local"),
                                                                       ("jay@jaycloud.at", "oidc")}


def test_config_validation(tmp_path, monkeypatch):
    for key in ("ROI_ADMIN_USER", "ROI_ADMIN_PASSWORD", "ROI_OIDC_ALLOWED_EMAILS", "ROI_OIDC_ALLOWED_GROUPS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ROI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ROI_OIDC_ISSUER", "https://auth.test/application/o/rtl/")
    monkeypatch.setenv("ROI_OIDC_CLIENT_ID", "c")
    monkeypatch.setenv("ROI_OIDC_CLIENT_SECRET", "s")
    monkeypatch.setenv("ROI_AUTH_MODES", "oidc")
    with pytest.raises(ConfigError, match="ALLOWED"):
        load_settings()
    monkeypatch.setenv("ROI_OIDC_ALLOWED_EMAILS", "Jay@JayCloud.at, b@x.at")
    s = load_settings()  # oidc-only: kein Admin-Passwort nötig
    assert s.admin_user is None and s.oidc_allowed_emails == {"jay@jaycloud.at", "b@x.at"}
    monkeypatch.setenv("ROI_AUTH_MODES", "all")
    with pytest.raises(ConfigError, match="ROI_ADMIN_USER"):
        load_settings()
    monkeypatch.delenv("ROI_OIDC_ISSUER")
    monkeypatch.setenv("ROI_AUTH_MODES", "oidc")
    with pytest.raises(ConfigError, match="braucht"):
        load_settings()
