import re

from app.db import Instance
from app.security import normalize_code
from tests.conftest import ADMIN_PW, csrf_from, login, make_instance


def test_healthz_empty(client):
    r = client.get("/healthz")
    assert r.status_code == 204
    assert r.content == b""


def test_security_headers(client):
    r = client.get("/login")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    assert "server" not in r.headers


def test_no_docs_and_generic_404(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    r = client.get("/api/v1/nothing")
    assert r.json() == {"error": "NOT_FOUND"}


def test_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = client.get("/audit", follow_redirects=False)
    assert r.status_code == 303


def test_login_logout(client):
    r = login(client)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"]
    assert "roi_session=" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    page = client.get("/")
    assert page.status_code == 200 and "Instanzen" in page.text
    # Logout ohne CSRF wird abgelehnt
    assert client.post("/logout", data={}, follow_redirects=False).status_code == 403
    r = client.post("/logout", data={"csrf": csrf_from(page.text)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/", follow_redirects=False).status_code == 303


def test_secure_cookie_with_https(settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    settings.cookie_secure = True
    settings.public_url = "https://rtl.example"
    with TestClient(create_app(settings), base_url="https://testserver") as c:
        page = c.get("/login")
        assert "__Host-roi_login=" in page.headers["set-cookie"]
        assert "Secure" in page.headers["set-cookie"]
        assert "max-age" in page.headers["strict-transport-security"]
        r = login(c)
        assert r.status_code == 303
        assert "__Host-roi_session=" in r.headers["set-cookie"] and "Secure" in r.headers["set-cookie"]


def test_login_wrong_password(client):
    r = login(client, password="falsch-falsch-falsch")
    assert r.status_code == 401
    assert "Benutzer oder Passwort falsch" in r.text
    r = login(client, user="gibtsnicht", password="x")
    assert r.status_code == 401


def test_login_without_csrf_rejected(client):
    client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": ADMIN_PW}, follow_redirects=False)
    assert r.status_code == 403
    r = client.post("/login", data={"username": "admin", "password": ADMIN_PW, "csrf": "0" * 64},
                    follow_redirects=False)
    assert r.status_code == 403


def test_user_lockout(client):
    for _ in range(5):
        assert login(client, password="falsch-falsch").status_code == 401
    r = login(client)  # richtiges Passwort, aber gesperrt
    assert r.status_code == 429
    assert "Zu viele Fehlversuche" in r.text


def test_ip_lockout(client):
    for i in range(10):
        login(client, user=f"user{i}", password="x")
    assert login(client).status_code == 429


def test_lockout_expires(client, app):
    clock = [1000.0]
    for limiter in (app.state.login_ip, app.state.login_user):
        limiter.clock = lambda: clock[0]
    for _ in range(5):
        login(client, password="falsch")
    assert login(client).status_code == 429
    clock[0] += 901
    assert login(client).status_code == 303


def test_audit_log_records_logins(client):
    login(client, password="falsch")
    login(client)
    page = client.get("/audit")
    assert "login_failed" in page.text and ">login<" in page.text


def test_create_instance_password_retrievable(client, app):
    login(client)
    page = client.get("/")
    csrf = csrf_from(page.text)
    # ohne CSRF: verboten
    assert client.post("/instances", data={"name": "Max"}, follow_redirects=False).status_code == 403
    r = client.post("/instances", data={"name": "Funkfreund Max", "csrf": csrf})
    assert r.status_code == 200
    code = re.search(r'class="mono big">([A-Z0-9]{4}-[A-Z0-9]{4})<', r.text).group(1)
    password = re.search(r"Passwort</dt><dd class=\"mono big\">([^<]+)<", r.text).group(1)
    assert normalize_code(code)
    with app.state.db.session() as s:
        inst = s.query(Instance).one()
        assert password not in inst.password_hash and inst.password_hash.startswith("$argon2id$")
        assert inst.password_enc.startswith("v1:") and password not in inst.password_enc  # nicht im Klartext
    detail = client.get(f"/instances/{inst.id}")
    assert password in detail.text  # für den Admin jederzeit abrufbar
    assert code in detail.text

    f = client.get(f"/instances/{inst.id}/zugangsdaten.json")
    assert f.status_code == 200
    assert f.headers["content-type"].startswith("application/json")
    assert 'attachment; filename="rtl-over-internet-funkfreund.max.json"' == f.headers["content-disposition"]
    data = f.json()
    assert data["format"] == "rtl.over.internet/credentials" and data["version"] == 1
    assert data["server"] == "http://testserver"
    assert data["instance_code"] == code and data["password"] == password
    assert data["instance"] == {"id": inst.id, "name": "Funkfreund Max"}
    assert "Benutzer" not in detail.text.split("Instanz-Code")[1].split("Einstellungen")[0]

    # neues Passwort: erst Rückfrage, dann gilt das alte nicht mehr und das neue ist abrufbar
    confirm = client.get(f"/instances/{inst.id}/password")
    assert "Bestehende Verbindungen bleiben erhalten" in confirm.text and 'name="revoke_tokens"' in confirm.text
    assert f'href="/instances/{inst.id}/password"' in detail.text
    r = client.post(f"/instances/{inst.id}/password", data={"csrf": csrf})
    new_pw = re.search(r"Passwort</dt><dd class=\"mono big\">([^<]+)<", r.text).group(1)
    assert new_pw != password
    detail = client.get(f"/instances/{inst.id}").text
    assert new_pw in detail and password not in detail


def test_export_json(client, app):
    inst = make_instance(app)
    assert client.get("/export.json", follow_redirects=False).status_code == 303  # nur angemeldet
    login(client)
    csrf = csrf_from(client.get("/").text)
    r = client.post("/instances", data={"name": "Export", "csrf": csrf})
    password = re.search(r"Passwort</dt><dd class=\"mono big\">([^<]+)<", r.text).group(1)
    exp = client.get("/export.json")
    assert exp.status_code == 200
    assert exp.headers["content-disposition"].startswith('attachment; filename="rtl-over-internet-')
    data = exp.json()
    names = {i["name"]: i for i in data["instances"]}
    assert names["Export"]["password"] == password
    assert names[inst.name]["password"] is None  # direkt in der DB angelegt, kein abrufbares Passwort
    assert set(data) >= {"instances", "devices", "shares", "sessions", "audit_log"}
    assert any(a["action"] == "instance_created" for a in data["audit_log"])
    assert "token_hash" not in exp.text and "password_hash" not in exp.text


def test_instance_without_stored_password(client, app):
    inst = make_instance(app)
    login(client)
    assert "nicht gespeichert" in client.get(f"/instances/{inst.id}").text
    r = client.get(f"/instances/{inst.id}/zugangsdaten.json")
    assert r.status_code == 409 and "kein Passwort gespeichert" in r.text


def test_secret_encryption():
    from app.security import decrypt_secret, encrypt_secret

    key = b"k" * 48
    enc = encrypt_secret(key, "geheim-123")
    assert enc != encrypt_secret(key, "geheim-123")  # zufällige Nonce
    assert decrypt_secret(key, enc) == "geheim-123"
    assert decrypt_secret(b"x" * 48, enc) is None  # anderer Schlüssel
    assert decrypt_secret(key, enc[:-4] + "AAAA") is None  # manipuliert
    assert decrypt_secret(key, None) is None and decrypt_secret(key, "kaputt") is None


def test_migration_adds_column(tmp_path):
    import sqlite3

    from app.db import Database

    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE instances (id INTEGER PRIMARY KEY, name VARCHAR(100), code VARCHAR(16), "
                "username VARCHAR(32), password_hash VARCHAR(255), enabled BOOLEAN, notes TEXT, "
                "max_streams INTEGER, created_at DATETIME)")
    con.commit()
    con.close()
    Database(f"sqlite:///{path.as_posix()}")
    cols = {row[1] for row in sqlite3.connect(path).execute("PRAGMA table_info(instances)")}
    assert "password_enc" in cols


def test_instance_actions_require_csrf(client, app):
    inst = make_instance(app)
    login(client)
    for path in ("disable", "enable", "code", "password", "delete", "edit"):
        r = client.post(f"/instances/{inst.id}/{path}", data={"csrf": "x"}, follow_redirects=False)
        assert r.status_code == 403, path


def test_disable_and_delete_instance(client, app):
    inst = make_instance(app)
    login(client)
    csrf = csrf_from(client.get(f"/instances/{inst.id}").text)
    client.post(f"/instances/{inst.id}/disable", data={"csrf": csrf})
    with app.state.db.session() as s:
        assert s.get(Instance, inst.id).enabled is False
    # Löschen nur mit richtigem Namen
    r = client.post(f"/instances/{inst.id}/delete", data={"csrf": csrf, "confirm_name": "falsch"},
                    follow_redirects=False)
    assert "error=1" in r.headers["location"]
    client.post(f"/instances/{inst.id}/delete", data={"csrf": csrf, "confirm_name": inst.name})
    with app.state.db.session() as s:
        assert s.get(Instance, inst.id) is None
    assert client.get(f"/instances/{inst.id}").status_code == 404
