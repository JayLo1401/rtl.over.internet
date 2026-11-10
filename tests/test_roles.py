"""Rechte: Systemadmin, Instanz-Admin, Instanz-Benutzer, Benutzer ohne Zuweisung."""

import re

import pytest

from app.db import InstanceMember, User
from tests.conftest import ADMIN_PW, csrf_from, enroll, login, make_instance


def _new_user(client, name):
    """Als Systemadmin einen lokalen Benutzer anlegen, liefert das erzeugte Passwort."""
    csrf = csrf_from(client.get("/users").text)
    r = client.post("/users", data={"username": name, "csrf": csrf})
    assert r.status_code == 200, r.text
    return re.search(r"Passwort</dt><dd class=\"mono big\">([^<]+)<", r.text).group(1)


def _user_id(app, name):
    with app.state.db.session() as s:
        return s.query(User).filter_by(username=name).one().id


def _assign(client, inst_id, user_id, role):
    csrf = csrf_from(client.get(f"/instances/{inst_id}").text)
    r = client.post(f"/instances/{inst_id}/members", data={"csrf": csrf, "user_id": user_id, "role": role},
                    follow_redirects=False)
    assert r.status_code == 303


def _as(client, name, pw):
    client.cookies.clear()
    assert login(client, user=name, password=pw).status_code == 303


@pytest.fixture
def setup(client, app):
    """Instanz A und B, Benutzer max (ohne Rechte) und eva; Systemadmin ist am Ende abgemeldet."""
    a = make_instance(app, name="Instanz A")
    b = make_instance(app, name="Instanz B")
    login(client)
    # make_instance speichert kein abrufbares Passwort: neu erzeugen, damit die Zugangsdatei funktioniert
    for inst in (a, b):
        csrf = csrf_from(client.get(f"/instances/{inst.id}").text)
        client.post(f"/instances/{inst.id}/password", data={"csrf": csrf})
    pw = {"max": _new_user(client, "max"), "eva": _new_user(client, "eva")}
    return a, b, pw


def test_new_user_has_no_rights(client, app, setup):
    a, b, pw = setup
    _as(client, "max", pw["max"])
    page = client.get("/").text
    assert "noch keine Instanz zugewiesen" in page
    assert "Instanz A" not in page and "Neue Instanz" not in page
    assert 'href="/users"' not in page and 'href="/audit"' not in page and 'href="/account"' in page
    assert client.get(f"/instances/{a.id}").status_code == 404  # Existenz wird nicht verraten
    assert client.get(f"/instances/{a.id}/zugangsdaten.json").status_code == 404
    for path in ("/users", "/audit", "/export.json"):
        assert client.get(path).status_code == 403, path
    csrf = csrf_from(page)
    assert client.post("/instances", data={"name": "X", "csrf": csrf}).status_code == 403
    assert client.post(f"/instances/{a.id}/disable", data={"csrf": csrf}).status_code == 404


def test_instance_user_reads_only(client, app, setup):
    a, b, pw = setup
    _assign(client, a.id, _user_id(app, "max"), "user")
    dev = enroll(client, a, password=ADMIN_PW)  # ein Server an Instanz A (Instanz-Passwort wurde neu erzeugt)
    _as(client, "max", pw["max"])
    page = client.get("/").text
    assert "Instanz A" in page and "Instanz B" not in page and "Benutzer" in page
    detail = client.get(f"/instances/{a.id}")
    assert detail.status_code == 200
    assert "Zugangsdatei herunterladen" in detail.text and "anzeigen" in detail.text
    for forbidden in ("Deaktivieren", "Neues Passwort", "Code neu erzeugen", "Löschen", "Widerrufen",
                      "Einstellungen", "Zugewiesene Benutzer"):
        assert forbidden not in detail.text, forbidden
    f = client.get(f"/instances/{a.id}/zugangsdaten.json")
    assert f.status_code == 200 and f.json()["password"]
    csrf = csrf_from(detail.text)
    for path in ("disable", "enable", "code", "password", "edit"):
        assert client.post(f"/instances/{a.id}/{path}", data={"csrf": csrf, "name": "x"}).status_code == 403
    assert client.get(f"/instances/{a.id}/password").status_code == 403
    assert client.get(f"/instances/{a.id}/delete").status_code == 403
    assert client.post(f"/devices/{dev['device_id']}/revoke", data={"csrf": csrf}).status_code == 403
    assert client.get(f"/instances/{b.id}").status_code == 404


def test_instance_admin_scope(client, app, setup):
    a, b, pw = setup
    eva = _user_id(app, "eva")
    _assign(client, a.id, eva, "admin")
    _assign(client, b.id, eva, "user")
    _as(client, "eva", pw["eva"])
    detail = client.get(f"/instances/{a.id}").text
    assert "Deaktivieren" in detail and "Einstellungen" in detail and "Löschen" not in detail
    csrf = csrf_from(detail)
    # Admin in A
    assert client.post(f"/instances/{a.id}/edit", data={"csrf": csrf, "name": "A neu"},
                       follow_redirects=False).status_code == 303
    assert client.post(f"/instances/{a.id}/disable", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert client.get(f"/instances/{a.id}/password").status_code == 200
    # nur Benutzer in B
    assert client.post(f"/instances/{b.id}/disable", data={"csrf": csrf}).status_code == 403
    # Systemadmin-Sachen bleiben verboten
    assert client.get(f"/instances/{a.id}/delete").status_code == 403
    assert client.post(f"/instances/{a.id}/members", data={"csrf": csrf, "user_id": eva, "role": "admin"}
                       ).status_code == 403
    assert client.get("/users").status_code == 403
    with app.state.db.session() as s:
        inst = s.get(type(a), a.id)
        assert inst.name == "A neu" and inst.enabled is False


def test_sysadmin_manages_users(client, app, setup):
    a, b, pw = setup
    max_id = _user_id(app, "max")
    _assign(client, a.id, max_id, "user")
    _assign(client, a.id, max_id, "admin")  # Rolle ändern statt doppelt anlegen
    with app.state.db.session() as s:
        rows = s.query(InstanceMember).filter_by(user_id=max_id).all()
        assert [(r.instance_id, r.role) for r in rows] == [(a.id, "admin")]
    users = client.get("/users").text
    assert "Instanz A" in users and "Instanz-Admin" in users
    csrf = csrf_from(users)
    # Benutzername-Regeln und Duplikate
    assert "gibt es schon" in client.post("/users", data={"username": "max", "csrf": csrf}).text
    assert "2–32 Zeichen" in client.post("/users", data={"username": "a@b", "csrf": csrf}).text
    assert "2–32 Zeichen" in client.post("/users", data={"username": "admin", "csrf": csrf}).text
    # Admin aus der .env ist nicht verwaltbar
    admin_id = _user_id(app, "admin")
    assert client.post(f"/users/{admin_id}/delete", data={"csrf": csrf}).status_code == 403
    assert client.post(f"/users/{admin_id}/password", data={"csrf": csrf}).status_code == 403
    # neues Passwort: das alte gilt nicht mehr
    r = client.post(f"/users/{max_id}/password", data={"csrf": csrf})
    new_pw = re.search(r"Passwort</dt><dd class=\"mono big\">([^<]+)<", r.text).group(1)
    client.cookies.clear()
    assert login(client, user="max", password=pw["max"]).status_code == 401
    _as(client, "max", new_pw)
    # Löschen nimmt die Zuweisungen mit
    _as(client, "admin", ADMIN_PW)
    csrf = csrf_from(client.get("/users").text)
    client.post(f"/users/{max_id}/delete", data={"csrf": csrf})
    with app.state.db.session() as s:
        assert s.query(InstanceMember).filter_by(user_id=max_id).count() == 0
        assert s.get(User, max_id) is None
    # Entfernen einer Zuweisung
    eva = _user_id(app, "eva")
    _assign(client, b.id, eva, "user")
    csrf = csrf_from(client.get(f"/instances/{b.id}").text)
    client.post(f"/instances/{b.id}/members/{eva}/delete", data={"csrf": csrf})
    with app.state.db.session() as s:
        assert s.query(InstanceMember).filter_by(user_id=eva).count() == 0


def test_account_password_change(client, app, setup):
    a, b, pw = setup
    assert client.get("/account").status_code == 403  # Admin aus der .env: Passwort kommt aus der .env
    _as(client, "max", pw["max"])
    page = client.get("/account")
    assert page.status_code == 200
    csrf = csrf_from(page.text)
    bad = [({"current": "falsch", "new": "x" * 12, "repeat": "x" * 12}, "stimmt nicht"),
           ({"current": pw["max"], "new": "kurz", "repeat": "kurz"}, "mindestens 12"),
           ({"current": pw["max"], "new": "x" * 12, "repeat": "y" * 12}, "Wiederholung")]
    for data, msg in bad:
        r = client.post("/account/password", data={"csrf": csrf, **data})
        assert r.status_code == 400 and msg in r.text
    r = client.post("/account/password", data={"csrf": csrf, "current": pw["max"], "new": "neues-passwort-12",
                                               "repeat": "neues-passwort-12"})
    assert r.status_code == 200 and "Passwort geändert" in r.text
    client.cookies.clear()
    assert login(client, user="max", password=pw["max"]).status_code == 401
    _as(client, "max", "neues-passwort-12")


def test_local_user_cannot_enroll_with_own_password(client, app, setup):
    """Benutzerpasswörter gelten nicht als Instanz-Passwort, nur das Admin-Passwort aus der .env."""
    a, b, pw = setup
    r = client.post("/api/v1/enroll", json={"instance_code": a.code, "password": pw["max"], "server_id": "s"})
    assert r.status_code == 401
