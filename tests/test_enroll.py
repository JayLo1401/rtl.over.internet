from app.db import Device
from app.security import format_code, token_hash
from tests.conftest import ADMIN_PW, INST_PW, connect, enroll, expect_close, hello, make_instance


def _post(client, **body):
    return client.post("/api/v1/enroll", json={"server_id": "srv-a", "server_name": "Dachboden", **body})


def test_enroll_with_code_and_password(client, app):
    inst = make_instance(app)
    res = enroll(client, inst)
    assert res["instance"] == {"id": inst.id, "name": inst.name}
    assert isinstance(res["device_id"], int) and len(res["device_token"]) >= 40
    with app.state.db.session() as s:
        dev = s.get(Device, res["device_id"])
        assert dev.token_hash == token_hash(res["device_token"])
        assert res["device_token"] not in (dev.token_hash or "")
        assert dev.enrolled_by == "instance"


def test_code_case_and_dash_insensitive(client, app):
    inst = make_instance(app)
    for code in (format_code(inst.code), inst.code.lower(), " " + format_code(inst.code).lower()):
        r = _post(client, instance_code=code, password=INST_PW)
        assert r.status_code == 200, code


def test_user_field_is_ignored(client, app):
    """rtltcp.server 1.5.0 schickt noch einen Benutzer mit: egal welcher, es zählt nur das Passwort."""
    inst = make_instance(app)
    assert _post(client, instance_code=inst.code, user="irgendwer", password=INST_PW).status_code == 200
    assert _post(client, instance_code=inst.code, user="irgendwer", password="falsch").status_code == 401


def test_enroll_with_admin_password(client, app):
    inst = make_instance(app)
    r = _post(client, instance_code=inst.code, password=ADMIN_PW)
    assert r.status_code == 200
    with app.state.db.session() as s:
        assert s.get(Device, r.json()["device_id"]).enrolled_by == "admin:admin"


def test_invalid_credentials_identical(client, app):
    inst = make_instance(app)
    other = make_instance(app, name="Andere", password="anderes-passwort-1")
    bodies = [
        dict(instance_code="ZZZZ-ZZZZ", password=INST_PW),  # falscher Code
        dict(instance_code=inst.code, password="falsch"),  # falsches Passwort
        dict(instance_code=other.code, password=INST_PW),  # Passwort einer anderen Instanz
        dict(instance_code="ZZZZ-ZZZZ", password=ADMIN_PW),  # Admin-Passwort, aber kein gültiger Code
        dict(instance_code="kaputt!", password=INST_PW),  # ungültiges Format
    ]
    for body in bodies:
        r = _post(client, **body)
        assert r.status_code == 401, body
        assert r.json() == {"error": "INVALID_CREDENTIALS"}


def test_enroll_rate_limit(client, app):
    inst = make_instance(app)
    for _ in range(10):
        assert _post(client, instance_code=inst.code, password="falsch").status_code == 401
    r = _post(client, instance_code=inst.code, password=INST_PW)
    assert r.status_code == 429
    assert r.json()["error"] == "RATE_LIMITED" and r.json()["retry_after"] > 0
    assert int(r.headers["retry-after"]) > 0


def test_enroll_disabled_instance(client, app):
    inst = make_instance(app, enabled=False)
    r = _post(client, instance_code=inst.code, password=INST_PW)
    assert r.status_code == 403 and r.json() == {"error": "INSTANCE_DISABLED"}
    # mit falschem Passwort verrät der Dienst nicht, dass die Instanz deaktiviert ist
    r = _post(client, instance_code=inst.code, password="falsch")
    assert r.status_code == 401


def test_bad_body(client):
    assert client.post("/api/v1/enroll", json={"instance_code": "x"}).status_code == 400
    r = _post(client, instance_code="K7QM4XPD", password="x", server_id="bad id with spaces")
    assert r.status_code == 400 and r.json() == {"error": "BAD_REQUEST"}
    big = client.post("/api/v1/enroll", content=b"x" * 70000, headers={"content-type": "application/json"})
    assert big.status_code == 413


def test_reenroll_replaces_token(client, app):
    inst = make_instance(app)
    first = enroll(client, inst)
    with connect(client, first["device_token"]) as ws:
        hello(ws)
        second = enroll(client, inst)
        assert second["device_id"] == first["device_id"]
        assert expect_close(ws) == 4401
    with connect(client, first["device_token"]) as ws:
        assert expect_close(ws) == 4401
    with connect(client, second["device_token"]) as ws:
        assert hello(ws)["device_id"] == first["device_id"]
