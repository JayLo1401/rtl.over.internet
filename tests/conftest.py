from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.config import load_settings
from app.db import Instance
from app.main import create_app
from app.security import hash_password, new_instance_code

ADMIN_PW = "admin-passwort-1234"
INST_PW = "instanz-passwort-5678"
FP_A = ":".join(["AA"] * 32)
FP_B = ":".join(["BB"] * 32)


@pytest.fixture
def settings(tmp_path, monkeypatch):
    for key in ("ROI_SECRET_KEY", "ROI_TRUSTED_PROXIES", "ROI_COOKIE_SECURE", "ROI_AUTH_MODES",
                "ROI_ADMIN_PASSWORD_FILE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ROI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ROI_ADMIN_USER", "admin")
    monkeypatch.setenv("ROI_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("ROI_PUBLIC_URL", "http://testserver")
    return load_settings(rendezvous_enabled=False, accept_timeout=0.3, candidates_timeout=0.3,
                         punch_timeout=0.3, punch_delay_ms=10, lease_interval=0.2, hello_timeout=1.0)


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


def csrf_from(html: str) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "kein CSRF-Feld"
    return m.group(1)


def login(client, user="admin", password=ADMIN_PW):
    page = client.get("/login")
    return client.post("/login", data={"username": user, "password": password, "csrf": csrf_from(page.text)},
                       follow_redirects=False)


def make_instance(app, name="Funkfreund Max", password=INST_PW, enabled=True, max_streams=None) -> Instance:
    with app.state.db.session() as s:
        inst = Instance(name=name, code=new_instance_code(), password_hash=hash_password(password),
                        enabled=enabled, max_streams=max_streams)
        s.add(inst)
        s.commit()
        return inst


def enroll(client, inst, server_id="srv-a", name="Dachboden", password=INST_PW):
    r = client.post("/api/v1/enroll", json={
        "instance_code": inst.code, "password": password,
        "server_id": server_id, "server_name": name, "version": "1.3.0"})
    assert r.status_code == 200, r.text
    return r.json()


def connect(client, token):
    return client.websocket_connect("/api/v1/control", headers={"Authorization": f"Bearer {token}"})


def hello(ws, name="Dachboden", fp=FP_A):
    ws.send_json({"type": "hello", "server_name": name, "version": "1.3.0", "cert_fp": fp})
    welcome = ws.receive_json()
    assert welcome["type"] == "welcome", welcome
    return welcome


def recv(ws, type_: str, max_skip: int = 20) -> dict:
    """Nächste Nachricht des gewünschten Typs (andere, z. B. shares oder lease, werden übersprungen)."""
    for _ in range(max_skip):
        msg = ws.receive_json()
        if msg["type"] == type_:
            return msg
    raise AssertionError(f"keine Nachricht vom Typ {type_}")


def expect_close(ws, max_skip: int = 20) -> int:
    for _ in range(max_skip):
        try:
            ws.receive_json()
        except WebSocketDisconnect as exc:
            return exc.code
    raise AssertionError("Verbindung wurde nicht geschlossen")
