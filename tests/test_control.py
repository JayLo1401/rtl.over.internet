import base64
import time

import pytest

from app.db import Device, StreamSession
from tests.conftest import FP_A, FP_B, connect, enroll, expect_close, hello, make_instance, recv

STICK = {"stick_id": "00000001", "name": "Standort1 Stick 1", "tuner": "R828D", "state": "ready",
         "compression": False}


@pytest.fixture
def pair(client, app):
    """Instanz mit Anbieter (A) und Nutzer (B), beide angemeldet."""
    inst = make_instance(app)
    a = enroll(client, inst, server_id="srv-a", name="Dachboden")
    b = enroll(client, inst, server_id="srv-b", name="Wohnzimmer")
    return inst, a, b


def _connect_pair(client, a, b):
    wa = connect(client, a["device_token"]).__enter__()
    hello(wa, "Dachboden", FP_A)
    wb = connect(client, b["device_token"]).__enter__()
    hello(wb, "Wohnzimmer", FP_B)
    wa.send_json({"type": "announce", "shares": [STICK]})
    shares = recv(wb, "shares")
    while not shares["shares"]:
        shares = recv(wb, "shares")
    return wa, wb, shares


def _close(*wss):
    for ws in wss:
        try:
            ws.__exit__(None, None, None)
        except Exception:
            pass


def _open_and_accept(wa, wb, share_id):
    wb.send_json({"type": "open_stream", "req": "a1", "share_id": share_id})
    req = recv(wa, "stream_request")
    wa.send_json({"type": "stream_accept", "session": req["session"]})
    return req, recv(wa, "session"), recv(wb, "session")


def test_invalid_token_closes_4401(client):
    with connect(client, "unsinn") as ws:
        assert expect_close(ws) == 4401
    with client.websocket_connect("/api/v1/control") as ws:
        assert expect_close(ws) == 4401


def test_disabled_instance_closes_4403(client, app, pair):
    inst, a, _ = pair
    with app.state.db.session() as s:
        s.get(type(inst), inst.id).enabled = False
        s.commit()
    with connect(client, a["device_token"]) as ws:
        assert expect_close(ws) == 4403


def test_hello_required(client, pair):
    _, a, _ = pair
    with connect(client, a["device_token"]) as ws:
        ws.send_json({"type": "announce", "shares": []})
        assert expect_close(ws) == 1008
    with connect(client, a["device_token"]) as ws:
        ws.send_json({"type": "hello", "cert_fp": "kein-fingerprint"})
        assert expect_close(ws) == 1008


def test_welcome_and_shares(client, pair):
    inst, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        assert shares["shares"] == [{
            "share_id": f"{a['device_id']}:00000001",
            "provider": {"device_id": a["device_id"], "name": "Dachboden"},
            "stick_id": "00000001", "name": "Standort1 Stick 1", "tuner": "R828D", "state": "ready",
            "online": True, "compression": False, "location": "", "antenna": ""}]
        own = recv(wa, "shares")
        while not own["shares"]:
            own = recv(wa, "shares")
        assert own["shares"][0]["provider"]["device_id"] == a["device_id"]  # eigene Freigaben auch
    finally:
        _close(wa)
    offline = recv(wb, "shares")
    assert offline["shares"][0]["online"] is False
    _close(wb)


def test_location_and_antenna_passed_through(client, app, pair):
    from tests.conftest import login

    inst, a, b = pair
    wa = connect(client, a["device_token"]).__enter__()
    hello(wa)
    wb = connect(client, b["device_token"]).__enter__()
    hello(wb, "Wohnzimmer", FP_B)
    try:
        wa.send_json({"type": "announce", "shares": [
            {**STICK, "location": "Wien Dach", "antenna": "DAB-Rundstrahler"},
            {**STICK, "stick_id": "00000002", "location": "x" * 150, "antenna": "Zeile\nUmbruch"},
            {**STICK, "stick_id": "00000003"}]})
        shares = recv(wb, "shares")
        while len(shares["shares"]) < 3:
            shares = recv(wb, "shares")
        by_id = {s["stick_id"]: s for s in shares["shares"]}
        assert (by_id["00000001"]["location"], by_id["00000001"]["antenna"]) == ("Wien Dach", "DAB-Rundstrahler")
        assert by_id["00000002"]["location"] == "x" * 100  # gekürzt
        assert by_id["00000002"]["antenna"] == "ZeileUmbruch"  # Steuerzeichen entfernt
        assert (by_id["00000003"]["location"], by_id["00000003"]["antenna"]) == ("", "")  # ältere Server
        # falscher Typ wird abgelehnt
        wa.send_json({"type": "announce", "shares": [{**STICK, "location": 5}]})
        assert recv(wa, "error")["code"] == "BAD_REQUEST"
        login(client)
        page = client.get(f"/instances/{inst.id}").text
        assert "Wien Dach" in page and "DAB-Rundstrahler" in page
        exp = {s["stick_id"]: s for s in client.get("/export.json").json()["shares"]}
        assert exp["00000001"]["antenna"] == "DAB-Rundstrahler"
    finally:
        _close(wa, wb)


def test_welcome_contents(client, pair, settings):
    inst, a, _ = pair
    with connect(client, a["device_token"]) as ws:
        w = hello(ws)
        assert w["device_id"] == a["device_id"]
        assert w["instance"] == {"id": inst.id, "name": inst.name}
        assert w["rendezvous"] == [{"host": "testserver", "port": 3478}, {"host": "testserver", "port": 3479}]


def test_full_session_flow(client, app, pair):
    inst, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        share_id = shares["shares"][0]["share_id"]
        req, sa, sb = _open_and_accept(wa, wb, share_id)
        assert req["stick_id"] == "00000001"
        assert req["from"] == {"device_id": b["device_id"], "name": "Wohnzimmer"}
        sid = req["session"]
        assert sa["role"] == "server" and sb["role"] == "client"
        assert sb["req"] == "a1" and "req" not in sa
        assert sa["punch_key"] == sb["punch_key"] and len(base64.b64decode(sa["punch_key"])) == 32
        assert sa["peer"] == {"device_id": b["device_id"], "name": "Wohnzimmer", "cert_fp": FP_B}
        assert sb["peer"] == {"device_id": a["device_id"], "name": "Dachboden", "cert_fp": FP_A}
        assert sa["lease"] == 60

        ca = ["[2a02:1::5]:51234", "192.168.1.5:51234", "84.115.1.2:40211"]
        cb = ["[2a02:2::7]:40000"]
        wa.send_json({"type": "candidates", "session": sid, "candidates": ca, "nat": "endpoint_independent"})
        wb.send_json({"type": "candidates", "session": sid, "candidates": cb, "nat": "symmetric"})
        pa, pb = recv(wa, "punch"), recv(wb, "punch")
        assert pa["peer_candidates"] == cb and pa["peer_nat"] == "symmetric"
        assert pb["peer_candidates"] == ca and pb["peer_nat"] == "endpoint_independent"
        assert pa["start_at"] == pb["start_at"] and pa["start_at"] > time.time() * 1000 - 1000

        wa.send_json({"type": "punch_result", "session": sid, "ok": True, "path": "[2a02:2::7]:40000"})
        wb.send_json({"type": "punch_result", "session": sid, "ok": True, "path": "[2a02:1::5]:51234"})
        lease = recv(wb, "lease")
        assert lease == {"type": "lease", "session": sid, "ttl": 60}
        recv(wa, "lease")
        assert app.state.hub.sessions[sid].state == "connected"

        wb.send_json({"type": "stream_end", "session": sid, "bytes": 123456789, "reason": "client left"})
        revoke = recv(wa, "revoke")
        assert revoke == {"type": "revoke", "session": sid, "reason": "peer_ended"}
        wa.send_json({"type": "stream_end", "session": sid, "bytes": 123456000, "reason": "peer gone"})
        # nachträgliche Meldung wird noch verbucht
        wa.send_json({"type": "announce", "shares": [STICK]})
        recv(wa, "shares")
        with app.state.db.session() as s:
            row = s.get(StreamSession, sid)
            assert row.state == "ended" and row.result == "ended"
            assert row.bytes_client == 123456789 and row.bytes_server == 123456000
            assert row.nat_server == "endpoint_independent" and row.nat_client == "symmetric"
            assert row.path == "[2a02:2::7]:40000"
        assert sid not in app.state.hub.sessions
    finally:
        _close(wa, wb)


def test_reject(client, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        wb.send_json({"type": "open_stream", "req": "r1", "share_id": shares["shares"][0]["share_id"]})
        req = recv(wa, "stream_request")
        wa.send_json({"type": "stream_reject", "session": req["session"], "code": "BUSY",
                      "message": "in use by 192.168.1.20"})
        err = recv(wb, "error")
        assert err["req"] == "r1" and err["code"] == "REJECTED" and err["provider_code"] == "BUSY"
        assert err["message"] == "in use by 192.168.1.20"
    finally:
        _close(wa, wb)


def test_accept_timeout(client, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        wb.send_json({"type": "open_stream", "req": "t1", "share_id": shares["shares"][0]["share_id"]})
        req = recv(wa, "stream_request")
        err = recv(wb, "error")
        assert err["code"] == "TIMEOUT" and err["req"] == "t1"
        assert recv(wa, "revoke") == {"type": "revoke", "session": req["session"], "reason": "timeout"}
        # zu spätes accept wird ignoriert
        wa.send_json({"type": "stream_accept", "session": req["session"]})
    finally:
        _close(wa, wb)


def test_candidates_timeout(client, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        req, _, _ = _open_and_accept(wa, wb, shares["shares"][0]["share_id"])
        wa.send_json({"type": "candidates", "session": req["session"], "candidates": [], "nat": "none"})
        assert recv(wb, "error")["code"] == "TIMEOUT"
        assert recv(wa, "error")["code"] == "TIMEOUT"
    finally:
        _close(wa, wb)


def test_direct_connection_failed(client, app, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        req, _, _ = _open_and_accept(wa, wb, shares["shares"][0]["share_id"])
        sid = req["session"]
        for ws, nat in ((wa, "symmetric"), (wb, "symmetric")):
            ws.send_json({"type": "candidates", "session": sid, "candidates": ["100.64.1.2:4000"], "nat": nat})
        recv(wa, "punch"), recv(wb, "punch")
        wa.send_json({"type": "punch_result", "session": sid, "ok": False})
        wb.send_json({"type": "punch_result", "session": sid, "ok": False})
        err = recv(wb, "error")
        assert err["code"] == "DIRECT_CONNECTION_FAILED" and err["req"] == "a1"
        assert err["nat"] == {"server": "symmetric", "client": "symmetric"}
        assert "IPv6" in err["message"]
        assert recv(wa, "error")["code"] == "DIRECT_CONNECTION_FAILED"
        with app.state.db.session() as s:
            assert s.get(StreamSession, sid).result == "direct_failed"
    finally:
        _close(wa, wb)


def test_punch_timeout_without_results(client, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        req, _, _ = _open_and_accept(wa, wb, shares["shares"][0]["share_id"])
        for ws in (wa, wb):
            ws.send_json({"type": "candidates", "session": req["session"], "candidates": [], "nat": "unknown"})
        assert recv(wb, "error")["code"] == "DIRECT_CONNECTION_FAILED"
    finally:
        _close(wa, wb)


def test_open_stream_errors(client, app, pair):
    inst, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        share_id = shares["shares"][0]["share_id"]
        cases = [("x1", "999:00000001", "NOT_FOUND"), ("x2", f"{a['device_id']}:fehlt", "NOT_FOUND"),
                 ("x3", "unsinn", "NOT_FOUND")]
        for req, sid, code in cases:
            wb.send_json({"type": "open_stream", "req": req, "share_id": sid})
            err = recv(wb, "error")
            assert (err["req"], err["code"]) == (req, code)
        # eigene Freigabe
        wa.send_json({"type": "open_stream", "req": "own", "share_id": share_id})
        assert recv(wa, "error")["code"] == "NOT_FOUND"
        # Limit
        with app.state.db.session() as s:
            s.get(type(inst), inst.id).max_streams = 0
            s.commit()
        wb.send_json({"type": "open_stream", "req": "lim", "share_id": share_id})
        assert recv(wb, "error")["code"] == "LIMIT_REACHED"
        # deaktiviert (nur in der DB, ohne Trennen)
        with app.state.db.session() as s:
            row = s.get(type(inst), inst.id)
            row.max_streams, row.enabled = None, False
            s.commit()
        wb.send_json({"type": "open_stream", "req": "dis", "share_id": share_id})
        assert recv(wb, "error")["code"] == "INSTANCE_DISABLED"
    finally:
        _close(wb)
    _close(wa)


def test_peer_offline(client, app, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    share_id = shares["shares"][0]["share_id"]
    _close(wa)
    try:
        wb.send_json({"type": "open_stream", "req": "p1", "share_id": share_id})
        assert recv(wb, "error")["code"] == "PEER_OFFLINE"
    finally:
        _close(wb)


def test_other_instance_cannot_open(client, app, pair):
    _, a, b = pair
    other = make_instance(app, name="Fremd", password="fremdes-passwort")
    c = enroll(client, other, server_id="srv-c", password="fremdes-passwort")
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        with connect(client, c["device_token"]) as wc:
            hello(wc)
            assert recv(wc, "shares")["shares"] == []
            wc.send_json({"type": "open_stream", "req": "f1", "share_id": shares["shares"][0]["share_id"]})
            assert recv(wc, "error")["code"] == "NOT_FOUND"
    finally:
        _close(wa, wb)


def test_peer_disconnect_revokes_session(client, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        req, _, _ = _open_and_accept(wa, wb, shares["shares"][0]["share_id"])
        _close(wb)
        assert recv(wa, "revoke") == {"type": "revoke", "session": req["session"], "reason": "peer_offline"}
    finally:
        _close(wa)


def test_duplicate_connection_4409(client, pair):
    _, a, _ = pair
    with connect(client, a["device_token"]) as w1:
        hello(w1)
        with connect(client, a["device_token"]) as w2:
            hello(w2)
            assert expect_close(w1) == 4409


def test_admin_revoke_device(client, app, pair):
    from tests.conftest import csrf_from, login

    inst, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        req, _, _ = _open_and_accept(wa, wb, shares["shares"][0]["share_id"])
        login(client)
        csrf = csrf_from(client.get(f"/instances/{inst.id}").text)
        client.post(f"/devices/{a['device_id']}/revoke", data={"csrf": csrf})
        assert recv(wb, "revoke") == {"type": "revoke", "session": req["session"], "reason": "token_revoked"}
        assert expect_close(wa) == 4401
        # Freigaben des widerrufenen Anbieters verschwinden
        assert recv(wb, "shares")["shares"] == []
        with app.state.db.session() as s:
            dev = s.get(Device, a["device_id"])
            assert dev.revoked_at is not None and dev.token_hash is None
    finally:
        _close(wa, wb)
    with connect(client, a["device_token"]) as ws:
        assert expect_close(ws) == 4401


def test_admin_disable_instance(client, app, pair):
    from tests.conftest import csrf_from, login

    inst, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        req, _, _ = _open_and_accept(wa, wb, shares["shares"][0]["share_id"])
        login(client)
        csrf = csrf_from(client.get(f"/instances/{inst.id}").text)
        client.post(f"/instances/{inst.id}/disable", data={"csrf": csrf})
        assert recv(wa, "revoke")["reason"] == "instance_disabled"
        assert expect_close(wa) == 4403
        assert expect_close(wb) == 4403
    finally:
        _close(wa, wb)


def test_new_password_keeps_or_revokes_devices(client, app, pair):
    from tests.conftest import csrf_from, login

    inst, a, b = pair
    login(client)
    with connect(client, a["device_token"]) as wa:
        hello(wa)
        csrf = csrf_from(client.get(f"/instances/{inst.id}/password").text)
        client.post(f"/instances/{inst.id}/password", data={"csrf": csrf})
        wa.send_json({"type": "announce", "shares": [STICK]})
        assert recv(wa, "shares")  # Verbindung besteht weiter
        client.post(f"/instances/{inst.id}/password", data={"csrf": csrf, "revoke_tokens": "1"})
        assert expect_close(wa) == 4401
    with app.state.db.session() as s:
        assert s.get(Device, b["device_id"]).revoked_at is not None


def test_bad_messages(client, pair):
    _, a, b = pair
    wa, wb, shares = _connect_pair(client, a, b)
    try:
        req, _, _ = _open_and_accept(wa, wb, shares["shares"][0]["share_id"])
        wa.send_json({"type": "candidates", "session": req["session"], "candidates": ["evil.example:80"]})
        err = recv(wa, "error")
        assert err["code"] == "BAD_REQUEST" and err["session"] == req["session"]
        wa.send_json({"type": "announce", "shares": [{"stick_id": "x" * 100}]})
        assert recv(wa, "error")["code"] == "BAD_REQUEST"
        wa.send_json({"type": "irgendwas_neues", "foo": 1})  # unbekannt: ignoriert
        wa.send_text("kein json")
        assert expect_close(wa) == 1008
    finally:
        _close(wa, wb)


def test_valid_candidate():
    from app.control import valid_candidate

    good = ["[2a02:8388::1]:51234", "192.168.1.5:1", "84.115.1.2:65535", "[::ffff:1.2.3.4]:5"]
    bad = ["2a02::1:5", "[1.2.3.4]:5", "1.2.3.4", "1.2.3.4:0", "1.2.3.4:70000", "host:80", "[zz::1]:5",
           "999.1.1.1:5", 5, None]
    assert all(valid_candidate(c) for c in good)
    assert not any(valid_candidate(c) for c in bad)
