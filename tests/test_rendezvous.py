import asyncio
import os
import socket
import uuid

from app import rendezvous as rv

KEY = os.urandom(32)
SID = uuid.uuid4()
NONCE = b"12345678"


def _responder(keys=None):
    keys = {SID: KEY} if keys is None else keys
    return rv.Responder(lambda s: keys.get(s))


def test_packet_layout():
    req = rv.build_request(SID, NONCE, KEY)
    assert len(req) == 64
    assert req[:4] == b"ROI1" and req[4] == 1
    assert req[5:21] == SID.bytes and req[21:29] == NONCE
    assert req[29:48] == bytes(19)
    assert req[48:] == rv.mac(KEY, req[:48])


def test_ipv4_response():
    req = rv.build_request(SID, NONCE, KEY)
    resp = _responder().handle(req, "84.115.1.2", 40211)
    assert resp is not None and len(resp) == len(req) == 64
    assert resp[29] == 4
    assert resp[30:32] == (40211).to_bytes(2, "big")
    assert resp[32:48] == bytes(10) + b"\xff\xff" + bytes([84, 115, 1, 2])
    assert rv.parse_response(resp, KEY) == (SID, NONCE, "84.115.1.2", 40211)


def test_ipv6_and_mapped_response():
    req = rv.build_request(SID, NONCE, KEY)
    r = _responder()
    assert rv.parse_response(r.handle(req, "2a02:8388::1", 51234), KEY) == (SID, NONCE, "2a02:8388::1", 51234)
    # Dual-Stack-Socket liefert IPv4 als ::ffff:a.b.c.d
    resp = r.handle(req, "::ffff:10.0.0.7", 5000)
    assert resp[29] == 4
    assert rv.parse_response(resp, KEY)[2] == "10.0.0.7"


def test_rejects_invalid_packets():
    r = _responder()
    req = rv.build_request(SID, NONCE, KEY)
    assert r.handle(req[:63], "1.2.3.4", 1) is None  # zu kurz
    assert r.handle(req + b"\0", "1.2.3.4", 1) is None  # zu lang
    assert r.handle(b"ROI2" + req[4:], "1.2.3.4", 1) is None  # Kennung
    tampered = bytearray(req)
    tampered[60] ^= 1
    assert r.handle(bytes(tampered), "1.2.3.4", 1) is None  # MAC
    other_key = rv.build_request(SID, NONCE, os.urandom(32))
    assert r.handle(other_key, "1.2.3.4", 1) is None  # falscher Schlüssel
    unknown = rv.build_request(uuid.uuid4(), NONCE, KEY)
    assert r.handle(unknown, "1.2.3.4", 1) is None  # keine laufende Sitzung
    padded = bytearray(req)
    padded[40] = 1
    padded[48:] = rv.mac(KEY, bytes(padded[:48]))
    assert r.handle(bytes(padded), "1.2.3.4", 1) is None  # Füllbytes müssen 0 sein
    resp_type = bytearray(req)
    resp_type[4] = 2
    assert r.handle(bytes(resp_type), "1.2.3.4", 1) is None


def test_per_session_limit():
    r = _responder()
    req = rv.build_request(SID, NONCE, KEY)
    answered = sum(r.handle(req, "1.2.3.4", 1) is not None for _ in range(rv.Responder.MAX_PER_SESSION + 50))
    assert answered == rv.Responder.MAX_PER_SESSION


def test_udp_two_ports_nat_detection():
    """Echte Sockets: derselbe lokale Socket fragt beide Ports an und bekommt beide Male dieselbe Adresse."""

    async def run():
        socks = [rv._make_socket("127.0.0.1", 0) for _ in range(2)]
        ports = [s.getsockname()[1] for s in socks]
        for s in socks:
            s.close()
        transports = await rv.start("127.0.0.1", ports, _responder())
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            client.settimeout(2)
            results = []
            for port in ports:
                await asyncio.get_running_loop().run_in_executor(
                    None, client.sendto, rv.build_request(SID, NONCE, KEY), ("127.0.0.1", port))
                data, src = await asyncio.get_running_loop().run_in_executor(None, client.recvfrom, 100)
                assert src[1] == port  # Antwort kommt vom angefragten Port
                results.append(rv.parse_response(data, KEY))
            client.close()
            return results
        finally:
            for t in transports:
                t.close()

    results = asyncio.run(run())
    assert results[0] == results[1]
    assert results[0][2] == "127.0.0.1"
