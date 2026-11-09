"""Rendezvous-Endpunkt (UDP, wie STUN): meldet einem rtltcp.server seine reflexive Adresse.

Paketformat siehe docs/protocol.md §3. Alle Mehrbyte-Zahlen in Netzwerk-Byte-Reihenfolge (big-endian).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import socket
import struct
import uuid
from typing import Callable

log = logging.getLogger("roi.rendezvous")

MAGIC = b"ROI1"
TYPE_REQUEST = 1
TYPE_RESPONSE = 2
PACKET_SIZE = 64
MAC_OFFSET = 48
MAC_SIZE = 16


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()[:MAC_SIZE]


def build_request(session: uuid.UUID, nonce: bytes, key: bytes) -> bytes:
    """Für Tests und als Referenz für die Gegenseite."""
    assert len(nonce) == 8
    head = MAGIC + bytes([TYPE_REQUEST]) + session.bytes + nonce + bytes(19)
    assert len(head) == MAC_OFFSET
    return head + mac(key, head)


def parse_request(packet: bytes) -> tuple[uuid.UUID, bytes] | None:
    """Prüft Länge, Kennung, Typ und Nullbytes (ohne MAC). Liefert (session, nonce)."""
    if len(packet) != PACKET_SIZE or packet[:4] != MAGIC or packet[4] != TYPE_REQUEST:
        return None
    if any(packet[29:MAC_OFFSET]):
        return None
    return uuid.UUID(bytes=packet[5:21]), packet[21:29]


def build_response(session: uuid.UUID, nonce: bytes, host: str, port: int, key: bytes) -> bytes:
    ip = ipaddress.ip_address(host.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address):
        family, addr = 4, ipaddress.IPv6Address(f"::ffff:{ip}").packed
    else:
        family, addr = 6, ip.packed
    head = MAGIC + bytes([TYPE_RESPONSE]) + session.bytes + nonce + bytes([family]) + struct.pack("!H", port) + addr
    assert len(head) == MAC_OFFSET
    return head + mac(key, head)


def parse_response(packet: bytes, key: bytes) -> tuple[uuid.UUID, bytes, str, int] | None:
    """Für Tests: (session, nonce, ip, port)."""
    if len(packet) != PACKET_SIZE or packet[:4] != MAGIC or packet[4] != TYPE_RESPONSE:
        return None
    if not hmac.compare_digest(packet[MAC_OFFSET:], mac(key, packet[:MAC_OFFSET])):
        return None
    family = packet[29]
    (port,) = struct.unpack("!H", packet[30:32])
    ip6 = ipaddress.IPv6Address(packet[32:48])
    ip = str(ip6.ipv4_mapped) if family == 4 else str(ip6)
    return uuid.UUID(bytes=packet[5:21]), packet[21:29], ip, port


KeyLookup = Callable[[uuid.UUID], "bytes | None"]


class Responder:
    """Beantwortet nur gültig signierte Anfragen laufender Sitzungen, Antwort genau so groß wie die Anfrage."""

    MAX_PER_SESSION = 200

    def __init__(self, lookup: KeyLookup):
        self.lookup = lookup
        self.counts: dict[uuid.UUID, int] = {}

    def handle(self, data: bytes, host: str, port: int) -> bytes | None:
        parsed = parse_request(data)
        if parsed is None:
            return None
        session, nonce = parsed
        key = self.lookup(session)
        if key is None:
            return None
        if not hmac.compare_digest(data[MAC_OFFSET:], mac(key, data[:MAC_OFFSET])):
            return None
        count = self.counts.get(session, 0)
        if count >= self.MAX_PER_SESSION:
            return None
        self.counts[session] = count + 1
        if len(self.counts) > 10000:
            self.counts.clear()
        try:
            return build_response(session, nonce, host, port, key)
        except ValueError:
            return None

    def forget(self, session: uuid.UUID) -> None:
        self.counts.pop(session, None)


class RendezvousProtocol(asyncio.DatagramProtocol):
    """Ein Protokoll pro Port, damit die Antwort vom angefragten Port kommt."""

    def __init__(self, responder: Responder):
        self.responder = responder
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        reply = self.responder.handle(data, addr[0], addr[1])
        if reply is not None and self.transport is not None:
            self.transport.sendto(reply, addr)

    def error_received(self, exc):  # pragma: no cover - ICMP-Fehler ignorieren
        pass


def _make_socket(bind: str, port: int) -> socket.socket:
    ip = ipaddress.ip_address(bind)
    if ip.version == 6:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        if ip == ipaddress.IPv6Address("::"):
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # Dual-Stack
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    sock.setblocking(False)
    return sock


async def start(bind: str, ports, responder: Responder) -> list[asyncio.DatagramTransport]:
    loop = asyncio.get_running_loop()
    transports = []
    for port in ports:
        try:
            sock = _make_socket(bind, port)
        except OSError:
            if bind != "::":
                raise
            log.warning("IPv6 nicht verfügbar, Rendezvous nur über IPv4 auf Port %s", port)
            sock = _make_socket("0.0.0.0", port)
        transport, _ = await loop.create_datagram_endpoint(lambda: RendezvousProtocol(responder), sock=sock)
        transports.append(transport)
        log.info("Rendezvous lauscht auf UDP %s:%s", bind, port)
    return transports
