"""Steuerkanal (WebSocket) und Koordination der Stream-Sitzungen. Siehe docs/protocol.md §2."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import secrets
import time
import uuid
from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy import select

from .config import Settings
from .db import Database, Device, Instance, Share, StreamSession, audit, utcnow
from .rendezvous import Responder
from .security import RateCounter, client_ip, token_hash

log = logging.getLogger("roi.control")

MAX_MESSAGE = 64 * 1024
MAX_SHARES = 64
MAX_CANDIDATES = 16
MAX_PENDING_PER_DEVICE = 8

CLOSE_TOKEN_INVALID = 4401
CLOSE_INSTANCE_DISABLED = 4403
CLOSE_REPLACED = 4409
CLOSE_POLICY = 1008

NAT_TYPES = {"endpoint_independent", "symmetric", "none", "unknown"}
_FP_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{64}$")
_STICK_RE = re.compile(r"^[\x21-\x7e]{1,64}$")
_CAND_RE = re.compile(r"^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$|^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


class BadMessage(ValueError):
    pass


def _str(msg: dict, key: str, maxlen: int, *, required: bool = True, default: str = "") -> str:
    value = msg.get(key)
    if value is None:
        if required:
            raise BadMessage(f"{key} fehlt")
        return default
    if not isinstance(value, str) or len(value) > maxlen:
        raise BadMessage(f"{key} ungültig")
    return value


def _clean(text: str, maxlen: int) -> str:
    return "".join(ch for ch in text if ch.isprintable())[:maxlen]


def valid_candidate(value) -> bool:
    if not isinstance(value, str) or len(value) > 64:
        return False
    m = _CAND_RE.match(value)
    if not m:
        return False
    host, port = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if m.group(1) and ip.version != 6:
        return False
    return 0 < int(port) < 65536


def nat_hint(nat_server: str, nat_client: str) -> str:
    if "symmetric" in (nat_server, nat_client):
        return ("Mindestens eine Seite hat symmetrisches NAT (typisch bei CGNAT). "
                "Ohne Relay geht es dann nur über IPv6: IPv6 an beiden Routern aktivieren.")
    return "Keine direkte Verbindung möglich. IPv6 an beiden Routern aktivieren bzw. prüfen, ob die Firewall UDP blockiert."


@dataclass(eq=False)
class Conn:
    ws: WebSocket
    device_id: int
    instance_id: int
    name: str
    cert_fp: str
    ip: str
    version: str = ""
    connected_at: datetime = field(default_factory=utcnow)
    closed: bool = False

    async def send(self, msg: dict) -> None:
        if self.closed:
            return
        try:
            await self.ws.send_text(json.dumps(msg, ensure_ascii=False, separators=(",", ":")))
        except Exception:  # Verbindung weg; das Aufräumen übernimmt die Empfangsschleife
            self.closed = True

    async def close(self, code: int, reason: str = "") -> None:
        if self.closed:
            return
        self.closed = True
        try:
            await self.ws.close(code, reason)
        except Exception:
            pass


@dataclass(eq=False)
class Sess:
    id: str
    instance_id: int
    provider: Conn
    client: Conn
    stick_id: str
    stick_name: str
    req: str
    state: str = "requested"  # requested → accepted → punching → connected
    punch_key: bytes | None = None
    candidates: dict = field(default_factory=dict)  # role -> (list, nat)
    results: dict = field(default_factory=dict)  # role -> (ok, path)
    bytes: dict = field(default_factory=dict)  # role -> int
    path: str = ""
    timer: asyncio.Task | None = None
    created: float = field(default_factory=time.monotonic)

    @property
    def uuid(self) -> uuid.UUID:
        return uuid.UUID(self.id)

    def role_of(self, conn: Conn) -> str | None:
        if conn is self.provider:
            return "server"
        if conn is self.client:
            return "client"
        return None

    def other(self, conn: Conn) -> Conn:
        return self.client if conn is self.provider else self.provider


class Hub:
    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self.conns: dict[int, Conn] = {}
        self.sessions: dict[str, Sess] = {}
        self.recent: dict[str, float] = {}  # beendete Sitzungen, für nachträgliche stream_end-Meldungen
        self.responder = Responder(self.punch_key_for)
        self.msg_rate = RateCounter(limit=100, window=10.0)
        self._lease_task: asyncio.Task | None = None

    # ------------------------------------------------------------ Lebenszyklus

    def start(self) -> None:
        self._lease_task = asyncio.create_task(self._lease_loop())

    async def stop(self) -> None:
        if self._lease_task:
            self._lease_task.cancel()
        for sess in list(self.sessions.values()):
            await self._end(sess, "aborted", "Vermittler wird beendet", revoke_reason="shutdown")
        for conn in list(self.conns.values()):
            await conn.close(1012, "restart")

    def punch_key_for(self, session: uuid.UUID) -> bytes | None:
        sess = self.sessions.get(str(session))
        if sess and sess.punch_key and sess.state in ("accepted", "punching", "connected"):
            return sess.punch_key
        return None

    async def _lease_loop(self) -> None:
        while True:
            await asyncio.sleep(self.settings.lease_interval)
            for sess in list(self.sessions.values()):
                if sess.state in ("accepted", "punching", "connected"):
                    msg = {"type": "lease", "session": sess.id, "ttl": self.settings.lease_ttl}
                    await sess.provider.send(msg)
                    await sess.client.send(msg)
            now = time.monotonic()
            for sid, expires in list(self.recent.items()):
                if expires < now:
                    del self.recent[sid]

    # ------------------------------------------------------------ Verbindung

    async def handle(self, ws: WebSocket) -> None:
        ip = client_ip(ws, self.settings.trusted_proxies)
        auth = ws.headers.get("authorization", "")
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""

        with self.db.session() as s:
            device = s.scalar(select(Device).where(Device.token_hash == token_hash(token))) if token else None
            if device is not None and device.revoked_at is not None:
                device = None
            instance = s.get(Instance, device.instance_id) if device else None
            device_id = device.id if device else None
            instance_info = {"id": instance.id, "name": instance.name} if instance else None
            enabled = bool(instance and instance.enabled)

        await ws.accept()
        if device_id is None or instance_info is None:
            await ws.close(CLOSE_TOKEN_INVALID, "token invalid")
            return
        if not enabled:
            await ws.close(CLOSE_INSTANCE_DISABLED, "instance disabled")
            return

        try:
            hello = await asyncio.wait_for(self._receive(ws), timeout=self.settings.hello_timeout)
            if hello.get("type") != "hello":
                raise BadMessage("hello erwartet")
            cert_fp = _str(hello, "cert_fp", 95)
            if not _FP_RE.match(cert_fp):
                raise BadMessage("cert_fp ungültig")
            name = _clean(_str(hello, "server_name", 100, required=False), 100)
            version = _clean(_str(hello, "version", 32, required=False), 32)
        except (asyncio.TimeoutError, BadMessage, WebSocketDisconnect, ValueError) as exc:
            try:
                await ws.close(CLOSE_POLICY, str(exc)[:100] if isinstance(exc, BadMessage) else "hello")
            except Exception:
                pass
            return

        with self.db.session() as s:
            device = s.get(Device, device_id)
            if device is None or device.revoked_at is not None:
                await ws.close(CLOSE_TOKEN_INVALID, "token invalid")
                return
            if name:
                device.server_name = name
            if version:
                device.version = version
            device.last_seen = utcnow()
            device.last_ip = ip
            name = device.server_name
            s.commit()

        conn = Conn(ws=ws, device_id=device_id, instance_id=instance_info["id"], name=name,
                    cert_fp=cert_fp, ip=ip, version=version)
        old = self.conns.get(device_id)
        self.conns[device_id] = conn
        if old is not None:
            await self._drop(old, CLOSE_REPLACED, "replaced")

        rv = [{"host": self.settings.rendezvous_host, "port": p} for p in self.settings.rendezvous_ports]
        await conn.send({"type": "welcome", "device_id": device_id, "instance": instance_info, "rendezvous": rv})
        await self.broadcast_shares(conn.instance_id)
        log.info("Gerät %s (%s) verbunden von %s", device_id, name, ip)

        try:
            while not conn.closed:
                msg = await self._receive(ws)
                if self.msg_rate.hit(str(device_id)):
                    await self._drop(conn, CLOSE_POLICY, "rate limit")
                    break
                try:
                    await self._dispatch(conn, msg)
                except BadMessage as exc:
                    err = {"type": "error", "code": "BAD_REQUEST", "message": str(exc)}
                    for key in ("req", "session"):
                        if isinstance(msg.get(key), str) and len(msg[key]) <= 64:
                            err[key] = msg[key]
                    await conn.send(err)
        except WebSocketDisconnect:
            pass
        except BadMessage:
            await self._drop(conn, CLOSE_POLICY, "bad message")
        except Exception:  # noqa: BLE001 - Verbindung sauber abbauen, nie Details nach außen
            log.exception("Fehler im Steuerkanal von Gerät %s", device_id)
        finally:
            await self._drop(conn, None, "")

    async def _receive(self, ws: WebSocket) -> dict:
        text = await ws.receive_text()
        if len(text) > MAX_MESSAGE:
            raise BadMessage("Nachricht zu groß")
        try:
            msg = json.loads(text)
        except ValueError as exc:
            raise BadMessage("kein JSON") from exc
        if not isinstance(msg, dict) or not isinstance(msg.get("type"), str):
            raise BadMessage("type fehlt")
        return msg

    async def _drop(self, conn: Conn, code: int | None, reason: str) -> None:
        """Verbindung entfernen: Sitzungen beenden, Gegenseiten benachrichtigen, Freigaben neu verteilen."""
        first = self.conns.get(conn.device_id) is conn
        if first:
            del self.conns[conn.device_id]
        if code is not None:
            await conn.close(code, reason)
        else:
            conn.closed = True
        for sess in [x for x in self.sessions.values() if x.provider is conn or x.client is conn]:
            await self._end(sess, "aborted", "Gegenstelle offline", revoke_reason="peer_offline")
        if first:
            with self.db.session() as s:
                device = s.get(Device, conn.device_id)
                if device:
                    device.last_seen = utcnow()
                    s.commit()
            await self.broadcast_shares(conn.instance_id)
            log.info("Gerät %s getrennt", conn.device_id)

    # ------------------------------------------------------------ Nachrichten

    async def _dispatch(self, conn: Conn, msg: dict) -> None:
        handler = {
            "announce": self._on_announce,
            "open_stream": self._on_open_stream,
            "stream_accept": self._on_stream_accept,
            "stream_reject": self._on_stream_reject,
            "candidates": self._on_candidates,
            "punch_result": self._on_punch_result,
            "stream_end": self._on_stream_end,
        }.get(msg["type"])
        if handler is not None:  # unbekannte Typen werden ignoriert
            await handler(conn, msg)

    async def _on_announce(self, conn: Conn, msg: dict) -> None:
        shares = msg.get("shares")
        if not isinstance(shares, list) or len(shares) > MAX_SHARES:
            raise BadMessage("shares ungültig")
        clean = {}
        for item in shares:
            if not isinstance(item, dict):
                raise BadMessage("shares ungültig")
            stick_id = _str(item, "stick_id", 64)
            if not _STICK_RE.match(stick_id):
                raise BadMessage("stick_id ungültig")
            clean[stick_id] = {
                "name": _clean(_str(item, "name", 100, required=False), 100),
                "tuner": _clean(_str(item, "tuner", 32, required=False), 32),
                "state": _clean(_str(item, "state", 32, required=False, default="unknown"), 32),
                "compression": bool(item.get("compression", False)),
            }
        with self.db.session() as s:
            existing = {sh.stick_id: sh for sh in s.scalars(select(Share).where(Share.device_id == conn.device_id))}
            for stick_id, sh in existing.items():
                if stick_id not in clean:
                    s.delete(sh)
            for stick_id, data in clean.items():
                sh = existing.get(stick_id) or Share(device_id=conn.device_id, stick_id=stick_id)
                for k, v in data.items():
                    setattr(sh, k, v)
                sh.updated_at = utcnow()
                s.add(sh)
            s.commit()
        await self.broadcast_shares(conn.instance_id)

    async def _on_open_stream(self, conn: Conn, msg: dict) -> None:
        req = _str(msg, "req", 64)
        share_id = _str(msg, "share_id", 100)

        async def fail(code: str, message: str) -> None:
            await conn.send({"type": "error", "req": req, "code": code, "message": message})

        dev_part, _, stick_id = share_id.partition(":")
        if not dev_part.isdigit() or not stick_id:
            return await fail("NOT_FOUND", "Freigabe nicht gefunden")
        provider_id = int(dev_part)

        with self.db.session() as s:
            instance = s.get(Instance, conn.instance_id)
            if instance is None:
                return await fail("NOT_FOUND", "Instanz nicht gefunden")
            if not instance.enabled:
                return await fail("INSTANCE_DISABLED", "Instanz ist deaktiviert")
            max_streams = instance.max_streams
            provider = s.get(Device, provider_id)
            share = s.scalar(select(Share).where(Share.device_id == provider_id, Share.stick_id == stick_id))
            if (provider is None or provider.instance_id != conn.instance_id or provider.revoked_at is not None
                    or share is None):
                return await fail("NOT_FOUND", "Freigabe nicht gefunden")
            stick_name = share.name
        if provider_id == conn.device_id:
            return await fail("NOT_FOUND", "Eigene Freigabe, bitte lokal verwenden")
        pconn = self.conns.get(provider_id)
        if pconn is None:
            return await fail("PEER_OFFLINE", "Anbieter ist offline")
        active = [x for x in self.sessions.values() if x.instance_id == conn.instance_id]
        if max_streams is not None and len(active) >= max_streams:
            return await fail("LIMIT_REACHED", f"Höchstens {max_streams} gleichzeitige Streams in dieser Instanz")
        if sum(1 for x in active if x.client is conn and x.state != "connected") >= MAX_PENDING_PER_DEVICE:
            return await fail("LIMIT_REACHED", "Zu viele offene Anfragen")

        sess = Sess(id=str(uuid.uuid4()), instance_id=conn.instance_id, provider=pconn, client=conn,
                    stick_id=stick_id, stick_name=stick_name, req=req)
        self.sessions[sess.id] = sess
        with self.db.session() as s:
            s.add(StreamSession(id=sess.id, instance_id=sess.instance_id, provider_device_id=pconn.device_id,
                                client_device_id=conn.device_id, provider_name=pconn.name, client_name=conn.name,
                                stick_id=stick_id, stick_name=stick_name))
            s.commit()
        await pconn.send({"type": "stream_request", "session": sess.id, "stick_id": stick_id,
                          "from": {"device_id": conn.device_id, "name": conn.name}})
        sess.timer = self._later(self.settings.accept_timeout, self._accept_timeout, sess)

    async def _accept_timeout(self, sess: Sess) -> None:
        await sess.client.send({"type": "error", "req": sess.req, "session": sess.id, "code": "TIMEOUT",
                                "message": "Anbieter antwortet nicht"})
        await self._end(sess, "timeout", "Anbieter antwortet nicht", revoke_reason="timeout",
                        notify_client=False)

    def _session_for(self, conn: Conn, msg: dict, states: tuple[str, ...], role: str | None = None) -> Sess | None:
        sid = _str(msg, "session", 64)
        sess = self.sessions.get(sid)
        if sess is None or sess.state not in states:
            return None
        r = sess.role_of(conn)
        if r is None or (role is not None and r != role):
            return None
        return sess

    async def _on_stream_accept(self, conn: Conn, msg: dict) -> None:
        sess = self._session_for(conn, msg, ("requested",), role="server")
        if sess is None:
            return
        self._cancel(sess)
        sess.state = "accepted"
        sess.punch_key = secrets.token_bytes(32)
        key = b64encode(sess.punch_key).decode()
        lease = self.settings.lease_ttl
        await sess.provider.send({
            "type": "session", "session": sess.id, "role": "server", "punch_key": key, "lease": lease,
            "peer": {"device_id": sess.client.device_id, "name": sess.client.name, "cert_fp": sess.client.cert_fp},
        })
        await sess.client.send({
            "type": "session", "session": sess.id, "req": sess.req, "role": "client", "punch_key": key,
            "lease": lease,
            "peer": {"device_id": sess.provider.device_id, "name": sess.provider.name,
                     "cert_fp": sess.provider.cert_fp},
        })
        self._update_db(sess, state="accepted")
        sess.timer = self._later(self.settings.candidates_timeout, self._candidates_timeout, sess)

    async def _on_stream_reject(self, conn: Conn, msg: dict) -> None:
        sess = self._session_for(conn, msg, ("requested",), role="server")
        if sess is None:
            return
        code = _clean(_str(msg, "code", 32, required=False, default="REJECTED"), 32)
        message = _clean(_str(msg, "message", 200, required=False), 200)
        await sess.client.send({"type": "error", "req": sess.req, "session": sess.id, "code": "REJECTED",
                                "provider_code": code, "message": message or "Anbieter hat abgelehnt"})
        await self._end(sess, "rejected", f"{code}: {message}".strip(": "), notify_client=False,
                        notify_provider=False)

    async def _candidates_timeout(self, sess: Sess) -> None:
        err = {"type": "error", "session": sess.id, "code": "TIMEOUT", "message": "Kandidaten fehlen"}
        await sess.provider.send(err)
        await sess.client.send({**err, "req": sess.req})
        await self._end(sess, "timeout", "Kandidaten fehlen", notify_client=False, notify_provider=False)

    async def _on_candidates(self, conn: Conn, msg: dict) -> None:
        sess = self._session_for(conn, msg, ("accepted",))
        if sess is None:
            return
        cands = msg.get("candidates")
        if not isinstance(cands, list) or len(cands) > MAX_CANDIDATES or not all(valid_candidate(c) for c in cands):
            raise BadMessage("candidates ungültig")
        nat = msg.get("nat", "unknown")
        if nat not in NAT_TYPES:
            nat = "unknown"
        role = sess.role_of(conn)
        sess.candidates[role] = (list(cands), nat)
        if len(sess.candidates) < 2:
            return
        self._cancel(sess)
        sess.state = "punching"
        start_at = int(time.time() * 1000) + self.settings.punch_delay_ms
        for r, target in (("server", sess.provider), ("client", sess.client)):
            peer_c, peer_nat = sess.candidates["client" if r == "server" else "server"]
            await target.send({"type": "punch", "session": sess.id, "peer_candidates": peer_c,
                               "peer_nat": peer_nat, "start_at": start_at})
        self._update_db(sess, state="punching", nat_server=sess.candidates["server"][1],
                        nat_client=sess.candidates["client"][1])
        delay = self.settings.punch_delay_ms / 1000 + self.settings.punch_timeout
        sess.timer = self._later(delay, self._punch_failed, sess)

    async def _on_punch_result(self, conn: Conn, msg: dict) -> None:
        sess = self._session_for(conn, msg, ("punching", "connected"))
        if sess is None:
            return
        ok = msg.get("ok") is True
        path = _clean(_str(msg, "path", 80, required=False), 80)
        sess.results[sess.role_of(conn)] = (ok, path)
        if ok and sess.state != "connected":
            self._cancel(sess)
            sess.state = "connected"
            sess.path = path
            self._update_db(sess, state="connected", path=path, connected_at=utcnow())
        elif len(sess.results) == 2 and not any(r[0] for r in sess.results.values()):
            self._cancel(sess)
            await self._punch_failed(sess)

    async def _punch_failed(self, sess: Sess) -> None:
        if sess.state == "connected":
            return
        nat_s = sess.candidates.get("server", (None, "unknown"))[1]
        nat_c = sess.candidates.get("client", (None, "unknown"))[1]
        err = {"type": "error", "session": sess.id, "code": "DIRECT_CONNECTION_FAILED",
               "message": nat_hint(nat_s, nat_c), "nat": {"server": nat_s, "client": nat_c}}
        await sess.provider.send(err)
        await sess.client.send({**err, "req": sess.req})
        await self._end(sess, "direct_failed", "Keine direkte Verbindung", notify_client=False,
                        notify_provider=False)

    async def _on_stream_end(self, conn: Conn, msg: dict) -> None:
        sid = _str(msg, "session", 64)
        n = msg.get("bytes")
        n = n if isinstance(n, int) and not isinstance(n, bool) and 0 <= n < 2**63 else None
        reason = _clean(_str(msg, "reason", 200, required=False), 200)
        sess = self.sessions.get(sid)
        if sess is not None and sess.role_of(conn) is not None:
            role = sess.role_of(conn)
            sess.bytes[role] = n
            result = "ended" if sess.state == "connected" else "aborted"
            await self._end(sess, result, reason or f"{role} beendet",
                            revoke_reason="peer_ended",
                            notify_provider=role == "client", notify_client=role == "server")
            return
        if sid in self.recent and n is not None:
            # Nachzügler: zweite Seite meldet ihre Datenmenge nach dem Ende
            with self.db.session() as s:
                row = s.get(StreamSession, sid)
                if row is not None:
                    if row.provider_device_id == conn.device_id:
                        row.bytes_server = n
                    elif row.client_device_id == conn.device_id:
                        row.bytes_client = n
                    s.commit()

    # ------------------------------------------------------------ Sitzungen

    def _later(self, delay: float, fn, *args) -> asyncio.Task:
        async def run():
            await asyncio.sleep(delay)
            try:
                await fn(*args)
            except Exception:  # noqa: BLE001
                log.exception("Fehler im Timer %s", getattr(fn, "__name__", fn))

        return asyncio.create_task(run())

    def _cancel(self, sess: Sess) -> None:
        if sess.timer is not None and sess.timer is not asyncio.current_task():
            sess.timer.cancel()
        sess.timer = None

    def _update_db(self, sess: Sess, **values) -> None:
        with self.db.session() as s:
            row = s.get(StreamSession, sess.id)
            if row is not None:
                for k, v in values.items():
                    setattr(row, k, v)
                s.commit()

    async def _end(self, sess: Sess, result: str, reason: str, *, revoke_reason: str = "",
                   notify_provider: bool = True, notify_client: bool = True) -> None:
        if self.sessions.pop(sess.id, None) is None:
            return
        self._cancel(sess)
        self.responder.forget(sess.uuid)
        self.recent[sess.id] = time.monotonic() + 120
        if revoke_reason:
            msg = {"type": "revoke", "session": sess.id, "reason": revoke_reason}
            if notify_provider:
                await sess.provider.send(msg)
            if notify_client:
                await sess.client.send(msg)
        now = utcnow()
        with self.db.session() as s:
            row = s.get(StreamSession, sess.id)
            if row is not None:
                row.state = "ended"
                row.result = result
                row.reason = reason[:200]
                row.ended_at = now
                if "server" in sess.bytes:
                    row.bytes_server = sess.bytes["server"]
                if "client" in sess.bytes:
                    row.bytes_client = sess.bytes["client"]
                duration = (now - row.connected_at).total_seconds() if row.connected_at else 0
                audit(s, "stream_session", actor=f"device:{sess.client.device_id}",
                      session=sess.id, instance_id=sess.instance_id, provider=sess.provider.name,
                      client=sess.client.name, stick=sess.stick_id, result=result, reason=reason,
                      path=sess.path, nat_server=row.nat_server, nat_client=row.nat_client,
                      duration_s=round(duration), bytes_server=row.bytes_server, bytes_client=row.bytes_client)
                s.commit()

    # ------------------------------------------------------------ Freigaben

    def shares_for(self, instance_id: int) -> list[dict]:
        with self.db.session() as s:
            rows = s.execute(
                select(Share, Device)
                .join(Device, Share.device_id == Device.id)
                .where(Device.instance_id == instance_id, Device.revoked_at.is_(None))
                .order_by(Device.id, Share.stick_id)
            ).all()
        return [
            {"share_id": f"{d.id}:{sh.stick_id}", "provider": {"device_id": d.id, "name": d.server_name},
             "stick_id": sh.stick_id, "name": sh.name, "tuner": sh.tuner, "state": sh.state,
             "online": d.id in self.conns, "compression": sh.compression}
            for sh, d in rows
        ]

    async def broadcast_shares(self, instance_id: int) -> None:
        targets = [c for c in self.conns.values() if c.instance_id == instance_id]
        if not targets:
            return
        msg = {"type": "shares", "shares": self.shares_for(instance_id)}
        for c in targets:
            await c.send(msg)

    # ------------------------------------------------------------ Verwaltung (Weboberfläche)

    def online(self, instance_id: int) -> dict[int, Conn]:
        return {d: c for d, c in self.conns.items() if c.instance_id == instance_id}

    def active_sessions(self, instance_id: int) -> list[Sess]:
        return [x for x in self.sessions.values() if x.instance_id == instance_id]

    async def end_session(self, session_id: str, reason: str) -> bool:
        sess = self.sessions.get(session_id)
        if sess is None:
            return False
        await self._end(sess, "revoked", reason, revoke_reason=reason)
        return True

    async def kick_device(self, device_id: int, code: int, reason: str) -> None:
        for sess in [x for x in self.sessions.values()
                     if device_id in (x.provider.device_id, x.client.device_id)]:
            await self._end(sess, "revoked", reason, revoke_reason=reason)
        conn = self.conns.get(device_id)
        if conn is not None:
            await self._drop(conn, code, reason)

    async def kick_instance(self, instance_id: int, code: int, reason: str) -> None:
        for sess in self.active_sessions(instance_id):
            await self._end(sess, "revoked", reason, revoke_reason=reason)
        for conn in list(self.online(instance_id).values()):
            await self._drop(conn, code, reason)
