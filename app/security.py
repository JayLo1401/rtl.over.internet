"""Passwörter, Tokens, Instanz-Codes, CSRF, Rate-Limits und Client-IP."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
import time
from collections import deque
from typing import Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_hasher = PasswordHasher()  # Argon2id mit den Standardparametern von argon2-cffi
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Prüft immer einen Hash, auch wenn es keinen gibt (gleiche Laufzeit)."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_password() -> str:
    """Erzeugtes Instanz-Passwort, gut abschreibbar: 4 Gruppen à 5 Zeichen aus 60 Zeichen (~118 Bit)."""
    return "-".join("".join(secrets.choice(CODE_ALPHABET.lower() + CODE_ALPHABET) for _ in range(5)) for _ in range(4))


# Instanz-Code: Crockford-artig ohne 0/O/1/I/L/U, 8 Zeichen (~39,6 Bit)
CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
_CODE_RE = re.compile(rf"^[{CODE_ALPHABET}]{{8}}$")


def new_instance_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


def normalize_code(code: str) -> str | None:
    value = re.sub(r"[\s-]", "", code or "").upper()
    return value if _CODE_RE.match(value) else None


def format_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


# ---------------------------------------------------------------- Abrufbare Geheimnisse (Instanz-Passwort)


def _aead(secret: bytes) -> AESGCM:
    return AESGCM(hashlib.sha256(b"roi:instance-password:v1:" + secret).digest())


def encrypt_secret(secret: bytes, plaintext: str) -> str:
    """AES-256-GCM mit einem aus ROI_SECRET_KEY abgeleiteten Schlüssel. Format: v1:<base64(nonce|ciphertext)>."""
    nonce = os.urandom(12)
    ct = _aead(secret).encrypt(nonce, plaintext.encode("utf-8"), b"instance-password")
    return "v1:" + base64.b64encode(nonce + ct).decode()


def decrypt_secret(secret: bytes, value: str | None) -> str | None:
    if not value or not value.startswith("v1:"):
        return None
    try:
        raw = base64.b64decode(value[3:])
        return _aead(secret).decrypt(raw[:12], raw[12:], b"instance-password").decode("utf-8")
    except (ValueError, InvalidTag):
        return None


# ---------------------------------------------------------------- CSRF


def csrf_token(secret: bytes, binding: str) -> str:
    return hmac.new(secret, b"csrf:" + binding.encode(), hashlib.sha256).hexdigest()


def csrf_ok(secret: bytes, binding: str, submitted: str | None) -> bool:
    if not binding or not submitted:
        return False
    return hmac.compare_digest(csrf_token(secret, binding), submitted)


# ---------------------------------------------------------------- Rate-Limit


class Limiter:
    """Zählt Fehlversuche pro Schlüssel in einem Zeitfenster und sperrt danach für `lock_seconds`."""

    def __init__(self, max_failures: int, window: float, lock_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.max_failures = max_failures
        self.window = window
        self.lock_seconds = lock_seconds
        self.clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._locked: dict[str, float] = {}
        self._lock = threading.Lock()

    def retry_after(self, key: str) -> int:
        """0 = nicht gesperrt, sonst Sekunden bis zur Freigabe."""
        with self._lock:
            until = self._locked.get(key)
            if until is None:
                return 0
            remaining = until - self.clock()
            if remaining <= 0:
                del self._locked[key]
                self._failures.pop(key, None)
                return 0
            return max(1, int(remaining + 0.999))

    def fail(self, key: str) -> None:
        with self._lock:
            now = self.clock()
            q = self._failures.setdefault(key, deque())
            q.append(now)
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.max_failures:
                self._locked[key] = now + self.lock_seconds
            self._gc(now)

    def success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def _gc(self, now: float) -> None:
        if len(self._failures) > 10000:
            for k in [k for k, q in self._failures.items() if not q or q[-1] < now - self.window]:
                del self._failures[k]


class RateCounter:
    """Einfacher Zähler für Anfragen pro Zeitfenster (unabhängig von Erfolg)."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.window = window
        self.clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> int:
        """Zählt eine Anfrage. 0 = erlaubt, sonst Sekunden bis zur nächsten erlaubten Anfrage."""
        with self._lock:
            now = self.clock()
            q = self._hits.setdefault(key, deque())
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(1, int(q[0] + self.window - now + 0.999))
            q.append(now)
            if len(self._hits) > 10000:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return 0


# ---------------------------------------------------------------- Client-IP


def client_ip(conn, trusted: list) -> str:
    """Adresse des Clients. X-Forwarded-For nur, wenn die Verbindung von einem vertrauten Proxy kommt."""
    peer = conn.client.host if conn.client else ""
    if not trusted or not _in(peer, trusted):
        return peer
    xff = conn.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    # von rechts: der erste Eintrag, der kein vertrauter Proxy ist
    for hop in reversed(hops):
        if not _in(hop, trusted):
            return hop if _valid_ip(hop) else peer
    return hops[0] if hops and _valid_ip(hops[0]) else peer


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _in(addr: str, nets: list) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in nets)
