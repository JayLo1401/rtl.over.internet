"""Konfiguration aus Umgebungsvariablen (Präfix ROI_)."""

from __future__ import annotations

import ipaddress
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(RuntimeError):
    pass


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _bool(name: str, default: bool | None) -> bool | None:
    value = _env(name)
    if value is None:
        return default
    if value.lower() in ("1", "true", "yes", "on"):
        return True
    if value.lower() in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name}: erwartet true/false, bekommen {value!r}")


@dataclass
class Settings:
    data_dir: Path
    public_url: str
    admin_user: str | None
    admin_password: str | None
    auth_modes: str
    trusted_proxies: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    secret_key: bytes
    cookie_secure: bool
    http_host: str = "127.0.0.1"
    http_port: int = 8090
    rendezvous_bind: str = "::"
    rendezvous_ports: tuple[int, ...] = (3478, 3479)
    rendezvous_host: str = ""
    rendezvous_enabled: bool = True
    session_idle_minutes: int = 30
    session_max_hours: int = 8
    # Zeitgrenzen des Verbindungsaufbaus (Sekunden), für Tests verkürzbar
    accept_timeout: float = 10.0
    candidates_timeout: float = 10.0
    punch_timeout: float = 15.0
    punch_delay_ms: int = 500
    lease_interval: float = 20.0
    lease_ttl: int = 60
    hello_timeout: float = 10.0
    # OpenID Connect (z. B. authentik), wie bei order.manager
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_button_label: str = "Mit authentik anmelden"
    oidc_allowed_emails: frozenset = frozenset()
    oidc_allowed_groups: frozenset = frozenset()
    extra: dict = field(default_factory=dict)

    @property
    def local_login_enabled(self) -> bool:
        return self.auth_modes in ("all", "internal")

    @property
    def oidc_configured(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @property
    def oidc_active(self) -> bool:
        return self.oidc_configured and self.auth_modes in ("all", "oidc")

    @property
    def oidc_redirect_uri(self) -> str:
        return self.public_url + "/login/oidc/callback"

    def oidc_allowed(self, email: str, groups) -> bool:
        if email and email.lower() in self.oidc_allowed_emails:
            return True
        return bool(self.oidc_allowed_groups & {str(g) for g in (groups or [])})

    @property
    def db_url(self) -> str:
        return f"sqlite:///{(self.data_dir / 'roi.db').as_posix()}"


def _set(name: str, lower: bool = False) -> frozenset:
    items = [x.strip() for x in (_env(name, "") or "").split(",") if x.strip()]
    return frozenset(x.lower() for x in items) if lower else frozenset(items)


def _load_secret_key(data_dir: Path) -> bytes:
    value = _env("ROI_SECRET_KEY")
    if value:
        if len(value) < 32:
            raise ConfigError("ROI_SECRET_KEY muss mindestens 32 Zeichen lang sein")
        return value.encode()
    path = data_dir / "secret_key"
    if path.exists():
        return path.read_bytes().strip()
    key = secrets.token_urlsafe(48).encode()
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def _admin_password() -> str | None:
    pw = _env("ROI_ADMIN_PASSWORD")
    pw_file = _env("ROI_ADMIN_PASSWORD_FILE")
    if pw_file:
        try:
            pw = Path(pw_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"ROI_ADMIN_PASSWORD_FILE nicht lesbar: {exc}") from exc
    return pw or None


def load_settings(**overrides) -> Settings:
    data_dir = Path(_env("ROI_DATA_DIR", "/data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    public_url = (_env("ROI_PUBLIC_URL", "http://localhost:8090") or "").rstrip("/")
    parts = urlsplit(public_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("ROI_PUBLIC_URL muss eine http(s)-URL sein")

    auth_modes = (_env("ROI_AUTH_MODES", "all") or "all").lower()
    if auth_modes not in ("all", "internal", "oidc"):
        raise ConfigError("ROI_AUTH_MODES muss all, internal oder oidc sein")

    admin_user = _env("ROI_ADMIN_USER")
    admin_password = _admin_password()
    oidc = {
        "oidc_issuer": _env("ROI_OIDC_ISSUER", "") or "",
        "oidc_client_id": _env("ROI_OIDC_CLIENT_ID", "") or "",
        "oidc_client_secret": _env("ROI_OIDC_CLIENT_SECRET", "") or "",
        "oidc_button_label": _env("ROI_OIDC_BUTTON_LABEL", "Mit authentik anmelden"),
        "oidc_allowed_emails": _set("ROI_OIDC_ALLOWED_EMAILS", lower=True),
        "oidc_allowed_groups": _set("ROI_OIDC_ALLOWED_GROUPS"),
    }
    oidc_configured = bool(oidc["oidc_issuer"] and oidc["oidc_client_id"] and oidc["oidc_client_secret"])
    if auth_modes == "oidc" and not oidc_configured:
        raise ConfigError("ROI_AUTH_MODES=oidc braucht ROI_OIDC_ISSUER, ROI_OIDC_CLIENT_ID und ROI_OIDC_CLIENT_SECRET")
    if oidc_configured and auth_modes != "internal" and not (oidc["oidc_allowed_emails"] or oidc["oidc_allowed_groups"]):
        raise ConfigError("OIDC: ROI_OIDC_ALLOWED_EMAILS oder ROI_OIDC_ALLOWED_GROUPS setzen "
                          "(jede OIDC-Anmeldung hat Admin-Rechte)")
    if auth_modes in ("all", "internal"):
        if not admin_user or not admin_password:
            raise ConfigError("ROI_ADMIN_USER und ROI_ADMIN_PASSWORD(_FILE) müssen gesetzt sein")
        if len(admin_password) < 12:
            raise ConfigError("ROI_ADMIN_PASSWORD muss mindestens 12 Zeichen lang sein")
    else:  # nur OIDC: lokaler Admin wird nicht verwendet
        admin_user, admin_password = None, None

    proxies = []
    for item in (_env("ROI_TRUSTED_PROXIES", "") or "").split(","):
        item = item.strip()
        if item:
            try:
                proxies.append(ipaddress.ip_network(item, strict=False))
            except ValueError as exc:
                raise ConfigError(f"ROI_TRUSTED_PROXIES: {item!r} ungültig") from exc

    cookie_secure = _bool("ROI_COOKIE_SECURE", None)
    if cookie_secure is None:
        cookie_secure = parts.scheme == "https"

    ports = tuple(int(p) for p in (_env("ROI_RENDEZVOUS_PORTS", "3478,3479") or "").split(",") if p.strip())
    if len(ports) != 2:
        raise ConfigError("ROI_RENDEZVOUS_PORTS braucht genau zwei Ports, z. B. 3478,3479")

    settings = Settings(
        data_dir=data_dir,
        public_url=public_url,
        admin_user=admin_user.lower() if admin_user else None,
        admin_password=admin_password,
        auth_modes=auth_modes,
        trusted_proxies=proxies,
        secret_key=_load_secret_key(data_dir),
        cookie_secure=cookie_secure,
        http_host=_env("ROI_HTTP_HOST", "127.0.0.1"),
        http_port=int(_env("ROI_HTTP_PORT", "8090")),
        rendezvous_bind=_env("ROI_RENDEZVOUS_BIND", "::"),
        rendezvous_ports=ports,
        rendezvous_host=_env("ROI_RENDEZVOUS_HOST", parts.hostname),
        rendezvous_enabled=bool(_bool("ROI_RENDEZVOUS_ENABLED", True)),
        **oidc,
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings
