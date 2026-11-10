"""Datenbankmodelle (SQLite über SQLAlchemy). Schema per create_all, Alembic folgt später."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # Systemadmin: der Admin aus ROI_ADMIN_USER oder ein OIDC-Benutzer in ROI_OIDC_ADMIN_GROUPS.
    # Alle anderen haben nur die Rechte aus instance_members.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_source: Mapped[str] = mapped_column(String(16), default="local")  # local | oidc
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WebSession(Base):
    __tablename__ = "web_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user: Mapped[User] = relationship()


class Instance(Base):
    __tablename__ = "instances"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    code: Mapped[str] = mapped_column(String(16), unique=True)  # normalisiert, ohne Bindestrich
    username: Mapped[str] = mapped_column(String(32), default="")  # veraltet, nicht mehr verwendet
    password_hash: Mapped[str] = mapped_column(String(255))
    # Für den Admin abrufbar, verschlüsselt mit ROI_SECRET_KEY (security.encrypt_secret)
    password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    max_streams: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    devices: Mapped[list["Device"]] = relationship(
        back_populates="instance", cascade="all, delete-orphan", passive_deletes=True
    )


class InstanceMember(Base):
    """Zuweisung eines Benutzers zu einer Instanz. role: "admin" (Instanz-Admin) oder "user" (nur lesen)."""

    __tablename__ = "instance_members"
    __table_args__ = (UniqueConstraint("instance_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(8), default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Device(Base):
    """Ein rtltcp.server, angemeldet an einer Instanz (ein Token pro server_id und Instanz)."""

    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("instance_id", "server_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"))
    server_id: Mapped[str] = mapped_column(String(64))
    server_name: Mapped[str] = mapped_column(String(100), default="")
    version: Mapped[str] = mapped_column(String(32), default="")
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    enrolled_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_ip: Mapped[str] = mapped_column(String(64), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    instance: Mapped[Instance] = relationship(back_populates="devices")
    shares: Mapped[list["Share"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class Share(Base):
    """Letzter bekannter Stand der Freigaben eines Anbieters (aus announce)."""

    __tablename__ = "shares"
    __table_args__ = (UniqueConstraint("device_id", "stick_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    stick_id: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(100), default="")
    tuner: Mapped[str] = mapped_column(String(32), default="")
    state: Mapped[str] = mapped_column(String(32), default="")
    compression: Mapped[bool] = mapped_column(Boolean, default=False)
    location: Mapped[str] = mapped_column(String(100), default="")  # Standort, z. B. „Wien Dach“
    antenna: Mapped[str] = mapped_column(String(100), default="")  # Antennentyp, Freitext
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class StreamSession(Base):
    __tablename__ = "stream_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"))
    provider_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    client_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    provider_name: Mapped[str] = mapped_column(String(100), default="")
    client_name: Mapped[str] = mapped_column(String(100), default="")
    stick_id: Mapped[str] = mapped_column(String(64))
    stick_name: Mapped[str] = mapped_column(String(100), default="")
    state: Mapped[str] = mapped_column(String(24), default="requested")
    result: Mapped[str] = mapped_column(String(64), default="")
    path: Mapped[str] = mapped_column(String(80), default="")
    nat_server: Mapped[str] = mapped_column(String(32), default="")
    nat_client: Mapped[str] = mapped_column(String(32), default="")
    bytes_server: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_client: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    connected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(100), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


class Database:
    def __init__(self, url: str):
        self.engine = create_engine(url, connect_args={"check_same_thread": False})
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)
        self._add_missing_columns()

    # Bis Alembic kommt: neue, nullable Spalten in bestehenden Tabellen ergänzen.
    _ADDED_COLUMNS = {
        "instances": {"password_enc": "TEXT"},
        "users": {"auth_source": "VARCHAR(16) NOT NULL DEFAULT 'local'"},
        "shares": {"location": "VARCHAR(100) NOT NULL DEFAULT ''", "antenna": "VARCHAR(100) NOT NULL DEFAULT ''"},
    }

    def _add_missing_columns(self) -> None:
        with self.engine.begin() as conn:
            for table, cols in self._ADDED_COLUMNS.items():
                have = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
                for name, sqltype in cols.items():
                    if name not in have:
                        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}")

    def session(self) -> Session:
        return self.Session()


def audit(db: Session, action: str, *, actor: str = "", ip: str = "", **detail) -> None:
    db.add(
        AuditLog(
            action=action,
            actor=actor[:100],
            ip=ip[:64],
            detail=json.dumps(detail, ensure_ascii=False, default=str) if detail else "",
        )
    )
