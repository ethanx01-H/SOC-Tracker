"""SQLAlchemy models for SOC Alert Tracker."""

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import SQLITE_PATH


engine = create_engine(
    f"sqlite:///{SQLITE_PATH}",
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable WAL mode and busy timeout for better concurrency."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "fastapi_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(220))
    role: Mapped[str] = mapped_column(String(2), default="L1")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    def __str__(self) -> str:
        return self.username


class Alert(Base):
    __tablename__ = "fastapi_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(80), default="Manual")
    severity: Mapped[str] = mapped_column(String(10), default="Medium")
    status: Mapped[str] = mapped_column(String(20), default="Open")
    analyst: Mapped[str] = mapped_column(String(80), default="Unassigned")
    tactic: Mapped[str] = mapped_column(String(100), default="Unknown")
    asset: Mapped[str] = mapped_column(String(160), default="Unknown")
    iocs_json: Mapped[str] = mapped_column(Text, default="[]")
    sla_hours: Mapped[int] = mapped_column(Integer, default=8)
    assigned_to_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    assigned_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    created_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    updated_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    escalated_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    assigned_to: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to_id])
    assigned_by: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_by_id])
    created_by: Mapped[Optional[User]] = relationship(foreign_keys=[created_by_id])
    updated_by: Mapped[Optional[User]] = relationship(foreign_keys=[updated_by_id])
    escalated_by: Mapped[Optional[User]] = relationship(foreign_keys=[escalated_by_id])
    events: Mapped[list["AlertEvent"]] = relationship(back_populates="alert", cascade="all, delete-orphan", order_by="desc(AlertEvent.created_at)")

    @property
    def iocs(self) -> list[str]:
        try:
            value = json.loads(self.iocs_json or "[]")
            return value if isinstance(value, list) else []
        except json.JSONDecodeError:
            return []

    @iocs.setter
    def iocs(self, value: list[str]) -> None:
        self.iocs_json = json.dumps(value or [])

    @property
    def pk(self) -> int:
        return self.id

    def get_absolute_url(self) -> str:
        return f"/alerts/{self.id}/"


class AlertEvent(Base):
    __tablename__ = "fastapi_alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("fastapi_alerts.id"))
    event_type: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    assigned_from_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    assigned_to_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="tracker")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert: Mapped[Alert] = relationship(back_populates="events")
    actor: Mapped[Optional[User]] = relationship(foreign_keys=[actor_id])
    assigned_from: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_from_id])
    assigned_to: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to_id])

    @property
    def event_type_display(self) -> str:
        return self.event_type.replace("_", " ").title()


class Evidence(Base):
    __tablename__ = "fastapi_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("fastapi_alerts.id"))
    uploaded_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255), unique=True)
    content_type: Mapped[str] = mapped_column(String(120), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert: Mapped[Alert] = relationship()
    uploaded_by: Mapped[Optional[User]] = relationship()


class AuditLog(Base):
    __tablename__ = "fastapi_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str] = mapped_column(String(80), default="")
    target_id: Mapped[str] = mapped_column(String(80), default="")
    message: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    actor: Mapped[Optional[User]] = relationship()
