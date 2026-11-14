"""SQLAlchemy models for Sentriq."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, create_engine, text, true
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import DATABASE_URL, DB_POOL_MAX_OVERFLOW, DB_POOL_SIZE

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    # A bounded pool per worker, and connections recycled well inside any idle
    # timeout the server or a firewall enforces.
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_POOL_MAX_OVERFLOW,
    pool_recycle=1800,
    pool_timeout=30,
)


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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())

    def __str__(self) -> str:
        return self.username


class Alert(Base):
    __tablename__ = "fastapi_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(160), unique=True, index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(80), default="Manual")
    severity: Mapped[str] = mapped_column(String(20), default="Medium", index=True)
    status: Mapped[str] = mapped_column(String(20), default="Open", index=True)
    analyst: Mapped[str] = mapped_column(String(80), default="Unassigned", index=True)
    tactic: Mapped[str] = mapped_column(String(100), default="Unknown")
    asset: Mapped[str] = mapped_column(String(160), default="Unknown")
    iocs_json: Mapped[str] = mapped_column(Text, default="[]")
    sla_hours: Mapped[int] = mapped_column(Integer, default=8)
    assigned_to_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True, index=True)
    assigned_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    created_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    updated_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    escalated_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    # Retention is measured from closure, not creation: a ticket opened 800 days
    # ago and closed yesterday must stay for another two years.
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    # Set when this ticket was merged into another one; the source stays readable
    # and points at the ticket that owns the investigation.
    duplicate_of_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_alerts.id"), nullable=True)

    assigned_to: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to_id])
    assigned_by: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_by_id])
    created_by: Mapped[Optional[User]] = relationship(foreign_keys=[created_by_id])
    updated_by: Mapped[Optional[User]] = relationship(foreign_keys=[updated_by_id])
    escalated_by: Mapped[Optional[User]] = relationship(foreign_keys=[escalated_by_id])
    events: Mapped[list["AlertEvent"]] = relationship(back_populates="alert", cascade="all, delete-orphan", order_by="desc(AlertEvent.created_at)")
    duplicate_of: Mapped[Optional["Alert"]] = relationship(remote_side=[id])

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
    alert_id: Mapped[int] = mapped_column(ForeignKey("fastapi_alerts.id"), index=True)
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
    # Declared as a unique index (not a column-level UNIQUE) so the model matches
    # what migration 0002 created; otherwise alembic autogenerate reports drift.
    __table_args__ = (Index("ix_fastapi_evidence_stored_name", "stored_name", unique=True),)

    IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}

    @property
    def is_image(self) -> bool:
        """True for formats the browser can preview in a popup."""
        return Path(self.stored_name).suffix.lower() in self.IMAGE_EXTENSIONS

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("fastapi_alerts.id"), index=True)
    uploaded_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255))
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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    actor: Mapped[Optional[User]] = relationship()


class SlaBreach(Base):
    """One row per ticket that missed its SLA.

    Written by the SLA sweep rather than computed on page load, so the count
    survives the ticket being closed — and survives archival in the JSONL export.
    """

    __tablename__ = "fastapi_sla_breaches"
    __table_args__ = (Index("ix_fastapi_sla_breaches_alert_due", "alert_id", "due_at", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("fastapi_alerts.id"), index=True)
    # Kept as a string so the history still reads correctly after the alert row
    # is archived and removed.
    alert_ref: Mapped[str] = mapped_column(String(16), default="")
    severity: Mapped[str] = mapped_column(String(20), default="Medium")
    due_at: Mapped[datetime] = mapped_column(DateTime)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    late_hours: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    alert: Mapped[Alert] = relationship()
