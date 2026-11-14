"""Alert business logic and helper functions."""

import csv
import io
import json
import logging
import math
import secrets
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Mapping
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import DISPLAY_TIMEZONE, SEVERITIES, STATUSES, UPLOAD_DIR
from ..models import Alert, AlertEvent, Evidence, User

logger = logging.getLogger("soc_tracker.alert_service")

# Dashboard and list date windows. "all" (or no value) means no time filter.
RANGE_WINDOWS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}
RANGE_CHOICES = (
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
    ("90d", "Last 90 days"),
    ("all", "All time"),
)

DISPLAY_TZ = ZoneInfo(DISPLAY_TIMEZONE)


def _parse_period(raw: str) -> tuple[date, date] | None:
    """Read a day (2026-10-20 or 20/10/2026), a month or a year.

    The form shows days as dd/mm/yyyy, so that shape is accepted too; months and
    years stay readable from a link even though the picker only offers days.
    Returns [first day, day after last].
    """
    value = (raw or "").strip()
    if not value:
        return None
    try:
        if len(value) == 4 and value.isdigit():
            first = date(int(value), 1, 1)
            return first, date(first.year + 1, 1, 1)
        if len(value) == 7 and value[4] == "-":
            year, month = value.split("-")
            first = date(int(year), int(month), 1)
            following = date(first.year + 1, 1, 1) if first.month == 12 else date(first.year, first.month + 1, 1)
            return first, following
        if len(value) == 10 and value[2] == "/" and value[5] == "/":
            day = datetime.strptime(value, "%d/%m/%Y").date()
            return day, day + timedelta(days=1)
        day = date.fromisoformat(value)
        return day, day + timedelta(days=1)
    except ValueError:
        return None


def _local_midnight(day: date) -> datetime:
    """Midnight on that day in the display timezone, as naive UTC."""
    return datetime.combine(day, time.min, tzinfo=DISPLAY_TZ).astimezone(timezone.utc).replace(tzinfo=None)


def custom_window(request) -> tuple[datetime | None, datetime | None]:
    """Turn the calendar inputs into naive-UTC bounds.

    A picked date means that day where the analyst sits, so the boundaries are
    built in the display timezone and converted: without this, "1 November" in
    Asia/Yangon would start six and a half hours early and quietly include
    tickets from the previous afternoon. The upper bound is exclusive (midnight
    after the chosen day, month or year) so the whole final period is included.
    """
    start_period = _parse_period(request.query_params.get("from") or "")
    end_period = _parse_period(request.query_params.get("to") or "")
    if start_period and end_period and end_period[0] < start_period[0]:
        start_period, end_period = end_period, start_period
    start = _local_midnight(start_period[0]) if start_period else None
    end = _local_midnight(end_period[1]) if end_period else None
    return start, end


def create_alert(db: Session, values: dict, user: User | None = None, *, source: str = "tracker", payload: dict | None = None) -> Alert:
    """Add a new alert with its creation event to the session.

    Flushes so the sequential ticket number can be derived from the primary key,
    but does not commit: the caller owns the transaction, so a batch that fails
    on its 50th record rolls back all of it instead of leaving 49 tickets behind.
    """
    iocs = values.pop("iocs", None) or []
    if not isinstance(iocs, list) or len(iocs) > 500:
        raise ValueError("IOC list must contain at most 500 values.")
    if any(not isinstance(value, (str, int, float)) or len(str(value)) > 2048 for value in iocs):
        raise ValueError("IOC values must be strings of at most 2048 characters.")
    actor = user or values.get("created_by")
    required_limits = {"title": 180, "description": 10000, "source": 80, "tactic": 100, "asset": 160}
    for key, limit in required_limits.items():
        value = values.get(key, "")
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError(f"{key.title()} must be text of at most {limit} characters.")
    if not values.get("title", "").strip():
        raise ValueError("Title is required.")
    if values.get("severity", "Medium") not in SEVERITIES or values.get("status", "Open") not in STATUSES:
        raise ValueError("Invalid severity or status.")
    if not isinstance(values.get("sla_hours", 8), int) or not 1 <= values.get("sla_hours", 8) <= 8760:
        raise ValueError("SLA hours must be between 1 and 8760.")
    # Use a unique temporary value until the database allocates the sequential primary key.
    alert = Alert(alert_id=f"TMP-{secrets.token_hex(4)}", **values)
    alert.iocs = iocs
    if user:
        alert.created_by = user
        alert.updated_by = user
    db.add(alert)
    db.flush()
    alert.alert_id = f"#{alert.id}"
    db.add(AlertEvent(
        alert=alert,
        event_type="created",
        actor=actor,
        message=f"{actor.username if actor else 'system'} created {alert.alert_id}.",
        source=source,
        payload_json=json.dumps(payload)[:100000] if payload is not None else "{}",
    ))
    db.flush()
    logger.info("Alert %s staged by %s", alert.alert_id, actor.username if actor else "system")
    return alert


def create_or_get_alert(db: Session, values: dict, user: User | None = None, *, source: str = "tracker", payload: dict | None = None) -> tuple[Alert, bool]:
    """Create an alert, or return the existing one for a repeated external id.

    A pasted Elastic export is often imported twice, so without this a second
    import turns one detection into several tickets. Returns (alert, created).
    """
    external_id = values.get("external_id")
    if external_id:
        existing = db.scalar(select(Alert).where(Alert.external_id == external_id))
        if existing:
            logger.info("Duplicate external id %s maps to existing %s", external_id, existing.alert_id)
            return existing, False
    try:
        return create_alert(db, dict(values), user, source=source, payload=payload), True
    except IntegrityError:
        # Another worker won the race between the lookup and the insert.
        db.rollback()
        if not external_id:
            raise
        existing = db.scalar(select(Alert).where(Alert.external_id == external_id))
        if existing:
            logger.info("Duplicate external id %s mapped to existing %s after race", external_id, existing.alert_id)
            return existing, False
        raise


def normalized_datetime(value: datetime) -> datetime:
    """Ensure datetime has UTC timezone."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def sla_status(alert: Alert) -> dict[str, str]:
    """Calculate SLA status for an alert."""
    if alert.status == "Closed":
        return {"label": "Closed", "class": "sla-closed"}
    due_at = normalized_datetime(alert.created_at) + timedelta(hours=alert.sla_hours)
    remaining = due_at - datetime.now(timezone.utc)
    if remaining.total_seconds() < 0:
        return {"label": "Overdue", "class": "sla-overdue"}
    hours = max(1, int((remaining.total_seconds() + 3599) // 3600))
    if hours <= 2:
        return {"label": f"Due in {hours}h", "class": "sla-due-soon"}
    return {"label": f"Due in {hours}h", "class": "sla-ok"}


def filtered_alerts(db: Session, request) -> list[Alert]:
    """Get alerts filtered by query parameters."""
    query = select(Alert).order_by(Alert.created_at.desc())
    search = (request.query_params.get("q") or "").strip()
    severity = request.query_params.get("severity") or ""
    alert_status = request.query_params.get("status") or ""
    source = request.query_params.get("source") or ""
    analyst = request.query_params.get("analyst") or ""
    sla = request.query_params.get("sla") or ""
    window = (request.query_params.get("range") or "").strip().lower()

    # Calendar dates win over the preset windows: an analyst who picks both is
    # narrowing the window they just clicked, not asking for a union.
    start, end = custom_window(request)
    if start or end:
        if start:
            query = query.where(Alert.created_at >= start)
        if end:
            query = query.where(Alert.created_at < end)
    elif window in RANGE_WINDOWS:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - RANGE_WINDOWS[window]
        query = query.where(Alert.created_at >= cutoff)

    if search:
        if search.lstrip("#").isdigit():
            # A ticket number is a lookup, not a text search: matching bare digits
            # against descriptions and IOCs made "9" return six unrelated tickets.
            query = query.where(Alert.alert_id == f"#{search.lstrip('#')}")
        else:
            like = f"%{search}%"
            evidence_alert_ids = select(Evidence.alert_id).where(Evidence.original_name.ilike(like))
            query = query.where(or_(
                Alert.alert_id.ilike(like),
                Alert.title.ilike(like),
                Alert.description.ilike(like),
                Alert.asset.ilike(like),
                Alert.source.ilike(like),
                Alert.analyst.ilike(like),
                Alert.iocs_json.ilike(like),
                Alert.assigned_to.has(User.username.ilike(like)),
                Alert.id.in_(evidence_alert_ids),
            ))
    if severity:
        query = query.where(Alert.severity == severity)
    if alert_status:
        query = query.where(Alert.status == alert_status)
    if source:
        query = query.where(Alert.source == source)
    if analyst:
        query = query.where(Alert.analyst == analyst)

    alerts = list(db.scalars(query))

    if sla == "overdue":
        alerts = [a for a in alerts if sla_status(a)["class"] == "sla-overdue"]
    elif sla == "closed":
        alerts = [a for a in alerts if a.status == "Closed"]
    elif sla == "due-soon":
        alerts = [a for a in alerts if sla_status(a)["class"] == "sla-due-soon"]
    elif sla == "on-track":
        alerts = [a for a in alerts if sla_status(a)["class"] == "sla-ok"]

    return alerts


def filtered_alerts_paginated(db: Session, request, page: int = 1, per_page: int = 50) -> dict:
    """Get paginated alerts with filters."""
    all_alerts = filtered_alerts(db, request)
    total = len(all_alerts)
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page

    return {
        "alerts": all_alerts[start:end],
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
    }


def form_values(form: Mapping[str, str]) -> dict:
    """Extract and validate alert form values."""
    iocs_text = form.get("iocs_text", "")
    title = form.get("title", "").strip()

    # Input validation
    if len(title) > 180:
        raise ValueError("Title must be 180 characters or less.")

    description = form.get("description", "").strip()
    if len(description) > 10000:
        raise ValueError("Description must be 10000 characters or less.")

    source = form.get("source", "Manual").strip() or "Manual"
    if len(source) > 80:
        raise ValueError("Source must be 80 characters or less.")

    tactic = form.get("tactic", "Unknown").strip() or "Unknown"
    if len(tactic) > 100:
        raise ValueError("Tactic must be 100 characters or less.")

    asset = form.get("asset", "Unknown").strip() or "Unknown"
    if len(asset) > 160:
        raise ValueError("Asset must be 160 characters or less.")

    severity = form.get("severity", "Medium")
    status = "Open"
    if severity not in SEVERITIES:
        raise ValueError("Select a valid severity.")
    try:
        sla_hours = int(form.get("sla_hours") or 8)
    except (TypeError, ValueError):
        raise ValueError("SLA hours must be a whole number.") from None
    if not 1 <= sla_hours <= 8760:
        raise ValueError("SLA hours must be between 1 and 8760.")
    iocs = [item.strip() for item in iocs_text.split(",") if item.strip()]
    if len(iocs) > 500 or any(len(item) > 2048 for item in iocs):
        raise ValueError("Provide no more than 500 IOCs, each 2048 characters or less.")

    return {
        "title": title,
        "description": description,
        "source": source,
        "severity": severity,
        "status": status,
        "analyst": "Unassigned",
        "tactic": tactic,
        "asset": asset,
        "iocs": iocs,
        "sla_hours": sla_hours,
    }


def export_csv(alerts: list[Alert]) -> str:
    """Export alerts to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "alert_id", "title", "severity", "status", "source",
        "analyst", "asset", "tactic", "sla_hours", "sla_status",
        "created_at", "updated_at"
    ])
    for alert in alerts:
        # Spreadsheet programs treat cells beginning with these characters as formulas.
        safe = lambda value: "'" + str(value) if str(value).lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
        writer.writerow([
            safe(alert.alert_id), safe(alert.title), safe(alert.severity), safe(alert.status),
            safe(alert.source), safe(alert.analyst), safe(alert.asset), safe(alert.tactic),
            alert.sla_hours,
            sla_status(alert)["label"],
            alert.created_at.isoformat(),
            alert.updated_at.isoformat(),
        ])
    return output.getvalue()
