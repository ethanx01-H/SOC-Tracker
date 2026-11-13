"""SLA breach history.

The dashboard can say a ticket is overdue right now; this records that it *was*
overdue, so the count survives the ticket being closed. A sweep writes one row
per missed due date and closes it out with how late the ticket actually was.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, SlaBreach

logger = logging.getLogger("soc_tracker.sla")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def due_at(alert: Alert) -> datetime:
    return (alert.created_at or utcnow()) + timedelta(hours=alert.sla_hours or 8)


def sweep(db: Session, now: datetime | None = None) -> dict:
    """Record newly missed SLAs and close out breaches for finished tickets."""
    now = now or utcnow()
    opened = 0
    resolved = 0

    active = db.scalars(select(Alert).where(Alert.status != "Closed")).all()
    for alert in active:
        due = due_at(alert)
        if now <= due:
            continue
        exists = db.scalar(
            select(SlaBreach.id).where(SlaBreach.alert_id == alert.id, SlaBreach.due_at == due)
        )
        if exists:
            continue
        db.add(SlaBreach(
            alert_id=alert.id,
            alert_ref=alert.alert_id,
            severity=alert.severity,
            due_at=due,
            detected_at=now,
        ))
        opened += 1

    for breach in db.scalars(select(SlaBreach).where(SlaBreach.resolved_at.is_(None))).all():
        alert = db.get(Alert, breach.alert_id)
        if alert is not None and alert.status != "Closed":
            continue
        finished = (alert.closed_at if alert is not None and alert.closed_at else now)
        breach.resolved_at = finished
        breach.late_hours = max(0, int((finished - breach.due_at).total_seconds() // 3600))
        resolved += 1

    if opened or resolved:
        db.commit()
        logger.info("SLA sweep: %s new breach(es), %s resolved", opened, resolved)
    return {"opened": opened, "resolved": resolved}


def summary(db: Session) -> dict:
    """Counts for the dashboard and metrics endpoint."""
    rows = db.scalars(select(SlaBreach)).all()
    open_breaches = [row for row in rows if row.resolved_at is None]
    late = [row.late_hours for row in rows if row.late_hours is not None]
    return {
        "total": len(rows),
        "open": len(open_breaches),
        "closed": len(rows) - len(open_breaches),
        "average_late_hours": round(sum(late) / len(late), 1) if late else 0.0,
    }


def recent(db: Session, limit: int = 20) -> list[SlaBreach]:
    return list(db.scalars(select(SlaBreach).order_by(SlaBreach.detected_at.desc()).limit(limit)))
