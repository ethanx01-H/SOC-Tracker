"""SLA breach history.

The dashboard can say a ticket is overdue right now; this records that it *was*
overdue, so the count survives the ticket being closed. A sweep writes one row
per missed due date and closes it out with how late the ticket actually was.
"""

import logging
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..models import Alert, SlaBreach

logger = logging.getLogger("sentriq.sla")

# How often a page load may trigger a sweep. The dashboard calls this on every
# load, so without a floor the same scan ran for every analyst, every refresh.
SWEEP_INTERVAL = timedelta(seconds=120)

_last_sweep: datetime | None = None
_sweep_lock = threading.Lock()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def due_at(alert: Alert) -> datetime:
    return (alert.created_at or utcnow()) + timedelta(hours=alert.sla_hours or 8)


def sweep(db: Session, now: datetime | None = None) -> dict:
    """Record newly missed SLAs and close out breaches for finished tickets.

    Two queries instead of two per ticket: the open tickets and their existing
    breaches are read in bulk, and the comparison runs over plain rows rather
    than ORM objects.
    """
    now = now or utcnow()
    opened = 0
    resolved = 0

    active = db.execute(
        select(Alert.id, Alert.alert_id, Alert.severity, Alert.created_at, Alert.sla_hours)
        .where(Alert.status != "Closed")
    ).all()

    missed = []
    for alert_id, alert_ref, severity, created_at, sla_hours in active:
        due = (created_at or now) + timedelta(hours=sla_hours or 8)
        if now > due:
            missed.append((alert_id, alert_ref, severity, due))

    if missed:
        already = set(
            db.execute(
                select(SlaBreach.alert_id, SlaBreach.due_at)
                .where(SlaBreach.alert_id.in_([row[0] for row in missed]))
            ).all()
        )
        for alert_id, alert_ref, severity, due in missed:
            if (alert_id, due) in already:
                continue
            db.add(SlaBreach(
                alert_id=alert_id,
                alert_ref=alert_ref,
                severity=severity,
                due_at=due,
                detected_at=now,
            ))
            opened += 1

    for breach, status, closed_at in db.execute(
        select(SlaBreach, Alert.status, Alert.closed_at)
        .join(Alert, Alert.id == SlaBreach.alert_id, isouter=True)
        .where(SlaBreach.resolved_at.is_(None))
    ):
        if status is not None and status != "Closed":
            continue
        finished = closed_at if closed_at else now
        breach.resolved_at = finished
        breach.late_hours = max(0, int((finished - breach.due_at).total_seconds() // 3600))
        resolved += 1

    if opened or resolved:
        db.commit()
        logger.info("SLA sweep: %s new breach(es), %s resolved", opened, resolved)
    return {"opened": opened, "resolved": resolved}


def sweep_throttled(db: Session, now: datetime | None = None) -> dict:
    """Sweep at most once per SWEEP_INTERVAL, for callers on a page-load path.

    The first analyst to load the dashboard after the interval does the work;
    everyone else reads what the tiles already need.
    """
    global _last_sweep
    now = now or utcnow()
    with _sweep_lock:
        if _last_sweep is not None and now - _last_sweep < SWEEP_INTERVAL:
            return {"opened": 0, "resolved": 0, "skipped": True}
        _last_sweep = now
    return sweep(db, now=now)


def summary(db: Session) -> dict:
    """Counts for the dashboard and metrics endpoint, aggregated in SQL."""
    total, open_breaches, average_late = db.execute(
        select(
            func.count(),
            func.sum(case((SlaBreach.resolved_at.is_(None), 1), else_=0)),
            func.avg(SlaBreach.late_hours),
        )
    ).one()
    open_breaches = int(open_breaches or 0)
    total = int(total or 0)
    return {
        "total": total,
        "open": open_breaches,
        "closed": total - open_breaches,
        "average_late_hours": round(float(average_late), 1) if average_late is not None else 0.0,
    }


def recent(db: Session, limit: int = 20) -> list[SlaBreach]:
    return list(db.scalars(select(SlaBreach).order_by(SlaBreach.detected_at.desc()).limit(limit)))
