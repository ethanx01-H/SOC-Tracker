"""Archive and remove tickets past the retention window.

The README promises 730 days. This module is what actually enforces it, and it
is deliberately two-step: the archive is written, read back and counted before
anything is deleted. A dry run is the default, so a mistyped command cannot
destroy history — it prints what it would do and exits.

Archives are gzipped JSON Lines, one object per ticket, containing the ticket,
its timeline, its evidence metadata (including SHA-256) and its SLA breaches.
Evidence files are deleted only after that line is safely on disk.
"""

import gzip
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import ARCHIVE_DIR, RETENTION_DAYS, UPLOAD_DIR
from ..models import Alert, AlertEvent, AuditLog, Evidence, SlaBreach

logger = logging.getLogger("sentriq.retention")


def utcnow() -> datetime:
    """Naive UTC, matching how timestamps are stored."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def retention_cutoff(days: int = RETENTION_DAYS, now: datetime | None = None) -> datetime:
    return (now or utcnow()) - timedelta(days=days)


def closed_reference(alert: Alert) -> datetime | None:
    """When the clock started for this ticket's retention period."""
    return alert.closed_at or alert.updated_at or alert.created_at


def expired_alerts(db: Session, days: int = RETENTION_DAYS, now: datetime | None = None) -> list[Alert]:
    """Closed tickets whose retention period has elapsed."""
    cutoff = retention_cutoff(days, now)
    closed = db.scalars(select(Alert).where(Alert.status == "Closed")).all()
    return [alert for alert in closed if (closed_reference(alert) or cutoff) < cutoff]


def serialise_alert(db: Session, alert: Alert) -> dict:
    events = db.scalars(
        select(AlertEvent).where(AlertEvent.alert_id == alert.id).order_by(AlertEvent.id)
    ).all()
    evidence = db.scalars(select(Evidence).where(Evidence.alert_id == alert.id)).all()
    breaches = db.scalars(select(SlaBreach).where(SlaBreach.alert_id == alert.id)).all()
    return {
        "alert": {
            "id": alert.id,
            "alert_id": alert.alert_id,
            "external_id": alert.external_id,
            "title": alert.title,
            "description": alert.description,
            "source": alert.source,
            "severity": alert.severity,
            "status": alert.status,
            "analyst": alert.analyst,
            "tactic": alert.tactic,
            "asset": alert.asset,
            "iocs": alert.iocs,
            "sla_hours": alert.sla_hours,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
            "closed_at": alert.closed_at.isoformat() if alert.closed_at else None,
            "duplicate_of_id": alert.duplicate_of_id,
        },
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "message": event.message,
                "source": event.source,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }
            for event in events
        ],
        "evidence": [
            {
                "id": item.id,
                "original_name": item.original_name,
                "stored_name": item.stored_name,
                "content_type": item.content_type,
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in evidence
        ],
        "sla_breaches": [
            {
                "alert_ref": breach.alert_ref,
                "severity": breach.severity,
                "due_at": breach.due_at.isoformat() if breach.due_at else None,
                "detected_at": breach.detected_at.isoformat() if breach.detected_at else None,
                "resolved_at": breach.resolved_at.isoformat() if breach.resolved_at else None,
                "late_hours": breach.late_hours,
            }
            for breach in breaches
        ],
    }


def archive(
    db: Session,
    days: int = RETENTION_DAYS,
    apply: bool = False,
    now: datetime | None = None,
    archive_dir: Path | None = None,
) -> dict:
    """Write an archive of expired tickets, then (only with ``apply``) delete them."""
    now = now or utcnow()
    directory = Path(archive_dir or ARCHIVE_DIR)
    targets = expired_alerts(db, days, now)
    summary = {
        "days": days,
        "cutoff": retention_cutoff(days, now).isoformat(),
        "alerts": len(targets),
        "events": 0,
        "evidence": 0,
        "sla_breaches": 0,
        "evidence_bytes": 0,
        "archive": None,
        "applied": False,
        "alert_refs": [alert.alert_id for alert in targets],
    }
    if not targets:
        return summary

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"alerts-{now.strftime('%Y%m%dT%H%M%SZ')}.jsonl.gz"

    records = []
    for alert in targets:
        record = serialise_alert(db, alert)
        summary["events"] += len(record["events"])
        summary["evidence"] += len(record["evidence"])
        summary["sla_breaches"] += len(record["sla_breaches"])
        summary["evidence_bytes"] += sum(item["size_bytes"] for item in record["evidence"])
        records.append(record)

    if not apply:
        # A dry run must not write anything: an operator checking the window
        # should not leave archive files behind.
        summary["would_write"] = str(path)
        logger.info("Retention dry run: %s tickets would be archived to %s", len(targets), path)
        return summary

    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    summary["archive"] = str(path)

    # Read it back before deleting anything: an archive nobody can open is worse
    # than no archive, because the source data is already gone by then.
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        written = sum(1 for _ in handle)
    if written != len(records):
        path.unlink(missing_ok=True)
        raise RuntimeError(f"Archive verification failed: wrote {written} of {len(records)} tickets.")

    alert_ids = [alert.id for alert in targets]
    evidence_rows = db.scalars(select(Evidence).where(Evidence.alert_id.in_(alert_ids))).all()
    for item in evidence_rows:
        (Path(UPLOAD_DIR) / item.stored_name).unlink(missing_ok=True)

    db.execute(delete(Evidence).where(Evidence.alert_id.in_(alert_ids)))
    db.execute(delete(SlaBreach).where(SlaBreach.alert_id.in_(alert_ids)))
    db.execute(delete(AlertEvent).where(AlertEvent.alert_id.in_(alert_ids)))
    db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
    db.add(AuditLog(
        action="retention.archived",
        target_type="alert_batch",
        target_id=str(len(alert_ids)),
        message=(
            f"Archived and removed {len(alert_ids)} ticket(s) closed more than {days} days ago "
            f"to {path.name} ({summary['evidence']} evidence file(s), "
            f"{summary['evidence_bytes']} bytes)."
        ),
    ))
    db.commit()
    summary["applied"] = True
    logger.warning("Retention removed %s archived tickets", len(alert_ids))
    return summary
