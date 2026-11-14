"""Merge duplicate tickets.

A merge moves the duplicate's timeline and evidence onto the surviving ticket,
then closes the duplicate with a pointer to where its history went. Nothing is
deleted: the merged ticket still opens, still shows what it held, and says where
the investigation continues.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, AlertEvent, Evidence, User

logger = logging.getLogger("sentriq.merge")


class MergeError(Exception):
    """A merge that cannot be performed; the message is safe to show."""


def merge_alerts(db: Session, source: Alert, target: Alert, user: User) -> dict:
    if source.id == target.id:
        raise MergeError("A ticket cannot be merged into itself.")
    if source.status == "Closed":
        raise MergeError("This ticket is already closed.")
    if target.status == "Closed":
        raise MergeError("The target ticket is closed; merge into an open one.")
    if source.duplicate_of_id:
        raise MergeError("This ticket was already merged into another one.")

    moved_events = 0
    for event in db.scalars(select(AlertEvent).where(AlertEvent.alert_id == source.id)).all():
        event.alert_id = target.id
        moved_events += 1

    moved_evidence = 0
    for item in db.scalars(select(Evidence).where(Evidence.alert_id == source.id)).all():
        item.alert_id = target.id
        moved_evidence += 1

    source.duplicate_of_id = target.id
    source.status = "Closed"
    source.closed_at = datetime.now(timezone.utc)
    source.updated_by = user

    db.add(AlertEvent(
        alert=target,
        event_type="merged",
        actor=user,
        message=(
            f"{user.username} merged {source.alert_id} into this ticket "
            f"({moved_events} timeline event(s), {moved_evidence} evidence file(s) moved)."
        ),
        source="tracker",
    ))
    db.add(AlertEvent(
        alert=source,
        event_type="merged",
        actor=user,
        message=f"{user.username} merged this ticket into {target.alert_id}.",
        source="tracker",
    ))

    logger.info("Merged %s into %s", source.alert_id, target.alert_id)
    return {
        "source": source.alert_id,
        "target": target.alert_id,
        "events": moved_events,
        "evidence": moved_evidence,
    }


def possible_duplicates(db: Session, alert: Alert, hours: int = 24, limit: int = 5) -> list[Alert]:
    """Tickets filed around the same time with the same title or asset.

    Advisory only — shown on the ticket, never enforced. Analysts know when two
    alerts about one host are genuinely different events.
    """
    from datetime import timedelta

    window_start = (alert.created_at or datetime.now(timezone.utc)) - timedelta(hours=hours)
    query = (
        select(Alert)
        .where(
            Alert.id != alert.id,
            Alert.created_at >= window_start,
            Alert.duplicate_of_id.is_(None),
        )
        .order_by(Alert.created_at.desc())
        .limit(limit * 4)
    )
    matches = []
    for candidate in db.scalars(query).all():
        same_title = candidate.title.strip().lower() == alert.title.strip().lower()
        same_asset = (candidate.asset or "").strip().lower() == (alert.asset or "").strip().lower()
        if same_title or (same_asset and alert.asset not in {"", "Unknown"}):
            matches.append(candidate)
        if len(matches) >= limit:
            break
    return matches
