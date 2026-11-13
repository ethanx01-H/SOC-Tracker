"""Retention archival and the hash-chained audit export."""

import gzip
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from soc_tracker.models import Alert, AuditLog, Evidence, SlaBreach, User
from soc_tracker.services import audit_export, retention_service
from soc_tracker.services.alert_service import create_alert


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def make_alert(db, user, *, title, status="Closed", closed_days_ago=800):
    alert = create_alert(db, {
        "title": title, "description": "retention fixture", "severity": "Medium",
        "asset": "RET-01", "tactic": "Execution", "iocs": [], "sla_hours": 8,
    }, user)
    alert.status = status
    if status == "Closed":
        alert.closed_at = utcnow() - timedelta(days=closed_days_ago)
        alert.updated_at = alert.closed_at
    db.commit()
    return alert


@pytest.fixture
def operator(db):
    user = User(username="ret_op", password_hash="x", role="L3", is_admin=True)
    db.add(user)
    db.commit()
    return user


def test_dry_run_changes_nothing(db, operator, tmp_path):
    old = make_alert(db, operator, title="Old closed ticket")
    db.add(Evidence(alert=old, original_name="a.txt", stored_name="a.txt", size_bytes=1, sha256="0" * 64))
    db.commit()

    summary = retention_service.archive(db, days=730, apply=False, archive_dir=tmp_path)

    assert summary["alerts"] == 1
    assert summary["applied"] is False
    assert summary["archive"] is None
    assert db.get(Alert, old.id) is not None
    assert list(tmp_path.iterdir()) == []


def test_apply_archives_then_removes(db, operator, tmp_path, monkeypatch):
    monkeypatch.setattr(retention_service, "UPLOAD_DIR", tmp_path / "evidence")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "keep.txt").write_text("payload")

    old = make_alert(db, operator, title="Ticket past retention")
    db.add(Evidence(alert=old, original_name="keep.txt", stored_name="keep.txt",
                    size_bytes=7, sha256="abc123"))
    db.add(SlaBreach(alert_id=old.id, alert_ref=old.alert_id, severity="Medium",
                     due_at=utcnow() - timedelta(days=800), detected_at=utcnow()))
    db.commit()

    summary = retention_service.archive(db, days=730, apply=True, archive_dir=tmp_path)

    assert summary["applied"] is True
    assert summary["alerts"] == 1
    assert summary["evidence"] == 1
    assert summary["sla_breaches"] == 1
    assert db.get(Alert, old.id) is None
    assert db.scalar(select(Evidence).where(Evidence.alert_id == old.id)) is None
    assert db.scalar(select(SlaBreach).where(SlaBreach.alert_id == old.id)) is None
    assert not (tmp_path / "evidence" / "keep.txt").exists()

    audit_row = db.scalar(select(AuditLog).where(AuditLog.action == "retention.archived"))
    assert audit_row is not None
    assert "1 ticket" in audit_row.message


def test_archive_file_keeps_the_evidence_metadata(db, operator, tmp_path):
    old = make_alert(db, operator, title="Archived with evidence")
    db.add(Evidence(alert=old, original_name="hashme.txt", stored_name="stored.txt",
                    size_bytes=4, sha256="f" * 64))
    db.commit()

    summary = retention_service.archive(db, days=730, apply=True, archive_dir=tmp_path)

    with gzip.open(summary["archive"], "rt", encoding="utf-8") as handle:
        record = json.loads(handle.readline())
    assert record["alert"]["alert_id"] == old.alert_id
    assert record["evidence"][0]["original_name"] == "hashme.txt"
    assert record["evidence"][0]["sha256"] == "f" * 64


def test_recent_and_open_tickets_are_never_archived(db, operator, tmp_path):
    make_alert(db, operator, title="Closed yesterday", closed_days_ago=1)
    make_alert(db, operator, title="Still open", status="WIP")

    summary = retention_service.archive(db, days=730, apply=True, archive_dir=tmp_path)

    assert summary["alerts"] == 0
    assert db.scalar(select(Alert).where(Alert.title == "Closed yesterday")) is not None
    assert db.scalar(select(Alert).where(Alert.title == "Still open")) is not None


def test_retention_uses_the_closure_date_not_the_creation_date(db, operator, tmp_path):
    """A ticket opened long ago but closed yesterday keeps its full window."""
    alert = make_alert(db, operator, title="Old but recently closed", closed_days_ago=1)
    alert.created_at = utcnow() - timedelta(days=900)
    db.commit()

    summary = retention_service.archive(db, days=730, apply=True, archive_dir=tmp_path)
    assert summary["alerts"] == 0


def test_audit_export_verifies(db, tmp_path):
    db.add(AuditLog(action="test.one", message="first", target_type="alert", target_id="1"))
    db.add(AuditLog(action="test.two", message="second", target_type="alert", target_id="2"))
    db.commit()

    result = audit_export.export(db, directory=tmp_path)
    assert result["records"] >= 2
    verdict = audit_export.verify(result["path"])
    assert verdict["ok"] is True
    assert verdict["head"] == result["head"]


def test_audit_export_detects_an_edited_record(db, tmp_path):
    db.add(AuditLog(action="test.one", message="first"))
    db.add(AuditLog(action="test.two", message="second"))
    db.commit()
    result = audit_export.export(db, directory=tmp_path)

    path = result["path"]
    lines = open(path, encoding="utf-8").read().splitlines()
    entry = json.loads(lines[0])
    entry["record"]["message"] = "tampered"
    lines[0] = json.dumps(entry, sort_keys=True)
    # The file is read-only by design; make it writable the way an attacker would.
    import os
    os.chmod(path, 0o644)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    verdict = audit_export.verify(path)
    assert verdict["ok"] is False
    assert verdict["broken_at"] == 1


def test_audit_export_detects_a_removed_record(db, tmp_path):
    for index in range(3):
        db.add(AuditLog(action=f"test.{index}", message=f"row {index}"))
    db.commit()
    result = audit_export.export(db, directory=tmp_path)

    import os
    path = result["path"]
    lines = open(path, encoding="utf-8").read().splitlines()
    os.chmod(path, 0o644)
    open(path, "w", encoding="utf-8").write("\n".join(lines[:1] + lines[2:]) + "\n")

    verdict = audit_export.verify(path)
    assert verdict["ok"] is False
    assert "manifest" in verdict["reason"] or verdict["broken_at"] == 3
