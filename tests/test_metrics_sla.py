"""SLA breach history, backup freshness, and the /metrics endpoint."""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.auth import hash_password
from soc_tracker.models import Alert, SlaBreach, User
from soc_tracker.services import backup_status, metrics, sla_service
from soc_tracker.services.alert_service import create_alert

from tests.support import make_session_factory


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def make_alert(db, user, *, hours_old=10, sla_hours=8, status="Open"):
    alert = create_alert(db, {
        "title": f"SLA fixture {hours_old}h", "description": "", "severity": "High",
        "asset": "SLA-01", "tactic": "Execution", "iocs": [], "sla_hours": sla_hours,
    }, user)
    alert.created_at = utcnow() - timedelta(hours=hours_old)
    alert.status = status
    db.commit()
    return alert


def test_sweep_records_a_breach_once(db, sample_user):
    make_alert(db, sample_user, hours_old=10, sla_hours=8)

    first = sla_service.sweep(db)
    second = sla_service.sweep(db)

    assert first["opened"] == 1
    assert second["opened"] == 0
    assert len(db.query(SlaBreach).all()) == 1


def test_sweep_ignores_tickets_inside_their_sla(db, sample_user):
    make_alert(db, sample_user, hours_old=2, sla_hours=8)
    assert sla_service.sweep(db)["opened"] == 0


def test_closing_a_breached_ticket_records_how_late(db, sample_user):
    alert = make_alert(db, sample_user, hours_old=20, sla_hours=8)
    sla_service.sweep(db)

    alert.status = "Closed"
    alert.closed_at = utcnow()
    db.commit()
    result = sla_service.sweep(db)

    breach = db.query(SlaBreach).one()
    assert result["resolved"] == 1
    assert breach.resolved_at is not None
    # Due 8h after creation, closed 20h after creation: 12 hours late.
    assert breach.late_hours == 12


def test_summary_counts_open_and_resolved(db, sample_user):
    make_alert(db, sample_user, hours_old=20, sla_hours=8)
    sla_service.sweep(db)
    summary = sla_service.summary(db)
    assert summary["total"] == 1
    assert summary["open"] == 1
    assert summary["closed"] == 0


def test_backup_status_flags_a_missing_snapshot(tmp_path):
    info = backup_status.status(tmp_path)
    assert info["count"] == 0
    assert info["stale"] is True
    assert info["age_seconds"] is None


def test_backup_status_measures_the_newest_snapshot(tmp_path):
    old = tmp_path / "soc-data-20260101T000000Z.tar.gz"
    new = tmp_path / "soc-data-20260102T000000Z.tar.gz"
    old.write_bytes(b"x")
    new.write_bytes(b"yy")
    ten_hours_ago = time.time() - 10 * 3600
    two_hours_ago = time.time() - 2 * 3600
    os.utime(old, (ten_hours_ago, ten_hours_ago))
    os.utime(new, (two_hours_ago, two_hours_ago))

    info = backup_status.status(tmp_path, max_age_hours=36)
    assert info["count"] == 2
    assert info["newest"] == new.name
    assert 7100 < info["age_seconds"] < 7300
    assert info["stale"] is False


def test_backup_status_flags_a_stale_snapshot(tmp_path):
    path = tmp_path / "soc-data-20260101T000000Z.tar.gz"
    path.write_bytes(b"x")
    long_ago = time.time() - 72 * 3600
    os.utime(path, (long_ago, long_ago))
    assert backup_status.status(tmp_path, max_age_hours=36)["stale"] is True


def test_metrics_render_exposes_the_gauges(db, sample_user):
    make_alert(db, sample_user)
    metrics.reset()
    metrics.record_request("GET", 200, 0.01)
    text = metrics.render(db)

    assert "soc_alerts_total" in text
    assert 'soc_alerts{status="Open"}' in text
    assert 'soc_alerts_by_severity{severity="High"}' in text
    assert 'soc_requests_total{method="GET",status="2xx"} 1' in text
    assert "soc_backup_age_seconds" in text
    assert "# TYPE soc_requests_total counter" in text


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    db.add(User(username="metrics_admin", password_hash=hash_password("MetricsPass123!"), role="L3", is_admin=True))
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


def test_metrics_endpoint_answers_loopback(sessions):
    from main import app

    client = TestClient(app, client=("127.0.0.1", 50000))
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "soc_alerts_total" in response.text


def test_metrics_endpoint_refuses_a_public_caller(sessions):
    from main import app

    client = TestClient(app, client=("203.0.113.7", 50000))
    response = client.get("/metrics")
    assert response.status_code == 403
    assert response.json()["ok"] is False


def test_metrics_endpoint_accepts_a_bearer_token(sessions, monkeypatch):
    from main import app
    from soc_tracker.routes import metrics_routes

    monkeypatch.setattr(metrics_routes, "METRICS_TOKEN", "scrape-me")
    client = TestClient(app, client=("203.0.113.7", 50000))

    assert client.get("/metrics").status_code == 403
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 403
    ok = client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
    assert ok.status_code == 200


def test_healthz_reports_backup_freshness(sessions, tmp_path, monkeypatch):
    from main import app
    from soc_tracker.services import backup_status as backup_module

    snapshot = tmp_path / "soc-data-20260101T000000Z.tar.gz"
    snapshot.write_bytes(b"x")
    monkeypatch.setattr(backup_module, "BACKUP_DIR", tmp_path)

    client = TestClient(app, client=("127.0.0.1", 50000))
    body = client.get("/healthz").json()
    assert body["database"] == "ok"
    assert body["backup"]["count"] == 1
    assert body["status"] in {"ok", "degraded"}


def test_backup_status_counts_postgres_dumps_too(tmp_path, monkeypatch):
    """A Postgres instance writes .dump files; freshness must see them."""
    monkeypatch.setattr(backup_status, "database_mode", lambda: "postgres")
    dump = tmp_path / "soc-pg-20260102-000000.dump"
    dump.write_bytes(b"custom-format dump")
    just_now = time.time() - 60
    os.utime(dump, (just_now, just_now))

    info = backup_status.status(tmp_path, max_age_hours=36)
    assert info["mode"] == "postgres"
    assert info["count"] == 1
    assert info["newest"] == dump.name
    assert info["stale"] is False


def test_backup_status_says_which_database_it_is_watching(tmp_path):
    assert backup_status.status(tmp_path)["mode"] in {"sqlite", "postgres"}
