"""Timestamps are stored in UTC and rendered in the team's timezone."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.auth import hash_password
from soc_tracker.models import Alert, User
from soc_tracker.services.alert_service import create_alert
from soc_tracker.utils import timezone_label, to_local

from tests.support import make_session_factory

YANGON = timezone(timedelta(hours=6, minutes=30))


def test_naive_utc_is_treated_as_utc():
    assert to_local(datetime(2026, 11, 13, 8, 0)) == "2026-11-13 14:30:00"


def test_aware_utc_converts():
    assert to_local(datetime(2026, 11, 13, 8, 0, tzinfo=timezone.utc)) == "2026-11-13 14:30:00"


def test_iso_string_converts():
    assert to_local("2026-11-13T08:00:00") == "2026-11-13 14:30:00"


def test_none_renders_empty():
    assert to_local(None) == ""


def test_label_shows_the_offset():
    assert timezone_label() == "Asia/Yangon (UTC+06:30)"


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    db.add(User(username="l1", password_hash=hash_password("Password123!"), role="L1"))
    db.commit()
    create_alert(db, {
        "title": "Timed ticket", "description": "", "source": "Manual",
        "severity": "Low", "status": "Open", "analyst": "l1",
        "tactic": "Unknown", "asset": "Unknown", "sla_hours": 8,
    })
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


def test_detail_page_renders_local_time_with_a_label(sessions):
    from main import app
    client = TestClient(app, follow_redirects=False)
    client.get("/login/")
    client.post("/login/", data={
        "username": "l1", "password": "Password123!", "csrf_token": client.cookies.get("csrf_token"),
    })
    page = client.get("/alerts/1/").text
    assert "Asia/Yangon (UTC+06:30)" in page
    # The stored UTC timestamp is shown shifted by 6h30m.
    db = sessions()
    event = db.query(models.AlertEvent).first()
    db.close()
    expected = to_local(event.created_at)
    assert expected in page
    utc_text = event.created_at.strftime("%Y-%m-%d %H:%M:%S")
    assert utc_text not in page
