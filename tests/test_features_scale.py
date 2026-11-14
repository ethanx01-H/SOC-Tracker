"""Dashboard ranges, bulk actions, duplicate merging, and notifications."""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from soc_tracker import models
from soc_tracker.auth import hash_password
from soc_tracker.config import DISPLAY_TIMEZONE
from soc_tracker.models import Alert, AlertEvent, AuditLog, Evidence, User
from soc_tracker.services import merge_service, notify
from soc_tracker.services.alert_service import create_alert

from tests.support import make_session_factory


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    session = factory()
    session.add(User(username="l2", password_hash=hash_password("Password123!"), role="L2"))
    session.add(User(username="l1", password_hash=hash_password("Password123!"), role="L1"))
    session.commit()
    session.close()
    yield factory
    models.SessionLocal = original


@pytest.fixture
def client(sessions):
    from main import app

    with TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def sign_in(client, username="l2"):
    client.get("/login/")
    token = client.cookies.get("csrf_token")
    response = client.post("/login/", data={
        "username": username, "password": "Password123!", "csrf_token": token,
    })
    assert response.status_code == 303, response.text
    return client.cookies.get("csrf_token")


def seed_alert(db, user, title, *, hours_old=0, status="Open"):
    alert = create_alert(db, {
        "title": title, "description": "", "severity": "High", "asset": "SCALE-01",
        "tactic": "Execution", "iocs": [], "sla_hours": 8,
    }, user)
    alert.created_at = utcnow() - timedelta(hours=hours_old)
    alert.status = status
    db.commit()
    return alert


def test_dashboard_range_hides_older_tickets(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Fresh ticket", hours_old=1)
    seed_alert(db, user, "Old ticket", hours_old=24 * 40)
    db.close()

    token = sign_in(client)
    recent = client.get("/?range=24h")
    assert recent.status_code == 200
    assert "Fresh ticket" in recent.text
    assert "Old ticket" not in recent.text

    everything = client.get("/?range=all")
    assert "Old ticket" in everything.text
    assert token


def seed_at(db, user, title, when):
    alert = create_alert(db, {
        "title": title, "description": "", "severity": "High", "asset": "DATE-01",
        "tactic": "Execution", "iocs": [], "sla_hours": 8,
    }, user)
    alert.created_at = when
    db.commit()
    return alert


def local_to_utc(*args):
    """A local wall-clock moment in the team's timezone, as naive UTC."""
    local = datetime(*args, tzinfo=ZoneInfo(DISPLAY_TIMEZONE))
    return local.astimezone(timezone.utc).replace(tzinfo=None)


def test_custom_date_range_uses_the_local_day(client, sessions):
    """A picked date means that day where the analyst sits, not a UTC day."""
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    # 00:30 on 2 November in the display zone — the previous day in UTC.
    seed_at(db, user, "After midnight locally", local_to_utc(2026, 11, 2, 0, 30))
    db.close()

    sign_in(client)
    inside = client.get("/alerts/?from=2026-11-02&to=2026-11-02")
    assert "After midnight locally" in inside.text

    outside = client.get("/alerts/?from=2026-11-01&to=2026-11-01")
    assert "After midnight locally" not in outside.text


def test_custom_range_wins_over_the_preset_window(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_at(db, user, "Older ticket", local_to_utc(2026, 10, 1, 9, 0))
    db.close()

    sign_in(client)
    # The 24h preset would exclude it; the dates say otherwise and dates win.
    page = client.get("/alerts/?range=24h&from=2026-10-01&to=2026-10-01")
    assert "Older ticket" in page.text


def test_inverted_custom_range_is_read_as_a_window(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_at(db, user, "Window ticket", local_to_utc(2026, 10, 5, 12, 0))
    db.close()

    sign_in(client)
    page = client.get("/alerts/?from=2026-10-10&to=2026-10-01")
    assert "Window ticket" in page.text


def test_unparseable_dates_are_ignored(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Still visible")
    db.close()

    sign_in(client)
    page = client.get("/alerts/?from=not-a-date&to=31-02-2026")
    assert "Still visible" in page.text


def test_a_month_range_covers_the_whole_month(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_at(db, user, "Mid October ticket", local_to_utc(2026, 10, 20, 10, 15))
    # 23:00 on the last day: the exclusive upper bound must still include it.
    seed_at(db, user, "Halloween late ticket", local_to_utc(2026, 10, 31, 23, 0))
    db.close()

    sign_in(client)
    october = client.get("/alerts/?from=2026-10&to=2026-10")
    assert "Mid October ticket" in october.text
    assert "Halloween late ticket" in october.text

    september = client.get("/alerts/?from=2026-09&to=2026-09")
    assert "Mid October ticket" not in september.text
    assert "Halloween late ticket" not in september.text


def test_a_year_range_uses_local_year_boundaries(client, sessions):
    """00:30 on 1 January locally is still 31 December in UTC."""
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_at(db, user, "New year ticket", local_to_utc(2026, 1, 1, 0, 30))
    db.close()

    sign_in(client)
    assert "New year ticket" in client.get("/alerts/?from=2026&to=2026").text
    assert "New year ticket" not in client.get("/alerts/?from=2025&to=2025").text


def test_the_form_switches_inputs_to_the_period_in_the_url(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Granularity ticket")
    db.close()

    sign_in(client)
    month = client.get("/?from=2026-10&to=2026-10")
    assert 'type="month"' in month.text
    assert 'value="2026-10"' in month.text
    assert '<option value="month" selected' in month.text

    year = client.get("/?from=2026&to=2026")
    assert 'type="number"' in year.text
    assert 'value="2026"' in year.text
    assert '<option value="year" selected' in year.text

    day = client.get("/?from=2026-10-20")
    assert 'type="date"' in day.text
    assert '<option value="day" selected' in day.text


def test_the_form_renders_the_calendar_inputs(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Calendar ticket")
    db.close()

    sign_in(client)
    page = client.get("/?from=2026-11-01&to=2026-11-13")
    assert 'name="from"' in page.text
    assert 'name="to"' in page.text
    assert 'type="date"' in page.text
    assert 'value="2026-11-01"' in page.text
    assert 'value="2026-11-13"' in page.text


def test_dashboard_partial_request_returns_only_the_results(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Partial ticket")
    db.close()

    sign_in(client)
    page = client.get("/alerts/?q=Partial", headers={"X-Partial": "1"})
    assert page.status_code == 200
    assert "Partial ticket" in page.text
    assert "<html" not in page.text
    assert "results-bar" in page.text


def test_search_by_ticket_number_is_exact(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    wanted = seed_alert(db, user, "Wanted ticket")
    seed_alert(db, user, "Noise ticket", hours_old=1)
    number = wanted.alert_id.lstrip("#")
    db.close()

    sign_in(client)
    page = client.get(f"/alerts/?q={number}")
    assert "Wanted ticket" in page.text
    assert "Noise ticket" not in page.text


def test_search_by_analyst_ignores_timeline_text(client, sessions):
    """Searching a username must not match every ticket that user ever touched."""
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Unassigned ticket")
    db.close()

    sign_in(client)
    page = client.get("/alerts/?q=l2")
    assert "Unassigned ticket" not in page.text


def test_bulk_returns_to_the_page_it_came_from(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    alert = seed_alert(db, user, "Return ticket")
    db.close()

    token = sign_in(client)
    response = client.post("/alerts/bulk/", data={
        "csrf_token": token, "action": "status:WIP", "ids": [str(alert.id)],
        "next": "/alerts/mine/?severity=High",
    })
    assert response.status_code == 303
    assert response.headers["location"] == "/alerts/mine/?severity=High"


def test_bulk_ignores_an_offsite_next(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    alert = seed_alert(db, user, "Offsite ticket")
    db.close()

    token = sign_in(client)
    response = client.post("/alerts/bulk/", data={
        "csrf_token": token, "action": "status:WIP", "ids": [str(alert.id)],
        "next": "//evil.example/x",
    })
    assert response.headers["location"] == "/alerts/"


def test_bulk_toolbar_reports_selection_state(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Toolbar ticket")
    db.close()

    sign_in(client)
    page = client.get("/alerts/")
    assert "data-bulk-all" in page.text
    assert "data-bulk-count" in page.text
    # Apply stays disabled until something is ticked.
    assert "data-bulk-apply disabled" in page.text


def test_dashboard_has_no_bulk_editing(client, sessions):
    """Bulk editing belongs on the queue page, not the read-only dashboard."""
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    seed_alert(db, user, "Dashboard ticket")
    db.close()

    sign_in(client)
    for path in ("/", "/?range=all"):
        page = client.get(path)
        assert "Dashboard ticket" in page.text
        assert "data-bulk-all" not in page.text
        assert "row-check" not in page.text
        assert 'action="/alerts/bulk/"' not in page.text

    # The fragment the dashboard swaps in must match the page it replaces.
    fragment = client.get("/?range=all", headers={"X-Partial": "1"})
    assert "row-check" not in fragment.text
    assert "data-bulk-all" not in fragment.text


def test_bulk_reports_a_status_that_is_already_set(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    alert = seed_alert(db, user, "Already WIP", status="WIP")
    db.close()

    token = sign_in(client)
    response = client.post("/alerts/bulk/", data={
        "csrf_token": token, "action": "status:WIP", "ids": [str(alert.id)],
    })
    assert response.status_code == 303

    follow_up = client.get("/alerts/")
    assert "Updated 0 ticket(s)." in follow_up.text
    assert "already WIP" in follow_up.text

    db = sessions()
    assert db.get(Alert, alert.id).status == "WIP"
    assert db.scalar(select(AuditLog).where(AuditLog.action == "alert.bulk_update")) is None
    db.close()


def test_bulk_assign_to_me(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    first = seed_alert(db, user, "Bulk one")
    second = seed_alert(db, user, "Bulk two")
    ids = [str(first.id), str(second.id)]
    db.close()

    token = sign_in(client)
    response = client.post("/alerts/bulk/", data={
        "csrf_token": token, "action": "assign_me", "ids": ids,
    })
    assert response.status_code == 303

    db = sessions()
    for pk in (first.id, second.id):
        alert = db.get(Alert, pk)
        assert alert.analyst == "l2"
        assert alert.status == "Pending"
    audit_row = db.scalar(select(AuditLog).where(AuditLog.action == "alert.bulk_update"))
    assert audit_row is not None
    db.close()


def test_bulk_status_change_skips_closed_tickets(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    open_alert = seed_alert(db, user, "Open one")
    closed_alert = seed_alert(db, user, "Closed one", status="Closed")
    db.close()

    token = sign_in(client)
    client.post("/alerts/bulk/", data={
        "csrf_token": token, "action": "status:WIP",
        "ids": [str(open_alert.id), str(closed_alert.id)],
    })

    db = sessions()
    assert db.get(Alert, open_alert.id).status == "WIP"
    assert db.get(Alert, closed_alert.id).status == "Closed"
    db.close()


def test_bulk_without_selection_changes_nothing(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    alert = seed_alert(db, user, "Untouched")
    db.close()

    token = sign_in(client)
    response = client.post("/alerts/bulk/", data={"csrf_token": token, "action": "status:WIP"})
    assert response.status_code == 303

    db = sessions()
    assert db.get(Alert, alert.id).status == "Open"
    db.close()


def test_merge_moves_events_and_evidence(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    source = seed_alert(db, user, "Duplicate ticket")
    target = seed_alert(db, user, "Original ticket")
    db.add(Evidence(alert=source, original_name="dup.txt", stored_name="dup.txt", size_bytes=3, sha256="a" * 64))
    db.commit()
    source_pk, target_pk = source.id, target.id
    target_ref = target.alert_id
    db.close()

    token = sign_in(client)
    response = client.post(f"/alerts/{source_pk}/merge/", data={
        "csrf_token": token, "target_alert_id": target_ref,
    })
    assert response.status_code == 303, response.text
    assert response.headers["location"].startswith(f"/alerts/{target_pk}/")

    db = sessions()
    merged = db.get(Alert, source_pk)
    assert merged.status == "Closed"
    assert merged.duplicate_of_id == target_pk
    assert db.scalar(select(Evidence).where(Evidence.alert_id == target_pk)) is not None
    assert db.scalar(select(AlertEvent).where(AlertEvent.alert_id == target_pk, AlertEvent.event_type == "merged"))
    audit_row = db.scalar(select(AuditLog).where(AuditLog.action == "alert.merged"))
    assert audit_row is not None
    db.close()


def test_merge_rejects_a_closed_target(client, sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    source = seed_alert(db, user, "Live ticket")
    target = seed_alert(db, user, "Finished ticket", status="Closed")
    target_ref = target.alert_id
    db.close()

    token = sign_in(client)
    client.post(f"/alerts/{source.id}/merge/", data={"csrf_token": token, "target_alert_id": target_ref})

    db = sessions()
    assert db.get(Alert, source.id).status == "Open"
    db.close()


def test_merge_service_refuses_self_merge(sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    alert = seed_alert(db, user, "Lonely ticket")
    with pytest.raises(merge_service.MergeError):
        merge_service.merge_alerts(db, alert, alert, user)
    db.close()


def test_possible_duplicates_match_on_asset(sessions):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    first = seed_alert(db, user, "First report")
    second = create_alert(db, {
        "title": "Different wording", "description": "", "severity": "Low",
        "asset": "SCALE-01", "tactic": "Execution", "iocs": [], "sla_hours": 8,
    }, user)
    db.commit()
    matches = merge_service.possible_duplicates(db, second)
    assert first in matches
    db.close()


def test_notifications_are_inert_until_configured(monkeypatch):
    monkeypatch.setattr(notify, "SMTP_HOST", None)
    monkeypatch.setattr(notify, "NOTIFY_EMAIL_TO", ())
    monkeypatch.setattr(notify, "NOTIFY_TEAMS_WEBHOOK", None)
    called = []
    monkeypatch.setattr(notify, "_deliver", lambda *args: called.append(args))

    class FakeAlert:
        severity = "Critical"
        alert_id = "#1"
        title = "Test"
        status = "Open"
        asset = "A"
        analyst = "l1"
        description = "d"

        def get_absolute_url(self):
            return "/alerts/1/"

    notify.notify(FakeAlert(), "created", "l1")
    assert called == []
    assert notify.enabled()["email"] is False


def test_notification_body_carries_the_ticket_and_link():
    class FakeAlert:
        severity = "Critical"
        alert_id = "#42"
        title = "Ransomware on FS-01"
        status = "Open"
        asset = "FS-01"
        analyst = "l1"
        description = "Encrypted shares"

        def get_absolute_url(self):
            return "/alerts/42/"

    subject, body = notify.compose(FakeAlert(), "assign", "admin", "https://soc.example")
    assert "Critical" in subject and "#42" in subject
    assert "https://soc.example/alerts/42/" in body
    assert "Encrypted shares" in body


def test_teams_delivery_posts_a_message_card(monkeypatch):
    sent = {}

    def fake_post(url, json=None, timeout=None):
        sent["url"] = url
        sent["json"] = json

        class Response:
            def raise_for_status(self):
                return None

        return Response()

    monkeypatch.setattr(notify.httpx, "post", fake_post)
    monkeypatch.setattr(notify, "NOTIFY_TEAMS_WEBHOOK", "https://teams.example/hook")
    notify._deliver("Subject", "Body text")
    assert sent["url"] == "https://teams.example/hook"
    assert sent["json"]["title"] == "Subject"
    assert sent["json"]["@type"] == "MessageCard"
