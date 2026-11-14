"""Login lockout must be scoped per (address, username) and per account."""

import pytest
from fastapi.testclient import TestClient

from sentriq import models
from sentriq.auth import hash_password
from sentriq.models import AuditLog, User
from tests.support import make_session_factory


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    for name in ("l1", "l2"):
        db.add(User(username=name, password_hash=hash_password("Password123!"), role="L1"))
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


@pytest.fixture
def client(sessions):
    from main import app
    return TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000))


def csrf_token(client, address):
    client.get("/login/", headers={"X-Forwarded-For": address})
    return client.cookies.get("csrf_token")


def attempt(client, username, password, address):
    return client.post(
        "/login/",
        data={"username": username, "password": password, "csrf_token": csrf_token(client, address)},
        headers={"X-Forwarded-For": address},
    )


def test_one_analysts_typos_do_not_lock_the_team_out(client):
    for _ in range(5):
        assert attempt(client, "l1", "wrong-password", "203.0.113.5").status_code == 200
    # A colleague behind the same proxy address signs in normally.
    assert attempt(client, "l2", "Password123!", "203.0.113.5").status_code == 303


def test_account_locks_out_across_rotating_addresses(client):
    for index in range(10):
        attempt(client, "l1", "wrong-password", f"203.0.113.{index + 1}")
    blocked = attempt(client, "l1", "Password123!", "203.0.113.200")
    assert blocked.status_code == 429
    assert "Too many failed attempts" in blocked.text
    assert blocked.headers["retry-after"]
    # The account lock is scoped to that account only.
    assert attempt(client, "l2", "Password123!", "203.0.113.200").status_code == 303


def test_successful_login_clears_only_its_own_counters(client):
    for _ in range(4):
        attempt(client, "l1", "wrong-password", "203.0.113.5")
        attempt(client, "l2", "wrong-password", "203.0.113.5")
    assert attempt(client, "l1", "Password123!", "203.0.113.5").status_code == 303
    # l1's counter was reset by its own success: one more typo is not a lockout.
    assert attempt(client, "l1", "wrong-password", "203.0.113.5").status_code == 200
    # l2 still carries its four failures, so its fifth trips the threshold and
    # the next attempt is refused.
    assert attempt(client, "l2", "wrong-password", "203.0.113.5").status_code == 200
    assert attempt(client, "l2", "wrong-password", "203.0.113.5").status_code == 429


def test_audit_trail_records_the_forwarded_address(client, sessions):
    attempt(client, "l1", "wrong-password", "203.0.113.77")
    db = sessions()
    try:
        rows = db.query(AuditLog).filter(AuditLog.action == "auth.login_failed").all()
        assert rows
        assert {row.source_ip for row in rows} == {"203.0.113.77"}
    finally:
        db.close()
