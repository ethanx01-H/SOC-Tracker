"""Deleting an account is allowed only while it has no history to lose."""

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.auth import hash_password
from soc_tracker.models import AuditLog, User
from soc_tracker.services.alert_service import create_alert

from tests.support import make_session_factory


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    db.add_all([
        User(username="admin_l3", password_hash=hash_password("AdminPass123!"), role="L3", is_admin=True),
        User(username="leaver", password_hash=hash_password("Password123!"), role="L1"),
        User(username="worker", password_hash=hash_password("Password123!"), role="L1"),
    ])
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


def make_client():
    from main import app
    return TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000))


def csrf_token(client, path="/login/"):
    client.get(path)
    return client.cookies.get("csrf_token")


def sign_in(client, username="admin_l3", password="AdminPass123!"):
    return client.post("/login/", data={
        "username": username, "password": password, "csrf_token": csrf_token(client),
    })


def user_id(sessions, username):
    db = sessions()
    try:
        return db.query(User).filter_by(username=username).one().id
    finally:
        db.close()


def delete_user(admin, sessions, username):
    return admin.post(
        f"/admin/users/{user_id(sessions, username)}/delete/",
        data={"csrf_token": csrf_token(admin, "/admin/users/")},
    )


def flash(client):
    return client.get("/admin/users/").text


def test_unused_account_is_deleted(sessions):
    admin = make_client()
    sign_in(admin)
    assert delete_user(admin, sessions, "leaver").status_code == 303

    db = sessions()
    try:
        assert db.query(User).filter_by(username="leaver").count() == 0
        assert db.query(AuditLog).filter_by(action="user.deleted").count() == 1
    finally:
        db.close()
    assert "Deleted user leaver" in flash(admin)


def test_account_with_ticket_history_is_not_deleted(sessions):
    db = sessions()
    worker = db.query(User).filter_by(username="worker").one()
    create_alert(db, {
        "title": "Worked ticket", "description": "", "source": "Manual",
        "severity": "Low", "status": "WIP", "analyst": "worker",
        "tactic": "Unknown", "asset": "Unknown", "sla_hours": 8,
    }, worker)
    db.commit()
    db.close()

    admin = make_client()
    sign_in(admin)
    assert delete_user(admin, sessions, "worker").status_code == 303

    db = sessions()
    try:
        assert db.query(User).filter_by(username="worker").count() == 1
        # Attribution on the ticket is intact.
        assert db.query(models.Alert).one().created_by.username == "worker"
    finally:
        db.close()
    # Flash messages are one-shot: read the page once.
    page = flash(admin)
    assert "Cannot delete worker" in page
    assert "1 ticket" in page


def test_account_that_only_ever_signed_in_is_not_deleted(sessions):
    worker_client = make_client()
    sign_in(worker_client, "worker", "Password123!")

    admin = make_client()
    sign_in(admin)
    assert delete_user(admin, sessions, "worker").status_code == 303
    assert "audit entr" in flash(admin)

    db = sessions()
    try:
        assert db.query(User).filter_by(username="worker").count() == 1
    finally:
        db.close()


def test_admin_cannot_delete_themselves(sessions):
    admin = make_client()
    sign_in(admin)
    assert delete_user(admin, sessions, "admin_l3").status_code == 303
    assert "cannot delete your own account" in flash(admin)

    db = sessions()
    try:
        assert db.query(User).filter_by(username="admin_l3").count() == 1
    finally:
        db.close()
