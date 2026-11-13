"""Deactivating an account locks it out without deleting it."""

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.auth import hash_password
from soc_tracker.models import AuditLog, User

from tests.support import make_session_factory


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    db.add_all([
        User(username="admin_l3", password_hash=hash_password("AdminPass123!"), role="L3", is_admin=True),
        User(username="l1", password_hash=hash_password("Password123!"), role="L1"),
        User(username="l2", password_hash=hash_password("Password123!"), role="L1"),
    ])
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


@pytest.fixture
def client(sessions):
    from main import app
    return TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000))


def csrf_token(client, path="/login/"):
    client.get(path)
    return client.cookies.get("csrf_token")


def sign_in(client, username, password):
    return client.post("/login/", data={
        "username": username, "password": password, "csrf_token": csrf_token(client),
    })


def user_id(sessions, username):
    db = sessions()
    try:
        return db.query(User).filter_by(username=username).one().id
    finally:
        db.close()


def set_active(admin, sessions, username, active):
    return admin.post(
        f"/admin/users/{user_id(sessions, username)}/active/",
        data={"is_active": "true" if active else "false", "csrf_token": csrf_token(admin, "/admin/users/")},
    )


def test_deactivated_account_cannot_sign_in(client, sessions):
    admin = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    sign_in(admin, "admin_l3", "AdminPass123!")
    assert set_active(admin, sessions, "l1", False).status_code == 303

    attacker_view = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    response = sign_in(attacker_view, "l1", "Password123!")
    assert response.status_code == 200
    assert "Invalid username or password" in response.text

    db = sessions()
    try:
        assert db.query(User).filter_by(username="l1").one().is_active is False
        assert db.query(AuditLog).filter_by(action="auth.login_inactive").count() == 1
    finally:
        db.close()


def test_deactivation_ends_an_existing_session(client, sessions):
    victim = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    assert sign_in(victim, "l1", "Password123!").status_code == 303
    assert victim.get("/alerts/").status_code == 200

    admin = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    sign_in(admin, "admin_l3", "AdminPass123!")
    set_active(admin, sessions, "l1", False)

    blocked = victim.get("/alerts/")
    assert blocked.status_code == 303
    assert blocked.headers["location"] == "/login/"


def test_reactivation_restores_access(client, sessions):
    admin = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    sign_in(admin, "admin_l3", "AdminPass123!")
    set_active(admin, sessions, "l1", False)
    set_active(admin, sessions, "l1", True)

    user = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    assert sign_in(user, "l1", "Password123!").status_code == 303
    assert user.get("/alerts/").status_code == 200


def test_admin_cannot_deactivate_themselves(client, sessions):
    admin = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    sign_in(admin, "admin_l3", "AdminPass123!")
    response = set_active(admin, sessions, "admin_l3", False)
    assert response.status_code == 303
    assert admin.get("/alerts/").status_code == 200

    db = sessions()
    try:
        assert db.query(User).filter_by(username="admin_l3").one().is_active is True
    finally:
        db.close()


def test_last_active_admin_cannot_be_deactivated(client, sessions):
    db = sessions()
    try:
        second = User(username="admin_two", password_hash=hash_password("AdminPass123!"),
                      role="L3", is_admin=True)
        db.add(second)
        db.commit()
    finally:
        db.close()

    admin = TestClient(client.app, follow_redirects=False, client=("127.0.0.1", 50000))
    sign_in(admin, "admin_l3", "AdminPass123!")

    # With a second admin present the deactivation is allowed...
    assert set_active(admin, sessions, "admin_two", False).status_code == 303
    db = sessions()
    try:
        assert db.query(User).filter_by(username="admin_two").one().is_active is False
    finally:
        db.close()

    # ...but the remaining admin cannot remove the last one (themselves excluded).
    response = set_active(admin, sessions, "admin_l3", False)
    assert response.status_code == 303
    db = sessions()
    try:
        assert db.query(User).filter_by(username="admin_l3").one().is_active is True
    finally:
        db.close()
