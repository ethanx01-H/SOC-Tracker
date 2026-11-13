"""Pytest configuration and fixtures."""

import pytest

from soc_tracker import middleware
from soc_tracker.auth import hash_password
from soc_tracker.models import User

from tests.support import make_engine, make_session_factory


@pytest.fixture(autouse=True)
def reset_security_state():
    """Rate limits and lockout counters are module globals; keep tests independent."""
    middleware.reset_security_state()
    yield
    middleware.reset_security_state()


@pytest.fixture(autouse=True)
def isolate_evidence_dir(tmp_path, monkeypatch):
    """Keep test uploads out of the real data/evidence directory.

    The upload route writes to config.UPLOAD_DIR, which in Docker is the same
    bind-mounted folder the team uses for real evidence.
    """
    from soc_tracker.routes import evidence_routes

    monkeypatch.setattr(evidence_routes, "UPLOAD_DIR", tmp_path)


@pytest.fixture
def engine():
    """Create one shared in-memory SQLite engine for testing.

    A plain ``sqlite:///:memory:`` URL gives every connection its own empty
    database, so the app thread never sees the rows the test inserted.
    """
    engine = make_engine()
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):
    """Create database session for testing."""
    session = make_session_factory(engine)()
    yield session
    session.close()


@pytest.fixture
def sample_user(db):
    """Create a sample L1 user for testing."""
    user = User(
        username="test_l1",
        password_hash=hash_password("TestPass123!"),
        role="L1",
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_user(db):
    """Create a sample L3 admin user for testing."""
    user = User(
        username="test_admin",
        password_hash=hash_password("AdminPass123!"),
        role="L3",
        is_admin=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
