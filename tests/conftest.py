"""Pytest configuration and fixtures."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from soc_tracker.models import Base, User
from soc_tracker.auth import hash_password


@pytest.fixture
def engine():
    """Create in-memory SQLite engine for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db(engine):
    """Create database session for testing."""
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = SessionLocal()
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
