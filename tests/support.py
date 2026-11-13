"""Shared helpers for the test suite."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from soc_tracker.models import Base


def make_engine():
    """One shared in-memory database for the whole test.

    The default ``sqlite:///:memory:`` hands every connection its own empty
    database, so the app thread (TestClient) never sees the rows the test
    fixture inserted. StaticPool keeps a single connection alive instead.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return engine


def make_session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
