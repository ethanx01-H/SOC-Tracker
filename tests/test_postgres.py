"""Postgres checks: migrations, then a ticket round trip through the app.

Skipped unless TEST_DATABASE_URL points at a scratch database. Run it with:

    TEST_DATABASE_URL=postgresql://user:pass@host/db pytest tests/test_postgres.py

The module drops and recreates the ``public`` schema first, so it must never be
pointed at a database anyone cares about.
"""

import os
import pathlib
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import sessionmaker

from soc_tracker.config import ALEMBIC_HEAD, normalise_database_url

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not URL, reason="set TEST_DATABASE_URL to a scratch Postgres database"
)

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def pg_url():
    return normalise_database_url(URL)


@pytest.fixture(scope="module")
def pg_engine(pg_url):
    engine = create_engine(pg_url, pool_pre_ping=True)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")

    # Migrate exactly the way the entrypoint does, so a broken revision shows up
    # here rather than on the first deploy.
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env={**os.environ, "DATABASE_URL": pg_url},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def pg_sessions(pg_engine):
    return sessionmaker(bind=pg_engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def client(pg_engine, pg_sessions):
    """App client whose database is the Postgres one, not the local SQLite file."""
    from main import app
    from soc_tracker.dependencies import get_db

    def override_get_db():
        session = pg_sessions()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000)) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _seed_admin(pg_sessions):
    from soc_tracker.auth import hash_password
    from soc_tracker.models import User

    with pg_sessions() as session:
        existing = session.scalar(select(User).where(User.username == "pg_admin"))
        if existing:
            return
        session.add(User(
            username="pg_admin", password_hash=hash_password("PostgresPass123!"),
            role="L3", is_admin=True,
        ))
        session.commit()


def _sign_in(client):
    client.get("/login/")
    token = client.cookies.get("csrf_token")
    response = client.post("/login/", data={
        "username": "pg_admin", "password": "PostgresPass123!", "csrf_token": token,
    })
    assert response.status_code == 303, response.text
    return client.cookies.get("csrf_token")


def test_migrations_reach_the_head_revision(pg_engine):
    with pg_engine.connect() as connection:
        revision = connection.exec_driver_sql("select version_num from alembic_version").scalar()
    assert revision == ALEMBIC_HEAD
    tables = set(inspect(pg_engine).get_table_names())
    assert {
        "fastapi_alerts", "fastapi_alert_events", "fastapi_evidence",
        "fastapi_audit_logs", "fastapi_users",
    } <= tables


def test_boolean_default_is_native(pg_engine):
    """is_active must default to a real boolean, not the integer SQLite used."""
    with pg_engine.connect() as connection:
        default = connection.execute(text(
            "select column_default from information_schema.columns "
            "where table_name = 'fastapi_users' and column_name = 'is_active'"
        )).scalar()
    assert default == "true"


def test_ticket_round_trip(client, pg_sessions, pg_engine):
    _seed_admin(pg_sessions)
    token = _sign_in(client)

    response = client.post("/alerts/new/", data={
        "csrf_token": token,
        "title": "Postgres round trip",
        "description": "Created while DATABASE_URL points at Postgres.",
        "severity": "High",
        "asset": "PG-TEST-01",
        "iocs_text": "192.0.2.10, evil.example",
        "sla_hours": "4",
    }, files=[("evidence_files", ("note.txt", b"evidence body", "text/plain"))])
    assert response.status_code == 303, response.text
    detail_url = response.headers["location"]

    page = client.get(detail_url)
    assert page.status_code == 200
    assert "Postgres round trip" in page.text
    assert "note.txt" in page.text

    listing = client.get("/alerts/")
    assert "Postgres round trip" in listing.text

    dashboard = client.get("/")
    assert dashboard.status_code == 200

    with pg_engine.connect() as connection:
        assert connection.exec_driver_sql("select count(*) from fastapi_alerts").scalar() == 1
        assert connection.exec_driver_sql("select count(*) from fastapi_evidence").scalar() == 1


def test_close_and_audit_trail(client, pg_sessions, pg_engine):
    _seed_admin(pg_sessions)
    token = _sign_in(client)
    with pg_engine.connect() as connection:
        alert_pk = connection.exec_driver_sql("select id from fastapi_alerts limit 1").scalar()

    response = client.post(f"/alerts/{alert_pk}/close/", data={
        "csrf_token": token, "resolution_summary": "Closed during the Postgres check.",
    })
    assert response.status_code == 303, response.text

    with pg_engine.connect() as connection:
        status = connection.exec_driver_sql(
            "select status from fastapi_alerts where id = %s", (alert_pk,)
        ).scalar()
        audit_rows = connection.exec_driver_sql(
            "select count(*) from fastapi_audit_logs where action = 'alert.closed'"
        ).scalar()
    assert status == "Closed"
    assert audit_rows == 1


def test_webhook_deduplicates_on_postgres(client, pg_engine):
    from soc_tracker.config import N8N_API_HEADER, N8N_API_KEY

    payload = {"_id": "pg-doc-1", "alert_name": "Postgres webhook alert", "severity": "Medium"}
    headers = {N8N_API_HEADER: N8N_API_KEY}
    first = client.post("/api/webhook/n8n", json=payload, headers=headers)
    second = client.post("/api/webhook/n8n", json=payload, headers=headers)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["created"] == second.json()["existing"]
    with pg_engine.connect() as connection:
        assert connection.exec_driver_sql(
            "select count(*) from fastapi_alerts where external_id = 'pg-doc-1'"
        ).scalar() == 1
