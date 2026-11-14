"""A batch webhook is one transaction: a bad record leaves nothing behind."""

import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.config import BASE_DIR, N8N_API_HEADER, N8N_API_KEY
from soc_tracker.models import Alert
from soc_tracker.services.alert_service import create_alert

from tests.support import make_session_factory

VALUES = {
    "title": "Valid ticket", "description": "", "source": "Manual",
    "severity": "Low", "status": "Open", "analyst": "Unassigned",
    "tactic": "Unknown", "asset": "Unknown", "sla_hours": 8,
}


@pytest.fixture
def client(engine):
    original = models.SessionLocal
    models.SessionLocal = make_session_factory(engine)
    from main import app
    yield TestClient(app, follow_redirects=False)
    models.SessionLocal = original


@pytest.fixture
def db(engine):
    session = make_session_factory(engine)()
    yield session
    session.close()


def test_create_alert_leaves_the_commit_to_the_caller(db):
    create_alert(db, dict(VALUES))
    db.rollback()
    assert db.query(Alert).count() == 0


def test_batch_with_one_bad_record_persists_nothing(client, db):
    good = {"_index": "logs", "_id": "ok-1", "_source": {"title": "First", "host.name": "h1"}}
    bad = {"_index": "logs", "_id": "bad-1", "_source": {"title": "x" * 181, "host.name": "h2"}}
    also_good = {"_index": "logs", "_id": "ok-2", "_source": {"title": "Third", "host.name": "h3"}}

    response = client.post(
        "/api/webhook/n8n",
        json={"hits": {"hits": [good, bad, also_good]}},
        headers={N8N_API_HEADER: N8N_API_KEY},
    )

    assert response.status_code == 422
    assert "Title must be" in response.json()["error"]
    assert db.query(Alert).count() == 0, "partial batch must not be committed"
    assert db.query(models.AlertEvent).count() == 0


def test_clean_batch_is_committed_once(client, db):
    records = [
        {"_index": "logs", "_id": f"ok-{index}", "_source": {"title": f"Ticket {index}"}}
        for index in range(3)
    ]
    response = client.post(
        "/api/webhook/n8n",
        json={"hits": {"hits": records}},
        headers={N8N_API_HEADER: N8N_API_KEY},
    )
    assert response.status_code == 200
    assert len(response.json()["created"]) == 3
    assert db.query(Alert).count() == 3


def test_ingest_is_off_when_no_key_is_configured(client, monkeypatch):
    """No key means no ingest: the endpoints refuse rather than accept anonymously."""
    from soc_tracker.routes import webhook_routes

    monkeypatch.setattr(webhook_routes, "WEBHOOK_ENABLED", False)

    batch = client.post("/api/webhook/n8n/", json={"hits": {"hits": []}})
    assert batch.status_code == 503
    assert batch.json()["error"] == "webhook disabled"

    log = client.post("/api/webhook/n8n/logs/", json={"alert_id": "#1", "message": "x"})
    assert log.status_code == 503


def test_production_starts_without_an_n8n_key():
    """The key is optional now: production only insists on APP_SECRET_KEY."""
    env = {
        **os.environ,
        "APP_ENV": "production",
        "APP_SECRET_KEY": "k" * 40,
        "COOKIE_SECURE": "1",
        "N8N_API_KEY": "",
    }
    result = subprocess.run(
        [sys.executable, "-c", "from soc_tracker.config import WEBHOOK_ENABLED; print(WEBHOOK_ENABLED)"],
        cwd=BASE_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_production_still_refuses_without_a_signing_key():
    env = {**os.environ, "APP_ENV": "production", "APP_SECRET_KEY": "", "COOKIE_SECURE": "1", "N8N_API_KEY": ""}
    result = subprocess.run(
        [sys.executable, "-c", "import soc_tracker.config"],
        cwd=BASE_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "APP_SECRET_KEY" in result.stderr
