"""A batch webhook is one transaction: a bad record leaves nothing behind."""

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.config import N8N_API_HEADER, N8N_API_KEY
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
