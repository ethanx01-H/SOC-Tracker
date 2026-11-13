"""A replayed n8n webhook must map to the ticket it already created."""

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.config import N8N_API_HEADER, N8N_API_KEY
from soc_tracker.models import Alert
from tests.support import make_session_factory


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


def payload(doc_id: str | None = "elastic-doc-abc123") -> dict:
    hit = {
        "_index": "logs-endpoint",
        "_source": {
            "kibana.alert.rule.name": "Suspicious PowerShell",
            "kibana.alert.severity": "high",
            "host.name": "WS-042",
        },
    }
    if doc_id is not None:
        hit["_id"] = doc_id
    return {"hits": {"hits": [hit]}}


def post(client, body):
    return client.post("/api/webhook/n8n", json=body, headers={N8N_API_HEADER: N8N_API_KEY})


def test_replay_returns_the_existing_ticket(client, db):
    first = post(client, payload())
    assert first.status_code == 200
    assert first.json()["created"] == ["#1"]

    replay = post(client, payload())
    assert replay.status_code == 200
    assert replay.json()["created"] == []
    assert replay.json()["existing"] == ["#1"]
    assert replay.json()["ids"] == ["#1"]

    assert db.query(Alert).count() == 1
    stored = db.query(Alert).one()
    assert stored.external_id == "logs-endpoint:elastic-doc-abc123"


def test_distinct_elastic_documents_still_create_new_tickets(client, db):
    post(client, payload("doc-1"))
    post(client, payload("doc-2"))
    assert db.query(Alert).count() == 2


def test_payload_without_an_identifier_cannot_be_deduplicated(client, db):
    # Nothing to match on: two deliveries are two tickets, which is why the
    # Elastic _id is preserved rather than dropped.
    post(client, payload(None))
    post(client, payload(None))
    assert db.query(Alert).count() == 2
    assert db.query(Alert).filter(Alert.external_id.isnot(None)).count() == 0


def test_mixed_batch_reports_created_and_existing(client, db):
    post(client, payload("doc-1"))
    body = payload("doc-1")
    body["hits"]["hits"].append({
        "_index": "logs-endpoint",
        "_id": "doc-2",
        "_source": {"kibana.alert.rule.name": "Encoded command", "host.name": "WS-007"},
    })
    response = post(client, body)
    assert response.status_code == 200
    assert response.json()["created"] == ["#2"]
    assert response.json()["existing"] == ["#1"]
    assert db.query(Alert).count() == 2
