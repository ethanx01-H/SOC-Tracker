"""Importing the same Elastic export twice must not double the tickets.

The import page keeps the Elastic ``_id`` on each ticket as ``external_id``, so a
pasted export that is imported again maps onto the tickets that already exist
instead of creating a second set. That behaviour used to be covered through the
removed n8n webhook; it is exercised here through the same service the import
page calls.
"""

import json

import pytest

from alerts.elastic import parse_elastic_alerts
from soc_tracker.models import Alert
from soc_tracker.services.alert_service import create_or_get_alert
from tests.support import make_session_factory


@pytest.fixture
def db(engine):
    session = make_session_factory(engine)()
    yield session
    session.close()


def export(doc_ids):
    hits = []
    for doc_id in doc_ids:
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
        hits.append(hit)
    return parse_elastic_alerts(json.dumps({"hits": {"hits": hits}}))


def import_export(db, records):
    """What the import page does: one loop, one commit, duplicates counted."""
    created = skipped = 0
    for item in records:
        _, is_new = create_or_get_alert(db, dict(item))
        if is_new:
            created += 1
        else:
            skipped += 1
    db.commit()
    return created, skipped


def test_replay_returns_the_existing_ticket(db):
    assert import_export(db, export(["elastic-doc-abc123"])) == (1, 0)

    assert import_export(db, export(["elastic-doc-abc123"])) == (0, 1)

    assert db.query(Alert).count() == 1
    stored = db.query(Alert).one()
    assert stored.external_id == "logs-endpoint:elastic-doc-abc123"


def test_distinct_elastic_documents_still_create_new_tickets(db):
    import_export(db, export(["doc-1"]))
    import_export(db, export(["doc-2"]))
    assert db.query(Alert).count() == 2


def test_export_without_an_identifier_cannot_be_deduplicated(db):
    # Nothing to match on: two imports are two tickets, which is why the
    # Elastic _id is preserved rather than dropped.
    import_export(db, export([None]))
    import_export(db, export([None]))
    assert db.query(Alert).count() == 2
    assert db.query(Alert).filter(Alert.external_id.isnot(None)).count() == 0


def test_mixed_export_reports_created_and_skipped(db):
    import_export(db, export(["doc-1"]))
    created, skipped = import_export(db, export(["doc-1", "doc-2"]))
    assert (created, skipped) == (1, 1)
    assert db.query(Alert).count() == 2
