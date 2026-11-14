"""Evidence reads are audited, and the download header cannot be broken."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sentriq import models
from sentriq.auth import hash_password
from sentriq.models import Alert, AuditLog, Evidence, User
from sentriq.routes import evidence_routes
from sentriq.routes.evidence_routes import content_disposition
from sentriq.services.alert_service import create_alert

from tests.support import make_session_factory


@pytest.fixture
def sessions(engine, tmp_path, monkeypatch):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    monkeypatch.setattr(evidence_routes, "UPLOAD_DIR", tmp_path)
    session = factory()
    session.add(User(username="l2", password_hash=hash_password("Password123!"), role="L2"))
    session.commit()
    session.close()
    yield factory
    models.SessionLocal = original


@pytest.fixture
def client(sessions):
    from main import app

    with TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000)) as test_client:
        yield test_client


def sign_in(client):
    client.get("/login/")
    token = client.cookies.get("csrf_token")
    response = client.post("/login/", data={
        "username": "l2", "password": "Password123!", "csrf_token": token,
    })
    assert response.status_code == 303
    return client.cookies.get("csrf_token")


def seed_evidence(sessions, tmp_path, name="capture.txt", payload=b"packet capture"):
    db = sessions()
    user = db.scalar(select(User).where(User.username == "l2"))
    alert = create_alert(db, {
        "title": "Evidence ticket", "description": "", "severity": "High",
        "asset": "EV-01", "tactic": "Execution", "iocs": [], "sla_hours": 8,
    }, user)
    stored = f"{alert.alert_id}_deadbeef{'.png' if name.endswith('.png') else '.txt'}"
    (tmp_path / stored).write_bytes(payload)
    evidence = Evidence(
        alert=alert, original_name=name, stored_name=stored,
        content_type="text/plain", size_bytes=len(payload), sha256="b" * 64,
    )
    db.add(evidence)
    db.commit()
    evidence_id, alert_id = evidence.id, alert.id
    db.close()
    return evidence_id, alert_id


def test_download_is_written_to_the_audit_trail(client, sessions, tmp_path):
    evidence_id, alert_id = seed_evidence(sessions, tmp_path)
    sign_in(client)

    response = client.get(f"/evidence/{evidence_id}/")
    assert response.status_code == 200
    assert response.content == b"packet capture"

    db = sessions()
    row = db.scalar(select(AuditLog).where(AuditLog.action == "evidence.downloaded"))
    assert row is not None
    assert row.target_type == "evidence"
    assert row.target_id == str(evidence_id)
    assert "capture.txt" in row.message
    assert row.actor is not None and row.actor.username == "l2"
    db.close()


def test_preview_is_audited_separately(client, sessions, tmp_path):
    evidence_id, _ = seed_evidence(sessions, tmp_path, name="shot.png", payload=b"\x89PNG\r\n\x1a\n")
    sign_in(client)

    response = client.get(f"/evidence/{evidence_id}/preview/")
    assert response.status_code == 200

    db = sessions()
    assert db.scalar(select(AuditLog).where(AuditLog.action == "evidence.previewed")) is not None
    assert db.scalar(select(AuditLog).where(AuditLog.action == "evidence.downloaded")) is None
    db.close()


def test_a_missing_file_is_not_audited(client, sessions, tmp_path):
    evidence_id, _ = seed_evidence(sessions, tmp_path)
    (tmp_path / f"#1_deadbeef.txt").unlink()
    for path in tmp_path.iterdir():
        path.unlink()
    sign_in(client)

    assert client.get(f"/evidence/{evidence_id}/").status_code == 404

    db = sessions()
    assert db.scalar(select(AuditLog).where(AuditLog.action == "evidence.downloaded")) is None
    db.close()


def test_content_disposition_cannot_be_broken_out_of():
    header = content_disposition("attachment", 'report"; x=1\r\nSet-Cookie: a=b.txt')
    assert "\r" not in header and "\n" not in header
    assert header.count('"') == 2
    assert "filename*=UTF-8''" in header


def test_content_disposition_keeps_a_unicode_name():
    header = content_disposition("attachment", "အစီရင်ခံစာ.pdf")
    assert "filename*=UTF-8''" in header
    assert "%" in header.split("filename*=")[1]
