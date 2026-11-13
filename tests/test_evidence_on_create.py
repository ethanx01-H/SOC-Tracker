"""Evidence can be attached on the new-alert form, not only after the fact."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_tracker import models
from soc_tracker.auth import hash_password
from soc_tracker.models import Alert, AlertEvent, AuditLog, Evidence, User
from soc_tracker.services import evidence_service

from tests.support import make_session_factory


@pytest.fixture
def sessions(engine):
    factory = make_session_factory(engine)
    original = models.SessionLocal
    models.SessionLocal = factory
    db = factory()
    db.add(User(username="l1", password_hash=hash_password("Password123!"), role="L1"))
    db.commit()
    db.close()
    yield factory
    models.SessionLocal = original


def make_client():
    from main import app
    return TestClient(app, follow_redirects=False, client=("127.0.0.1", 50000))


def sign_in(client):
    client.get("/login/")
    client.post("/login/", data={
        "username": "l1", "password": "Password123!", "csrf_token": client.cookies.get("csrf_token"),
    })
    return client.cookies.get("csrf_token")


def create_alert(client, csrf, files=None, title="Phishing wave on finance", **extra):
    data = {"csrf_token": csrf, "title": title, "description": "Reported by user", "severity": "High"}
    data.update(extra)
    return client.post("/alerts/new/", data=data, files=files)


def test_two_files_are_attached_while_creating(sessions, tmp_path):
    client = make_client()
    csrf = sign_in(client)
    files = [
        ("evidence_files", ("screenshot.png", b"PNGDATA", "image/png")),
        ("evidence_files", ("proxy.log", b"line one\nline two\n", "text/plain")),
    ]

    response = create_alert(client, csrf, files=files)
    assert response.status_code == 303

    db = sessions()
    try:
        alert = db.query(Alert).one()
        stored = db.query(Evidence).order_by(Evidence.original_name).all()
        assert [item.original_name for item in stored] == ["proxy.log", "screenshot.png"]
        assert all(item.alert_id == alert.id for item in stored)
        assert [item.size_bytes for item in stored] == [18, 7]
        assert all(len(item.sha256) == 64 for item in stored)
        assert db.query(AlertEvent).filter_by(event_type="evidence").count() == 2
        assert db.query(AuditLog).filter_by(action="alert.created").one().message.endswith("2 evidence file(s).")
    finally:
        db.close()

    names = sorted(path.name for path in tmp_path.iterdir())
    assert len(names) == 2, names
    assert all(name.startswith("#1_") for name in names)
    assert {Path(name).suffix for name in names} == {".log", ".png"}


def test_attached_evidence_downloads_back(sessions, tmp_path):
    client = make_client()
    csrf = sign_in(client)
    create_alert(client, csrf, files=[("evidence_files", ("note.txt", b"chain of custody", "text/plain"))])

    db = sessions()
    try:
        evidence_id = db.query(Evidence).one().id
    finally:
        db.close()

    response = client.get(f"/evidence/{evidence_id}/")
    assert response.status_code == 200
    assert response.content == b"chain of custody"


def test_rejected_file_creates_no_alert_at_all(sessions, tmp_path):
    client = make_client()
    csrf = sign_in(client)
    files = [("evidence_files", ("payload.exe", b"MZ", "application/octet-stream"))]

    response = create_alert(client, csrf, files=files)
    assert response.status_code == 200
    assert "not allowed" in response.text

    db = sessions()
    try:
        assert db.query(Alert).count() == 0
        assert db.query(Evidence).count() == 0
    finally:
        db.close()
    assert list(tmp_path.iterdir()) == []


def test_oversized_file_creates_no_alert_at_all(sessions, tmp_path, monkeypatch):
    monkeypatch.setattr(evidence_service, "MAX_UPLOAD_BYTES", 8)
    client = make_client()
    csrf = sign_in(client)
    files = [("evidence_files", ("big.log", b"x" * 64, "text/plain"))]

    response = create_alert(client, csrf, files=files)
    assert response.status_code == 200
    assert "larger than" in response.text

    db = sessions()
    try:
        assert db.query(Alert).count() == 0
    finally:
        db.close()


def test_create_without_files_still_works(sessions):
    client = make_client()
    csrf = sign_in(client)
    assert create_alert(client, csrf).status_code == 303

    db = sessions()
    try:
        assert db.query(Alert).count() == 1
        assert db.query(Evidence).count() == 0
    finally:
        db.close()


def test_upload_route_no_longer_exists(sessions):
    client = make_client()
    csrf = sign_in(client)
    create_alert(client, csrf)

    db = sessions()
    try:
        alert_id = db.query(Alert).one().id
    finally:
        db.close()

    response = client.post(
        f"/alerts/{alert_id}/evidence/",
        data={"csrf_token": csrf},
        files={"evidence_file": ("late.txt", b"added after creation", "text/plain")},
    )
    assert response.status_code in (404, 405)

    db = sessions()
    try:
        assert db.query(Evidence).count() == 0
    finally:
        db.close()


def test_images_preview_inline_and_other_types_do_not(sessions):
    client = make_client()
    csrf = sign_in(client)
    create_alert(client, csrf, files=[
        ("evidence_files", ("shot.png", b"\x89PNG\r\n\x1a\nbody", "image/png")),
        ("evidence_files", ("notes.txt", b"plain text", "text/plain")),
    ])

    db = sessions()
    try:
        image = db.query(Evidence).filter_by(original_name="shot.png").one()
        other = db.query(Evidence).filter_by(original_name="notes.txt").one()
    finally:
        db.close()

    preview = client.get(f"/evidence/{image.id}/preview/")
    assert preview.status_code == 200
    assert preview.headers["content-type"] == "image/png"
    assert preview.headers["content-disposition"].startswith("inline")

    # A non-image is not previewable, and the download route still attaches it.
    assert client.get(f"/evidence/{other.id}/preview/").status_code == 404
    assert client.get(f"/evidence/{other.id}/").headers["content-disposition"].startswith("attachment")


def test_detail_page_shows_thumbnail_and_no_upload_box(sessions):
    client = make_client()
    csrf = sign_in(client)
    create_alert(client, csrf, files=[("evidence_files", ("shot.png", b"\x89PNG\r\n\x1a\nbody", "image/png"))])

    db = sessions()
    try:
        image = db.query(Evidence).one()
        alert_id = image.alert_id
    finally:
        db.close()

    page = client.get(f"/alerts/{alert_id}/").text
    assert 'name="evidence_file"' not in page, "the upload box must be gone"
    assert f'src="/evidence/{image.id}/preview/"' in page
    assert f'id="preview-{image.id}"' in page
    assert "lightbox" in page
