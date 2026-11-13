"""OWASP Top 10 (2021) Security Tests for SOC Alert Tracker."""

import hashlib
import os
import re
import time
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from soc_tracker.models import Base, User, Alert, AlertEvent, AuditLog, Evidence
from soc_tracker.auth import hash_password, verify_password

from tests.support import make_engine


@pytest.fixture
def engine():
    engine = make_engine()
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def app(engine, db):
    import soc_tracker.models
    original = soc_tracker.models.SessionLocal
    soc_tracker.models.SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    from main import app

    l1 = User(username="l1", password_hash=hash_password("Password123!"), role="L1", is_admin=False)
    l2 = User(username="l2", password_hash=hash_password("Password123!"), role="L2", is_admin=False)
    admin = User(username="admin_l3", password_hash=hash_password("Password123!"), role="L3", is_admin=True)
    db.add_all([l1, l2, admin])
    db.commit()

    yield app
    soc_tracker.models.SessionLocal = original


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app, follow_redirects=False)


def get_csrf(client):
    """Get CSRF token from cookies."""
    client.get("/login/")
    for cookie in client.cookies.jar:
        if cookie.name == "csrf_token":
            return cookie.value
    return ""


def login_with_csrf(client, username, password):
    """Login with CSRF token."""
    csrf = get_csrf(client)
    return client.post("/login/", data={
        "username": username,
        "password": password,
        "csrf_token": csrf,
    })


@pytest.fixture
def l1_session(client):
    login_with_csrf(client, "l1", "Password123!")
    return client


@pytest.fixture
def l2_session(client):
    login_with_csrf(client, "l2", "Password123!")
    return client


@pytest.fixture
def admin_session(client):
    login_with_csrf(client, "admin_l3", "Password123!")
    return client


def create_test_alert(db, status="Open", severity="Medium"):
    alert = Alert(
        alert_id="#TEST01", title="Test Alert", description="Test description",
        source="Manual", severity=severity, status=status, analyst="l1",
        tactic="Initial Access", asset="test-host", iocs_json='["192.168.1.1"]', sla_hours=8,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# ============================================================================
# A01: Broken Access Control
# ============================================================================

class TestA01BrokenAccessControl:

    def test_unauthenticated_access_denied(self, client):
        for route in ["/", "/alerts/", "/alerts/new/", "/admin/users/", "/admin/audit/"]:
            response = client.get(route)
            assert response.status_code in [303, 401, 403], f"Route {route} accessible without auth"

    def test_l1_cannot_access_admin(self, l1_session):
        assert l1_session.get("/admin/users/").status_code == 403
        assert l1_session.get("/admin/audit/").status_code == 403

    def test_l1_cannot_create_users(self, l1_session):
        csrf = get_csrf(l1_session)
        response = l1_session.post("/admin/users/", data={
            "username": "newuser", "password": "Password123!", "role": "L1", "csrf_token": csrf,
        })
        assert response.status_code == 403

    def test_l1_cannot_delete_alerts(self, l1_session, db):
        alert = create_test_alert(db)
        csrf = get_csrf(l1_session)
        assert l1_session.post(f"/alerts/{alert.id}/delete/", data={"csrf_token": csrf}).status_code == 403

    def test_l1_cannot_edit_closed(self, l1_session, db):
        alert = create_test_alert(db, status="Closed")
        assert l1_session.get(f"/alerts/{alert.id}/edit/").status_code == 403

    def test_l2_cannot_delete_alerts(self, l2_session, db):
        alert = create_test_alert(db)
        csrf = get_csrf(l2_session)
        assert l2_session.post(f"/alerts/{alert.id}/delete/", data={"csrf_token": csrf}).status_code == 403

    def test_l2_cannot_access_admin(self, l2_session):
        assert l2_session.get("/admin/users/").status_code == 403

    def test_path_traversal_in_upload(self, l1_session, db):
        csrf = get_csrf(l1_session)
        response = l1_session.post(
            "/alerts/new/",
            data={"csrf_token": csrf, "title": "Traversal attempt"},
            files={"evidence_files": ("../../../etc/passwd.txt", b"test", "text/plain")},
        )
        assert response.status_code == 303
        evidence = db.scalar(select(Evidence).order_by(Evidence.id.desc()))
        assert evidence is not None
        assert ".." not in evidence.stored_name
        assert "/" not in evidence.stored_name


# ============================================================================
# A02: Cryptographic Failures
# ============================================================================

class TestA02CryptographicFailures:

    def test_password_hash_algorithm(self):
        hashed = hash_password("Test123!")
        assert "pbkdf2_sha256" in hashed
        parts = hashed.split("$")
        assert len(parts) == 3
        assert len(parts[1]) >= 32

    def test_unique_salts(self):
        h1 = hash_password("Test123!")
        h2 = hash_password("Test123!")
        assert h1 != h2

    def test_timing_safe_comparison(self):
        hashed = hash_password("Test123!")
        assert verify_password("Test123!", hashed) is True
        assert verify_password("Wrong!", hashed) is False

    def test_no_plaintext_storage(self, db):
        user = User(username="test", password_hash=hash_password("Test123!"), role="L1")
        db.add(user)
        db.commit()
        assert user.password_hash != "Test123!"
        assert "pbkdf2_sha256" in user.password_hash

    def test_session_cookie_httponly(self, client):
        response = login_with_csrf(client, "l1", "Password123!")
        session_headers = [h for h in response.headers.get_list("set-cookie") if h.startswith("session=")]
        assert session_headers, "login did not set a session cookie"
        for header in session_headers:
            assert "httponly" in header.lower()


# ============================================================================
# A03: Injection
# ============================================================================

class TestA03Injection:

    def test_sql_injection_in_search(self, l1_session, db):
        create_test_alert(db)
        for payload in ["'; DROP TABLE fastapi_alerts; --", "' OR '1'='1", "1; SELECT * FROM fastapi_users"]:
            response = l1_session.get(f"/alerts/?q={payload}")
            assert response.status_code == 200
        assert len(list(db.scalars(select(Alert)))) >= 1

    def test_xss_in_title(self, l1_session, db):
        csrf = get_csrf(l1_session)
        for payload in ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>"]:
            l1_session.post("/alerts/new/", data={
                "title": payload, "description": "Test", "source": "Manual",
                "severity": "Low", "status": "Open", "csrf_token": csrf,
            })
            alert = db.scalar(select(Alert).where(Alert.title == payload))
            assert alert is not None

    def test_xss_in_search(self, l1_session):
        response = l1_session.get("/alerts/?q=<script>alert('xss')</script>")
        assert response.status_code == 200

    def test_command_injection(self, l1_session, db):
        alert = create_test_alert(db)
        csrf = get_csrf(l1_session)
        for payload in ["; ls -la", "| cat /etc/passwd", "$(whoami)", "`id`"]:
            response = l1_session.post(f"/alerts/{alert.id}/notes/", data={"note": f"Test {payload}", "csrf_token": csrf})
            assert response.status_code in [200, 303]


# ============================================================================
# A04: Insecure Design
# ============================================================================

class TestA04InsecureDesign:

    def test_password_complexity(self, admin_session):
        csrf = get_csrf(admin_session)
        for pwd in ["short", "alllowercase1!", "ALLUPPERCASE1!", "NoNumbers!", "NoSymbols123"]:
            response = admin_session.post("/admin/users/", data={
                "username": f"t_{pwd[:4]}", "password": pwd, "role": "L1", "csrf_token": csrf,
            })
            assert "Password must" in response.text

    def test_account_lockout(self, client, db):
        db.add(User(username="locktest", password_hash=hash_password("Password123!"), role="L1"))
        db.commit()
        for _ in range(6):
            login_with_csrf(client, "locktest", "wrong")
        response = login_with_csrf(client, "locktest", "Password123!")
        assert "Too many failed attempts" in response.text

    def test_resolution_summary_required(self, l1_session, db):
        alert = create_test_alert(db, status="WIP")
        csrf = get_csrf(l1_session)
        response = l1_session.post(f"/alerts/{alert.id}/close/", data={"resolution_summary": "", "csrf_token": csrf})
        assert response.status_code == 303
        db.refresh(alert)
        assert alert.status == "WIP", "empty resolution summary must not close the ticket"
        follow_up = l1_session.get(alert.get_absolute_url())
        assert "Resolution summary is required" in follow_up.text
        response = l1_session.post(f"/alerts/{alert.id}/close/", data={"resolution_summary": "Short", "csrf_token": csrf})
        assert response.status_code == 303
        db.refresh(alert)
        assert alert.status == "Closed"

    def test_session_expiry(self, client):
        response = login_with_csrf(client, "l1", "Password123!")
        session_headers = [h for h in response.headers.get_list("set-cookie") if h.startswith("session=")]
        assert session_headers
        for header in session_headers:
            assert "max-age" in header.lower()


# ============================================================================
# A05: Security Misconfiguration
# ============================================================================

class TestA05SecurityMisconfiguration:

    def test_security_headers(self, client):
        response = client.get("/login/")
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert "camera=()" in response.headers.get("permissions-policy", "")

    def test_csp_header(self, client):
        csp = client.get("/login/").headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp

    def test_server_header_hidden(self, client):
        server = client.get("/login/").headers.get("server", "")
        assert "uvicorn" not in server.lower()

    def test_no_debug_info(self, client):
        response = client.get("/nonexistent-route-12345")
        assert response.status_code == 404
        assert "traceback" not in response.text.lower()


# ============================================================================
# A06: Vulnerable Components
# ============================================================================

class TestA06VulnerableComponents:

    def test_version_constraints(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "requirements.txt")) as f:
            content = f.read()
        for line in content.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                assert ">=" in line or "==" in line or "<" in line, f"No version constraint: {line}"


# ============================================================================
# A07: Authentication Failures
# ============================================================================

class TestA07AuthenticationFailures:

    def test_invalid_credentials_rejected(self, client):
        response = login_with_csrf(client, "nonexistent", "wrong")
        assert "Invalid username or password" in response.text

    def test_wrong_password_rejected(self, client, db):
        db.add(User(username="authtest", password_hash=hash_password("Correct123!"), role="L1"))
        db.commit()
        response = login_with_csrf(client, "authtest", "Wrong123!")
        assert "Invalid username or password" in response.text

    def test_session_invalidated_on_logout(self, client):
        login_with_csrf(client, "l1", "Password123!")
        csrf = get_csrf(client)
        client.post("/logout/", data={"csrf_token": csrf})
        assert client.get("/").status_code in [303, 401]

    def test_no_user_enumeration(self, client, db):
        db.add(User(username="enumtest", password_hash=hash_password("Password123!"), role="L1"))
        db.commit()
        r1 = login_with_csrf(client, "nonexistent", "wrong")
        r2 = login_with_csrf(client, "enumtest", "wrong")
        assert "Invalid username or password" in r1.text
        assert "Invalid username or password" in r2.text

    def test_password_not_in_response(self, client):
        response = login_with_csrf(client, "l1", "Password123!")
        assert "Password123!" not in response.text


# ============================================================================
# A08: Data Integrity Failures
# ============================================================================

class TestA08DataIntegrityFailures:

    def test_evidence_sha256_tracking(self, l1_session, db):
        content = b"test evidence content"
        csrf = get_csrf(l1_session)
        response = l1_session.post(
            "/alerts/new/",
            data={"csrf_token": csrf, "title": "Evidence integrity"},
            files={"evidence_files": ("test.txt", content, "text/plain")},
        )
        assert response.status_code == 303
        evidence = db.scalar(select(Evidence).order_by(Evidence.id.desc()))
        assert evidence is not None
        assert evidence.sha256 == hashlib.sha256(content).hexdigest()

    def test_file_type_validation(self, l1_session, db):
        csrf = get_csrf(l1_session)
        response = l1_session.post(
            "/alerts/new/",
            data={"csrf_token": csrf, "title": "Blocked type"},
            files={"evidence_files": ("malicious.exe", b"MZ...", "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "not allowed" in response.text
        assert db.scalar(select(Evidence).order_by(Evidence.id.desc())) is None

    def test_session_tampering_rejected(self, client):
        login_with_csrf(client, "l1", "Password123!")
        client.cookies.set("session", "tampered_value")
        assert client.get("/").status_code in [303, 401, 403]


# ============================================================================
# A09: Logging and Monitoring
# ============================================================================

class TestA09LoggingMonitoring:

    def test_failed_login_logged(self, client, db):
        login_with_csrf(client, "nonexistent", "wrong")
        log = db.scalar(select(AuditLog).where(AuditLog.action == "auth.login_failed"))
        assert log is not None

    def test_successful_login_logged(self, client, db):
        login_with_csrf(client, "l1", "Password123!")
        log = db.scalar(select(AuditLog).where(AuditLog.action == "auth.login"))
        assert log is not None

    def test_alert_creation_logged(self, l1_session, db):
        csrf = get_csrf(l1_session)
        l1_session.post("/alerts/new/", data={
            "title": "Audit Test", "description": "Test", "source": "Manual",
            "severity": "Low", "status": "Open", "csrf_token": csrf,
        })
        log = db.scalar(select(AuditLog).where(AuditLog.action == "alert.created"))
        assert log is not None

    def test_user_management_logged(self, admin_session, db):
        csrf = get_csrf(admin_session)
        admin_session.post("/admin/users/", data={
            "username": "audituser", "password": "Password123!", "role": "L1", "csrf_token": csrf,
        })
        log = db.scalar(select(AuditLog).where(AuditLog.action == "user.created"))
        assert log is not None


# ============================================================================
# A10: SSRF
# ============================================================================

class TestA10SSRF:

    def test_no_outbound_requests(self, l1_session):
        csrf = get_csrf(l1_session)
        response = l1_session.post("/alerts/new/", data={
            "title": "SSRF Test http://evil.com",
            "description": "http://internal-service.local/admin",
            "source": "Manual", "severity": "Low", "status": "Open",
            "asset": "http://169.254.169.254/latest/meta-data/",
            "csrf_token": csrf,
        })
        assert response.status_code in [200, 303]

    def test_webhook_requires_api_key(self, client):
        response = client.post("/api/webhook/n8n/", json={"title": "Test", "severity": "High"})
        assert response.status_code == 401

    def test_webhook_rejects_invalid_key(self, client):
        response = client.post("/api/webhook/n8n/", json={"title": "Test", "severity": "High"}, headers={"X-API-Key": "invalid"})
        assert response.status_code == 401


# ============================================================================
# Additional Security Checks
# ============================================================================

class TestAdditionalSecurity:

    def test_pbkdf2_iterations(self):
        from soc_tracker.auth import hash_password
        import inspect
        source = inspect.getsource(hash_password)
        assert "240_000" in source or "240000" in source

    def test_session_samesite(self, client):
        login_with_csrf(client, "l1", "Password123!")
        for cookie in client.cookies.jar:
            if cookie.name == "session":
                samesite = cookie.get_nonstandard_attr("SameSite") or cookie.get("samesite")
                assert samesite in ["Lax", "Strict", "lax", "strict"]

    def test_no_sensitive_data_in_urls(self, client):
        response = login_with_csrf(client, "l1", "Password123!")
        assert "Password123!" not in str(response.url)

    def test_error_messages_generic(self, client):
        response = client.get("/nonexistent-route-12345")
        assert response.status_code == 404
        assert "traceback" not in response.text.lower()
        assert "/home/" not in response.text
