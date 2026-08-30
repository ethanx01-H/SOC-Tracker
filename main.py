"""SOC Alert Tracker - FastAPI Application Entry Point.

A lightweight, self-hosted security operations alert tracker with role-based
alert management, Elastic SIEM integration, and n8n workflow automation.
"""

import logging
import os
import secrets

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from alerts.elastic import parse_elastic_alerts, record_to_alert, records_from

from soc_tracker.config import ALEMBIC_HEAD, BASE_DIR, DATA_DIR, SQLITE_PATH, UPLOAD_DIR
from soc_tracker.middleware import security_middleware
from soc_tracker.models import Alert, AlertEvent, Base, Evidence, User, engine, SessionLocal, generate_alert_id
from soc_tracker.auth import hash_password
from soc_tracker.routes import auth_routes, alert_routes, admin_routes, evidence_routes, webhook_routes
from soc_tracker.services.alert_service import create_alert

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("soc_tracker")

# Create FastAPI app
app = FastAPI(title="SOC Alert Tracker")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# Add security middleware
app.middleware("http")(security_middleware)

# Include routers
app.include_router(auth_routes.router)
app.include_router(alert_routes.router)
app.include_router(admin_routes.router)
app.include_router(evidence_routes.router)
app.include_router(webhook_routes.router)


def bootstrap_users(db: Session) -> None:
    """Create default demo users if they don't exist."""
    for username, role, is_admin in [("l1", "L1", False), ("l2", "L2", False), ("admin_l3", "L3", True)]:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            db.add(User(username=username, password_hash=hash_password("password123"), role=role, is_admin=is_admin))
            logger.info("Created demo user '%s' with role %s", username, role)
        else:
            user.role = role
            user.is_admin = is_admin
    db.commit()


def seed_sample_alerts(db: Session) -> None:
    """Seed sample alerts for demo purposes."""
    if db.scalar(select(func.count(Alert.id))) > 0:
        return

    l1 = db.scalar(select(User).where(User.username == "l1"))
    l2 = db.scalar(select(User).where(User.username == "l2"))
    samples = [
        {
            "title": "Suspicious VPN login from new country",
            "description": "Successful VPN login for a finance user from a country not previously seen for this account. MFA succeeded, but the source IP has poor reputation.",
            "source": "Elastic",
            "severity": "High",
            "status": "Triage",
            "analyst": "l1",
            "tactic": "Initial Access",
            "asset": "finance.user@example.local",
            "iocs": ["198.51.100.77", "finance.user@example.local"],
            "sla_hours": 4,
            "created_by": l1,
            "updated_by": l1,
            "assigned_to": l1,
            "assigned_by": l1,
        },
        {
            "title": "Encoded PowerShell launched from Downloads",
            "description": "EDR detected an encoded PowerShell command launched from a user Downloads directory. The host should be isolated if follow-up telemetry confirms credential access.",
            "source": "Elastic EDR",
            "severity": "Critical",
            "status": "Escalated",
            "analyst": "l2",
            "tactic": "Execution",
            "asset": "WIN-ENG-044",
            "iocs": ["powershell.exe", "-EncodedCommand", "WIN-ENG-044"],
            "sla_hours": 2,
            "created_by": l1,
            "updated_by": l2,
            "escalated_by": l1,
            "assigned_to": l2,
            "assigned_by": l2,
        },
        {
            "title": "DNS tunneling pattern to new domain",
            "description": "Firewall analytics found high-entropy DNS queries to a newly registered domain from a workstation subnet.",
            "source": "Firewall",
            "severity": "Medium",
            "status": "Investigating",
            "analyst": "l1",
            "tactic": "Command and Control",
            "asset": "10.32.14.88",
            "iocs": ["updates-cdn-check.example", "10.32.14.88"],
            "sla_hours": 8,
            "created_by": l1,
            "updated_by": l1,
            "assigned_to": l1,
            "assigned_by": l2,
        },
        {
            "title": "Quarantined phishing payload",
            "description": "Email gateway quarantined a phishing message with a blocked HTML attachment before delivery to the accounts payable mailbox.",
            "source": "Email Gateway",
            "severity": "Low",
            "status": "Closed",
            "analyst": "l1",
            "tactic": "Initial Access",
            "asset": "mailbox:ap@company.local",
            "iocs": ["invoice_review.html", "185.199.110.153"],
            "sla_hours": 24,
            "created_by": l1,
            "updated_by": l1,
            "assigned_to": l1,
            "assigned_by": l2,
        },
    ]
    for sample in samples:
        alert = create_alert(db, sample)
        db.add(AlertEvent(
            alert=alert,
            event_type="assigned",
            actor=sample["assigned_by"],
            assigned_to=sample["assigned_to"],
            message=f"{sample['assigned_by'].username} assigned this alert to {sample['assigned_to'].username}.",
            source="seed"
        ))
        db.commit()
    logger.info("Seeded %d sample alerts", len(samples))


def run_migrations() -> None:
    """Run database migrations or create tables."""
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError:
        Base.metadata.create_all(bind=engine)
        return

    config = Config(str(BASE_DIR / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{SQLITE_PATH}")
    inspector = inspect(engine)
    has_app_tables = inspector.has_table("fastapi_users")
    has_version_table = inspector.has_table("alembic_version")
    if has_version_table:
        with engine.connect() as connection:
            current_revision = connection.exec_driver_sql("select version_num from alembic_version").scalar()
        if current_revision == ALEMBIC_HEAD:
            return
    if has_app_tables and not has_version_table:
        Base.metadata.create_all(bind=engine)
        command.stamp(config, "head")
        return
    command.upgrade(config, "head")


@app.on_event("startup")
def startup() -> None:
    """Initialize database and seed data on startup."""
    logger.info("Starting SOC Alert Tracker...")
    run_migrations()
    with SessionLocal() as db:
        bootstrap_users(db)
        seed_sample_alerts(db)
    logger.info("SOC Alert Tracker ready")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        reload=True,
        server_header=False,
    )
