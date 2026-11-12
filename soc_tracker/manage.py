"""Administrative commands for one-time operator provisioning."""

import argparse
import getpass

from sqlalchemy import select

from .auth import hash_password, validate_password_strength
from .config import APP_ENV
from .models import Alert, AlertEvent, SessionLocal, User
from .services.alert_service import create_alert


def create_admin(username: str) -> None:
    password = getpass.getpass("Admin password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    error = validate_password_strength(password)
    if error:
        raise SystemExit(error)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            raise SystemExit(f"User {username!r} already exists.")
        db.add(User(username=username, password_hash=hash_password(password), role="L3", is_admin=True))
        db.commit()
    print(f"Created administrator {username!r}.")


def seed_demo() -> None:
    """Create synthetic review tickets. Never seed the production environment."""
    if APP_ENV == "production":
        raise SystemExit("Demo records are disabled when APP_ENV=production.")
    with SessionLocal() as db:
        if db.scalar(select(Alert.id).where(Alert.source == "Demo")):
            raise SystemExit("Demo tickets already exist; no duplicate tickets were added.")
        admin = db.scalar(select(User).where(User.username == "admin_l3"))
        l1 = db.scalar(select(User).where(User.username == "l1"))
        l2 = db.scalar(select(User).where(User.username == "l2"))
        if not admin or not l1 or not l2:
            raise SystemExit("Create admin_l3, l1, and l2 accounts before seeding demo tickets.")

        samples = [
            {
                "title": "Malware detection on DEMO-WKS-01",
                "description": "Synthetic EDR alert: a test artifact matched a malware detection rule. No real malware or production host is involved.",
                "severity": "Critical", "status": "WIP", "asset": "DEMO-WKS-01",
                "tactic": "Execution", "iocs": ["eicar-demo.invalid", "192.0.2.41"], "owner": l1,
            },
            {
                "title": "Possible account compromise for demo.user",
                "description": "Synthetic identity alert: sign-ins from two reserved test networks were observed close together. Verify session activity and revoke test sessions if suspicious.",
                "severity": "High", "status": "Pending", "asset": "demo.user@example.invalid",
                "tactic": "Initial Access", "iocs": ["192.0.2.52", "198.51.100.27"], "owner": l2,
            },
            {
                "title": "Phishing email reported by a demo mailbox",
                "description": "Synthetic mail alert: a user reported an invoice-themed message containing a link to a reserved .invalid domain. Review the message and confirm no credentials were entered.",
                "severity": "High", "status": "Open", "asset": "demo.mailbox@example.invalid",
                "tactic": "Initial Access", "iocs": ["invoice-review.invalid", "192.0.2.63"], "owner": None,
            },
            {
                "title": "Port scanning detected from the test subnet",
                "description": "Synthetic network alert: repeated connection attempts to multiple test ports were observed from a documentation-only IP address.",
                "severity": "Medium", "status": "Open", "asset": "DEMO-NET-01",
                "tactic": "Reconnaissance", "iocs": ["198.51.100.88"], "owner": None,
            },
            {
                "title": "Suspicious attachment quarantined",
                "description": "Synthetic email security alert: a macro-enabled spreadsheet was quarantined before delivery. Confirm the recipient and review the gateway verdict.",
                "severity": "Medium", "status": "Open", "asset": "demo.finance@example.invalid",
                "tactic": "Initial Access", "iocs": ["quarterly-report.xlsx", "203.0.113.19"], "owner": None,
            },
        ]

        for sample in samples:
            owner = sample.pop("owner")
            values = {
                **sample,
                "source": "Demo",
                "analyst": owner.username if owner else "Unassigned",
                "sla_hours": {"Critical": 2, "High": 4, "Medium": 8}[sample["severity"]],
            }
            if owner:
                values.update(assigned_to=owner, assigned_by=admin)
            alert = create_alert(db, values, admin)
            if owner:
                db.add(AlertEvent(
                    alert=alert, event_type="assigned", actor=admin, assigned_to=owner,
                    message=f"admin_l3 assigned this demo ticket to {owner.username}.", source="demo",
                ))
                if alert.status == "WIP":
                    db.add(AlertEvent(
                        alert=alert, event_type="started", actor=owner,
                        message=f"{owner.username} started work on this demo ticket.", source="demo",
                    ))
        db.commit()
    print(f"Created {len(samples)} synthetic demo tickets.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("create-admin", help="Create the first or another L3 administrator")
    admin.add_argument("username")
    commands.add_parser("seed-demo", help="Add five synthetic tickets for a local review environment")
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.username.strip())
    elif args.command == "seed-demo":
        seed_demo()


if __name__ == "__main__":
    main()
