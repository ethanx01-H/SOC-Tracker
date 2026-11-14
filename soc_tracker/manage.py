"""Administrative commands for one-time operator provisioning."""

import argparse
import getpass
import json
from datetime import datetime

from sqlalchemy import select

from .auth import hash_password, validate_password_strength
from .config import APP_ENV, DATABASE_URL, RETENTION_DAYS
from .models import Alert, AlertEvent, SessionLocal, User
from .services import audit_export as audit_export_service
from .services import backup_status as backup_status_service
from .services import retention_service, sla_service
from .services.sqlite_import import import_sqlite
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


def run_retention(days: int, apply: bool) -> None:
    """Archive tickets past the retention window; dry run unless --apply."""
    with SessionLocal() as db:
        summary = retention_service.archive(db, days=days, apply=apply)
    print(json.dumps(summary, indent=2))
    if not summary["alerts"]:
        print(f"Nothing to archive: no closed tickets older than {days} days.")
    elif not apply:
        print("Dry run: nothing was written or deleted. Re-run with --apply to archive and remove.")


def run_audit_export(start: str | None, end: str | None, out: str | None) -> None:
    from pathlib import Path

    window = {
        "start": datetime.fromisoformat(start) if start else None,
        "end": datetime.fromisoformat(end) if end else None,
    }
    with SessionLocal() as db:
        result = audit_export_service.export(
            db, window["start"], window["end"], directory=Path(out) if out else None
        )
    print(f"Wrote {result['records']} audit records to {result['path']}")
    print(f"Manifest: {result['manifest']}")
    print(f"Head hash: {result['head']}")
    print("Record the head hash somewhere outside this host; it is what proves the export later.")


def run_audit_verify(path: str) -> None:
    result = audit_export_service.verify(path)
    print(json.dumps(result, indent=2))
    if not result["ok"]:
        raise SystemExit("Verification FAILED: the export does not match its manifest.")


def run_sla_sweep() -> None:
    with SessionLocal() as db:
        print(json.dumps(sla_service.sweep(db), indent=2))


def run_backup_status() -> None:
    print(json.dumps(backup_status_service.status(), indent=2))


def run_import_sqlite(path: str) -> None:
    """Move a pre-Postgres database across, once."""
    counts = import_sqlite(path, DATABASE_URL)
    print(f"Imported {counts.get('fastapi_alerts', 0)} tickets and "
          f"{counts.get('fastapi_users', 0)} accounts into Postgres.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    admin = commands.add_parser("create-admin", help="Create the first or another L3 administrator")
    admin.add_argument("username")
    commands.add_parser("seed-demo", help="Add five synthetic tickets for a local review environment")

    retention = commands.add_parser("retention", help="Archive closed tickets past the retention window")
    retention.add_argument("--days", type=int, default=RETENTION_DAYS, help=f"Retention window (default {RETENTION_DAYS})")
    retention.add_argument("--apply", action="store_true", help="Write the archive and delete the rows (default is a dry run)")

    export = commands.add_parser("audit-export", help="Write a hash-chained audit export")
    export.add_argument("--from", dest="start", default=None, help="Start timestamp (ISO 8601, UTC)")
    export.add_argument("--to", dest="end", default=None, help="End timestamp (ISO 8601, UTC)")
    export.add_argument("--out", default=None, help="Directory for the export")

    verify = commands.add_parser("audit-verify", help="Verify an audit export against its manifest")
    verify.add_argument("path")

    commands.add_parser("sla-sweep", help="Record newly missed SLAs and close resolved breaches")
    commands.add_parser("backup-status", help="Report the newest data snapshot and its age")
    importer = commands.add_parser("import-sqlite", help="Copy a SQLite database into the configured Postgres")
    importer.add_argument("path")

    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(args.username.strip())
    elif args.command == "seed-demo":
        seed_demo()
    elif args.command == "retention":
        run_retention(args.days, args.apply)
    elif args.command == "audit-export":
        run_audit_export(args.start, args.end, args.out)
    elif args.command == "audit-verify":
        run_audit_verify(args.path)
    elif args.command == "sla-sweep":
        run_sla_sweep()
    elif args.command == "backup-status":
        run_backup_status()
    elif args.command == "import-sqlite":
        run_import_sqlite(args.path)


if __name__ == "__main__":
    main()
