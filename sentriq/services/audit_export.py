"""Hash-chained audit export.

An audit trail that can be edited by whoever holds the database is not an audit
trail. Each exported row carries the hash of the previous row, so removing or
reordering a record breaks the chain and verification says exactly where.

The head hash is the anchor: record it somewhere else (a change ticket, an
off-box log) and any later rewrite of the export is detectable. Files are
written read-only, which stops accidental edits, not a determined one — real
immutability needs object-lock or WORM storage.
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import AUDIT_EXPORT_DIR
from ..models import AuditLog

logger = logging.getLogger("sentriq.audit_export")

GENESIS = "0" * 64


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _row(entry: AuditLog) -> dict:
    return {
        "id": entry.id,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "actor_id": entry.actor_id,
        "actor": entry.actor.username if entry.actor is not None else None,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "message": entry.message,
        "source_ip": entry.source_ip,
    }


def chain_hash(previous: str, record: dict) -> str:
    return hashlib.sha256((previous + _canonical(record)).encode("utf-8")).hexdigest()


def export(
    db: Session,
    start: datetime | None = None,
    end: datetime | None = None,
    directory: Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Write a verifiable JSONL export plus its manifest."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    target_dir = Path(directory or AUDIT_EXPORT_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)

    query = select(AuditLog).order_by(AuditLog.id)
    if start is not None:
        query = query.where(AuditLog.created_at >= start)
    if end is not None:
        query = query.where(AuditLog.created_at <= end)
    rows = db.scalars(query).all()

    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    path = target_dir / f"audit-{stamp}.jsonl"
    previous = GENESIS
    with open(path, "w", encoding="utf-8") as handle:
        for sequence, entry in enumerate(rows, start=1):
            record = _row(entry)
            digest = chain_hash(previous, record)
            handle.write(json.dumps(
                {"seq": sequence, "prev": previous, "record": record, "hash": digest},
                sort_keys=True,
            ) + "\n")
            previous = digest

    manifest = {
        "file": path.name,
        "records": len(rows),
        "head": previous,
        "genesis": GENESIS,
        "from": start.isoformat() if start else None,
        "to": end.isoformat() if end else None,
        "generated_at": now.isoformat(),
        "algorithm": "sha256(prev_hash + canonical_json(record))",
    }
    manifest_path = path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    # Read-only: an accidental overwrite or an editor save is refused outright.
    os.chmod(path, 0o444)
    os.chmod(manifest_path, 0o444)

    logger.info("Exported %s audit records to %s (head %s)", len(rows), path.name, previous[:16])
    return {"path": str(path), "manifest": str(manifest_path), "records": len(rows), "head": previous}


def verify(path: str | Path) -> dict:
    """Recompute the chain and report the first record that does not match."""
    path = Path(path)
    manifest_path = path.with_suffix(".manifest.json")
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest next to {path.name}; cannot verify the chain.")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    previous = manifest.get("genesis", GENESIS)
    count = 0
    with open(path, encoding="utf-8") as handle:
        for count, line in enumerate(handle, start=1):
            entry = json.loads(line)
            expected = chain_hash(previous, entry["record"])
            if entry.get("prev") != previous:
                return {"ok": False, "records": count, "broken_at": entry.get("seq"),
                        "reason": "previous-hash mismatch (a record was removed or reordered)"}
            if entry.get("hash") != expected:
                return {"ok": False, "records": count, "broken_at": entry.get("seq"),
                        "reason": "record hash mismatch (a record was edited)"}
            previous = entry["hash"]

    if count != manifest["records"]:
        return {"ok": False, "records": count, "broken_at": None,
                "reason": f"record count {count} does not match the manifest ({manifest['records']})"}
    if previous != manifest["head"]:
        return {"ok": False, "records": count, "broken_at": None,
                "reason": "head hash does not match the manifest"}
    return {"ok": True, "records": count, "head": previous}
