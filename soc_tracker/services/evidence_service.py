"""Evidence storage shared by the new-alert form and the upload route.

Both entry points must apply the same rules — extension allow-list, size cap,
hashed filename, SHA-256 recorded, timeline event, audit row — so the rules live
here instead of being copied into each route.
"""

import hashlib
import logging
import re
import secrets
from pathlib import Path

from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from ..config import ALLOWED_EVIDENCE_EXTENSIONS, MAX_UPLOAD_BYTES, UPLOAD_DIR
from ..models import Alert, AlertEvent, Evidence, User

logger = logging.getLogger("soc_tracker.evidence_service")

CHUNK = 1024 * 1024


class EvidenceError(Exception):
    """Rejected upload. The message is safe to show to the analyst."""


def secure_upload_name(filename: str) -> str:
    """Sanitize an uploaded filename to something safe on disk and in headers."""
    name = Path(filename or "evidence.bin").name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    return name or "evidence.bin"


def read_upload(upload: UploadFile) -> tuple[str, bytes]:
    """Validate and read one upload. Raises EvidenceError on a rejected file.

    Synchronous on purpose: routes are plain ``def`` so this blocking read runs
    in Starlette's thread pool instead of stalling the event loop.
    """
    name = secure_upload_name(upload.filename or "evidence.bin")
    extension = Path(name).suffix.lower()
    if extension not in ALLOWED_EVIDENCE_EXTENSIONS:
        raise EvidenceError(f"Evidence type {extension or '(none)'} is not allowed.")

    chunks = []
    total = 0
    try:
        while chunk := upload.file.read(min(CHUNK, MAX_UPLOAD_BYTES + 1 - total)):
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise EvidenceError(f"{name} is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
            chunks.append(chunk)
    finally:
        upload.file.close()
    return name, b"".join(chunks)


def store_evidence(
    db: Session,
    alert: Alert,
    user: User | None,
    name: str,
    content: bytes,
    content_type: str | None,
) -> tuple[Evidence, Path]:
    """Write the file and stage the evidence row plus its timeline event."""
    extension = Path(name).suffix.lower()
    stored_name = f"{alert.alert_id}_{secrets.token_hex(8)}{extension}"
    path = UPLOAD_DIR / stored_name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)

    evidence = Evidence(
        alert=alert,
        uploaded_by=user,
        original_name=name,
        stored_name=stored_name,
        content_type=content_type or "application/octet-stream",
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    db.add(evidence)
    db.add(AlertEvent(
        alert=alert,
        event_type="evidence",
        actor=user,
        message=f"Uploaded evidence {name}.",
    ))
    logger.info("Evidence '%s' stored for %s", name, alert.alert_id)
    return evidence, path
