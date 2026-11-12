"""Evidence upload and download routes."""

import hashlib
import logging
import re
import secrets
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from sqlalchemy.orm import Session

from ..auth import can_edit_alert, require_user, UserDep
from ..config import ALLOWED_EVIDENCE_EXTENSIONS, MAX_UPLOAD_BYTES, UPLOAD_DIR
from ..dependencies import get_db
from ..models import Alert, AlertEvent, Evidence
from ..utils import audit, redirect_to

logger = logging.getLogger("soc_tracker.evidence_routes")

router = APIRouter()


def secure_upload_name(filename: str) -> str:
    """Sanitize uploaded filename."""
    name = Path(filename or "evidence.bin").name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    return name or "evidence.bin"


@router.post("/alerts/{pk}/evidence/")
async def evidence_upload(
    request: Request,
    pk: int,
    evidence_file: Annotated[UploadFile, File()],
    user: UserDep,
    db: Session = Depends(get_db),
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    original_name = secure_upload_name(evidence_file.filename or "evidence.bin")
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EVIDENCE_EXTENSIONS:
        return redirect_to(alert.get_absolute_url(), f"Evidence type {extension or '(none)'} is not allowed.")
    chunks = []
    total = 0
    while chunk := await evidence_file.read(min(1024 * 1024, MAX_UPLOAD_BYTES + 1 - total)):
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            await evidence_file.close()
            return redirect_to(alert.get_absolute_url(), "Evidence file is too large.")
        chunks.append(chunk)
    content = b"".join(chunks)
    digest = hashlib.sha256(content).hexdigest()
    stored_name = f"{alert.alert_id}_{secrets.token_hex(8)}{extension}"
    path = UPLOAD_DIR / stored_name
    path.write_bytes(content)
    evidence = Evidence(
        alert=alert,
        uploaded_by=user,
        original_name=original_name,
        stored_name=stored_name,
        content_type=evidence_file.content_type or "application/octet-stream",
        size_bytes=len(content),
        sha256=digest,
    )
    db.add(evidence)
    db.add(AlertEvent(alert=alert, event_type="evidence", actor=user, message=f"Uploaded evidence {original_name}."))
    audit(db, user, "evidence.uploaded", f"Uploaded evidence {original_name} to {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    logger.info("Evidence '%s' uploaded to %s by %s", original_name, alert.alert_id, user.username)
    return redirect_to(alert.get_absolute_url(), "Uploaded evidence.")


@router.get("/evidence/{evidence_id}/")
async def evidence_download(evidence_id: int, user: UserDep, db: Session = Depends(get_db)):
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404)
    alert = db.get(Alert, evidence.alert_id)
    if not alert:
        raise HTTPException(status_code=404)
    path = UPLOAD_DIR / evidence.stored_name
    if not path.exists():
        raise HTTPException(status_code=404)
    return Response(
        path.read_bytes(),
        media_type=evidence.content_type,
        headers={"Content-Disposition": f'attachment; filename="{evidence.original_name}"'},
    )
