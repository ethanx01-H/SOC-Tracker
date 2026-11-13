"""Evidence upload and download routes."""

import logging

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from typing import Annotated
from sqlalchemy.orm import Session

from ..auth import can_edit_alert, require_user, UserDep
from ..config import UPLOAD_DIR
from ..dependencies import get_db
from ..models import Alert, Evidence
from ..services.evidence_service import EvidenceError, read_upload, store_evidence
from ..utils import audit, redirect_to

logger = logging.getLogger("soc_tracker.evidence_routes")

router = APIRouter()


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
    try:
        name, content = await read_upload(evidence_file)
    except EvidenceError as error:
        return redirect_to(alert.get_absolute_url(), str(error))
    store_evidence(db, alert, user, name, content, evidence_file.content_type)
    audit(db, user, "evidence.uploaded", f"Uploaded evidence {name} to {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
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
