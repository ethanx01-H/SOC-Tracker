"""Evidence download and image preview routes.

Evidence is attached when the alert is created (see routes/alert_routes.py); this
module only serves what is already stored, so there is no way to add a file to an
existing ticket.
"""

import logging
import mimetypes
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from ..auth import UserDep
from ..config import UPLOAD_DIR
from ..dependencies import get_db
from ..models import Alert, Evidence

logger = logging.getLogger("soc_tracker.evidence_routes")

router = APIRouter()


def _stored_path(evidence: Evidence) -> Path:
    path = UPLOAD_DIR / evidence.stored_name
    if not path.exists():
        raise HTTPException(status_code=404)
    return path


@router.get("/evidence/{evidence_id}/")
async def evidence_download(evidence_id: int, user: UserDep, db: Session = Depends(get_db)):
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404)
    if not db.get(Alert, evidence.alert_id):
        raise HTTPException(status_code=404)
    return Response(
        _stored_path(evidence).read_bytes(),
        media_type=evidence.content_type,
        headers={"Content-Disposition": f'attachment; filename="{evidence.original_name}"'},
    )


@router.get("/evidence/{evidence_id}/preview/")
async def evidence_preview(evidence_id: int, user: UserDep, db: Session = Depends(get_db)):
    """Serve an image inline so the ticket can show it in a popup.

    The media type comes from the extension, not from the stored upload header:
    the browser must never be told to interpret analyst-supplied bytes as
    anything other than an image.
    """
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404)
    if not evidence.is_image:
        raise HTTPException(status_code=404)
    media_type = mimetypes.guess_type(f"preview{Path(evidence.stored_name).suffix}")[0]
    return Response(
        _stored_path(evidence).read_bytes(),
        media_type=media_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'inline; filename="{evidence.original_name}"',
            "Cache-Control": "private, max-age=300",
        },
    )
