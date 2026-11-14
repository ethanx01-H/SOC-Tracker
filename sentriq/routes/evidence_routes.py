"""Evidence download and image preview routes.

Evidence is attached when the alert is created (see routes/alert_routes.py); this
module only serves what is already stored, so there is no way to add a file to an
existing ticket.

Every read of an evidence file is written to the audit trail. Chain of custody is
the question a bank asks after an incident — "who pulled this packet capture, and
when" — and it cannot be answered from a mutable row that only records uploads.
"""

import logging
import mimetypes
import re
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..auth import UserDep
from ..config import UPLOAD_DIR
from ..dependencies import get_db
from ..models import Alert, Evidence
from ..utils import audit

logger = logging.getLogger("sentriq.evidence_routes")

router = APIRouter()


def _stored_path(evidence: Evidence) -> Path:
    path = UPLOAD_DIR / evidence.stored_name
    if not path.exists():
        raise HTTPException(status_code=404)
    return path


def content_disposition(disposition: str, filename: str) -> str:
    """Build a header value that cannot break out of the quoted filename.

    The original name is analyst-supplied, so quotes and line breaks are stripped,
    a plain ASCII fallback is offered to old clients, and the real name rides in
    ``filename*`` (RFC 5987) for everything that understands UTF-8.
    """
    cleaned = re.sub(r'[\r\n"\\]', "", filename or "") or "evidence"
    fallback = cleaned.encode("ascii", "ignore").decode().strip() or "evidence"
    return f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{quote(cleaned)}"


def _record_read(db: Session, user, evidence: Evidence, action: str, request: Request) -> None:
    """Audit an evidence read, with the hash so the copy can be tied to the file."""
    audit(
        db, user, action,
        f"{user.username} read {evidence.original_name} "
        f"({evidence.size_bytes} bytes, sha256 {evidence.sha256[:16]}…) "
        f"from alert #{evidence.alert_id}.",
        "evidence", str(evidence.id), request,
    )
    db.commit()


@router.get("/evidence/{evidence_id}/")
def evidence_download(evidence_id: int, request: Request, user: UserDep, db: Session = Depends(get_db)):
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404)
    if not db.get(Alert, evidence.alert_id):
        raise HTTPException(status_code=404)
    content = _stored_path(evidence).read_bytes()
    _record_read(db, user, evidence, "evidence.downloaded", request)
    return Response(
        content,
        media_type=evidence.content_type,
        headers={"Content-Disposition": content_disposition("attachment", evidence.original_name)},
    )


@router.get("/evidence/{evidence_id}/preview/")
def evidence_preview(evidence_id: int, request: Request, user: UserDep, db: Session = Depends(get_db)):
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
    content = _stored_path(evidence).read_bytes()
    _record_read(db, user, evidence, "evidence.previewed", request)
    return Response(
        content,
        media_type=media_type or "application/octet-stream",
        headers={
            "Content-Disposition": content_disposition("inline", evidence.original_name),
            "Cache-Control": "private, max-age=300",
        },
    )
