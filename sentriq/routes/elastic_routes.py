"""Importing alerts that were copied out of Elastic SIEM.

The pasted-JSON page is the only ingest path: there is no inbound API and no
shared key, so nothing can create a ticket without a signed-in analyst.
"""

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from alerts.elastic import parse_elastic_alerts

from ..auth import can_create_alert, UserDep
from ..dependencies import get_db
from ..services.alert_service import create_or_get_alert
from ..utils import audit, redirect_to, render

logger = logging.getLogger("sentriq.elastic_routes")

router = APIRouter()


@router.get("/elastic/import/", response_class=HTMLResponse)
def elastic_import_page(request: Request, user: UserDep, db: Session = Depends(get_db)):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    return render(request, "alerts/elastic_import.html", {"raw_json": "", "error": None}, db, user)


@router.post("/elastic/import/")
def elastic_import(request: Request, raw_json: Annotated[str, Form()], user: UserDep, db: Session = Depends(get_db)):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    try:
        parsed = parse_elastic_alerts(raw_json)
    except json.JSONDecodeError as error:
        return render(request, "alerts/elastic_import.html", {"raw_json": raw_json, "error": f"Invalid JSON: {error}"}, db, user)
    created = []
    skipped = 0
    for item in parsed:
        alert, is_new = create_or_get_alert(db, dict(item), user)
        if is_new:
            created.append(alert)
        else:
            skipped += 1
    message = f"Imported {len(created)} alert(s) from Elastic."
    if skipped:
        message += f" Skipped {skipped} duplicate(s)."
    audit(db, user, "alert.elastic_import", message, "alert_batch", str(len(created)), request)
    db.commit()
    logger.info("Imported %d Elastic alerts by %s (%d duplicates skipped)", len(created), user.username, skipped)
    return redirect_to("/alerts/", message)
