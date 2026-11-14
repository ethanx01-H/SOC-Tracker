"""Webhook routes for n8n integration."""

import hmac
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from typing import Annotated, Any

from alerts.elastic import parse_elastic_alerts, record_to_alert, records_from

from ..auth import can_create_alert, require_user, UserDep
from ..config import N8N_API_HEADER, N8N_API_KEY, WEBHOOK_ENABLED
from ..dependencies import get_db
from ..models import Alert, AlertEvent, AuditLog
from ..net import client_ip
from ..services.alert_service import create_or_get_alert
from ..utils import audit, redirect_to, render

logger = logging.getLogger("soc_tracker.webhook_routes")

router = APIRouter()


def api_key_valid(request: Request) -> bool:
    """Validate n8n API key using timing-safe comparison.

    With no key configured the integration is switched off rather than left
    open, so these routes answer 503 instead of accepting anonymous posts.
    """
    if not WEBHOOK_ENABLED:
        return False
    provided = request.headers.get(N8N_API_HEADER, "")
    return hmac.compare_digest(provided.encode(), N8N_API_KEY.encode())


def webhook_disabled() -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": "webhook disabled", "detail": "Set N8N_API_KEY to enable n8n ingest."},
        status_code=503,
    )


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


@router.post("/api/webhook/n8n")
@router.post("/api/webhook/n8n/")
def n8n_webhook(request: Request, payload: Any = Body(None), db: Session = Depends(get_db)):
    if not WEBHOOK_ENABLED:
        return webhook_disabled()
    if not api_key_valid(request):
        logger.warning("Invalid API key attempt from %s", client_ip(request))
        return JSONResponse({"ok": False, "error": "invalid api key"}, status_code=401)
    records = records_from(payload)
    if not records:
        return JSONResponse({"ok": False, "error": "no alert records found"}, status_code=400)
    if len(records) > 100:
        return JSONResponse({"ok": False, "error": "maximum 100 alerts per request"}, status_code=413)
    created = []
    existing = []
    try:
        for record in records:
            alert, is_new = create_or_get_alert(db, record_to_alert(record), source="n8n", payload=record)
            if is_new:
                created.append(alert)
            else:
                existing.append(alert)
        message = f"n8n created {len(created)} alert(s)."
        if existing:
            message += f" {len(existing)} duplicate(s) matched existing tickets."
        db.add(AuditLog(action="webhook.alerts_created", target_type="alert_batch", target_id=str(len(created)), message=message, source_ip=client_ip(request)))
        # One commit for the whole batch: a failure part-way leaves nothing behind.
        db.commit()
    except (ValueError, TypeError) as error:
        db.rollback()
        return JSONResponse({"ok": False, "error": str(error)}, status_code=422)
    logger.info("n8n webhook created %d alerts, matched %d duplicates", len(created), len(existing))
    return {
        "ok": True,
        "created": [alert.alert_id for alert in created],
        "existing": [alert.alert_id for alert in existing],
        "ids": [alert.alert_id for alert in created + existing],
    }


@router.post("/api/webhook/n8n/logs")
@router.post("/api/webhook/n8n/logs/")
def n8n_log_webhook(request: Request, payload: Any = Body(None), db: Session = Depends(get_db)):
    if not WEBHOOK_ENABLED:
        return webhook_disabled()
    if not api_key_valid(request):
        return JSONResponse({"ok": False, "error": "invalid api key"}, status_code=401)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "JSON object required"}, status_code=400)
    nested_alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    alert_id = payload.get("alert_id") or payload.get("alertId") or nested_alert.get("id")
    alert = db.scalar(select(Alert).where(Alert.alert_id == alert_id))
    if not alert:
        raise HTTPException(status_code=404)
    message = payload.get("message") or payload.get("log") or payload.get("event") or "n8n workflow log received."
    message = str(message)[:10000]
    event = AlertEvent(alert=alert, event_type="n8n_log", message=message, source="n8n", payload_json=json.dumps(payload))
    db.add(event)
    db.add(AuditLog(action="webhook.log_added", target_type="alert", target_id=alert.alert_id, message=f"n8n added a workflow log to {alert.alert_id}.", source_ip=client_ip(request)))
    db.commit()
    db.refresh(event)
    logger.info("n8n log added to %s", alert.alert_id)
    return {"ok": True, "event_id": event.id, "alert_id": alert.alert_id}
