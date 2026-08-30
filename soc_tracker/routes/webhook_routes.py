"""Webhook routes for n8n integration."""

import hmac
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import can_create_alert, require_user, UserDep
from ..config import N8N_API_HEADER, N8N_API_KEY
from ..models import Alert, AlertEvent
from ..services.alert_service import create_alert
from ..utils import redirect_to, render

from alerts.elastic import parse_elastic_alerts, record_to_alert, records_from

logger = logging.getLogger("soc_tracker.webhook_routes")

router = APIRouter()


def get_db():
    from ..models import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


def api_key_valid(request: Request) -> bool:
    """Validate n8n API key using timing-safe comparison."""
    provided = request.headers.get(N8N_API_HEADER, "")
    return hmac.compare_digest(provided.encode(), N8N_API_KEY.encode())


@router.get("/elastic/import/", response_class=HTMLResponse)
async def elastic_import_page(request: Request, db: DbSession, user: UserDep):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    return render(request, "alerts/elastic_import.html", {"raw_json": "", "error": None}, db, user)


@router.post("/elastic/import/")
async def elastic_import(request: Request, db: DbSession, user: UserDep, raw_json: Annotated[str, Form()]):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    try:
        parsed = parse_elastic_alerts(raw_json)
    except json.JSONDecodeError as error:
        return render(request, "alerts/elastic_import.html", {"raw_json": raw_json, "error": f"Invalid JSON: {error}"}, db, user)
    created = [create_alert(db, dict(item), user) for item in parsed]
    logger.info("Imported %d Elastic alerts by %s", len(created), user.username)
    return redirect_to("/alerts/", f"Imported {len(created)} Elastic alert(s).")


@router.post("/api/webhook/n8n")
@router.post("/api/webhook/n8n/")
async def n8n_webhook(request: Request, db: DbSession):
    if not api_key_valid(request):
        logger.warning("Invalid API key attempt from %s", request.client.host if request.client else "unknown")
        return JSONResponse({"ok": False, "error": "invalid api key"}, status_code=401)
    try:
        payload = await request.json()
    except json.JSONDecodeError as error:
        return JSONResponse({"ok": False, "error": str(error)}, status_code=400)
    records = records_from(payload)
    if not records:
        return JSONResponse({"ok": False, "error": "no alert records found"}, status_code=400)
    created = []
    for record in records:
        alert = create_alert(db, record_to_alert(record))
        alert.events[0].source = "n8n"
        alert.events[0].payload_json = json.dumps(record)
        db.commit()
        created.append(alert)
    logger.info("n8n webhook created %d alerts", len(created))
    return {"ok": True, "created": [alert.alert_id for alert in created]}


@router.post("/api/webhook/n8n/logs")
@router.post("/api/webhook/n8n/logs/")
async def n8n_log_webhook(request: Request, db: DbSession):
    if not api_key_valid(request):
        return JSONResponse({"ok": False, "error": "invalid api key"}, status_code=401)
    try:
        payload = await request.json()
    except json.JSONDecodeError as error:
        return JSONResponse({"ok": False, "error": str(error)}, status_code=400)
    alert_id = payload.get("alert_id") or payload.get("alertId") or payload.get("alert", {}).get("id")
    alert = db.scalar(select(Alert).where(Alert.alert_id == alert_id))
    if not alert:
        raise HTTPException(status_code=404)
    message = payload.get("message") or payload.get("log") or payload.get("event") or "n8n workflow log received."
    event = AlertEvent(alert=alert, event_type="n8n_log", message=message, source="n8n", payload_json=json.dumps(payload))
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.info("n8n log added to %s", alert.alert_id)
    return {"ok": True, "event_id": event.id, "alert_id": alert.alert_id}
