"""Alert CRUD routes."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import (
    can_create_alert,
    can_delete_alert,
    can_edit_alert,
    can_escalate_alert,
    can_assign_alert,
    assignable_roles_for,
    require_user,
)
from ..dependencies import get_db
from ..models import Alert, AlertEvent, Evidence, User
from ..services.alert_service import (
    create_alert,
    export_csv,
    filtered_alerts,
    filtered_alerts_paginated,
    form_values,
    sla_status,
)
from ..services.chart_service import chart_counts
from ..utils import audit, redirect_to, render

logger = logging.getLogger("soc_tracker.alert_routes")

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alerts = filtered_alerts(db, request)
    counts = {
        "total": len(alerts),
        "open": len([a for a in alerts if a.status == "Open"]),
        "pending": len([a for a in alerts if a.status == "Pending"]),
        "wip": len([a for a in alerts if a.status == "WIP"]),
        "critical": len([a for a in alerts if a.severity == "Critical"]),
        "overdue": len([a for a in alerts if sla_status(a)["class"] == "sla-overdue"]),
    }
    return render(request, "alerts/dashboard.html", {
        "alerts": alerts[:80],
        "counts": counts,
        "charts": chart_counts(alerts),
    }, db, user)


@router.get("/alerts/", response_class=HTMLResponse)
async def alert_list(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user), page: int = 1):
    pagination = filtered_alerts_paginated(db, request, page=page)
    return render(request, "alerts/list.html", {
        "alerts": pagination["alerts"],
        "page": pagination["page"],
        "total_pages": pagination["total_pages"],
        "total": pagination["total"],
    }, db, user)


@router.get("/alerts/mine/", response_class=HTMLResponse)
async def my_alerts(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alerts = [
        a for a in filtered_alerts(db, request)
        if (a.assigned_to_id == user.id or a.analyst == user.username) and a.status != "Closed"
    ]
    return render(request, "alerts/list.html", {
        "alerts": alerts,
        "page_title": "My assigned alerts",
        "page_eyebrow": "Work queue",
    }, db, user)


@router.get("/alerts/export.csv")
async def alert_export(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alerts = filtered_alerts(db, request)
    csv_content = export_csv(alerts)
    return Response(
        csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc-alerts.csv"'},
    )


@router.get("/alerts/new/", response_class=HTMLResponse)
async def alert_create_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    return render(request, "alerts/form.html", {"title": "New alert", "alert": None, "form": {}}, db, user)


@router.post("/alerts/new/")
async def alert_create(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    form = dict(await request.form())
    try:
        values = form_values(form)
    except ValueError as e:
        return render(request, "alerts/form.html", {
            "title": "New alert", "alert": None, "form": form, "error": str(e)
        }, db, user)
    if not values["title"]:
        return render(request, "alerts/form.html", {
            "title": "New alert", "alert": None, "form": form, "error": "Title is required."
        }, db, user)
    values["status"] = "Open"
    values["analyst"] = "Unassigned"
    alert = create_alert(db, values, user)
    audit(db, user, "alert.created", f"Created {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Created {alert.alert_id}.")


@router.get("/alerts/{pk}/", response_class=HTMLResponse)
async def alert_detail(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    assignable_users = list(db.scalars(select(User).where(User.role.in_(roles)).order_by(User.username))) if roles else []
    evidence = list(db.scalars(select(Evidence).where(Evidence.alert_id == alert.id).order_by(Evidence.created_at.desc())))
    return render(request, "alerts/detail.html", {
        "alert": alert,
        "can_edit": can_edit_alert(user, alert),
        "can_escalate": can_escalate_alert(user) and alert.status != "Closed" and alert.escalated_by_id is None,
        "can_start": alert.status == "Pending" and (
            alert.assigned_to_id == user.id or (alert.assigned_to_id is None and alert.analyst == user.username)
        ),
        "can_assign": can_assign_alert(user),
        "assignable_users": assignable_users,
        "evidence": evidence,
    }, db, user)


@router.get("/alerts/{pk}/edit/", response_class=HTMLResponse)
async def alert_edit_page(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    form = {
        "title": alert.title,
        "description": alert.description,
        "source": alert.source,
        "severity": alert.severity,
        "status": alert.status,
        "analyst": alert.analyst,
        "tactic": alert.tactic,
        "asset": alert.asset,
        "iocs_text": ", ".join(alert.iocs),
        "sla_hours": alert.sla_hours,
    }
    return render(request, "alerts/form.html", {"title": f"Edit {alert.alert_id}", "alert": alert, "form": form}, db, user)


@router.post("/alerts/{pk}/edit/")
async def alert_edit(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    form = dict(await request.form())
    try:
        values = form_values(form)
    except ValueError as e:
        return render(request, "alerts/form.html", {
            "title": f"Edit {alert.alert_id}", "alert": alert, "form": form, "error": str(e)
        }, db, user)
    if not values["title"]:
        return render(request, "alerts/form.html", {
            "title": f"Edit {alert.alert_id}", "alert": alert, "form": form, "error": "Title is required."
        }, db, user)
    iocs = values.pop("iocs")
    values.pop("status", None)
    values.pop("analyst", None)
    for key, value in values.items():
        setattr(alert, key, value)
    alert.iocs = iocs
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="updated", actor=user, message=f"{user.username} updated {alert.alert_id}."))
    audit(db, user, "alert.updated", f"Updated {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Updated {alert.alert_id}.")


@router.post("/alerts/{pk}/escalate/")
async def alert_escalate(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_escalate_alert(user):
        raise HTTPException(status_code=403)
    if alert.status == "Closed":
        raise HTTPException(status_code=409, detail="Closed tickets cannot be escalated.")
    if alert.escalated_by_id is not None:
        raise HTTPException(status_code=409, detail="Ticket has already been escalated.")
    alert.escalated_by = user
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="escalated", actor=user, message=f"{user.username} escalated this alert."))
    audit(db, user, "alert.escalated", f"Escalated {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Escalated {alert.alert_id}.")


@router.post("/alerts/{pk}/start/")
async def alert_start(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    is_assigned_analyst = alert.assigned_to_id == user.id or (
        alert.assigned_to_id is None and alert.analyst == user.username
    )
    if not is_assigned_analyst or alert.status != "Pending":
        raise HTTPException(status_code=403)
    alert.status = "WIP"
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="started", actor=user, message=f"{user.username} started work on {alert.alert_id}."))
    audit(db, user, "alert.started", f"Started work on {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Started work on {alert.alert_id}.")


@router.post("/alerts/{pk}/assign/")
async def alert_assign(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    if not roles:
        raise HTTPException(status_code=403)
    if alert.status == "Closed":
        raise HTTPException(status_code=409, detail="Closed tickets cannot be reassigned.")
    form = dict(await request.form())
    assigned_to = db.get(User, int(form.get("assigned_to") or 0))
    if not assigned_to or assigned_to.role not in roles:
        return redirect_to(alert.get_absolute_url(), "Select a valid analyst for your role.")
    previous_assignee = alert.assigned_to
    alert.assigned_to = assigned_to
    alert.assigned_by = user
    alert.analyst = assigned_to.username
    alert.status = "Pending"
    alert.updated_by = user
    db.add(AlertEvent(
        alert=alert, event_type="assigned", actor=user,
        assigned_from=previous_assignee, assigned_to=assigned_to,
        message=f"{user.username} assigned this alert to {assigned_to.username}."
    ))
    audit(db, user, "alert.assigned", f"Assigned {alert.alert_id} to {assigned_to.username}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Assigned {alert.alert_id} to {assigned_to.username}.")


@router.post("/alerts/{pk}/notes/")
async def alert_note(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    form = dict(await request.form())
    note = form.get("note", "").strip()
    if not note:
        return redirect_to(alert.get_absolute_url(), "Note cannot be empty.")
    if len(note) > 10000:
        return redirect_to(alert.get_absolute_url(), "Notes must be 10000 characters or less.")
    db.add(AlertEvent(alert=alert, event_type="note", actor=user, message=note))
    audit(db, user, "alert.note_added", f"Added a note to {alert.alert_id}.", "alert", alert.alert_id, request)
    alert.updated_by = user
    db.commit()
    return redirect_to(alert.get_absolute_url(), "Added investigation note.")


@router.post("/alerts/{pk}/close/")
async def alert_close(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    if alert.status == "Closed":
        raise HTTPException(status_code=409, detail="Ticket is already closed.")
    form = dict(await request.form())
    summary = form.get("resolution_summary", "").strip()
    if len(summary) < 20:
        return redirect_to(alert.get_absolute_url(), "Resolution summary must be at least 20 characters.")
    if len(summary) > 10000:
        return redirect_to(alert.get_absolute_url(), "Resolution summary must be 10000 characters or less.")
    alert.status = "Closed"
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="closed", actor=user, message=f"Resolution: {summary}"))
    audit(db, user, "alert.closed", f"Closed {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Closed {alert.alert_id}.")


@router.post("/alerts/{pk}/delete/")
async def alert_delete(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if not can_delete_alert(user):
        raise HTTPException(status_code=403)
    raise HTTPException(status_code=409, detail="Alert deletion is disabled to preserve incident and evidence history. Close the alert instead.")
