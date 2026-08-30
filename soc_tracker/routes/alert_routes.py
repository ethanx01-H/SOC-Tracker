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
    UserDep,
)
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


def get_db():
    from ..models import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: DbSession, user: UserDep):
    alerts = filtered_alerts(db, request)
    counts = {
        "total": len(alerts),
        "open": len([a for a in alerts if a.status != "Closed"]),
        "critical": len([a for a in alerts if a.severity == "Critical"]),
        "escalated": len([a for a in alerts if a.status == "Escalated"]),
        "overdue": len([a for a in alerts if sla_status(a)["class"] == "sla-overdue"]),
    }
    return render(request, "alerts/dashboard.html", {
        "alerts": alerts[:80],
        "counts": counts,
        "charts": chart_counts(alerts),
    }, db, user)


@router.get("/alerts/", response_class=HTMLResponse)
async def alert_list(request: Request, db: DbSession, user: UserDep, page: int = 1):
    pagination = filtered_alerts_paginated(db, request, page=page)
    return render(request, "alerts/list.html", {
        "alerts": pagination["alerts"],
        "page": pagination["page"],
        "total_pages": pagination["total_pages"],
        "total": pagination["total"],
    }, db, user)


@router.get("/alerts/mine/", response_class=HTMLResponse)
async def my_alerts(request: Request, db: DbSession, user: UserDep):
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
async def alert_export(request: Request, db: DbSession, user: UserDep):
    alerts = filtered_alerts(db, request)
    csv_content = export_csv(alerts)
    return Response(
        csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc-alerts.csv"'},
    )


@router.get("/alerts/new/", response_class=HTMLResponse)
async def alert_create_page(request: Request, db: DbSession, user: UserDep):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    return render(request, "alerts/form.html", {"title": "New alert", "alert": None, "form": {}}, db, user)


@router.post("/alerts/new/")
async def alert_create(request: Request, db: DbSession, user: UserDep):
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
    alert = create_alert(db, values, user)
    audit(db, user, "alert.created", f"Created {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Created {alert.alert_id}.")


@router.get("/r/{alert_id}/")
async def alert_report(alert_id: str, db: DbSession, user: UserDep):
    alert = db.scalar(select(Alert).where(Alert.alert_id == alert_id))
    if not alert:
        raise HTTPException(status_code=404)
    return redirect_to(alert.get_absolute_url())


@router.get("/alerts/{pk}/", response_class=HTMLResponse)
async def alert_detail(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    assignable_users = list(db.scalars(select(User).where(User.role.in_(roles)).order_by(User.username))) if roles else []
    evidence = list(db.scalars(select(Evidence).where(Evidence.alert_id == alert.id).order_by(Evidence.created_at.desc())))
    return render(request, "alerts/detail.html", {
        "alert": alert,
        "can_edit": can_edit_alert(user, alert),
        "can_escalate": can_escalate_alert(user) and alert.status != "Escalated",
        "can_assign": can_assign_alert(user),
        "assignable_users": assignable_users,
        "evidence": evidence,
    }, db, user)


@router.get("/alerts/{pk}/edit/", response_class=HTMLResponse)
async def alert_edit_page(request: Request, pk: int, db: DbSession, user: UserDep):
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
async def alert_edit(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    old_status = alert.status
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
    if old_status != "Closed" and values["status"] == "Closed":
        return render(request, "alerts/form.html", {
            "title": f"Edit {alert.alert_id}", "alert": alert, "form": form,
            "error": "Use the close workflow to close an alert with a resolution summary."
        }, db, user)
    iocs = values.pop("iocs")
    for key, value in values.items():
        setattr(alert, key, value)
    alert.iocs = iocs
    alert.updated_by = user
    if old_status != "Escalated" and alert.status == "Escalated":
        alert.escalated_by = user
    db.add(AlertEvent(alert=alert, event_type="updated", actor=user, message=f"{user.username} updated {alert.alert_id}."))
    audit(db, user, "alert.updated", f"Updated {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Updated {alert.alert_id}.")


@router.post("/alerts/{pk}/escalate/")
async def alert_escalate(pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_escalate_alert(user):
        raise HTTPException(status_code=403)
    alert.status = "Escalated"
    alert.escalated_by = user
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="escalated", actor=user, message=f"{user.username} escalated this alert."))
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Escalated {alert.alert_id}.")


@router.post("/alerts/{pk}/assign/")
async def alert_assign(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    if not roles:
        raise HTTPException(status_code=403)
    form = dict(await request.form())
    assigned_to = db.get(User, int(form.get("assigned_to") or 0))
    if not assigned_to or assigned_to.role not in roles:
        return redirect_to(alert.get_absolute_url(), "Select a valid analyst for your role.")
    previous_assignee = alert.assigned_to
    alert.assigned_to = assigned_to
    alert.assigned_by = user
    alert.analyst = assigned_to.username
    alert.status = "Investigating"
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
async def alert_note(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    form = dict(await request.form())
    note = form.get("note", "").strip()
    if not note:
        return redirect_to(alert.get_absolute_url(), "Note cannot be empty.")
    db.add(AlertEvent(alert=alert, event_type="note", actor=user, message=note))
    alert.updated_by = user
    db.commit()
    return redirect_to(alert.get_absolute_url(), "Added investigation note.")


@router.post("/alerts/{pk}/close/")
async def alert_close(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    form = dict(await request.form())
    summary = form.get("resolution_summary", "").strip()
    if len(summary) < 20:
        return redirect_to(alert.get_absolute_url(), "Resolution summary must be at least 20 characters.")
    alert.status = "Closed"
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="closed", actor=user, message=f"Resolution: {summary}"))
    audit(db, user, "alert.closed", f"Closed {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Closed {alert.alert_id}.")


@router.post("/alerts/{pk}/delete/")
async def alert_delete(request: Request, pk: int, db: DbSession, user: UserDep):
    if not can_delete_alert(user):
        raise HTTPException(status_code=403)
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    alert_id = alert.alert_id
    audit(db, user, "alert.deleted", f"Deleted {alert_id}.", "alert", alert_id, request)
    db.delete(alert)
    db.commit()
    logger.info("Alert %s deleted by %s", alert_id, user.username)
    return redirect_to("/alerts/", f"Deleted {alert_id}.")
