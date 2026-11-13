"""Alert CRUD routes."""

import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
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
    user_role,
)
from ..dependencies import get_db
from ..models import Alert, AlertEvent, Evidence, User
from ..services.alert_service import (
    RANGE_CHOICES,
    create_alert,
    export_csv,
    filtered_alerts,
    filtered_alerts_paginated,
    form_values,
    sla_status,
)
from ..services import merge_service, notify, sla_service
from ..services.chart_service import chart_counts
from ..services.evidence_service import EvidenceError, read_upload, store_evidence
from ..config import PUBLIC_BASE_URL
from ..utils import audit, is_local_path, is_partial_request, page_url, redirect_to, render

logger = logging.getLogger("soc_tracker.alert_routes")

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    # Lazy SLA sweep: keeps breach history current without a scheduler. Idempotent,
    # and a failure here must never break the dashboard.
    try:
        sla_service.sweep(db)
    except Exception:
        logger.exception("SLA sweep failed")
        db.rollback()
    alerts = filtered_alerts(db, request)
    counts = {
        "total": len(alerts),
        "open": len([a for a in alerts if a.status == "Open"]),
        "pending": len([a for a in alerts if a.status == "Pending"]),
        "wip": len([a for a in alerts if a.status == "WIP"]),
        "critical": len([a for a in alerts if a.severity == "Critical"]),
        "overdue": len([a for a in alerts if sla_status(a)["class"] == "sla-overdue"]),
    }
    context = {
        "alerts": alerts[:80],
        "total": len(alerts),
        "counts": counts,
        "charts": chart_counts(alerts),
        "ranges": RANGE_CHOICES,
        "active_range": (request.query_params.get("range") or "all").lower(),
    }
    if is_partial_request(request):
        return render(request, "alerts/partials/dashboard_results.html", context, db, user)
    return render(request, "alerts/dashboard.html", context, db, user)


@router.get("/alerts/", response_class=HTMLResponse)
def alert_list(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user), page: int = 1):
    pagination = filtered_alerts_paginated(db, request, page=page)
    context = {
        "alerts": pagination["alerts"],
        "page": pagination["page"],
        "total_pages": pagination["total_pages"],
        "total": pagination["total"],
        "prev_url": page_url(request, pagination["page"] - 1) if pagination["page"] > 1 else None,
        "next_url": page_url(request, pagination["page"] + 1) if pagination["page"] < pagination["total_pages"] else None,
    }
    if is_partial_request(request):
        return render(request, "alerts/partials/alert_results.html", context, db, user)
    return render(request, "alerts/list.html", context, db, user)


@router.get("/alerts/mine/", response_class=HTMLResponse)
def my_alerts(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
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
def alert_export(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alerts = filtered_alerts(db, request)
    csv_content = export_csv(alerts)
    return Response(
        csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc-alerts.csv"'},
    )


@router.get("/alerts/new/", response_class=HTMLResponse)
def alert_create_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    return render(request, "alerts/form.html", {"title": "New alert", "alert": None, "form": {}}, db, user)


@router.post("/alerts/new/")
def alert_create(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    title: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    source: Annotated[str, Form()] = "Manual",
    severity: Annotated[str, Form()] = "Medium",
    tactic: Annotated[str, Form()] = "Unknown",
    asset: Annotated[str, Form()] = "Unknown",
    iocs_text: Annotated[str, Form()] = "",
    sla_hours: Annotated[str, Form()] = "8",
    evidence_files: Annotated[list[UploadFile] | None, File()] = None,
):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    # Declared as form parameters rather than request.form(): a sync handler
    # cannot await the parse, and FastAPI already parsed multipart for us.
    form = {
        "title": title,
        "description": description,
        "source": source,
        "severity": severity,
        "tactic": tactic,
        "asset": asset,
        "iocs_text": iocs_text,
        "sla_hours": sla_hours,
    }
    uploads = [item for item in (evidence_files or []) if item and item.filename]
    try:
        values = form_values(form)
        if not values["title"]:
            raise ValueError("Title is required.")
        # Read and validate every attachment before touching the database, so a
        # rejected file cannot leave a half-created ticket behind.
        prepared = [read_upload(upload) for upload in uploads]
    except (ValueError, EvidenceError) as error:
        return render(request, "alerts/form.html", {
            "title": "New alert", "alert": None, "form": form, "error": str(error)
        }, db, user)
    values["status"] = "Open"
    values["analyst"] = "Unassigned"
    alert = create_alert(db, values, user)
    written = []
    try:
        for (name, content), upload in zip(prepared, uploads):
            _, path = store_evidence(db, alert, user, name, content, upload.content_type)
            written.append(path)
        message = f"Created {alert.alert_id}."
        if prepared:
            message = f"Created {alert.alert_id} with {len(prepared)} evidence file(s)."
        audit(db, user, "alert.created", message, "alert", alert.alert_id, request)
        db.commit()
    except Exception:
        # Nothing half-written: drop the rows and the files just saved.
        db.rollback()
        for path in written:
            path.unlink(missing_ok=True)
        raise
    notify.notify(alert, "created", user.username, PUBLIC_BASE_URL)
    return redirect_to(alert.get_absolute_url(), f"Created {alert.alert_id}.")


@router.get("/alerts/{pk}/", response_class=HTMLResponse)
def alert_detail(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    assignable_users = list(db.scalars(select(User).where(User.role.in_(roles)).order_by(User.username))) if roles else []
    evidence = list(db.scalars(select(Evidence).where(Evidence.alert_id == alert.id).order_by(Evidence.created_at.desc(), Evidence.id.desc())))
    return render(request, "alerts/detail.html", {
        "alert": alert,
        "can_edit": can_edit_alert(user, alert),
        "can_escalate": can_escalate_alert(user) and alert.status != "Closed" and alert.escalated_by_id is None,
        "can_take": alert.status == "Open" and alert.assigned_to_id is None and user_role(user) in {"L1", "L2", "L3"},
        "status_choices": ["Open", "WIP", "Pending"],
        "can_assign": can_assign_alert(user),
        "assignable_users": assignable_users,
        "evidence": evidence,
        "duplicates": merge_service.possible_duplicates(db, alert),
        "can_merge": user_role(user) in {"L2", "L3"} and alert.status != "Closed",
    }, db, user)


@router.get("/alerts/{pk}/edit/", response_class=HTMLResponse)
def alert_edit_page(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
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
def alert_edit(
    request: Request,
    pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    title: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
    source: Annotated[str, Form()] = "Manual",
    severity: Annotated[str, Form()] = "Medium",
    tactic: Annotated[str, Form()] = "Unknown",
    asset: Annotated[str, Form()] = "Unknown",
    iocs_text: Annotated[str, Form()] = "",
    sla_hours: Annotated[str, Form()] = "8",
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    form = {
        "title": title,
        "description": description,
        "source": source,
        "severity": severity,
        "tactic": tactic,
        "asset": asset,
        "iocs_text": iocs_text,
        "sla_hours": sla_hours,
    }
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
def alert_escalate(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
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
    notify.notify(alert, "escalate", user.username, PUBLIC_BASE_URL)
    return redirect_to(alert.get_absolute_url(), f"Escalated {alert.alert_id}.")


@router.post("/alerts/{pk}/take/")
def alert_take(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if user_role(user) not in {"L1", "L2", "L3"}:
        raise HTTPException(status_code=403)
    if alert.status != "Open" or alert.assigned_to_id is not None:
        raise HTTPException(status_code=409, detail="Only unassigned Open tickets can be taken.")
    alert.assigned_to = user
    alert.assigned_by = user
    alert.analyst = user.username
    alert.status = "Pending"
    alert.updated_by = user
    db.add(AlertEvent(
        alert=alert, event_type="assigned", actor=user, assigned_to=user,
        message=f"{user.username} assigned this ticket to themselves.",
    ))
    audit(db, user, "alert.self_assigned", f"Assigned {alert.alert_id} to self.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Assigned {alert.alert_id} to you.")


@router.post("/alerts/{pk}/status/")
def alert_status_update(
    request: Request,
    pk: int,
    status: Annotated[str, Form()],
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    if alert.status == "Closed":
        raise HTTPException(status_code=409, detail="Closed tickets cannot be reopened here.")
    if status not in {"Open", "WIP", "Pending"}:
        raise HTTPException(status_code=422, detail="Select Open, WIP, or Pending.")

    old_status = alert.status
    if status == "Open":
        if alert.assigned_to_id is not None and alert.assigned_to_id != user.id and not can_assign_alert(user):
            raise HTTPException(status_code=403)
        alert.assigned_to = None
        alert.assigned_by = None
        alert.analyst = "Unassigned"
    elif alert.assigned_to_id is None:
        if user_role(user) not in {"L1", "L2"}:
            raise HTTPException(status_code=409, detail="Assign this ticket to an analyst first.")
        alert.assigned_to = user
        alert.assigned_by = user
        alert.analyst = user.username
        db.add(AlertEvent(
            alert=alert, event_type="assigned", actor=user, assigned_to=user,
            message=f"{user.username} assigned this ticket to themselves.",
        ))
    elif alert.assigned_to_id != user.id and not can_assign_alert(user):
        raise HTTPException(status_code=403, detail="Only the assigned analyst or an assigning role can change this ticket's status.")

    alert.status = status
    alert.updated_by = user
    db.add(AlertEvent(
        alert=alert, event_type="status_changed", actor=user,
        message=f"{user.username} changed status from {old_status} to {status}.",
    ))
    audit(db, user, "alert.status_changed", f"Changed {alert.alert_id} from {old_status} to {status}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Updated {alert.alert_id} to {status}.")


@router.post("/alerts/{pk}/assign/")
def alert_assign(
    request: Request,
    pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    assigned_to: Annotated[str, Form()] = "",
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    if not roles:
        raise HTTPException(status_code=403)
    if alert.status == "Closed":
        raise HTTPException(status_code=409, detail="Closed tickets cannot be reassigned.")
    try:
        target = db.get(User, int(assigned_to or 0))
    except (TypeError, ValueError):
        target = None
    if not target or target.role not in roles:
        return redirect_to(alert.get_absolute_url(), "Select a valid analyst for your role.")
    previous_assignee = alert.assigned_to
    alert.assigned_to = target
    alert.assigned_by = user
    alert.analyst = target.username
    alert.status = "Pending"
    alert.updated_by = user
    db.add(AlertEvent(
        alert=alert, event_type="assigned", actor=user,
        assigned_from=previous_assignee, assigned_to=target,
        message=f"{user.username} assigned this alert to {target.username}."
    ))
    audit(db, user, "alert.assigned", f"Assigned {alert.alert_id} to {target.username}.", "alert", alert.alert_id, request)
    db.commit()
    notify.notify(alert, "assign", user.username, PUBLIC_BASE_URL)
    return redirect_to(alert.get_absolute_url(), f"Assigned {alert.alert_id} to {target.username}.")


@router.post("/alerts/{pk}/notes/")
def alert_note(
    request: Request,
    pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    note: Annotated[str, Form()] = "",
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    note = note.strip()
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
def alert_close(
    request: Request,
    pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    resolution_summary: Annotated[str, Form()] = "",
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    if alert.status == "Closed":
        raise HTTPException(status_code=409, detail="Ticket is already closed.")
    summary = resolution_summary.strip()
    if not summary:
        return redirect_to(alert.get_absolute_url(), "Resolution summary is required.")
    alert.status = "Closed"
    alert.closed_at = datetime.now(timezone.utc)
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="closed", actor=user, message=f"Resolution: {summary}"))
    audit(db, user, "alert.closed", f"Closed {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Closed {alert.alert_id}.")


@router.post("/alerts/{pk}/delete/")
def alert_delete(request: Request, pk: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if not can_delete_alert(user):
        raise HTTPException(status_code=403)
    raise HTTPException(status_code=409, detail="Alert deletion is disabled to preserve incident and evidence history. Close the alert instead.")


@router.post("/alerts/{pk}/merge/")
def alert_merge(
    request: Request,
    pk: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    target_alert_id: Annotated[str, Form()] = "",
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if user_role(user) not in {"L2", "L3"}:
        raise HTTPException(status_code=403)
    wanted = target_alert_id.strip().upper()
    target = db.scalar(select(Alert).where(Alert.alert_id == wanted))
    if not target:
        return redirect_to(alert.get_absolute_url(), f"No ticket with the number {wanted or '(blank)'}.")
    try:
        result = merge_service.merge_alerts(db, alert, target, user)
    except merge_service.MergeError as error:
        return redirect_to(alert.get_absolute_url(), str(error))
    audit(
        db, user, "alert.merged",
        f"Merged {result['source']} into {result['target']} "
        f"({result['events']} event(s), {result['evidence']} evidence file(s)).",
        "alert", result["target"], request,
    )
    db.commit()
    return redirect_to(
        target.get_absolute_url(),
        f"Merged {result['source']} into {result['target']}.",
    )


@router.post("/alerts/bulk/")
def alert_bulk(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
    ids: Annotated[list[str] | None, Form()] = None,
    action: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form(alias="next")] = "",
):
    """Apply one action to several tickets at once.

    Every ticket is checked individually: a bulk action must not quietly skip the
    permission rules that a single-ticket action enforces.
    """
    # Send the analyst back where they were. Landing on the unfiltered queue after
    # a bulk action made the change look like it had not happened.
    back = return_to if is_local_path(return_to) else "/alerts/"
    selected: list[int] = []
    for raw in ids or []:
        try:
            selected.append(int(raw))
        except (TypeError, ValueError):
            continue
    if not selected:
        return redirect_to(back, "Select at least one ticket first.")

    alerts = list(db.scalars(select(Alert).where(Alert.id.in_(selected))))
    changed = 0
    skipped = 0
    for alert in alerts:
        if action == "assign_me":
            if alert.status == "Closed" or not can_create_alert(user):
                skipped += 1
                continue
            alert.assigned_to = user
            alert.assigned_by = user
            alert.analyst = user.username
            if alert.status == "Open":
                alert.status = "Pending"
            alert.updated_by = user
            db.add(AlertEvent(
                alert=alert, event_type="assigned", actor=user, assigned_to=user,
                message=f"{user.username} assigned this ticket to themselves (bulk action).",
            ))
            changed += 1
        elif action.startswith("status:"):
            wanted = action.split(":", 1)[1]
            if wanted not in {"Open", "WIP", "Pending"} or alert.status == "Closed" or not can_edit_alert(user, alert):
                skipped += 1
                continue
            previous = alert.status
            alert.status = wanted
            alert.updated_by = user
            db.add(AlertEvent(
                alert=alert, event_type="status",
                message=f"{user.username} changed status from {previous} to {wanted} (bulk action).",
            ))
            changed += 1
        else:
            skipped += 1

    if changed:
        audit(
            db, user, "alert.bulk_update",
            f"Bulk action '{action}' updated {changed} ticket(s)"
            + (f", skipped {skipped}." if skipped else "."),
            "alert_batch", str(changed), request,
        )
        db.commit()
    message = f"Updated {changed} ticket(s)."
    if skipped:
        message += f" {skipped} skipped (closed, or not permitted)."
    return redirect_to(back, message)
