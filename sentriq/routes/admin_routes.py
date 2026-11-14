"""Admin routes for user management and audit log."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..auth import can_manage_users, hash_password, validate_password_strength, require_user, UserDep
from ..config import ROLES
from ..dependencies import get_db
from ..models import Alert, AlertEvent, AuditLog, Evidence, User
from ..utils import audit, redirect_to, render

logger = logging.getLogger("sentriq.admin_routes")

router = APIRouter()


@router.get("/admin/users/", response_class=HTMLResponse)
def user_admin(request: Request, user: UserDep, db: Session = Depends(get_db)):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    users = list(db.scalars(select(User).order_by(User.username)))
    return render(request, "admin/users.html", {"users": users, "error": None}, db, user)


@router.post("/admin/users/")
def user_create(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()],
    user: UserDep,
    db: Session = Depends(get_db),
    must_change_password: Annotated[bool, Form()] = False,
):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    username = username.strip()
    users = list(db.scalars(select(User).order_by(User.username)))
    if role not in ROLES:
        return render(request, "admin/users.html", {"users": users, "error": "Select a valid role."}, db, user)
    if len(username) < 2:
        return render(request, "admin/users.html", {"users": users, "error": "Username must be at least 2 characters."}, db, user)
    if len(username) > 80:
        return render(request, "admin/users.html", {"users": users, "error": "Username must be 80 characters or less."}, db, user)
    password_error = validate_password_strength(password)
    if password_error:
        return render(request, "admin/users.html", {"users": users, "error": password_error}, db, user)
    if db.scalar(select(User).where(User.username == username)):
        return render(request, "admin/users.html", {"users": users, "error": f"User {username} already exists."}, db, user)
    db.add(User(
        username=username,
        password_hash=hash_password(password),
        role=role,
        is_admin=role == "L3",
        must_change_password=must_change_password,
    ))
    audit(db, user, "user.created", f"Created user {username} with role {role}.", "user", username, request)
    db.commit()
    logger.info("User '%s' created with role %s by %s", username, role, user.username)
    return redirect_to("/admin/users/", f"Created user {username}.")


@router.post("/admin/users/{user_id}/role/")
def user_role_update(
    request: Request,
    user_id: int,
    role: Annotated[str, Form()],
    user: UserDep,
    db: Session = Depends(get_db),
):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404)
    if role not in ROLES:
        return redirect_to("/admin/users/", "Select a valid role.")
    if target.id == user.id and role != "L3":
        return redirect_to("/admin/users/", "You cannot demote your active admin account.")
    target.role = role
    target.is_admin = role == "L3"
    audit(db, user, "user.role_updated", f"Updated {target.username} to {role}.", "user", target.id, request)
    db.commit()
    logger.info("User '%s' role updated to %s by %s", target.username, role, user.username)
    return redirect_to("/admin/users/", f"Updated {target.username} to {role}.")


@router.post("/admin/users/{user_id}/password/")
def user_password_reset(
    request: Request,
    user_id: int,
    password: Annotated[str, Form()],
    user: UserDep,
    db: Session = Depends(get_db),
):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404)
    password_error = validate_password_strength(password)
    if password_error:
        return redirect_to("/admin/users/", password_error)
    target.password_hash = hash_password(password)
    target.must_change_password = True
    audit(db, user, "user.password_reset", f"Reset password for {target.username}.", "user", target.id, request)
    db.commit()
    logger.info("Password reset for '%s' by %s", target.username, user.username)
    return redirect_to("/admin/users/", f"Reset password for {target.username}.")


@router.post("/admin/users/{user_id}/active/")
def user_set_active(
    request: Request,
    user_id: int,
    is_active: Annotated[str, Form()],
    user: UserDep,
    db: Session = Depends(get_db),
):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404)
    activate = is_active == "true"
    if not activate and target.id == user.id:
        return redirect_to("/admin/users/", "You cannot deactivate your own account.")
    if not activate and target.is_admin:
        remaining = db.scalar(
            select(func.count(User.id)).where(
                User.is_admin.is_(True), User.is_active.is_(True), User.id != target.id
            )
        )
        if not remaining:
            return redirect_to("/admin/users/", "At least one active administrator is required.")
    target.is_active = activate
    audit(
        db, user,
        "user.activated" if activate else "user.deactivated",
        f"{'Activated' if activate else 'Deactivated'} {target.username}.",
        "user", target.username, request,
    )
    db.commit()
    logger.info("User '%s' %s by %s", target.username, "activated" if activate else "deactivated", user.username)
    return redirect_to("/admin/users/", f"{'Activated' if activate else 'Deactivated'} {target.username}.")


@router.post("/admin/users/{user_id}/delete/")
def user_delete(
    request: Request,
    user_id: int,
    user: UserDep,
    db: Session = Depends(get_db),
):
    """Remove an account that never touched a ticket.

    SQLite here does not enforce foreign keys, so deleting a user who worked
    tickets would not fail loudly — it would blank "Created by"/"Assigned to" on
    their alerts and orphan their audit rows. Refuse instead and point at
    deactivation, which keeps attribution intact.
    """
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404)
    if target.id == user.id:
        return redirect_to("/admin/users/", "You cannot delete your own account.")
    if target.is_admin:
        remaining = db.scalar(
            select(func.count(User.id)).where(
                User.is_admin.is_(True), User.is_active.is_(True), User.id != target.id
            )
        )
        if not remaining:
            return redirect_to("/admin/users/", "At least one active administrator is required.")

    history = user_history(db, target)
    if history["total"]:
        return redirect_to(
            "/admin/users/",
            f"Cannot delete {target.username}: {describe_history(history)} reference this account. "
            "Deactivate it instead so tickets and the audit trail keep their attribution.",
        )

    audit(db, user, "user.deleted", f"Deleted user {target.username}.", "user", target.username, request)
    db.delete(target)
    db.commit()
    logger.info("User '%s' deleted by %s", target.username, user.username)
    return redirect_to("/admin/users/", f"Deleted user {target.username}.")


def user_history(db: Session, target: User) -> dict[str, int]:
    """Count everything that points at this account."""
    alerts = db.scalar(select(func.count(Alert.id)).where(or_(
        Alert.created_by_id == target.id,
        Alert.assigned_to_id == target.id,
        Alert.assigned_by_id == target.id,
        Alert.updated_by_id == target.id,
        Alert.escalated_by_id == target.id,
    ))) or 0
    events = db.scalar(select(func.count(AlertEvent.id)).where(or_(
        AlertEvent.actor_id == target.id,
        AlertEvent.assigned_to_id == target.id,
        AlertEvent.assigned_from_id == target.id,
    ))) or 0
    evidence = db.scalar(select(func.count(Evidence.id)).where(Evidence.uploaded_by_id == target.id)) or 0
    logs = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.actor_id == target.id)) or 0
    counts = {"alerts": alerts, "events": events, "evidence": evidence, "audit": logs}
    counts["total"] = sum(counts.values())
    return counts


def describe_history(history: dict[str, int]) -> str:
    labels = (
        ("alerts", "ticket", "tickets"),
        ("events", "timeline event", "timeline events"),
        ("evidence", "evidence file", "evidence files"),
        ("audit", "audit entry", "audit entries"),
    )
    parts = [
        f"{history[key]} {singular if history[key] == 1 else plural}"
        for key, singular, plural in labels
        if history[key]
    ]
    return ", ".join(parts)


@router.get("/admin/audit/", response_class=HTMLResponse)
def audit_log_page(request: Request, user: UserDep, db: Session = Depends(get_db)):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    logs = list(db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)))
    return render(request, "admin/audit.html", {"logs": logs}, db, user)
