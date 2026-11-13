"""Authentication routes (login, logout)."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user, hash_password, signer, session_stamp, validate_password_strength, verify_password, UserDep
from ..config import COOKIE_SECURE, LOGIN_LOCKOUT_SECONDS, SESSION_TTL_SECONDS
from ..dependencies import get_db
from ..middleware import clear_failed_logins, is_login_locked, record_failed_login
from ..models import AuditLog, User
from ..net import client_ip
from ..utils import audit, flash, redirect_to, render

logger = logging.getLogger("soc_tracker.auth_routes")

router = APIRouter()


@router.get("/login/", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    return render(request, "registration/login.html", {"error": None}, db)


@router.post("/login/")
async def login(request: Request, username: Annotated[str, Form()], password: Annotated[str, Form()], db: Session = Depends(get_db)):
    source_ip = client_ip(request)

    # Lockout is scoped to this (address, username) pair plus the account itself,
    # so one analyst's failed attempts cannot lock the whole team out behind a proxy.
    if is_login_locked(source_ip, username):
        logger.warning("Login lockout triggered for '%s' from %s", username, source_ip)
        response = render(request, "registration/login.html", {"error": "Too many failed attempts. Try again later."}, db, None)
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
        response.headers["Retry-After"] = str(LOGIN_LOCKOUT_SECONDS)
        return response

    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.password_hash):
        record_failed_login(source_ip, username)
        db.add(AuditLog(
            actor=user,
            action="auth.login_failed",
            message=f"Failed login attempt for '{username}'.",
            target_type="user",
            target_id=username,
            source_ip=source_ip,
        ))
        db.commit()
        logger.info("Failed login attempt for '%s' from %s", username, source_ip)
        return render(request, "registration/login.html", {"error": "Invalid username or password."}, db)

    # Clear only this pair's counters on success.
    clear_failed_logins(source_ip, username)
    response = redirect_to("/")
    response.set_cookie(
        "session",
        signer.dumps({"user_id": user.id, "session_stamp": session_stamp(user)}),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
    )
    db.add(AuditLog(
        actor=user,
        action="auth.login",
        message=f"{user.username} logged in.",
        target_type="user",
        target_id=user.username,
        source_ip=source_ip,
    ))
    db.commit()
    logger.info("User '%s' logged in from %s", user.username, source_ip)
    return response


@router.post("/logout/")
async def logout():
    response = redirect_to("/login/")
    response.delete_cookie("session")
    return response


@router.get("/account/password/", response_class=HTMLResponse)
async def password_page(request: Request, user: UserDep, db: Session = Depends(get_db)):
    return render(request, "account/password.html", {"error": None}, db, user)


@router.post("/account/password/")
async def password_change(
    request: Request,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    confirm_password: Annotated[str, Form()],
    user: UserDep,
    db: Session = Depends(get_db),
):
    if not verify_password(current_password, user.password_hash):
        return render(request, "account/password.html", {"error": "Current password is incorrect."}, db, user)
    error = validate_password_strength(new_password)
    if error:
        return render(request, "account/password.html", {"error": error}, db, user)
    if new_password != confirm_password:
        return render(request, "account/password.html", {"error": "New passwords do not match."}, db, user)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    audit(db, user, "auth.password_changed", f"{user.username} changed their password.", "user", user.username, request)
    db.commit()
    response = redirect_to("/login/", "Password changed. Sign in with your new password.")
    response.delete_cookie("session")
    return response
