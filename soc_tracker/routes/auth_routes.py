"""Authentication routes (login, logout)."""

import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user, hash_password, signer, session_stamp, verify_password
from ..config import COOKIE_SECURE, LOGIN_LOCKOUT_SECONDS, LOGIN_LOCKOUT_THRESHOLD, SESSION_TTL_SECONDS
from ..dependencies import get_db
from ..middleware import failed_logins
from ..models import AuditLog, User
from ..utils import flash, redirect_to, render

logger = logging.getLogger("soc_tracker.auth_routes")

router = APIRouter()


@router.get("/login/", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    return render(request, "registration/login.html", {"error": None}, db)


@router.post("/login/")
async def login(request: Request, username: Annotated[str, Form()], password: Annotated[str, Form()], db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"

    # Login lockout check
    now = time.monotonic()
    attempts = failed_logins[client_ip]
    attempts[:] = [t for t in attempts if now - t < LOGIN_LOCKOUT_SECONDS]
    if len(attempts) >= LOGIN_LOCKOUT_THRESHOLD:
        logger.warning("Login lockout triggered for %s", client_ip)
        return render(request, "registration/login.html", {"error": "Too many failed attempts. Try again later."}, db, None)

    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.password_hash):
        failed_logins[client_ip].append(now)
        db.add(AuditLog(
            actor=user,
            action="auth.login_failed",
            message=f"Failed login attempt for '{username}'.",
            target_type="user",
            target_id=username,
            source_ip=client_ip,
        ))
        db.commit()
        logger.info("Failed login attempt for '%s' from %s", username, client_ip)
        return render(request, "registration/login.html", {"error": "Invalid username or password."}, db)

    # Clear failed attempts on success
    failed_logins.pop(client_ip, None)
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
        source_ip=client_ip,
    ))
    db.commit()
    logger.info("User '%s' logged in from %s", user.username, client_ip)
    return response


@router.post("/logout/")
async def logout():
    response = redirect_to("/login/")
    response.delete_cookie("session")
    return response
