"""Authentication routes (login, logout)."""

import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import current_user, hash_password, signer, verify_password
from ..config import COOKIE_SECURE, LOGIN_LOCKOUT_SECONDS, LOGIN_LOCKOUT_THRESHOLD
from ..middleware import failed_logins
from ..models import AuditLog, User
from ..utils import base_context, flash, redirect_to, render

logger = logging.getLogger("soc_tracker.auth_routes")

router = APIRouter()


def get_db():
    from ..models import SessionLocal
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


@router.get("/login/", response_class=HTMLResponse)
async def login_page(request: Request, db: DbSession):
    return render(request, "registration/login.html", {"error": None}, db)


@router.post("/login/")
async def login(request: Request, db: DbSession, username: Annotated[str, Form()], password: Annotated[str, Form()]):
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
        signer.dumps({"user_id": user.id}),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=28800,
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
