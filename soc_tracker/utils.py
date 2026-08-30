"""Utility functions for rendering, CSRF, flash messages, and auditing."""

import logging
import secrets
from typing import Optional

from fastapi import Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status

from .auth import (
    can_create_alert,
    can_delete_alert,
    can_manage_users,
    csrf_token_for,
    set_security_cookies,
    signer,
    user_role,
)
from .config import BASE_DIR, COOKIE_SECURE, ROLES, SEVERITIES, STATUSES
from .models import AuditLog, User
from .services.alert_service import sla_status

logger = logging.getLogger("soc_tracker.utils")

templates = Jinja2Templates(directory=BASE_DIR / "templates")


def csrf_token_for(request: Request) -> str:
    """Get or generate CSRF token."""
    token = request.cookies.get("csrf_token")
    return token if token else secrets.token_urlsafe(32)


def set_security_cookies(response: Response, request: Request, csrf_token: str | None = None) -> None:
    """Set CSRF and security cookies on response."""
    token = csrf_token or csrf_token_for(request)
    response.set_cookie("csrf_token", token, httponly=True, secure=COOKIE_SECURE, samesite="lax")


def flash(response: Response, message: str) -> None:
    """Set flash message cookie."""
    response.set_cookie("flash", signer.dumps(message), httponly=True, secure=COOKIE_SECURE, samesite="lax")


def base_context(request: Request, user: User | None, db: Session) -> dict:
    """Build base template context with common variables."""
    message = None
    raw = request.cookies.get("flash")
    if raw:
        try:
            message = signer.loads(raw)
        except Exception:
            message = None
    return {
        "request": request,
        "current_user": user,
        "current_role": user_role(user) if user else None,
        "can_create_alert": can_create_alert(user) if user else False,
        "can_delete_alert": can_delete_alert(user) if user else False,
        "can_manage_users": can_manage_users(user) if user else False,
        "messages": [message] if message else [],
        "statuses": STATUSES,
        "severities": SEVERITIES,
        "roles": ROLES,
        "sla_status": sla_status,
        "csrf_token": csrf_token_for(request),
    }


def render(request: Request, template: str, context: dict, db: Session, user: User | None = None) -> HTMLResponse:
    """Render template with base context and security cookies."""
    base = base_context(request, user, db)
    response = templates.TemplateResponse(request, template, {**base, **context})
    response.delete_cookie("flash")
    set_security_cookies(response, request, base["csrf_token"])
    return response


def redirect_to(path: str, message: str | None = None) -> RedirectResponse:
    """Create redirect response with optional flash message."""
    response = RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)
    if message:
        flash(response, message)
    return response


def audit(db: Session, actor: User | None, action: str, message: str, target_type: str = "", target_id: str = "", request: Request | None = None) -> None:
    """Add audit log entry."""
    source_ip = request.client.host if request and request.client else ""
    db.add(AuditLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        message=message,
        source_ip=source_ip,
    ))
    logger.info("Audit: %s - %s", action, message)
