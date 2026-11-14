"""Utility functions for rendering, CSRF, flash messages, and auditing."""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from fastapi import Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status

from .auth import (
    can_create_alert,
    can_delete_alert,
    can_manage_users,
    signer,
    user_role,
)
from .config import BASE_DIR, COOKIE_SECURE, DISPLAY_TIMEZONE, ROLES, SEVERITIES, SEVERITY_LABELS, STATUSES
from .models import AuditLog, User
from .net import client_ip
from .services.alert_service import sla_status

logger = logging.getLogger("soc_tracker.utils")

templates = Jinja2Templates(directory=BASE_DIR / "templates")
DISPLAY_TZ = ZoneInfo(DISPLAY_TIMEZONE)


def to_local(value, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Render a stored UTC timestamp in the team's timezone.

    Timestamps are written to SQLite as naive UTC (``datetime.now(timezone.utc)``
    into a DateTime column), so a naive value is treated as UTC before the
    conversion. Without this every timeline and audit row is off by the zone
    offset — 6h30m for Asia/Yangon.
    """
    if value is None or value == "":
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(DISPLAY_TZ).strftime(fmt)


def timezone_label() -> str:
    """Human label for the display zone, e.g. 'Asia/Yangon (UTC+06:30)'."""
    offset = datetime.now(DISPLAY_TZ).utcoffset() or timedelta(0)
    total = int(offset.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"{DISPLAY_TIMEZONE} (UTC{sign}{total // 3600:02d}:{total % 3600 // 60:02d})"


templates.env.filters["localdt"] = to_local


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
        "severity_labels": SEVERITY_LABELS,
        "roles": ROLES,
        "sla_status": sla_status,
        "display_timezone": timezone_label(),
        "csrf_token": csrf_token_for(request),
        "date_from": request.query_params.get("from", ""),
        "date_to": request.query_params.get("to", ""),
    }


def render(request: Request, template: str, context: dict, db: Session, user: User | None = None) -> HTMLResponse:
    """Render template with base context and security cookies."""
    base = base_context(request, user, db)
    response = templates.TemplateResponse(request, template, {**base, **context})
    response.delete_cookie("flash")
    set_security_cookies(response, request, base["csrf_token"])
    return response


def is_partial_request(request: Request) -> bool:
    """True when the browser asked for the results fragment instead of a page.

    Filtering used to submit a GET form, which reloaded the whole page and
    scrolled back to the top. The list and dashboard now answer the same URL with
    just the results markup when this header is present.
    """
    return request.headers.get("x-partial") == "1"


def is_local_path(path: str) -> bool:
    """True for a same-site absolute path.

    Redirect targets that come from a form field have to be checked: ``//evil.example``
    is a protocol-relative URL, not a local path.
    """
    return bool(path) and path.startswith("/") and not path.startswith("//") and "\\" not in path


def page_url(request: Request, page: int) -> str:
    """Current URL with the page number replaced, other filters preserved."""
    params = [(key, value) for key, value in request.query_params.multi_items() if key != "page"]
    params.append(("page", str(page)))
    return f"{request.url.path}?{urlencode(params)}"


def redirect_to(path: str, message: str | None = None) -> RedirectResponse:
    """Create redirect response with optional flash message."""
    response = RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)
    if message:
        flash(response, message)
    return response


def audit(db: Session, actor: User | None, action: str, message: str, target_type: str = "", target_id: str = "", request: Request | None = None) -> None:
    """Add audit log entry."""
    source_ip = client_ip(request) if request else ""
    db.add(AuditLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        message=message,
        source_ip=source_ip,
    ))
    logger.info("Audit: %s - %s", action, message)
