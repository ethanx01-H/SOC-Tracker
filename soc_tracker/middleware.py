"""Security middleware for rate limiting, CSRF protection, and security headers."""

import logging
import re
import time
from collections import defaultdict, deque
from urllib.parse import parse_qs

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .config import (
    COOKIE_SECURE,
    LOGIN_ACCOUNT_LOCKOUT_THRESHOLD,
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_LOCKOUT_THRESHOLD,
    MAX_REQUEST_BYTES,
    RATE_LIMIT_EXEMPT_PATHS,
    RATE_LIMIT_EXEMPT_PREFIXES,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW,
)
from .net import client_ip

logger = logging.getLogger("soc_tracker.middleware")

rate_limits: dict[str, deque[float]] = defaultdict(deque)
# Keyed by "ip|username": a shared NAT or proxy address must not let one
# analyst's typos lock the rest of the team out.
failed_logins: dict[str, list[float]] = defaultdict(list)
# Keyed by username alone: stops a distributed spray that rotates addresses.
account_failures: dict[str, list[float]] = defaultdict(list)


def _username_key(username: str) -> str:
    return (username or "").strip().lower()


def _pair_key(client_address: str, username: str) -> str:
    return f"{client_address}|{_username_key(username)}"


def _prune(bucket: dict[str, list[float]], key: str, now: float, window: int) -> list[float]:
    entries = bucket[key]
    if entries:
        entries[:] = [stamp for stamp in entries if now - stamp < window]
    return entries


def is_login_locked(client_address: str, username: str, now: float | None = None) -> bool:
    """True when this (address, username) pair or the account itself is locked out."""
    now = time.monotonic() if now is None else now
    per_pair = _prune(failed_logins, _pair_key(client_address, username), now, LOGIN_LOCKOUT_SECONDS)
    per_account = _prune(account_failures, _username_key(username), now, LOGIN_LOCKOUT_SECONDS)
    return len(per_pair) >= LOGIN_LOCKOUT_THRESHOLD or len(per_account) >= LOGIN_ACCOUNT_LOCKOUT_THRESHOLD


def record_failed_login(client_address: str, username: str, now: float | None = None) -> None:
    now = time.monotonic() if now is None else now
    failed_logins[_pair_key(client_address, username)].append(now)
    account_failures[_username_key(username)].append(now)
    _bound_lockout_memory()


def clear_failed_logins(client_address: str, username: str) -> None:
    """Clear only this pair's counters after a successful login.

    Clearing the whole address bucket (the previous behaviour) let one valid
    login wipe the protection for every other account behind the same proxy.
    """
    failed_logins.pop(_pair_key(client_address, username), None)
    account_failures.pop(_username_key(username), None)


def _bound_lockout_memory() -> None:
    if len(failed_logins) > 10000:
        for key in list(failed_logins)[:2000]:
            failed_logins.pop(key, None)
    if len(account_failures) > 10000:
        for key in list(account_failures)[:2000]:
            account_failures.pop(key, None)


def reset_security_state() -> None:
    """Drop all in-process limiter and lockout state (used by tests)."""
    rate_limits.clear()
    failed_logins.clear()
    account_failures.clear()


def _is_rate_limit_exempt(path: str) -> bool:
    return path in RATE_LIMIT_EXEMPT_PATHS or path.startswith(RATE_LIMIT_EXEMPT_PREFIXES)


async def security_middleware(request: Request, call_next):
    """Combined middleware for rate limiting, CSRF, and security headers."""
    now = time.monotonic()
    client_address = client_ip(request)
    path = request.url.path

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse({"ok": False, "error": "request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"ok": False, "error": "invalid content length"}, status_code=400)

    # Rate limiting. Health checks and static assets are excluded: the container
    # healthcheck must never 429 itself, and one page view pulls several assets.
    if not _is_rate_limit_exempt(path):
        attempts = rate_limits[client_address]
        while attempts and now - attempts[0] > RATE_LIMIT_WINDOW:
            attempts.popleft()
        if len(attempts) >= RATE_LIMIT_REQUESTS:
            logger.warning("Rate limit exceeded for %s on %s", client_address, path)
            return JSONResponse(
                {"ok": False, "error": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
            )
        attempts.append(now)
        # Bound memory use when clients rotate source addresses.
        if len(rate_limits) > 10000:
            for key in list(rate_limits)[:2000]:
                rate_limits.pop(key, None)
    _bound_lockout_memory()

    # CSRF check — skip only for webhook API endpoints
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not path.startswith("/api/webhook"):
        cookie_token = request.cookies.get("csrf_token")
        header_token = request.headers.get("X-CSRF-Token")
        form_token = None
        content_type = request.headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            body = await _read_bounded_body(request)
            if body is None:
                return JSONResponse({"ok": False, "error": "request body too large"}, status_code=413)
            parsed = parse_qs(body.decode("utf-8", errors="ignore"))
            values = parsed.get("csrf_token", [])
            form_token = values[0] if values else None
        elif "multipart/form-data" in content_type:
            body = await _read_bounded_body(request)
            if body is None:
                return JSONResponse({"ok": False, "error": "request body too large"}, status_code=413)
            match = re.search(rb'name="csrf_token"\r\n\r\n([^\r\n]+)', body)
            form_token = match.group(1).decode("utf-8", errors="ignore") if match else None

        if content_type and ("application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type):
            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = receive

        if not cookie_token or (header_token or form_token) != cookie_token:
            logger.warning("CSRF token mismatch from %s on %s", client_address, path)
            return JSONResponse({"ok": False, "error": "invalid csrf token"}, status_code=403)

    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:"
    )
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if "server" in response.headers:
        del response.headers["server"]

    return response


async def _read_bounded_body(request: Request) -> bytes | None:
    """Read a form body under the configured cap and make it available to the route."""
    parts = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            return None
        parts.append(chunk)
    body = b"".join(parts)
    request._body = body

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request._receive = receive
    return body
