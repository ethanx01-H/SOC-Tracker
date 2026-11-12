"""Security middleware for rate limiting, CSRF protection, and security headers."""

import logging
import re
import time
from collections import defaultdict, deque
from urllib.parse import parse_qs

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .config import COOKIE_SECURE, MAX_REQUEST_BYTES, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW

logger = logging.getLogger("soc_tracker.middleware")

rate_limits: dict[str, deque[float]] = defaultdict(deque)
failed_logins: dict[str, list[float]] = defaultdict(list)


async def security_middleware(request: Request, call_next):
    """Combined middleware for rate limiting, CSRF, and security headers."""
    now = time.monotonic()
    client_ip = request.client.host if request.client else "unknown"

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse({"ok": False, "error": "request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"ok": False, "error": "invalid content length"}, status_code=400)

    # Rate limiting
    attempts = rate_limits[client_ip]
    while attempts and now - attempts[0] > RATE_LIMIT_WINDOW:
        attempts.popleft()
    if len(attempts) >= RATE_LIMIT_REQUESTS:
        logger.warning("Rate limit exceeded for %s", client_ip)
        return JSONResponse({"ok": False, "error": "rate limit exceeded"}, status_code=429)
    attempts.append(now)
    # Bound memory use when clients rotate source addresses.
    if len(rate_limits) > 10000:
        for key in list(rate_limits)[:2000]:
            rate_limits.pop(key, None)
    if len(failed_logins) > 10000:
        for key in list(failed_logins)[:2000]:
            failed_logins.pop(key, None)

    # CSRF check — skip only for webhook API endpoints
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.url.path.startswith("/api/webhook"):
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
            logger.warning("CSRF token mismatch from %s on %s", client_ip, request.url.path)
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
