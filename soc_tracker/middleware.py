"""Security middleware for rate limiting, CSRF protection, and security headers."""

import logging
import re
import time
from collections import defaultdict, deque
from urllib.parse import parse_qs

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .config import COOKIE_SECURE, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW

logger = logging.getLogger("soc_tracker.middleware")

rate_limits: dict[str, deque[float]] = defaultdict(deque)
failed_logins: dict[str, list[float]] = defaultdict(list)


async def security_middleware(request: Request, call_next):
    """Combined middleware for rate limiting, CSRF, and security headers."""
    now = time.monotonic()
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    attempts = rate_limits[client_ip]
    while attempts and now - attempts[0] > RATE_LIMIT_WINDOW:
        attempts.popleft()
    if len(attempts) >= RATE_LIMIT_REQUESTS:
        logger.warning("Rate limit exceeded for %s", client_ip)
        return JSONResponse({"ok": False, "error": "rate limit exceeded"}, status_code=429)
    attempts.append(now)

    # CSRF check — skip only for webhook API endpoints
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.url.path.startswith("/api/webhook"):
        cookie_token = request.cookies.get("csrf_token")
        header_token = request.headers.get("X-CSRF-Token")
        form_token = None
        content_type = request.headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            body = await request.body()
            parsed = parse_qs(body.decode("utf-8", errors="ignore"))
            values = parsed.get("csrf_token", [])
            form_token = values[0] if values else None
        elif "multipart/form-data" in content_type:
            body = await request.body()
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
