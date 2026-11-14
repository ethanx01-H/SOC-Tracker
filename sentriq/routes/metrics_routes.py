"""Prometheus scrape endpoint.

Not a public page: without METRICS_TOKEN it answers on loopback only, which
suits a sidecar scraper on the same host. With a token it answers any caller
that presents ``Authorization: Bearer <token>``.
"""

import hmac
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from ..config import METRICS_TOKEN
from ..dependencies import get_db
from ..net import client_ip
from ..services import metrics

logger = logging.getLogger("sentriq.metrics_routes")

router = APIRouter()

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _authorised(request: Request) -> bool:
    if METRICS_TOKEN:
        provided = request.headers.get("authorization", "")
        expected = f"Bearer {METRICS_TOKEN}"
        return hmac.compare_digest(provided.encode(), expected.encode())
    return client_ip(request) in LOOPBACK


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(request: Request, db: Session = Depends(get_db)):
    if not _authorised(request):
        logger.warning("Rejected metrics scrape from %s", client_ip(request))
        return JSONResponse({"ok": False, "error": "metrics are not public"}, status_code=403)
    return PlainTextResponse(
        metrics.render(db),
        media_type="text/plain; version=0.0.4; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )
