"""SOC Alert Tracker - FastAPI Application Entry Point.

A lightweight, self-hosted security operations alert tracker with role-based
alert management, Elastic SIEM integration, and n8n workflow automation.
"""

import logging
import os
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect

from soc_tracker.config import ALEMBIC_HEAD, BASE_DIR, DATABASE_URL, DB_IS_SQLITE, SQLITE_PATH, WEB_CONCURRENCY
from soc_tracker.middleware import security_middleware
from soc_tracker.models import Base, engine
from soc_tracker.routes import auth_routes, alert_routes, admin_routes, evidence_routes, metrics_routes, webhook_routes
from soc_tracker.services import backup_status

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("soc_tracker")

# Create FastAPI app
app = FastAPI(title="SOC Alert Tracker")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# Add security middleware
app.middleware("http")(security_middleware)

# Include routers
app.include_router(auth_routes.router)
app.include_router(alert_routes.router)
app.include_router(admin_routes.router)
app.include_router(evidence_routes.router)
app.include_router(metrics_routes.router)
app.include_router(webhook_routes.router)


@app.exception_handler(RequestValidationError)
def handle_validation_error(request: Request, exc: RequestValidationError):
    """Keep the webhook contract: malformed JSON is a 400, not FastAPI's 422."""
    if request.url.path.startswith("/api/webhook"):
        return JSONResponse({"ok": False, "error": "invalid json body"}, status_code=400)
    return JSONResponse({"detail": exc.errors()}, status_code=422)


@app.get("/healthz", include_in_schema=False)
def healthz():
    """Liveness for the container, plus backup freshness for the operator.

    A stale snapshot does not fail the check — restarting the app would not fix
    a dead backup job, and a restart loop would only hide it. It reports
    ``degraded`` instead, and /metrics exposes the same age as a gauge to alert on.
    """
    backup = backup_status.status()
    payload = {
        "status": "ok",
        "database": "ok",
        "backup": {
            "count": backup["count"],
            "newest": backup["newest"],
            "age_hours": round((backup["age_seconds"] or 0) / 3600, 1),
            "stale": backup["stale"],
        },
    }
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
    except Exception:
        logger.exception("Health check failed")
        return JSONResponse({**payload, "status": "unavailable", "database": "down"}, status_code=503)
    if backup["stale"]:
        payload["status"] = "degraded"
    return payload


def run_migrations() -> None:
    """Run database migrations or create tables."""
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError:
        Base.metadata.create_all(bind=engine)
        return

    config = Config(str(BASE_DIR / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
    inspector = inspect(engine)
    has_app_tables = inspector.has_table("fastapi_users")
    has_version_table = inspector.has_table("alembic_version")
    if has_version_table:
        with engine.connect() as connection:
            current_revision = connection.exec_driver_sql("select version_num from alembic_version").scalar()
        if current_revision == ALEMBIC_HEAD:
            return
    if has_app_tables and not has_version_table:
        Base.metadata.create_all(bind=engine)
        command.stamp(config, "0002_add_evidence_audit")
    command.upgrade(config, "head")


@app.on_event("startup")
def startup() -> None:
    """Initialize database in development only; deployment migrates before serving."""
    logger.info("Starting SOC Alert Tracker...")
    if DB_IS_SQLITE and WEB_CONCURRENCY > 1:
        # SQLite serialises writers across the whole file; several worker
        # processes on one file turn that into lock timeouts, not parallelism.
        logger.warning(
            "WEB_CONCURRENCY=%s with SQLite: run one worker, or set DATABASE_URL to Postgres.",
            WEB_CONCURRENCY,
        )
    if DB_IS_SQLITE and os.environ.get("APP_ENV", "development").lower() == "production":
        logger.warning(
            "Production is running on SQLite at %s. Single host, single writer, no failover.",
            SQLITE_PATH,
        )
    if os.environ.get("APP_ENV", "development").lower() != "production":
        run_migrations()
    backup_status.warn_if_stale()
    logger.info("SOC Alert Tracker ready")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        reload=True,
        server_header=False,
    )
