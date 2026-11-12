"""SOC Alert Tracker - FastAPI Application Entry Point.

A lightweight, self-hosted security operations alert tracker with role-based
alert management, Elastic SIEM integration, and n8n workflow automation.
"""

import logging
import os
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect

from soc_tracker.config import ALEMBIC_HEAD, BASE_DIR, SQLITE_PATH
from soc_tracker.middleware import security_middleware
from soc_tracker.models import Base, engine
from soc_tracker.routes import auth_routes, alert_routes, admin_routes, evidence_routes, webhook_routes

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
app.include_router(webhook_routes.router)


@app.get("/healthz", include_in_schema=False)
def healthz():
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return {"status": "ok"}
    except Exception:
        logger.exception("Health check failed")
        return JSONResponse({"status": "unavailable"}, status_code=503)


def run_migrations() -> None:
    """Run database migrations or create tables."""
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError:
        Base.metadata.create_all(bind=engine)
        return

    config = Config(str(BASE_DIR / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{SQLITE_PATH}")
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
        command.stamp(config, "head")
        return
    command.upgrade(config, "head")


@app.on_event("startup")
def startup() -> None:
    """Initialize database in development only; deployment migrates before serving."""
    logger.info("Starting SOC Alert Tracker...")
    if os.environ.get("APP_ENV", "development").lower() != "production":
        run_migrations()
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
