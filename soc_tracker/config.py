"""Application configuration from environment variables."""

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "evidence"
SQLITE_PATH = os.environ.get("SQLITE_PATH", str(DATA_DIR / "fastapi.sqlite3"))
Path(SQLITE_PATH).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
APP_ENV = os.environ.get("APP_ENV", "development").lower()
N8N_API_KEY = os.environ.get("N8N_API_KEY") or (None if APP_ENV == "production" else secrets.token_urlsafe(32))
N8N_API_HEADER = os.environ.get("N8N_API_HEADER", "X-API-Key")
SECRET_KEY = os.environ.get("APP_SECRET_KEY") or (None if APP_ENV == "production" else secrets.token_hex(32))
if APP_ENV == "production" and (not N8N_API_KEY or len(N8N_API_KEY) < 32 or not SECRET_KEY or len(SECRET_KEY) < 32):
    raise RuntimeError("Production requires APP_SECRET_KEY and N8N_API_KEY of at least 32 characters.")
SECRET_KEY = SECRET_KEY or "development-only-secret"
N8N_API_KEY = N8N_API_KEY or "development-only-api-key"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1" if APP_ENV == "production" else "0") == "1"
if APP_ENV == "production" and not COOKIE_SECURE:
    raise RuntimeError("Production requires COOKIE_SECURE=1 and an HTTPS reverse proxy.")
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "28800"))
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "120"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(25 * 1024 * 1024)))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
ALLOWED_EVIDENCE_EXTENSIONS = {".xlsx", ".csv", ".jpg", ".jpeg", ".png", ".txt", ".log", ".json", ".pdf", ".pcap", ".pcapng"}

STATUSES = ["Open", "Pending", "WIP", "Closed"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
ROLES = ["L1", "L2", "L3"]
ALEMBIC_HEAD = "0003_ticket_numbers_and_workflow"

LOGIN_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
