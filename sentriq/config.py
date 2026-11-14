"""Application configuration from environment variables."""

import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

from .dburl import normalise_database_url

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "evidence"

DATABASE_URL = normalise_database_url((os.environ.get("DATABASE_URL") or "").strip())
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is required. Sentriq runs on Postgres only: set "
        "DATABASE_URL=postgresql://user:password@host:5432/sentriq in the "
        "environment or in .env."
    )
if not DATABASE_URL.startswith("postgresql"):
    raise RuntimeError(
        "DATABASE_URL must be a Postgres URL, got "
        f"{DATABASE_URL.split(':', 1)[0]}://... (SQLite is not supported.)"
    )
DB_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "10"))
DB_POOL_MAX_OVERFLOW = int(os.environ.get("DB_POOL_MAX_OVERFLOW", "20"))
WEB_CONCURRENCY = int(os.environ.get("WEB_CONCURRENCY", "1"))
APP_ENV = os.environ.get("APP_ENV", "development").lower()
SECRET_KEY = os.environ.get("APP_SECRET_KEY") or (None if APP_ENV == "production" else secrets.token_hex(32))
if APP_ENV == "production" and (not SECRET_KEY or len(SECRET_KEY) < 32):
    raise RuntimeError("Production requires APP_SECRET_KEY of at least 32 characters.")
SECRET_KEY = SECRET_KEY or "development-only-secret"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1" if APP_ENV == "production" else "0") == "1"
if APP_ENV == "production" and not COOKIE_SECURE:
    raise RuntimeError("Production requires COOKIE_SECURE=1 and an HTTPS reverse proxy.")
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "28800"))
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "120"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_EXEMPT_PATHS = ("/healthz", "/metrics")
RATE_LIMIT_EXEMPT_PREFIXES = ("/static/",)
# Only these peers may speak for the client through X-Forwarded-For / X-Real-IP.
TRUSTED_PROXIES = tuple(
    entry.strip()
    for entry in os.environ.get("TRUSTED_PROXIES", "127.0.0.1/32,::1/128").split(",")
    if entry.strip()
)
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", str(25 * 1024 * 1024)))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(6 * 1024 * 1024)))
ALLOWED_EVIDENCE_EXTENSIONS = {".xlsx", ".csv", ".jpg", ".jpeg", ".png", ".txt", ".log", ".json", ".pdf", ".pcap", ".pcapng"}

STATUSES = ["Open", "Pending", "WIP", "Closed"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_LABELS = {
    "Critical": "0 - Critical",
    "High": "1 - High",
    "Medium": "2 - Medium",
    "Low": "3 - Low",
    "Informational": "4 - Informational",
}
ROLES = ["L1", "L2", "L3"]
# Timestamps are stored in UTC and rendered in this zone for analysts.
DISPLAY_TIMEZONE = os.environ.get("DISPLAY_TIMEZONE", "Asia/Yangon")
ALEMBIC_HEAD = "0009_retention_sla_merge"

LOGIN_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_ACCOUNT_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_ACCOUNT_LOCKOUT_THRESHOLD", "10"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))

# Shared limiter/lockout store. Without it, counters live in each worker's
# memory, so N workers multiply every limit by N and a lockout only applies to
# the worker that saw the failed attempt.
REDIS_URL = os.environ.get("REDIS_URL") or None

# Retention and archival. The README promises 730 days; the job enforces it.
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "730"))
ARCHIVE_DIR = Path(os.environ.get("ARCHIVE_DIR", str(DATA_DIR / "archive")))
AUDIT_EXPORT_DIR = Path(os.environ.get("AUDIT_EXPORT_DIR", str(DATA_DIR / "audit-exports")))
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", str(BASE_DIR / "backups")))
# A snapshot older than this makes /healthz report degraded.
BACKUP_MAX_AGE_HOURS = int(os.environ.get("BACKUP_MAX_AGE_HOURS", "36"))
# Bearer token for /metrics. Unset means /metrics only answers on loopback.
METRICS_TOKEN = os.environ.get("METRICS_TOKEN") or None

# Outbound notifications. Both channels stay inert until they are configured.
SMTP_HOST = os.environ.get("SMTP_HOST") or None
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER") or None
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD") or None
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "1") == "1"
NOTIFY_EMAIL_FROM = os.environ.get("NOTIFY_EMAIL_FROM") or SMTP_USER
NOTIFY_EMAIL_TO = tuple(
    entry.strip() for entry in os.environ.get("NOTIFY_EMAIL_TO", "").split(",") if entry.strip()
)
NOTIFY_TEAMS_WEBHOOK = os.environ.get("NOTIFY_TEAMS_WEBHOOK") or None
NOTIFY_ON_ASSIGN = os.environ.get("NOTIFY_ON_ASSIGN", "1") == "1"
NOTIFY_ON_ESCALATE = os.environ.get("NOTIFY_ON_ESCALATE", "1") == "1"
# New tickets notify only at this severity or above.
NOTIFY_MIN_SEVERITY = os.environ.get("NOTIFY_MIN_SEVERITY", "High")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL") or ""

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
