"""Application configuration from environment variables."""

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "evidence"
SQLITE_PATH = os.environ.get("SQLITE_PATH", str(DATA_DIR / "fastapi.sqlite3"))
N8N_API_KEY = os.environ.get("N8N_API_KEY") or secrets.token_urlsafe(32)
N8N_API_HEADER = os.environ.get("N8N_API_HEADER", "X-API-Key")
SECRET_KEY = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "120"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
ALLOWED_EVIDENCE_EXTENSIONS = {".txt", ".log", ".json", ".csv", ".png", ".jpg", ".jpeg", ".pdf", ".pcap", ".pcapng"}

STATUSES = ["New", "Triage", "Investigating", "Escalated", "Contained", "Closed"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
ROLES = ["L1", "L2", "L3"]
ALEMBIC_HEAD = "0002_add_evidence_audit"

LOGIN_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
