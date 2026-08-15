import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from hashlib import pbkdf2_hmac
from pathlib import Path
from typing import Annotated
from urllib.parse import parse_qs, urlencode

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, func, inspect, or_, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from alerts.elastic import parse_elastic_alerts, record_to_alert, records_from


BASE_DIR = Path(__file__).resolve().parent
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

DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
engine = create_engine(f"sqlite:///{SQLITE_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
signer = URLSafeSerializer(SECRET_KEY, salt="soc-alert-tracker")
rate_limits: dict[str, deque[float]] = defaultdict(deque)
failed_logins: dict[str, list[float]] = defaultdict(list)
LOGIN_LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))

app = FastAPI(title="SOC Alert Tracker")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    now = time.monotonic()
    client_ip = request.client.host if request.client else "unknown"
    attempts = rate_limits[client_ip]
    while attempts and now - attempts[0] > RATE_LIMIT_WINDOW:
        attempts.popleft()
    if len(attempts) >= RATE_LIMIT_REQUESTS:
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
            return JSONResponse({"ok": False, "error": "invalid csrf token"}, status_code=403)

    response = await call_next(request)
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:"
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if "server" in response.headers:
        del response.headers["server"]
    return response


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "fastapi_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(220))
    role: Mapped[str] = mapped_column(String(2), default="L1")
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

    def __str__(self) -> str:
        return self.username


class Alert(Base):
    __tablename__ = "fastapi_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(80), default="Manual")
    severity: Mapped[str] = mapped_column(String(10), default="Medium")
    status: Mapped[str] = mapped_column(String(20), default="New")
    analyst: Mapped[str] = mapped_column(String(80), default="Unassigned")
    tactic: Mapped[str] = mapped_column(String(100), default="Unknown")
    asset: Mapped[str] = mapped_column(String(160), default="Unknown")
    iocs_json: Mapped[str] = mapped_column(Text, default="[]")
    sla_hours: Mapped[int] = mapped_column(Integer, default=8)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    assigned_by_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    escalated_by_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    assigned_to: Mapped[User | None] = relationship(foreign_keys=[assigned_to_id])
    assigned_by: Mapped[User | None] = relationship(foreign_keys=[assigned_by_id])
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_id])
    updated_by: Mapped[User | None] = relationship(foreign_keys=[updated_by_id])
    escalated_by: Mapped[User | None] = relationship(foreign_keys=[escalated_by_id])
    events: Mapped[list["AlertEvent"]] = relationship(back_populates="alert", cascade="all, delete-orphan", order_by="desc(AlertEvent.created_at)")

    @property
    def iocs(self) -> list[str]:
        try:
            value = json.loads(self.iocs_json or "[]")
            return value if isinstance(value, list) else []
        except json.JSONDecodeError:
            return []

    @iocs.setter
    def iocs(self, value: list[str]) -> None:
        self.iocs_json = json.dumps(value or [])

    @property
    def pk(self) -> int:
        return self.id

    def get_absolute_url(self) -> str:
        return f"/alerts/{self.id}/"


class AlertEvent(Base):
    __tablename__ = "fastapi_alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("fastapi_alerts.id"))
    event_type: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    assigned_from_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="tracker")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert: Mapped[Alert] = relationship(back_populates="events")
    actor: Mapped[User | None] = relationship(foreign_keys=[actor_id])
    assigned_from: Mapped[User | None] = relationship(foreign_keys=[assigned_from_id])
    assigned_to: Mapped[User | None] = relationship(foreign_keys=[assigned_to_id])

    @property
    def event_type_display(self) -> str:
        return self.event_type.replace("_", " ").title()


class Evidence(Base):
    __tablename__ = "fastapi_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("fastapi_alerts.id"))
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255), unique=True)
    content_type: Mapped[str] = mapped_column(String(120), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert: Mapped[Alert] = relationship()
    uploaded_by: Mapped[User | None] = relationship()


class AuditLog(Base):
    __tablename__ = "fastapi_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("fastapi_users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    target_type: Mapped[str] = mapped_column(String(80), default="")
    target_id: Mapped[str] = mapped_column(String(80), default="")
    message: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    actor: Mapped[User | None] = relationship()


async def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, salt, digest = stored_hash.split("$", 2)
    except ValueError:
        return False
    return secrets.compare_digest(hash_password(password, salt), f"pbkdf2_sha256${salt}${digest}")


def validate_password_strength(password: str) -> str | None:
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include an uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include a lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include a number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include a symbol."
    return None


def bootstrap_users(db: Session) -> None:
    for username, role, is_admin in [("l1", "L1", False), ("l2", "L2", False), ("admin_l3", "L3", True)]:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            db.add(User(username=username, password_hash=hash_password("password123"), role=role, is_admin=is_admin))
        else:
            user.role = role
            user.is_admin = is_admin
    db.commit()


def seed_sample_alerts(db: Session) -> None:
    if db.scalar(select(func.count(Alert.id))) > 0:
        return

    l1 = db.scalar(select(User).where(User.username == "l1"))
    l2 = db.scalar(select(User).where(User.username == "l2"))
    samples = [
        {
            "title": "Suspicious VPN login from new country",
            "description": "Successful VPN login for a finance user from a country not previously seen for this account. MFA succeeded, but the source IP has poor reputation.",
            "source": "Elastic",
            "severity": "High",
            "status": "Triage",
            "analyst": "l1",
            "tactic": "Initial Access",
            "asset": "finance.user@example.local",
            "iocs": ["198.51.100.77", "finance.user@example.local"],
            "sla_hours": 4,
            "created_by": l1,
            "updated_by": l1,
            "assigned_to": l1,
            "assigned_by": l1,
        },
        {
            "title": "Encoded PowerShell launched from Downloads",
            "description": "EDR detected an encoded PowerShell command launched from a user Downloads directory. The host should be isolated if follow-up telemetry confirms credential access.",
            "source": "Elastic EDR",
            "severity": "Critical",
            "status": "Escalated",
            "analyst": "l2",
            "tactic": "Execution",
            "asset": "WIN-ENG-044",
            "iocs": ["powershell.exe", "-EncodedCommand", "WIN-ENG-044"],
            "sla_hours": 2,
            "created_by": l1,
            "updated_by": l2,
            "escalated_by": l1,
            "assigned_to": l2,
            "assigned_by": l2,
        },
        {
            "title": "DNS tunneling pattern to new domain",
            "description": "Firewall analytics found high-entropy DNS queries to a newly registered domain from a workstation subnet.",
            "source": "Firewall",
            "severity": "Medium",
            "status": "Investigating",
            "analyst": "l1",
            "tactic": "Command and Control",
            "asset": "10.32.14.88",
            "iocs": ["updates-cdn-check.example", "10.32.14.88"],
            "sla_hours": 8,
            "created_by": l1,
            "updated_by": l1,
            "assigned_to": l1,
            "assigned_by": l2,
        },
        {
            "title": "Quarantined phishing payload",
            "description": "Email gateway quarantined a phishing message with a blocked HTML attachment before delivery to the accounts payable mailbox.",
            "source": "Email Gateway",
            "severity": "Low",
            "status": "Closed",
            "analyst": "l1",
            "tactic": "Initial Access",
            "asset": "mailbox:ap@company.local",
            "iocs": ["invoice_review.html", "185.199.110.153"],
            "sla_hours": 24,
            "created_by": l1,
            "updated_by": l1,
            "assigned_to": l1,
            "assigned_by": l2,
        },
    ]
    for sample in samples:
        alert = create_alert(db, sample)
        db.add(AlertEvent(alert=alert, event_type="assigned", actor=sample["assigned_by"], assigned_to=sample["assigned_to"], message=f"{sample['assigned_by'].username} assigned this alert to {sample['assigned_to'].username}.", source="seed"))
        db.commit()


def next_alert_id(db: Session) -> str:
    last_id = db.scalar(select(func.max(Alert.id))) or 0
    return f"SOC-{last_id + 1:06d}"


def create_alert(db: Session, values: dict, user: User | None = None) -> Alert:
    iocs = values.pop("iocs", None) or []
    actor = user or values.get("created_by")
    alert = Alert(alert_id=next_alert_id(db), **values)
    alert.iocs = iocs
    if user:
        alert.created_by = user
        alert.updated_by = user
        if alert.status == "Escalated":
            alert.escalated_by = user
    db.add(alert)
    db.flush()
    db.add(AlertEvent(alert=alert, event_type="created", actor=actor, message=f"{actor.username if actor else 'n8n'} created {alert.alert_id}."))
    db.commit()
    db.refresh(alert)
    return alert


def current_user(request: Request, db: Session) -> User | None:
    raw = request.cookies.get("session")
    if not raw:
        return None
    try:
        data = signer.loads(raw)
    except BadSignature:
        return None
    return db.get(User, data.get("user_id"))


async def require_user(request: Request, db: DbSession) -> User:
    user = current_user(request, db)
    if user:
        return user
    raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login/"})


UserDep = Annotated[User, Depends(require_user)]


def user_role(user: User) -> str:
    return "L3" if user.is_admin else user.role


def can_create_alert(user: User) -> bool:
    return user_role(user) in {"L1", "L2", "L3"}


def can_edit_alert(user: User, alert: Alert) -> bool:
    role = user_role(user)
    return role in {"L2", "L3"} or (role == "L1" and alert.status != "Escalated")


def can_delete_alert(user: User) -> bool:
    return user_role(user) == "L3"


def can_manage_users(user: User) -> bool:
    return user_role(user) == "L3"


def can_escalate_alert(user: User) -> bool:
    return user_role(user) in {"L1", "L2"}


def can_assign_alert(user: User) -> bool:
    return user_role(user) in {"L2", "L3"}


def assignable_roles_for(user: User) -> list[str]:
    role = user_role(user)
    if role == "L3":
        return ["L1", "L2"]
    if role == "L2":
        return ["L1"]
    return []


def audit(db: Session, actor: User | None, action: str, message: str, target_type: str = "", target_id: str = "", request: Request | None = None) -> None:
    source_ip = request.client.host if request and request.client else ""
    db.add(AuditLog(actor=actor, action=action, target_type=target_type, target_id=str(target_id), message=message, source_ip=source_ip))


def normalized_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def sla_status(alert: Alert) -> dict[str, str]:
    if alert.status == "Closed":
        return {"label": "Closed", "class": "sla-closed"}
    due_at = normalized_datetime(alert.created_at) + timedelta(hours=alert.sla_hours)
    remaining = due_at - datetime.now(timezone.utc)
    if remaining.total_seconds() < 0:
        return {"label": "Overdue", "class": "sla-overdue"}
    hours = max(1, int((remaining.total_seconds() + 3599) // 3600))
    if hours <= 2:
        return {"label": f"Due in {hours}h", "class": "sla-due-soon"}
    return {"label": f"Due in {hours}h", "class": "sla-ok"}


def csrf_token_for(request: Request) -> str:
    token = request.cookies.get("csrf_token")
    return token if token else secrets.token_urlsafe(32)


def set_security_cookies(response: Response, request: Request, csrf_token: str | None = None) -> None:
    token = csrf_token or csrf_token_for(request)
    response.set_cookie("csrf_token", token, httponly=True, secure=COOKIE_SECURE, samesite="lax")


def secure_upload_name(filename: str) -> str:
    name = Path(filename or "evidence.bin").name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")
    return name or "evidence.bin"


def flash(response: Response, message: str) -> None:
    response.set_cookie("flash", signer.dumps(message), httponly=True, secure=COOKIE_SECURE, samesite="lax")


def base_context(request: Request, user: User | None, db: Session) -> dict:
    message = None
    raw = request.cookies.get("flash")
    if raw:
        try:
            message = signer.loads(raw)
        except BadSignature:
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
        "roles": ROLES,
        "sla_status": sla_status,
        "csrf_token": csrf_token_for(request),
    }


def render(request: Request, template: str, context: dict, db: Session, user: User | None = None) -> HTMLResponse:
    base = base_context(request, user, db)
    response = templates.TemplateResponse(request, template, {**base, **context})
    response.delete_cookie("flash")
    set_security_cookies(response, request, base["csrf_token"])
    return response


def redirect_to(path: str, message: str | None = None) -> RedirectResponse:
    response = RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)
    if message:
        flash(response, message)
    return response


def filtered_alerts(db: Session, request: Request) -> list[Alert]:
    query = select(Alert).order_by(Alert.created_at.desc())
    search = (request.query_params.get("q") or "").strip()
    severity = request.query_params.get("severity") or ""
    alert_status = request.query_params.get("status") or ""
    source = request.query_params.get("source") or ""
    analyst = request.query_params.get("analyst") or ""
    sla = request.query_params.get("sla") or ""
    if search:
        like = f"%{search}%"
        evidence_alert_ids = select(Evidence.alert_id).where(Evidence.original_name.ilike(like))
        query = query.where(or_(
            Alert.alert_id.ilike(like),
            Alert.title.ilike(like),
            Alert.description.ilike(like),
            Alert.asset.ilike(like),
            Alert.source.ilike(like),
            Alert.analyst.ilike(like),
            Alert.iocs_json.ilike(like),
            Alert.events.any(AlertEvent.message.ilike(like)),
            Alert.id.in_(evidence_alert_ids),
        ))
    if severity:
        query = query.where(Alert.severity == severity)
    if alert_status:
        query = query.where(Alert.status == alert_status)
    if source:
        query = query.where(Alert.source == source)
    if analyst:
        query = query.where(Alert.analyst == analyst)
    alerts = list(db.scalars(query))
    if sla == "overdue":
        alerts = [alert for alert in alerts if sla_status(alert)["class"] == "sla-overdue"]
    elif sla == "closed":
        alerts = [alert for alert in alerts if alert.status == "Closed"]
    elif sla == "due-soon":
        alerts = [alert for alert in alerts if sla_status(alert)["class"] == "sla-due-soon"]
    elif sla == "on-track":
        alerts = [alert for alert in alerts if sla_status(alert)["class"] == "sla-ok"]
    return alerts


def pie_path(cx: int, cy: int, radius: int, start_angle: float, end_angle: float) -> str:
    if end_angle - start_angle >= 359.99:
        return (
            f"M {cx} {cy - radius} "
            f"A {radius} {radius} 0 1 1 {cx - 0.01} {cy - radius} "
            f"A {radius} {radius} 0 1 1 {cx} {cy - radius} Z"
        )
    start = math.radians(start_angle - 90)
    end = math.radians(end_angle - 90)
    x1 = cx + radius * math.cos(start)
    y1 = cy + radius * math.sin(start)
    x2 = cx + radius * math.cos(end)
    y2 = cy + radius * math.sin(end)
    large_arc = 1 if end_angle - start_angle > 180 else 0
    return f"M {cx} {cy} L {x1:.2f} {y1:.2f} A {radius} {radius} 0 {large_arc} 1 {x2:.2f} {y2:.2f} Z"


def chart_counts(alerts: list[Alert]) -> dict[str, dict[str, object]]:
    colors = ["#1f6feb", "#0f766e", "#b7791f", "#b42318", "#6f42c1", "#475569", "#0891b2", "#be123c"]

    def group(items: list[tuple[str, str]]) -> dict[str, object]:
        counts: dict[str, int] = {}
        hrefs: dict[str, str] = {}
        for label, href in items:
            label = label or "Unknown"
            counts[label] = counts.get(label, 0) + 1
            hrefs[label] = href
        total = sum(counts.values())
        start = 0.0
        slices = []
        for index, (label, count) in enumerate(sorted(counts.items())):
            end = start + (count / total * 360 if total else 0)
            slices.append({
                "label": label,
                "count": count,
                "percent": round(count / total * 100) if total else 0,
                "path": pie_path(50, 50, 46, start, end),
                "color": colors[index % len(colors)],
                "href": hrefs[label],
            })
            start = end
        return {"total": total, "slices": slices}

    def alerts_url(**params: str) -> str:
        return f"/alerts/?{urlencode({key: value for key, value in params.items() if value})}"

    return {
        "severity": group([(alert.severity, alerts_url(severity=alert.severity)) for alert in alerts]),
        "source": group([(alert.source, alerts_url(source=alert.source)) for alert in alerts]),
        "analyst": group([(alert.analyst, alerts_url(analyst=alert.analyst)) for alert in alerts]),
        "tactic": group([(alert.tactic, alerts_url(q=alert.tactic)) for alert in alerts]),
    }


def form_values(form: dict) -> dict:
    iocs_text = form.get("iocs_text", "")
    return {
        "title": form.get("title", "").strip(),
        "description": form.get("description", "").strip(),
        "source": form.get("source", "Manual").strip() or "Manual",
        "severity": form.get("severity", "Medium"),
        "status": form.get("status", "New"),
        "analyst": form.get("analyst", "Unassigned").strip() or "Unassigned",
        "tactic": form.get("tactic", "Unknown").strip() or "Unknown",
        "asset": form.get("asset", "Unknown").strip() or "Unknown",
        "iocs": [item.strip() for item in iocs_text.split(",") if item.strip()],
        "sla_hours": int(form.get("sla_hours") or 8),
    }


def run_migrations() -> None:
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
    run_migrations()
    with SessionLocal() as db:
        bootstrap_users(db)
        seed_sample_alerts(db)


@app.get("/login/", response_class=HTMLResponse)
async def login_page(request: Request, db: DbSession):
    return render(request, "registration/login.html", {"error": None}, db)


@app.post("/login/")
async def login(request: Request, db: DbSession, username: Annotated[str, Form()], password: Annotated[str, Form()]):
    client_ip = request.client.host if request.client else "unknown"

    # Login lockout check
    now = time.monotonic()
    attempts = failed_logins[client_ip]
    attempts[:] = [t for t in attempts if now - t < LOGIN_LOCKOUT_SECONDS]
    if len(attempts) >= LOGIN_LOCKOUT_THRESHOLD:
        return render(request, "registration/login.html", {"error": "Too many failed attempts. Try again later."}, db, None)

    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.password_hash):
        failed_logins[client_ip].append(now)
        audit(db, user, "auth.login_failed", f"Failed login attempt for '{username}'.", "user", username, request)
        db.commit()
        return render(request, "registration/login.html", {"error": "Invalid username or password."}, db)

    # Clear failed attempts on success
    failed_logins.pop(client_ip, None)
    response = redirect_to("/")
    response.set_cookie("session", signer.dumps({"user_id": user.id}), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=28800)
    audit(db, user, "auth.login", f"{user.username} logged in.", "user", user.username, request)
    db.commit()
    return response


@app.post("/logout/")
async def logout():
    response = redirect_to("/login/")
    response.delete_cookie("session")
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: DbSession, user: UserDep):
    alerts = filtered_alerts(db, request)
    counts = {
        "total": len(alerts),
        "open": len([alert for alert in alerts if alert.status != "Closed"]),
        "critical": len([alert for alert in alerts if alert.severity == "Critical"]),
        "escalated": len([alert for alert in alerts if alert.status == "Escalated"]),
        "overdue": len([alert for alert in alerts if sla_status(alert)["class"] == "sla-overdue"]),
    }
    return render(request, "alerts/dashboard.html", {"alerts": alerts[:80], "counts": counts, "charts": chart_counts(alerts)}, db, user)


@app.get("/alerts/", response_class=HTMLResponse)
async def alert_list(request: Request, db: DbSession, user: UserDep):
    return render(request, "alerts/list.html", {"alerts": filtered_alerts(db, request)}, db, user)


@app.get("/alerts/mine/", response_class=HTMLResponse)
async def my_alerts(request: Request, db: DbSession, user: UserDep):
    alerts = [
        alert for alert in filtered_alerts(db, request)
        if (alert.assigned_to_id == user.id or alert.analyst == user.username) and alert.status != "Closed"
    ]
    return render(request, "alerts/list.html", {"alerts": alerts, "page_title": "My assigned alerts", "page_eyebrow": "Work queue"}, db, user)


@app.get("/alerts/export.csv")
async def alert_export(request: Request, db: DbSession, user: UserDep):
    alerts = filtered_alerts(db, request)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["alert_id", "title", "severity", "status", "source", "analyst", "asset", "tactic", "sla_hours", "sla_status", "created_at", "updated_at"])
    for alert in alerts:
        writer.writerow([
            alert.alert_id,
            alert.title,
            alert.severity,
            alert.status,
            alert.source,
            alert.analyst,
            alert.asset,
            alert.tactic,
            alert.sla_hours,
            sla_status(alert)["label"],
            alert.created_at.isoformat(),
            alert.updated_at.isoformat(),
        ])
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc-alerts.csv"'},
    )


@app.get("/admin/users/", response_class=HTMLResponse)
async def user_admin(request: Request, db: DbSession, user: UserDep):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    users = list(db.scalars(select(User).order_by(User.username)))
    return render(request, "admin/users.html", {"users": users, "error": None}, db, user)


@app.post("/admin/users/")
async def user_create(
    request: Request,
    db: DbSession,
    user: UserDep,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()],
):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    username = username.strip()
    users = list(db.scalars(select(User).order_by(User.username)))
    if role not in ROLES:
        return render(request, "admin/users.html", {"users": users, "error": "Select a valid role."}, db, user)
    if len(username) < 2:
        return render(request, "admin/users.html", {"users": users, "error": "Username must be at least 2 characters."}, db, user)
    password_error = validate_password_strength(password)
    if password_error:
        return render(request, "admin/users.html", {"users": users, "error": password_error}, db, user)
    if db.scalar(select(User).where(User.username == username)):
        return render(request, "admin/users.html", {"users": users, "error": f"User {username} already exists."}, db, user)
    db.add(User(username=username, password_hash=hash_password(password), role=role, is_admin=role == "L3"))
    audit(db, user, "user.created", f"Created user {username} with role {role}.", "user", username, request)
    db.commit()
    return redirect_to("/admin/users/", f"Created user {username}.")


@app.post("/admin/users/{user_id}/role/")
async def user_role_update(
    request: Request,
    user_id: int,
    db: DbSession,
    user: UserDep,
    role: Annotated[str, Form()],
):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404)
    if role not in ROLES:
        return redirect_to("/admin/users/", "Select a valid role.")
    if target.id == user.id and role != "L3":
        return redirect_to("/admin/users/", "You cannot demote your active admin account.")
    target.role = role
    target.is_admin = role == "L3"
    audit(db, user, "user.role_updated", f"Updated {target.username} to {role}.", "user", target.id, request)
    db.commit()
    return redirect_to("/admin/users/", f"Updated {target.username} to {role}.")


@app.post("/admin/users/{user_id}/password/")
async def user_password_reset(
    request: Request,
    user_id: int,
    db: DbSession,
    user: UserDep,
    password: Annotated[str, Form()],
):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404)
    password_error = validate_password_strength(password)
    if password_error:
        return redirect_to("/admin/users/", password_error)
    target.password_hash = hash_password(password)
    audit(db, user, "user.password_reset", f"Reset password for {target.username}.", "user", target.id, request)
    db.commit()
    return redirect_to("/admin/users/", f"Reset password for {target.username}.")


@app.get("/admin/audit/", response_class=HTMLResponse)
async def audit_log_page(request: Request, db: DbSession, user: UserDep):
    if not can_manage_users(user):
        raise HTTPException(status_code=403)
    logs = list(db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)))
    return render(request, "admin/audit.html", {"logs": logs}, db, user)


@app.get("/alerts/new/", response_class=HTMLResponse)
async def alert_create_page(request: Request, db: DbSession, user: UserDep):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    return render(request, "alerts/form.html", {"title": "New alert", "alert": None, "form": {}}, db, user)


@app.post("/alerts/new/")
async def alert_create(request: Request, db: DbSession, user: UserDep):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    form = dict(await request.form())
    values = form_values(form)
    if not values["title"]:
        return render(request, "alerts/form.html", {"title": "New alert", "alert": None, "form": form, "error": "Title is required."}, db, user)
    alert = create_alert(db, values, user)
    audit(db, user, "alert.created", f"Created {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Created {alert.alert_id}.")


@app.get("/r/{alert_id}/")
async def alert_report(alert_id: str, db: DbSession, user: UserDep):
    alert = db.scalar(select(Alert).where(Alert.alert_id == alert_id))
    if not alert:
        raise HTTPException(status_code=404)
    return redirect_to(alert.get_absolute_url())


@app.get("/alerts/{pk}/", response_class=HTMLResponse)
async def alert_detail(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    assignable_users = list(db.scalars(select(User).where(User.role.in_(roles)).order_by(User.username))) if roles else []
    evidence = list(db.scalars(select(Evidence).where(Evidence.alert_id == alert.id).order_by(Evidence.created_at.desc())))
    return render(request, "alerts/detail.html", {
        "alert": alert,
        "can_edit": can_edit_alert(user, alert),
        "can_escalate": can_escalate_alert(user) and alert.status != "Escalated",
        "can_assign": can_assign_alert(user),
        "assignable_users": assignable_users,
        "evidence": evidence,
    }, db, user)


@app.get("/alerts/{pk}/edit/", response_class=HTMLResponse)
async def alert_edit_page(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    form = {
        "title": alert.title,
        "description": alert.description,
        "source": alert.source,
        "severity": alert.severity,
        "status": alert.status,
        "analyst": alert.analyst,
        "tactic": alert.tactic,
        "asset": alert.asset,
        "iocs_text": ", ".join(alert.iocs),
        "sla_hours": alert.sla_hours,
    }
    return render(request, "alerts/form.html", {"title": f"Edit {alert.alert_id}", "alert": alert, "form": form}, db, user)


@app.post("/alerts/{pk}/edit/")
async def alert_edit(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    old_status = alert.status
    form = dict(await request.form())
    values = form_values(form)
    if not values["title"]:
        return render(request, "alerts/form.html", {"title": f"Edit {alert.alert_id}", "alert": alert, "form": form, "error": "Title is required."}, db, user)
    if old_status != "Closed" and values["status"] == "Closed":
        return render(request, "alerts/form.html", {"title": f"Edit {alert.alert_id}", "alert": alert, "form": form, "error": "Use the close workflow to close an alert with a resolution summary."}, db, user)
    iocs = values.pop("iocs")
    for key, value in values.items():
        setattr(alert, key, value)
    alert.iocs = iocs
    alert.updated_by = user
    if old_status != "Escalated" and alert.status == "Escalated":
        alert.escalated_by = user
    db.add(AlertEvent(alert=alert, event_type="updated", actor=user, message=f"{user.username} updated {alert.alert_id}."))
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Updated {alert.alert_id}.")


@app.post("/alerts/{pk}/escalate/")
async def alert_escalate(pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_escalate_alert(user):
        raise HTTPException(status_code=403)
    alert.status = "Escalated"
    alert.escalated_by = user
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="escalated", actor=user, message=f"{user.username} escalated this alert."))
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Escalated {alert.alert_id}.")


@app.post("/alerts/{pk}/assign/")
async def alert_assign(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    roles = assignable_roles_for(user)
    if not roles:
        raise HTTPException(status_code=403)
    form = dict(await request.form())
    assigned_to = db.get(User, int(form.get("assigned_to") or 0))
    if not assigned_to or assigned_to.role not in roles:
        return redirect_to(alert.get_absolute_url(), "Select a valid analyst for your role.")
    previous_assignee = alert.assigned_to
    alert.assigned_to = assigned_to
    alert.assigned_by = user
    alert.analyst = assigned_to.username
    alert.status = "Investigating"
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="assigned", actor=user, assigned_from=previous_assignee, assigned_to=assigned_to, message=f"{user.username} assigned this alert to {assigned_to.username}."))
    audit(db, user, "alert.assigned", f"Assigned {alert.alert_id} to {assigned_to.username}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Assigned {alert.alert_id} to {assigned_to.username}.")


@app.post("/alerts/{pk}/notes/")
async def alert_note(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    form = dict(await request.form())
    note = form.get("note", "").strip()
    if not note:
        return redirect_to(alert.get_absolute_url(), "Note cannot be empty.")
    db.add(AlertEvent(alert=alert, event_type="note", actor=user, message=note))
    alert.updated_by = user
    db.commit()
    return redirect_to(alert.get_absolute_url(), "Added investigation note.")


@app.post("/alerts/{pk}/evidence/")
async def evidence_upload(
    request: Request,
    pk: int,
    db: DbSession,
    user: UserDep,
    evidence_file: Annotated[UploadFile, File()],
):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    original_name = secure_upload_name(evidence_file.filename or "evidence.bin")
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EVIDENCE_EXTENSIONS:
        return redirect_to(alert.get_absolute_url(), f"Evidence type {extension or '(none)'} is not allowed.")
    content = await evidence_file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        return redirect_to(alert.get_absolute_url(), "Evidence file is too large.")
    digest = hashlib.sha256(content).hexdigest()
    stored_name = f"{alert.alert_id}_{secrets.token_hex(8)}{extension}"
    path = UPLOAD_DIR / stored_name
    path.write_bytes(content)
    evidence = Evidence(
        alert=alert,
        uploaded_by=user,
        original_name=original_name,
        stored_name=stored_name,
        content_type=evidence_file.content_type or "application/octet-stream",
        size_bytes=len(content),
        sha256=digest,
    )
    db.add(evidence)
    db.add(AlertEvent(alert=alert, event_type="evidence", actor=user, message=f"Uploaded evidence {original_name}."))
    audit(db, user, "evidence.uploaded", f"Uploaded evidence {original_name} to {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), "Uploaded evidence.")


@app.get("/evidence/{evidence_id}/")
async def evidence_download(evidence_id: int, db: DbSession, user: UserDep):
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404)
    # Authorize: user must be able to view the parent alert
    alert = db.get(Alert, evidence.alert_id)
    if not alert:
        raise HTTPException(status_code=404)
    path = UPLOAD_DIR / evidence.stored_name
    if not path.exists():
        raise HTTPException(status_code=404)
    return Response(
        path.read_bytes(),
        media_type=evidence.content_type,
        headers={"Content-Disposition": f'attachment; filename="{evidence.original_name}"'},
    )


@app.post("/alerts/{pk}/close/")
async def alert_close(request: Request, pk: int, db: DbSession, user: UserDep):
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    if not can_edit_alert(user, alert):
        raise HTTPException(status_code=403)
    form = dict(await request.form())
    summary = form.get("resolution_summary", "").strip()
    if len(summary) < 20:
        return redirect_to(alert.get_absolute_url(), "Resolution summary must be at least 20 characters.")
    alert.status = "Closed"
    alert.updated_by = user
    db.add(AlertEvent(alert=alert, event_type="closed", actor=user, message=f"Resolution: {summary}"))
    audit(db, user, "alert.closed", f"Closed {alert.alert_id}.", "alert", alert.alert_id, request)
    db.commit()
    return redirect_to(alert.get_absolute_url(), f"Closed {alert.alert_id}.")


@app.post("/alerts/{pk}/delete/")
async def alert_delete(request: Request, pk: int, db: DbSession, user: UserDep):
    if not can_delete_alert(user):
        raise HTTPException(status_code=403)
    alert = db.get(Alert, pk)
    if not alert:
        raise HTTPException(status_code=404)
    alert_id = alert.alert_id
    audit(db, user, "alert.deleted", f"Deleted {alert_id}.", "alert", alert_id, request)
    db.delete(alert)
    db.commit()
    return redirect_to("/alerts/", f"Deleted {alert_id}.")


@app.get("/elastic/import/", response_class=HTMLResponse)
async def elastic_import_page(request: Request, db: DbSession, user: UserDep):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    return render(request, "alerts/elastic_import.html", {"raw_json": "", "error": None}, db, user)


@app.post("/elastic/import/")
async def elastic_import(request: Request, db: DbSession, user: UserDep, raw_json: Annotated[str, Form()]):
    if not can_create_alert(user):
        raise HTTPException(status_code=403)
    try:
        parsed = parse_elastic_alerts(raw_json)
    except json.JSONDecodeError as error:
        return render(request, "alerts/elastic_import.html", {"raw_json": raw_json, "error": f"Invalid JSON: {error}"}, db, user)
    created = [create_alert(db, dict(item), user) for item in parsed]
    return redirect_to("/alerts/", f"Imported {len(created)} Elastic alert(s).")


def api_key_valid(request: Request) -> bool:
    provided = request.headers.get(N8N_API_HEADER, "")
    return hmac.compare_digest(provided.encode(), N8N_API_KEY.encode())


@app.post("/api/webhook/n8n")
@app.post("/api/webhook/n8n/")
async def n8n_webhook(request: Request, db: DbSession):
    if not api_key_valid(request):
        return JSONResponse({"ok": False, "error": "invalid api key"}, status_code=401)
    try:
        payload = await request.json()
    except json.JSONDecodeError as error:
        return JSONResponse({"ok": False, "error": str(error)}, status_code=400)
    records = records_from(payload)
    if not records:
        return JSONResponse({"ok": False, "error": "no alert records found"}, status_code=400)
    created = []
    for record in records:
        alert = create_alert(db, record_to_alert(record))
        alert.events[0].source = "n8n"
        alert.events[0].payload_json = json.dumps(record)
        db.commit()
        created.append(alert)
    return {"ok": True, "created": [alert.alert_id for alert in created]}


@app.post("/api/webhook/n8n/logs")
@app.post("/api/webhook/n8n/logs/")
async def n8n_log_webhook(request: Request, db: DbSession):
    if not api_key_valid(request):
        return JSONResponse({"ok": False, "error": "invalid api key"}, status_code=401)
    try:
        payload = await request.json()
    except json.JSONDecodeError as error:
        return JSONResponse({"ok": False, "error": str(error)}, status_code=400)
    alert_id = payload.get("alert_id") or payload.get("alertId") or payload.get("alert", {}).get("id")
    alert = db.scalar(select(Alert).where(Alert.alert_id == alert_id))
    if not alert:
        raise HTTPException(status_code=404)
    message = payload.get("message") or payload.get("log") or payload.get("event") or "n8n workflow log received."
    event = AlertEvent(alert=alert, event_type="n8n_log", message=message, source="n8n", payload_json=json.dumps(payload))
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"ok": True, "event_id": event.id, "alert_id": alert.alert_id}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), reload=True, server_header=False)
