"""Prometheus metrics for /metrics.

Per-process request counters (Prometheus sums them across workers) plus gauges
read from the database and the backup directory on each scrape, so the numbers
that matter for a SOC — backlog, overdue tickets, breach history, backup age —
are all in one place.
"""

import threading
import time
from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import SEVERITIES, STATUSES, WEB_CONCURRENCY
from ..limiter import store_kind
from ..models import Alert, AuditLog, Evidence, SlaBreach, User
from . import backup_status

_lock = threading.Lock()
_requests: Counter = Counter()
_duration_sum = 0.0
_duration_count = 0
_started_at = time.time()

STATUS_BUCKETS = ("2xx", "3xx", "4xx", "5xx")


def record_request(method: str, status_code: int, seconds: float) -> None:
    global _duration_sum, _duration_count
    bucket = f"{status_code // 100}xx" if 200 <= status_code < 600 else "other"
    with _lock:
        _requests[(method, bucket)] += 1
        _duration_sum += seconds
        _duration_count += 1


def reset() -> None:
    """Clear counters (used by tests)."""
    global _duration_sum, _duration_count
    with _lock:
        _requests.clear()
        _duration_sum = 0.0
        _duration_count = 0


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _line(name: str, labels: dict | None, value) -> str:
    if labels:
        rendered = ",".join(f'{key}="{_escape(val)}"' for key, val in labels.items())
        return f"{name}{{{rendered}}} {value}"
    return f"{name} {value}"


def render(db: Session) -> str:
    """Render the current metrics in Prometheus text exposition format."""
    lines: list[str] = []

    def metric(name: str, kind: str, help_text: str) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")

    with _lock:
        request_snapshot = dict(_requests)
        duration_sum = _duration_sum
        duration_count = _duration_count

    metric("soc_requests_total", "counter", "HTTP requests handled, by method and status class")
    for (method, bucket), count in sorted(request_snapshot.items()):
        lines.append(_line("soc_requests_total", {"method": method, "status": bucket}, count))

    metric("soc_request_duration_seconds_sum", "counter", "Total time spent handling requests")
    lines.append(_line("soc_request_duration_seconds_sum", None, round(duration_sum, 6)))
    metric("soc_request_duration_seconds_count", "counter", "Requests timed")
    lines.append(_line("soc_request_duration_seconds_count", None, duration_count))

    metric("soc_process_uptime_seconds", "gauge", "Seconds since this process started")
    lines.append(_line("soc_process_uptime_seconds", None, round(time.time() - _started_at, 1)))

    metric("soc_workers_configured", "gauge", "WEB_CONCURRENCY the process was started with")
    lines.append(_line("soc_workers_configured", None, WEB_CONCURRENCY))

    metric("soc_limiter_store", "gauge", "1 when rate limiting uses the named shared store")
    kind = store_kind()
    for candidate in ("memory", "redis"):
        lines.append(_line("soc_limiter_store", {"kind": candidate}, 1 if kind == candidate else 0))

    metric("soc_alerts", "gauge", "Tickets by status")
    by_status = dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
    for status in STATUSES:
        lines.append(_line("soc_alerts", {"status": status}, by_status.get(status, 0)))

    metric("soc_alerts_by_severity", "gauge", "Tickets by severity")
    by_severity = dict(db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all())
    for severity in SEVERITIES:
        lines.append(_line("soc_alerts_by_severity", {"severity": severity}, by_severity.get(severity, 0)))

    metric("soc_alerts_total", "gauge", "All tickets")
    lines.append(_line("soc_alerts_total", None, db.scalar(select(func.count()).select_from(Alert)) or 0))

    metric("soc_unassigned_alerts", "gauge", "Open tickets nobody owns")
    lines.append(_line("soc_unassigned_alerts", None, db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.assigned_to_id.is_(None), Alert.status != "Closed"
        )
    ) or 0))

    metric("soc_sla_breaches", "gauge", "SLA breaches by state")
    breaches = db.execute(
        select(SlaBreach.resolved_at.is_(None), func.count()).group_by(SlaBreach.resolved_at.is_(None))
    ).all()
    totals = {is_open: count for is_open, count in breaches}
    lines.append(_line("soc_sla_breaches", {"state": "open"}, totals.get(True, 0)))
    lines.append(_line("soc_sla_breaches", {"state": "resolved"}, totals.get(False, 0)))

    metric("soc_evidence_files", "gauge", "Stored evidence files")
    lines.append(_line("soc_evidence_files", None, db.scalar(select(func.count()).select_from(Evidence)) or 0))
    metric("soc_evidence_bytes", "gauge", "Total evidence size on disk")
    lines.append(_line("soc_evidence_bytes", None, db.scalar(select(func.coalesce(func.sum(Evidence.size_bytes), 0))) or 0))

    metric("soc_users", "gauge", "Accounts by state")
    active = db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))) or 0
    total_users = db.scalar(select(func.count()).select_from(User)) or 0
    lines.append(_line("soc_users", {"state": "active"}, active))
    lines.append(_line("soc_users", {"state": "inactive"}, total_users - active))

    metric("soc_audit_records", "gauge", "Audit rows retained")
    lines.append(_line("soc_audit_records", None, db.scalar(select(func.count()).select_from(AuditLog)) or 0))

    backup = backup_status.status()
    metric("soc_backup_age_seconds", "gauge", "Age of the newest data snapshot")
    lines.append(_line("soc_backup_age_seconds", None, backup["age_seconds"] if backup["age_seconds"] is not None else -1))
    metric("soc_backup_snapshots", "gauge", "Snapshots present in the backup directory")
    lines.append(_line("soc_backup_snapshots", None, backup["count"]))
    metric("soc_backup_stale", "gauge", "1 when the newest snapshot is older than the threshold")
    lines.append(_line("soc_backup_stale", None, 1 if backup["stale"] else 0))

    return "\n".join(lines) + "\n"
