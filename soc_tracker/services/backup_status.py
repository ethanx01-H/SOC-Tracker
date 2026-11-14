"""Backup freshness, for /healthz and /metrics.

The snapshot scripts write ``soc-data-<stamp>.tar.gz`` for SQLite and
``soc-pg-<stamp>.dump`` for Postgres; nothing used to check that they kept doing
so, which is how a backup job dies quietly for a month. This module is the
check: newest snapshot, its age, and whether that age crosses the configured
threshold.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from ..config import BACKUP_DIR, BACKUP_MAX_AGE_HOURS, DATABASE_URL

logger = logging.getLogger("soc_tracker.backup")


PATTERNS = ("soc-data-*.tar.gz", "soc-pg-*.dump")


def database_mode() -> str:
    """Which snapshot format this instance should be producing."""
    return "postgres" if DATABASE_URL else "sqlite"


def snapshots(directory: Path | None = None) -> list[Path]:
    folder = Path(directory or BACKUP_DIR)
    if not folder.is_dir():
        return []
    found = [path for pattern in PATTERNS for path in folder.glob(pattern)]
    return sorted(found, key=lambda path: path.stat().st_mtime, reverse=True)


def status(directory: Path | None = None, max_age_hours: int = BACKUP_MAX_AGE_HOURS) -> dict:
    items = snapshots(directory)
    if not items:
        return {
            "count": 0,
            "newest": None,
            "age_seconds": None,
            "size_bytes": 0,
            "max_age_hours": max_age_hours,
            "stale": True,
            "directory": str(Path(directory or BACKUP_DIR)),
            "mode": database_mode(),
        }

    newest = items[0]
    info = newest.stat()
    taken = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc)
    age_seconds = max(0.0, (datetime.now(timezone.utc) - taken).total_seconds())
    return {
        "count": len(items),
        "newest": newest.name,
        "age_seconds": round(age_seconds, 1),
        "size_bytes": info.st_size,
        "max_age_hours": max_age_hours,
        "stale": age_seconds > max_age_hours * 3600,
        "directory": str(newest.parent),
        "mode": database_mode(),
    }


def warn_if_stale(directory: Path | None = None) -> None:
    """Log once at startup so a broken backup job shows up in the logs."""
    info = status(directory)
    if info["count"] == 0 and info["mode"] == "postgres":
        logger.warning(
            "No Postgres snapshot (soc-pg-*.dump) in %s. Run scripts/backup-postgres.sh, "
            "or back the database up on its own host.",
            info["directory"],
        )
    elif info["count"] == 0:
        logger.warning("No data snapshot found in %s; nothing has been backed up yet.", info["directory"])
    elif info["stale"]:
        logger.warning(
            "Newest data snapshot %s is %.1f hours old (threshold %s h). Check the backup job.",
            info["newest"], info["age_seconds"] / 3600, info["max_age_hours"],
        )
    else:
        logger.info(
            "Newest data snapshot %s is %.1f hours old.",
            info["newest"], info["age_seconds"] / 3600,
        )
