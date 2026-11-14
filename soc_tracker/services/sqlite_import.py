"""One-way import of a SQLite SOC Tracker database into Postgres.

The application runs on Postgres only, so an installation that still has its
data in ``fastapi.sqlite3`` has to be moved across once. Three things need care:
the table order, the self-reference on ``fastapi_alerts.duplicate_of_id``, and
the type differences SQLite papers over - it stores booleans as 0/1 and
timestamps as text, which Postgres will not accept.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path

from sqlalchemy import Boolean, DateTime, create_engine, inspect, text

TABLES = [
    "fastapi_users",
    "fastapi_alerts",
    "fastapi_alert_events",
    "fastapi_evidence",
    "fastapi_audit_logs",
    "fastapi_sla_breaches",
]


def _coerce(value, column_type):
    if value is None:
        return None
    if isinstance(column_type, Boolean):
        return bool(value)
    if isinstance(column_type, DateTime) and isinstance(value, str):
        return dt.datetime.fromisoformat(value)
    return value


def import_sqlite(sqlite_path: str | Path, database_url: str, progress=print) -> dict[str, int]:
    """Copy every row of a SQLite database into an empty Postgres database.

    Refuses to touch a Postgres database that already has tickets, because a
    half-imported database is worse than no import at all.
    """
    source_path = Path(sqlite_path)
    if not source_path.exists():
        raise RuntimeError(f"no SQLite database at {source_path}")

    engine = create_engine(database_url)
    inspector = inspect(engine)
    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    counts: dict[str, int] = {}

    try:
        with engine.begin() as connection:
            existing = connection.execute(text("select count(*) from fastapi_alerts")).scalar() or 0
            if existing:
                raise RuntimeError(
                    f"the target database already has {existing} tickets; import into an empty database"
                )

            for table in TABLES:
                types = {column["name"]: column["type"] for column in inspector.get_columns(table)}
                rows = [
                    {name: _coerce(row[name], types[name]) for name in row.keys()}
                    for row in source.execute(f"select * from {table}")
                ]
                counts[table] = len(rows)
                if not rows:
                    progress(f"{table:24s} 0 rows")
                    continue

                # The self-reference cannot be satisfied while the rows go in.
                deferred = []
                if table == "fastapi_alerts":
                    deferred = [(row["id"], row["duplicate_of_id"]) for row in rows if row["duplicate_of_id"]]
                    for row in rows:
                        row["duplicate_of_id"] = None

                columns = ", ".join(rows[0])
                placeholders = ", ".join(f":{name}" for name in rows[0])
                connection.execute(text(f"insert into {table} ({columns}) values ({placeholders})"), rows)

                for alert_id, duplicate_of in deferred:
                    connection.execute(
                        text("update fastapi_alerts set duplicate_of_id = :dup where id = :id"),
                        {"dup": duplicate_of, "id": alert_id},
                    )
                progress(f"{table:24s} {len(rows):>4} rows")

            # Identity columns kept their values, so move the sequences past them.
            for table in TABLES:
                connection.execute(
                    text(
                        f"select setval(pg_get_serial_sequence('{table}', 'id'), "
                        f"coalesce((select max(id) from {table}), 1))"
                    )
                )
    finally:
        source.close()
        engine.dispose()

    return counts
