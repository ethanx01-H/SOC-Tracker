#!/bin/sh
set -eu

DATA_DIR=${DATA_DIR:-/app/data}
BACKUP_DIR=${BACKUP_DIR:-/app/backups}

# Snapshot the data before anything else touches it. This runs before the app
# serves traffic, so the database and its WAL file are captured consistently.
if [ -n "${DATABASE_URL:-}" ]; then
    # Postgres: pg_dump writes soc-pg-<stamp>.dump. If the client is missing the
    # script says so and exits 0 - the database host's own backups still count.
    if [ -f /app/scripts/backup-postgres.sh ]; then
        sh /app/scripts/backup-postgres.sh "$BACKUP_DIR" "${BACKUP_KEEP:-20}" "${BACKUP_MIN_INTERVAL:-300}" \
            || echo "WARNING: Postgres snapshot failed, starting anyway" >&2
    fi
else
    if [ -f /app/scripts/backup.sh ]; then
        sh /app/scripts/backup.sh "$DATA_DIR" "$BACKUP_DIR" "${BACKUP_KEEP:-20}" "${BACKUP_MIN_INTERVAL:-300}" \
            || echo "WARNING: data snapshot failed, starting anyway" >&2
    fi

    # Loud warning if the database is missing but snapshots exist: this is what a
    # mistyped `docker compose down -v` used to look like.
    if [ ! -f "$DATA_DIR/fastapi.sqlite3" ] && ls "$BACKUP_DIR"/soc-data-*.tar.gz >/dev/null 2>&1; then
        echo "WARNING: no database in $DATA_DIR, but snapshots exist in $BACKUP_DIR." >&2
        echo "WARNING: restore one before using this instance:" >&2
        echo "WARNING:   sh scripts/restore-data.sh <snapshot> $DATA_DIR --force" >&2
    fi
fi

alembic upgrade head
exec gunicorn main:app \
  --bind 0.0.0.0:8080 \
  --workers "${WEB_CONCURRENCY:-4}" \
  --worker-class uvicorn.workers.UvicornWorker \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
