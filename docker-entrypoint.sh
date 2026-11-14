#!/bin/sh
set -eu

BACKUP_DIR=${BACKUP_DIR:-/app/backups}

# Snapshot the database before anything else touches it. pg_dump writes
# soc-pg-<stamp>.dump; if the client is missing the script says so and exits 0,
# because the database host's own backups still count.
if [ -f /app/scripts/backup-postgres.sh ]; then
    sh /app/scripts/backup-postgres.sh "$BACKUP_DIR" "${BACKUP_KEEP:-20}" "${BACKUP_MIN_INTERVAL:-300}" \
        || echo "WARNING: Postgres snapshot failed, starting anyway" >&2
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL is not set. SOC Tracker runs on Postgres only." >&2
    echo "ERROR: set DATABASE_URL=postgresql://user:password@host:5432/soc_tracker" >&2
    exit 1
fi

alembic upgrade head
exec gunicorn main:app \
  --bind 0.0.0.0:8080 \
  --workers "${WEB_CONCURRENCY:-4}" \
  --worker-class uvicorn.workers.UvicornWorker \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
