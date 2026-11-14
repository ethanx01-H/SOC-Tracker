#!/bin/sh
# Snapshot a Postgres-backed Sentriq database with pg_dump.
#
# Usage: backup-postgres.sh [backup-dir] [keep] [min-interval-seconds]
#
# Reads DATABASE_URL. The SQLAlchemy driver suffix (+psycopg) is stripped
# because pg_dump speaks the plain libpq connection string. The dump is written
# to a temporary name and renamed only after pg_restore can read it, so a failed
# dump never looks like a usable snapshot.
set -eu

BACKUP_DIR=${1:-/app/backups}
KEEP=${2:-20}
MIN_INTERVAL=${3:-300}

if [ -z "${DATABASE_URL:-}" ]; then
    echo "backup-postgres: DATABASE_URL is empty, nothing to dump"
    exit 0
fi

if ! command -v pg_dump >/dev/null 2>&1; then
    echo "backup-postgres: pg_dump not installed, no snapshot taken." >&2
    echo "backup-postgres: install the Postgres client, or back this database up on its host." >&2
    exit 0
fi

url=$(printf '%s' "$DATABASE_URL" | sed 's/^postgresql+psycopg2*:/postgresql:/; s/^postgres+psycopg2*:/postgresql:/')

mkdir -p "$BACKUP_DIR"

newest=$(ls -1t "$BACKUP_DIR"/sentriq-pg-*.dump 2>/dev/null | head -n 1 || true)
if [ -n "$newest" ]; then
    age=$(( $(date +%s) - $(date -r "$newest" +%s) ))
    if [ "$age" -lt "$MIN_INTERVAL" ]; then
        echo "backup-postgres: $newest is ${age}s old, skipping"
        exit 0
    fi
fi

stamp=$(date -u +%Y%m%d-%H%M%S)
target="$BACKUP_DIR/sentriq-pg-$stamp.dump"
partial="$target.part"

if ! pg_dump --format=custom --no-owner --no-privileges --file="$partial" "$url"; then
    rm -f "$partial"
    echo "backup-postgres: pg_dump failed, no snapshot kept" >&2
    exit 1
fi

if command -v pg_restore >/dev/null 2>&1; then
    if ! pg_restore --list "$partial" >/dev/null 2>&1; then
        rm -f "$partial"
        echo "backup-postgres: dump did not verify, no snapshot kept" >&2
        exit 1
    fi
fi

mv "$partial" "$target"
echo "backup-postgres: wrote $target"

# Keep the newest $KEEP dumps.
count=$(ls -1 "$BACKUP_DIR"/sentriq-pg-*.dump 2>/dev/null | wc -l | tr -d ' ')
if [ "$count" -gt "$KEEP" ]; then
    ls -1t "$BACKUP_DIR"/sentriq-pg-*.dump | tail -n "+$((KEEP + 1))" | while read -r old; do
        rm -f "$old"
        echo "backup-postgres: removed $old"
    done
fi
