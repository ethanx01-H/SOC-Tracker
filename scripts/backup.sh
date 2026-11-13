#!/bin/sh
# Consistent snapshot of the SOC Tracker data directory.
#
# Usage: backup.sh [data-dir] [backup-dir] [keep] [min-interval-seconds]
#
# The database is copied with SQLite's online backup API, so this is safe to run
# while the app is serving traffic (unlike copying the .sqlite3 file next to its
# -wal). The copy is integrity-checked before it is kept. Evidence files are
# tarred alongside it, and the result is a single archive that restore-data.sh
# can unpack.
set -eu

DATA_DIR=${1:-/app/data}
BACKUP_DIR=${2:-/app/backups}
KEEP=${3:-20}
MIN_INTERVAL=${4:-300}
DB_NAME=fastapi.sqlite3

if [ ! -f "$DATA_DIR/$DB_NAME" ]; then
    echo "backup: no database in $DATA_DIR, nothing to snapshot"
    exit 0
fi

mkdir -p "$BACKUP_DIR"

newest=$(ls -1t "$BACKUP_DIR"/soc-data-*.tar.gz 2>/dev/null | head -n 1 || true)
if [ -n "$newest" ]; then
    age=$(( $(date +%s) - $(date -r "$newest" +%s) ))
    if [ "$age" -lt "$MIN_INTERVAL" ]; then
        echo "backup: $newest is ${age}s old, skipping"
        exit 0
    fi
fi

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/data"

python3 - "$DATA_DIR/$DB_NAME" "$staging/data/$DB_NAME" <<'PY'
import sqlite3
import sys

source = sqlite3.connect(sys.argv[1])
target = sqlite3.connect(sys.argv[2])
with target:
    source.backup(target)
status = target.execute("PRAGMA quick_check").fetchone()[0]
target.close()
source.close()
if status != "ok":
    raise SystemExit(f"backup: integrity check failed: {status}")
PY

if [ -d "$DATA_DIR/evidence" ]; then
    cp -a "$DATA_DIR/evidence" "$staging/data/evidence"
fi

stamp=$(date +%Y%m%d-%H%M%S)
target="$BACKUP_DIR/soc-data-$stamp.tar.gz"
tar czf "$target" -C "$staging/data" .
echo "backup: wrote $target ($(wc -c < "$target") bytes)"

ls -1t "$BACKUP_DIR"/soc-data-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old"
    echo "backup: pruned $old"
done

exit 0
