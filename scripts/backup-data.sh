#!/bin/sh
# Take a timestamped snapshot of the SOC Tracker data directory.
#
# Usage: backup-data.sh [data-dir] [backup-dir] [keep] [min-interval-seconds]
#
# The snapshot is a plain tar.gz of the data directory, so it can be restored
# with tar alone even if this script is gone. The newest snapshot is reused when
# it is younger than min-interval, which keeps a crash-restart loop from filling
# the disk.
set -eu

DATA_DIR=${1:-/app/data}
BACKUP_DIR=${2:-/app/backups}
KEEP=${3:-20}
MIN_INTERVAL=${4:-300}

if [ ! -f "$DATA_DIR/fastapi.sqlite3" ]; then
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

stamp=$(date +%Y%m%d-%H%M%S)
target="$BACKUP_DIR/soc-data-$stamp.tar.gz"

# The app is not serving yet when this runs, so a plain tar is consistent:
# the database, its -wal/-shm companions and the evidence files are captured
# together and restore together.
tar czf "$target" -C "$DATA_DIR" .
echo "backup: wrote $target ($(wc -c < "$target") bytes)"

# Keep only the newest $KEEP snapshots.
ls -1t "$BACKUP_DIR"/soc-data-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old"
    echo "backup: pruned $old"
done

exit 0
