#!/bin/sh
# Restore a snapshot into the data directory.
#
# Usage: restore-data.sh <snapshot.tar.gz> [data-dir] [--force]
#
# Stop the application first: replacing an open SQLite database underneath a
# running worker is not safe.
set -eu

SNAPSHOT=${1:?usage: restore-data.sh <snapshot.tar.gz> [data-dir] [--force]}
DATA_DIR=${2:-/app/data}
FORCE=${3:-}

if [ ! -f "$SNAPSHOT" ]; then
    echo "restore: $SNAPSHOT not found" >&2
    exit 1
fi

if [ -f "$DATA_DIR/fastapi.sqlite3" ] && [ "$FORCE" != "--force" ]; then
    echo "restore: $DATA_DIR already holds a database. Stop the app, then re-run with --force to overwrite it." >&2
    exit 1
fi

mkdir -p "$DATA_DIR"
tar xzf "$SNAPSHOT" -C "$DATA_DIR"
echo "restore: extracted $SNAPSHOT into $DATA_DIR"
