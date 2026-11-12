#!/bin/sh
set -eu
alembic upgrade head
exec gunicorn main:app \
  --bind 0.0.0.0:8080 \
  --workers "${WEB_CONCURRENCY:-1}" \
  --worker-class uvicorn.workers.UvicornWorker \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
