FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt ./
# postgresql-client is for pg_dump: the entrypoint snapshots a Postgres
# database to backups/soc-pg-<stamp>.dump before it serves traffic.
RUN apk add --no-cache postgresql-client \
    && pip install --no-cache-dir -r requirements.txt \
    && addgroup -S app && adduser -S -G app app
COPY . .
RUN mkdir -p /app/data && chown -R app:app /app

EXPOSE 8080
USER app
ENTRYPOINT ["/app/docker-entrypoint.sh"]
