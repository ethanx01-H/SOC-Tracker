# Sentriq

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)


A lightweight, self-hosted security operations alert tracker built with FastAPI. Designed for SOC teams that need role-based alert management and a straightforward way to bring Elastic SIEM alerts in — without vendor lock-in.

## Quick start (local Python demo)

Create a virtual environment and install the app:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set `APP_SECRET_KEY` in `.env` to a random value of at least 32 characters, then start the app bound to this computer:

```bash
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
```

On first startup, database migrations run automatically. In another terminal, create the first administrator:

```bash
.venv/bin/python -m sentriq.manage create-admin admin_l3
```

The command prompts you to choose a password. Open `http://127.0.0.1:8080` and sign in as `admin_l3`. A fresh install has no default users or demo tickets; create L1/L2 users from the Users page, then optionally seed synthetic review tickets:

```bash
.venv/bin/python -m sentriq.manage seed-demo
```

The seed command is disabled when `APP_ENV=production`. New users have **Require password change at next login** enabled by default; the admin can turn it off in the create-user form. Any signed-in user can later change their own password from **Change password** in the sidebar. Stop the server with `Ctrl+C`.

### Local review accounts

The current local review database has these demo accounts. They are not automatically created on fresh installs.

| Username | Role | Password |
|---|---|---|
| `l1` | L1 Analyst | `SocReview2026!` |
| `l2` | L2 Analyst | `SocReview2026!` |
| `admin_l3` | L3 Admin | `SocReview2026!` |

Change the shared demo password after signing in. Do not use it outside this localhost demo.

### One command, Postgres included

`scripts/demo_local.py` starts a local Postgres, migrates it, copies the demo
tickets in, takes a snapshot and starts the app with four workers:

```bash
pip install -r requirements-dev.txt   # adds pgserver, a bundled Postgres
.venv/bin/python scripts/demo_local.py start
.venv/bin/python scripts/demo_local.py status
.venv/bin/python scripts/demo_local.py stop
```

It prints the URL and the review accounts when it is ready, and everything it
creates lives in `~/.local/share/sentriq-demo` (override with
`DEMO_STATE_DIR`), so stopping and starting keeps the tickets. The Postgres
there is a development bundle, not a server to run in production; it is only
there so the demo exercises the same SQL as production. Postgres refuses to
initialise a cluster on a Windows drvfs mount such as `/mnt/d` under WSL, which
is why the state directory is outside the repository.

## Quick start (Docker)

```bash
git clone https://github.com/ethanx01-H/Sentriq.git
cd Sentriq
cp .env.example .env
# Replace APP_SECRET_KEY with a random 32-byte secret.
docker compose up --build
```

The review deployment listens on `http://127.0.0.1:8080` and creates no default users or sample incidents. Create the first administrator in a second terminal:

```bash
docker compose exec sentriq python -m sentriq.manage create-admin admin_l3
```

The command prompts for the password twice. Create L1/L2 users from the administrator page and optionally add five synthetic review tickets with `docker compose exec sentriq python -m sentriq.manage seed-demo`. The seed command refuses to run in production. New users are required to change their password by default; the admin can disable this when creating the account. Each user can change their own password from the **Change password** link in the sidebar.

This compose setup binds to localhost for review and defaults to non-secure cookies so it works over local HTTP. For production, set `APP_ENV=production` and `COOKIE_SECURE=1`, put the app behind HTTPS, and restrict access to the proxy/network. Do not expose port 8080 directly to the internet. [nginx.conf](nginx.conf) is an example HTTPS reverse proxy configuration; update its hostname and certificate paths before enabling it.

### Where the data lives, and how to update safely

The compose file bind-mounts host directories instead of using Docker volumes:

- `./data` → `/app/data` — uploaded `evidence/`
- `./pgdata` → the Postgres data directory (override with `SENTRIQ_PGDATA_DIR`)
- `./backups` → `/app/backups` — `pg_dump` snapshots (override with `SENTRIQ_BACKUP_DIR`)

Because those are host directories, `docker compose down -v`, `docker volume rm`,
`docker volume prune` and `docker system prune --volumes` cannot delete the alerts or the
evidence. Those commands only remove Docker-managed volumes, and this stack no longer has
any.

Every container start writes a snapshot before the app serves traffic (newest 20 kept, at
most one every five minutes). `scripts/backup-postgres.sh` runs `pg_dump --format=custom`,
checks the result with `pg_restore --list`, and only then renames it into place, so a failed
dump never looks like a usable snapshot. To restore one into a fresh database:

```bash
docker compose exec -T postgres createdb -U sentriq sentriq_restore
pg_restore --no-owner --no-privileges -d "postgresql://sentriq:***@localhost:5432/sentriq_restore" backups/soc-pg-YYYYmmdd-HHMMSS.dump
```

For a nightly snapshot while the stack is running, use the host scheduler. Linux or WSL
(`crontab -e`), 02:00 daily, keep 30, no minimum interval:

```cron
0 2 * * * cd /path/to/Sentriq && docker compose exec -T sentriq sh scripts/backup-postgres.sh /app/backups 30 0 >> /var/log/sentriq-backup.log 2>&1
```

On Windows, create a daily Task Scheduler job that runs:

```powershell
powershell -Command "cd D:\IT\automation_script\Sentriq; docker compose exec -T sentriq sh scripts/backup-postgres.sh /app/backups 30 0"
```

Test the restore path, not just the backup: restore a snapshot into a scratch database at
least once a quarter and compare row counts. A backup nobody has restored is a guess.

Updating is then just:

```bash
docker compose down
docker compose up -d --build
```

Moving data out of the old named volume, only if you ran an earlier compose file:

```powershell
docker compose down
docker run --rm -v sentriq_sentriq_data:/from -v "${PWD}\data:/to" alpine sh -c "cp -a /from/. /to/"
docker compose up -d --build
```

```bash
# same thing from WSL or Linux
docker run --rm -v sentriq_sentriq_data:/from -v "$PWD/data:/to" alpine sh -c "cp -a /from/. /to/"
```

Confirm the tickets are there, then remove the old volume with `docker volume rm
sentriq_sentriq_data`. On a Linux host the container runs as uid 1000, so make the
directory writable: `chown -R 1000:1000 data backups`.

### Data storage and retention

Alert, account, event, and audit records live in Postgres; uploaded evidence lives in `data/evidence/`. In Docker the evidence directory is bind-mounted from `./data` and the database files sit in `./pgdata` (see above). Alert deletion is disabled; tickets leave the database only through the retention job below, which archives them first. Losing the host can still destroy the data — the `pg_dump` snapshots in `./backups` are the recovery point, and a database host your DBA backs up is better still.

**Postgres is required.** `DATABASE_URL` has no default: the app refuses to start
without it, and refuses a `sqlite://` URL with an explanation. Both `postgres://`
and `postgresql://` are rewritten to `psycopg://` internally, so a URL copied from
a DBA works unchanged:

```bash
DATABASE_URL=postgresql://sentriq:***@db:5432/sentriq
```

**Shared limiter counters.** Rate limits and login lockouts live in process memory by default, which is correct for one worker and wrong for several: each worker counts only its own traffic, so N workers allow N times the limit, and a lockout applies only to the worker that saw the failed attempt. Set `REDIS_URL` to share both counters across workers. Without Redis, either keep `WEB_CONCURRENCY=1` or accept the multiplied limit.

**Retention (730 days).** `python -m sentriq.manage retention` prints what would be archived; add `--apply` to actually do it:

```bash
python -m sentriq.manage retention --days 730           # dry run, changes nothing
python -m sentriq.manage retention --days 730 --apply   # archive, then remove
```

Only *closed* tickets are eligible, and the clock starts at closure — a ticket opened three years ago and closed last week keeps its full window. The job writes a gzipped JSON Lines archive (ticket, timeline, evidence metadata with SHA-256, SLA breaches) into `data/archive/`, reads it back to prove it opens and holds the expected number of tickets, and only then deletes rows and evidence files. One audit row records the batch. Nothing is deleted if the archive cannot be verified.

**Immutable audit export.** The audit trail is hash-chained on export: each record carries the hash of the one before it, so a deleted or edited row breaks the chain and verification names the record.

```bash
python -m sentriq.manage audit-export                 # all records
python -m sentriq.manage audit-export --from 2026-01-01 --to 2026-04-01
python -m sentriq.manage audit-verify data/audit-exports/audit-20260401T000000Z.jsonl
```

Exports are written read-only with a manifest holding the head hash. Copy the head hash somewhere off this host (a change ticket, an external log): that anchor is what proves later that the export was not rewritten. Read-only is not immutable — for the bank's requirement, land the export in object-lock or WORM storage.

**Monitoring.** `/healthz` reports database health and the age of the newest snapshot, and answers `degraded` when the snapshot is older than `BACKUP_MAX_AGE_HOURS` (default 36) without failing the check — restarting the app would not fix a dead backup job. `/metrics` serves Prometheus text: request counts and latency, tickets by status and severity, unassigned backlog, SLA breaches, evidence volume, audit row count, backup age and staleness, and which limiter store is in use. Without `METRICS_TOKEN` it answers on loopback only; with a token it requires `Authorization: Bearer <token>`.

```bash
python -m sentriq.manage backup-status   # newest snapshot and its age
python -m sentriq.manage sla-sweep       # record newly missed SLAs
```

Schedule retention, the audit export and the SLA sweep from cron (or Windows Task Scheduler), and alert on `soc_backup_stale`, `soc_backup_age_seconds` and `soc_sla_breaches{state="open"}`. Set `TRUSTED_PROXIES` to the addresses of your reverse proxy so lockouts, rate limits, and audit rows key on the real client address rather than the proxy.

## Database

Postgres, and nothing else. There is no SQLite fallback: the app refuses to start
without a Postgres `DATABASE_URL`, and refuses a `sqlite://` URL with a message
that says so. Two reasons. The SQL differs between engines — the SLA due date is
`created_at + interval '8 hours'` here — so a SQLite demo would never exercise the
query production runs, and the first Postgres run would be the production one. And
a single file cannot be shared by two app hosts or backed up by a DBA.

- **Docker**: `docker compose up --build` starts `postgres:16-alpine` beside the
  app and points `DATABASE_URL` at it. Its files live in `./pgdata`, a host
  directory, so `docker compose down -v` cannot delete the database.
- **Without Docker**: install Postgres 14 or newer and set
  `DATABASE_URL=postgresql://user:***@host:5432/sentriq`. Migrations run at
  startup.
- **Coming from an older install**: `python -m sentriq.manage import-sqlite
  data/fastapi.sqlite3` copies every table into the configured Postgres database,
  ids included, and refuses if the target already has tickets.

Measured on 5,000 tickets, four workers, ten concurrent page loads: Postgres p95
125 ms for the dashboard and 62 ms for the queue.

### Backing up Postgres

`scripts/backup-postgres.sh` writes `backups/soc-pg-<stamp>.dump` with
`pg_dump --format=custom`, keeps the newest 20, and checks each dump with
`pg_restore --list` before renaming it into place, so a failed dump never looks
like a usable snapshot. The container runs it at startup; for a schedule you can
point at, use cron on the host:

```cron
0 2 * * * cd /path/to/Sentriq && docker compose exec -T sentriq sh scripts/backup-postgres.sh /app/backups 30 0 >> /var/log/sentriq-backup.log 2>&1
```

Restore into a fresh database:

```bash
pg_restore --no-owner --no-privileges -d "$DATABASE_URL" backups/soc-pg-YYYYmmdd-HHMMSS.dump
```

`/healthz` and `/metrics` report the newest `soc-pg-*.dump` and go degraded when
there is none or the newest is older than `BACKUP_MAX_AGE_HOURS`.
If `pg_dump` is not installed, the startup log says so plainly rather than
pretending the database is being backed up.

## Screenshots

### Login

![Login page](docs/screenshots/login.png)

### Dashboard

SOC dashboard with alert counts, charts, and filtered alert queue.

![Dashboard](docs/screenshots/dashboard.png)

### Alert detail

Full alert view with assignment, IOCs, investigation notes, evidence uploads, and activity log.

![Alert detail](docs/screenshots/alert-detail.png)

### User administration

Create users, manage roles (L1/L2/L3), and reset passwords.

![Users admin](docs/screenshots/users-admin.png)

## Features

### Alert management
- SOC dashboard with source/analyst/tactic pie charts and alert counts
- Create, edit, escalate, assign, and close alerts with resolution summaries
- Sequential ticket numbers (`#1`, `#2`, ...) that remain stable after migration
- Severity scale: `0 - Critical`, `1 - High`, `2 - Medium`, `3 - Low`, `4 - Informational`
- Ticket workflow: Open when unassigned, Pending while awaiting analysis, WIP during active analysis, and Closed after resolution; analysts can assign open tickets to themselves
- L1, L2, and L3 users can assign unassigned Open tickets to themselves
- Optional IOCs when creating tickets; close summaries have no application-level word-count limit
- Filter by severity, status, search terms; CSV export of filtered results
- Dashboard date ranges (24 hours, 7, 30, 90 days, all time) applied to the counts, charts and queue
- Bulk actions on the queue: assign selected tickets to yourself, or move them to WIP/Pending/Open
- Duplicate handling: tickets filed within 24 hours with the same title or asset are listed on the ticket, and L2/L3 can merge one into another — the timeline and evidence move to the surviving ticket, and the duplicate closes pointing at it
- SLA breach history: a sweep records each missed due date and, on closure, how late the ticket actually was; the totals are exposed on `/metrics` and by `python -m sentriq.manage sla-sweep`
- Search matches ticket number, title, description, asset, source, analyst and IOC, and filters apply in place without reloading the page or losing your scroll position
- Notifications by email and Microsoft Teams on new high-severity tickets, assignment and escalation — each channel stays inert until it is configured
- Evidence is attached when the ticket is created; there is no later upload, so a ticket's evidence is exactly what the analyst filed with it
- Every file is stored with its SHA-256 recorded; PNG and JPEG appear as small thumbnails (four per row) that open a full-size popup, everything else is listed as a normal row that downloads. Every download and preview is written to the audit trail with the reader, the file name and its hash — chain of custody, not just a list of uploads
- Evidence uploads accept `.xlsx`, `.csv`, `.jpg`, `.jpeg`, `.png`, `.txt`, `.log`, `.json`, `.pdf`, `.pcap`, `.pcapng`, up to 6 MB each; a rejected file cancels the whole create, so no half-made ticket is left behind
- Investigation notes and activity-log timeline per alert

### Role-based access control

| Capability         | L1 Analyst | L2 Analyst | L3 Admin |
|--------------------|:----------:|:----------:|:--------:|
| View alerts        | Yes        | Yes        | Yes      |
| Create alerts      | Yes        | Yes        | Yes      |
| Edit alerts        | Yes*       | Yes        | Yes      |
| Escalate alerts    | Yes        | Yes        | Yes      |
| Assign to analysts | No         | L1 only    | L1 + L2  |
| Delete alerts      | No         | No         | Disabled |
| Manage users       | No         | No         | Yes      |

*L1 can edit assigned alerts while they remain open or in progress; closed tickets are read-only for L1.

### Account lifecycle

Admins create users on the **Users** page and can deactivate, reactivate or delete them from the same row. A deactivated account cannot sign in (the login form gives the same "invalid username or password" answer, so it does not confirm which accounts exist), and any session it already holds stops working on the next request. Deactivation is reversible and keeps the account, its tickets and its audit trail; nothing is deleted.

**Delete** removes the row permanently, but only for an account with no history — no tickets, timeline events, evidence or audit entries. If anything references the account the delete is refused, and the message states how many records would lose their attribution. That refusal is deliberate: the database would refuse the delete anyway, but a raw foreign-key error is a poor thing to show an administrator, so the check explains which records would lose their attribution. For a leaver who touched tickets, deactivate instead — access ends immediately and the record stays intact.

Two guards apply to both actions: you cannot act on your own account, and the last active administrator cannot be removed.

Timestamps are stored in UTC and rendered in the configured zone (`DISPLAY_TIMEZONE`, default `Asia/Yangon`) with the zone labelled above the activity log and the audit table.

### Elastic JSON import

Paste raw Elastic alert JSON directly into the tracker. Supported shapes:

- Raw Elastic hits with `_source`
- `hits.hits` search responses
- Plain JSON objects with ECS or Kibana alert fields

The parser extracts title, description, source, severity, asset, MITRE tactic, and IOCs automatically.

## Configuration

All settings are controlled via environment variables. See `.env.example` for the full list.

| Variable                 | Required | Default                | Description                              |
|--------------------------|----------|------------------------|------------------------------------------|
| `APP_SECRET_KEY`         | Yes*     | auto-generated         | Cookie signing key (must persist)        |
| `COOKIE_SECURE`          | No       | `0`                    | Set to `1` for HTTPS-only cookies        |
| `RATE_LIMIT_REQUESTS`    | No       | `120`                  | Max requests per window                  |
| `RATE_LIMIT_WINDOW`      | No       | `60`                   | Rate limit window in seconds             |
| `LOGIN_LOCKOUT_THRESHOLD`| No       | `5`                    | Failed attempts per address+username     |
| `LOGIN_ACCOUNT_LOCKOUT_THRESHOLD` | No | `10`                 | Failed attempts per account, any address |
| `LOGIN_LOCKOUT_SECONDS`  | No       | `300`                  | Lockout duration in seconds              |
| `TRUSTED_PROXIES`        | No       | `127.0.0.1/32,::1/128` | Peers allowed to set `X-Forwarded-For`   |
| `DISPLAY_TIMEZONE`       | No       | `Asia/Yangon`          | Zone used to render stored UTC times     |
| `DATABASE_URL`           | **Yes**  | —                      | Postgres URL; the app will not start without it |
| `WEB_CONCURRENCY`        | No       | `4`                    | Worker processes; see Performance        |
| `REDIS_URL`              | No       | unset                  | Shared limiter and lockout counters      |
| `RETENTION_DAYS`         | No       | `730`                  | Archive window for closed tickets        |
| `METRICS_TOKEN`          | No       | unset                  | Bearer token for `/metrics`              |
| `BACKUP_MAX_AGE_HOURS`   | No       | `36`                   | Snapshot age that marks `/healthz` stale |
| `SMTP_HOST`              | No       | unset                  | Email notifications                      |
| `NOTIFY_EMAIL_TO`        | No       | unset                  | Comma-separated recipients               |
| `NOTIFY_TEAMS_WEBHOOK`   | No       | unset                  | Teams incoming webhook                   |

`TRUSTED_PROXIES` matters behind nginx or a Docker port mapping: the app resolves
the client address from `X-Forwarded-For` only when the direct peer is in this
list, and uses that address for rate limiting, login lockout, and every audit
row. Leave it at loopback for a direct deployment. `docker-compose.yml` widens it
to the Docker bridge range so the host proxy is trusted; never widen it to a
range that can reach the app port directly, or clients can choose their own
identity. `/healthz` and `/static/` are exempt from the request limiter so the
container healthcheck cannot throttle itself.

Production startup fails unless both secrets are explicitly supplied and at least 32 characters long. Keep them stable and private.

## Performance

The dashboard, the queue and the CSV export are all built from one filter
(`alert_query` in `sentriq/services/alert_service.py`), and the database
answers it: tiles and pie panels are `COUNT` and `GROUP BY`, and the queue pages
with `LIMIT`/`OFFSET`. Nothing loads the whole table to count it.

Measured on a 5,000-ticket database, one host, SQLite (the engine in use when the query layer was rewritten; the Postgres figures are in [Database](#database)):

| page                     | before        | after, 1 worker | after, 4 workers |
|--------------------------|---------------|-----------------|------------------|
| dashboard, one analyst   | 1,300 ms      | 29 ms           | 29 ms            |
| queue, one analyst       | 110 ms        | 14 ms           | 16 ms            |
| dashboard, 10 at once    | ~70,000 ms    | 942 ms          | 78 ms            |
| queue, 10 at once        | ~17,000 ms    | 551 ms          | 38 ms            |

Ten concurrent analysts is the target, so `WEB_CONCURRENCY` now defaults to 4.
Workers are separate processes, which is what turns the queue into parallel work.
The rate limiter and login lockout counters live inside each worker, so four
workers allow four times the per-client limit.
Set `REDIS_URL` to share those counters, and move to Postgres (`DATABASE_URL`)
when several analysts write at the same time or the database must live off this
host.

The SLA sweep runs at most once every two minutes per worker instead of on every
page load, and reads the open tickets in one query rather than one query per
ticket. `python -m sentriq.manage sweep-sla` does the same work from cron if
you would rather schedule it.

## Development

For local development without Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8080
```

The `--reload` flag auto-restarts on code changes. Do not use `--reload` in production.

## Tech stack

- **Backend:** FastAPI + SQLAlchemy + Alembic (Postgres 14+)
- **Frontend:** Jinja2 server-rendered HTML, vanilla CSS (light/dark)
- **Auth:** Cookie-based sessions with PBKDF2-SHA256 password hashing
- **Security:** CSRF protection, rate limiting, login lockout, security headers, audit logging
- **Deployment:** Docker with gunicorn + uvicorn workers
- **Testing:** pytest with 103 automated tests

## Testing

Run the test suite:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

The runtime image installs `requirements.txt` only, so test tooling never ships. Check the dependency tree for advisories before a release:

```bash
pip-audit -r requirements.txt
```

Test coverage includes:
- Elastic/Kibana JSON parser (43 tests)
- Authentication and RBAC permissions (41 tests)
- Alert service business logic (19 tests)
- Retention archival and audit-export chain verification
- SLA breach history, backup freshness, and the metrics endpoint
- Limiter counters in memory and through Redis (`fakeredis`), including the Redis-outage fallback
- A guard that no request handler is declared `async def`, so blocking database and PBKDF2 work stays off the event loop

The suite runs on Postgres. It starts a bundled Postgres server for the session
(`pgserver`, a development dependency) and gives every test its own database
cloned from a migrated template, so tests stay isolated without a shared fixture
database. Nothing else to start:

```bash
pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

`tests/test_postgres.py` still exists as a separate check that drops and recreates
the `public` schema and runs the real migrations to head, which is closer to a
fresh deployment than the template clone is:

```bash
TEST_DATABASE_URL=postgresql://user:***@host/scratch_db pytest tests/test_postgres.py
```

It drops and recreates the `public` schema, runs the real migrations to head, and drives a ticket round trip, a close with audit rows, and import deduplication. Point it at a scratch database only.

## Future improvements

- ~~Automated tests for alert workflows, role permissions, and imports~~ ✅ Done
- ~~Dashboard date-range filters~~ ✅ Done (trend charts still open)
- ~~SLA tracking with breach history~~ ✅ Done
- ~~External integrations for notifications~~ ✅ Done (email and Teams)
- Trend charts for weekly and monthly reporting
- Evidence tagging and per-evidence retention
- API documentation page with example payloads for Elastic imports
- OpenTelemetry traces for slow dashboard queries at scale

## Contributing

Community contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for suggested areas, pull request guidance, and security notes.

## License

[MIT](LICENSE)
