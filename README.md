# SOC Alert Tracker

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)


A lightweight, self-hosted security operations alert tracker built with FastAPI. Designed for SOC teams that need role-based alert management, Elastic SIEM integration, and n8n workflow automation — without vendor lock-in.

## Quick start (local Python demo)

Create a virtual environment and install the app:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set `APP_SECRET_KEY` and `N8N_API_KEY` in `.env` to different random values of at least 32 characters, then start the app bound to this computer:

```bash
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080
```

On first startup, database migrations run automatically. In another terminal, create the first administrator:

```bash
.venv/bin/python -m soc_tracker.manage create-admin admin_l3
```

The command prompts you to choose a password. Open `http://127.0.0.1:8080` and sign in as `admin_l3`. A fresh install has no default users or demo tickets; create L1/L2 users from the Users page, then optionally seed synthetic review tickets:

```bash
.venv/bin/python -m soc_tracker.manage seed-demo
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

## Quick start (Docker)

```bash
git clone https://github.com/ethanx01-H/SOC-Tracker.git
cd SOC-Tracker
cp .env.example .env
# Replace N8N_API_KEY and APP_SECRET_KEY with separate random 32-byte secrets.
docker compose up --build
```

The review deployment listens on `http://127.0.0.1:8080` and creates no default users or sample incidents. Create the first administrator in a second terminal:

```bash
docker compose exec soc-alert-tracker python -m soc_tracker.manage create-admin admin_l3
```

The command prompts for the password twice. Create L1/L2 users from the administrator page and optionally add five synthetic review tickets with `docker compose exec soc-alert-tracker python -m soc_tracker.manage seed-demo`. The seed command refuses to run in production. New users are required to change their password by default; the admin can disable this when creating the account. Each user can change their own password from the **Change password** link in the sidebar.

This compose setup binds to localhost for review and defaults to non-secure cookies so it works over local HTTP. For production, set `APP_ENV=production` and `COOKIE_SECURE=1`, put the app behind HTTPS, and restrict access to the proxy/network. Do not expose port 8080 directly to the internet. [nginx.conf](nginx.conf) is an example HTTPS reverse proxy configuration; update its hostname and certificate paths before enabling it.

### Where the data lives, and how to update safely

The compose file bind-mounts host directories instead of using Docker volumes:

- `./data` → `/app/data` — the SQLite database, its WAL files, and `evidence/`
- `./backups` → `/app/backups` — automatic snapshots (override with `SOC_BACKUP_DIR`)

Because those are host directories, `docker compose down -v`, `docker volume rm`,
`docker volume prune` and `docker system prune --volumes` cannot delete the alerts or the
evidence. Those commands only remove Docker-managed volumes, and this stack no longer has
any.

Every container start writes a snapshot before the app serves traffic (newest 20 kept, at
most one every five minutes). `scripts/backup.sh` copies the database with SQLite's online
backup API — safe while the app is serving, unlike copying the `.sqlite3` file next to its
`-wal` — verifies the copy with `PRAGMA quick_check`, and tars it together with the evidence
files. To restore one:

```bash
docker compose down
docker compose run --rm --entrypoint sh soc-alert-tracker scripts/restore-data.sh /app/backups/soc-data-YYYYmmdd-HHMMSS.tar.gz /app/data --force
docker compose up -d
```

For a nightly snapshot while the stack is running, use the host scheduler. Linux or WSL
(`crontab -e`), 02:00 daily, keep 30, no minimum interval:

```cron
0 2 * * * cd /path/to/SOC-Tracker && docker compose exec -T soc-alert-tracker sh scripts/backup.sh /app/data /app/backups 30 0 >> /var/log/soc-tracker-backup.log 2>&1
```

On Windows, create a daily Task Scheduler job that runs:

```powershell
powershell -Command "cd D:\IT\automation_script\SOC-Tracker; docker compose exec -T soc-alert-tracker sh scripts/backup.sh /app/data /app/backups 30 0"
```

Test the restore path, not just the backup: run the restore commands above against a
snapshot at least once a quarter. A backup nobody has restored is a guess.

Updating is then just:

```bash
docker compose down
docker compose up -d --build
```

Moving data out of the old named volume, only if you ran an earlier compose file:

```powershell
docker compose down
docker run --rm -v soc-tracker_soc_tracker_data:/from -v "${PWD}\data:/to" alpine sh -c "cp -a /from/. /to/"
docker compose up -d --build
```

```bash
# same thing from WSL or Linux
docker run --rm -v soc-tracker_soc_tracker_data:/from -v "$PWD/data:/to" alpine sh -c "cp -a /from/. /to/"
```

Confirm the tickets are there, then remove the old volume with `docker volume rm
soc-tracker_soc_tracker_data`. On a Linux host the container runs as uid 1000, so make the
directory writable: `chown -R 1000:1000 data backups`. Since the container and a local
`uvicorn main:app` now share `./data`, run one at a time — two writers on one SQLite file
is how databases get corrupted.

### Data storage and retention

The local/demo app stores alert, account, event, and audit records in `data/fastapi.sqlite3` and evidence files in `data/evidence/`. In Docker, both are under `/app/data`, bind-mounted from `./data` on the host (see above). Alert deletion is disabled, and the app does not automatically expire records or evidence; this is persistence, not a guaranteed retention policy. Removing the host directory or losing the host can still destroy the data — the snapshots in `./backups` are the recovery point.

The current SQLite setup is for a single-instance pilot and does not provide a production two-year retention guarantee. Before production, use a managed database with durable backups and a tested restore process, and durable evidence storage with a lifecycle/retention policy that keeps incident records and evidence for at least 730 days. Protect audit exports separately (ideally immutable storage), monitor backup/retention jobs, and verify restores. Keep database, evidence, and audit retention aligned; do not enable automatic deletion before the required retention period. Request limiting and login lockout are in process memory; keep one worker and use proxy-level limits unless a shared limiter is configured. Set `TRUSTED_PROXIES` to the addresses of your reverse proxy so lockouts, rate limits, and audit rows key on the real client address rather than the proxy.

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
- Evidence is attached when the ticket is created; there is no later upload, so a ticket's evidence is exactly what the analyst filed with it
- Every file is stored with its SHA-256 recorded; PNG and JPEG appear as small thumbnails (four per row) that open a full-size popup, everything else is listed as a normal row that downloads
- Evidence uploads accept `.xlsx`, `.csv`, `.jpg`, `.jpeg`, `.png`, `.txt`, `.log`, `.json`, `.pdf`, `.pcap`, `.pcapng`, up to 20 MB each (25 MB per submission); a rejected file cancels the whole create, so no half-made ticket is left behind
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

**Delete** removes the row permanently, but only for an account with no history — no tickets, timeline events, evidence or audit entries. If anything references the account the delete is refused, and the message states how many records would lose their attribution. That refusal is deliberate: SQLite here does not enforce foreign keys, so deleting a user who worked tickets would not raise an error, it would quietly leave "Created by" and "Assigned to" blank on their incidents. For a leaver who touched tickets, deactivate instead — access ends immediately and the record stays intact.

Two guards apply to both actions: you cannot act on your own account, and the last active administrator cannot be removed.

Timestamps are stored in UTC and rendered in the configured zone (`DISPLAY_TIMEZONE`, default `Asia/Yangon`) with the zone labelled above the activity log and the audit table.

### Elastic JSON import

Paste raw Elastic alert JSON directly into the tracker. Supported shapes:

- Raw Elastic hits with `_source`
- `hits.hits` search responses
- Plain JSON objects with ECS or Kibana alert fields

The parser extracts title, description, source, severity, asset, MITRE tactic, and IOCs automatically.

### n8n webhook integration

Push alerts from n8n workflows:

```bash
curl -X POST http://localhost:8080/api/webhook/n8n/ \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Brute force detected","severity":"High","source":"n8n"}'
```

Push enrichment logs into an existing alert:

```bash
curl -X POST http://localhost:8080/api/webhook/n8n/logs/ \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"alert_id":"#1","message":"GeoIP lookup completed.","workflow":"SOC enrichment"}'
```

Deliveries are idempotent: when a payload carries an Elastic `_id` (or an
`external_id`), a retry returns the ticket that already exists instead of
creating a second one. The response lists `created`, `existing`, and the combined
`ids`, so a workflow can tell a first delivery from a replay.

## Configuration

All settings are controlled via environment variables. See `.env.example` for the full list.

| Variable                 | Required | Default                | Description                              |
|--------------------------|----------|------------------------|------------------------------------------|
| `N8N_API_KEY`            | Yes*     | auto-generated         | Shared secret for n8n webhook API        |
| `APP_SECRET_KEY`         | Yes*     | auto-generated         | Cookie signing key (must persist)        |
| `SQLITE_PATH`            | No       | `data/fastapi.sqlite3` | SQLite database path                     |
| `COOKIE_SECURE`          | No       | `0`                    | Set to `1` for HTTPS-only cookies        |
| `RATE_LIMIT_REQUESTS`    | No       | `120`                  | Max requests per window                  |
| `RATE_LIMIT_WINDOW`      | No       | `60`                   | Rate limit window in seconds             |
| `LOGIN_LOCKOUT_THRESHOLD`| No       | `5`                    | Failed attempts per address+username     |
| `LOGIN_ACCOUNT_LOCKOUT_THRESHOLD` | No | `10`                 | Failed attempts per account, any address |
| `LOGIN_LOCKOUT_SECONDS`  | No       | `300`                  | Lockout duration in seconds              |
| `TRUSTED_PROXIES`        | No       | `127.0.0.1/32,::1/128` | Peers allowed to set `X-Forwarded-For`   |
| `DISPLAY_TIMEZONE`       | No       | `Asia/Yangon`          | Zone used to render stored UTC times     |

`TRUSTED_PROXIES` matters behind nginx or a Docker port mapping: the app resolves
the client address from `X-Forwarded-For` only when the direct peer is in this
list, and uses that address for rate limiting, login lockout, and every audit
row. Leave it at loopback for a direct deployment. `docker-compose.yml` widens it
to the Docker bridge range so the host proxy is trusted; never widen it to a
range that can reach the app port directly, or clients can choose their own
identity. `/healthz` and `/static/` are exempt from the request limiter so the
container healthcheck cannot throttle itself.

Production startup fails unless both secrets are explicitly supplied and at least 32 characters long. Keep them stable and private.

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

- **Backend:** FastAPI + SQLAlchemy + Alembic (SQLite with WAL mode)
- **Frontend:** Jinja2 server-rendered HTML, vanilla CSS (light/dark)
- **Auth:** Cookie-based sessions with PBKDF2-SHA256 password hashing
- **Security:** CSRF protection, rate limiting, login lockout, security headers, audit logging
- **Deployment:** Docker with gunicorn + uvicorn workers
- **Testing:** pytest with 103 automated tests

## Testing

Run the test suite:

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

Test coverage includes:
- Elastic/Kibana JSON parser (43 tests)
- Authentication and RBAC permissions (41 tests)
- Alert service business logic (19 tests)

## Future improvements

- ~~Automated tests for alert workflows, role permissions, imports, and webhooks~~ ✅ Done
- Dashboard date-range filters and trend charts for weekly/monthly reporting
- Richer SLA tracking with due dates, owner notifications, and breach history
- Evidence management improvements (tagging, retention)
- External integrations for SIEM enrichment, ticket export, and notifications
- Deployment docs for HTTPS, reverse proxy, and backups
- API documentation page with example payloads for n8n and Elastic imports

## Contributing

Community contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for suggested areas, pull request guidance, and security notes.

## License

[MIT](LICENSE)
