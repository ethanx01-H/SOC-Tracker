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

The default SQLite deployment is a single-instance pilot setup. Back up the Docker volume and evidence files together, test restores, and export audit logs to protected external storage for production use. Request limiting and login lockout are in process memory; keep one worker and use proxy-level limits unless a shared limiter is configured.

## Screenshots

### Login

![Login page](docs/screenshots/login.png)

### Dashboard

SOC dashboard with alert counts, pie charts, and filtered alert queue.

![Dashboard](docs/screenshots/dashboard.png)

### Alert detail

Full alert view with assignment, IOCs, investigation notes, evidence uploads, and activity log.

![Alert detail](docs/screenshots/alert-detail.png)

### User administration

Create users, manage roles (L1/L2/L3), and reset passwords.

![Users admin](docs/screenshots/users-admin.png)

## Features

### Alert management
- SOC dashboard with severity/source/analyst/tactic pie charts and alert counts
- Create, edit, escalate, assign, and close alerts with resolution summaries
- Sequential ticket numbers (`#1`, `#2`, ...) that remain stable after migration
- Ticket workflow: Open when unassigned, Pending when assigned, WIP when work starts, and Closed after resolution
- Filter by severity, status, search terms; CSV export of filtered results
- Evidence file uploads with SHA-256 integrity tracking
- Evidence uploads accept `.xlsx`, `.csv`, `.jpg`, and `.png` files
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
| `LOGIN_LOCKOUT_THRESHOLD`| No       | `5`                    | Failed login attempts before lockout     |
| `LOGIN_LOCKOUT_SECONDS`  | No       | `300`                  | Lockout duration in seconds              |

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
- Evidence management improvements (file previews, tagging, retention)
- External integrations for SIEM enrichment, ticket export, and notifications
- Deployment docs for HTTPS, reverse proxy, and backups
- API documentation page with example payloads for n8n and Elastic imports

## Contributing

Community contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for suggested areas, pull request guidance, and security notes.

## License

[MIT](LICENSE)
