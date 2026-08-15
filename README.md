# SOC Alert Tracker

SOC Alert Tracker is a FastAPI-based security operations alert tracker with role-based access control and a local webhook API for n8n.

## Features

- SOC dashboard with alert counts, pie charts, and queue filtering
- Alert creation, editing, filtering, severity, analyst, asset, source, MITRE tactic, IOCs, and SLA metadata
- Role-based access: L1, L2, and L3/admin
- Six-digit alert IDs such as `SOC-000001`
- Full-page alert detail links for weekly or monthly reports
- Evidence file uploads with SHA-256 integrity tracking
- Investigation notes and close-with-resolution workflow
- CSV export of filtered alerts
- n8n can POST alerts and workflow logs into the tracker through webhook APIs
- Elastic JSON paste to import alerts directly from Kibana
- SQLite persistence by default with Alembic migrations

## Roles

- L1: view, create, edit, and escalate alerts. L1 cannot delete alerts and cannot edit alerts after escalation.
- L2: view, create, edit, escalate, and assign investigations to L1.
- L3/admin: all access, including delete and assignment to L1 or L2.
- Assignment records `assigned_to`, `assigned_by`, and an activity-log entry visible on the alert detail page.

Demo users are created automatically on startup:

```text
l1 / password123
l2 / password123
admin_l3 / password123
```

## Report links

Open any alert and use the report URL from the detail page.

Example:

```text
http://localhost:8080/r/SOC-000001/
```

## Elastic JSON paste

Open `Elastic JSON`, paste an Elastic alert JSON document, and click `Add parsed alert`.

Supported shapes include:

- A raw Elastic hit with `_source`
- A `hits.hits` search response
- A plain JSON object with ECS or Kibana alert fields

The tracker extracts useful fields such as title, description, source, severity, asset, MITRE tactic, and IOCs.

## n8n integration

Tracker endpoint:

```text
POST http://localhost:8080/api/webhook/n8n/
Header: X-API-Key: <your N8N_API_KEY>
Content-Type: application/json
```

n8n can also push workflow logs into an existing alert:

```text
POST http://localhost:8080/api/webhook/n8n/logs/
Header: X-API-Key: <your N8N_API_KEY>
Content-Type: application/json
```

Log payload:

```json
{
  "alert_id": "SOC-000001",
  "event": "workflow completed",
  "message": "n8n enriched this alert with GeoIP and reputation data.",
  "workflow": "SOC enrichment"
}
```

## Run

Copy the example environment file and set your secrets:

```bash
cp .env.example .env
# Edit .env and set N8N_API_KEY and APP_SECRET_KEY
```

Install and run locally:

```bash
python3 -m pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

Then visit `http://localhost:8080`.

By default, SQLite data is stored at `data/fastapi.sqlite3`. Override it with `SQLITE_PATH`.

## Docker

Build and run with Docker:

```bash
docker build -t soc-alert-tracker .
docker run --rm -p 8080:8080 \
  -e N8N_API_KEY="your-secret" \
  -e APP_SECRET_KEY="your-secret" \
  soc-alert-tracker
```

With Docker Compose (reads from `.env`):

```bash
cp .env.example .env
# Edit .env and set N8N_API_KEY and APP_SECRET_KEY
docker compose up --build
```

## Project structure

```text
main.py              FastAPI application (routes, models, auth)
alerts/elastic.py    Elastic JSON parser
templates/           Jinja2 HTML templates
static/alerts/       CSS for the web UI
alembic/             Database migrations
data/                Runtime SQLite database (gitignored)
```

## Future improvements

- Add automated tests for alert workflows, role permissions, imports, and webhooks.
- Add dashboard date-range filters and trend charts for weekly/monthly reporting.
- Add richer SLA tracking with due dates, owner notifications, and breach history.
- Add evidence management improvements such as file previews, tagging, and retention controls.
- Add external integrations for SIEM enrichment, ticket export, email/slack notifications, and case handoff.
- Add deployment documentation for HTTPS, backups, and environment-specific configuration.
- Add an API documentation page with example payloads for n8n and Elastic alert imports.

## Contributing

Community contributions are welcome. See `CONTRIBUTING.md` for suggested areas, pull request guidance, and security notes.

## License

MIT. See `LICENSE`.
