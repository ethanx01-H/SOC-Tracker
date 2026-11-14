#!/usr/bin/env python3
"""Start the whole local demo with one command: Postgres, app, health check.

    .venv/bin/python scripts/demo_local.py start
    .venv/bin/python scripts/demo_local.py status
    .venv/bin/python scripts/demo_local.py stop

Postgres here is the bundled one from ``pgserver`` (a development dependency),
not a server you would run in production. It exists so the demo exercises the
same SQL as production, and its data lives in ``.demo-postgres/`` so a restart
keeps the tickets instead of wiping them.

Everything this script creates stays under ``~/.local/share/sentriq-demo``
(override with ``DEMO_STATE_DIR``): the database cluster, the app log, the pid
file. Delete that folder to start from scratch. It is deliberately not inside
the repository: Postgres will not initialise a cluster on a Windows drvfs mount
such as ``/mnt/d`` under WSL.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # run as a script, so the app package is not importable yet
    sys.path.insert(0, str(ROOT))
# Postgres needs a real Linux filesystem: initdb refuses a drvfs mount such as
# /mnt/d under WSL, so the cluster lives in the home directory, not in the repo.
STATE = pathlib.Path(os.environ.get("DEMO_STATE_DIR", pathlib.Path.home() / ".local" / "share" / "sentriq-demo"))
PGDATA = STATE / "pgdata"
URI_FILE = STATE / "uri.txt"
PID_FILE = STATE / "app.pid"
LOG_FILE = STATE / "app.log"
PORT = int(os.environ.get("DEMO_PORT", "8080"))
WORKERS = os.environ.get("WEB_CONCURRENCY", "4")

TABLES = [
    "fastapi_users",
    "fastapi_alerts",
    "fastapi_alert_events",
    "fastapi_evidence",
    "fastapi_audit_logs",
    "fastapi_sla_breaches",
]


def say(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------
# Postgres
# --------------------------------------------------------------------------


def database_url() -> str | None:
    """The URL of the demo Postgres, if it is running and answering."""
    if not URI_FILE.exists():
        return None
    url = URI_FILE.read_text().strip()
    if not url:
        return None
    try:
        from sqlalchemy import create_engine, text

        from sentriq.dburl import normalise_database_url

        engine = create_engine(normalise_database_url(url), connect_args={"connect_timeout": 5})
        with engine.connect() as connection:
            connection.execute(text("select 1"))
        return url
    except Exception:
        return None


def serve_postgres() -> int:
    """Child process: run the database until the process is killed."""
    import pgserver

    # pgserver has no public re-export; this is its documented entry point.
    server = pgserver.get_server(str(PGDATA), cleanup_mode=None)  # pyright: ignore[reportPrivateImportUsage]
    URI_FILE.parent.mkdir(parents=True, exist_ok=True)
    URI_FILE.write_text(server.get_uri())
    say(f"postgres ready: {server.get_uri()}")
    while True:
        time.sleep(30)


def start_postgres() -> str:
    url = database_url()
    if url:
        say(f"postgres already running")
        return url

    STATE.mkdir(parents=True, exist_ok=True)
    first_run = not (PGDATA / "PG_VERSION").exists()
    say("starting postgres" + (" (first run creates the cluster, this takes a moment)" if first_run else ""))
    child = subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).resolve()), "_serve_postgres"],
        cwd=str(ROOT),
        stdout=LOG_FILE.open("ab"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=os.environ.copy(),
    )
    (STATE / "pg.pid").write_text(str(child.pid))

    deadline = time.time() + 120
    while time.time() < deadline:
        url = database_url()
        if url:
            return url
        time.sleep(1)
    raise SystemExit(f"postgres did not come up in 120 s; see {STATE} and try again")


# --------------------------------------------------------------------------
# Schema and demo data
# --------------------------------------------------------------------------


def migrate(url: str) -> None:
    say("running migrations")
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(ROOT),
        env={**os.environ, "DATABASE_URL": url},
        check=True,
        stdout=subprocess.DEVNULL,
    )


def pg_bin() -> pathlib.Path:
    """The bundled Postgres client binaries, for pg_dump in the backup step."""
    import pgserver

    return pathlib.Path(pgserver.__file__).parent / "pginstall" / "bin"


def backup(url: str) -> None:
    """Snapshot before serving, the same way the container entrypoint does."""
    script = ROOT / "scripts" / "backup-postgres.sh"
    if not script.exists():
        return
    say("taking a database snapshot")
    subprocess.run(
        ["sh", str(script), str(STATE / "backups"), "20", "300"],
        env={**os.environ, "DATABASE_URL": url, "PATH": f"{pg_bin()}:{os.environ.get('PATH', '')}"},
        check=False,
    )


def ticket_count(url: str) -> int:
    from sqlalchemy import create_engine, text

    from sentriq.dburl import normalise_database_url

    engine = create_engine(normalise_database_url(url))
    try:
        with engine.connect() as connection:
            return connection.execute(text("select count(*) from fastapi_alerts")).scalar() or 0
    finally:
        engine.dispose()


def seed_demo_data(url: str) -> None:
    """Create the review accounts and the synthetic demo tickets in Postgres."""
    from sqlalchemy import create_engine, text

    from sentriq.auth import hash_password
    from sentriq.dburl import normalise_database_url

    say("creating the review accounts and demo tickets")
    engine = create_engine(normalise_database_url(url))
    with engine.begin() as connection:
        for username, role, is_admin in (("admin_l3", "L3", True), ("l2", "L2", False), ("l1", "L1", False)):
            exists = connection.execute(
                text("select 1 from fastapi_users where username = :u"), {"u": username}
            ).scalar()
            if not exists:
                connection.execute(
                    text(
                        "insert into fastapi_users (username, password_hash, role, is_admin, "
                        "must_change_password, is_active) values (:u, :p, :r, :a, false, true)"
                    ),
                    {"u": username, "p": hash_password("SocReview2026!"), "r": role, "a": is_admin},
                )
    engine.dispose()

    subprocess.run(
        [sys.executable, "-m", "sentriq.manage", "seed-demo"],
        cwd=str(ROOT),
        env={**os.environ, "DATABASE_URL": url},
        check=False,
    )


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------


def app_running() -> bool:
    """True only for our gunicorn, not for whatever else took the pid over.

    A bare os.kill(pid, 0) is not enough: after a crash the pid file outlives the
    process, and the operating system eventually hands that number to something
    else, at which point "already running" hides a dead app.
    """
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
        command = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode()
    except (ValueError, OSError):
        return False
    return "gunicorn" in command and f":{PORT}" in command


def health() -> dict | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=3) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError):
        return None


def start_app(url: str) -> None:
    if app_running():
        say("app already running")
        return

    say(f"starting the app on port {PORT} with {WORKERS} workers")
    environment = {
        **os.environ,
        "DATABASE_URL": url,
        "DATA_DIR": str(ROOT / "data"),
        "BACKUP_DIR": str(STATE / "backups"),
        "APP_ENV": "review",
        "COOKIE_SECURE": "0",
        "WEB_CONCURRENCY": WORKERS,
    }
    with LOG_FILE.open("ab") as log:
        process = subprocess.Popen(
            [
                str(ROOT / ".venv" / "bin" / "gunicorn"),
                "main:app",
                "-k", "uvicorn.workers.UvicornWorker",
                "-w", WORKERS,
                "-b", f"0.0.0.0:{PORT}",
                "--log-level", "warning",
            ],
            cwd=str(ROOT),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=environment,
        )
    PID_FILE.write_text(str(process.pid))

    deadline = time.time() + 60
    while time.time() < deadline:
        if health():
            return
        if process.poll() is not None:
            raise SystemExit(f"the app exited during startup; see {LOG_FILE}")
        time.sleep(1)
    raise SystemExit(f"the app did not answer on port {PORT} within 60 s; see {LOG_FILE}")


def stop_app() -> None:
    if not app_running():
        say("app not running")
        PID_FILE.unlink(missing_ok=True)
        return
    pid = int(PID_FILE.read_text().strip())
    os.killpg(pid, signal.SIGTERM)
    for _ in range(30):
        if not app_running():
            break
        time.sleep(0.5)
    PID_FILE.unlink(missing_ok=True)
    say("app stopped")


def stop_postgres() -> None:
    pg_ctl = pg_bin() / "pg_ctl"
    if not PGDATA.exists() or not (PGDATA / "postmaster.pid").exists():
        say("postgres not running")
        return
    subprocess.run([str(pg_ctl), "-D", str(PGDATA), "stop", "-m", "fast"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    say("postgres stopped")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def command_start() -> int:
    if not (ROOT / ".venv" / "bin" / "gunicorn").exists():
        raise SystemExit("no .venv here; run: python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt")

    url = start_postgres()
    migrate(url)
    if ticket_count(url) == 0:
        seed_demo_data(url)
    backup(url)
    start_app(url)

    info = health() or {}
    say("")
    say(f"  Sentriq is up at http://localhost:{PORT}")
    say(f"  database      Postgres (bundled), {ticket_count(url)} tickets")
    say(f"  backup        {info.get('backup', {}).get('newest') or 'none yet'}")
    say(f"  accounts      admin_l3 / l2 / l1, password SocReview2026!")
    say(f"  logs          {LOG_FILE}")
    say("")
    say("  stop it with: .venv/bin/python scripts/demo_local.py stop")
    return 0


def command_status() -> int:
    url = database_url()
    info = health()
    say(f"postgres: {'up' if url else 'down'}")
    say(f"app:      {'up' if app_running() else 'down'}")
    if info:
        say(f"health:   {info.get('status')} (database {info.get('database')})")
        say(f"backup:   {info.get('backup', {}).get('newest') or 'none'}")
    if url:
        say(f"tickets:  {ticket_count(url)}")
    return 0 if (url and info) else 1


def command_stop() -> int:
    stop_app()
    stop_postgres()
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"start", "stop", "status", "_serve_postgres"}:
        say(__doc__ or "usage: demo_local.py start|stop|status")
        return 2
    if argv[1] == "_serve_postgres":
        return serve_postgres()
    return {"start": command_start, "stop": command_stop, "status": command_status}[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
