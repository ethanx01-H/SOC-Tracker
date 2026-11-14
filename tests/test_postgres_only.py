"""The application refuses to run on anything but Postgres.

These run the import in a subprocess because the check happens at import time in
``soc_tracker.config``, which is the only place it can be enforced for every
entry point: uvicorn, gunicorn, alembic and the management commands.
"""

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run_config_import(**environment):
    env = {key: value for key, value in os.environ.items() if key != "DATABASE_URL"}
    env.update(environment)
    return subprocess.run(
        [sys.executable, "-c", "import soc_tracker.config"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
    )


def test_no_database_url_is_a_refusal():
    result = run_config_import()
    assert result.returncode != 0
    assert "DATABASE_URL is required" in result.stderr
    assert "Postgres only" in result.stderr


def test_a_sqlite_url_is_refused_with_a_way_out():
    result = run_config_import(DATABASE_URL="sqlite:///tmp/whatever.sqlite3")
    assert result.returncode != 0
    assert "SQLite is not supported" in result.stderr
    # The message names the migration command, because that is what an operator
    # with an existing database needs next.
    assert "import-sqlite" in result.stderr


def test_something_that_is_not_postgres_is_refused():
    result = run_config_import(DATABASE_URL="mysql://user:pass@host/db")
    assert result.returncode != 0
    assert "must be a Postgres URL" in result.stderr


def test_a_postgres_url_is_accepted():
    result = run_config_import(DATABASE_URL="postgresql://user:pass@host:5432/soc_tracker")
    assert result.returncode == 0, result.stderr
