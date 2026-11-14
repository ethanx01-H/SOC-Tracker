"""Shared helpers for the test suite.

The suite runs on Postgres, because the application refuses to start on SQLite:
a SQLite fixture would exercise a configuration that cannot be deployed, which
is how a Postgres-only query bug reaches production.

One bundled Postgres server is started per test session, and every test gets its
own database cloned from a migrated template. Cloning takes milliseconds, so the
isolation is cheap enough to keep.
"""

from __future__ import annotations

import os
import pathlib
import tempfile
import uuid

import pgserver
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

STATE_DIR = pathlib.Path(
    os.environ.get("SOC_TEST_PGDATA", pathlib.Path(tempfile.gettempdir()) / "sentriq-tests-pg")
)

_server = pgserver.get_server(str(STATE_DIR), cleanup_mode=None)  # pyright: ignore[reportPrivateImportUsage]
_BASE_URI = _server.get_uri()

# Override, not setdefault: a DATABASE_URL left in the shell must never point
# the suite at a database somebody cares about.
os.environ["DATABASE_URL"] = _BASE_URI

from sentriq.dburl import normalise_database_url  # noqa: E402
from sentriq.models import Base  # noqa: E402

TEMPLATE = "soc_test_template"


def url_for(name: str) -> str:
    """The server's URI pointed at another database on the same cluster."""
    head, _, tail = _BASE_URI.partition("/postgres?")
    if not tail:
        head, _, tail = _BASE_URI.partition("/postgres")
    return normalise_database_url(f"{head}/{name}?{tail}" if tail else f"{head}/{name}")


def _admin_engine():
    return create_engine(normalise_database_url(_BASE_URI), isolation_level="AUTOCOMMIT")


def ensure_template() -> None:
    """A migrated database with no rows, ready to be cloned."""
    admin = _admin_engine()
    with admin.connect() as connection:
        exists = connection.execute(
            text("select 1 from pg_database where datname = :name"), {"name": TEMPLATE}
        ).scalar()
        if exists:
            connection.execute(text(f'drop database "{TEMPLATE}"'))
        connection.execute(text(f'create database "{TEMPLATE}"'))

    engine = create_engine(url_for(TEMPLATE))
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    admin.dispose()


def make_engine():
    """A fresh database for one test, cloned from the migrated template."""
    ensure_template()
    name = f"soc_test_{uuid.uuid4().hex[:12]}"
    admin = _admin_engine()
    with admin.connect() as connection:
        connection.execute(text(f'create database "{name}" template "{TEMPLATE}"'))
    admin.dispose()
    return create_engine(url_for(name), pool_pre_ping=True)


def make_session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def server_uri() -> str:
    return _BASE_URI
