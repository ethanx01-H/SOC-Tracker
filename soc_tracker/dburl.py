"""Database URL handling, kept separate so it can be read without a database.

``soc_tracker.config`` refuses to import without a Postgres URL, which is the
point, but tooling still needs to normalise a URL before the app is configured.
"""


def normalise_database_url(url: str) -> str:
    """Route any Postgres URL through psycopg 3.

    A DBA will hand over ``postgresql://user:***@host/db``; SQLAlchemy reads
    that scheme as psycopg2, which this image does not ship. Rewriting the
    scheme here means the URL can be pasted in unchanged.
    """
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url
