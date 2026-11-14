"""The database does the counting, paging and SLA bucketing now.

These tests exist because that moved the meaning of a filter from Python
(`sla_status`) into SQL. Each one compares the query's answer with the answer
the old Python path gives, so a drift in the SQL shows up as a failure rather
than as a dashboard that is quietly wrong.
"""

from datetime import datetime, timedelta, timezone

import pytest

from soc_tracker.models import Alert
from soc_tracker.services.alert_service import (
    alert_query,
    dashboard_counts,
    filtered_alerts_paginated,
    sla_status,
)
from soc_tracker.services.chart_service import chart_counts, chart_counts_for_query


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Query:
    """Stand-in for the request object the filter reads."""

    def __init__(self, **params):
        self.query_params = {key: str(value) for key, value in params.items()}


def make_alert(db, number, *, status="Open", severity="High", hours_ago=1, sla_hours=8,
               severity_source="Elastic", analyst="Unassigned"):
    alert = Alert(
        alert_id=f"#{number}", title=f"Ticket {number}", description="Boundary case.",
        source=severity_source, severity=severity, status=status, analyst=analyst,
        tactic="Execution", asset="WKS-1", iocs_json="[]", sla_hours=sla_hours,
        created_at=utcnow() - timedelta(hours=hours_ago),
        closed_at=utcnow() if status == "Closed" else None,
    )
    db.add(alert)
    return alert


@pytest.fixture
def boundary_tickets(db):
    """One ticket in every SLA bucket, including both edges of each boundary."""
    make_alert(db, 1, status="Open", hours_ago=9)          # 1h overdue
    make_alert(db, 2, status="WIP", hours_ago=8.01)        # just overdue
    make_alert(db, 3, status="Open", hours_ago=7.9)        # 7h59m left, on track
    make_alert(db, 4, status="Pending", hours_ago=6.5)     # 1h30m left, due soon
    make_alert(db, 5, status="Open", hours_ago=6.0)        # exactly 2h left, due soon
    make_alert(db, 6, status="Closed", hours_ago=48)       # closed, never overdue
    make_alert(db, 7, status="Open", hours_ago=1, sla_hours=1)   # 24h ticket, overdue
    make_alert(db, 8, status="Open", hours_ago=0.5)        # 7h30m left, on track
    db.commit()


@pytest.mark.parametrize("bucket", ["overdue", "due-soon", "on-track", "closed"])
def test_sla_filter_matches_the_python_classification(db, boundary_tickets, bucket):
    # The filter value and the CSS class do not share a spelling: on-track is
    # what the queue calls the bucket that sla_status() labels sla-ok.
    css_class = {"on-track": "sla-ok"}.get(bucket, f"sla-{bucket}")
    expected = {
        alert.id for alert in db.query(Alert).all()
        if sla_status(alert)["class"] == css_class
    }
    actual = {alert.id for alert in db.scalars(alert_query(Query(sla=bucket)))}
    assert actual == expected, f"{bucket}: SQL {sorted(actual)} vs python {sorted(expected)}"
    assert actual, f"{bucket} matched nothing, so the comparison proves nothing"


def test_dashboard_counts_match_a_python_count(db, boundary_tickets):
    counts = dashboard_counts(db, alert_query(Query(), ordered=False))
    alerts = db.query(Alert).all()
    assert counts == {
        "total": len(alerts),
        "open": len([a for a in alerts if a.status == "Open"]),
        "pending": len([a for a in alerts if a.status == "Pending"]),
        "wip": len([a for a in alerts if a.status == "WIP"]),
        "critical": len([a for a in alerts if a.severity == "Critical"]),
        "overdue": len([a for a in alerts if sla_status(a)["class"] == "sla-overdue"]),
    }


def test_counts_follow_the_filter(db, boundary_tickets):
    counts = dashboard_counts(db, alert_query(Query(status="Open"), ordered=False))
    assert counts["total"] == db.query(Alert).filter(Alert.status == "Open").count()
    assert counts["wip"] == 0


def test_a_page_reads_a_page_and_still_counts_everything(db):
    for number in range(1, 121):
        make_alert(db, number, hours_ago=number / 60)
    db.commit()

    first = filtered_alerts_paginated(db, Query(), page=1, per_page=50)
    last = filtered_alerts_paginated(db, Query(), page=3, per_page=50)
    beyond = filtered_alerts_paginated(db, Query(), page=99, per_page=50)

    assert (first["total"], first["total_pages"]) == (120, 3)
    assert len(first["alerts"]) == 50
    assert len(last["alerts"]) == 20
    # Page 99 is clamped to the last page rather than rendering an empty table.
    assert beyond["page"] == 3
    assert {a.alert_id for a in first["alerts"]}.isdisjoint({a.alert_id for a in last["alerts"]})


def test_chart_totals_agree_with_the_filter(db, boundary_tickets):
    base = alert_query(Query(), ordered=False)
    from_query = chart_counts_for_query(db, base.subquery())
    from_list = chart_counts(list(db.scalars(base)))
    for panel in ("severity", "source", "analyst", "tactic"):
        assert from_query[panel]["total"] == from_list[panel]["total"]
        assert [s["label"] for s in from_query[panel]["slices"]] == [s["label"] for s in from_list[panel]["slices"]]


def test_the_sla_deadline_compiles_for_both_databases():
    """The dialect picks the SQL, not a global read at import time.

    The suite runs SQLite even when the process is configured for Postgres, so
    an import-time branch here would emit interval arithmetic at a SQLite
    connection and fail with a syntax error.
    """
    from sqlalchemy import select
    from sqlalchemy.dialects import postgresql, sqlite

    from soc_tracker.services.alert_service import _sla_due_sql

    statement = select(_sla_due_sql(Alert.created_at, Alert.sla_hours))
    sqlite_sql = str(statement.compile(dialect=sqlite.dialect()))
    postgres_sql = str(statement.compile(dialect=postgresql.dialect()))

    assert "datetime(" in sqlite_sql
    assert "|| ' hours'" in sqlite_sql
    assert "interval" not in sqlite_sql

    assert "interval '1 hour'" in postgres_sql
    assert "datetime(" not in postgres_sql
