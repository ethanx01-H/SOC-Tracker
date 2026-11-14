"""The SLA sweep runs on a page load, so it has to be cheap and throttled."""

from datetime import timedelta

import pytest

from soc_tracker.services import sla_service

from tests.test_query_scaling import boundary_tickets, make_alert, utcnow  # noqa: F401


@pytest.fixture(autouse=True)
def clean_throttle():
    """The throttle is a module global: another test may have just swept."""
    previous = sla_service._last_sweep
    sla_service._last_sweep = None
    yield
    sla_service._last_sweep = previous


def test_sweep_opens_one_breach_per_missed_ticket(db, boundary_tickets):
    first = sla_service.sweep(db)
    assert first["opened"] >= 1
    assert sla_service.sweep(db)["opened"] == 0


def test_sweep_throttle_holds_off_a_second_page_load(db, boundary_tickets):
    now = utcnow()
    first = sla_service.sweep_throttled(db, now=now)
    second = sla_service.sweep_throttled(db, now=now + timedelta(seconds=1))
    assert "skipped" not in first
    assert second["skipped"] is True

    # Past the interval it does the work again.
    later = sla_service.sweep_throttled(db, now=now + sla_service.SWEEP_INTERVAL + timedelta(seconds=1))
    assert "skipped" not in later
