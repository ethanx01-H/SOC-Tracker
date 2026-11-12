"""Tests for alert service functions."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from soc_tracker.services.alert_service import (
    normalized_datetime,
    sla_status,
    form_values,
    create_alert,
)
from soc_tracker.models import Alert


class TestNormalizedDatetime:
    """Test datetime timezone normalization."""

    def test_naive_datetime(self):
        dt = datetime(2024, 1, 1, 12, 0, 0)
        result = normalized_datetime(dt)
        assert result.tzinfo == timezone.utc

    def test_aware_datetime(self):
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = normalized_datetime(dt)
        assert result.tzinfo == timezone.utc

    def test_other_timezone(self):
        from datetime import timezone
        tz = timezone(timedelta(hours=5))
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=tz)
        result = normalized_datetime(dt)
        assert result.tzinfo == tz  # Preserves existing timezone


class TestSlaStatus:
    """Test SLA status calculation."""

    def _make_alert(self, status="Open", created_hours_ago=0, sla_hours=8):
        """Create a mock alert."""
        alert = MagicMock()
        alert.status = status
        alert.created_at = datetime.now(timezone.utc) - timedelta(hours=created_hours_ago)
        alert.sla_hours = sla_hours
        return alert

    def test_closed_alert(self):
        alert = self._make_alert(status="Closed")
        result = sla_status(alert)
        assert result["label"] == "Closed"
        assert result["class"] == "sla-closed"

    def test_overdue_alert(self):
        alert = self._make_alert(status="Open", created_hours_ago=10, sla_hours=8)
        result = sla_status(alert)
        assert result["label"] == "Overdue"
        assert result["class"] == "sla-overdue"

    def test_due_soon_alert(self):
        alert = self._make_alert(status="Open", created_hours_ago=7, sla_hours=8)
        result = sla_status(alert)
        assert "Due in" in result["label"]
        assert result["class"] == "sla-due-soon"

    def test_on_track_alert(self):
        alert = self._make_alert(status="Open", created_hours_ago=1, sla_hours=8)
        result = sla_status(alert)
        assert "Due in" in result["label"]
        assert result["class"] == "sla-ok"


class TestFormValues:
    """Test form value extraction and validation."""

    def test_basic_form(self):
        form = {
            "title": "Test Alert",
            "description": "Test description",
            "source": "Manual",
            "severity": "High",
            "status": "Open",
            "analyst": "l1",
            "tactic": "Initial Access",
            "asset": "server01",
            "iocs_text": "192.168.1.1, evil.com",
            "sla_hours": "4",
        }
        result = form_values(form)
        assert result["title"] == "Test Alert"
        assert result["description"] == "Test description"
        assert result["source"] == "Manual"
        assert result["severity"] == "High"
        assert result["status"] == "Open"
        assert result["analyst"] == "l1"
        assert result["tactic"] == "Initial Access"
        assert result["asset"] == "server01"
        assert result["iocs"] == ["192.168.1.1", "evil.com"]
        assert result["sla_hours"] == 4

    def test_empty_form(self):
        form = {}
        result = form_values(form)
        assert result["title"] == ""
        assert result["description"] == ""
        assert result["source"] == "Manual"
        assert result["severity"] == "Medium"
        assert result["status"] == "Open"
        assert result["analyst"] == "Unassigned"
        assert result["tactic"] == "Unknown"
        assert result["asset"] == "Unknown"
        assert result["iocs"] == []
        assert result["sla_hours"] == 8

    def test_title_too_long(self):
        form = {"title": "x" * 181}
        with pytest.raises(ValueError, match="Title must be 180 characters"):
            form_values(form)

    def test_description_too_long(self):
        form = {"description": "x" * 10001}
        with pytest.raises(ValueError, match="Description must be 10000 characters"):
            form_values(form)

    def test_source_too_long(self):
        form = {"source": "x" * 81}
        with pytest.raises(ValueError, match="Source must be 80 characters"):
            form_values(form)

    def test_tactic_too_long(self):
        form = {"tactic": "x" * 101}
        with pytest.raises(ValueError, match="Tactic must be 100 characters"):
            form_values(form)

    def test_asset_too_long(self):
        form = {"asset": "x" * 161}
        with pytest.raises(ValueError, match="Asset must be 160 characters"):
            form_values(form)

    def test_iocs_parsing(self):
        form = {"iocs_text": "192.168.1.1, evil.com, , hash123"}
        result = form_values(form)
        assert result["iocs"] == ["192.168.1.1", "evil.com", "hash123"]

    def test_whitespace_trimming(self):
        form = {
            "title": "  Test Alert  ",
            "description": "  Test description  ",
            "source": "  Manual  ",
            "analyst": "  l1  ",
            "tactic": "  Initial Access  ",
            "asset": "  server01  ",
        }
        result = form_values(form)
        assert result["title"] == "Test Alert"
        assert result["description"] == "Test description"
        assert result["source"] == "Manual"
        assert result["analyst"] == "l1"
        assert result["tactic"] == "Initial Access"
        assert result["asset"] == "server01"


def test_ticket_numbers_are_sequential(db):
    values = {
        "title": "Sequence test", "description": "", "source": "Manual",
        "severity": "Low", "status": "Open", "analyst": "Unassigned",
        "tactic": "Unknown", "asset": "Unknown", "sla_hours": 8,
    }
    first = create_alert(db, dict(values))
    second = create_alert(db, dict(values))
    assert first.alert_id == "#1"
    assert second.alert_id == "#2"
