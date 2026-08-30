"""Tests for Elastic alert parser."""

import json
import pytest

from alerts.elastic import (
    parse_elastic_alerts,
    record_to_alert,
    records_from,
    normalize_severity,
    first_value,
    read_path,
    flatten,
    collect_iocs,
)


class TestNormalizeSeverity:
    """Test severity normalization."""

    def test_critical_text(self):
        assert normalize_severity("critical") == "Critical"
        assert normalize_severity("Critical") == "Critical"
        assert normalize_severity("fatal") == "Critical"

    def test_high_text(self):
        assert normalize_severity("high") == "High"
        assert normalize_severity("High") == "High"
        assert normalize_severity("error") == "High"

    def test_medium_text(self):
        assert normalize_severity("medium") == "Medium"
        assert normalize_severity("warning") == "Medium"
        assert normalize_severity("warn") == "Medium"

    def test_low_text(self):
        assert normalize_severity("low") == "Low"
        assert normalize_severity("info") == "Low"
        assert normalize_severity("") == "Low"

    def test_numeric_severity(self):
        assert normalize_severity(70) == "Critical"
        assert normalize_severity(80) == "Critical"
        assert normalize_severity(50) == "High"
        assert normalize_severity(60) == "High"
        assert normalize_severity(20) == "Medium"
        assert normalize_severity(30) == "Medium"
        assert normalize_severity(10) == "Low"
        assert normalize_severity(0) == "Low"

    def test_none_severity(self):
        assert normalize_severity(None) == "Low"


class TestReadPath:
    """Test nested dictionary path reading."""

    def test_simple_path(self):
        record = {"key": "value"}
        assert read_path(record, "key") == "value"

    def test_nested_path(self):
        record = {"level1": {"level2": "value"}}
        assert read_path(record, "level1.level2") == "value"

    def test_missing_path(self):
        record = {"key": "value"}
        assert read_path(record, "missing") is None

    def test_missing_nested_path(self):
        record = {"level1": {"level2": "value"}}
        assert read_path(record, "level1.missing") is None

    def test_non_dict_input(self):
        assert read_path("not a dict", "key") is None
        assert read_path(None, "key") is None


class TestFlatten:
    """Test value flattening."""

    def test_none(self):
        assert flatten(None) == []

    def test_string(self):
        assert flatten("value") == ["value"]

    def test_list(self):
        assert flatten(["a", "b"]) == ["a", "b"]

    def test_nested_list(self):
        assert flatten([["a", "b"], "c"]) == ["a", "b", "c"]

    def test_dict_with_name(self):
        assert flatten({"name": "value"}) == ["value"]

    def test_dict_with_ip(self):
        assert flatten({"ip": "192.168.1.1"}) == ["192.168.1.1"]

    def test_empty_dict(self):
        assert flatten({}) == []

    def test_empty_string(self):
        assert flatten("") == []

    def test_whitespace_string(self):
        assert flatten("  ") == []


class TestFirstValue:
    """Test first value extraction from record."""

    def test_simple_field(self):
        record = {"title": "Test Alert"}
        assert first_value(record, ["title"]) == "Test Alert"

    def test_multiple_paths(self):
        record = {"summary": "Test Alert"}
        assert first_value(record, ["title", "summary"]) == "Test Alert"

    def test_missing_fields(self):
        record = {"other": "value"}
        assert first_value(record, ["title", "summary"]) == ""

    def test_empty_record(self):
        assert first_value({}, ["title"]) == ""


class TestRecordsFrom:
    """Test record extraction from various formats."""

    def test_list_of_records(self):
        data = [{"title": "Alert 1"}, {"title": "Alert 2"}]
        result = records_from(data)
        assert len(result) == 2

    def test_hits_format(self):
        data = {
            "hits": {
                "hits": [
                    {"_source": {"title": "Alert 1"}},
                    {"_source": {"title": "Alert 2"}},
                ]
            }
        }
        result = records_from(data)
        assert len(result) == 2
        assert result[0]["title"] == "Alert 1"

    def test_source_format(self):
        data = {"_source": {"title": "Alert 1"}, "_id": "123"}
        result = records_from(data)
        assert len(result) == 1
        assert result[0]["title"] == "Alert 1"
        assert result[0]["_id"] == "123"

    def test_alert_format(self):
        data = {"alert": {"title": "Alert 1"}}
        result = records_from(data)
        assert len(result) == 1
        assert result[0]["title"] == "Alert 1"

    def test_plain_object(self):
        data = {"title": "Alert 1"}
        result = records_from(data)
        assert len(result) == 1
        assert result[0]["title"] == "Alert 1"

    def test_non_dict(self):
        assert records_from("string") == []
        assert records_from(123) == []


class TestRecordToAlert:
    """Test alert record conversion."""

    def test_basic_conversion(self):
        record = {
            "title": "Test Alert",
            "description": "Test description",
            "severity": "High",
            "source": "Elastic",
            "tactic": "Initial Access",
            "asset": "server01",
        }
        result = record_to_alert(record)
        assert result["title"] == "Test Alert"
        assert result["description"] == "Test description"
        assert result["severity"] == "High"
        assert result["source"] == "Elastic"
        assert result["tactic"] == "Initial Access"
        assert result["asset"] == "server01"
        assert result["status"] == "New"
        assert result["analyst"] == "Unassigned"

    def test_kibana_fields(self):
        record = {
            "kibana.alert.rule.name": "Kibana Rule",
            "kibana.alert.severity": "high",
            "kibana.alert.reason": "Alert reason",
        }
        result = record_to_alert(record)
        assert result["title"] == "Kibana Rule"
        assert result["severity"] == "High"
        assert result["description"] == "Alert reason"

    def test_default_values(self):
        record = {}
        result = record_to_alert(record)
        assert result["title"] == "Elastic alert"
        assert result["description"] == "Imported from Elastic JSON."
        assert result["source"] == "Elastic"
        assert result["severity"] == "Low"
        assert result["tactic"] == "Unknown"
        assert result["asset"] == "Unknown"

    def test_sla_hours_by_severity(self):
        assert record_to_alert({"severity": "Critical"})["sla_hours"] == 2
        assert record_to_alert({"severity": "High"})["sla_hours"] == 4
        assert record_to_alert({"severity": "Medium"})["sla_hours"] == 8
        assert record_to_alert({"severity": "Low"})["sla_hours"] == 24


class TestParseElasticAlerts:
    """Test full Elastic alert parsing."""

    def test_parse_hits_format(self):
        raw = json.dumps({
            "hits": {
                "hits": [
                    {"_source": {"title": "Alert 1", "severity": "high"}},
                    {"_source": {"title": "Alert 2", "severity": "low"}},
                ]
            }
        })
        result = parse_elastic_alerts(raw)
        assert len(result) == 2
        assert result[0]["title"] == "Alert 1"
        assert result[0]["severity"] == "High"
        assert result[1]["title"] == "Alert 2"
        assert result[1]["severity"] == "Low"

    def test_parse_single_source(self):
        raw = json.dumps({"_source": {"title": "Single Alert"}})
        result = parse_elastic_alerts(raw)
        assert len(result) == 1
        assert result[0]["title"] == "Single Alert"

    def test_parse_plain_object(self):
        raw = json.dumps({"title": "Plain Alert", "severity": "medium"})
        result = parse_elastic_alerts(raw)
        assert len(result) == 1
        assert result[0]["title"] == "Plain Alert"
        assert result[0]["severity"] == "Medium"

    def test_invalid_json(self):
        with pytest.raises(json.JSONDecodeError):
            parse_elastic_alerts("not json")


class TestCollectIocs:
    """Test IOC collection from records."""

    def test_ip_addresses(self):
        record = {
            "source": {"ip": "192.168.1.1"},
            "destination": {"ip": "10.0.0.1"},
        }
        iocs = collect_iocs(record)
        assert "192.168.1.1" in iocs
        assert "10.0.0.1" in iocs

    def test_domains(self):
        record = {
            "url": {"domain": "evil.example.com"},
            "dns": {"question": {"name": "malware.example.com"}},
        }
        iocs = collect_iocs(record)
        assert "evil.example.com" in iocs
        assert "malware.example.com" in iocs

    def test_hashes(self):
        record = {
            "file": {"hash": {"sha256": "abc123"}},
            "process": {"hash": {"sha256": "def456"}},
        }
        iocs = collect_iocs(record)
        assert "abc123" in iocs
        assert "def456" in iocs

    def test_usernames(self):
        record = {
            "user": {"name": "admin"},
            "source": {"user": {"name": "attacker"}},
        }
        iocs = collect_iocs(record)
        assert "admin" in iocs
        assert "attacker" in iocs

    def test_no_duplicates(self):
        record = {
            "source": {"ip": "192.168.1.1"},
            "host": {"ip": "192.168.1.1"},
        }
        iocs = collect_iocs(record)
        assert iocs.count("192.168.1.1") == 1
