import json


def parse_elastic_alerts(raw_json):
    parsed = json.loads(raw_json)
    return [record_to_alert(record) for record in records_from(parsed)]


def records_from(value):
    if isinstance(value, list):
        records = []
        for item in value:
            records.extend(records_from(item))
        return records
    if not isinstance(value, dict):
        return []
    hits = value.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        records = []
        for hit in hits["hits"]:
            records.extend(records_from(hit))
        return records
    if isinstance(value.get("_source"), dict):
        return [{**value["_source"], "_id": value.get("_id"), "_index": value.get("_index")}]
    if isinstance(value.get("alert"), dict):
        return [value["alert"]]
    return [value]


def external_identifier(record):
    """Stable identifier used to deduplicate replayed webhook payloads."""
    if not isinstance(record, dict):
        return None
    doc_id = str(record.get("_id") or record.get("external_id") or "").strip()
    if not doc_id:
        return None
    index = str(record.get("_index") or "").strip()
    return (f"{index}:{doc_id}" if index else doc_id)[:160]


def record_to_alert(record):
    severity = normalize_severity(first_value(record, [
        "severity",
        "kibana.alert.severity",
        "signal.rule.severity",
        "rule.severity",
        "event.severity",
        "log.level",
    ]))
    return {
        "external_id": external_identifier(record),
        "title": first_value(record, [
            "title",
            "summary",
            "kibana.alert.rule.name",
            "signal.rule.name",
            "rule.name",
            "event.action",
            "message",
        ]) or "Elastic alert",
        "description": first_value(record, [
            "description",
            "kibana.alert.reason",
            "kibana.alert.rule.description",
            "signal.reason",
            "rule.description",
            "message",
        ]) or "Imported from Elastic JSON.",
        "source": first_value(record, ["source", "event.module", "event.dataset", "data_stream.dataset", "_index"]) or "Elastic",
        "severity": severity,
        "status": "Open",
        "analyst": "Unassigned",
        "tactic": first_value(record, [
            "tactic",
            "kibana.alert.rule.threat.tactic.name",
            "signal.rule.threat.tactic.name",
            "threat.tactic.name",
        ]) or "Unknown",
        "asset": first_value(record, [
            "asset",
            "host.name",
            "host.hostname",
            "agent.name",
            "observer.name",
            "user.name",
            "source.ip",
            "destination.ip",
        ]) or "Unknown",
        "iocs": collect_iocs(record),
        "sla_hours": {"Critical": 2, "High": 4, "Medium": 8}.get(severity, 24),
    }


def first_value(record, paths):
    for path in paths:
        values = flatten(read_path(record, path))
        if values:
            return values[0]
    return ""


def read_path(record, path):
    if not isinstance(record, dict):
        return None
    if path in record:
        return record[path]
    value = record
    for key in path.split("."):
        if isinstance(value, list):
            value = [item.get(key) for item in value if isinstance(item, dict) and key in item]
        elif isinstance(value, dict):
            value = value.get(key)
        else:
            return None
    return value


def flatten(value):
    if value is None:
        return []
    if isinstance(value, list):
        output = []
        for item in value:
            output.extend(flatten(item))
        return output
    if isinstance(value, dict):
        for key in ("name", "ip"):
            if key in value:
                return flatten(value[key])
        return []
    text = str(value).strip()
    return [text] if text else []


def collect_iocs(record):
    fields = [
        "source.ip",
        "destination.ip",
        "client.ip",
        "server.ip",
        "host.ip",
        "related.ip",
        "url.domain",
        "dns.question.name",
        "destination.domain",
        "related.hosts",
        "file.hash.sha256",
        "file.hash.sha1",
        "file.hash.md5",
        "process.hash.sha256",
        "related.hash",
        "user.name",
        "source.user.name",
        "destination.user.name",
    ]
    values = []
    for field in fields:
        values.extend(flatten(read_path(record, field)))
    return list(dict.fromkeys(values))


def normalize_severity(value):
    text = str(value or "").lower()
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = -1
    if text in {"critical", "fatal"} or number >= 70:
        return "Critical"
    if text in {"high", "error"} or number >= 50:
        return "High"
    if text in {"medium", "warning", "warn"} or number >= 20:
        return "Medium"
    return "Low"
