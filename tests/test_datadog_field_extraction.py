"""Datadog fetchers read the response fields where the API puts them. No network.

Each response below follows the example bodies and schemas in Datadog's API
reference (docs.datadoghq.com/api/latest/...): incidents (Get a list of
incidents, Create an incident for timeline cells), logs archives (Get all
archives), logs indexes (Get all indexes), monitors (Get all monitor details),
security monitoring (List rules, Get a list of security signals). Values are
synthetic.

What this cannot prove: the shape of a real tenant's payload where the docs
give none. The timeline-cell read and the signal triage state are the two to
check on a live run.

Run: ``pytest tests/test_datadog_field_extraction.py``
"""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DATADOG = REPO_ROOT / "fetchers" / "datadog"


def _load(short_name: str):
    spec = importlib.util.spec_from_file_location(
        f"datadog_{short_name}_under_test", DATADOG / short_name / "fetcher.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


incidents_list = _load("incidents_list")
incident_timelines = _load("incident_timelines")
log_archives = _load("log_archives")
log_indexes = _load("log_indexes")
monitors_list = _load("monitors_list")
siem_detection_rules = _load("siem_detection_rules")
siem_signals = _load("siem_signals")


@pytest.fixture(autouse=True)
def _credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("DATADOG_API_KEY", "test-api-key")
    monkeypatch.setenv("DATADOG_APP_KEY", "test-app-key")
    monkeypatch.setenv("DATADOG_BASE_URL", "https://api.example.invalid")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv("DATADOG_AUDIT_INDEXES", raising=False)


class FakeResponse:
    def __init__(self, body: Any):
        self._body = body
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._body


# --- incidents_list --------------------------------------------------------


def incident(
    incident_id: str,
    detected: str = "2026-09-19T10:00:00.000Z",
    resolved: str = "2026-09-19T13:30:00.000Z",
    state: str = "resolved",
    commander: str = "00000000-0000-0000-0000-00000000c0de",
) -> Dict[str, Any]:
    """Shape of one data[] item from GET /api/v2/incidents."""
    return {
        "id": incident_id,
        "type": "incidents",
        "attributes": {
            "title": "Database latency",
            "severity": "SEV-2",
            "state": state,
            "created": "2026-09-19T09:58:00.000Z",
            "detected": detected,
            "resolved": resolved,
            "customer_impact_scope": "Some API calls were slow",
            "customer_impact_duration": 3600,
            "fields": {"state": {"type": "dropdown", "value": state}},
        },
        "relationships": {
            "commander_user": {"data": {"id": commander, "type": "users"}},
            "created_by_user": {"data": {"id": "00000000-0000-0000-0000-0000000000aa", "type": "users"}},
        },
    }


def test_incident_commander_comes_from_relationships():
    record = incidents_list.extract_incident_fields(incident("inc-1"))
    assert record["commander_id"] == "00000000-0000-0000-0000-00000000c0de"


def test_incident_commander_without_relationship_is_null():
    raw = incident("inc-1")
    raw["relationships"]["commander_user"] = {"data": None}
    assert incidents_list.extract_incident_fields(raw)["commander_id"] is None


def test_incident_commander_falls_back_to_legacy_attribute():
    raw = incident("inc-1")
    del raw["relationships"]
    raw["attributes"]["commander"] = {"data": {"id": "legacy-user", "type": "users"}}
    assert incidents_list.extract_incident_fields(raw)["commander_id"] == "legacy-user"


def test_resolution_hours_reads_fractional_second_timestamps():
    record = incidents_list.extract_incident_fields(incident("inc-1"))
    assert record["resolution_hours"] == 3.5


@pytest.mark.parametrize(
    "detected, resolved, hours",
    [
        ("2026-09-19T10:00:00Z", "2026-09-19T12:00:00Z", 2.0),
        ("2026-09-19T10:00:00.123456Z", "2026-09-19T11:00:00.123456Z", 1.0),
        ("2026-09-19T10:00:00+00:00", "2026-09-19T10:30:00.000Z", 0.5),
        ("2026-09-19T10:00:00.000Z", None, None),
        ("not a time", "2026-09-19T10:30:00.000Z", None),
    ],
)
def test_parse_resolution_hours(detected, resolved, hours):
    assert incidents_list.parse_resolution_hours(detected, resolved) == hours


def test_incident_status_reads_state():
    record = incidents_list.extract_incident_fields(incident("inc-1", state="active"))
    assert record["status"] == "active"


def test_incident_status_falls_back_to_state_field():
    raw = incident("inc-1", state="stable")
    del raw["attributes"]["state"]
    assert incidents_list.extract_incident_fields(raw)["status"] == "stable"


def test_incidents_summary_averages_resolution_hours(monkeypatch):
    raw = [
        incident("inc-1", resolved="2026-09-19T12:00:00.000Z"),  # 2.0 h
        incident("inc-2", resolved="2026-09-19T14:00:00.000Z"),  # 4.0 h
        incident("inc-3", state="active", resolved=None),
    ]
    monkeypatch.setattr(incidents_list, "fetch_all_incidents", lambda *a, **k: raw)
    result = incidents_list.get_incidents_list()
    assert result["status"] == "success"
    assert result["summary"]["avg_resolution_hours"] == 3.0
    assert result["summary"]["incidents_by_status"] == {"resolved": 2, "active": 1}
    assert [r["commander_id"] for r in result["data"]] == ["00000000-0000-0000-0000-00000000c0de"] * 3


# --- incident_timelines ----------------------------------------------------


def test_timeline_cell_keeps_markdown_content():
    cell = {
        "id": "cell-1",
        "type": "incident_timeline_cells",
        "attributes": {
            "cell_type": "markdown",
            "content": {"content": "Rolled back the 14:02 deploy; latency recovered."},
            "important": True,
            "created": "2026-09-19T11:00:00.000Z",
            "modified": "2026-09-19T11:05:00.000Z",
        },
        "relationships": {"created_by_user": {"data": {"id": "user-1", "type": "users"}}},
    }
    record = incident_timelines.extract_cell_fields(cell)
    assert record["content"] == "Rolled back the 14:02 deploy; latency recovered."
    assert record["important"] is True
    assert record["cell_type"] == "markdown"
    assert record["created_by_id"] == "user-1"
    assert record["content_raw"] is None


def test_timeline_cell_keeps_unknown_content_object():
    cell = {"attributes": {"cell_type": "incident_status_change", "content": {"from": "active", "to": "stable"}},
            "relationships": {"created_by": {"data": {"id": "user-2"}}}}
    record = incident_timelines.extract_cell_fields(cell)
    assert record["content"] is None
    assert record["content_raw"] == {"from": "active", "to": "stable"}
    assert record["created_by_id"] == "user-2"


# --- log_archives ----------------------------------------------------------


def archive(archive_id: str, state: str, destination: Dict[str, Any], include_tags: bool = False) -> Dict[str, Any]:
    """Shape of one data[] item from GET /api/v2/logs/config/archives."""
    return {
        "id": archive_id,
        "type": "archives",
        "attributes": {
            "name": f"archive-{archive_id}",
            "query": "source:nginx",
            "state": state,
            "include_tags": include_tags,
            "compression_method": "ZSTD",
            "destination": destination,
        },
    }


AZURE_DEST = {
    "type": "azure",
    "container": "logs-container",
    "storage_account": "examplestorage",
    "path": "/archive",
    "region": "eastus",
    "integration": {"client_id": "aaaaaaaa-1111-2222-3333-444444444444", "tenant_id": "bbbbbbbb-1111-2222-3333-444444444444"},
}
S3_DEST = {"type": "s3", "bucket": "example-log-bucket", "path": "/dd",
           "integration": {"account_id": "000000000000", "role_name": "DatadogArchive"}}


def test_archive_reads_include_tags_snake_case():
    assert log_archives.extract_archive_fields(archive("a1", "WORKING", S3_DEST, include_tags=True))["includeTags"] is True
    # A real False stays False, not null.
    assert log_archives.extract_archive_fields(archive("a1", "WORKING", S3_DEST, include_tags=False))["includeTags"] is False


def test_archive_reads_azure_storage_account():
    record = log_archives.extract_archive_fields(archive("a1", "WORKING", AZURE_DEST))
    assert record["storage_account"] == "examplestorage"
    assert record["storage_location"] == "logs-container"
    assert record["destination_type"] == "azure"


def test_archive_azure_without_container_falls_back_to_storage_account():
    dest = {k: v for k, v in AZURE_DEST.items() if k != "container"}
    assert log_archives.extract_archive_fields(archive("a1", "WORKING", dest))["storage_location"] == "examplestorage"


def test_enabled_archives_counts_working_states(monkeypatch):
    body = {"data": [
        archive("a1", "WORKING", S3_DEST),
        archive("a2", "WORKING_AUTH_LEGACY", S3_DEST),
        archive("a3", "FAILING", AZURE_DEST),
        archive("a4", "UNKNOWN", AZURE_DEST),
    ]}
    monkeypatch.setattr(log_archives.requests, "get", lambda *a, **k: FakeResponse(body))
    result = log_archives.get_log_archives()
    assert result["summary"]["enabled_archives"] == 2
    assert result["summary"]["archives_by_state"] == {
        "WORKING": 1, "WORKING_AUTH_LEGACY": 1, "FAILING": 1, "UNKNOWN": 1,
    }


# --- log_indexes -----------------------------------------------------------


def index(name: str, query: str, retention: int) -> Dict[str, Any]:
    """Shape of one indexes[] item from GET /api/v1/logs/config/indexes."""
    return {
        "name": name,
        "filter": {"query": query},
        "num_retention_days": retention,
        "num_flex_logs_retention_days": 360,
        "daily_limit": 300000000,
        "is_rate_limited": False,
        "exclusion_filters": [],
        "tags": ["team:security"],
    }


INDEXES = {"indexes": [
    index("main", "*", 15),
    index("cloudtrail", "source:cloudtrail", 365),
    index("auditd", "source:auditd", 30),
]}


def _run_indexes(monkeypatch) -> Dict[str, Any]:
    monkeypatch.setattr(log_indexes.requests, "get", lambda *a, **k: FakeResponse(INDEXES))
    return log_indexes.get_log_indexes()


def test_audit_indexes_default_to_every_index(monkeypatch):
    summary = _run_indexes(monkeypatch)["summary"]
    assert summary["audit_index_selection"] == "all_indexes"
    assert summary["audit_indexes"] == ["main", "cloudtrail", "auditd"]
    # An audit source the old keyword list missed (auditd) is no longer dropped.
    assert summary["audit_indexes_below_90_days"] == 2
    assert summary["min_retention_days_audit_indexes"] == 15
    assert all(i["is_audit_index"] for i in summary["indexes_summary"])


def test_audit_indexes_from_config(monkeypatch):
    monkeypatch.setenv("DATADOG_AUDIT_INDEXES", "cloudtrail, auditd missing-index")
    result = _run_indexes(monkeypatch)
    summary = result["summary"]
    assert summary["audit_index_selection"] == "configured"
    assert summary["audit_indexes"] == ["cloudtrail", "auditd"]
    assert summary["audit_indexes_not_found"] == ["missing-index"]
    assert summary["audit_indexes_below_90_days"] == 1
    assert summary["min_retention_days_audit_indexes"] == 30
    assert {r["name"]: r["is_audit_index"] for r in result["data"]} == {
        "main": False, "cloudtrail": True, "auditd": True,
    }
    # Every index still reports its retention.
    assert summary["indexes_below_90_days"] == 2
    assert summary["min_retention_days"] == 15


def test_audit_indexes_configured_but_none_found(monkeypatch):
    monkeypatch.setenv("DATADOG_AUDIT_INDEXES", "nope")
    summary = _run_indexes(monkeypatch)["summary"]
    assert summary["audit_indexes"] == []
    assert summary["min_retention_days_audit_indexes"] is None
    assert summary["audit_indexes_below_90_days"] == 0


# --- monitors_list ---------------------------------------------------------


def monitor(message: str) -> Dict[str, Any]:
    """Shape of one item from GET /api/v1/monitor."""
    return {
        "id": 12345,
        "name": "High CPU",
        "type": "query alert",
        "query": "avg(last_5m):avg:system.cpu.user{env:prod} by {host} > 90",
        "message": message,
        "overall_state": "OK",
        "tags": ["env:prod"],
        "options": {
            "thresholds": {"critical": 90, "warning": 80},
            "notify_no_data": True,
            "no_data_timeframe": 10,
        },
    }


def test_monitor_options_are_read_from_options():
    record = monitors_list.extract_monitor_fields(monitor("CPU high @slack-ops"))
    assert record["thresholds"] == {"critical": 90, "warning": 80}
    assert record["notify_no_data"] is True
    assert record["no_data_timeframe"] == 10


def test_monitor_notify_no_data_false_is_kept():
    raw = monitor("x")
    raw["options"]["notify_no_data"] = False
    assert monitors_list.extract_monitor_fields(raw)["notify_no_data"] is False


def test_monitor_message_is_not_truncated():
    long_text = "Runbook: " + "check the dashboard and the logs. " * 10
    message = long_text + "\n{{#is_alert}}@pagerduty-Infra @oncall@example.com{{/is_alert}}"
    assert len(message) > 200
    record = monitors_list.extract_monitor_fields(monitor(message))
    assert record["message"] == message
    assert record["notification_targets"] == ["pagerduty-Infra", "oncall@example.com"]


def test_monitor_query_is_not_truncated():
    raw = monitor("x")
    raw["query"] = "avg(last_5m):" + "+".join(f"avg:metric.{i}{{*}}" for i in range(40)) + " > 1"
    assert len(raw["query"]) > 200
    assert monitors_list.extract_monitor_fields(raw)["query"] == raw["query"]


@pytest.mark.parametrize(
    "message, targets",
    [
        ("Disk full. @slack-ops @pagerduty-Storage", ["slack-ops", "pagerduty-Storage"]),
        ("@webhook-soar, @user@example.com.", ["webhook-soar", "user@example.com"]),
        ("Mail admin@example.com if unsure", []),
        ("@slack-ops and again @slack-ops", ["slack-ops"]),
        ("{{#is_alert}}@pagerduty-Infra{{/is_alert}}{{#is_warning}}@slack-ops{{/is_warning}}",
         ["pagerduty-Infra", "slack-ops"]),
        ("Escalate (@teams-SecOps)", ["teams-SecOps"]),
        ("", []),
    ],
)
def test_notification_targets(message, targets):
    assert monitors_list.extract_notification_targets(message) == targets


# --- siem_detection_rules --------------------------------------------------


def rule(updated_ms: int) -> Dict[str, Any]:
    """Shape of one data[] item from GET /api/v2/security_monitoring/rules (flat, not JSON:API)."""
    return {
        "id": "abc-def-ghi",
        "name": "Brute force on login",
        "type": "log_detection",
        "isEnabled": True,
        "isDefault": False,
        "hasExtendedTitle": True,
        "createdAt": updated_ms - 1000,
        "updatedAt": updated_ms,
        "options": {"detectionMethod": "threshold", "evaluationWindow": 300, "keepAlive": 3600},
        "queries": [{
            "name": "a",
            "query": "source:auth @evt.outcome:failure",
            "aggregation": "count",
            "dataSource": "logs",
            "groupByFields": ["@usr.id"],
            "distinctFields": [],
        }],
        "cases": [{
            "name": "many failures",
            "status": "high",
            "condition": "a > 10",
            "notifications": ["@slack-security"],
        }],
    }


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def test_rule_keeps_detection_method_queries_and_cases():
    record = siem_detection_rules.extract_rule_fields(rule(_ms(datetime.now(timezone.utc))))
    assert record["detection_method"] == "threshold"
    assert record["queries"] == [{
        "name": "a",
        "query": "source:auth @evt.outcome:failure",
        "data_source": "logs",
        "aggregation": "count",
        "group_by_fields": ["@usr.id"],
        "distinct_fields": [],
        "metrics": [],
    }]
    assert record["cases"] == [{
        "name": "many failures", "status": "high", "condition": "a > 10", "notifications": ["@slack-security"],
    }]
    assert record["severities"] == ["high"]


def test_rules_summary_counts_epoch_millisecond_updates(monkeypatch):
    now = datetime.now(timezone.utc)
    rules = [rule(_ms(now - timedelta(days=5))), rule(_ms(now - timedelta(days=200)))]
    monkeypatch.setattr(siem_detection_rules, "fetch_all_rules", lambda *a, **k: rules)
    summary = siem_detection_rules.get_siem_detection_rules()["summary"]
    assert summary["rules_updated_last_90_days"] == 1
    # Removed: the rules API reports nothing about when a rule last fired.
    assert "rules_never_triggered_count" not in summary


@pytest.mark.parametrize(
    "value, expected",
    [
        (1758276000000, datetime(2025, 9, 19, 10, 0, tzinfo=timezone.utc)),
        ("2025-09-19T10:00:00.000Z", datetime(2025, 9, 19, 10, 0, tzinfo=timezone.utc)),
        (None, None),
        (True, None),
        ("garbage", None),
    ],
)
def test_parse_rule_time(value, expected):
    assert siem_detection_rules.parse_rule_time(value) == expected


# --- siem_signals ----------------------------------------------------------


def search_signal() -> Dict[str, Any]:
    """Shape of one data[] item from POST /api/v2/security_monitoring/signals/search."""
    return {
        "id": "AAAAAWgN8Xwgr1vKDQAAAABBV2dOOFh3ZzZobm1mWXJFYTR0OA",
        "type": "signal",
        "attributes": {
            "message": "Detect Account Take Over (ATO) through brute force attempts",
            "tags": ["security:attack", "technique:T1110-brute-force"],
            "timestamp": "2026-09-19T14:46:01.000Z",
            "attributes": {
                "status": "high",
                "workflow": {
                    "first_seen": "2026-09-19T14:46:01.000Z",
                    "last_seen": "2026-09-19T14:46:49.000Z",
                    "rule": {"id": "0f5-e0c-805", "name": "Brute Force Attack Grouped By User", "version": 12},
                    "triage": {"state": "under_review"},
                },
            },
        },
    }


def test_signal_reads_nested_attributes():
    record = siem_signals.extract_signal_fields(search_signal())
    assert record["severity"] == "high"
    assert record["status"] == "under_review"
    assert record["rule_id"] == "0f5-e0c-805"
    assert record["rule_name"] == "Brute Force Attack Grouped By User"
    assert record["timestamp"] == "2026-09-19T14:46:01.000Z"


def test_signal_reads_custom_attributes():
    raw = search_signal()
    raw["attributes"]["custom"] = raw["attributes"].pop("attributes")
    record = siem_signals.extract_signal_fields(raw)
    assert (record["severity"], record["status"], record["rule_id"]) == ("high", "under_review", "0f5-e0c-805")


def test_signal_missing_fields_are_null():
    record = siem_signals.extract_signal_fields({"id": "s1", "attributes": {"timestamp": "2026-09-19T14:46:01.000Z"}})
    assert (record["severity"], record["status"], record["rule_id"], record["rule_name"]) == (None, None, None, None)


def test_signals_summary_counts(monkeypatch):
    first = search_signal()
    b = json.loads(json.dumps(search_signal()))
    b["attributes"]["attributes"]["status"] = "low"
    b["attributes"]["attributes"]["workflow"]["triage"]["state"] = "archived"
    monkeypatch.setattr(siem_signals, "fetch_all_signals", lambda *args, **kwargs: [first, b])
    summary = siem_signals.get_siem_signals()["summary"]
    assert summary["severity_counts"] == {"high": 1, "low": 1}
    assert summary["status_counts"] == {"under_review": 1, "archived": 1}
    assert summary["top_triggering_rules"] == [{"rule_name": "Brute Force Attack Grouped By User", "count": 2}]


def test_evidence_written_only_under_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(siem_signals, "fetch_all_signals", lambda *a, **k: [search_signal()])
    assert siem_signals.main() == 0
    written: List[Path] = list(tmp_path.iterdir())
    assert [p.name for p in written] == ["datadog_siem_signals.json"]
    assert json.loads(written[0].read_text())["data"][0]["severity"] == "high"
