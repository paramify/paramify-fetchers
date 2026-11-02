"""azure_sql_managed_instance_backups failover history: Activity Log events grouped into failovers, and a read that
fails or is cut reading null."""

from __future__ import annotations

import importlib.util
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "sql_managed_instance_backups" / "fetcher.py"
sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))

spec = importlib.util.spec_from_file_location("azure_sql_mi_failover_history_under_test", FETCHER)
backups = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backups)
Collector = sys.modules["azure_common"].Collector

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
RG = "/subscriptions/s1/resourceGroups/rg-a"
GROUP = f"{RG}/providers/Microsoft.Sql/locations/regionwest/instanceFailoverGroups/fog-a"
OTHER_VIEW = f"{RG}/providers/Microsoft.Sql/locations/regioneast/instanceFailoverGroups/fog-a"
INSTANCE = f"{RG}/providers/Microsoft.Sql/managedInstances/mi-a"
GROUP_FAILOVER = "Microsoft.Sql/locations/instanceFailoverGroups/failover/action"


def _event(resource_id, status, minute, correlation="c1", caller=None, operation=GROUP_FAILOVER):
    return {"operation": operation, "status": status, "caller": caller, "caller_type": "user" if caller else None,
            "resource_id": resource_id, "correlation_id": correlation, "event_id": f"{correlation}-{minute}",
            "time": (NOW + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")}


def test_failover_target_reads_kind_name_and_region_in_any_case():
    assert backups.failover_target(GROUP.upper()) == ("failover_group", "FOG-A", "REGIONWEST")
    assert backups.failover_target(INSTANCE) == ("managed_instance", "mi-a", None)
    assert backups.failover_target(f"{RG}/providers/Microsoft.Web/sites/app") == (None, None, None)


def test_a_failover_runs_from_its_first_event_to_its_final_status():
    [record] = backups.failover_records([
        _event(GROUP, "Accepted", 1), _event(GROUP, "Started", 0, caller="ops@example.com"),
        _event(GROUP, "Succeeded", 7)])
    assert (record["start_time"], record["end_time"], record["duration_minutes"]) == (
        "2026-10-01T00:00:00Z", "2026-10-01T00:07:00Z", 7.0)
    assert (record["status"], record["succeeded"], record["allows_data_loss"], record["new_primary_location"],
            record["caller"]) == ("Succeeded", True, False, "regionwest", "ops@example.com")


def test_a_failover_without_a_final_status_has_no_end_and_did_not_succeed():
    [record] = backups.failover_records([_event(GROUP, "Started", 0, caller="ops@example.com")])
    assert (record["status"], record["succeeded"], record["end_time"], record["duration_minutes"]) == (
        "Started", False, None, None)


def test_separate_requests_stay_separate_and_other_operations_are_ignored():
    records = backups.failover_records([
        _event(GROUP, "Succeeded", 0, "c1"), _event(GROUP, "Failed", 30, "c2"),
        _event(INSTANCE, "Succeeded", 60, "c3", operation="Microsoft.Sql/managedInstances/failover/action"),
        _event(INSTANCE, "Succeeded", 90, "c4", operation="Microsoft.Sql/managedInstances/write"),
    ])
    assert [(r["kind"], r["status"], r["allows_data_loss"]) for r in records] == [
        ("managed_instance", "Succeeded", None), ("failover_group", "Failed", False),
        ("failover_group", "Succeeded", False)]


def test_one_request_logged_on_both_regional_views_is_one_failover():
    [record] = backups.failover_records([
        _event(GROUP, "Started", 0, caller="ops@example.com"), _event(OTHER_VIEW, "Succeeded", 4)])
    assert (record["new_primary_location"], record["duration_minutes"]) == ("regionwest", 4.0)


def test_forced_failover_allows_data_loss():
    [record] = backups.failover_records([_event(
        GROUP, "Succeeded", 0, operation="Microsoft.Sql/locations/instanceFailoverGroups/forceFailoverAllowDataLoss/action")])
    assert record["allows_data_loss"] is True


@pytest.mark.parametrize("raw, days", [(None, 90), ("30", 30), ("0", 1), ("365", 90), ("soon", 90)])
def test_failover_history_days_stay_within_the_activity_log(monkeypatch, raw, days):
    if raw is None:
        monkeypatch.delenv(backups.FAILOVER_DAYS_ENV, raising=False)
    else:
        monkeypatch.setenv(backups.FAILOVER_DAYS_ENV, raw)
    assert backups.failover_history_days() == days


def _monitor(monkeypatch, events):
    queries = []

    def activity_logs(filter):
        queries.append(filter)
        return iter(events)

    monkeypatch.setattr(backups, "monitor_client", lambda *a: ns(activity_logs=ns(list=activity_logs)))
    return queries


def test_read_names_both_ends_of_the_window_and_keeps_only_failover_events(monkeypatch):
    event = ns(operation_name=ns(value=GROUP_FAILOVER), status=ns(value="Succeeded"), caller=None, claims=None,
               resource_id=GROUP, correlation_id="c1", event_data_id="e1", event_timestamp=NOW)
    other = ns(operation_name=ns(value="Microsoft.Sql/managedInstances/write"), status=ns(value="Succeeded"))
    queries = _monitor(monkeypatch, [event, other])
    events, window = backups.read_failover_history("s1", object(), Collector(logging.getLogger("t")), 30, NOW)
    assert queries == ["eventTimestamp ge '2026-09-01T00:00:00Z' and eventTimestamp le '2026-10-01T00:00:00Z' "
                       "and resourceProvider eq 'Microsoft.Sql'"]
    assert [e["time"] for e in events] == ["2026-10-01T00:00:00Z"]
    assert (window["complete"], window["events_read"], window["days"]) == (True, 2, 30)


def test_a_read_cut_at_the_event_limit_reads_null(monkeypatch):
    monkeypatch.setattr(backups, "ACTIVITY_LOG_MAX_EVENTS", 1)
    _monitor(monkeypatch, [ns(), ns()])
    events, window = backups.read_failover_history("s1", object(), Collector(logging.getLogger("t")), 90, NOW)
    assert events is None and (window["complete"], window["cut_reason"]) == (False, "max_events")


def test_real_sdk_event_projects():
    models = pytest.importorskip("azure.mgmt.monitor.v2015_04_01.models")
    event = models.EventData.deserialize({
        "operationName": {"value": GROUP_FAILOVER}, "status": {"value": "Succeeded"}, "caller": "ops@example.com",
        "claims": {"idtyp": "user"}, "resourceId": GROUP, "correlationId": "c1", "eventDataId": "e1",
        "eventTimestamp": "2026-09-26T00:12:00.1234567Z"})
    assert backups.project_event(event) == {
        "operation": GROUP_FAILOVER, "status": "Succeeded", "caller": "ops@example.com", "caller_type": "user",
        "resource_id": GROUP, "correlation_id": "c1", "event_id": "e1", "time": "2026-09-26T00:12:00Z"}
