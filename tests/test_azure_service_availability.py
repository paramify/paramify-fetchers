"""azure_service_availability: Resource Health timelines, outage windows, health-check results, scope. Synthetic, no network."""

from __future__ import annotations

import importlib.util
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_service_availability_under_test",
                                               AZURE / "service_availability" / "fetcher.py")
sa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sa)
azure_rest = sys.modules["azure_rest"]
Collector = sys.modules["azure_common"].Collector

NOW = datetime(2026, 6, 30, 12, 30, tzinfo=timezone.utc)
WINDOW_START = NOW - timedelta(days=30)
SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg1"
RG_OUT = f"{SUB}/resourceGroups/rg-out"
WEB = f"{RG}/providers/Microsoft.Web/sites/web1"
FUNC = f"{RG}/providers/Microsoft.Web/sites/func1"
WEB_OUT = f"{RG_OUT}/providers/Microsoft.Web/sites/web2"
FD = f"{RG}/providers/Microsoft.Cdn/profiles/fd1"
CDN = f"{RG}/providers/Microsoft.Cdn/profiles/cdn1"
MI = f"{RG}/providers/Microsoft.Sql/managedInstances/mi1"


def ts(delta: timedelta) -> str:
    return (NOW - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def status(state, ago, name=None, **props):
    """One availabilityStatus, `ago` before NOW."""
    body = {"availabilityState": state, "occuredTime": ts(ago), **props}
    return {"id": f"{WEB}/providers/Microsoft.ResourceHealth/availabilityStatuses/{name or ago}", "properties": body}


INCIDENT = {"correlationId": "TRK-1", "eventStartTime": ts(timedelta(days=10)), "status": {"value": "Resolved"},
            "incidentProperties": {"title": "Networking issue", "service": "App Service", "region": "East US 2",
                                   "incidentType": "Outage"}}


def outage_history():
    return [
        status("Available", timedelta(days=60), "old", context="Platform Initiated"),
        status("Unavailable", timedelta(days=10), "down", context="Platform Initiated", reasonType="Unplanned",
               title="Unavailable", serviceImpactingEvents=[INCIDENT]),
        status("Available", timedelta(days=10) - timedelta(hours=2), "up"),
        status("Available", timedelta(minutes=5), "current", reportedTime=ts(timedelta(minutes=1)),
               recentlyResolved={"unavailableOccuredTime": ts(timedelta(days=10)),
                                 "resolvedTime": ts(timedelta(days=10) - timedelta(hours=2))}),
    ]


# --- Resource Health timelines ---

def test_an_always_available_resource_has_no_outage_and_full_availability():
    h = sa.health_record([status("Available", timedelta(days=60))], NOW, WINDOW_START)
    assert (h["status"], h["current_state"], h["outages"], h["longest_outage_hours"]) == (sa.READ, "Available", 0, 0.0)
    assert (h["availability_percentage"], h["observed_hours"], h["windows"]) == (100.0, 720.0, [])


def test_an_outage_is_measured_from_unavailable_to_available_with_its_incident():
    h = sa.health_record(outage_history(), NOW, WINDOW_START)
    assert (h["outages"], h["longest_outage_hours"], h["unavailable_hours_in_window"]) == (1, 2.0, 2.0)
    [window] = h["windows"]
    assert (window["state"], window["start"], window["end"], window["ongoing"], window["initiated_by"]) == (
        "Unavailable", ts(timedelta(days=10)), ts(timedelta(days=10) - timedelta(hours=2)), False, "platform")
    assert window["service_impacting_events"] == [{
        "correlation_id": "TRK-1", "title": "Networking issue", "service": "App Service", "region": "East US 2",
        "incident_type": "Outage", "status": "Resolved", "started": ts(timedelta(days=10)), "last_modified": None}]
    assert h["service_impacting_events"] == window["service_impacting_events"]
    assert h["availability_percentage"] == round(100 * (720 - 2) / 720, 3)
    assert h["recently_resolved"]["resolved"] == ts(timedelta(days=10) - timedelta(hours=2))
    assert h["last_checked"] == ts(timedelta(minutes=1))


def test_adjacent_statuses_in_the_same_state_merge_and_duplicates_count_once():
    history = outage_history()
    history.insert(2, status("Unavailable", timedelta(days=10) - timedelta(hours=1), "still-down"))
    history.append(history[1])
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["outages"], h["longest_outage_hours"]) == (1, 2.0)


def test_a_period_the_customer_started_is_listed_but_is_not_an_outage():
    history = [
        status("Available", timedelta(days=60), "a"),
        status("Unavailable", timedelta(days=5), "stop", context="Customer Initiated", reasonType="UserInitiated"),
        status("Available", timedelta(days=4), "b"),
    ]
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["outages"], h["longest_outage_hours"], h["customer_initiated_unavailable_windows"]) == (0, 0.0, 1)
    assert (h["windows"][0]["initiated_by"], h["availability_percentage"]) == ("customer", 100.0)


def test_an_ongoing_outage_runs_until_the_run_and_the_resource_is_not_available():
    history = [status("Available", timedelta(days=40), "a"),
               status("Unavailable", timedelta(hours=3), "down", reasonType="Unplanned")]
    record = sa.resource_record({"id": WEB}, sa.health_record(history, NOW, WINDOW_START), None, 1.0)
    assert (record["available_now"], record["resource_health"]["ongoing_outage"]) == (False, True)
    assert (record["longest_outage_hours"], record["meets_recovery_time_objective"]) == (3.0, False)
    assert record["resource_health"]["windows"][0]["end"] is None


def test_an_outage_that_began_before_the_lookback_keeps_its_full_length():
    history = [status("Unavailable", timedelta(days=31), "down", reasonType="Unplanned"),
               status("Available", timedelta(days=29), "up")]
    h = sa.health_record(history, NOW, WINDOW_START)
    [window] = h["windows"]
    assert (window["duration_hours"], window["hours_in_window"]) == (48.0, 24.0)
    assert (h["longest_outage_hours"], h["unavailable_hours_in_window"]) == (48.0, 24.0)


def test_an_outage_that_ended_before_the_lookback_is_left_out():
    history = [status("Unavailable", timedelta(days=40), "down", reasonType="Unplanned"),
               status("Available", timedelta(days=39), "up")]
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["outages"], h["windows"], h["availability_percentage"]) == (0, [], 100.0)


def test_degraded_and_unknown_periods_are_windows_but_not_outages():
    history = [status("Available", timedelta(days=40), "a"),
               status("Degraded", timedelta(days=3), "slow"),
               status("Unknown", timedelta(days=2), "quiet"),
               status("Available", timedelta(days=1), "b")]
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["outages"], h["degraded_windows"], h["unknown_windows"]) == (0, 1, 1)
    assert (h["degraded_hours_in_window"], h["unknown_hours_in_window"]) == (24.0, 24.0)
    assert h["availability_percentage"] == 100.0


def test_unknown_hours_are_not_counted_as_available():
    history = [status("Available", timedelta(days=40), "a"),
               status("Unknown", timedelta(days=20), "quiet"),
               status("Available", timedelta(days=10), "b"),
               status("Unavailable", timedelta(days=5), "down", reasonType="Unplanned"),
               status("Available", timedelta(days=5) - timedelta(hours=24), "up")]
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["observed_hours"], h["unknown_hours_in_window"], h["known_hours"]) == (720.0, 240.0, 480.0)
    assert h["availability_percentage"] == 95.0
    assert (h["longest_unknown_hours"], h["longest_outage_hours"]) == (240.0, 24.0)


@pytest.mark.parametrize("history, rto, expected", [
    # An ongoing outage longer than the objective misses it.
    ([status("Available", timedelta(days=40), "a"), status("Unavailable", timedelta(hours=30), "down")], 24.0, False),
    # A finished outage longer than the objective misses it, whatever else happened.
    ([status("Available", timedelta(days=40), "a"), status("Unavailable", timedelta(days=3), "down"),
      status("Available", timedelta(days=3) - timedelta(hours=25), "up"), status("Unknown", timedelta(days=1), "q")],
     24.0, False),
    # An Unknown period longer than the objective could hide a miss.
    ([status("Available", timedelta(days=40), "a"), status("Unknown", timedelta(days=20), "q"),
      status("Available", timedelta(days=6), "b")], 24.0, None),
    # Degraded still serves, so a long Degraded period is not a miss.
    ([status("Available", timedelta(days=40), "a"), status("Degraded", timedelta(days=3), "slow"),
      status("Available", timedelta(days=1), "b")], 24.0, True),
    # Nothing known in the lookback: unknown.
    ([status("Unknown", timedelta(minutes=1), "q")], 24.0, None),
    # Unknown right after an outage may be the same outage: 20 h + 18 h could be a 38 h miss.
    ([status("Available", timedelta(days=40), "a"), status("Unavailable", timedelta(hours=60), "down"),
      status("Unknown", timedelta(hours=40), "q"), status("Available", timedelta(hours=22), "b")], 24.0, None),
    # Unknown right before an outage may hide its start.
    ([status("Available", timedelta(days=40), "a"), status("Unknown", timedelta(hours=60), "q"),
      status("Unavailable", timedelta(hours=42), "down"), status("Available", timedelta(hours=22), "b")], 24.0, None),
    # Available between them: the outage is known to be 20 h.
    ([status("Available", timedelta(days=40), "a"), status("Unavailable", timedelta(hours=60), "down"),
      status("Available", timedelta(hours=40), "b"), status("Unknown", timedelta(hours=39), "q"),
      status("Available", timedelta(hours=21), "c")], 24.0, True),
])
def test_recovery_time_objective_cases(history, rto, expected):
    assert sa.meets_objective(sa.health_record(history, NOW, WINDOW_START), rto) is expected


def test_an_outage_and_the_unknown_time_touching_it_are_measured_together():
    history = [status("Available", timedelta(days=40), "a"), status("Unknown", timedelta(hours=70), "q1"),
               status("Unavailable", timedelta(hours=60), "down"), status("Unknown", timedelta(hours=40), "q2"),
               status("Degraded", timedelta(hours=22), "slow"), status("Unknown", timedelta(hours=20), "q3"),
               status("Available", timedelta(hours=1), "b")]
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["longest_outage_hours"], h["longest_outage_with_adjacent_unknown_hours"]) == (20.0, 48.0)


def test_a_resource_with_no_known_hours_has_no_outage_figures():
    for history in ([status("Unknown", timedelta(0), "current")], [status("Unknown", timedelta(days=40), "q")]):
        h = sa.health_record(history, NOW, WINDOW_START)
        assert h["known_hours"] == 0
        assert all(h[k] is None for k in ("outages", "longest_outage_hours", "ongoing_outage",
                                          "unavailable_hours_in_window", "availability_percentage",
                                          "longest_outage_with_adjacent_unknown_hours"))
        assert h["windows_total"] == 1 and h["customer_initiated_unavailable_windows"] == 0


def test_history_that_starts_inside_the_lookback_is_flagged():
    assert sa.health_record([status("Available", timedelta(days=5))], NOW, WINDOW_START)["history_starts_in_lookback"]
    assert not sa.health_record([status("Available", timedelta(days=60))], NOW, WINDOW_START)["history_starts_in_lookback"]


def test_front_door_periods_are_origin_probe_failures_not_outages():
    history = [status("Available", timedelta(days=40), "a"),
               status("Unavailable", timedelta(days=3), "down", title="Unavailable Backends", reasonType="Unplanned"),
               status("Degraded", timedelta(days=2), "slow", reasonType="Unplanned"),
               status("Available", timedelta(days=1), "b"),
               status("Unavailable", timedelta(hours=2), "again", reasonType="Unplanned")]
    h = sa.health_record(history, NOW, WINDOW_START, origin_driven=True)
    assert h["signal"] == sa.ORIGIN_PROBES
    assert all(h[k] is None for k in ("outages", "longest_outage_hours", "availability_percentage", "ongoing_outage"))
    assert (h["origin_probe_failure_windows"], h["origin_probe_failure_hours_in_window"]) == (3, 50.0)
    assert (h["longest_origin_probe_failure_hours"], h["failing_origin_probes_now"]) == (24.0, True)
    assert not any(w["counts_as_outage"] for w in h["windows"])
    record = sa.resource_record({"id": FD}, h, None, 1.0)
    assert (record["available_now"], record["meets_recovery_time_objective"]) == (None, None)


def test_only_the_newest_windows_are_listed_but_every_one_is_counted():
    history = [status("Available", timedelta(days=40), "a")]
    for i in range(120):
        down = timedelta(days=25) - timedelta(hours=4 * i)
        history += [status("Unavailable", down, f"d{i}", reasonType="Unplanned"),
                    status("Available", down - timedelta(hours=1), f"u{i}")]
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["outages"], h["windows_total"], h["windows_listed"], len(h["windows"])) == (120, 120, 100, 100)
    assert h["windows"][-1]["start"] == ts(timedelta(days=25) - timedelta(hours=4 * 119))


def test_a_degraded_resource_still_counts_as_available_now():
    h = sa.health_record([status("Degraded", timedelta(hours=1))], NOW, WINDOW_START)
    assert sa.available_now(h) is True


def test_statuses_without_a_state_are_events_inside_their_window():
    history = outage_history()
    history.append({"id": "evt", "properties": {"availabilityState": None, "occuredTime": ts(timedelta(days=10) - timedelta(hours=1)),
                                                "title": "Root cause", "healthEventCause": "PlatformInitiated"}})
    history.append({"id": "untimed", "properties": {"availabilityState": "Available"}})
    h = sa.health_record(history, NOW, WINDOW_START)
    assert [e["title"] for e in h["windows"][0]["health_events"]] == ["Root cause"]
    assert (h["outages"], h["statuses_without_time"]) == (1, 1)


def test_the_corrected_occurred_time_spelling_is_read_too():
    history = [{"id": "a", "properties": {"availabilityState": "Available", "occurredTime": ts(timedelta(days=2))}}]
    h = sa.health_record(history, NOW, WINDOW_START)
    assert (h["current_state"], h["history_from"]) == ("Available", ts(timedelta(days=2)))
    assert h["observed_hours"] == 48.0


def test_an_empty_history_is_no_data_and_every_figure_is_unknown():
    h = sa.health_record([], NOW, WINDOW_START)
    assert h["status"] == sa.NO_DATA
    assert all(h[k] is None for k in ("current_state", "outages", "longest_outage_hours", "availability_percentage"))
    record = sa.resource_record({"id": WEB}, h, None, 4.0)
    assert (record["available_now"], record["meets_recovery_time_objective"]) == (None, None)


@pytest.mark.parametrize("rto, expected", [(1.0, False), (2.0, True), (4.0, True), (None, None)])
def test_meets_objective(rto, expected):
    assert sa.meets_objective(sa.health_record(outage_history(), NOW, WINDOW_START), rto) is expected


@pytest.mark.parametrize("props, expected", [
    ({"context": "Platform Initiated"}, "platform"),
    ({"healthEventCause": "PlatformInitiated"}, "platform"),
    ({"reasonType": "Unplanned", "context": "Not Applicable"}, "unknown"),
    ({"reasonType": "Planned"}, "unknown"),
    ({"context": "Customer Initiated"}, "customer"),
    ({"reasonType": "UserInitiated"}, "customer"),
    ({}, "unknown"),
])
def test_initiated_by(props, expected):
    assert sa.initiated_by(props) == expected


@pytest.mark.parametrize("exc, expected", [
    (azure_rest.ArmError(403, "AuthorizationFailed", "no"), sa.NOT_AUTHORIZED),
    (azure_rest.ArmError(409, "AuthError", "Make sure the resource provider has been registered"), sa.NOT_REGISTERED),
    (azure_rest.ArmError(400, "ResourceTypeNotSupported", "no"), sa.NOT_SUPPORTED),
    (azure_rest.ArmError(404, "ResourceNotFound", "gone"), sa.NOT_FOUND),
    (azure_rest.ArmError(500, "InternalServerError", "boom"), sa.ERROR),
    (ConnectionError("reset"), sa.ERROR),
])
def test_classify(exc, expected):
    assert sa.classify(exc) == expected


# --- health check ---

def metric(*series):
    return [{"name": {"value": "HealthCheckStatus"}, "timeseries": [{"data": list(s)} for s in series]}]


def point(hours_ago, average, minimum=None):
    end = NOW.replace(minute=0)
    return {"timeStamp": (end - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "average": average, "minimum": average if minimum is None else minimum}


def test_points_fold_across_series_per_hour():
    points = sa.project_points(metric([point(2, 100), point(1, 100)], [point(1, 50, 0)]) + [{"name": {"value": "Other"}}])
    assert [(p["average"], p["minimum"]) for p in points] == [(100, 100), (75.0, 0)]


def test_an_app_healthy_every_hour():
    end = NOW.replace(minute=0)
    check = sa.health_check_record(sa.READ, "/health", sa.READ, sa.project_points(metric([point(h, 100) for h in (3, 2, 1)])), end)
    assert (check["health_check_enabled"], check["hours_with_data"], check["hours_unhealthy"]) == (True, 3, 0)
    assert (check["healthy_percentage"], check["healthy_last_hour"], check["lowest_status"]) == (100.0, True, 100)


def test_an_hour_with_an_unhealthy_instance_is_unhealthy():
    end = NOW.replace(minute=0)
    points = sa.project_points(metric([point(3, 100), point(2, 90, 0), point(1, 100), {"timeStamp": ts(timedelta(0))}]))
    check = sa.health_check_record(sa.READ, "/health", sa.READ, points, end)
    assert (check["hours_with_data"], check["hours_unhealthy"], check["healthy_percentage"]) == (3, 1, 66.67)
    assert check["unhealthy_hours"] == [points[1]["time"]]
    assert check["healthy_last_hour"] is True


def test_old_results_leave_the_last_hour_unknown():
    end = NOW.replace(minute=0)
    check = sa.health_check_record(sa.READ, "/health", sa.READ, sa.project_points(metric([point(10, 100)])), end)
    assert (check["hours_with_data"], check["healthy_last_hour"], check["last_hour"]) == (1, None, None)


def test_a_stopped_app_gets_no_health_check_verdict():
    end = NOW.replace(minute=0)
    check = sa.health_check_record(sa.READ, "/health", sa.READ, sa.project_points(metric([point(1, 0)])), end, stopped=True)
    assert (check["app_stopped"], check["hours_unhealthy"], check["healthy_last_hour"]) == (True, 1, None)


def test_a_failed_metric_read_is_unknown_not_zero():
    check = sa.health_check_record(sa.READ, "/health", sa.ERROR, [], NOW)
    assert all(check[k] is None for k in ("hours_with_data", "hours_unhealthy", "healthy_percentage", "healthy_last_hour"))


# --- collection ---

class FakeArm:
    """ARM answers for one subscription: a web app, a function app, an out-of-scope web app, a Front Door and a CDN
    profile, and a managed instance."""

    def __init__(self, health=None, failing=(), registration="Registered", web_state="Running", web_metric=None):
        self.calls: list[str] = []
        self.health = health or {}
        self.web_state = web_state
        self.web_metric = web_metric
        self.failing = dict(failing)
        self.registration = registration

    def _fail(self, path):
        for key, exc in self.failing.items():
            if key in path:
                raise exc

    def get(self, path, api_version):
        self.calls.append(path)
        self._fail(path)
        if path.endswith("/providers/Microsoft.ResourceHealth"):
            return {"registrationState": self.registration}
        if path == f"{WEB}/config/web":
            return {"properties": {"healthCheckPath": "/health"}}
        return {"properties": {"healthCheckPath": None}}

    def list(self, path, api_version, params=None):
        self.calls.append(path)
        self._fail(path)
        if path.endswith("/providers/Microsoft.Web/sites"):
            return [
                {"id": WEB, "name": "web1", "kind": "app,linux", "location": "East US 2",
                 "properties": {"state": self.web_state, "sku": "PremiumV3"}},
                {"id": FUNC, "name": "func1", "kind": "functionapp", "location": "Central US", "properties": {}},
                {"id": WEB_OUT, "name": "web2", "kind": "app", "location": "East US 2", "properties": {}},
            ]
        if path.endswith("/providers/Microsoft.Cdn/profiles"):
            return [{"id": FD, "name": "fd1", "location": "Global", "sku": {"name": "Premium_AzureFrontDoor"}},
                    {"id": CDN, "name": "cdn1", "location": "Global", "sku": {"name": "Standard_Microsoft"}}]
        if path.endswith("/providers/Microsoft.Sql/managedInstances"):
            return [{"id": MI, "name": "mi1", "location": "eastus2", "properties": {"state": "Ready"}}]
        if path.endswith("/availabilityStatuses"):
            resource = path.split("/providers/Microsoft.ResourceHealth")[0]
            return self.health.get(resource, [status("Available", timedelta(days=60))])
        if path.endswith("/providers/Microsoft.Insights/metrics"):
            assert params["metricnames"] == "HealthCheckStatus" and params["interval"] == "PT1H"
            return self.web_metric or metric([point(2, 100), point(1, 100)])
        raise AssertionError(f"unexpected list {path}")


@pytest.fixture(autouse=True)
def fixed_now(monkeypatch):
    monkeypatch.setattr(sa, "utc_now", lambda: NOW)
    for env in (sa.LOOKBACK_ENV, sa.RTO_ENV, "AZURE_RESOURCE_EXCLUSIONS"):
        monkeypatch.delenv(env, raising=False)


def run(client):
    collector = Collector(sa.logger)
    results, summary = sa.collect(client, "s1", collector)
    return results, summary, collector


def test_collect_reads_every_in_scope_resource_and_only_front_door_profiles():
    client = FakeArm(health={WEB: outage_history()})
    results, summary, collector = run(client)
    assert collector.ok
    by_id = {r["id"]: r for r in results["resources"]}
    assert sorted(by_id) == sorted([WEB, FUNC, WEB_OUT, FD, MI])
    assert (by_id[WEB]["app_type"], by_id[FUNC]["app_type"], by_id[FD]["region"]) == ("web_app", "function_app", "global")
    assert results["cdn_profiles_not_front_door"] == 1
    assert by_id[WEB]["health_check"]["healthy_last_hour"] is True
    assert by_id[FUNC]["health_check"]["metric_status"] == sa.NOT_READ
    assert by_id[FD]["health_check"] is None
    assert not any(c.endswith(f"{FUNC}/providers/Microsoft.Insights/metrics") for c in client.calls)
    assert {k: summary[k] for k in (
        "resources", "app_services", "web_apps", "function_apps", "front_door_profiles", "sql_managed_instances",
        "resource_health_read", "resource_health_unknown", "resources_available_now", "outages_in_window",
        "longest_outage_hours", "apps_with_health_check", "apps_without_health_check", "all_apps_have_health_check",
        "apps_health_check_healthy_last_hour", "service_impacting_events")} == {
        "resources": 5, "app_services": 3, "web_apps": 2, "function_apps": 1, "front_door_profiles": 1,
        "sql_managed_instances": 1, "resource_health_read": 5, "resource_health_unknown": 0,
        "resources_available_now": 4, "outages_in_window": 1, "longest_outage_hours": 2.0,
        "apps_with_health_check": 1, "apps_without_health_check": 2, "all_apps_have_health_check": False,
        "apps_health_check_healthy_last_hour": 1, "service_impacting_events": 1}
    assert summary["regions"] == ["centralus", "eastus2", "global"]
    east = next(r for r in results["regions"] if r["region"] == "eastus2")
    assert (east["resources"], east["outages_in_window"], east["apps_with_health_check"]) == (3, 1, 1)
    assert summary["resources_recovery_time_objective_unknown"] is None


def test_front_door_failures_are_counted_apart_from_outages():
    failing = [status("Available", timedelta(days=40), "a"),
               status("Unavailable", timedelta(hours=5), "down", title="Unavailable Backends", reasonType="Unplanned")]
    results, summary, collector = run(FakeArm(health={FD: failing}))
    assert collector.ok
    assert {k: summary[k] for k in ("resources_unavailable_now", "outages_in_window", "ongoing_outages",
                                    "front_door_profiles_failing_origin_probes_now",
                                    "front_door_origin_probe_failure_windows",
                                    "front_door_longest_origin_probe_failure_hours")} == {
        "resources_unavailable_now": 0, "outages_in_window": 0, "ongoing_outages": 0,
        "front_door_profiles_failing_origin_probes_now": 1, "front_door_origin_probe_failure_windows": 1,
        "front_door_longest_origin_probe_failure_hours": 5.0}
    glob = next(r for r in results["regions"] if r["region"] == "global")
    assert (glob["availability_unknown_now"], glob["front_door_profiles_failing_origin_probes_now"]) == (0, 1)


def test_an_ongoing_outage_past_the_objective_fails_every_resource_check(monkeypatch):
    monkeypatch.setenv(sa.RTO_ENV, "24")
    down = [status("Available", timedelta(days=40), "a"), status("Unavailable", timedelta(hours=30), "down")]
    _, summary, _ = run(FakeArm(health={WEB: down}))
    assert (summary["resources_missing_recovery_time_objective"], summary["all_resources_meet_recovery_time_objective"],
            summary["longest_outage_hours"], summary["ongoing_outages"]) == (1, False, 30.0, 1)


def test_a_long_unknown_period_leaves_the_objective_unknown(monkeypatch):
    monkeypatch.setenv(sa.RTO_ENV, "24")
    quiet = [status("Available", timedelta(days=40), "a"), status("Unknown", timedelta(days=20), "q"),
             status("Available", timedelta(days=6), "b")]
    _, summary, _ = run(FakeArm(health={WEB: quiet}))
    assert (summary["resources_recovery_time_objective_unknown"], summary["all_resources_meet_recovery_time_objective"],
            summary["longest_unknown_hours"]) == (1, None, 336.0)


def test_the_summary_counts_resources_whose_availability_leaves_out_unknown_time():
    quiet = [status("Available", timedelta(days=40), "a"), status("Unknown", timedelta(days=20), "q"),
             status("Available", timedelta(days=6), "b")]
    unknown_now = [status("Unknown", timedelta(0), "current")]
    unknown_all_along = [status("Unknown", timedelta(days=40), "q")]
    created_lately = [status("Available", timedelta(days=5), "a")]
    _, summary, _ = run(FakeArm(health={WEB: quiet, FUNC: unknown_now, MI: unknown_all_along, WEB_OUT: created_lately}))
    assert {k: summary[k] for k in ("lowest_availability_percentage", "resources_without_availability",
                                    "resources_with_unknown_hours", "resources_with_partial_history",
                                    "resources_availability_unknown_now", "outages_in_window",
                                    "resources_with_outage_in_window", "longest_outage_hours")} == {
        "lowest_availability_percentage": 100.0, "resources_without_availability": 2,
        "resources_with_unknown_hours": 1, "resources_with_partial_history": 2,
        "resources_availability_unknown_now": 2, "outages_in_window": 0, "resources_with_outage_in_window": 0,
        "longest_outage_hours": 0.0}


def test_outage_counts_are_null_when_no_resource_has_known_hours(monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:rg-out")
    unknown = [status("Unknown", timedelta(0), "current")]
    results, summary, collector = run(FakeArm(health={WEB: unknown, FUNC: unknown, MI: unknown}))
    assert collector.ok
    assert all(summary[k] is None for k in ("outages_in_window", "resources_with_outage_in_window", "ongoing_outages",
                                            "longest_outage_hours", "lowest_availability_percentage"))
    assert summary["resources_without_availability"] == 3
    east = next(r for r in results["regions"] if r["region"] == "eastus2")
    assert (east["outages_in_window"], east["longest_outage_hours"]) == (None, None)


def test_a_stopped_app_is_not_counted_as_failing_its_health_check():
    results, summary, _ = run(FakeArm(web_state="Stopped", web_metric=metric([point(2, 0), point(1, 0)])))
    web = next(r for r in results["resources"] if r["id"] == WEB)["health_check"]
    assert (web["app_stopped"], web["hours_unhealthy"]) == (True, 2)
    assert {k: summary[k] for k in ("apps_stopped", "apps_health_check_unhealthy_last_hour", "apps_with_unhealthy_hours",
                                    "apps_health_check_without_recent_data")} == {
        "apps_stopped": 1, "apps_health_check_unhealthy_last_hour": 0, "apps_with_unhealthy_hours": 0,
        "apps_health_check_without_recent_data": 0}


def test_a_running_app_whose_health_check_fails_is_unhealthy():
    _, summary, _ = run(FakeArm(web_metric=metric([point(2, 0), point(1, 15.5, 0)])))
    assert (summary["apps_health_check_unhealthy_last_hour"], summary["apps_with_unhealthy_hours"]) == (1, 1)


def test_excluded_resources_get_no_calls_and_are_counted_out(monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:rg-out, id:" + MI + ", location:nowhere")
    client = FakeArm()
    results, summary, collector = run(client)
    assert collector.ok
    assert sorted(r["id"] for r in results["resources"]) == sorted([WEB, FUNC, FD])
    assert [(e["kind"], e["id"]) for e in results["excluded"]] == [("app", WEB_OUT), ("sql_managed_instance", MI)]
    assert not any(c.startswith(WEB_OUT) or c.startswith(MI) for c in client.calls)
    assert {k: summary[k] for k in ("excluded_apps", "excluded_sql_managed_instances", "excluded_front_door_profiles",
                                    "in_scope_apps", "in_scope_sql_managed_instances", "resources")} == {
        "excluded_apps": 1, "excluded_sql_managed_instances": 1, "excluded_front_door_profiles": 0,
        "in_scope_apps": 2, "in_scope_sql_managed_instances": 0, "resources": 3}
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:nowhere"]


def test_an_excluded_cdn_profile_is_not_counted(monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "id:" + CDN)
    client = FakeArm()
    results, summary, collector = run(client)
    assert collector.ok
    assert results["cdn_profiles_not_front_door"] == 0
    assert [(e["kind"], e["id"]) for e in results["excluded"]] == [("cdn_profile", CDN)]
    assert (summary["resource_exclusion_patterns_unmatched"], summary["front_door_profiles"]) == ([], 1)


def test_an_invalid_exclusion_pattern_fails_the_run(monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg-out")
    _, _, collector = run(FakeArm())
    assert not collector.ok


MEASURED_FIELDS = (
    "resources_available_now", "resources_unavailable_now", "resources_degraded_now",
    "resources_availability_unknown_now", "resources_with_outage_in_window", "outages_in_window", "ongoing_outages",
    "customer_initiated_unavailable_windows", "longest_outage_hours", "longest_degraded_hours", "longest_unknown_hours",
    "lowest_availability_percentage", "resources_without_availability", "resources_with_unknown_hours",
    "resources_with_partial_history", "resources_meeting_recovery_time_objective",
    "resources_missing_recovery_time_objective", "resources_recovery_time_objective_unknown",
    "all_resources_meet_recovery_time_objective")
APP_FIELDS = (
    "apps_stopped", "apps_with_health_check", "apps_without_health_check", "apps_health_check_unknown",
    "all_apps_have_health_check", "apps_health_check_healthy_last_hour", "apps_health_check_unhealthy_last_hour",
    "apps_health_check_without_recent_data", "apps_with_unhealthy_hours", "health_check_metric_unread")
FRONT_DOOR_FIELDS = ("front_door_profiles_failing_origin_probes_now", "front_door_origin_probe_failure_windows",
                     "front_door_longest_origin_probe_failure_hours")
WHOLE_RUN_FIELDS = ("resources", "resource_health_unknown", "windows_not_listed", "service_impacting_events")


def test_a_failed_app_list_leaves_every_count_over_apps_null(monkeypatch):
    monkeypatch.setenv(sa.RTO_ENV, "24")
    client = FakeArm(failing={"/providers/Microsoft.Web/sites": azure_rest.ArmError(500, "InternalServerError", "boom")})
    results, summary, collector = run(client)
    assert not collector.ok
    nulls = ("app_services", "web_apps", "excluded_apps", "in_scope_apps") + MEASURED_FIELDS + APP_FIELDS + WHOLE_RUN_FIELDS
    assert {k: summary[k] for k in nulls} == dict.fromkeys(nulls)
    assert (summary["front_door_profiles"], summary["sql_managed_instances"]) == (1, 1)
    assert (summary["front_door_profiles_failing_origin_probes_now"], summary["front_door_origin_probe_failure_windows"]) == (0, 0)
    for region in results["regions"]:
        assert (region["outages_in_window"], region["available_now"], region["apps_with_health_check"]) == (None, None, None)


def test_a_failed_profile_list_leaves_the_front_door_counts_null():
    client = FakeArm(failing={"/providers/Microsoft.Cdn/profiles": azure_rest.ArmError(500, "InternalServerError", "boom")})
    results, summary, collector = run(client)
    assert not collector.ok
    assert {k: summary[k] for k in FRONT_DOOR_FIELDS + WHOLE_RUN_FIELDS} == dict.fromkeys(FRONT_DOOR_FIELDS + WHOLE_RUN_FIELDS)
    assert (summary["outages_in_window"], summary["apps_with_health_check"], results["cdn_profiles_not_front_door"]) == (0, 1, None)
    assert all(r["front_door_profiles_failing_origin_probes_now"] is None for r in results["regions"])


def test_without_an_objective_no_recovery_count_passes():
    _, summary, _ = run(FakeArm())
    assert all(summary[k] is None for k in ("resources_meeting_recovery_time_objective",
                                            "resources_missing_recovery_time_objective",
                                            "resources_recovery_time_objective_unknown",
                                            "all_resources_meet_recovery_time_objective"))


def test_a_refused_health_read_is_unknown_and_fails_the_run():
    client = FakeArm(failing={f"{MI}/providers/Microsoft.ResourceHealth": azure_rest.ArmError(403, "AuthorizationFailed", "no")})
    results, summary, collector = run(client)
    mi = next(r for r in results["resources"] if r["id"] == MI)
    assert not collector.ok
    assert (mi["resource_health"]["status"], mi["available_now"], mi["outages_in_window"]) == (sa.NOT_AUTHORIZED, None, None)
    assert (summary["resource_health_unknown"], summary["resources_availability_unknown_now"]) == (1, 1)


def test_a_resource_type_resource_health_does_not_cover_is_unknown_without_failing():
    client = FakeArm(failing={f"{FD}/providers/Microsoft.ResourceHealth": azure_rest.ArmError(400, "ResourceTypeNotSupported", "no")})
    results, summary, collector = run(client)
    assert collector.ok
    assert summary["resource_health_by_status"] == {"not_supported": 1, "read": 4}
    assert next(r for r in results["resources"] if r["id"] == FD)["available_now"] is None


def test_unregistered_resource_health_reads_nothing_and_fails_once():
    client = FakeArm(registration="NotRegistered")
    results, summary, collector = run(client)
    assert len(collector.failures) == 1
    assert not any(c.endswith("/availabilityStatuses") for c in client.calls)
    assert (summary["resource_health_registration"], summary["resource_health_read"]) == ("not_registered", 0)
    assert summary["resource_health_by_status"] == {"not_registered": 5}


def test_a_failed_config_read_still_reads_the_metric_and_leaves_the_setting_unknown():
    client = FakeArm(failing={f"{FUNC}/config/web": azure_rest.ArmError(500, "InternalServerError", "boom")})
    results, summary, collector = run(client)
    func = next(r for r in results["resources"] if r["id"] == FUNC)["health_check"]
    assert not collector.ok
    assert (func["config_status"], func["health_check_enabled"], func["metric_status"]) == (sa.ERROR, None, sa.READ)
    assert (summary["apps_health_check_unknown"], summary["all_apps_have_health_check"]) == (1, False)


def test_a_failed_metric_read_fails_the_run_and_reads_unknown():
    client = FakeArm(failing={f"{WEB}/providers/Microsoft.Insights/metrics": azure_rest.ArmError(500, "InternalServerError", "x")})
    results, summary, collector = run(client)
    assert not collector.ok
    assert (summary["health_check_metric_unread"], summary["apps_health_check_without_recent_data"]) == (1, 1)


def test_the_recovery_time_objective_is_checked_per_resource(monkeypatch):
    monkeypatch.setenv(sa.RTO_ENV, "1.5")
    results, summary, collector = run(FakeArm(health={WEB: outage_history()}))
    assert collector.ok
    assert {k: summary[k] for k in ("recovery_time_objective_hours", "resources_meeting_recovery_time_objective",
                                    "resources_missing_recovery_time_objective",
                                    "resources_recovery_time_objective_unknown",
                                    "all_resources_meet_recovery_time_objective")} == {
        "recovery_time_objective_hours": 1.5, "resources_meeting_recovery_time_objective": 3,
        "resources_missing_recovery_time_objective": 1, "resources_recovery_time_objective_unknown": 0,
        "all_resources_meet_recovery_time_objective": False}


@pytest.mark.parametrize("raw", ["soon", "0", "-2"])
def test_an_invalid_recovery_time_objective_fails_the_run(monkeypatch, raw):
    monkeypatch.setenv(sa.RTO_ENV, raw)
    _, summary, collector = run(FakeArm())
    assert not collector.ok and summary["recovery_time_objective_hours"] is None


@pytest.mark.parametrize("raw", ["soon", "0", "-2", "1.5"])
def test_an_invalid_lookback_fails_the_run(monkeypatch, raw):
    monkeypatch.setenv(sa.LOOKBACK_ENV, raw)
    _, summary, collector = run(FakeArm())
    assert not collector.ok and summary["lookback_days"] == 30


def test_the_lookback_is_capped_at_what_resource_health_keeps(monkeypatch):
    monkeypatch.setenv(sa.LOOKBACK_ENV, "90")
    results, summary, _ = run(FakeArm())
    assert summary["lookback_days"] == 30
    assert results["settings"]["window_start"] == ts(timedelta(days=30))


def test_every_summary_field_is_documented():
    instructions = yaml.safe_load((AZURE / "service_availability" / "fetcher.yaml").read_text())["evidence_set"]["instructions"]
    documented = set(re.findall(r"^- (\w+) —", instructions, re.MULTILINE))
    _, summary, _ = run(FakeArm())
    assert set(summary) == documented
