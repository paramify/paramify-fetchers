"""azure_service_health_advisories: event projection, open rule, impacted resources, exclusions. Synthetic payloads."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location(
    "azure_service_health_advisories_under_test", AZURE / "service_health_advisories" / "fetcher.py")
sh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sh)
azure_rest = sys.modules["azure_rest"]
azure_common = sys.modules["azure_common"]
ResourceExclusions = sys.modules["resource_exclusions"].ResourceExclusions

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
SUB = "/subscriptions/s1"
APP = f"{SUB}/resourceGroups/rg-app/providers/Microsoft.Web/sites/app1"
DB = f"{SUB}/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql1"


def raw_event(tid="AAAA-111", event_type="HealthAdvisory", status="Active", mitigation="2026-12-01T00:00:00Z",
              updates=(), **props):
    regions = [{"impactedRegion": "East US 2", "status": status, "lastUpdateTime": "2026-10-20T00:00:00Z",
                "updates": list(updates)}]
    base = {
        "eventType": event_type, "eventSource": "ServiceHealth", "status": status, "title": f"Event {tid}",
        "summary": "<p>Plan&nbsp;the <b>migration</b>.</p>", "eventLevel": "Warning", "level": "Warning",
        "priority": 10, "impactStartTime": "2026-10-01T00:00:00Z", "impactMitigationTime": mitigation,
        "lastUpdateTime": "2026-10-20T00:00:00Z", "isEventSensitive": False,
        "impact": [{"impactedService": "App Service", "impactedRegions": regions}],
    }
    return {"id": f"{SUB}/providers/Microsoft.ResourceHealth/events/{tid}", "name": tid, "properties": {**base, **props}}


def update(at, text="<p>Update</p>"):
    return {"updateDateTime": at, "summary": text}


def raw_resource(rid=APP, region="eastus2", rtype="Microsoft.Web/sites", **props):
    return {"properties": {"targetResourceId": rid, "targetResourceType": rtype, "targetRegion": region,
                           "info": [{"key": "detail", "value": "<b>x</b>"}], **props}}


def event(tid="AAAA-111", resources=(APP,), resources_status=sh.READ, details_status=sh.NOT_NEEDED, **kwargs):
    record = sh.event_record(raw_event(tid, **kwargs), NOW)
    listed = [sh.impacted_record(raw_resource(r)) for r in resources]
    return sh.with_reads(record, details_status, resources_status, listed)


# --- projection ---

def test_plain_strips_html_unescapes_and_caps():
    assert sh.plain("<p>Plan&nbsp;the <b>migration</b>.</p>") == "Plan the migration ."
    long = sh.plain("<p>" + "x" * 5000 + "</p>")
    assert long.startswith("x" * sh.MAX_TEXT) and "truncated from 5000" in long
    assert (sh.plain(""), sh.plain(None), sh.plain("<br/>")) == (None, None, None)


def test_query_start_is_month_day_year_without_padding():
    assert sh.query_start(datetime(2026, 8, 3, tzinfo=timezone.utc)) == "8/3/2026"


@pytest.mark.parametrize("event_type, status, mitigation, expected", [
    ("ServiceIssue", "Active", "2026-10-01T00:00:00Z", True),
    ("ServiceIssue", "Resolved", "2026-12-01T00:00:00Z", False),
    ("HealthAdvisory", "Resolved", "2026-12-01T00:00:00Z", True),
    ("HealthAdvisory", "Active", "2026-10-01T00:00:00Z", False),
    ("PlannedMaintenance", "Active", "2026-11-01T13:00:00Z", True),
    ("SecurityAdvisory", "Active", None, True),
    ("SecurityAdvisory", "Resolved", "", False),
    ("RCA", "Resolved", "not a time", False),
])
def test_open_follows_microsofts_active_rule(event_type, status, mitigation, expected):
    assert sh.is_open(event_type, status, mitigation, NOW) is expected


def test_event_projection_reads_the_fields_an_assessor_needs():
    record = sh.event_record(raw_event(
        event_type="HealthAdvisory", eventSubType="Retirement", eventTags=["Action Recommended"],
        recommendedActions={"message": "<p>Migrate</p>", "actions": [{"actionText": "<a>Move to v2</a>"}, {}]},
        updates=[update("2026-10-05T00:00:00Z", "<p>Second</p>"), update("2026-10-02T00:00:00.1234567Z", "First")],
    ), NOW)
    assert {k: record[k] for k in ("tracking_id", "event_type", "event_sub_type", "status", "event_level", "summary",
                                   "published_at", "update_count", "latest_update", "recommended_action_message",
                                   "recommended_actions", "action_recommended", "is_sensitive", "open")} == {
        "tracking_id": "AAAA-111", "event_type": "HealthAdvisory", "event_sub_type": "Retirement",
        "status": "Active", "event_level": "Warning", "summary": "Plan the migration .",
        "published_at": "2026-10-02T00:00:00.1234567Z", "update_count": 2,
        "latest_update": {"at": "2026-10-05T00:00:00Z", "summary": "Second"},
        "recommended_action_message": "Migrate", "recommended_actions": ["Move to v2"], "action_recommended": True,
        "is_sensitive": False, "open": True}
    assert record["impacted_services"] == [{"service": "App Service", "regions": [
        {"region": "East US 2", "status": "Active", "last_update_time": "2026-10-20T00:00:00Z"}]}]


def test_an_update_sent_to_several_regions_counts_once():
    raw = raw_event(updates=[update("2026-10-02T00:00:00Z")])
    region = raw["properties"]["impact"][0]["impactedRegions"][0]
    raw["properties"]["impact"][0]["impactedRegions"].append({**region, "impactedRegion": "West US"})
    record = sh.event_record(raw, NOW)
    assert record["update_count"] == 1
    assert [r["region"] for r in record["impacted_services"][0]["regions"]] == ["East US 2", "West US"]


def test_no_updates_or_actions_leave_published_and_action_empty():
    record = sh.event_record(raw_event(), NOW)
    assert (record["published_at"], record["latest_update"], record["action_recommended"]) == (None, None, False)
    assert sh.event_record(raw_event(eventTags=["action recommended"]), NOW)["action_recommended"] is True


def test_impacted_resource_projection_derives_name_and_group_from_the_id():
    record = sh.impacted_record(raw_resource())
    assert record == {"resource_id": APP, "resource_type": "microsoft.web/sites", "resource_name": "app1",
                      "resource_group": "rg-app", "region": "eastus2", "status": None,
                      "maintenance_start_time": None, "maintenance_end_time": None, "info": {"detail": "x"}}


@pytest.mark.parametrize("status, expected", [
    (404, sh.NOT_FOUND), (403, sh.NOT_AUTHORIZED), (401, sh.NOT_AUTHORIZED), (400, sh.ERROR), (500, sh.ERROR),
])
def test_read_status_comes_from_the_http_status(status, expected):
    assert sh.read_status(azure_rest.ArmError(status, "Code", "message")) == expected
    assert sh.read_status(ConnectionError("reset")) == sh.ERROR


def test_a_missing_resource_list_is_none_but_a_refused_one_is_unknown():
    assert event(resources=(), resources_status=sh.NOT_FOUND)["impacted_resources"] == []
    assert event(resources_status=sh.NOT_AUTHORIZED)["impacted_resources"] is None
    assert event(resources_status=sh.ERROR)["impacted_resources"] is None


# --- scope ---

def test_scope_takes_out_matching_resources_and_events_left_with_none():
    events = [event("A", resources=(APP, DB)), event("B", resources=(DB,)), event("C", resources=()),
              event("D", resources_status=sh.NOT_AUTHORIZED)]
    scope = ResourceExclusions(["rg:rg-data", "rg:nothing-here"])
    kept, excluded = sh.apply_scope(scope, events)
    assert [(e["tracking_id"], [r["resource_name"] for r in e["impacted_resources"] or []],
             e["excluded_impacted_resources"]) for e in kept] == [("A", ["app1"], 1), ("C", [], 0), ("D", [], 0)]
    assert [(x["kind"], x["name"], x["pattern"], x["reason"], x["tracking_id"]) for x in excluded] == [
        ("impacted_resource", "sql1", "rg:rg-data", "resource_matched", "A"),
        ("impacted_resource", "sql1", "rg:rg-data", "resource_matched", "B"),
        ("event", "Event B", None, "every_impacted_resource_excluded", "B")]
    assert scope.unmatched() == ["rg:nothing-here"]


def test_a_location_pattern_matches_a_region_written_with_spaces():
    record = sh.with_reads(sh.event_record(raw_event(), NOW), sh.NOT_NEEDED, sh.READ,
                           [sh.impacted_record(raw_resource(region="East US 2"))])
    kept, excluded = sh.apply_scope(ResourceExclusions(["location:eastus2"]), [record])
    assert (kept, [x["kind"] for x in excluded]) == ([], ["impacted_resource", "event"])


# --- summary ---

def test_summary_counts_open_events_by_kind_and_the_resources_they_name():
    events = [
        event("SI", event_type="ServiceIssue", status="Active", resources=(APP,), eventLevel="Error"),
        event("SA", event_type="SecurityAdvisory", resources=(), eventLevel="Critical", isEventSensitive=True,
              details_status=sh.NOT_AUTHORIZED),
        event("HA", eventSubType="Retirement", eventTags=["Action Recommended"], resources=(APP, DB)),
        event("PM", event_type="PlannedMaintenance", mitigation="2026-10-15T00:00:00Z", resources=(DB,)),
        event("RCA", event_type="RCA", status="Resolved", mitigation="2026-10-10T00:00:00Z", resources=()),
    ]
    summary = sh.summarize(events, True, 2, 90)
    assert summary == {
        "lookback_days": 90, "events": 5,
        "events_by_type": {"HealthAdvisory": 1, "PlannedMaintenance": 1, "RCA": 1, "SecurityAdvisory": 1,
                           "ServiceIssue": 1},
        "events_by_status": {"Active": 4, "Resolved": 1},
        "events_by_level": {"Critical": 1, "Error": 1, "Warning": 3},
        "retirement_advisories": 1, "billing_events_skipped": 2,
        "open_events": 3, "open_events_by_type": {"HealthAdvisory": 1, "SecurityAdvisory": 1, "ServiceIssue": 1},
        "open_service_issues": 1, "open_security_advisories": 1, "open_health_advisories": 1,
        "open_retirement_advisories": 1, "upcoming_planned_maintenance": 0, "open_events_action_recommended": 1,
        "open_high_severity_events": 2,
        "sensitive_events": 1, "sensitive_event_details_read": 0, "sensitive_event_details_not_authorized": 1,
        "events_impacted_resources_unread": 0, "events_impacted_resources_not_authorized": 0,
        "impacted_resources": 2, "impacted_resources_by_type": {"microsoft.web/sites": 2},
        "events_with_impacted_resources": 3, "open_events_with_impacted_resources": 2,
    }


def test_resource_counts_are_unknown_while_any_list_is_unread():
    events = [event("A"), event("B", event_type="SecurityAdvisory", resources_status=sh.NOT_AUTHORIZED)]
    summary = sh.summarize(events, True, 0, 90)
    assert {k: summary[k] for k in sh.RESOURCE_COUNTS} == dict.fromkeys(sh.RESOURCE_COUNTS, None)
    assert (summary["events_impacted_resources_unread"], summary["events_impacted_resources_not_authorized"],
            summary["open_events"]) == (1, 1, 2)


def test_every_count_is_unknown_when_the_event_list_was_not_read():
    summary = sh.summarize([], False, None, 30)
    assert {k: summary[k] for k in sh.EVENT_COUNTS + sh.RESOURCE_COUNTS} == dict.fromkeys(
        sh.EVENT_COUNTS + sh.RESOURCE_COUNTS, None)
    assert summary["lookback_days"] == 30
    quiet = sh.summarize([], True, 0, 90)
    assert (quiet["events"], quiet["open_events"], quiet["impacted_resources"], quiet["events_by_type"]) == (0, 0, 0, {})


# --- collection ---

class _Health:
    """One subscription's Service Health API; `refuse` maps a path suffix to the error it answers."""

    def __init__(self, events, resources=None, details=None, refuse=None, cred=None):
        self.events, self.resources, self.details = events, resources or {}, details or {}
        self.refuse, self.calls, self.cred = refuse or {}, [], cred

    def _answer(self, method, path):
        self.calls.append((method, path.split("/events", 1)[1] or "/"))
        for suffix, error in self.refuse.items():
            if path.endswith(suffix):
                raise error

    def list(self, path, api_version, params=None):
        self._answer("GET", path)
        if path.endswith("/events"):
            assert params == {"queryStartTime": "8/3/2026"} and api_version == sh.API
            return self.events
        return self.resources.get(path.split("/")[-2], [])

    def post(self, path, api_version):
        self._answer("POST", path)
        return self.details[path.split("/")[-2]]

    def post_list(self, path, api_version):
        self._answer("POST", path)
        return self.resources.get(path.split("/")[-2], [])


def collector():
    return azure_common.Collector(sh.logger)


def test_collect_reads_each_event_its_details_and_resources_and_skips_billing():
    sensitive = raw_event("SA-1", event_type="SecurityAdvisory", isEventSensitive=True, summary=None)
    details = raw_event("SA-1", event_type="SecurityAdvisory", isEventSensitive=True, summary="<p>Rotate keys</p>",
                        updates=[update("2026-10-03T00:00:00Z", "Patched")])
    client = _Health(
        [raw_event("HA-1"), sensitive, raw_event("BILL-1", event_type="Billing")],
        resources={"HA-1": [raw_resource()], "SA-1": [raw_resource(DB, rtype="Microsoft.Sql/servers")]},
        details={"SA-1": {"properties": details["properties"]}},
    )
    c = collector()
    events, read, billing = sh.collect(client, "s1", NOW, 90, c)
    assert (read, billing, c.ok) == (True, 1, True)
    assert sorted(client.calls) == sorted([
        ("GET", "/"), ("GET", "/HA-1/impactedResources"), ("POST", "/SA-1/fetchEventDetails"),
        ("POST", "/SA-1/listSecurityAdvisoryImpactedResources")])
    by_id = {e["tracking_id"]: e for e in events}
    assert (by_id["SA-1"]["summary"], by_id["SA-1"]["published_at"], by_id["SA-1"]["details_status"]) == (
        "Rotate keys", "2026-10-03T00:00:00Z", sh.READ)
    assert [r["resource_name"] for r in by_id["SA-1"]["impacted_resources"]] == ["sql1"]
    assert (by_id["HA-1"]["details_status"], by_id["HA-1"]["impacted_resources_status"]) == (sh.NOT_NEEDED, sh.READ)


def test_refused_advisory_details_and_resources_are_unknown_not_a_failure():
    client = _Health(
        [raw_event("HA-1"), raw_event("SA-1", event_type="SecurityAdvisory", isEventSensitive=True)],
        refuse={"/fetchEventDetails": azure_rest.ArmError(403, "AuthorizationFailed", "no"),
                "/listSecurityAdvisoryImpactedResources": azure_rest.ArmError(403, "AuthorizationFailed", "no")},
    )
    c = collector()
    events, read, _ = sh.collect(client, "s1", NOW, 90, c)
    sa = next(e for e in events if e["tracking_id"] == "SA-1")
    assert (c.ok, sa["details_status"], sa["impacted_resources_status"], sa["impacted_resources"]) == (
        True, sh.NOT_AUTHORIZED, sh.NOT_AUTHORIZED, None)
    assert sh.summarize(events, read, 0, 90)["impacted_resources"] is None


def test_a_missing_resource_list_reads_as_none_listed():
    client = _Health([raw_event("HA-1")], refuse={"/impactedResources": azure_rest.ArmError(404, "NotFound", "x")})
    c = collector()
    [ev], _, _ = sh.collect(client, "s1", NOW, 90, c)
    assert (c.ok, ev["impacted_resources_status"], ev["impacted_resources"]) == (True, sh.NOT_FOUND, [])


def test_a_failed_resource_list_fails_the_run():
    client = _Health([raw_event("HA-1")], refuse={"/impactedResources": azure_rest.ArmError(500, "Internal", "x")})
    c = collector()
    [ev], _, _ = sh.collect(client, "s1", NOW, 90, c)
    assert (c.ok, ev["impacted_resources_status"], c.failures[0]["operation"]) == (
        False, sh.ERROR, "resourceHealth.events.impactedResources (HA-1)")


def test_every_plain_resource_list_refused_means_reader_is_missing():
    client = _Health([raw_event("HA-1"), raw_event("SI-1", event_type="ServiceIssue")],
                     refuse={"/impactedResources": azure_rest.ArmError(403, "AuthorizationFailed", "no")})
    c = collector()
    sh.collect(client, "s1", NOW, 90, c)
    assert [f["type"] for f in c.failures] == ["PermissionError"]


def test_a_failed_event_list_is_recorded_and_leaves_every_count_unknown():
    client = _Health([], refuse={"/events": azure_rest.ArmError(403, "AuthorizationFailed", "no")})
    c = collector()
    assert sh.collect(client, "s1", NOW, 90, c) == ([], False, None)
    assert not c.ok


@pytest.fixture
def fixed_now(monkeypatch):
    monkeypatch.setattr(sh, "datetime", SimpleNamespace(now=lambda tz=None: NOW))


def test_collect_subscription_writes_scope_fields_and_registration(monkeypatch, fixed_now):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:rg-data")
    monkeypatch.setattr(sh, "provider_registration_status", lambda *a: azure_common.REGISTERED)
    client = _Health([raw_event("HA-1"), raw_event("HA-2")],
                     resources={"HA-1": [raw_resource()], "HA-2": [raw_resource(DB)]})
    results, summary = sh.collect_subscription(client, "s1", collector())
    assert [e["tracking_id"] for e in results["events"]] == ["HA-1"]
    assert (results["query_start"], results["provider_registration_status"], len(results["limitations"])) == (
        "8/3/2026", azure_common.REGISTERED, 5)
    assert {k: summary[k] for k in ("events", "impacted_resources", "excluded_events", "excluded_impacted_resources",
                                    "resource_exclusion_patterns", "resource_exclusion_patterns_unmatched")} == {
        "events": 1, "impacted_resources": 1, "excluded_events": 1, "excluded_impacted_resources": 1,
        "resource_exclusion_patterns": ["rg:rg-data"], "resource_exclusion_patterns_unmatched": []}


def test_collect_subscription_leaves_exclusion_counts_unknown_when_nothing_was_read(monkeypatch, fixed_now):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "bad-pattern")
    monkeypatch.setattr(sh, "provider_registration_status", lambda *a: azure_common.REGISTRATION_UNKNOWN)
    c = collector()
    _, summary = sh.collect_subscription(
        _Health([], refuse={"/events": azure_rest.ArmError(500, "Internal", "x")}), "s1", c)
    assert (summary["excluded_events"], summary["excluded_impacted_resources"], summary["events"]) == (None, None, None)
    assert {f["operation"] for f in c.failures} == {"config AZURE_RESOURCE_EXCLUSIONS", "resourceHealth.events.list"}


def test_lookback_days_comes_from_the_environment(monkeypatch, fixed_now):
    monkeypatch.setenv(sh.LOOKBACK_ENV, "365")
    monkeypatch.setattr(sh, "provider_registration_status", lambda *a: azure_common.REGISTERED)
    seen = {}

    class _Window(_Health):
        def list(self, path, api_version, params=None):
            seen.update(params or {})
            return []

    results, summary = sh.collect_subscription(_Window([]), "s1", collector())
    assert (seen, results["lookback_days"], summary["lookback_days"]) == ({"queryStartTime": "11/1/2025"}, 365, 365)


# --- shared client: POST list actions ---

class _Response:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text, self.headers = status, body, "", "", {}

    def json(self):
        return self._body


class _Session:
    def __init__(self):
        self.sent = []

    def post(self, url, headers=None, **kwargs):
        self.sent.append(("post", url, kwargs.get("params")))
        if url.endswith("/denied"):
            return _Response(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
        return _Response(200, {"value": [1], "nextLink": "https://management.azure.com/next?page=2"})

    def get(self, url, headers=None, **kwargs):
        self.sent.append(("get", url, kwargs.get("params")))
        return _Response(200, {"value": [2]})


def test_post_list_posts_once_then_follows_next_link_by_get(monkeypatch):
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    cred = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="t", expires_on=10 ** 12))
    session = _Session()
    client = azure_rest.AzureRestClient(cred, session)
    assert client.post_list("/subscriptions/s1/x/list", "2025-05-01") == [1, 2]
    assert session.sent == [("post", "https://management.azure.com/subscriptions/s1/x/list", {"api-version": "2025-05-01"}),
                            ("get", "https://management.azure.com/next?page=2", None)]
    with pytest.raises(azure_rest.ArmError) as err:
        client.post("/subscriptions/s1/denied", "2025-05-01")
    assert err.value.status == 403
