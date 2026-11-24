"""azure_endpoint_availability: web test and load balancer projection, hourly averages against the target, null-not-zero summaries, and a full run against synthetic ARM and metrics responses. No SDK or network."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_endpoint_availability_under_test", AZURE / "endpoint_availability" / "fetcher.py")
ea = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ea)
azure_rest = sys.modules["azure_rest"]

SUB = "/subscriptions/s1"
COMPONENT = f"{SUB}/resourceGroups/rg1/providers/microsoft.insights/components/appi1"
SETTINGS = {"lookback_days": 7, "target": 99.9}


def raw_test(name="home", enabled=True, component=COMPONENT, url="https://app.example.com/health", location="eastus"):
    tags = {f"hidden-link:{component}": "Resource"} if component else {}
    return {"id": f"{SUB}/resourceGroups/rg1/providers/Microsoft.Insights/webtests/{name}-appi1", "name": f"{name}-appi1", "tags": tags,
            "location": location,
            "properties": {"Name": name, "Kind": "standard", "Enabled": enabled, "Frequency": 300,
                           "Locations": [{"Id": "us-va-ash-azr"}, {"Id": "us-tx-sn1-azr"}, {"Id": "us-il-ch1-azr"}],
                           "Request": {"RequestUrl": url}}}


def raw_lb(name="lb1", sku="Standard", public=True, rules=1, probes=1, location="eastus"):
    fe = {"name": "fe", "properties": {"publicIPAddress": {"id": "pip"}} if public else {"privateIPAddress": "10.0.0.4"}}
    return {"id": f"{SUB}/resourceGroups/rg-aks/providers/Microsoft.Network/loadBalancers/{name}", "name": name, "sku": {"name": sku},
            "location": location, "properties": {"frontendIPConfigurations": [fe], "loadBalancingRules": [{"name": f"r{i}"} for i in range(rules)],
                                                 "probes": [{"name": f"p{i}"} for i in range(probes)]}}


def metric(name, *hourly):
    return [{"name": {"value": name}, "timeseries": [{"data": [{"timeStamp": f"2026-11-{16 + h // 24:02d}T{h % 24:02d}:00:00Z", "average": v}
                                                               for h, v in enumerate(hourly)]}]}]


def test_component_comes_from_the_hidden_link_tag():
    assert ea.component_of({f"hidden-link:{COMPONENT}": "Resource", "env": "x"}) == COMPONENT
    assert ea.component_of({"hidden-link:/x": "Other"}) is None and ea.component_of(None) is None


def test_records_read_test_and_load_balancer_settings():
    t = ea.test_record(raw_test())
    assert (t["test_name"], t["kind"], t["enabled"], t["locations"], t["url"], t["component_id"]) == (
        "home", "standard", True, 3, "https://app.example.com/health", COMPONENT)
    b = ea.load_balancer_record(raw_lb(public=False, sku="Basic"))
    assert (b["standard"], b["public"], b["frontends"]) == (False, False, 1)


def test_hourly_points_average_series_and_skip_empty_hours():
    m = metric(ea.AVAILABILITY_METRIC, 100, 99) + [{"name": {"value": ea.AVAILABILITY_METRIC}, "timeseries": [
        {"data": [{"timeStamp": "2026-11-16T00:00:00Z", "average": 90}, {"timeStamp": "2026-11-16T02:00:00Z", "average": None}]}]}]
    assert ea.hourly_points(m, ea.AVAILABILITY_METRIC) == [("2026-11-16T00:00:00Z", 95.0), ("2026-11-16T01:00:00Z", 99.0)]


def test_judgement_is_null_when_unread_or_without_data():
    ok = ea.judged([("a", 100.0), ("b", 99.0)], ea.READ, 99.9, 2)
    assert (ok["availability_percentage"], ok["lowest_hour_percentage"], ok["latest_hour_percentage"], ok["below_target"]) == (99.5, 99.0, 99.0, True)
    assert ea.judged([], ea.READ, 99.9)["availability_percentage"] is None and ea.judged([], ea.READ, 99.9)["hours_with_data"] == 0
    assert ea.judged([("a", 100.0)], ea.ERROR, 99.9)["hours_with_data"] is None


def _test(enabled=True, status=ea.READ, points=(("a", 100.0),), url="https://app.example.com/health"):
    t = ea.test_record(raw_test(enabled=enabled, url=url))
    t.update(ea.judged(list(points), status if enabled else ea.NOT_APPLICABLE, 99.9, len(points)))
    return t


def _lb(sku="Standard", vip=(("a", 100.0),), dip=(("a", 100.0),), status=ea.READ, rules=1, probes=1):
    b = ea.load_balancer_record(raw_lb(sku=sku, rules=rules, probes=probes))
    standard = sku == "Standard"
    b["data_path"] = ea.judged(list(vip), status if standard and rules else ea.NOT_APPLICABLE, 99.9, len(vip))
    b["health_probe"] = ea.judged(list(dip), status if standard and probes else ea.NOT_APPLICABLE, 99.9, len(dip))
    return b


def test_summary_counts_tests_and_load_balancers_against_the_target():
    tests = [_test(points=(("a", 100.0), ("b", 98.0))), _test(url="https://api.example.com/", points=(("a", 100.0),)), _test(enabled=False)]
    lbs = [_lb(dip=(("a", 100.0), ("b", 99.0))), _lb(sku="Basic")]
    s = ea.summarize(tests, lbs, SETTINGS)
    assert (s["availability_tests_enabled"], s["endpoints_tested"], s["lowest_availability_percentage"]) == (2, 2, 99.0)
    assert (s["availability_tests_below_target"], s["availability_tests_below_target_latest_hour"]) == (1, 1)
    assert (s["load_balancers_standard"], s["lowest_data_path_availability"], s["lowest_health_probe_availability"], s["load_balancers_below_target"]) == (1, 100.0, 99.5, 1)


def test_unread_results_leave_verdicts_null_not_zero():
    s = ea.summarize([_test(status=ea.ERROR, points=())], [_lb(status=ea.ERROR, vip=(), dip=())], SETTINGS)
    assert (s["availability_tests_results_unread"], s["lowest_availability_percentage"]) == (1, None)
    # An unread item is not judged; it never counts as meeting the target.
    assert (s["availability_tests_below_target"], s["availability_tests_not_judged"]) == (0, 1)
    assert (s["load_balancers_metrics_unread"], s["lowest_data_path_availability"]) == (1, None)
    assert (s["load_balancers_below_target"], s["load_balancers_not_judged"]) == (0, 1)
    unlisted = ea.summarize([], [], SETTINGS, tests_listed=False, balancers_listed=False)
    assert (unlisted["availability_tests_enabled"], unlisted["endpoints_tested"], unlisted["load_balancers_standard"]) == (None, None, None)


def test_no_tests_reads_as_zero_tested_endpoints_not_unknown():
    s = ea.summarize([], [], SETTINGS)
    assert (s["availability_tests_enabled"], s["endpoints_tested"], s["lowest_availability_percentage"]) == (0, 0, None)


def test_summary_matches_the_instructions(assert_summary_documented):
    s = ea.summarize([_test()], [_lb()], SETTINGS)
    s.update(ea.ResourceExclusions().summary([], ("availability_test", "load_balancer"), {"availability_tests": 1, "load_balancers": 1}))
    assert_summary_documented("azure/endpoint_availability", s)


# --- full run against synthetic ARM and metrics responses ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text, self.headers = status, body, "", json.dumps(body), {}

    def json(self):
        return self._body


class _Arm:
    def __init__(self, tests=None, metrics_status=200):
        self.tests = tests if tests is not None else [raw_test(), raw_test("off", enabled=False)]
        self.metrics_status, self.calls = metrics_status, []
        self.lbs = [raw_lb(), raw_lb("basic", sku="Basic", public=False)]

    def get(self, url, params=None, headers=None, timeout=None, allow_redirects=True):
        path = urlparse(url).path
        self.calls.append((path, dict(params or {})))
        if path.endswith("/providers/Microsoft.Insights/webtests"):
            return _Resp(200, {"value": self.tests})
        if path.endswith("/providers/Microsoft.Network/loadBalancers"):
            return _Resp(200, {"value": self.lbs})
        if path.endswith("/providers/Microsoft.Insights/metrics"):
            if self.metrics_status != 200:
                return _Resp(self.metrics_status, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            name = params["metricnames"]
            # A full day: 24 hourly points (23 at 100 and one at 88 averages 99.5 for the test).
            return _Resp(200, {"value": metric(name, *([100.0] * 23 + [88.0])) if name == ea.AVAILABILITY_METRIC else metric(name, *([100.0] * 24))})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


@pytest.fixture
def arm(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Arm(**kwargs)
        monkeypatch.setattr("requests.Session", lambda: session)
        return session

    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: _Cred())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "s1")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for env in ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", "AZURE_RESOURCE_EXCLUSIONS", "AZURE_TARGET_SUBSCRIPTION_ONLY",
                ea.LOOKBACK_ENV, ea.TARGET_ENV):
        monkeypatch.delenv(env, raising=False)
    return serve


def _evidence(tmp_path):
    [path] = tmp_path.glob("azure_endpoint_availability_s1.json")
    return json.loads(path.read_text())


def test_main_reads_each_enabled_test_and_standard_load_balancer(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(ea.TARGET_ENV, "99.9")
    monkeypatch.setenv(ea.LOOKBACK_ENV, "1")
    session = arm()
    assert ea.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["in_scope_availability_tests"], s["availability_tests_enabled"], s["endpoints_tested"], s["lowest_availability_percentage"]) == (2, 1, 1, 99.5)
    assert (s["availability_tests_below_target"], s["load_balancers_standard"], s["lowest_data_path_availability"], s["load_balancers_below_target"]) == (1, 1, 100.0, 0)
    metric_calls = [p for path, p in session.calls if path.endswith("/metrics")]
    # One call for the enabled test (filtered to its name, on its component) and two for the Standard load balancer only.
    assert [c["metricnames"] for c in metric_calls] == [ea.AVAILABILITY_METRIC, ea.DATA_PATH_METRIC, ea.HEALTH_PROBE_METRIC]
    assert metric_calls[0]["$filter"] == "availabilityResult/name eq 'home'" and metric_calls[0]["interval"] == "PT1H"
    assert any(path.startswith(COMPONENT) for path, _ in session.calls)


def test_unreadable_metrics_fail_the_run_and_leave_verdicts_null(arm, tmp_path):
    arm(metrics_status=403)
    assert ea.main() != 0
    s = _evidence(tmp_path)["summary"]
    assert (s["availability_tests_results_unread"], s["lowest_availability_percentage"], s["load_balancers_metrics_unread"], s["lowest_data_path_availability"]) == (1, None, 1, None)


def test_a_test_without_its_component_link_fails_the_run(arm, tmp_path):
    arm(tests=[raw_test(component=None)])
    assert ea.main() != 0
    assert _evidence(tmp_path)["summary"]["availability_tests_results_unread"] == 1


def test_an_invalid_target_fails_the_run_and_stays_unset(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(ea.TARGET_ENV, "101")
    arm()
    assert ea.main() != 0
    s = _evidence(tmp_path)["summary"]
    assert (s["availability_target_percentage"], s["availability_tests_below_target"]) == (None, None)


def test_without_an_adopted_target_below_target_counts_stay_null():
    s = ea.summarize([_test(points=(("a", 50.0),))], [_lb(dip=(("a", 10.0),))], {"lookback_days": 7, "target": None})
    assert (s["availability_target_percentage"], s["availability_tests_below_target"], s["load_balancers_below_target"]) == (None, None, None)
    assert (s["lowest_availability_percentage"], s["lowest_health_probe_availability"]) == (50.0, 10.0)


# --- measurement coverage and what tests validate ---

def test_a_partial_window_is_unknown_never_healthy():
    few_good_hours = ea.judged([("a", 100.0), ("b", 100.0), ("c", 100.0)], ea.READ, 99.9, 168)
    assert (few_good_hours["availability_percentage"], few_good_hours["hours_missing"], few_good_hours["measurement_coverage_percentage"]) == (100.0, 165, 1.8)
    assert (few_good_hours["measurement_complete"], few_good_hours["below_target"]) == (False, None)


def test_one_incomplete_test_is_not_judged_and_the_others_still_are():
    complete = _test(points=tuple((str(h), 100.0) for h in range(23)) + (("23", 50.0),))
    partial = ea.test_record(raw_test("api", url="https://api.example.com/"))
    partial.update(ea.judged([("a", 100.0)], ea.READ, 99.9, 24))
    s = ea.summarize([complete, partial], [], SETTINGS)
    assert (s["availability_tests_with_missing_measurements"], s["lowest_measurement_coverage_percentage"]) == (1, 4.2)
    assert (s["availability_tests_below_target"], s["availability_tests_not_judged"]) == (1, 1)


def test_status_code_and_content_checks_are_read_from_standard_and_classic_tests():
    standard = {"ValidationRules": {"ExpectedHttpStatusCode": 200, "SSLCheck": True, "ContentValidation": {"ContentMatch": "healthy"}}}
    assert ea.validation(standard) == {"checks_status_code": True, "checks_content": True, "checks_ssl": True}
    assert ea.validation({"ValidationRules": {"ExpectedHttpStatusCode": 200}})["checks_content"] is False
    ping = {"Configuration": {"WebTest": '<WebTest><Items><Request ExpectedHttpStatusCode="200" /></Items><ValidationRules><ValidationRule '
                                          'Classname="Microsoft.VisualStudio.TestTools.WebTesting.Rules.ValidationRuleFindText"><RuleParameters>'
                                          '<RuleParameter Name="FindText" Value="OK" /></RuleParameters></ValidationRule></ValidationRules></WebTest>'}}
    assert ea.validation(ping) == {"checks_status_code": True, "checks_content": True, "checks_ssl": False}
    assert ea.validation({}) == {"checks_status_code": False, "checks_content": False, "checks_ssl": False}


def test_application_checks_are_counted_across_enabled_tests():
    works = ea.test_record({**raw_test(), "properties": {**raw_test()["properties"], "ValidationRules": {"ExpectedHttpStatusCode": 200, "ContentValidation": {"ContentMatch": "ok"}}}})
    works.update(ea.judged([("a", 100.0)], ea.READ, 99.9, 1))
    s = ea.summarize([works, _test(url="https://api.example.com/")], [], SETTINGS)
    assert (s["availability_tests_checking_application"], s["availability_tests_reachability_only"]) == (1, 1)


# --- review fixes: location exclusions, load balancers without rules or probes, classic test URLs ---

def test_location_patterns_exclude_tests_and_load_balancers(arm, tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "location:westus2")
    session = arm(tests=[raw_test(), raw_test("west", location="westus2")])
    session.lbs = [raw_lb(), raw_lb("west-lb", location="westus2")]
    assert ea.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["excluded_availability_tests"], s["excluded_load_balancers"], s["resource_exclusion_patterns_unmatched"]) == (1, 1, [])
    assert (s["in_scope_availability_tests"], s["in_scope_load_balancers"]) == (1, 1)


def test_an_outbound_only_load_balancer_does_not_leave_the_verdict_unknown(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(ea.TARGET_ENV, "99.9")
    monkeypatch.setenv(ea.LOOKBACK_ENV, "1")
    session = arm()
    session.lbs = [raw_lb(), raw_lb("outbound", public=True, rules=0, probes=0)]
    assert ea.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["load_balancers_standard"], s["load_balancers_without_measured_traffic"]) == (2, 1)
    assert (s["load_balancers_below_target"], s["load_balancers_not_judged"], s["load_balancers_with_missing_measurements"]) == (0, 0, 0)
    lb_calls = [path for path, _ in session.calls if "/loadBalancers/" in path]
    assert all("/loadBalancers/lb1/" in path for path in lb_calls)  # nothing is asked of the outbound-only load balancer


def test_a_load_balancer_without_probes_is_judged_on_its_data_path_only():
    b = _lb(vip=(("a", 98.0),), dip=(), probes=0)
    assert (b["data_path"]["metric_status"], b["health_probe"]["metric_status"]) == (ea.READ, ea.NOT_APPLICABLE)
    s = ea.summarize([], [b], SETTINGS)
    assert (s["load_balancers_below_target"], s["load_balancers_not_judged"], s["load_balancers_with_missing_measurements"]) == (1, 0, 0)


def test_classic_ping_tests_read_their_url_from_the_webtest_xml():
    xml = ('<WebTest Name="home"><Items><Request Method="GET" Version="1.1" Url="https://app.example.com/?a=1&amp;b=2" '
           'ExpectedHttpStatusCode="200" /></Items></WebTest>')
    raw = {**raw_test(), "properties": {**raw_test()["properties"], "Kind": "ping", "Request": None, "Configuration": {"WebTest": xml}}}
    t = ea.test_record(raw)
    assert t["url"] == "https://app.example.com/?a=1&b=2"
    t.update(ea.judged([("a", 100.0)], ea.READ, 99.9, 1))
    assert ea.summarize([t], [], SETTINGS)["endpoints_tested"] == 1


def test_without_a_target_the_not_judged_counts_stay_null():
    s = ea.summarize([_test()], [_lb()], {"lookback_days": 7, "target": None})
    assert (s["availability_tests_not_judged"], s["load_balancers_not_judged"]) == (None, None)
