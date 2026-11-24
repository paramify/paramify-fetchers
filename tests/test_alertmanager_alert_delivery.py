"""alertmanager_alert_delivery, against real responses captured from Alertmanager 0.35.0 (tests/fixtures/alertmanager).

The sandbox had a working webhook receiver, a receiver pointed at a closed port, and a receiver with no integration
for a heartbeat alert; four alerts, one silenced. metrics.txt is the default format (failures per integration type);
metrics-receiver-name.txt is the same setup with --enable-feature=receiver-name-in-metrics. No network.
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "alertmanager"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
spec = importlib.util.spec_from_file_location("alertmanager_alert_delivery_under_test",
                                              REPO_ROOT / "fetchers" / "alertmanager" / "alert_delivery" / "fetcher.py")
am = importlib.util.module_from_spec(spec)
spec.loader.exec_module(am)

NOW = datetime(2026, 11, 17, 23, 41, 5, tzinfo=timezone.utc)


def _load(name):
    text = (FIXTURES / name).read_text()
    return text if name.endswith(".txt") else json.loads(text)


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self.text = body if isinstance(body, str) else json.dumps(body)
        self._body = body

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


class _Alertmanager:
    """requests.Session that only implements GET, so any write attempt fails the test."""

    def __init__(self, metrics="metrics.txt", refused=(), flaky=(), bodies=None):
        self.metrics, self.refused, self.flaky = metrics, set(refused), dict.fromkeys(flaky, 1)
        self.bodies = bodies or {}  # path -> body served instead of the fixture
        self.gets = []

    def get(self, url, timeout=None, allow_redirects=True, headers=None):
        path = urlparse(url).path
        self.gets.append((path, dict(headers or {})))
        if path in self.flaky and self.flaky[path]:
            self.flaky[path] -= 1
            return _Resp(503, "busy")
        if path in self.refused:
            return _Resp(403, "forbidden")
        bodies = {"/api/v2/status": _load("status.json"), "/api/v2/alerts": _load("alerts.json"),
                  "/api/v2/silences": _load("silences.json"), "/metrics": _load(self.metrics)}
        bodies.update(self.bodies)
        return _Resp(200, bodies[path]) if path in bodies else _Resp(404, "not found")


@pytest.fixture
def alertmanager(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Alertmanager(**kwargs)
        monkeypatch.setattr(am.requests, "Session", lambda: session)
        return session

    monkeypatch.setattr(am.time, "sleep", lambda s: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("ALERTMANAGER_BASE_URL", "http://alertmanager.example.com:9093/")
    monkeypatch.delenv("ALERTMANAGER_TOKEN", raising=False)
    return serve


def _evidence(tmp_path):
    return json.loads((tmp_path / "alertmanager_alert_delivery.json").read_text())


def test_real_responses_give_routing_alerts_and_delivery(alertmanager, tmp_path, assert_summary_documented):
    alertmanager()
    assert am.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["config_read"], s["receivers_total"], s["receivers_without_integrations_names"]) == (True, 3, ["null"])
    assert (s["default_receiver"], s["default_receiver_has_integrations"], s["routes_total"]) == ("ops-webhook", True, 2)
    assert (s["routes_to_receivers_without_integrations"], s["inhibit_rules"], s["integration_types"]) == (1, 1, ["webhook"])
    # Three firing (one of them the heartbeat that goes nowhere by design) and one silenced.
    assert (s["alerts_active"], s["alerts_suppressed"], s["alerts_silenced"], s["alerts_inhibited"]) == (3, 1, 1, 0)
    assert (s["alerts_active_to_receivers_without_integrations"], s["silences_active"]) == (1, 1)
    # Without receiver names in the metrics, the failure can only be pinned to the webhook integration type.
    assert (s["notifications_attempted"], s["notifications_failed"]) == (4, 2)  # the closed-port receiver retried once more
    assert (s["notification_failures_by"], s["notification_failures"]) == ("integration", ["webhook"])
    # Without receiver names only a restart resets the counters, so they date from the process start.
    assert (s["process_started"], s["counters_since"]) == ("2026-11-17T23:31:05Z", "2026-11-17T23:31:05Z")
    assert (s["cluster_status"], s["cluster_peers"]) == ("disabled", 0)
    assert_summary_documented("alertmanager/alert_delivery", s)


def test_receiver_names_in_metrics_pin_the_failure_to_the_receiver():
    m = am.parse_metrics(_load("metrics-receiver-name.txt"))
    assert m["by"] == "receiver"
    assert ({k: v for k, v in m["attempts"].items() if v}, {k: v for k, v in m["failures"].items() if v}) == (
        {"ops-webhook": 1.0, "pager": 2.0}, {"pager": 1.0})


def test_receiver_settings_never_reach_the_evidence(alertmanager, tmp_path):
    alertmanager()
    am.main()
    text = (tmp_path / "alertmanager_alert_delivery.json").read_text()
    # The status holds the whole configuration; only names, integration types and the route tree are kept.
    assert "<secret>" in json.dumps(_load("status.json"))
    for leaked in ("<secret>", "http_config", "webhook_configs", "global", "127.0.0.1:9099", "unreachable"):
        assert leaked not in text, leaked
    receivers = _evidence(tmp_path)["results"]["receivers"]
    assert receivers == [{"name": "ops-webhook", "integration_types": ["webhook"], "integrations": 1},
                         {"name": "pager", "integration_types": ["webhook"], "integrations": 1},
                         {"name": "null", "integration_types": [], "integrations": 0}]


def test_unreadable_metrics_leave_only_delivery_fields_null(alertmanager, tmp_path):
    alertmanager(refused=("/metrics",))
    assert am.main() == 1
    ev = _evidence(tmp_path)
    s = ev["summary"]
    assert (s["notifications_attempted"], s["notifications_failed"], s["notification_failures"]) == (None, None, None)
    assert (s["config_read"], s["alerts_active"]) == (True, 3)
    assert ev["metadata"]["api_failures"][0]["operation"] == "metrics"
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_unreadable_status_leaves_routing_null_not_zero():
    s = am.summarize(None, None, _load("alerts.json"), None, None, NOW)
    assert (s["config_read"], s["receivers_total"], s["default_receiver_has_integrations"]) == (None, None, None)
    assert (s["alerts_active"], s["alerts_active_to_receivers_without_integrations"], s["silences_active"]) == (3, None, None)


def test_a_default_route_to_a_receiver_without_integrations_is_reported():
    status = {"config": {"original": "route:\n  receiver: blackhole\nreceivers:\n  - name: blackhole\n"}}
    s = am.summarize(status, am.parse_config(status), [], [], {"by": "integration", "attempts": {}, "failures": {}}, NOW)
    assert (s["default_receiver"], s["default_receiver_has_integrations"], s["receivers_without_integrations"]) == ("blackhole", False, 1)
    assert (s["notifications_attempted"], s["notifications_failed"], s["notification_failures"]) == (0, 0, [])


def test_reads_are_get_only_retried_and_carry_the_optional_token(alertmanager, tmp_path, monkeypatch):
    monkeypatch.setenv("ALERTMANAGER_TOKEN", "proxy-token")
    session = alertmanager(flaky=("/api/v2/alerts",))
    assert am.main() == 0
    paths = [p for p, _ in session.gets]
    assert paths.count("/api/v2/alerts") == 2 and set(paths) == {"/api/v2/status", "/api/v2/alerts", "/api/v2/silences", "/metrics"}
    assert all(h.get("Authorization") == "Bearer proxy-token" for _, h in session.gets)


def test_a_missing_base_url_is_bad_config(alertmanager, tmp_path, monkeypatch):
    alertmanager()
    monkeypatch.delenv("ALERTMANAGER_BASE_URL")
    assert am.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"
    assert _evidence(tmp_path)["summary"]["config_read"] is None


# --- review fixes (PR 392) ---

BUILD_INFO = 'alertmanager_build_info{version="0.35.0"} 1\n'
STATUS_NULL_ONLY = {**_load("status.json"), "config": {"original": (
    "route:\n  receiver: \"null\"\nreceivers:\n  - name: \"null\"\n")}}


def _delivery(s):
    return (s["notifications_attempted"], s["notifications_failed"], s["notification_failures"], s["counters_since"])


def _assert_metrics_failed(tmp_path, reason):
    ev = _evidence(tmp_path)
    s = ev["summary"]
    assert _delivery(s) == (None, None, None, None)
    assert ev["results"]["notifications"] is None
    # The reads that did work are kept.
    assert (s["config_read"], s["alerts_active"], s["routes_total"]) == (True, 3, 2)
    assert ev["metadata"]["partial_failure"] is True
    failure = ev["metadata"]["api_failures"][0]
    assert (failure["operation"], failure["type"]) == ("metrics", "MetricsError")
    assert reason in failure["message"], failure["message"]
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "partial_failure"


def test_a_proxy_page_at_metrics_is_a_failed_read_not_zero_failures(alertmanager, tmp_path):
    # A reverse proxy that forwards only /api/ answers /metrics with its own 200 page.
    alertmanager(bodies={"/metrics": "<html><body><h1>Welcome to nginx!</h1></body></html>"})
    assert am.main() == 1
    _assert_metrics_failed(tmp_path, "alertmanager_build_info")


@pytest.mark.parametrize("body, reason", [
    # Build info and a started notification, but no failure counter: failures unknown, not 0.
    (BUILD_INFO + 'alertmanager_notifications_total{integration="webhook"} 1\n',
     "alertmanager_notifications_failed_total is not"),
    (BUILD_INFO + 'alertmanager_notifications_failed_total{integration="webhook",reason="other"} 1\n',
     "alertmanager_notifications_total is not"),
    # A value that is not a number is not skipped.
    (BUILD_INFO + 'alertmanager_notifications_total{integration="webhook"} 1\n'
     'alertmanager_notifications_failed_total{integration="webhook",reason="other"} invalid\n', "not a number"),
    # One that float() refuses does not crash the run or lose the other evidence.
    (BUILD_INFO + 'alertmanager_notifications_total{integration="webhook"} 1\n'
     'alertmanager_notifications_failed_total{integration="webhook",reason="other"} 1e+\n', "not a number"),
    (BUILD_INFO + 'alertmanager_notifications_total{integration="webhook"} NaN\n'
     'alertmanager_notifications_failed_total{integration="webhook",reason="other"} 0\n', "not a finite count"),
    # Some series name the receiver and some only the integration: attribution is not knowable.
    (BUILD_INFO + 'alertmanager_notifications_total{integration="webhook",receiver_name="pager"} 2\n'
     'alertmanager_notifications_failed_total{integration="webhook",reason="other"} 1\n', "some do not"),
    (BUILD_INFO + 'alertmanager_notifications_total{reason="other"} 2\n'
     'alertmanager_notifications_failed_total{integration="webhook",reason="other"} 1\n', "neither"),
    # No counters at all while a routed receiver has an integration.
    (BUILD_INFO, "a routed receiver has an integration"),
])
def test_partial_or_malformed_metrics_are_a_failed_read(alertmanager, tmp_path, body, reason):
    alertmanager(bodies={"/metrics": body})
    assert am.main() == 1
    _assert_metrics_failed(tmp_path, reason)


def test_no_counters_with_no_routed_integration_is_zero_not_a_failure(alertmanager, tmp_path):
    # With receiver-name-in-metrics, Alertmanager creates no counters when no routed receiver has an integration.
    body = BUILD_INFO + "alertmanager_config_last_reload_success_timestamp_seconds 1.7949583171216176e+09\n"
    alertmanager(bodies={"/api/v2/status": STATUS_NULL_ONLY, "/metrics": body})
    assert am.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert _delivery(s) == (0, 0, [], "2026-11-17T23:31:57Z")
    assert s["notification_failures_by"] == "receiver"


def test_receiver_named_counters_date_from_the_last_reload_not_the_process_start(alertmanager, tmp_path):
    # With receiver names, a configuration reload resets the counters without a restart. The fixture's process
    # started at 23:31:05 (status uptime); here the configuration was reloaded an hour later.
    reloaded = datetime(2026, 11, 18, 0, 31, 5, tzinfo=timezone.utc).timestamp()
    text = "\n".join(f"alertmanager_config_last_reload_success_timestamp_seconds {reloaded!r}"
                     if line.startswith("alertmanager_config_last_reload_success_timestamp_seconds") else line
                     for line in _load("metrics-receiver-name.txt").splitlines())
    alertmanager(bodies={"/metrics": text})
    assert am.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["process_started"], s["counters_since"]) == ("2026-11-17T23:31:05Z", "2026-11-18T00:31:05Z")
    assert (s["notification_failures_by"], s["notification_failures"]) == ("receiver", ["pager"])


def test_receiver_named_counters_without_a_reload_time_have_no_start():
    text = "\n".join(line for line in _load("metrics-receiver-name.txt").splitlines()
                     if not line.startswith("alertmanager_config_last_reload_success_timestamp_seconds"))
    s = am.summarize(_load("status.json"), am.parse_config(_load("status.json")), [], [], am.parse_metrics(text), NOW)
    assert (s["process_started"], s["counters_since"], s["hours_since_counters_started"]) == ("2026-11-17T23:31:05Z", None, None)


def test_failed_notifications_count_once_not_per_retry():
    # The closed-port receiver made 13 requests (alertmanager_notification_requests_failed_total) for 1 notification.
    text = _load("metrics-receiver-name.txt")
    assert 'alertmanager_notification_requests_failed_total{integration="webhook",receiver_name="pager"} 13' in text
    s = am.summarize(None, None, None, None, am.parse_metrics(text), NOW)
    assert (s["notifications_attempted"], s["notifications_failed"]) == (3, 1)
    described = (REPO_ROOT / "fetchers" / "alertmanager" / "alert_delivery" / "fetcher.yaml").read_text()
    assert "retries included" not in described and "accepted or rejected" not in described


def test_older_match_and_match_re_keys_are_kept_as_matchers():
    status = {"config": {"original": (
        "route:\n  receiver: ops\n  routes:\n"
        "    - receiver: \"null\"\n      match:\n        alertname: Watchdog\n"
        "    - receiver: pager\n      match_re:\n        severity: critical|page\n      continue: true\n"
        "    - receiver: pager\n      matchers: ['team=\"db\"']\n      match:\n        env: prod\n"
        "receivers:\n  - name: ops\n  - name: pager\n  - name: \"null\"\n")}}
    routes = am.route_records(am.parse_config(status)["route"])
    assert [r["matchers"] for r in routes] == [
        None, ['alertname="Watchdog"'], ['severity=~"critical|page"'], ['team="db"', 'env="prod"']]


def test_a_status_without_its_configuration_is_a_failed_read(alertmanager, tmp_path):
    status = {k: v for k, v in _load("status.json").items() if k != "config"}
    alertmanager(bodies={"/api/v2/status": status})
    assert am.main() == 1
    ev = _evidence(tmp_path)
    s = ev["summary"]
    assert (s["config_read"], s["receivers_total"], s["default_receiver_has_integrations"]) == (False, None, None)
    assert ev["metadata"]["api_failures"][0]["operation"] == "status configuration"
    # The status itself was read: the process start and cluster still come from it, and the metrics still count.
    assert (s["process_started"], s["cluster_status"], s["notifications_failed"]) == ("2026-11-17T23:31:05Z", "disabled", 2)


def test_alerts_that_are_not_a_list_are_a_failed_read(alertmanager, tmp_path):
    alertmanager(bodies={"/api/v2/alerts": {"message": "ok"}})
    assert am.main() == 1
    ev = _evidence(tmp_path)
    assert (ev["summary"]["alerts_active"], ev["results"]["alerts"]) == (None, None)
    assert ev["metadata"]["api_failures"][0]["operation"] == "alerts"
