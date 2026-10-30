"""Cover for datadog_siem_configuration against a fake Datadog API.

No network and no credentials: ``requests.get`` in the fetcher module is
replaced by a router that answers each path with a response shaped like the
examples in Datadog's API reference (Security Monitoring: Get content pack
states, Get all suppression rules, Get the list of signal-based notification
rules, List rules; Webhooks Integration: Get a webhook integration).

What this proves: Cloud SIEM reads as not active only on the documented
`onboarding` content pack signal, never on a 404 or 403; a failed sub-read fails
the run instead of passing as "not enabled"; and `notification_types` comes from
configured notification targets, not webhook names. What it cannot prove: that
the preview content pack states endpoint is served on every Datadog site
(including GovCloud) and that real targets carry the leading `@`. That still
needs a live tenant.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "datadog" / "siem_configuration" / "fetcher.py"
BASE = "https://api.example.test"

CONTENT_PACKS = "/api/v2/security_monitoring/content_packs/states"
SUPPRESSIONS = "/api/v2/security_monitoring/configuration/suppressions"
NOTIFICATION_RULES = "/api/v2/security/signals/notification_rules"
RULES = "/api/v2/security_monitoring/rules"
WEBHOOKS = "/api/v1/integration/webhooks/configuration/webhooks/"


def load_fetcher():
    spec = importlib.util.spec_from_file_location("dd_siem_configuration_under_test", FETCHER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status: int, body: Any):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> Any:
        return self._body


def error(status: int) -> FakeResponse:
    return FakeResponse(status, {"errors": ["Not Found" if status == 404 else "Forbidden"]})


def content_packs(detail_type: str) -> Dict[str, Any]:
    details: Dict[str, Any] = {"type": detail_type}
    if detail_type == "logs":
        details.update({"cp_activation": "activated", "data_last_seen": "within_24_hours",
                        "filters_configured": True, "integration_installed_status": "installed",
                        "logs_seen_from_any_index": True, "siem_index_incorrect": False})
    return {
        "data": [{"id": "aws-cloudtrail", "type": "content_pack_state",
                  "attributes": {"status": "active", "details": details}}],
        "meta": {"cloud_siem_index_incorrect": False, "sku": "add_on_2024"},
    }


SUPPRESSION_BODY = {
    "data": [
        {"id": "3dd-0uc-h1s", "type": "suppressions",
         "attributes": {"name": "Suppress scanner noise", "enabled": True, "editable": True,
                        "start_date": 1703187336000, "expiration_date": 1703187999000,
                        "rule_query": "type:log_detection source:cloudtrail",
                        "suppression_query": "env:staging", "data_exclusion_query": "",
                        "version": 2, "tags": []}},
        {"id": "4ee-1vd-i2t", "type": "suppressions",
         "attributes": {"name": "Old exception", "enabled": False, "rule_query": "",
                        "suppression_query": "host:legacy", "version": 1}},
    ],
    "meta": {"page": {"pageNumber": 0, "pageSize": 100, "totalCount": 2}},
}

NOTIFICATION_RULES_BODY = {
    "data": [
        {"id": "aaa-bbb-ccc", "type": "notification_rules",
         "attributes": {"name": "High signals", "enabled": True, "version": 1,
                        "selectors": {"severities": ["critical", "high"],
                                      "rule_types": ["log_detection"],
                                      "trigger_source": "security_signals"},
                        "targets": ["@slack-secops", "@john.doe@email.com", "@webhook-soar-intake"]}},
        {"id": "ddd-eee-fff", "type": "notification_rules",
         "attributes": {"name": "Disabled rule", "enabled": False, "version": 3,
                        "selectors": {"trigger_source": "security_signals"},
                        "targets": ["@opsgenie-oncall"]}},
    ]
}

RULES_BODY = {
    "data": [
        {"id": "r1", "name": "Brute force", "type": "log_detection", "isEnabled": True,
         "cases": [{"status": "high", "notifications": ["@pagerduty-security"]}]},
        {"id": "r2", "name": "Disabled", "type": "log_detection", "isEnabled": False,
         "cases": [{"status": "low", "notifications": ["@teams-ops"]}]},
        {"id": "r3", "name": "Workload rule", "type": "workload_security", "isEnabled": True,
         "cases": [{"status": "low", "notifications": ["@jira-board"]}]},
        {"id": "r4", "name": "No targets", "type": "signal_correlation", "isEnabled": True,
         "cases": [{"status": "info", "notifications": []}]},
    ],
    "meta": {"page": {"total_count": 4, "total_filtered_count": 4}},
}

WEBHOOK_BODY = {"name": "soar-intake", "url": "https://hooks.soar.example/ingest?token=x",
                "encode_as": "json", "payload": None, "custom_headers": None}


Route = Callable[[Optional[Dict[str, Any]]], FakeResponse]


def default_routes() -> Dict[str, Route]:
    return {
        CONTENT_PACKS: lambda p: FakeResponse(200, content_packs("logs")),
        SUPPRESSIONS: lambda p: FakeResponse(200, SUPPRESSION_BODY),
        NOTIFICATION_RULES: lambda p: FakeResponse(200, NOTIFICATION_RULES_BODY),
        RULES: lambda p: FakeResponse(200, RULES_BODY),
        WEBHOOKS + "soar-intake": lambda p: FakeResponse(200, WEBHOOK_BODY),
    }


@pytest.fixture
def run(monkeypatch, tmp_path):
    """Run the fetcher's main() against `routes`; returns (exit code, evidence, calls)."""

    def _run(routes: Dict[str, Route]) -> Tuple[int, Dict[str, Any], List[str]]:
        module = load_fetcher()
        calls: List[str] = []

        def fake_get(url, headers=None, params=None, timeout=None):
            assert url.startswith(BASE), url
            path = url[len(BASE):]
            calls.append(path)
            assert headers["DD-API-KEY"] == "api-key-for-test"
            route = routes.get(path)
            return route(params) if route else error(404)

        monkeypatch.setattr(module.requests, "get", fake_get)
        monkeypatch.setattr(module, "load_dotenv", lambda *a, **k: None)
        monkeypatch.setenv("DATADOG_API_KEY", "api-key-for-test")
        monkeypatch.setenv("DATADOG_APP_KEY", "app-key-for-test")
        monkeypatch.setenv("DATADOG_BASE_URL", BASE)
        monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
        monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
        code = module.main()
        evidence = json.loads((tmp_path / "datadog_siem_configuration.json").read_text())
        return code, evidence, calls

    return _run


def status_file(tmp_path: Path) -> Optional[Dict[str, Any]]:
    path = tmp_path / "status.json"
    return json.loads(path.read_text()) if path.exists() else None


def test_enabled_with_suppressions_reports_enabled(run, tmp_path):
    code, ev, calls = run(default_routes())

    assert code == 0
    assert ev["status"] == "success"
    assert ev["summary"]["siem_enabled"] is True
    assert ev["data"]["siem_state"]["sku"] == "add_on_2024"
    assert ev["summary"]["suppression_rules_count"] == 2
    assert ev["summary"]["enabled_suppression_rules"] == 1
    first = ev["data"]["suppression_rules"][0]
    assert first["enabled"] is True
    assert first["start_date"] == 1703187336000
    assert first["suppression_query"] == "env:staging"
    assert ev["errors"] == []
    assert status_file(tmp_path) is None
    # The documented path, not the old `suppression_rules` one.
    assert SUPPRESSIONS in calls
    assert not any("suppression_rules" in c for c in calls)


def test_404_on_a_sub_call_is_not_reported_as_siem_not_enabled(run, tmp_path):
    routes = default_routes()
    routes[SUPPRESSIONS] = lambda p: error(404)

    code, ev, _ = run(routes)

    assert code == 1
    assert ev["status"] == "error"
    assert ev["summary"]["siem_enabled"] is True
    assert ev["summary"]["suppression_rules_count"] is None
    assert ev["data"]["suppression_rules"] is None
    assert "not enabled" not in json.dumps(ev).lower()
    assert any(e["endpoint"] == SUPPRESSIONS and e["status_code"] == 404 for e in ev["errors"])
    assert status_file(tmp_path)["code"] == "partial_failure"


def test_403_on_a_sub_call_fails_as_not_authorized(run, tmp_path):
    routes = default_routes()
    routes[NOTIFICATION_RULES] = lambda p: error(403)

    code, ev, _ = run(routes)

    assert code == 1
    assert ev["summary"]["siem_enabled"] is True
    assert ev["summary"]["notification_types"] is None
    assert status_file(tmp_path)["code"] == "not_authorized"


def test_unreadable_siem_state_is_unknown_not_disabled(run, tmp_path):
    routes = default_routes()
    routes[CONTENT_PACKS] = lambda p: error(404)

    code, ev, _ = run(routes)

    assert code == 0
    assert ev["status"] == "success"
    assert ev["summary"]["siem_enabled"] is None
    assert ev["data"]["siem_state"]["status_code"] == 404
    assert ev["errors"][0]["endpoint"] == CONTENT_PACKS
    assert ev["summary"]["suppression_rules_count"] == 2


def test_onboarding_content_packs_report_not_enabled(run, tmp_path):
    routes = default_routes()
    routes[CONTENT_PACKS] = lambda p: FakeResponse(200, content_packs("onboarding"))

    code, ev, calls = run(routes)

    assert code == 0
    assert ev["status"] == "not_available"
    assert ev["summary"]["siem_enabled"] is False
    assert "not active" in ev["message"]
    assert calls == [CONTENT_PACKS]


def test_notification_types_come_from_enabled_configuration(run):
    code, ev, _ = run(default_routes())

    assert code == 0
    # Enabled notification rule: slack, email, webhook. Enabled SIEM rule:
    # pagerduty. Not opsgenie (disabled notification rule), teams (disabled
    # rule) or jira (not a Cloud SIEM rule type).
    assert ev["summary"]["notification_types"] == ["email", "pagerduty", "slack", "webhook"]
    assert [r["rule_id"] for r in ev["data"]["detection_rule_notifications"]] == ["r1"]
    assert ev["summary"]["enabled_notification_rules"] == 1
    assert ev["data"]["referenced_webhooks"] == [
        {"name": "soar-intake", "found": True, "url_domain": "hooks.soar.example"}
    ]
    assert "token=x" not in json.dumps(ev)


def test_webhook_named_in_a_target_but_missing_is_flagged(run):
    routes = default_routes()
    del routes[WEBHOOKS + "soar-intake"]

    code, ev, _ = run(routes)

    assert code == 0
    assert ev["data"]["referenced_webhooks"][0]["found"] is False
    assert ev["summary"]["missing_webhooks"] == ["soar-intake"]


def test_webhook_names_do_not_drive_notification_types(run):
    routes = default_routes()
    body = json.loads(json.dumps(NOTIFICATION_RULES_BODY))
    body["data"][0]["attributes"]["targets"] = ["@webhook-slack-pagerduty-bridge"]
    routes[NOTIFICATION_RULES] = lambda p: FakeResponse(200, body)
    routes[RULES] = lambda p: FakeResponse(200, {"data": []})
    routes[WEBHOOKS + "slack-pagerduty-bridge"] = lambda p: FakeResponse(
        200, {"name": "slack-pagerduty-bridge", "url": "https://bridge.example/x"})

    _, ev, _ = run(routes)

    assert ev["summary"]["notification_types"] == ["webhook"]


def test_suppressions_are_paged(run):
    def page(params):
        n = params["page[number]"]
        size = params["page[size]"]
        start = n * size
        count = max(0, min(size, 150 - start))
        return FakeResponse(200, {"data": [
            {"id": f"s{i}", "type": "suppressions", "attributes": {"name": f"s{i}", "enabled": True}}
            for i in range(start, start + count)
        ]})

    routes = default_routes()
    routes[SUPPRESSIONS] = page

    _, ev, calls = run(routes)

    assert ev["summary"]["suppression_rules_count"] == 150
    assert calls.count(SUPPRESSIONS) == 2


@pytest.mark.parametrize("target,expected", [
    ("@slack-secops", ("slack", None)),
    ("slack-secops", ("slack", None)),
    ("@pagerduty-Security", ("pagerduty", None)),
    ("@webhook-soar", ("webhook", "soar")),
    ("@teams-ops", ("teams", None)),
    ("@team-platform", ("team", None)),
    ("@jane@example.com", ("email", None)),
    ("@something-else", ("other", None)),
])
def test_classify_target(target, expected):
    assert load_fetcher().classify_target(target) == expected
