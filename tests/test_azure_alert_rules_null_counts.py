"""A processing rule list that could not be read gives null suppression fields, never "not suppressed"."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_null_counts", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rules_fetcher = _load("alert_rules")
routing = sys.modules["alert_routing"]
RG = "/subscriptions/s1/resourceGroups/rg1"
GROUP = f"{RG}/providers/microsoft.insights/actionGroups/ag1"
RULE = {"id": f"{RG}/providers/Microsoft.Insights/metricAlerts/r1", "name": "r1", "location": "global",
        "properties": {"enabled": True, "severity": 2, "scopes": [f"{RG}/providers/x/y/z"],
                       "actions": [{"actionGroupId": GROUP}]}}
SUPPRESS_ALL = {"id": f"{RG}/providers/Microsoft.AlertsManagement/actionRules/apr", "name": "apr",
                "properties": {"enabled": True, "scopes": [RG], "actions": [{"actionType": "RemoveAllActionGroups"}]}}
SUPPRESSION_FIELDS = rules_fetcher.SUPPRESSION_FIELDS


def _run(monkeypatch, tmp_path, processing, refuse_processing=False):
    group = {"id": GROUP, "name": "ag1", "enabled": True, "deliverable": True, "notifies_people": True,
             "receivers": [], "receiver_kinds": ["email"]}
    m = rules_fetcher

    def processing_rules(rest, sub, now):
        if refuse_processing:
            raise PermissionError("(AuthorizationFailed) 403")
        return {"rules": [routing.processing_rule_record(p, now) for p in processing]}

    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(m, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(m, "list_all", lambda rest, path, api: {"items": [RULE] if path.endswith("metricAlerts") else [], "pages": 1})
    monkeypatch.setattr(m, "collect_action_groups", lambda rest, sub: {"groups": [group]})
    monkeypatch.setattr(m, "collect_processing_rules", processing_rules)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = m.main()
    evidence = json.loads((tmp_path / "azure_alert_rules_s1.json").read_text())
    return code, evidence["results"]["alert_rules"], evidence["summary"]


def test_refused_processing_rule_list_gives_null_suppression_fields(monkeypatch, tmp_path):
    code, rules, summary = _run(monkeypatch, tmp_path, [], refuse_processing=True)
    assert code == 1
    assert (rules[0]["suppressed"], rules[0]["reaches_human"]) == (None, None)
    assert {k: summary[k] for k in SUPPRESSION_FIELDS if summary[k] is not None} == {}
    for key in ("processing_rules", "in_scope_processing_rules", "excluded_processing_rules"):
        assert summary[key] is None, key
    # What does not depend on the processing rules still reads.
    assert summary["total_alert_rules"] == 1 and summary["enabled_alerting_rules"] == 1


def test_read_empty_processing_rule_list_still_counts_zero_and_false(monkeypatch, tmp_path):
    code, rules, summary = _run(monkeypatch, tmp_path, [])
    assert code == 0
    assert (rules[0]["suppressed"], rules[0]["reaches_human"]) == (False, True)
    assert summary["enabled_rules_suppressed"] == 0 and summary["enabled_rules_possibly_suppressed"] == 0
    assert summary["suppressing_processing_rules_active"] == 0
    assert (summary["processing_rules"], summary["in_scope_processing_rules"],
            summary["excluded_processing_rules"]) == (0, 0, 0)
    assert summary["enabled_rules_reaching_human"] == 1 and summary["all_enabled_rules_reach_human"] is True


def test_read_suppression_rule_still_suppresses(monkeypatch, tmp_path):
    code, rules, summary = _run(monkeypatch, tmp_path, [SUPPRESS_ALL])
    assert code == 0
    assert (rules[0]["suppressed"], rules[0]["reaches_human"]) == (True, False)
    assert summary["enabled_rules_suppressed"] == 1 and summary["enabled_rules_not_reaching_human"] == 1


@pytest.mark.parametrize("enabled, expected", [(True, None), (False, False)])
def test_route_with_unread_processing_rules_is_unknown_only_for_enabled_rules(enabled, expected):
    r = routing.route(enabled, [GROUP], [RG], {GROUP.lower(): {"enabled": True, "deliverable": True, "notifies_people": True,
                                                              "receivers": []}}, None)
    assert r["suppressed"] is expected
    assert r["reaches_human"] is (None if enabled else False)
