"""resource_exclusions in the Azure Monitor fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rules_fetcher = _load("alert_rules")


def _metric_rule(rg: str, name: str, location: str, group: str) -> dict:
    return {"id": f"{rg}/providers/Microsoft.Insights/metricAlerts/{name}", "name": name, "location": location,
            "properties": {"enabled": True, "severity": 2, "scopes": [f"{rg}/providers/x/y/z"],
                           "actions": [{"actionGroupId": group}]}}


def _group(rg: str, name: str) -> dict:
    return {"id": f"{rg}/providers/microsoft.insights/actionGroups/{name}", "name": name, "enabled": True,
            "deliverable": True, "notifies_people": True, "receivers": [], "receiver_kinds": ["email"]}


def run_alert_rules(monkeypatch, tmp_path, patterns):
    out_group = _group(OUT_RG, "ag-out")
    in_group = _group(IN_RG, "ag-in")
    rules = [_metric_rule(IN_RG, "in-rule", "global", out_group["id"]),
             _metric_rule(OUT_RG, "out-rule", "global", in_group["id"]),
             _metric_rule(IN_RG, "east-rule", "regioneast", in_group["id"])]
    m = rules_fetcher
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(m, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(m, "list_all", lambda rest, path, api: {
        "items": rules if path.endswith("metricAlerts") else [], "pages": 1})
    monkeypatch.setattr(m, "collect_action_groups", lambda rest, sub: {"groups": [in_group, out_group]})
    monkeypatch.setattr(m, "collect_processing_rules", lambda rest, sub, now: {"rules": []})
    monkeypatch.setattr(m, "add_referenced_groups", lambda *a: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)
    code = m.main()
    return code, json.loads((tmp_path / "azure_alert_rules_s1.json").read_text())


def test_alert_rules_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_alert_rules(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert summary["total_alert_rules"] == summary["in_scope_alert_rules"] == 3
    assert summary["action_groups"] == summary["in_scope_action_groups"] == 2
    assert summary["excluded_alert_rules"] == summary["excluded_action_groups"] == 0


def test_alert_rules_exclude_by_group_and_region_but_keep_routing_to_an_excluded_group(monkeypatch, tmp_path):
    code, evidence = run_alert_rules(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [r["name"] for r in results["alert_rules"]] == ["in-rule"]
    assert results["alert_rules"][0]["reaches_human"] is True
    assert [g["name"] for g in results["action_groups"]] == ["ag-in"]
    assert sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"]) == [
        ("action_group", "ag-out", "rg:rg-out"),
        ("alert_rule", "east-rule", "location:regioneast"),
        ("alert_rule", "out-rule", "rg:rg-out"),
    ]
    assert (summary["total_alert_rules"], summary["in_scope_alert_rules"], summary["excluded_alert_rules"]) == (1, 1, 2)
    assert (summary["action_groups"], summary["excluded_action_groups"]) == (1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_alert_rules_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_alert_rules(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_alert_rules"] == 3
