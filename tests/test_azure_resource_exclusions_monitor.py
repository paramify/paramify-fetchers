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
routing = sys.modules["alert_routing"]
FAR = "/subscriptions/s2/resourceGroups/rg-far"
SUPPRESS = {"actionType": "RemoveAllActionGroups"}


def _metric_rule(rg: str, name: str, location: str, group: str) -> dict:
    return {"id": f"{rg}/providers/Microsoft.Insights/metricAlerts/{name}", "name": name, "location": location,
            "properties": {"enabled": True, "severity": 2, "scopes": [f"{rg}/providers/x/y/z"],
                           "actions": [{"actionGroupId": group}]}}


def _group(rg: str, name: str) -> dict:
    return {"id": f"{rg}/providers/microsoft.insights/actionGroups/{name}", "name": name, "enabled": True,
            "deliverable": True, "notifies_people": True, "receivers": [], "receiver_kinds": ["email"]}


def _far(name: str) -> str:
    return f"{FAR}/providers/microsoft.insights/actionGroups/{name}"


def _processing_rule(rg: str, name: str, scope: str, action: dict) -> dict:
    return {"id": f"{rg}/providers/Microsoft.AlertsManagement/actionRules/{name}", "name": name,
            "properties": {"enabled": True, "scopes": [scope], "actions": [action]}}


def _adds(group_id: str) -> dict:
    return {"actionType": "AddActionGroups", "actionGroupIds": [group_id]}


def run_alert_rules_reads(monkeypatch, tmp_path, patterns, extra_rules=(), processing=(), failing=()):
    """GETs of other subscriptions' groups append the group's name to fetched; a name in failing raises."""
    out_group = _group(OUT_RG, "ag-out")
    in_group = _group(IN_RG, "ag-in")
    rules = [_metric_rule(IN_RG, "in-rule", "global", out_group["id"]),
             _metric_rule(OUT_RG, "out-rule", "global", in_group["id"]),
             _metric_rule(IN_RG, "east-rule", "regioneast", in_group["id"]), *extra_rules]
    fetched: list = []

    def fetch(rest, gid):
        name = gid.rsplit("/", 1)[1]
        fetched.append(name)
        if name in failing:
            raise RuntimeError("(InternalServerError) the action group could not be read")
        return _group(FAR, name)

    m = rules_fetcher
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(m, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(m, "list_all", lambda rest, path, api: {
        "items": rules if path.endswith("metricAlerts") else [], "pages": 1})
    monkeypatch.setattr(m, "collect_action_groups", lambda rest, sub: {"groups": [in_group, out_group]})
    monkeypatch.setattr(m, "collect_processing_rules", lambda rest, sub, now: {
        "rules": [routing.processing_rule_record(p, now) for p in processing]})
    monkeypatch.setattr(routing, "fetch_action_group", fetch)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)
    code = m.main()
    return code, json.loads((tmp_path / "azure_alert_rules_s1.json").read_text()), fetched


def run_alert_rules(monkeypatch, tmp_path, patterns, **fakes):
    code, evidence, _ = run_alert_rules_reads(monkeypatch, tmp_path, patterns, **fakes)
    return code, evidence


def _without_clock(results: dict) -> dict:
    return {k: v for k, v in results.items() if k != "evaluated_at"}


FAR_RULES = (_metric_rule(IN_RG, "far-in-rule", "global", _far("ag-far-in")),
             _metric_rule(OUT_RG, "far-out-rule", "global", _far("ag-far-out")))
FAR_PROCESSING = (
    _processing_rule(IN_RG, "apr-in", f"{SUB}/resourceGroups/rg-quiet", _adds(_far("ag-far-apr-in"))),
    _processing_rule(OUT_RG, "apr-out", OUT_RG, _adds(_far("ag-far-apr-out"))),
    # Excluded, but it adds a group to every in-scope rule under rg-in.
    _processing_rule(OUT_RG, "apr-routes-in", IN_RG, _adds(_far("ag-far-routed"))),
)


def test_alert_rules_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_alert_rules(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        "total_alert_rules": 3, "rules_by_type": {"metric": 3}, "alerting_rules": 3, "enabled_alerting_rules": 3,
        "disabled_alerting_rules": 0, "enabled_rules_without_action_groups": 0,
        "enabled_rules_routing_to_enabled_receiver": 3, "enabled_rules_routing_unknown": 0,
        "enabled_rules_routing_to_person": 3, "enabled_rules_suppressed": 0, "enabled_rules_possibly_suppressed": 0,
        "enabled_rules_reaching_human": 3, "enabled_rules_reaching_human_unknown": 0,
        "enabled_rules_not_reaching_human": 0, "reaching_human_percentage": 100, "all_enabled_rules_reach_human": True,
        "log_search_rules_enabled": 0, "action_groups": 2, "deliverable_action_groups": 2,
        "action_groups_notifying_people": 2, "processing_rules": 0, "suppressing_processing_rules_active": 0,
        "provider_registration_status": {"Microsoft.Insights": "registered", "Microsoft.AlertsManagement": "registered"},
        "resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
        "excluded_alert_rules": 0, "excluded_action_groups": 0, "excluded_processing_rules": 0,
        "in_scope_alert_rules": 3, "in_scope_action_groups": 2, "in_scope_processing_rules": 0,
    }


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


def test_alert_rules_excluded_suppression_rule_still_mutes_in_scope_rules_but_leaves_the_counts(monkeypatch, tmp_path):
    processing = [_processing_rule(OUT_RG, "apr-mute", IN_RG, SUPPRESS)]
    code, evidence = run_alert_rules(monkeypatch, tmp_path, "rg:rg-out", processing=processing)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["processing_rules"] == []
    [entry] = [e for e in results["excluded"] if e["kind"] == "processing_rule"]
    assert (entry["name"], entry["pattern"], entry["location"]) == ("apr-mute", "rg:rg-out", None)
    assert (summary["processing_rules"], summary["suppressing_processing_rules_active"],
            summary["in_scope_processing_rules"], summary["excluded_processing_rules"]) == (0, 0, 0, 1)
    assert {r["name"]: r["suppressed"] for r in results["alert_rules"]} == {"in-rule": True, "east-rule": True}
    assert (summary["enabled_rules_suppressed"], summary["enabled_rules_reaching_human"]) == (2, 0)
    # in-rule still routes to the excluded ag-out, which deliverable_action_groups leaves out.
    assert (summary["enabled_rules_routing_to_enabled_receiver"], summary["deliverable_action_groups"]) == (2, 1)


def test_alert_rules_location_patterns_reach_no_action_group_or_processing_rule(monkeypatch, tmp_path):
    processing = [_processing_rule(IN_RG, "apr-mute", IN_RG, SUPPRESS)]
    _, evidence = run_alert_rules(monkeypatch, tmp_path, "location:*", processing=processing)
    assert {e["kind"] for e in evidence["results"]["excluded"]} == {"alert_rule"}
    assert (evidence["summary"]["in_scope_action_groups"], evidence["summary"]["in_scope_processing_rules"]) == (2, 1)


def test_alert_rules_read_other_subscriptions_groups_only_for_in_scope_routes(monkeypatch, tmp_path):
    _, plain, fetched = run_alert_rules_reads(monkeypatch, tmp_path, None, FAR_RULES, FAR_PROCESSING)
    assert sorted(fetched) == ["ag-far-apr-in", "ag-far-apr-out", "ag-far-in", "ag-far-out", "ag-far-routed"]
    _, evidence, fetched = run_alert_rules_reads(monkeypatch, tmp_path, "rg:rg-out", FAR_RULES, FAR_PROCESSING)
    assert sorted(fetched) == ["ag-far-apr-in", "ag-far-in", "ag-far-routed"]
    kept = {"in-rule", "east-rule", "far-in-rule"}
    rules = evidence["results"]["alert_rules"]
    assert {r["name"] for r in rules} == kept
    assert rules == [r for r in plain["results"]["alert_rules"] if r["name"] in kept]
    [in_rule] = [r for r in rules if r["name"] == "in-rule"]
    assert [g["found"] for g in in_rule["resolved_action_groups"] if g["id"] == _far("ag-far-routed")] == [True]


def test_alert_rules_failed_group_reads_for_excluded_rules_leave_the_run_ok(monkeypatch, tmp_path):
    fakes = {"extra_rules": FAR_RULES, "processing": FAR_PROCESSING}
    failing = ("ag-far-out", "ag-far-apr-out")
    code, _ = run_alert_rules(monkeypatch, tmp_path, None, failing=failing, **fakes)
    assert code == 1
    _, clean = run_alert_rules(monkeypatch, tmp_path, "rg:rg-out", **fakes)
    code, evidence = run_alert_rules(monkeypatch, tmp_path, "rg:rg-out", failing=failing, **fakes)
    assert code == 0
    assert evidence["summary"] == clean["summary"]
    assert _without_clock(evidence["results"]) == _without_clock(clean["results"])


def test_alert_rules_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_alert_rules(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_alert_rules"] == 3
