"""resource_exclusions in the Azure fetchers whose records point at a resource: changes, grants, custom roles, alerts."""

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

import azure_rest  # noqa: E402
from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
MG = "/providers/Microsoft.Management/managementGroups/mg1"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_references_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cp = _load("change_provenance")
ra = _load("rbac_role_assignments")
cr = _load("rbac_custom_roles")
fa = _load("monitor_fired_alerts")


def _env(monkeypatch, tmp_path, patterns):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


def _run(m, monkeypatch, tmp_path, patterns, filename):
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    _env(monkeypatch, tmp_path, patterns)
    code = m.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _added_fields(kinds: dict) -> dict:
    """The fields a run without patterns adds to the summary: kind -> in-scope total."""
    return {
        "resource_exclusion_patterns": [],
        "resource_exclusion_patterns_unmatched": [],
        **{f"excluded_{kind}s": 0 for kind in kinds},
        **{f"in_scope_{kind}s": total for kind, total in kinds.items()},
    }


def _excluded(evidence) -> list:
    return sorted((e["kind"], e["name"], e["pattern"], e["reason"]) for e in evidence["results"]["excluded"])


# --- change_provenance ---

APP_X = f"{IN_RG}/providers/Microsoft.Web/sites/app-x"
SA_IN = f"{IN_RG}/providers/Microsoft.Storage/storageAccounts/sa-in"
SA_IN2 = f"{IN_RG}/providers/Microsoft.Storage/storageAccounts/sa-in2"
SA_OUT = f"{OUT_RG}/providers/Microsoft.Storage/storageAccounts/sa-out"


def _change(cid, target, when, by="alice@example.com", by_type="User", client="Azure Portal", correlation=None,
            table="resourcechanges"):
    return cp.change_record({
        "changeId": f"{target}/providers/Microsoft.Resources/changes/{cid}", "targetResourceId": target,
        "targetResourceType": "x", "changeType": "Update", "timestamp": when, "changedBy": by,
        "changedByType": by_type, "clientType": client, "operation": "write", "correlationId": correlation,
        "changesCount": 1, "changedProperties": ["tags"]}, table)


def _cp_records():
    changes = [
        _change("c-in", SA_IN, "2026-10-10T10:00:00Z"),
        _change("c-out", SA_OUT, "2026-10-10T10:01:00Z"),
        _change("c-sub", SUB, "2026-10-10T10:02:00Z", table="resourcecontainerchanges"),
        _change("c-rg-out", OUT_RG, "2026-10-10T10:03:00Z", table="resourcecontainerchanges"),
        _change("c-app-x", APP_X, "2026-10-10T10:04:00Z", by="bob@example.com"),
        # A person's deployment, seen only through a change to an excluded resource...
        _change("c-dep-out", SA_OUT, "2026-10-10T11:00:30Z", client="CLI", correlation="corr-1"),
        # ...and a callerless change to an in-scope output of the same deployment, which takes its origin from it.
        _change("c-dep-in", SA_IN2, "2026-10-10T11:00:40Z", by="System", by_type=None, client=None),
    ]
    deployments = [{
        "id": f"{IN_RG}/providers/Microsoft.Resources/deployments/dep1", "name": "dep1", "scope": "resource_group",
        "resource_group": "rg-in", "provisioning_state": "Succeeded", "started": "2026-10-10T11:00:00Z",
        "timestamp": "2026-10-10T11:01:00Z", "duration": "PT1M", "correlation_id": "corr-1", "mode": "Incremental",
        "template_hash": "h", "template_link": None, "output_resource_ids": [SA_OUT, SA_IN2],
    }]
    return changes, deployments


def run_cp(monkeypatch, tmp_path, patterns):
    changes, deployments = _cp_records()
    monkeypatch.setattr(cp, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(cp, "collect_changes", lambda sub, cred, days, collector: (changes, {}))
    monkeypatch.setattr(cp, "collect_deployments", lambda sub, cred, collector: (deployments, [], ["rg-in", "rg-out"]))
    monkeypatch.delenv("AZURE_PIPELINE_PRINCIPALS", raising=False)
    monkeypatch.delenv("AZURE_CHANGE_LOOKBACK_DAYS", raising=False)
    return _run(cp, monkeypatch, tmp_path, patterns, "azure_change_provenance")


def _cp_summary(keep):
    changes, deployments = _cp_records()
    attributed = [c for c in cp.attribute(changes, deployments) if keep(c)]
    return cp.summarize(attributed, deployments, [], {"rg-in", "rg-out"})


def test_change_provenance_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_cp(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {**_cp_summary(lambda c: True), **_added_fields({"change": 7})}


def test_change_provenance_drops_changes_to_excluded_targets_and_keeps_attribution(monkeypatch, tmp_path):
    code, evidence = run_cp(monkeypatch, tmp_path, f"rg:rg-out, id:{APP_X}, location:regionwest, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("change", "c-app-x", f"id:{APP_X}", "target_matched"),
        ("change", "c-dep-out", "rg:rg-out", "target_matched"),
        ("change", "c-out", "rg:rg-out", "target_matched"),
        ("change", "c-rg-out", "rg:rg-out", "target_matched"),
    ]
    assert next(e for e in results["excluded"] if e["name"] == "c-rg-out")["target_id"] == OUT_RG
    # The subscription's own change stays, as do changes to in-scope resources.
    assert [c["change_id"].rsplit("/", 1)[-1] for c in results["changes"]] == ["c-in", "c-sub", "c-dep-in"]
    # The in-scope change still takes its origin from the deployment's excluded change.
    dep_in = results["changes"][-1]
    assert (dep_in["origin"], dep_in["attribution"]) == ("manual_deployment", "deployment_window")
    assert summary == {
        **_cp_summary(lambda c: c["target_resource_id"] in (SA_IN, SUB, SA_IN2)),
        "resource_exclusion_patterns": ["rg:rg-out", f"id:{APP_X}", "location:regionwest", "rg:typo"],
        "resource_exclusion_patterns_unmatched": ["location:regionwest", "rg:typo"],
        "excluded_changes": 4, "in_scope_changes": 3,
    }
    assert (summary["total_changes"], summary["direct_changes"], summary["manual_deployment_changes"]) == (3, 2, 1)
    assert summary["direct_changes_by_changed_by"] == {"alice@example.com": 2}
    # What was read stays: the deployment and who ran it.
    assert summary["deployments_in_history"] == 1
    assert results["deployments"][0]["run_by"] == ["alice@example.com"]


def test_a_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_cp(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"
    assert evidence["summary"]["total_changes"] == 7


# --- rbac_role_assignments ---

READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
ROLE_NAMES = {ra.OWNER_ROLE_ID: {"role_name": "Owner", "role_type": "BuiltInRole"},
              READER: {"role_name": "Reader", "role_type": "BuiltInRole"}}
KV_OUT = f"{IN_RG}/providers/Microsoft.KeyVault/vaults/kv-out"


def _grant(name, scope, role, principal):
    return ra.assignment_record({
        "id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}", "name": name, "scope": scope,
        "principal_id": principal, "principal_type": "User",
        "role_definition_id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{role}"}, ROLE_NAMES)


def _eligible(name, scope, role, principal):
    return ra.eligibility_record({
        "id": f"{scope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/{name}", "scope": scope,
        "principal_id": principal, "principal_type": "User",
        "role_definition_id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{role}"}, ROLE_NAMES)


def _ra_records():
    at_scope = [_grant("a-sub", SUB, ra.OWNER_ROLE_ID, "p1"), _grant("a-mg", MG, READER, "p2")]
    below = [
        _grant("b-in", IN_RG, READER, "p3"),
        _grant("b-out", OUT_RG, ra.OWNER_ROLE_ID, "p4"),
        _grant("b-kv", KV_OUT, ra.OWNER_ROLE_ID, "p5"),
        _grant("b-vault-in", f"{IN_RG}/providers/Microsoft.KeyVault/vaults/kv-in", ra.OWNER_ROLE_ID, "p6"),
    ]
    schedules = [{"origin_role_assignment_id": below[1]["id"], "assignment_type": "Assigned",
                  "end_date_time": "2027-01-01T00:00:00Z"}]
    eligible = [_eligible("e-sub", SUB, ra.OWNER_ROLE_ID, "p7"), _eligible("e-in", IN_RG, ra.OWNER_ROLE_ID, "p8"),
                _eligible("e-out", OUT_RG, ra.OWNER_ROLE_ID, "p9")]
    return at_scope, below, schedules, eligible


def run_ra(monkeypatch, tmp_path, patterns):
    at_scope, below, schedules, eligible = _ra_records()
    monkeypatch.setattr(ra, "credential", lambda: object())
    monkeypatch.setattr(ra, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(ra, "authorization_client", lambda *a: object())
    monkeypatch.setattr(ra, "collect_role_assignments", lambda *a: (at_scope, below, ROLE_NAMES))
    monkeypatch.setattr(ra, "collect_pim", lambda *a: {
        "available": True, "schedules": schedules, "eligible": eligible, "policies": None, "notes": []})
    return _run(ra, monkeypatch, tmp_path, patterns, "azure_rbac_role_assignments")


def _ra_summary(keep):
    at_scope, below, schedules, eligible = _ra_records()
    ra.add_pim_fields(at_scope + below, schedules)
    at_scope, below = [a for a in at_scope if keep(a)], [a for a in below if keep(a)]
    eligible = [e for e in eligible if keep(e)]
    return {**ra.summarize(at_scope), **ra.summarize_all_scopes(at_scope, below),
            "provider_registration_status": "registered",
            **ra.summarize_pim(at_scope + below, True, eligible, None, True)}


def test_rbac_assignments_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_ra(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        **_ra_summary(lambda r: True), **_added_fields({"role_assignment": 6, "eligible_role_assignment": 3})}


def test_rbac_grants_at_excluded_scopes_leave_and_wider_scopes_stay(monkeypatch, tmp_path):
    code, evidence = run_ra(monkeypatch, tmp_path, f"rg:rg-out, id:{KV_OUT}, id:{MG}, location:regionwest")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("eligible_role_assignment", "e-out", "rg:rg-out", "scope_matched"),
        ("role_assignment", "b-kv", f"id:{KV_OUT}", "scope_matched"),
        ("role_assignment", "b-out", "rg:rg-out", "scope_matched"),
    ]
    out = next(e for e in results["excluded"] if e["name"] == "b-out")
    assert (out["scope"], out["principal_id"], out["role_name"]) == (OUT_RG, "p4", "Owner")
    # The management group grant stays even though an id: pattern names its scope.
    assert [a["name"] for a in results["role_assignments"]] == ["a-sub", "a-mg"]
    assert [a["name"] for a in results["role_assignments_below_subscription"]] == ["b-in", "b-vault-in"]
    assert [e["principal_id"] for e in results["eligible_role_assignments"]] == ["p7", "p8"]
    kept = {"a-sub", "a-mg", "b-in", "b-vault-in", "e-sub", "e-in"}
    assert summary == {
        **_ra_summary(lambda r: (r.get("name") or r["id"].rsplit("/", 1)[-1]) in kept),
        "resource_exclusion_patterns": ["rg:rg-out", f"id:{KV_OUT}", f"id:{MG}", "location:regionwest"],
        "resource_exclusion_patterns_unmatched": [f"id:{MG}", "location:regionwest"],
        "excluded_role_assignments": 2, "excluded_eligible_role_assignments": 1,
        "in_scope_role_assignments": 4, "in_scope_eligible_role_assignments": 2,
    }
    assert (summary["all_scopes_over_broad_builtin_assignments"], summary["below_subscription_role_assignments"],
            summary["permanent_over_broad_assignments"], summary["eligible_over_broad_assignments"]) == (2, 2, 2, 2)
    # The excluded time-bound grant leaves the standing counts with it.
    assert summary["assignments_by_standing"] == {"permanent": 4, "pim_activated": 0, "time_bound": 0}


MSI = "providers/Microsoft.ManagedIdentity/userAssignedIdentities"


IDENTITIES = tuple(f"{OUT_RG}/{MSI}/{n}" for n in ("id-reach", "id-idle", "id-unread"))


def _run_identity_grants(monkeypatch, tmp_path, patterns):
    reach, idle, unread = IDENTITIES
    at_scope, below, schedules, eligible = _ra_records()
    below += [
        _grant("b-on-reach", reach, ra.OWNER_ROLE_ID, "p10"),  # controls an identity that holds a role in rg-in
        _grant("b-reach-in", IN_RG, READER, "pid-reach"),
        _grant("b-on-idle", idle, ra.OWNER_ROLE_ID, "p11"),  # its identity holds roles only in the excluded group
        _grant("b-idle-out", OUT_RG, READER, "pid-idle"),
        _grant("b-on-unread", unread, ra.OWNER_ROLE_ID, "p12"),
    ]
    eligible += [_eligible("e-on-reach", reach, ra.OWNER_ROLE_ID, "p13")]
    reads: list = []
    monkeypatch.setattr(ra, "identity_principal_ids", lambda cred, scopes: reads.extend(scopes) or {
        reach.lower(): "pid-reach", idle.lower(): "pid-idle"})
    monkeypatch.setattr(ra, "credential", lambda: object())
    monkeypatch.setattr(ra, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(ra, "authorization_client", lambda *a: object())
    monkeypatch.setattr(ra, "collect_role_assignments", lambda *a: (at_scope, below, ROLE_NAMES))
    monkeypatch.setattr(ra, "collect_pim", lambda *a: {
        "available": True, "schedules": schedules, "eligible": eligible, "policies": None, "notes": []})
    code, evidence = _run(ra, monkeypatch, tmp_path, patterns, "azure_rbac_role_assignments")
    return code, evidence, reads


def test_rbac_grants_on_an_excluded_identity_that_reaches_in_scope_stay(monkeypatch, tmp_path):
    reach, idle, unread = IDENTITIES
    code, evidence, reads = _run_identity_grants(monkeypatch, tmp_path, "rg:rg-out")
    results = evidence["results"]
    assert code == 0
    assert sorted(reads) == sorted([idle, reach, unread])
    # A grant on the whole group still leaves; grants on an identity reaching in, or one that couldn't be read, stay.
    assert _excluded(evidence) == [
        ("eligible_role_assignment", "e-out", "rg:rg-out", "scope_matched"),
        ("role_assignment", "b-idle-out", "rg:rg-out", "scope_matched"),
        ("role_assignment", "b-on-idle", "rg:rg-out", "scope_matched"),
        ("role_assignment", "b-out", "rg:rg-out", "scope_matched"),
    ]
    below = {a["name"]: a for a in results["role_assignments_below_subscription"]}
    assert {"b-on-reach", "b-on-unread", "b-reach-in"} <= set(below)
    assert (below["b-on-reach"]["kept_by_identity_rule"], below["b-on-unread"]["kept_by_identity_rule"]) == (
        "rg:rg-out", "rg:rg-out")
    assert "kept_by_identity_rule" not in below["b-reach-in"]
    eligible = {e["principal_id"]: e for e in results["eligible_role_assignments"]}
    assert eligible["p13"]["kept_by_identity_rule"] == "rg:rg-out"
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] == []


def test_rbac_an_id_pattern_on_a_reaching_identity_counts_as_matched_though_its_grants_stay(monkeypatch, tmp_path, caplog):
    reach = IDENTITIES[0]
    code, evidence, _ = _run_identity_grants(monkeypatch, tmp_path, f"id:{reach}")
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] == []
    assert "matched nothing" not in caplog.text
    kept = [a["name"] for a in evidence["results"]["role_assignments_below_subscription"] if "kept_by_identity_rule" in a]
    assert kept == ["b-on-reach"]


def test_rbac_reads_no_identity_without_patterns_or_identity_grants(monkeypatch, tmp_path):
    monkeypatch.setattr(ra, "identity_principal_ids", lambda *a: pytest.fail("no identity read expected"))
    assert run_ra(monkeypatch, tmp_path, None)[0] == 0
    assert run_ra(monkeypatch, tmp_path, "rg:rg-out")[0] == 0


# --- rbac_custom_roles ---

VM_OUT = f"{IN_RG}/providers/Microsoft.Compute/virtualMachines/vm-out"


def _role(name, scopes, actions=("Microsoft.Compute/virtualMachines/read",)):
    return cr.custom_role_record({
        "id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{name}", "name": name, "role_name": name,
        "role_type": "CustomRole", "assignable_scopes": scopes, "permissions": [{"actions": list(actions)}]})


def _cr_records():
    return sorted([
        _role("r-out", [OUT_RG], ["Microsoft.Authorization/roleAssignments/write"]),
        _role("r-two-out", [OUT_RG, VM_OUT], ["*"]),
        _role("r-mixed", [OUT_RG, IN_RG], ["Microsoft.Authorization/roleAssignments/write"]),
        _role("r-sub", [SUB]),
        _role("r-mg", [MG]),
    ], key=lambda r: r["id"])


def run_cr(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(cr, "credential", lambda: object())
    monkeypatch.setattr(cr, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(cr, "collect_custom_roles", lambda *a: (_cr_records(), 9))
    return _run(cr, monkeypatch, tmp_path, patterns, "azure_rbac_custom_roles")


def test_custom_roles_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_cr(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        **cr.summarize(_cr_records(), 9), "provider_registration_status": "registered",
        **_added_fields({"custom_role": 5})}


def test_a_custom_role_leaves_only_when_every_assignable_scope_is_excluded(monkeypatch, tmp_path):
    code, evidence = run_cr(monkeypatch, tmp_path, f"rg:rg-out, id:{VM_OUT}, id:{MG}, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("custom_role", "r-out", "rg:rg-out", "all_scopes_matched"),
        ("custom_role", "r-two-out", "rg:rg-out", "all_scopes_matched"),
    ]
    two = next(e for e in results["excluded"] if e["name"] == "r-two-out")
    assert two["matched_scopes"] == [{"scope": OUT_RG, "pattern": "rg:rg-out"}, {"scope": VM_OUT, "pattern": f"id:{VM_OUT}"}]
    assert two["id"].endswith("/roleDefinitions/r-two-out")
    assert sorted(r["role_name"] for r in results["custom_roles"]) == ["r-mg", "r-mixed", "r-sub"]
    in_scope = [r for r in _cr_records() if r["role_name"] in ("r-mg", "r-mixed", "r-sub")]
    assert summary == {
        **cr.summarize(in_scope, 9, 2), "provider_registration_status": "registered",
        "resource_exclusion_patterns": ["rg:rg-out", f"id:{VM_OUT}", f"id:{MG}", "rg:typo"],
        "resource_exclusion_patterns_unmatched": [f"id:{MG}", "rg:typo"],
        "excluded_custom_roles": 2, "in_scope_custom_roles": 3,
    }
    assert (summary["total_role_definitions"], summary["builtin_role_definitions"],
            summary["custom_role_definitions"]) == (9, 4, 3)
    assert (summary["custom_roles_with_privilege_escalation"], summary["custom_roles_with_escalation_names"],
            summary["owner_equivalent_custom_roles"]) == (1, ["r-mixed"], 0)


# --- monitor_fired_alerts ---

RULE_IN = f"{IN_RG}/providers/Microsoft.Insights/metricAlerts/cpu-in"
RULE_QUIET = f"{IN_RG}/providers/Microsoft.Insights/metricAlerts/cpu-quiet"
RULE_OUT = f"{OUT_RG}/providers/Microsoft.Insights/metricAlerts/cpu-out"
APP_IN = f"{IN_RG}/providers/Microsoft.Web/sites/app-in"
APP_OUT = f"{OUT_RG}/providers/Microsoft.Web/sites/app-out"


def _raw_alert(n, rule, target, state="New"):
    return {"id": f"{SUB}/providers/Microsoft.AlertsManagement/alerts/a{n}", "name": f"alert {n}",
            "properties": {"essentials": {
                "alertRule": rule, "severity": "Sev2", "monitorService": "Platform", "monitorCondition": "Fired",
                "alertState": state, "targetResource": target, "targetResourceName": target.rsplit("/", 1)[-1],
                "targetResourceType": "Microsoft.Web/sites", "startDateTime": f"2026-10-1{n}T10:00:00Z"}}}


RAW_ALERTS = [
    _raw_alert(1, RULE_IN, APP_IN),
    _raw_alert(2, RULE_IN, APP_OUT),
    _raw_alert(3, RULE_OUT, APP_IN, state="Closed"),  # an excluded rule's alert on an in-scope resource stays
    _raw_alert(4, RULE_QUIET, APP_X),
    _raw_alert(5, "ServiceHealth", SUB),
]
RAW_RULES = [{"id": r, "name": r.rsplit("/", 1)[-1], "properties": {"enabled": True}}
             for r in (RULE_IN, RULE_QUIET, RULE_OUT)]


class _Alerts:
    """Alerts Management and the metric rule list for subscription s1; records which histories were read."""

    cred = object()

    def __init__(self):
        self.histories: list = []

    def get(self, path, api_version):
        if path.endswith("/history"):
            self.histories.append(path.split("/")[-2])
            return {"properties": {"modifications": []}}
        return {"properties": {"total": len(RAW_ALERTS)}}

    def list(self, path, api_version, params=None):
        if path.endswith("/Microsoft.AlertsManagement/alerts"):
            return RAW_ALERTS
        return RAW_RULES if path.endswith("/metricAlerts") else []


def run_fa(monkeypatch, tmp_path, patterns):
    client = _Alerts()
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.setattr(azure_rest, "resolve_subscription",
                        lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(azure_rest, "AzureRestClient", lambda cred, session=None: client)
    monkeypatch.setattr(fa, "provider_registration_status", lambda *a: "registered")
    monkeypatch.chdir(tmp_path)
    _env(monkeypatch, tmp_path, patterns)
    code = fa.main()
    return code, json.loads((tmp_path / "azure_monitor_fired_alerts_s1.json").read_text()), client


def _fa_summary(keep_alert, keep_rule, total, alerts_listed=None):
    alerts = [fa.with_history(fa.alert_record(a), fa.HISTORY_READ, []) for a in RAW_ALERTS]
    alerts = [a for a in alerts if keep_alert(a)]
    rules = [r for r in fa.rule_activity([fa.rule_record("metric", r) for r in RAW_RULES], alerts) if keep_rule(r)]
    summary = fa.summarize(alerts, rules, total, alerts_listed=alerts_listed)
    return {**summary, "provider_registration_status": dict.fromkeys(fa.NAMESPACES, "registered")}


def _without_age(summary):
    return {k: v for k, v in summary.items() if k != "max_open_alert_age_hours"}


def test_fired_alerts_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, client = run_fa(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert _without_age(evidence["summary"]) == _without_age({
        **_fa_summary(lambda a: True, lambda r: True, 5), **_added_fields({"alert_rule": 3, "alert": 5})})
    assert len(client.histories) == 5


def test_alerts_on_excluded_resources_leave_every_count_and_their_rules_fires(monkeypatch, tmp_path):
    code, evidence, client = run_fa(monkeypatch, tmp_path, f"rg:rg-out, id:{APP_X}, location:regionwest")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("alert", "alert 2", "rg:rg-out", "target_matched"),
        ("alert", "alert 4", f"id:{APP_X}", "target_matched"),
        ("alert_rule", "cpu-out", "rg:rg-out", "resource_matched"),
    ]
    assert next(e for e in results["excluded"] if e["name"] == "alert 2")["target_id"] == APP_OUT
    # Excluded alerts get no history read.
    assert sorted(client.histories) == ["a1", "a3", "a5"]
    assert [a["name"] for a in results["alerts"]] == ["alert 1", "alert 3", "alert 5"]
    assert [(r["name"], r["fire_count"], r["listed"]) for r in results["alert_rules"]] == [
        ("cpu-in", 1, True), ("cpu-quiet", 0, True)]
    expected = _fa_summary(lambda a: a["name"] in ("alert 1", "alert 3", "alert 5"),
                           lambda r: r["name"] != "cpu-out", 5, alerts_listed=5)
    assert _without_age(summary) == _without_age({
        **expected, "alerts_summary_total": None,
        "resource_exclusion_patterns": ["rg:rg-out", f"id:{APP_X}", "location:regionwest"],
        "resource_exclusion_patterns_unmatched": ["location:regionwest"],
        "excluded_alert_rules": 1, "excluded_alerts": 2, "in_scope_alert_rules": 2, "in_scope_alerts": 3,
    })
    # The completeness check still compares every alert listed with Azure's own total.
    assert (summary["alerts_fired"], summary["all_alerts_listed"], summary["alerts_summary_total"]) == (3, True, None)
    assert (summary["alert_rules_listed"], summary["rules_that_fired"], summary["enabled_rules_never_fired"],
            summary["rules_fired_not_listed"]) == (2, 1, 1, 0)
