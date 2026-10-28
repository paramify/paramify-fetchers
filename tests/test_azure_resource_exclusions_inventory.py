"""resource_exclusions in the Azure inventory, residual, Defender assessment and Policy compliance fetchers: excluded
resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace as NS

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
PATTERNS = "rg:rg-out, location:regioneast, rg:typo"
NEW_KEYS = {"resource_exclusion_patterns", "resource_exclusion_patterns_unmatched"}


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inv = _load("resource_inventory")
rr = _load("residual_resources")
da = _load("defender_assessments")
pc = _load("policy_compliance")


def _env(monkeypatch, tmp_path, module, patterns):
    monkeypatch.setattr(module, "load_dotenv", lambda: None)
    monkeypatch.setattr(module, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


def _entries(results):
    return sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"])


# --- resource_inventory ---

SA_IN = f"{IN_RG}/providers/Microsoft.Storage/storageAccounts/sa-in"
SA_OUT = f"{OUT_RG}/providers/Microsoft.Storage/storageAccounts/sa-out"
VM_EAST = f"{IN_RG}/providers/Microsoft.Compute/virtualMachines/vm-east"
VNET_IN = f"{IN_RG}/providers/Microsoft.Network/virtualNetworks/vnet-in"


def _resource(rid, rtype, location="regionwest"):
    return {"id": rid, "name": rid.rsplit("/", 1)[-1], "type": rtype, "location": location,
            "resourceGroup": rid.split("/")[4], "tags": {"owner": "x"}, "sku": None, "kind": "", "provisioningState": ""}


def _assessment(target, status="Unhealthy", severity="High"):
    return {"id": f"{target}/providers/Microsoft.Security/assessments/a1",
            "resourceDetails": {"Source": "Azure", "Id": target}, "status": status, "severity": severity}


def _state(target, compliance="NonCompliant"):
    return {"id": f"{target}/providers/Microsoft.PolicyInsights/policyStates/latest/1", "resourceId": target,
            "complianceState": compliance}


INVENTORY_TABLES = {
    "Resources": [_resource(SA_IN, "microsoft.storage/storageaccounts"),
                  _resource(SA_OUT, "microsoft.storage/storageaccounts"),
                  _resource(VM_EAST, "microsoft.compute/virtualmachines", "regioneast"),
                  _resource(VNET_IN, "microsoft.network/virtualnetworks")],
    # The resource group itself is outside the inventory; an excluded one leaves the outside counts too.
    "SecurityResources": [_assessment(SA_IN, "Healthy"), _assessment(SA_OUT), _assessment(VM_EAST),
                          _assessment(f"{VNET_IN}/subnets/snet-in", severity="Low"), _assessment(OUT_RG),
                          _assessment(SUB)],
    "PolicyResources": [_state(SA_IN, "Compliant"), _state(SA_OUT), _state(VM_EAST), _state(OUT_RG)],
}


def run_inventory(monkeypatch, tmp_path, patterns):
    _env(monkeypatch, tmp_path, inv, patterns)
    monkeypatch.setattr(inv, "credential", lambda: object())
    monkeypatch.setattr(inv, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(inv, "query_all", lambda client, sub, query: {
        "rows": INVENTORY_TABLES[query.split(" ", 1)[0]], "total_records": 0, "pages": 1})
    code = inv.main()
    return code, json.loads((tmp_path / "azure_resource_inventory_s1.json").read_text())


def _inventory_summary_before():
    resources = sorted((inv.resource_record(r) for r in INVENTORY_TABLES["Resources"]), key=lambda r: r["id"])
    keys = {r["id"].lower() for r in resources}
    defender = inv.tally_defender(INVENTORY_TABLES["SecurityResources"], keys, "s1")
    policy = inv.tally_policy(INVENTORY_TABLES["PolicyResources"], keys, "s1")
    return inv.summarize(inv.with_coverage(resources, defender, policy), defender, policy)


def test_inventory_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_inventory(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    new = NEW_KEYS | {"excluded_resources", "in_scope_resources"}
    assert {k: v for k, v in summary.items() if k not in new} == _inventory_summary_before()
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert (summary["excluded_resources"], summary["in_scope_resources"], summary["total_resources"]) == (0, 4, 4)


def test_inventory_excluded_resources_leave_every_tally_and_the_region_counts(monkeypatch, tmp_path):
    code, evidence = run_inventory(monkeypatch, tmp_path, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [r["name"] for r in results["resources"]] == ["vnet-in", "sa-in"]
    assert _entries(results) == [("resource", "sa-out", "rg:rg-out"), ("resource", "vm-east", "location:regioneast")]
    assert (summary["total_resources"], summary["in_scope_resources"], summary["excluded_resources"]) == (2, 2, 2)
    assert summary["resources_by_location"] == {"regionwest": 2} and summary["location_count"] == 1
    assert summary["resources_by_type"] == {"microsoft.network/virtualnetworks": 1,
                                            "microsoft.storage/storageaccounts": 1}
    # The subnet's assessment still counts for its in-scope VNet; the excluded group's own does not count outside.
    assert (summary["defender_assessments_total"], summary["defender_assessments_outside_inventory"]) == (3, 1)
    assert (summary["unhealthy_high_severity_assessments"],
            summary["defender_unhealthy_high_severity_outside_inventory"]) == (0, 1)
    assert summary["all_assessable_resources_assessed_by_defender"] is True
    assert (summary["policy_evaluations_total"], summary["non_compliant_policy_evaluations"],
            summary["policy_non_compliant_outside_inventory"]) == (1, 0, 0)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_inventory_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_inventory(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_resources"] == 4


# --- residual_resources ---

DISK_IN = f"{IN_RG}/providers/Microsoft.Compute/disks/disk-in"
DISK_EAST = f"{IN_RG}/providers/Microsoft.Compute/disks/disk-east"
ID_IN = f"{IN_RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-in"
ID_OUT = f"{OUT_RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-out"
SITE = f"{IN_RG}/providers/Microsoft.Web/sites/app-in"
ROLE = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/r1"


def _row(rid, location="regionwest", **extra):
    return {"id": rid, "name": rid.rsplit("/", 1)[-1], "type": "t", "resourceGroup": rid.split("/")[4],
            "location": location, "tags": None, **extra}


def _role_assignment(scope, name, principal):
    return {"id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}", "principalId": principal,
            "principalType": "User", "roleDefinitionId": ROLE, "scope": scope, "createdOn": "2026-01-01T00:00:00Z"}


def _residual_rows():
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    return {
        rr.ORPHAN_QUERIES["unattached_disk"]: [_row(DISK_IN), _row(DISK_EAST, "regioneast")],
        # rg-out holds no resources, so it is an empty group; it matches rg: through its own id.
        rr.RESOURCE_GROUPS_QUERY: [_row(IN_RG), _row(OUT_RG)],
        rr.OCCUPIED_GROUPS_QUERY: [{"id": "rg-in", "resources": 4}],
        rr.SLOTS_QUERY: [_row(f"{SITE}/slots/live", state="Running", lastModified=recent),
                         _row(f"{SITE}/slots/old", "regioneast", state="Stopped", lastModified=recent)],
        rr.ASSIGNMENTS_QUERY: [_role_assignment(SUB, "ra-sub", "p-gone"), _role_assignment(IN_RG, "ra-in", "p-here"),
                               _role_assignment(OUT_RG, "ra-out", "p-gone-too")],
        rr.IDENTITIES_QUERY: [_row(ID_IN, principalId="p-id-in"), _row(ID_OUT, principalId="p-id-out")],
        # id-in is used only by a resource in the excluded group: still in use.
        rr.IDENTITY_REFERENCES_QUERY: [{"id": f"{OUT_RG}/providers/Microsoft.Web/sites/app-out",
                                        "identityId": ID_IN.lower()}],
        rr.SUBSCRIPTION_QUERY: [{"id": SUB, "tenantId": "t1"}],
    }


def _residual_fakes(monkeypatch):
    rows = _residual_rows()

    async def principals(collector, cred, ids, home=None):
        return {"p-here"}

    monkeypatch.setattr(rr, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(rr, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(rr, "query_all", lambda client, sub, query: {
        "rows": rows.get(query, []), "total_records": len(rows.get(query, [])), "pages": 1})
    monkeypatch.setattr(rr, "role_definition_names", lambda sub, cred: {})
    monkeypatch.setattr(rr, "existing_principals", principals)
    monkeypatch.setattr(rr, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(rr, "federated_credential_count", lambda arm, identity_id: 0)
    monkeypatch.delenv("AZURE_STALE_SLOT_DAYS", raising=False)


def run_residual(monkeypatch, tmp_path, patterns):
    _env(monkeypatch, tmp_path, rr, patterns)
    _residual_fakes(monkeypatch)
    code = rr.main()
    return code, json.loads((tmp_path / "azure_residual_resources_s1.json").read_text())


def test_residual_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_residual(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    resources, assignments, _, check, checked = rr.collect("s1", object(), rr.Collector(logging.getLogger("t")))
    new = NEW_KEYS | {"excluded_orphaned_resources", "excluded_role_assignments", "in_scope_orphaned_resources",
                      "in_scope_role_assignments"}
    assert {k: v for k, v in summary.items() if k not in new} == rr.summarize(resources, assignments, check, checked)
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert (summary["total_orphans"], summary["identities_checked"], summary["slots_checked"]) == (7, 2, 2)
    assert (summary["excluded_orphaned_resources"], summary["excluded_role_assignments"]) == (0, 0)
    assert (summary["in_scope_orphaned_resources"], summary["in_scope_role_assignments"]) == (5, 3)


def test_residual_excludes_orphans_and_assignments_but_keeps_cross_references(monkeypatch, tmp_path):
    code, evidence = run_residual(monkeypatch, tmp_path, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [r["name"] for r in results["orphaned_resources"]] == ["disk-in"]
    assert [a["id"].rsplit("/", 1)[-1] for a in results["role_assignments"]] == ["ra-sub", "ra-in"]
    assert _entries(results) == [
        ("orphaned_resource", "disk-east", "location:regioneast"),
        ("orphaned_resource", "id-out", "rg:rg-out"),
        ("orphaned_resource", "old", "location:regioneast"),
        ("orphaned_resource", "rg-out", "rg:rg-out"),
        ("role_assignment", "ra-out", "rg:rg-out"),
    ]
    assert summary["orphans_by_kind"] == {"deleted_principal_assignment": 1, "unattached_disk": 1}
    assert (summary["total_orphans"], summary["deleted_principal_assignments"], summary["principals_checked"]) == (
        2, 1, 2)
    assert (summary["identities_checked"], summary["slots_checked"]) == (1, 1)
    assert (summary["excluded_orphaned_resources"], summary["excluded_role_assignments"]) == (4, 1)
    assert (summary["in_scope_orphaned_resources"], summary["in_scope_role_assignments"]) == (1, 2)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_residual_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_residual(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_orphans"] == 7


# --- defender_assessments ---

APP_IN = f"{IN_RG}/providers/Microsoft.Web/sites/app-in"
APP_OUT = f"{OUT_RG}/providers/Microsoft.Web/sites/app-out"


def _defender_record(resource, check, status="Unhealthy"):
    return da.project_assessment(NS(
        id=f"{resource}/providers/Microsoft.Security/assessments/{check}", name=check, display_name=f"check {check}",
        resource_details=NS(source="Azure", id=resource, additional_properties={}),
        status=NS(code=status, cause=None, description=None, status_change_date=None, first_evaluation_date=None),
        metadata=None))


DEFENDER_RECORDS = [_defender_record(APP_IN, "c1"), _defender_record(f"{APP_IN}/slots/staging", "c2"),
                    _defender_record(APP_OUT, "c3"), _defender_record(SUB, "c4", "Healthy")]


def run_defender(monkeypatch, tmp_path, patterns):
    _env(monkeypatch, tmp_path, da, patterns)
    monkeypatch.setattr(da, "credential", lambda: object())
    monkeypatch.setattr(da, "collect_assessments", lambda sub, cred, collector: (list(DEFENDER_RECORDS), da.REGISTERED))
    code = da.main()
    return code, json.loads((tmp_path / "azure_defender_assessments_s1.json").read_text())


def test_defender_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_defender(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    new = NEW_KEYS | {"excluded_assessments", "in_scope_assessments"}
    assert {k: v for k, v in summary.items() if k not in new} == da.summarize(DEFENDER_RECORDS, da.REGISTERED)
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert (summary["excluded_assessments"], summary["in_scope_assessments"], summary["total_assessments"]) == (0, 4, 4)


def test_defender_assessments_follow_their_resource_and_never_match_a_region(monkeypatch, tmp_path):
    code, evidence = run_defender(monkeypatch, tmp_path, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [a["name"] for a in results["assessments"]] == ["c1", "c2", "c4"]
    (entry,) = results["excluded"]
    assert (entry["kind"], entry["name"], entry["pattern"], entry["id"], entry["resource_group"]) == (
        "assessment", "check c3", "rg:rg-out", APP_OUT, "rg-out")
    assert (summary["total_assessments"], summary["unhealthy_count"], summary["healthy_percentage"]) == (3, 2, 33)
    assert (summary["excluded_assessments"], summary["in_scope_assessments"]) == (1, 3)
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:regioneast", "rg:typo"]


def test_defender_id_pattern_takes_the_resource_and_its_children(monkeypatch, tmp_path):
    _, evidence = run_defender(monkeypatch, tmp_path, f"id:{APP_IN.upper()}")
    assert [a["name"] for a in evidence["results"]["assessments"]] == ["c3", "c4"]
    assert _entries(evidence["results"]) == [("assessment", "check c1", f"id:{APP_IN.upper()}"),
                                             ("assessment", "check c2", f"id:{APP_IN.upper()}")]


def test_defender_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_defender(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_assessments"] == 4


# --- policy_compliance ---

VM_IN = f"{IN_RG}/providers/Microsoft.Compute/virtualMachines/vm-in"
VM_OUT = f"{OUT_RG}/providers/Microsoft.Compute/virtualMachines/vm-out"
VM_EAST2 = f"{IN_RG}/providers/Microsoft.Compute/virtualMachines/vm-east"
ASSIGN_SUB = f"{SUB}/providers/Microsoft.Authorization/policyAssignments/a-sub"
ASSIGN_OUT = f"{OUT_RG}/providers/Microsoft.Authorization/policyAssignments/a-out"
DEF = "/providers/Microsoft.Authorization/policyDefinitions/d1"
WHEN = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _results(non_compliant):
    return NS(query_results_uri=None, non_compliant_resources=non_compliant, non_compliant_policies=1,
              resource_details=[NS(compliance_state="NonCompliant", count=non_compliant),
                                NS(compliance_state="Compliant", count=2)],
              policy_details=[], policy_group_details=[])


def _policy_state(resource, location="regionwest", assignment=ASSIGN_SUB):
    return NS(resource_id=resource, resource_type="t", resource_location=location, compliance_state="NonCompliant",
              policy_assignment_id=assignment, policy_assignment_name=assignment.rsplit("/", 1)[-1],
              policy_assignment_scope=None, policy_definition_id=DEF, policy_definition_name="d1",
              policy_definition_reference_id=None, policy_definition_action="audit", policy_set_definition_id=None,
              policy_set_definition_name=None, timestamp=WHEN)


def _group(resource, state, n=2):
    return NS(resource_id=resource, policy_assignment_id=ASSIGN_SUB, policy_definition_id=DEF,
              policy_definition_reference_id=None, compliance_state=state, additional_properties={"evaluations": n})


def _task(scope, name):
    return NS(id=f"{scope}/providers/Microsoft.PolicyInsights/remediations/{name}", name=name,
              policy_assignment_id=ASSIGN_SUB, policy_definition_reference_id=None, provisioning_state="Succeeded",
              resource_discovery_mode=None, deployment_status=NS(total_deployments=2, successful_deployments=2,
                                                                 failed_deployments=0),
              created_on=WHEN, last_updated_on=WHEN)


def _deployment(resource, location):
    return NS(remediated_resource_id=resource, deployment_id=None, status="Succeeded", resource_location=location,
              error=None, created_on=WHEN, last_updated_on=WHEN)


def _policy_client(calls):
    groups = [_group(VM_IN, "NonCompliant"), _group(VM_IN, "Compliant"), _group(VM_OUT, "NonCompliant"),
              _group(VM_OUT, "Compliant"), _group(VM_EAST2, "NonCompliant")]
    timeline = [NS(timestamp=datetime(2026, 10, d, tzinfo=timezone.utc), compliance_state=s)
                for d, s in ((1, "NonCompliant"), (2, "Compliant"), (3, "NonCompliant"))]

    def summarize_for_subscription(resource, sub):
        return NS(value=[NS(results=_results(3), policy_assignments=[
            NS(policy_assignment_id=ASSIGN_SUB, policy_set_definition_id=None, results=_results(3),
               policy_definitions=[]),
            NS(policy_assignment_id=ASSIGN_OUT, policy_set_definition_id=None, results=_results(1),
               policy_definitions=[])])])

    def for_subscription(resource, sub, query_options):
        apply = getattr(query_options, "apply", None) or ""
        if apply.endswith("/aggregate($count as n)"):
            return [NS(additional_properties={"n": len(groups)})]
        if apply:
            return groups
        if resource == pc.HISTORY:
            calls.append(("timeline", query_options.filter))
            return timeline
        if getattr(query_options, "select", None):
            return []
        return [_policy_state(VM_IN), _policy_state(VM_OUT), _policy_state(VM_EAST2, "regioneast"),
                _policy_state(SUB, None)]

    def for_resource(resource, resource_id, query_options):
        calls.append(("details", "/" + resource_id))
        return []

    def at_subscription(name):
        calls.append(("deployments", name))
        return [_deployment(VM_IN, "regionwest"), _deployment(VM_EAST2, "regioneast")]

    def at_resource_group(rg, name):
        calls.append(("deployments", name))
        return [_deployment(VM_OUT, "regionwest")]

    return NS(policy_states=NS(summarize_for_subscription=summarize_for_subscription,
                               list_query_results_for_subscription=for_subscription,
                               list_query_results_for_resource=for_resource),
              remediations=NS(list_for_subscription=lambda: [_task(SUB, "t-sub"), _task(OUT_RG, "t-out")],
                              list_deployments_at_subscription=at_subscription,
                              list_deployments_at_resource_group=at_resource_group))


def run_policy(monkeypatch, tmp_path, patterns):
    _env(monkeypatch, tmp_path, pc, patterns)
    calls: list = []
    client = _policy_client(calls)
    insights = ModuleType("azure.mgmt.policyinsights")
    insights.PolicyInsightsClient = lambda **kw: client
    models = ModuleType("azure.mgmt.policyinsights.models")
    models.QueryOptions = lambda **kw: NS(**kw)
    monkeypatch.setitem(sys.modules, "azure.mgmt.policyinsights", insights)
    monkeypatch.setitem(sys.modules, "azure.mgmt.policyinsights.models", models)
    monkeypatch.setattr(pc, "credential", lambda: object())
    monkeypatch.setattr(pc, "provider_registration_status", lambda *a: "registered")
    for env in (pc.MAX_NON_COMPLIANT_ENV, pc.MAX_DETAIL_RESOURCES_ENV, pc.MAX_RECURRENCE_PAIRS_ENV,
                pc.MAX_REMEDIATION_DEPLOYMENTS_ENV):
        monkeypatch.delenv(env, raising=False)
    code = pc.main()
    return code, json.loads((tmp_path / "azure_policy_compliance_s1.json").read_text()), calls


def test_policy_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, calls = run_policy(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert (summary["assignments_evaluated"], summary["listed_non_compliant_states"], summary["remediation_tasks"],
            summary["remediation_deployments_listed"], summary["history_non_compliant_pairs"],
            summary["recurrence_pairs_read"]) == (2, 4, 2, 3, 3, 2)
    for kind, plural, total in (("policy_assignment", "policy_assignments", 2), ("policy_state", "policy_states", 4),
                                ("remediation_task", "remediation_tasks", 2),
                                ("remediation_deployment", "remediation_deployments", 3)):
        assert (summary[f"excluded_{kind}s"], summary[f"in_scope_{plural}"]) == (0, total)
    assert sorted(c for c in calls if c[0] == "details") == [("details", VM_EAST2), ("details", VM_IN),
                                                              ("details", VM_OUT)]


def test_policy_records_follow_their_resource_and_tasks_their_scope(monkeypatch, tmp_path):
    code, evidence, calls = run_policy(monkeypatch, tmp_path, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [a["policy_assignment_name"] for a in results["assignment_compliance"]] == ["a-sub"]
    assert [s["resource_id"] for s in results["non_compliant_states"]] == [SUB, VM_IN]
    assert [t["name"] for t in results["remediation_tasks"]] == ["t-sub"]
    assert [d["remediated_resource_id"] for d in results["remediation_deployments"]] == [VM_IN]
    assert _entries(results) == [
        ("policy_assignment", "a-out", "rg:rg-out"),
        ("policy_state", "d1", "location:regioneast"),
        ("policy_state", "d1", "rg:rg-out"),
        ("remediation_deployment", "t-sub", "location:regioneast"),
        ("remediation_task", "t-out", "rg:rg-out"),
    ]
    # Excluded states are not read for details, nor an excluded task for its deployments.
    assert [c for c in calls if c[0] in ("details", "deployments")] == [("details", VM_IN), ("deployments", "t-sub")]
    # History rows carry no region: the excluded group's pair goes, the east one stays.
    assert [r["resource_id"] for r in results["non_compliance_recurrence"]] == [VM_IN]
    assert (summary["history_non_compliant_pairs"], summary["history_persistently_non_compliant_pairs"]) == (2, 1)
    assert (summary["assignments_evaluated"], summary["listed_non_compliant_states"],
            summary["listed_distinct_non_compliant_resources"], summary["remediation_tasks"],
            summary["remediation_deployments_listed"]) == (1, 2, 2, 1, 1)
    # The service's subscription-wide counts cannot be split by resource.
    assert summary["non_compliant_resources"] == 3
    assert (summary["excluded_policy_assignments"], summary["excluded_policy_states"],
            summary["excluded_remediation_tasks"], summary["excluded_remediation_deployments"]) == (1, 2, 1, 1)
    assert (summary["in_scope_policy_assignments"], summary["in_scope_policy_states"],
            summary["in_scope_remediation_tasks"], summary["in_scope_remediation_deployments"]) == (1, 2, 1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_policy_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _ = run_policy(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["listed_non_compliant_states"] == 4
