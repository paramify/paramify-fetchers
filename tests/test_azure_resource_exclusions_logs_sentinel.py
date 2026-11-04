"""resource_exclusions in the Azure monitoring, log and Sentinel fetchers: excluded resources leave every count, get no
further reads and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_logs_sentinel_exclusions_under_test",
                                                  AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ala = _load("activity_log_alerts")
deletion = _load("log_analytics_deletion_rights")
query_audit = _load("log_analytics_query_audit")
immutability = _load("log_storage_immutability")
analytics = _load("sentinel_analytics_rules")
automation = _load("sentinel_automation_rules")
data_sources = _load("sentinel_data_sources")
incidents = _load("sentinel_incidents")
service_logs = _load("service_log_records")
routing = sys.modules["alert_routing"]
azure_rest = sys.modules["azure_rest"]


def _set_patterns(monkeypatch, patterns):
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


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


# --- activity_log_alerts ---

NSG_WRITE = "Microsoft.Network/networkSecurityGroups/write"
NSG_DELETE = "Microsoft.Network/networkSecurityGroups/delete"
FAR = "/subscriptions/s2/resourceGroups/rg-far/providers/microsoft.insights/actionGroups"


def _group(rg: str, name: str) -> dict:
    return {"id": f"{rg}/providers/microsoft.insights/actionGroups/{name}", "name": name, "enabled": True,
            "deliverable": True, "notifies_people": True, "receivers": [], "receiver_kinds": ["email"]}


def _activity_alert(rg: str, name: str, operation: str, group: str) -> dict:
    condition = {"all_of": [{"field": "operationName", "equals": operation, "contains_any": None, "any_of": []}]}
    return ala.alert_record({"id": f"{rg}/providers/Microsoft.Insights/activityLogAlerts/{name}", "name": name,
                             "location": "Global", "enabled": True, "scopes": [SUB], "condition": condition,
                             "action_groups": [group]})


def _adds_far_group(rg: str, name: str) -> dict:
    return routing.processing_rule_record(
        {"id": f"{rg}/providers/Microsoft.AlertsManagement/actionRules/{name}", "name": name,
         "properties": {"enabled": True, "scopes": [SUB],
                        "actions": [{"actionType": "AddActionGroups", "actionGroupIds": [f"{FAR}/ag-far"]}]}},
        datetime.now(timezone.utc))


def run_activity_alerts(monkeypatch, tmp_path, patterns):
    """The excluded rule routes to a group in another subscription; referenced collects the ids handed over for reading."""
    ag_in, ag_out = _group(IN_RG, "ag-in"), _group(OUT_RG, "ag-out")
    alerts = [
        # An in-scope rule routing through an action group in the excluded resource group.
        _activity_alert(IN_RG, "ala-in", NSG_WRITE, ag_out["id"]),
        _activity_alert(OUT_RG, "ala-out", NSG_DELETE, f"{FAR}/ag-only-out"),
        _activity_alert(IN_RG, "ala-named", NSG_DELETE, ag_in["id"]),
    ]
    referenced: list = []

    def add_referenced(rest, group_ids, by_id, collector):
        group_ids = sorted(set(group_ids))
        referenced.extend(group_ids)
        for gid in group_ids:
            if gid.startswith(FAR):
                by_id[gid.lower()] = _group(FAR.rsplit("/providers/", 1)[0], gid.rsplit("/", 1)[1])

    m = ala
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(m, "collect_activity_log_alerts", lambda sub, cred, collector: [dict(a) for a in alerts])
    monkeypatch.setattr(m, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(m, "collect_action_groups", lambda rest, sub: {"groups": [ag_in, ag_out]})
    monkeypatch.setattr(m, "collect_processing_rules",
                        lambda rest, sub, now: {"rules": [_adds_far_group(OUT_RG, "pr-out")]})
    monkeypatch.setattr(m, "add_referenced_groups", add_referenced)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    _set_patterns(monkeypatch, patterns)
    code = m.main()
    return code, json.loads((tmp_path / "azure_activity_log_alerts_s1.json").read_text()), referenced


def test_activity_alerts_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, referenced = run_activity_alerts(monkeypatch, tmp_path, None)
    results = evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert evidence["summary"] == {
        **ala.summarize(results["activity_log_alerts"]), "provider_registration_status": "registered",
        **_added_fields({"activity_log_alert": 3, "action_group": 2, "processing_rule": 1}),
    }
    assert f"{FAR}/ag-only-out" in referenced


def test_activity_alerts_exclude_by_group_and_id_but_keep_routing_through_excluded_records(monkeypatch, tmp_path):
    named = f"{IN_RG}/providers/Microsoft.Insights/activityLogAlerts/ala-named"
    code, evidence, referenced = run_activity_alerts(
        monkeypatch, tmp_path, f"rg:rg-out, id:{named}, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("action_group", "ag-out", "rg:rg-out", "resource_matched"),
        ("activity_log_alert", "ala-named", f"id:{named}", "resource_matched"),
        ("activity_log_alert", "ala-out", "rg:rg-out", "resource_matched"),
        ("processing_rule", "pr-out", "rg:rg-out", "resource_matched"),
    ]
    (alert,) = results["activity_log_alerts"]
    assert alert["name"] == "ala-in"
    # The excluded action group and the excluded processing rule's added group still route the in-scope rule.
    assert sorted(g["id"].rsplit("/", 1)[1] for g in alert["resolved_action_groups"] if g["found"]) == ["ag-far", "ag-out"]
    assert alert["reaches_human"] is True and alert["processing_rule_matches"][0]["id"].endswith("/pr-out")
    assert [g["name"] for g in results["action_groups"]] == ["ag-in"] and results["processing_rules"] == []
    # The excluded rule's own group in another subscription is never read.
    assert f"{FAR}/ag-only-out" not in referenced and f"{FAR}/ag-far" in referenced
    assert summary["monitored_operation_coverage"]["create_update_network_security_group"] is True
    assert summary["monitored_operation_coverage"]["delete_network_security_group"] is False
    assert (summary["total_activity_log_alerts"], summary["monitored_operations_covered"],
            summary["alerts_reaching_human"]) == (1, 1, 1)
    assert (summary["excluded_activity_log_alerts"], summary["excluded_action_groups"],
            summary["excluded_processing_rules"]) == (2, 1, 1)
    assert (summary["in_scope_activity_log_alerts"], summary["in_scope_action_groups"],
            summary["in_scope_processing_rules"]) == (1, 1, 0)
    # Activity log alerts are Global, and action groups and processing rules carry no location.
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:regioneast", "rg:typo"]


def test_activity_alerts_location_global_takes_every_rule_but_no_group(monkeypatch, tmp_path):
    code, evidence, _ = run_activity_alerts(monkeypatch, tmp_path, "location:global")
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["activity_log_alerts"] == []
    assert {e["kind"] for e in evidence["results"]["excluded"]} == {"activity_log_alert"}
    assert (summary["total_activity_log_alerts"], summary["in_scope_action_groups"],
            summary["all_monitored_operations_covered"]) == (0, 2, False)


def test_activity_alerts_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _ = run_activity_alerts(monkeypatch, tmp_path, "rg-out")
    assert code == 1 and evidence["summary"]["total_activity_log_alerts"] == 3


# --- the per-workspace fetchers ---

LAW = "providers/Microsoft.OperationalInsights/workspaces"
WS_IN = f"{IN_RG}/{LAW}/law-in"
WS_OUT = f"{OUT_RG}/{LAW}/law-out"
WS_EAST = f"{IN_RG}/{LAW}/law-east"
WS_PLAIN = f"{IN_RG}/{LAW}/law-plain"


def _workspace(wid: str, location: str, sentinel: bool = True) -> dict:
    name = wid.rsplit("/", 1)[1]
    return {"id": wid, "name": name, "resource_group": wid.split("/")[4], "location": location,
            "customer_id": f"cust-{name}", "retention_in_days": 90, "sentinel_onboarded": sentinel}


WORKSPACES = [_workspace(WS_IN, "regionwest"), _workspace(WS_OUT, "regionwest"), _workspace(WS_EAST, "regioneast"),
              _workspace(WS_PLAIN, "regionwest", sentinel=False)]


WS_LIST = "/subscriptions/s1/providers/Microsoft.OperationalInsights/workspaces"


def _listed(workspaces) -> list:
    return [{"id": w["id"], "name": w["name"], "location": w["location"],
             "properties": {"customerId": w["customer_id"], "retentionInDays": w["retention_in_days"]}}
            for w in workspaces]


def _onboarding(monkeypatch, workspaces) -> list:
    """Sentinel onboarding answered from the fake workspaces; returns the workspace ids whose state was read."""
    read: list = []
    by_id = {w["id"]: w["sentinel_onboarded"] for w in workspaces}
    monkeypatch.setattr(azure_rest, "sentinel_onboarded", lambda client, wid: read.append(wid) or by_id[wid])
    return read


def _rest_env(monkeypatch, tmp_path, patterns, client=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: object())
    if client is not None:
        monkeypatch.setattr(azure_rest, "AzureRestClient", lambda cred, session=None: client)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "s1")
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("SENTINEL_WORKSPACES", raising=False)
    _set_patterns(monkeypatch, patterns)


def _evidence(out_dir: Path, name: str) -> dict:
    return json.loads((out_dir / f"{name}_s1.json").read_text())


def run_workspaces(m, monkeypatch, tmp_path, patterns, detail, old_sentinel_only=None):
    """Run main() over WORKSPACES with collect faked by detail(ws); with old_sentinel_only set, also run the shared
    run_workspaces on the same fakes, as the fetcher did before it took exclusions. Returns (code, new, old, read)."""
    read: list = []
    fake_collect = lambda client, ws, collector: read.append(ws["name"]) or detail(ws)  # noqa: E731
    _rest_env(monkeypatch, tmp_path, patterns, FakeClient(lists={WS_LIST: _listed(WORKSPACES)}, gets={}))
    onboarding = _onboarding(monkeypatch, WORKSPACES)
    monkeypatch.setattr(m, "collect", fake_collect)
    old = None
    if old_sentinel_only is not None:
        monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "old"))
        azure_rest.run_workspaces(fetcher=m.NAME, logger=logging.getLogger("old"), collect=fake_collect,
                                  summarize=m.summarize, sentinel_only=old_sentinel_only)
        old = _evidence(tmp_path / "old", m.NAME)
        read.clear()
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "new"))
    onboarding.clear()
    code = m.main()
    # An excluded workspace's Sentinel onboarding isn't read either.
    assert all(w["id"] in onboarding for w in WORKSPACES if w["name"] in read)
    if patterns and "rg:rg-out" in patterns:
        assert WS_OUT not in onboarding
    return code, _evidence(tmp_path / "new", m.NAME), old, read


def _assert_unchanged_apart_from_new_fields(new: dict, old: dict, in_scope_workspaces: int):
    assert new["results"] == {**old["results"], "excluded": []}
    assert new["summary"] == {**old["summary"], **_added_fields({"workspace": in_scope_workspaces})}


def _assert_workspace_exclusions(evidence: dict, read: list, sentinel_only: bool):
    summary = evidence["summary"]
    assert _excluded(evidence) == [
        ("workspace", "law-east", "location:regioneast", "resource_matched"),
        ("workspace", "law-out", "rg:rg-out", "resource_matched"),
    ]
    assert read == ["law-in"] if sentinel_only else read == ["law-in", "law-plain"]
    assert [w["name"] for w in evidence["results"]["workspaces"]] == read
    assert (summary["excluded_workspaces"], summary["in_scope_workspaces"]) == (2, 2)
    assert summary["workspaces_collected"] == len(read)
    if sentinel_only:
        assert evidence["results"]["workspaces_without_sentinel"] == ["law-plain"]
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


WS_PATTERNS = "rg:rg-out, location:regioneast, rg:typo"


# log_analytics_deletion_rights

def _deletion_detail(ws: dict) -> dict:
    count = {"law-in": 2, "law-out": 9, "law-east": 7, "law-plain": 1}[ws["name"]]
    return {"deletion_grants": [], "principals_with_deletion_rights": count,
            "principals_with_explicit_grant": int(ws["name"] != "law-in")}


def test_deletion_rights_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, new, old, _ = run_workspaces(deletion, monkeypatch, tmp_path, None, _deletion_detail, old_sentinel_only=False)
    assert code == 0
    _assert_unchanged_apart_from_new_fields(new, old, 4)


def test_deletion_rights_excluded_workspaces_are_not_read(monkeypatch, tmp_path):
    code, evidence, _, read = run_workspaces(deletion, monkeypatch, tmp_path, WS_PATTERNS, _deletion_detail)
    assert code == 0
    _assert_workspace_exclusions(evidence, read, sentinel_only=False)
    assert evidence["summary"]["max_principals_with_deletion_rights"] == 2
    assert evidence["summary"]["workspaces_with_explicit_grants"] == 1


class FakeClient:
    """ARM lists and GETs keyed by path; each read path is appended to reads, and each query's text to queries."""

    def __init__(self, lists: dict, gets: dict, rows=()):
        self.lists, self.gets, self.rows = lists, gets, list(rows)
        self.reads: list = []
        self.queries: list = []

    def list(self, path, api_version, params=None):
        self.reads.append(path)
        if path not in self.lists:
            raise azure_rest.ArmError(404, "ResourceNotFound", "not found")
        return [dict(item) for item in self.lists[path]]

    def get(self, path, api_version):
        self.reads.append(path)
        if path not in self.gets:
            raise azure_rest.ArmError(404, "ResourceNotFound", "not found")
        return self.gets[path]

    def graph_post(self, path, body):
        return {"value": []}

    def query(self, customer_id, kql, timespan):
        self.queries.append((customer_id, kql))
        return next((rows for fragment, rows in self.rows if fragment in kql), [])


def test_deletion_rights_keep_every_assignment_inherited_at_an_in_scope_workspace(monkeypatch, tmp_path):
    contributor = "/providers/Microsoft.Authorization/roleDefinitions/la-contributor"
    assignments = [{"properties": {"principalId": f"p-{scope.rsplit('/', 1)[1]}", "principalType": "User",
                                   "roleDefinitionId": contributor, "scope": scope}}
                   for scope in (SUB, OUT_RG.replace("rg-out", "rg-in"), "/providers/Microsoft.Management/managementGroups/mg")]
    auth = "providers/Microsoft.Authorization"
    client = FakeClient(
        lists={f"{WS_IN}/{auth}/roleAssignments": assignments, f"{WS_IN}/{auth}/roleEligibilityScheduleInstances": [],
               WS_LIST: _listed(w for w in WORKSPACES if w["name"] != "law-plain")},
        gets={contributor: {"properties": {"roleName": "Log Analytics Contributor", "type": "BuiltInRole",
                                           "permissions": [{"actions": ["Microsoft.OperationalInsights/*"]}]}}},
    )
    _rest_env(monkeypatch, tmp_path, "rg:rg-out, location:regioneast", client)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    _onboarding(monkeypatch, WORKSPACES)
    code = deletion.main()
    evidence = _evidence(tmp_path, deletion.NAME)
    assert code == 0
    (ws,) = evidence["results"]["workspaces"]
    assert sorted(g["scope_level"] for g in ws["deletion_grants"]) == ["management_group", "resource_group", "subscription"]
    assert not any("law-out" in r or "law-east" in r for r in client.reads)


# log_analytics_query_audit

def _audit_detail(ws: dict) -> dict:
    return {"lookback_days": 90, "query_auditing_enabled": ws["name"] in ("law-in", "law-east")}


def test_query_audit_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, new, old, _ = run_workspaces(query_audit, monkeypatch, tmp_path, None, _audit_detail, old_sentinel_only=False)
    assert code == 0
    _assert_unchanged_apart_from_new_fields(new, old, 4)


def test_query_audit_excluded_workspaces_are_not_read(monkeypatch, tmp_path):
    code, evidence, _, read = run_workspaces(query_audit, monkeypatch, tmp_path, WS_PATTERNS, _audit_detail)
    summary = evidence["summary"]
    assert code == 0
    _assert_workspace_exclusions(evidence, read, sentinel_only=False)
    assert (summary["workspaces_with_query_auditing"], summary["workspaces_without_query_auditing"],
            summary["sentinel_workspaces"]) == (1, 1, 1)


def test_query_audit_still_queries_an_excluded_audit_destination_for_an_in_scope_workspace(monkeypatch, tmp_path):
    diag = "providers/Microsoft.Insights/diagnosticSettings"
    client = FakeClient(
        lists={f"{WS_IN}/{diag}": [{"name": "audit", "properties": {
            "workspaceId": WS_OUT, "logs": [{"category": "Audit", "enabled": True}]}}],
            f"{WS_OUT}/{diag}": [], WS_LIST: _listed(w for w in WORKSPACES if w["name"] in ("law-in", "law-out"))},
        gets={WS_OUT: {"properties": {"customerId": "cust-law-out", "retentionInDays": 90}},
              f"{WS_OUT}/tables/LAQueryLogs": {"properties": {"retentionInDays": 90}}},
        rows=[("by User", [{"User": "alice@example.com", "Queries": 3, "LastQuery": "2026-11-01T00:00:00Z"}])],
    )
    _rest_env(monkeypatch, tmp_path, "rg:rg-out", client)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    _onboarding(monkeypatch, WORKSPACES)
    code = query_audit.main()
    evidence = _evidence(tmp_path, query_audit.NAME)
    assert code == 0
    (ws,) = evidence["results"]["workspaces"]
    assert ws["audit_destination_workspace_id"] == WS_OUT and ws["distinct_human_users"] == 1
    # Both LAQueryLogs queries ran at the excluded destination, for the in-scope workspace only.
    assert [c for c, _ in client.queries] == ["cust-law-out", "cust-law-out"]
    assert all(WS_IN in kql and WS_OUT not in kql for _, kql in client.queries)
    assert f"{WS_OUT}/{diag}" not in client.reads


# sentinel_analytics_rules, sentinel_automation_rules, sentinel_data_sources

def _analytics_detail(ws: dict) -> dict:
    enabled = {"law-in": 5, "law-out": 0, "law-east": 40}[ws["name"]]
    return {"rules": [], "enabled_rules": enabled, "fusion_enabled": ws["name"] != "law-out",
            "enabled_rules_missing_data": ["r1"], "enabled_rules_quiet": [], "ingesting_tables_not_read": ["T1", "T2"],
            "ingesting_tables_read_only_by_templates": [], "enabled_rules_tables_unknown": []}


def _automation_detail(ws: dict) -> dict:
    active = {"law-in": 2, "law-out": 0, "law-east": 6}[ws["name"]]
    return {"rules": [], "active_rules": active, "playbooks_run": [f"pb-{ws['name']}"] if active else []}


def _data_sources_detail(ws: dict) -> dict:
    sources = {"law-in": 3, "law-out": 0, "law-east": 1}[ws["name"]]
    return {"sources_ingesting": sources, "data_connectors_total": sources, "connectors_connected": sources,
            "connectors_not_connected": 0, "connectors_quiet": 0, "connectors_configured_without_data": 0,
            "health_monitoring": ws["name"] == "law-east", "connectors_unhealthy": int(ws["name"] == "law-out")}


SENTINEL = [(analytics, _analytics_detail), (automation, _automation_detail), (data_sources, _data_sources_detail)]


def test_sentinel_fetchers_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    for m, detail in SENTINEL:
        code, new, old, _ = run_workspaces(m, monkeypatch, tmp_path / m.NAME, None, detail, old_sentinel_only=True)
        assert code == 0, m.NAME
        _assert_unchanged_apart_from_new_fields(new, old, 4)


def test_sentinel_fetchers_do_not_read_excluded_workspaces(monkeypatch, tmp_path):
    results = {}
    for m, detail in SENTINEL:
        code, evidence, _, read = run_workspaces(m, monkeypatch, tmp_path / m.NAME, WS_PATTERNS, detail)
        assert code == 0, m.NAME
        _assert_workspace_exclusions(evidence, read, sentinel_only=True)
        results[m.NAME] = evidence["summary"]
    rules = results[analytics.NAME]
    assert (rules["enabled_rules_total"], rules["min_enabled_rules"], rules["workspaces_with_no_enabled_rules"],
            rules["workspaces_with_fusion_enabled"], rules["ingesting_tables_not_read"]) == (5, 5, 0, 1, 2)
    auto = results[automation.NAME]
    assert (auto["active_rules_total"], auto["workspaces_with_no_active_rules"], auto["playbooks_run"]) == (2, 0, 1)
    sources = results[data_sources.NAME]
    assert (sources["min_sources_ingesting"], sources["workspaces_with_no_sources"],
            sources["workspaces_with_health_monitoring"], sources["connectors_unhealthy"]) == (3, 0, 0, 0)


def test_workspace_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _, read = run_workspaces(automation, monkeypatch, tmp_path, "law-out", _automation_detail)
    assert code == 1 and read == ["law-east", "law-in", "law-out"]
    assert evidence["summary"]["resource_exclusion_patterns"] == ["law-out"]


# sentinel_incidents

INCIDENT_FIELDS = ("incidents_in_scope", "open_incidents", "closed_incidents", "closed_missing_close_time",
                   "closed_close_time_not_retained", "acknowledged_incidents", "open_unacknowledged",
                   "open_new_unowned_history_incomplete", "recurring_titles")


def _incident_detail(ws: dict) -> dict:
    n = {"law-in": 4, "law-out": 100, "law-east": 30}[ws["name"]]
    return {"incidents": [], **{field: n for field in INCIDENT_FIELDS}}


def test_incidents_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, _, read = run_workspaces(incidents, monkeypatch, tmp_path, None, _incident_detail)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        "workspaces_collected": 3, "workspaces_without_sentinel": 1,
        **incidents.summarize(evidence["results"]["workspaces"], True), **_added_fields({"workspace": 4}),
    }
    assert evidence["summary"]["incidents_in_scope"] == 134


def test_incidents_excluded_workspaces_are_not_read(monkeypatch, tmp_path):
    code, evidence, _, read = run_workspaces(incidents, monkeypatch, tmp_path, WS_PATTERNS, _incident_detail)
    assert code == 0
    _assert_workspace_exclusions(evidence, read, sentinel_only=True)
    assert all(evidence["summary"][field] == 4 for field in INCIDENT_FIELDS)


class RefusedClient(FakeClient):
    """Refuses (403) the lists whose paths are in `refused`."""

    def __init__(self, lists: dict, gets: dict, refused=(), rows=()):
        super().__init__(lists, gets, rows)
        self.refused = set(refused)

    def list(self, path, api_version, params=None):
        if path in self.refused:
            self.reads.append(path)
            raise azure_rest.ArmError(403, "AuthorizationFailed", "The client does not have authorization")
        return super().list(path, api_version, params)


def _status(tmp_path) -> str:
    return json.loads((tmp_path / "status.json").read_text())["code"]


@pytest.mark.parametrize("m", [deletion, incidents], ids=lambda m: m.NAME)
def test_a_named_workspace_a_pattern_excludes_fails_the_run_as_bad_config(monkeypatch, tmp_path, m):
    _rest_env(monkeypatch, tmp_path, "rg:rg-out", FakeClient(lists={WS_LIST: _listed(WORKSPACES)}, gets={}))
    monkeypatch.setenv("SENTINEL_WORKSPACES", "law-out, law-in")
    onboarding = _onboarding(monkeypatch, WORKSPACES)
    read: list = []
    monkeypatch.setattr(m, "collect", lambda client, ws, collector: read.append(ws["name"]) or {})
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = m.main()
    evidence = _evidence(tmp_path, m.NAME)
    assert code == 1 and _status(tmp_path) == "bad_config"
    assert _excluded(evidence) == [("workspace", "law-out", "rg:rg-out", "resource_matched")]
    assert read == ["law-in"] and WS_OUT not in onboarding
    assert (evidence["summary"]["excluded_workspaces"], evidence["summary"]["in_scope_workspaces"]) == (1, 1)
    if m is incidents:  # as when a named workspace isn't found
        assert (evidence["summary"]["incidents_in_scope"], evidence["summary"]["open_incidents"]) == (None, None)


def test_incidents_workspace_counts_are_null_when_the_workspace_list_was_refused(monkeypatch, tmp_path):
    _rest_env(monkeypatch, tmp_path, WS_PATTERNS, RefusedClient({}, {}, refused=[WS_LIST]))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = incidents.main()
    summary = _evidence(tmp_path, incidents.NAME)["summary"]
    assert code == 1 and _status(tmp_path) == "not_authorized"
    assert (summary["in_scope_workspaces"], summary["excluded_workspaces"]) == (None, None)
    assert summary["incidents_in_scope"] is None


# --- log_storage_immutability ---

STORAGE = "providers/Microsoft.Storage/storageAccounts"
ST_IN, ST_OUT, ST_EAST = f"{IN_RG}/{STORAGE}/stin", f"{OUT_RG}/{STORAGE}/stout", f"{IN_RG}/{STORAGE}/steast"
LOCKED = {"hasImmutabilityPolicy": True, "immutabilityPolicy": {"properties": {
    "state": "Locked", "immutabilityPeriodSinceCreationInDays": 365}}}


def _container(account: str, name: str, props: dict | None = None) -> dict:
    return {"id": f"{account}/blobServices/default/containers/{name}", "name": name, "properties": props or {}}


def _storage_client() -> FakeClient:
    accounts = [{"id": a, "name": a.rsplit("/", 1)[1], "location": loc, "kind": "StorageV2", "properties": {}}
                for a, loc in ((ST_IN, "regionwest"), (ST_OUT, "regionwest"), (ST_EAST, "regioneast"))]
    containers = {
        ST_IN: [_container(ST_IN, "insights-logs-audit", LOCKED), _container(ST_IN, "am-securityevent"),
                _container(ST_IN, "app-data")],
        ST_OUT: [_container(ST_OUT, "insights-activity-logs", LOCKED)],
        ST_EAST: [_container(ST_EAST, "insights-metrics-pt1m")],
    }
    return FakeClient(
        lists={f"{SUB}/{STORAGE}": accounts,
               **{f"{a}/blobServices/default/containers": c for a, c in containers.items()}},
        gets={f"{a}/blobServices/default": {"properties": {"deleteRetentionPolicy": {"enabled": True, "days": 7}}}
              for a in containers},
    )


def run_immutability(monkeypatch, tmp_path, patterns):
    client = _storage_client()
    _rest_env(monkeypatch, tmp_path, patterns, client)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = immutability.main()
    return code, _evidence(tmp_path, immutability.NAME), client


def test_immutability_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, _ = run_immutability(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        "storage_accounts_scanned": 3, "accounts_with_log_containers": 3, "log_containers": 4, "locked_policy": 2,
        "unlocked_policy_only": 0, "legal_hold": 0, "unprotected": 2, "min_retention_days": 365,
        **_added_fields({"storage_account": 3, "container": 4}),
    }


def test_immutability_excludes_accounts_and_a_named_container(monkeypatch, tmp_path):
    locked = f"{ST_IN}/blobServices/default/containers/insights-logs-audit"
    code, evidence, client = run_immutability(monkeypatch, tmp_path, f"rg:rg-out, location:regioneast, id:{locked}, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("container", "insights-logs-audit", f"id:{locked}", "resource_matched"),
        ("storage_account", "steast", "location:regioneast", "resource_matched"),
        ("storage_account", "stout", "rg:rg-out", "resource_matched"),
    ]
    ((account,),) = [results["accounts"]]
    assert account["account"] == "stin" and [c["container"] for c in account["log_containers"]] == ["am-securityevent"]
    # Excluded accounts get neither the container list nor the blob service read.
    assert not any(r.startswith((ST_OUT, ST_EAST)) for r in client.reads)
    assert summary == {
        "storage_accounts_scanned": 1, "accounts_with_log_containers": 1, "log_containers": 1, "locked_policy": 0,
        "unlocked_policy_only": 0, "legal_hold": 0, "unprotected": 1, "min_retention_days": None,
        "resource_exclusion_patterns": ["rg:rg-out", "location:regioneast", f"id:{locked}", "rg:typo"],
        "resource_exclusion_patterns_unmatched": ["rg:typo"],
        "excluded_storage_accounts": 2, "excluded_containers": 1, "in_scope_storage_accounts": 1,
        "in_scope_containers": 1,
    }


def test_immutability_account_whose_log_containers_all_leave_is_not_listed_or_read(monkeypatch, tmp_path):
    code, evidence, client = run_immutability(monkeypatch, tmp_path, f"id:{ST_EAST}/blobServices/default/containers/*")
    assert code == 0
    assert [a["account"] for a in evidence["results"]["accounts"]] == ["stin", "stout"]
    assert f"{ST_EAST}/blobServices/default" not in client.reads
    assert (evidence["summary"]["in_scope_storage_accounts"], evidence["summary"]["accounts_with_log_containers"]) == (3, 2)


# --- service_log_records ---

WEB = "providers/Microsoft.Web/sites"
MIS = "providers/Microsoft.Sql/managedInstances"
APP_IN, APP_OUT, APP_EAST = f"{IN_RG}/{WEB}/app-in", f"{OUT_RG}/{WEB}/app-out", f"{IN_RG}/{WEB}/app-east"
SLOT_A, SLOT_B = f"{APP_IN}/slots/a", f"{APP_IN}/slots/b"
MI_IN, MI_OUT = f"{IN_RG}/{MIS}/mi-in", f"{IN_RG}/{MIS}/mi-out"
LAW_IN = f"{IN_RG}/{LAW}/law-in"
LAW_SHARED = f"{OUT_RG}/{LAW}/law-shared"
LAW_ONLY_OUT = f"{OUT_RG}/{LAW}/law-only-out"
DIAG = "providers/Microsoft.Insights/diagnosticSettings"


def _setting(workspace: str, category: str) -> list:
    return [{"name": "to-law", "properties": {"workspaceId": workspace, "logs": [{"category": category, "enabled": True}]}}]


def _site(sid: str, location: str = "regionwest") -> dict:
    name = sid.split("/sites/", 1)[1].replace("/slots/", "/")
    return {"id": sid, "name": name, "location": location, "kind": "app", "properties": {"state": "Running"}}


def _http_row(sid: str, records: int) -> dict:
    return {"ResourceId": sid.lower(), "Records": records, "LastRecord": "2026-11-02T00:00:00Z", "ClientIps": 1,
            "Status2xx": records, "Status3xx": 0, "Status4xx": 0, "Status5xx": 0, "Hosts": "[]"}


def _audit_row(mid: str, records: int) -> dict:
    return {"ResourceId": mid.lower(), "Database": "", "Action": "BATCH COMPLETED", "Records": records, "Failed": 0,
            "SucceededEvents": records, "LastRecord": "2026-11-02T00:00:00Z"}


def _table(retention: int) -> dict:
    return {"properties": {"plan": "Analytics", "retentionInDays": retention, "totalRetentionInDays": retention}}


def _service_logs_client() -> FakeClient:
    http = [_http_row(APP_IN, 10), _http_row(SLOT_A, 3), _http_row(SLOT_B, 50), _http_row(APP_OUT, 400),
            _http_row(APP_EAST, 70)]
    audit = [_audit_row(MI_IN, 5), _audit_row(MI_OUT, 600)]
    tables = {}
    for law, retention in ((LAW_IN, 30), (LAW_SHARED, 7), (LAW_ONLY_OUT, 1)):
        for t in ("AppServiceHTTPLogs", "AzureDiagnostics"):
            tables[f"{law}/tables/{t}"] = _table(retention)
    return FakeClient(
        lists={
            f"{SUB}/{WEB}": [_site(APP_IN), _site(APP_OUT), _site(APP_EAST, "regioneast")],
            f"{APP_IN}/slots": [_site(SLOT_A), _site(SLOT_B)],
            f"{APP_OUT}/slots": [_site(f"{APP_OUT}/slots/x")], f"{APP_EAST}/slots": [], f"{APP_OUT}/slots/x/{DIAG}": [],
            f"{SUB}/{MIS}": [{"id": m, "name": m.rsplit("/", 1)[1], "location": "regionwest"} for m in (MI_IN, MI_OUT)],
            f"{MI_IN}/databases": [], f"{MI_OUT}/databases": [],
            # The in-scope app also sends to a workspace in the excluded group; the excluded app only to its own.
            f"{APP_IN}/{DIAG}": _setting(LAW_IN, "AppServiceHTTPLogs") + _setting(LAW_SHARED, "AppServiceHTTPLogs"),
            f"{SLOT_A}/{DIAG}": _setting(LAW_IN, "AppServiceHTTPLogs"), f"{SLOT_B}/{DIAG}": _setting(LAW_IN, "AppServiceHTTPLogs"),
            f"{APP_OUT}/{DIAG}": _setting(LAW_ONLY_OUT, "AppServiceHTTPLogs"),
            f"{APP_EAST}/{DIAG}": _setting(LAW_ONLY_OUT, "AppServiceHTTPLogs"),
            f"{MI_IN}/{DIAG}": _setting(LAW_IN, "SQLSecurityAuditEvents"),
            f"{MI_OUT}/{DIAG}": _setting(LAW_ONLY_OUT, "SQLSecurityAuditEvents"),
        },
        gets={LAW_IN: {"properties": {"customerId": "cust-in"}}, LAW_SHARED: {"properties": {"customerId": "cust-shared"}},
              LAW_ONLY_OUT: {"properties": {"customerId": "cust-only-out"}}, **tables},
        rows=[("top-nested", []), ("arg_max(TimeGenerated, CIp", []), ("AppServiceHTTPLogs", http),
              ("by ResourceId = tolower(_ResourceId), Principal", []), ("AzureDiagnostics", audit)],
    )


def run_service_logs(monkeypatch, tmp_path, patterns):
    client = _service_logs_client()
    _rest_env(monkeypatch, tmp_path, patterns, client)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = service_logs.main()
    return code, _evidence(tmp_path, service_logs.NAME), client


def test_service_logs_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, _ = run_service_logs(monkeypatch, tmp_path, None)
    results = evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert evidence["summary"] == {
        **service_logs.summarize(results["apps"], results["managed_instances"], results["app_dependencies"],
                                 results["workspaces"], results["lookback_days"]),
        **_added_fields({"app": 6, "managed_instance": 2}),
    }
    assert (evidence["summary"]["http_log_records"], evidence["summary"]["audit_records"]) == (533, 605)


def test_service_logs_excluded_apps_and_instances_leave_every_count(monkeypatch, tmp_path):
    patterns = f"rg:rg-out, location:regioneast, id:{MI_OUT}, id:{SLOT_B}, rg:typo"
    code, evidence, client = run_service_logs(monkeypatch, tmp_path, patterns)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("app", "app-east", "location:regioneast", "resource_matched"),
        ("app", "app-in/b", f"id:{SLOT_B}", "resource_matched"),
        ("app", "app-out", "rg:rg-out", "resource_matched"),
        ("managed_instance", "mi-out", f"id:{MI_OUT}", "resource_matched"),
    ]
    assert [a["name"] for a in results["apps"]] == ["app-in", "app-in/a"]
    assert [m["name"] for m in results["managed_instances"]] == ["mi-in"]
    # Excluded apps and instances get no slot, settings or database read, so a workspace only they send to isn't read.
    for path in (f"{APP_OUT}/slots", f"{APP_EAST}/slots", f"{APP_OUT}/{DIAG}", f"{APP_EAST}/{DIAG}", f"{SLOT_B}/{DIAG}",
                 f"{MI_OUT}/databases", f"{MI_OUT}/{DIAG}", LAW_ONLY_OUT):
        assert path not in client.reads, path
    assert "cust-only-out" not in {c for c, _ in client.queries}
    # The workspace in the excluded group still holds the in-scope app's logs, so it is read and its retention counts.
    assert sorted(w["name"] for w in results["workspaces"]) == ["law-in", "law-shared"]
    assert summary["http_log_retention_days"] == 7
    # Records about excluded apps and instances are in the same workspaces but count toward nothing.
    assert (summary["apps"], summary["http_log_records"], summary["apps_with_http_log_records"]) == (2, 13, 2)
    assert (summary["managed_instances"], summary["audit_records"], summary["instances_with_audit_records"]) == (1, 5, 1)
    assert (summary["excluded_apps"], summary["excluded_managed_instances"]) == (3, 1)
    assert (summary["in_scope_apps"], summary["in_scope_managed_instances"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


@pytest.mark.parametrize("m", [deletion, query_audit, analytics, automation, data_sources], ids=lambda m: m.NAME)
def test_workspace_counts_are_null_when_the_workspace_list_was_refused(monkeypatch, tmp_path, m):
    _rest_env(monkeypatch, tmp_path, WS_PATTERNS, RefusedClient({}, {}, refused=[WS_LIST]))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = m.main()
    summary = _evidence(tmp_path, m.NAME)["summary"]
    assert code == 1 and _status(tmp_path) == "not_authorized"
    assert (summary["in_scope_workspaces"], summary["excluded_workspaces"]) == (None, None)


def test_immutability_counts_are_null_when_the_account_list_was_refused(monkeypatch, tmp_path):
    good = _storage_client()
    _rest_env(monkeypatch, tmp_path, "rg:rg-out", RefusedClient(good.lists, good.gets, refused=[f"{SUB}/{STORAGE}"]))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = immutability.main()
    summary = _evidence(tmp_path, immutability.NAME)["summary"]
    assert code == 1 and _status(tmp_path) == "not_authorized"
    assert summary == {
        "resource_exclusion_patterns": ["rg:rg-out"], "resource_exclusion_patterns_unmatched": ["rg:rg-out"],
        "excluded_storage_accounts": None, "excluded_containers": None,
        "in_scope_storage_accounts": None, "in_scope_containers": None,
    }


@pytest.mark.parametrize("refused, unknown, known", [
    (f"{SUB}/{WEB}", "apps", {"excluded_managed_instances": 1, "in_scope_managed_instances": 1}),
    (f"{SUB}/{MIS}", "managed_instances", {"excluded_apps": 1, "in_scope_apps": 4}),
])
def test_service_log_counts_are_null_when_their_list_was_refused(monkeypatch, tmp_path, refused, unknown, known):
    good = _service_logs_client()
    _rest_env(monkeypatch, tmp_path, f"rg:rg-out, id:{MI_OUT}",
              RefusedClient(good.lists, good.gets, refused=[refused], rows=good.rows))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = service_logs.main()
    summary = _evidence(tmp_path, service_logs.NAME)["summary"]
    assert code == 1 and _status(tmp_path) == "not_authorized"
    assert (summary[f"in_scope_{unknown}"], summary[f"excluded_{unknown}"]) == (None, None)
    assert {k: summary[k] for k in known} == known
