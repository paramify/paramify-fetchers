"""resource_exclusions in the SQL Managed Instance and logging fetchers: excluded resources leave every count and stay
listed under excluded, and an in-scope resource's verdict doesn't change because something it points at is excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace as ns

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_sql_logs_under_test",
                                                  AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


configuration = _load("sql_managed_instance_configuration")
backups = _load("sql_managed_instance_backups")
encryption = _load("sql_managed_instance_encryption")
law = _load("log_analytics_workspaces")
rds = _load("resource_diagnostic_settings")

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
PATTERNS = "rg:rg-out, location:regionsouth, rg:typo"
DENIED = Exception("(AuthorizationFailed) The client does not have authorization")
EXCLUSION_KEYS = ("resource_exclusion_patterns", "resource_exclusion_patterns_unmatched")


def _common(monkeypatch, tmp_path, module, patterns):
    monkeypatch.setattr(module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(module, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(module, "credential", lambda: object())
    monkeypatch.setattr(module, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


def _without_exclusion_fields(summary: dict, kinds: tuple, plurals: tuple) -> dict:
    added = {*EXCLUSION_KEYS, *(f"excluded_{k}s" for k in kinds), *(f"in_scope_{p}" for p in plurals)}
    assert added <= set(summary)
    return {k: v for k, v in summary.items() if k not in added}


def _excluded(results: dict) -> list:
    return sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"])


# --- SQL Managed Instance ---

MI_IN = f"{IN_RG}/providers/Microsoft.Sql/managedInstances/mi-in"
MI_SOUTH = f"{IN_RG}/providers/Microsoft.Sql/managedInstances/mi-south"
MI_OUT = f"{OUT_RG}/providers/Microsoft.Sql/managedInstances/mi-out"
LOCATIONS = {MI_IN: "regioneast", MI_OUT: "regionwest", MI_SOUTH: "regionsouth"}
WORKSPACE_OUT = f"{OUT_RG}/providers/Microsoft.OperationalInsights/workspaces/law-out"


def _key(rid):
    return rid.split("/")[4], rid.rsplit("/", 1)[1]


def _call(table):
    def fn(*args, **kwargs):
        value = table[args or tuple(kwargs.values())]
        if isinstance(value, Exception):
            raise value
        return value

    return fn


def _failover_view(rg, location, role, name, primary, partner):
    return ns(id=f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Sql/locations/{location}/instanceFailoverGroups/{name}",
              name=name, replication_role=role, replication_state="CATCH_UP", secondary_type="Geo",
              read_write_endpoint=ns(failover_policy="Manual", failover_with_data_loss_grace_period_minutes=60),
              managed_instance_pairs=[ns(primary_managed_instance_id=primary, partner_managed_instance_id=partner)],
              partner_regions=[])


FAILOVER = {
    ("rg-in", "regioneast"): [_failover_view("rg-in", "regioneast", "Primary", "fog-a", MI_IN, MI_OUT)],
    ("rg-out", "regionwest"): [_failover_view("rg-out", "regionwest", "Secondary", "fog-a", MI_IN, MI_OUT),
                               _failover_view("rg-out", "regionwest", "Primary", "fog-b", MI_OUT, MI_SOUTH)],
    ("rg-in", "regionsouth"): [_failover_view("rg-in", "regionsouth", "Secondary", "fog-b", MI_OUT, MI_SOUTH)],
}


def _sql_client(failover=None):
    keys = [_key(rid) for rid in LOCATIONS]
    return ns(
        managed_instances=ns(list=lambda: [
            ns(id=rid, name=_key(rid)[1], location=loc, state="Ready", current_backup_storage_redundancy="Geo",
               public_data_endpoint_enabled=rid != MI_IN, minimal_tls_version="1.2")
            for rid, loc in LOCATIONS.items()]),
        managed_databases=ns(list_by_instance=_call({
            _key(rid): [ns(id=f"{rid}/databases/app", name="app", status="Online")] for rid in LOCATIONS})),
        managed_backup_short_term_retention_policies=ns(get=_call(
            {(*k, "app", "default"): ns(retention_days=7 if k[1] == "mi-in" else 3) for k in keys})),
        managed_instance_long_term_retention_policies=ns(get=_call(
            {(*k, "app", "default"): ns(weekly_retention="P4W") for k in keys})),
        instance_failover_groups=ns(list_by_location=_call(failover or FAILOVER)),
        managed_instance_encryption_protectors=ns(get=_call(
            {(*k, "current"): ns(server_key_type="ServiceManaged" if k[1] == "mi-in" else "AzureKeyVault")
             for k in keys})),
        managed_database_transparent_data_encryption=ns(get=_call(
            {(*k, "app", "current"): ns(state="Enabled" if k[1] == "mi-in" else "Disabled") for k in keys})),
        managed_instance_administrators=ns(list_by_instance=_call(
            {k: [ns(administrator_type="ActiveDirectory", login="dba")] for k in keys})),
        managed_instance_azure_ad_only_authentications=ns(list_by_instance=_call(
            {k: [ns(azure_ad_only_authentication=True)] for k in keys})),
    )


def run_sql(monkeypatch, tmp_path, module, patterns, failover=None):
    _common(monkeypatch, tmp_path, module, patterns)
    monkeypatch.setattr(module, "sql_client", lambda *a: _sql_client(failover))
    if module is configuration:
        audit = ns(id="ds", name="ds", workspace_id=WORKSPACE_OUT,
                   logs=[ns(category="SQLSecurityAuditEvents", enabled=True)])
        monkeypatch.setattr(module, "monitor_client", lambda *a: ns(diagnostic_settings=ns(list=lambda **k: [audit])))
    code = module.main()
    name = module.logger.name
    return code, json.loads((tmp_path / f"{name}_s1.json").read_text())


def test_sql_configuration_and_encryption_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    for module in (configuration, encryption):
        code, evidence = run_sql(monkeypatch, tmp_path, module, None)
        summary, results = evidence["summary"], evidence["results"]
        assert code == 0 and results["excluded"] == []
        assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
        assert summary["total_managed_instances"] == summary["in_scope_managed_instances"] == 3
        assert summary["excluded_managed_instances"] == 0
        assert _without_exclusion_fields(summary, ("managed_instance",), ("managed_instances",)) == {
            **module.summarize(results["managed_instances"]), "provider_registration_status": "registered"}


def test_sql_configuration_excludes_by_group_and_region_and_keeps_an_excluded_audit_destination(
        monkeypatch, tmp_path):
    code, evidence = run_sql(monkeypatch, tmp_path, configuration, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    [instance] = results["managed_instances"]
    assert instance["name"] == "mi-in" and instance["audit_log_destinations"] == [WORKSPACE_OUT]
    assert _excluded(results) == [("managed_instance", "mi-out", "rg:rg-out"),
                                  ("managed_instance", "mi-south", "location:regionsouth")]
    assert {e["id"] for e in results["excluded"]} == {MI_OUT, MI_SOUTH}
    assert (summary["total_managed_instances"], summary["in_scope_managed_instances"],
            summary["excluded_managed_instances"]) == (1, 1, 2)
    assert (summary["instances_public_data_endpoint_enabled"], summary["instances_audit_logs_exported"]) == (0, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_sql_encryption_counts_only_in_scope_instances_and_their_databases(monkeypatch, tmp_path):
    code, evidence = run_sql(monkeypatch, tmp_path, encryption, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [i["name"] for i in results["managed_instances"]] == ["mi-in"]
    assert _excluded(results) == [("managed_instance", "mi-out", "rg:rg-out"),
                                  ("managed_instance", "mi-south", "location:regionsouth")]
    assert (summary["instances_customer_managed_key"], summary["total_user_databases"],
            summary["tde_enabled_user_databases"], summary["tde_disabled_user_databases"]) == (0, 1, 1, 0)
    assert (summary["in_scope_managed_instances"], summary["excluded_managed_instances"]) == (1, 2)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_sql_backups_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_sql(monkeypatch, tmp_path, backups, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert summary["in_scope_managed_instances"] == summary["total_managed_instances"] == 3
    assert summary["in_scope_instance_failover_groups"] == summary["total_instance_failover_groups"] == 2
    assert summary["excluded_managed_instances"] == summary["excluded_instance_failover_groups"] == 0
    kinds, plurals = ("managed_instance", "instance_failover_group"), ("managed_instances", "instance_failover_groups")
    assert _without_exclusion_fields(summary, kinds, plurals) == {
        **backups.summarize(results["managed_instances"], results["instance_failover_groups"], True),
        "provider_registration_status": "registered"}


def test_sql_backups_keep_a_failover_group_with_an_in_scope_instance_and_drop_one_with_none(monkeypatch, tmp_path):
    code, evidence = run_sql(monkeypatch, tmp_path, backups, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    [instance] = results["managed_instances"]
    assert (instance["name"], instance["failover_groups"], instance["in_failover_group"]) == ("mi-in", ["fog-a"], True)
    assert [g["name"] for g in results["instance_failover_groups"]] == ["fog-a"]
    assert _excluded(results) == [("instance_failover_group", "fog-b", "location:regionsouth"),
                                  ("managed_instance", "mi-out", "rg:rg-out"),
                                  ("managed_instance", "mi-south", "location:regionsouth")]
    [group] = [e for e in results["excluded"] if e["kind"] == "instance_failover_group"]
    assert (group["matched_id"], group["reason"]) == (MI_SOUTH, "managed_instance_matched")
    assert (summary["total_managed_instances"], summary["excluded_managed_instances"]) == (1, 2)
    assert (summary["total_instance_failover_groups"], summary["in_scope_instance_failover_groups"],
            summary["excluded_instance_failover_groups"]) == (1, 1, 1)
    assert (summary["total_user_databases"], summary["databases_retention_below_7_days"],
            summary["instances_in_failover_group"]) == (1, 0, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_sql_backups_failover_verdict_still_uses_an_excluded_partners_region(monkeypatch, tmp_path):
    failover = {**FAILOVER, ("rg-in", "regioneast"): DENIED}
    code, evidence = run_sql(monkeypatch, tmp_path, backups, "rg:rg-out", failover)
    assert code == 1
    [instance] = [i for i in evidence["results"]["managed_instances"] if i["name"] == "mi-in"]
    assert (instance["in_failover_group"], instance["failover_groups"]) == (True, ["fog-a"])
    assert [g["name"] for g in evidence["results"]["instance_failover_groups"]] == ["fog-a", "fog-b"]


def test_sql_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    for module in (configuration, backups, encryption):
        code, evidence = run_sql(monkeypatch, tmp_path, module, "rg-out")
        assert code == 1
        assert evidence["summary"]["total_managed_instances"] == 3 and evidence["results"]["excluded"] == []


# --- Log Analytics workspaces ---

def _workspace(rg, name, location, retention, sentinel):
    rid = f"{SUB}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}"
    packs = [{"name": "SecurityInsights", "enabled": sentinel}]
    return law.workspace_record({"id": rid, "name": name, "location": location, "retention_in_days": retention},
                                [], [], packs)


def run_law(monkeypatch, tmp_path, patterns):
    _common(monkeypatch, tmp_path, law, patterns)
    workspaces = [_workspace("rg-in", "law-in", "regioneast", 90, True),
                  _workspace("rg-in", "law-south", "regionsouth", 7, False),
                  _workspace("rg-out", "law-out", "regionwest", 30, True)]
    monkeypatch.setattr(law, "collect_workspaces", lambda *a: workspaces)
    code = law.main()
    return code, json.loads((tmp_path / "azure_log_analytics_workspaces_s1.json").read_text())


def test_log_analytics_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_law(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert (summary["total_workspaces"], summary["in_scope_workspaces"], summary["excluded_workspaces"]) == (3, 3, 0)
    assert _without_exclusion_fields(summary, ("workspace",), ("workspaces",)) == {
        **law.summarize(results["workspaces"]), "provider_registration_status": "registered"}


def test_log_analytics_excludes_by_group_and_region(monkeypatch, tmp_path):
    code, evidence = run_law(monkeypatch, tmp_path, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [w["name"] for w in results["workspaces"]] == ["law-in"]
    assert _excluded(results) == [("workspace", "law-out", "rg:rg-out"),
                                  ("workspace", "law-south", "location:regionsouth")]
    assert (summary["total_workspaces"], summary["in_scope_workspaces"], summary["excluded_workspaces"]) == (1, 1, 2)
    assert (summary["min_workspace_retention_in_days"], summary["sentinel_onboarded_workspaces"]) == (90, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_log_analytics_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_law(monkeypatch, tmp_path, "law-out")
    assert code == 1
    assert evidence["summary"]["total_workspaces"] == 3


# --- resource diagnostic settings ---

VAULT_IN = f"{IN_RG}/providers/Microsoft.KeyVault/vaults/kv-in"
VAULT_SOUTH = f"{IN_RG}/providers/Microsoft.KeyVault/vaults/kv-south"
STORAGE_OUT = f"{OUT_RG}/providers/Microsoft.Storage/storageAccounts/saout"
SUB_LEVEL = f"{SUB}/providers/Microsoft.Example/things/thing-south"
INVENTORY = [
    {"id": VAULT_IN, "name": "kv-in", "type": "Microsoft.KeyVault/vaults", "location": "regioneast",
     "resourceGroup": "rg-in"},
    {"id": VAULT_SOUTH, "name": "kv-south", "type": "Microsoft.KeyVault/vaults", "location": "regionsouth",
     "resourceGroup": "rg-in"},
    {"id": WORKSPACE_OUT, "name": "law-out", "type": "Microsoft.OperationalInsights/workspaces",
     "location": "regionwest", "resourceGroup": "rg-out"},
    {"id": STORAGE_OUT, "name": "saout", "type": "Microsoft.Storage/storageAccounts", "kind": "BlobStorage",
     "location": "regionwest", "resourceGroup": "rg-out"},
    {"id": SUB_LEVEL, "name": "thing-south", "type": "Microsoft.Example/things", "location": "regionsouth",
     "resourceGroup": ""},
]


class _Rest:
    def get(self, path, api_version):
        return {"properties": {"customerId": "cust-1"}}

    def list(self, path, api_version):
        return []

    def query(self, customer_id, kql, timespan):
        return [{"ResourceId": VAULT_IN.lower(), "Table": "AzureDiagnostics", "Records": 3,
                 "LastIngested": "2026-10-12T00:00:00Z"}]


def run_rds(monkeypatch, tmp_path, patterns):
    _common(monkeypatch, tmp_path, rds, patterns)
    category = ns(name="AuditEvent", category_type="Logs", category_groups=["audit", "allLogs"])
    setting = ns(id="ds", name="ds", storage_account_id=None, workspace_id=WORKSPACE_OUT, event_hub_name=None,
                 event_hub_authorization_rule_id=None, marketplace_partner_id=None,
                 log_analytics_destination_type=None, logs=[ns(category=None, category_group="allLogs", enabled=True)])
    read: list = []
    monitor = ns(diagnostic_settings_category=ns(list=lambda resource_uri: read.append(resource_uri) or [category]),
                 diagnostic_settings=ns(list=lambda resource_uri: [setting]))
    monkeypatch.setattr(rds, "enumerate_resources", lambda *a: {"rows": INVENTORY, "total_records": 5, "pages": 1})
    monkeypatch.setattr(rds, "monitor_client", lambda *a: monitor)
    monkeypatch.setattr(rds, "AzureRestClient", lambda cred: _Rest())
    for env in (rds.BASIC_LOOKBACK_ENV, rds.APPROVED_WORKSPACES_ENV, rds.INGESTION_LOOKBACK_ENV):
        monkeypatch.delenv(env, raising=False)
    code = rds.main()
    return code, json.loads((tmp_path / "azure_resource_diagnostic_settings_s1.json").read_text()), read


def test_diagnostic_settings_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, read = run_rds(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == [] and len(read) == 6
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert (summary["resources_evaluated"], summary["in_scope_resources"], summary["excluded_resources"]) == (6, 6, 0)
    records, destinations = results["resources"], results["log_analytics_destinations"]
    assert _without_exclusion_fields(summary, ("resource",), ("resources",)) == {
        **rds.summarize(records, 5, 5, 1), "provider_registration_status": "registered",
        **rds.summarize_ingestion(records, destinations, 7, 0, [])}


def test_diagnostic_settings_exclude_and_skip_resources_but_still_read_an_excluded_destination(
        monkeypatch, tmp_path):
    code, evidence, read = run_rds(monkeypatch, tmp_path, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [r["name"] for r in results["resources"]] == ["thing-south", "kv-in"]
    assert sorted(read) == sorted(rds.resource_uri(i) for i in (VAULT_IN, SUB_LEVEL))
    assert _excluded(results) == [("resource", "kv-south", "location:regionsouth"),
                                  ("resource", "law-out", "rg:rg-out"),
                                  ("resource", "saout", "rg:rg-out"),
                                  ("resource", "saout/blobServices/default", "rg:rg-out")]
    [vault] = [r for r in results["resources"] if r["id"] == VAULT_IN]
    assert (vault["has_enabled_log_setting"], vault["ingested_in_window"]) == (True, True)
    assert [d["workspace_id"] for d in results["log_analytics_destinations"]] == [WORKSPACE_OUT]
    assert (summary["resources_enumerated"], summary["resource_graph_total_records"]) == (5, 5)
    assert (summary["resources_evaluated"], summary["in_scope_resources"], summary["excluded_resources"]) == (2, 2, 4)
    assert (summary["child_services_synthesized"], summary["resources_emitting_logs"],
            summary["resources_with_recent_ingestion"], summary["log_analytics_destinations_queried"]) == (0, 2, 1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_diagnostic_settings_subscription_level_resource_leaves_only_by_id(monkeypatch, tmp_path):
    _, evidence, _ = run_rds(monkeypatch, tmp_path, f"id:{SUB_LEVEL.upper()}")
    assert _excluded(evidence["results"]) == [("resource", "thing-south", f"id:{SUB_LEVEL.upper()}")]


def test_diagnostic_settings_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence, read = run_rds(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["results"]["excluded"] == [] and evidence["summary"]["in_scope_resources"] == 6 == len(read)
