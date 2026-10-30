"""resource_exclusions in the App Service fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
NEW_FIELDS = {"resource_exclusion_patterns", "resource_exclusion_patterns_unmatched"}
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=timezone.utc)


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


config_fetcher = _load("app_service_configuration")
plans_fetcher = _load("app_service_plans")
backups_fetcher = _load("app_service_backups")
deployments_fetcher = _load("app_service_deployments")


def _site_id(rg: str, name: str) -> str:
    return f"{rg}/providers/Microsoft.Web/sites/{name}"


def _plan_id(rg: str, name: str) -> str:
    return f"{rg}/providers/Microsoft.Web/serverfarms/{name}"


def _common(m, monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


# --- azure_app_service_configuration ---

def _config_client(sites, reads):
    def per_app(value):
        def fn(resource_group_name, name):
            reads.append(name)
            return value
        return fn

    return ns(
        web_apps=ns(
            list=lambda: sites,
            get_configuration=per_app(ns(min_tls_version="1.2", ftps_state="Disabled")),
            get_auth_settings_v2_without_secrets=per_app(ns(platform=None, global_validation=None)),
            get_scm_allowed=per_app(ns(allow=False)),
            get_ftp_allowed=per_app(ns(allow=False)),
            get_app_settings_key_vault_references=per_app([]),
            get_site_connection_string_key_vault_references=per_app([]),
        ),
        provider=ns(get_web_app_stacks=lambda: []),
    )


def run_configuration(monkeypatch, tmp_path, patterns):
    def site(rg, name, location, kind="app"):
        return ns(id=_site_id(rg, name), name=name, kind=kind, location=location, state="Running", https_only=True)

    sites = [site(IN_RG, "web-in", "regionwest"), site(OUT_RG, "web-out", "regionwest"),
             site(IN_RG, "web-east", "regioneast"), site(OUT_RG, "func-out", "regionwest", kind="functionapp")]
    reads: list = []
    m = config_fetcher
    _common(m, monkeypatch, tmp_path, patterns)
    monkeypatch.delenv(m.SCAN_ENV, raising=False)
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "web_client", lambda *a: _config_client(sites, reads))
    monkeypatch.setattr(m, "_attach_diagnostic_settings", lambda *a: None)
    code = m.main()
    return code, json.loads((tmp_path / "azure_app_service_configuration_s1.json").read_text()), set(reads)


def test_configuration_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, reads = run_configuration(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == [] and reads == {"web-in", "web-out", "web-east"}
    assert set(summary) - set(config_fetcher.summarize(results["web_apps"])) == NEW_FIELDS | {
        "provider_registration_status", "excluded_web_apps", "in_scope_web_apps"}
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert summary["total_web_apps"] == summary["in_scope_web_apps"] == 3
    assert summary["excluded_web_apps"] == 0


def test_configuration_excludes_by_group_and_region_and_reads_nothing_for_them(monkeypatch, tmp_path):
    code, evidence, reads = run_configuration(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [a["name"] for a in results["web_apps"]] == ["web-in"] and reads == {"web-in"}
    assert sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"]) == [
        ("web_app", "web-east", "location:regioneast"),
        ("web_app", "web-out", "rg:rg-out"),
    ]
    assert results["excluded"][0] == {"kind": "web_app", "name": "web-out", "pattern": "rg:rg-out",
                                      "reason": "resource_matched", "id": _site_id(OUT_RG, "web-out"),
                                      "resource_group": "rg-out", "location": "regionwest"}
    assert (summary["total_web_apps"], summary["in_scope_web_apps"], summary["excluded_web_apps"]) == (1, 1, 2)
    assert (summary["https_only_apps"], summary["https_only_percentage"]) == (1, 100)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_configuration_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _ = run_configuration(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_web_apps"] == 3


# --- azure_app_service_plans ---

PLAN_FREE = _plan_id(OUT_RG, "plan-free")
PLAN_EAST = _plan_id(IN_RG, "plan-east")
APP_EAST = _site_id(IN_RG, "app-east")
# (group, plan, region, zone redundant, capacity, tier) -> the sites on it as (group, site, region).
PLANS = [
    (IN_RG, "plan-in", "regionwest", True, 3, "PremiumV3", [(IN_RG, "app-in", "regionwest"),
                                                            (OUT_RG, "app-out", "regionwest")]),
    (OUT_RG, "plan-out", "regionwest", True, 2, "PremiumV3", [(OUT_RG, "app-out2", "regionwest")]),
    (OUT_RG, "plan-free", "regionwest", False, 1, "Free", [(IN_RG, "app-cross", "regionwest")]),
    (IN_RG, "plan-east", "regioneast", False, 1, "PremiumV3", [(IN_RG, "app-east", "regioneast")]),
    (IN_RG, "plan-orphan", "regionwest", False, 2, "PremiumV3", [(OUT_RG, "app-orphan", "regionwest")]),
]


def run_plans(monkeypatch, tmp_path, patterns):
    # number_of_sites is Azure's count, excluded sites included.
    plans = [ns(id=_plan_id(rg, name), name=name, location=location, kind="app", status="Ready",
                sku=ns(name=tier, tier=tier, size=tier, family=tier, capacity=capacity),
                zone_redundant=zone_redundant, number_of_sites=len(hosted))
             for rg, name, location, zone_redundant, capacity, tier, hosted in PLANS]
    sites = [ns(id=_site_id(site_rg, site), name=site, location=region, kind="app", state="Running",
                server_farm_id=_plan_id(rg, name))
             for rg, name, *_, hosted in PLANS for site_rg, site, region in hosted]
    client = ns(app_service_plans=ns(list=lambda detailed: plans), web_apps=ns(list=lambda: sites))
    m = plans_fetcher
    _common(m, monkeypatch, tmp_path, patterns)
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setitem(sys.modules, "azure.mgmt.web", ns(WebSiteManagementClient=lambda **kw: client))
    code = m.main()
    return code, json.loads((tmp_path / "azure_app_service_plans_s1.json").read_text())


def _listed(results) -> dict:
    return {p["name"]: (p["number_of_sites"], [s["name"] for s in p["sites"]]) for p in results["app_service_plans"]}


def test_plans_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert set(summary) - set(plans_fetcher.summarize(results["app_service_plans"])) == NEW_FIELDS | {
        "provider_registration_status", "excluded_app_service_plans", "excluded_sites",
        "in_scope_app_service_plans", "in_scope_sites"}
    assert summary["total_app_service_plans"] == summary["in_scope_app_service_plans"] == 5
    assert summary["total_sites"] == summary["in_scope_sites"] == 6
    assert summary["excluded_app_service_plans"] == summary["excluded_sites"] == 0
    assert (summary["single_instance_plans"], summary["no_sla_tier_plans"], summary["empty_plans"]) == (2, 1, 0)
    assert summary["sites_on_zone_redundant_plans"] == 3
    # Without patterns the listed sites are Azure's own count.
    assert all(count == len(sites) for count, sites in _listed(results).values())


def test_plans_keep_an_excluded_free_plan_while_an_in_scope_app_runs_on_it(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _listed(results) == {"plan-in": (1, ["app-in"]), "plan-orphan": (0, []), "plan-free": (1, ["app-cross"])}
    assert sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"]) == [
        ("app_service_plan", "plan-east", "location:regioneast"),
        ("app_service_plan", "plan-out", "rg:rg-out"),
        ("site", "app-east", "location:regioneast"),
        ("site", "app-orphan", "rg:rg-out"),
        ("site", "app-out", "rg:rg-out"),
        ("site", "app-out2", "rg:rg-out"),
    ]
    assert next(e for e in results["excluded"] if e["name"] == "plan-out") == {
        "kind": "app_service_plan", "name": "plan-out", "pattern": "rg:rg-out", "reason": "resource_matched",
        "id": _plan_id(OUT_RG, "plan-out"), "resource_group": "rg-out", "location": "regionwest"}
    assert (summary["total_app_service_plans"], summary["in_scope_app_service_plans"],
            summary["excluded_app_service_plans"]) == (3, 3, 2)
    assert (summary["single_instance_plans"], summary["no_sla_tier_plans"]) == (1, 1)
    assert (summary["zone_redundant_plans"], summary["zone_redundant_percentage"]) == (1, 33)
    assert (summary["total_sites"], summary["in_scope_sites"], summary["excluded_sites"]) == (2, 2, 4)
    assert (summary["sites_on_zone_redundant_plans"], summary["sites_on_multi_instance_plans"]) == (1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_plans_an_in_scope_plan_whose_sites_are_all_excluded_is_empty(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, "rg:rg-out")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _listed(results)["plan-orphan"] == (0, [])
    assert [e["name"] for e in results["excluded"] if e["kind"] == "app_service_plan"] == ["plan-out"]
    assert (summary["total_app_service_plans"], summary["empty_plans"], summary["excluded_sites"]) == (4, 1, 3)


def test_plans_id_patterns_take_out_a_plan_only_with_its_last_in_scope_site(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, f"id:{PLAN_EAST}, id:{APP_EAST.upper()}, id:{PLAN_FREE}")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [(e["kind"], e["id"]) for e in results["excluded"]] == [("site", APP_EAST), ("app_service_plan", PLAN_EAST)]
    assert "plan-free" in _listed(results) and "plan-east" not in _listed(results)
    assert (summary["total_app_service_plans"], summary["single_instance_plans"], summary["no_sla_tier_plans"]) == (
        4, 1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == []


def test_plans_an_id_pattern_on_a_plan_alone_keeps_it_for_its_in_scope_site(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, f"id:{PLAN_EAST}")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert _listed(results)["plan-east"] == (1, ["app-east"])
    assert summary["total_app_service_plans"] == summary["in_scope_app_service_plans"] == 5
    assert summary["excluded_app_service_plans"] == 0


def test_plans_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_app_service_plans"] == 5


# --- azure_app_service_backups ---

STORAGE_ID = f"{OUT_RG}/providers/Microsoft.Storage/storageAccounts/stout"
CONTAINER = "https://stout.blob.core.windows.net/backups"


BACKUP_SITES = [("rg-in", "web-in", "regionwest", "app"), ("rg-out", "web-out", "regionwest", "app"),
                ("rg-in", "web-east", "regioneast", "app"), ("rg-in", "func-in", "regionwest", "functionapp"),
                ("rg-out", "func-out", "regionwest", "functionapp")]
# Resource Graph rows carry no region here, so the regioneast slot can only follow its app.
BACKUP_SLOTS = [("rg-in", "web-in"), ("rg-out", "web-out"), ("rg-in", "web-east")]
BOUNDARY = ["boundary_excluded_web_apps", "boundary_excluded_function_apps", "boundary_excluded_deployment_slots"]


def _table(values: dict):
    """A per-app read answering only the in-scope apps; any other call fails the run."""
    def fn(*args):
        if args not in values:
            raise AssertionError(f"unexpected call {args}")
        return values[args]
    return fn


def run_backups(monkeypatch, tmp_path, patterns, read=("web-in", "web-out", "web-east"), graph_fails=False):
    sites = [ns(id=_site_id(f"{SUB}/resourceGroups/{rg}", name), name=name, kind=kind, location=location,
                state="Running", sku="Standard") for rg, name, location, kind in BACKUP_SITES]
    graph = [{"id": s.id, "name": s.name, "kind": s.kind, "type": "microsoft.web/sites", "location": None}
             for s in sites] + [
        {"id": _site_id(f"{SUB}/resourceGroups/{rg}", f"{app}/slots/stage"), "name": f"{app}/stage", "kind": "app",
         "type": "microsoft.web/sites/slots", "location": None} for rg, app in BACKUP_SLOTS]
    apps = {(rg, name) for rg, name, _, _ in BACKUP_SITES if name in read}
    snapshots = [ns(time=(NOW - timedelta(hours=h)).isoformat()) for h in (0.5, 1.5)]
    config = ns(backup_name="b", enabled=True, storage_account_url=f"{CONTAINER}?sig=x", databases=[],
                backup_schedule=ns(frequency_interval=1, frequency_unit="Day", retention_period_in_days=30))
    client = ns(web_apps=ns(
        list=lambda: sites,
        get=_table({}),
        list_snapshots=_table({app: snapshots for app in apps}),
        list_backups=_table({app: [] for app in apps}),
        get_backup_configuration=_table({app: config for app in apps}),
    ))
    storage = [{"id": STORAGE_ID, "name": "stout", "location": "regionwest", "replication": "Standard_GRS"}]

    def query(_client, _sub, text):
        if graph_fails and "storageaccounts" not in text:
            raise RuntimeError("Resource Graph reported 8 rows but paging returned 7")
        found = storage if "storageaccounts" in text else graph
        return {"rows": found, "total_records": len(found), "pages": 1}

    m = backups_fetcher
    _common(m, monkeypatch, tmp_path, patterns)
    monkeypatch.setattr(m, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(m, "web_client", lambda *a: client)
    monkeypatch.setattr(m, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(m, "query_all", query)
    monkeypatch.setattr(m, "utc_now", lambda: NOW)
    code = m.main()
    return code, json.loads((tmp_path / "azure_app_service_backups_s1.json").read_text())


def test_backups_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_backups(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    expected = backups_fetcher.summarize(results["web_apps"], results["inventory_check"], results["exclusions"],
                                         results["custom_backup_storage_accounts"], results["settings"])
    assert set(summary) - set(expected) == NEW_FIELDS | {"provider_registration_status", *BOUNDARY, "in_scope_web_apps"}
    assert "excluded_web_apps" not in summary
    assert summary["total_web_apps"] == summary["in_scope_web_apps"] == summary["resource_graph_web_apps"] == 3
    assert [summary[k] for k in BOUNDARY] == [0, 0, 0]
    assert (summary["excluded_function_apps"], summary["excluded_deployment_slots"]) == (2, 3)


def test_backups_exclude_sites_and_slots_but_keep_an_in_scope_apps_storage_account(monkeypatch, tmp_path):
    code, evidence = run_backups(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo", read=("web-in",))
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [a["name"] for a in results["web_apps"]] == ["web-in"]
    assert results["web_apps"][0]["backed_up"] is True
    assert sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"]) == [
        ("deployment_slot", "web-east/stage", "location:regioneast"),
        ("deployment_slot", "web-out/stage", "rg:rg-out"),
        ("function_app", "func-out", "rg:rg-out"),
        ("web_app", "web-east", "location:regioneast"),
        ("web_app", "web-out", "rg:rg-out"),
    ]
    assert [r["name"] for r in results["exclusions"]["function_apps"]["resources"]] == ["func-in"]
    assert [r["name"] for r in results["exclusions"]["deployment_slots"]["resources"]] == ["web-in/stage"]
    assert [s["name"] for s in results["custom_backup_storage_accounts"]] == ["stout"]
    assert results["custom_backup_storage_accounts"][0]["resolved"] is True
    assert (summary["total_web_apps"], summary["in_scope_web_apps"]) == (1, 1)
    assert (summary["apps_backed_up"], summary["backup_coverage_percentage"]) == (1, 100)
    # Out of the boundary by pattern, versus in scope but not assessed by this fetcher.
    assert [summary[k] for k in BOUNDARY] == [2, 1, 2]
    assert (summary["excluded_function_apps"], summary["excluded_deployment_slots"]) == (1, 1)
    assert summary["resource_graph_web_apps"] == 1
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_backups_resource_graph_failure_still_applies_the_patterns_to_the_site_list(monkeypatch, tmp_path):
    code, evidence = run_backups(monkeypatch, tmp_path, "rg:rg-out, location:regioneast", read=("web-in",),
                                 graph_fails=True)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 1
    assert [f["operation"] for f in evidence["metadata"]["api_failures"]] == [
        "resourcegraph.resources (web sites and slots)"]
    assert [a["name"] for a in results["web_apps"]] == ["web-in"] and results["inventory_check"] is None
    assert sorted((e["kind"], e["name"]) for e in results["excluded"]) == [
        ("function_app", "func-out"), ("web_app", "web-east"), ("web_app", "web-out")]
    # Slots are listed only by Resource Graph, so neither slot count is known.
    assert [summary[k] for k in BOUNDARY] == [2, 1, None]
    assert (summary["excluded_function_apps"], summary["excluded_deployment_slots"]) == (1, None)
    assert summary["in_scope_web_apps"] == 1 and summary["resource_graph_web_apps"] is None


def test_backups_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_backups(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_web_apps"] == 3


# --- azure_app_service_deployments ---

# (group, site, region, kind) -> its slots.
DEPLOY_SITES = [(IN_RG, "web-in", "regionwest", "app", ["stage", "qa"]),
                (OUT_RG, "web-out", "regionwest", "app", ["stage"]),
                (IN_RG, "web-east", "regioneast", "app", ["stage"]),
                (IN_RG, "web-id", "regionwest", "app", ["stage"]),
                (IN_RG, "func-in", "regionwest", "functionapp", []),
                (OUT_RG, "func-out", "regionwest", "functionapp", [])]
SWAP = "Microsoft.Web/sites/slots/slotsSwap/action"
PUBLISH = "Microsoft.Web/sites/publishxml/action"
PACKAGE = "Microsoft.Web/sites/extensions/write"
# (operation, group, the path below sites/): one request each.
DEPLOY_EVENTS = [
    (SWAP, IN_RG, "web-in/slots/stage"),
    (SWAP, IN_RG, "web-in/slots/qa"),
    (SWAP, OUT_RG, "web-out/slots/stage"),
    (PUBLISH, IN_RG, "web-east"),
    (PUBLISH, IN_RG, "web-id"),
    (PACKAGE, OUT_RG, "func-out/extensions/MSDeploy"),
    (PUBLISH, OUT_RG, "deleted-out"),
    (PUBLISH, IN_RG, "deleted-in"),
    (PUBLISH, IN_RG, "func-in"),
]
DEPLOY_SCOPE = f"rg:rg-out, location:regioneast, id:{_site_id(IN_RG, 'web-id')}, " \
               f"id:{_site_id(IN_RG, 'web-in')}/slots/qa, rg:typo"
DEPLOY_BOUNDARY = ["boundary_excluded_web_apps", "boundary_excluded_function_apps",
                   "boundary_excluded_deployment_slots", "in_scope_web_apps"]


def _deploy_site(rg, name, location, kind="app"):
    return ns(id=_site_id(rg, name), name=name, kind=kind, location=location, state="Running", https_only=True,
              client_cert_enabled=None, public_network_access="Enabled")


def _deploy_client(reads):
    regions = {name: (rg, location) for rg, name, location, _, _ in DEPLOY_SITES}
    slots = {name: names for _, name, _, _, names in DEPLOY_SITES}

    def read(value):
        def fn(resource_group_name, name, slot=None):
            reads.append(f"{name}/{slot}" if slot else name)
            return value(name) if callable(value) else value
        return fn

    def list_slots(name):
        rg, location = regions[name]
        return [ns(**{**vars(_deploy_site(rg, f"{name}/{s}", location)), "id": f"{_site_id(rg, name)}/slots/{s}"})
                for s in slots[name]]

    source = ns(repo_url=None, branch=None)
    return ns(web_apps=ns(
        list=lambda: [_deploy_site(rg, name, location, kind) for rg, name, location, kind, _ in DEPLOY_SITES],
        list_deployments=read([]), list_deployments_slot=read([]),
        get_source_control=read(source), get_source_control_slot=read(source),
        list_slots=read(list_slots),
        get_configuration=read(ns(min_tls_version="1.2")), get_configuration_slot=read(ns(min_tls_version="1.2")),
    ))


def run_deployments(monkeypatch, tmp_path, patterns):
    events = [ns(operation_name=ns(value=op), status=ns(value="Succeeded"), caller="releaser@example.com",
                 claims={"idtyp": "user"}, resource_id=f"{rg}/providers/Microsoft.Web/sites/{path}",
                 correlation_id=f"corr-{i}", event_data_id=f"ev-{i}", event_timestamp=NOW)
              for i, (op, rg, path) in enumerate(DEPLOY_EVENTS)]
    reads: list = []
    failures: list = []
    m = deployments_fetcher
    _common(m, monkeypatch, tmp_path, patterns)
    monkeypatch.delenv("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS", raising=False)
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "web_client", lambda *a: _deploy_client(reads))
    monkeypatch.setattr(m, "monitor_client", lambda *a: ns(activity_logs=ns(list=lambda filter: iter(events))))
    monkeypatch.setattr(m, "report_failure", lambda reason, code: failures.append(code))
    code = m.main()
    evidence = json.loads((tmp_path / "azure_app_service_deployments_s1.json").read_text())
    return code, evidence, set(reads), failures


def test_deployments_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, reads, _ = run_deployments(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert reads == {"web-in", "web-in/stage", "web-in/qa", "web-out", "web-out/stage", "web-east", "web-east/stage",
                     "web-id", "web-id/stage"}
    expected = deployments_fetcher.summarize(results["web_apps"], 2, results["activity_log"])
    assert set(summary) - set(expected) == NEW_FIELDS | {"provider_registration_status", *DEPLOY_BOUNDARY}
    assert [summary[k] for k in DEPLOY_BOUNDARY] == [0, 0, 0, 4]
    assert summary["resource_exclusion_patterns"] == summary["resource_exclusion_patterns_unmatched"] == []
    assert (summary["total_web_apps"], summary["total_deployment_slots"], summary["excluded_function_apps"]) == (4, 5, 2)
    assert (summary["slot_swaps"], summary["publish_profile_downloads"]) == (3, 2)
    assert summary["deployment_activity_on_unlisted_sites"] == 4
    assert summary["slots_matching_production"] == 5
    assert results["activity_log"]["requests_on_excluded_sites"] == dict.fromkeys(deployments_fetcher.ACTIVITY_CATEGORIES, 0)


def test_deployments_exclude_by_group_region_and_id_and_read_nothing_for_them(monkeypatch, tmp_path):
    code, evidence, reads, _ = run_deployments(monkeypatch, tmp_path, DEPLOY_SCOPE)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert reads == {"web-in", "web-in/stage"}
    assert [a["name"] for a in results["web_apps"]] == ["web-in"]
    assert [s["name"] for s in results["web_apps"][0]["slots"]] == ["stage"]
    assert sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"]) == [
        ("deployment_slot", "web-in/qa", f"id:{_site_id(IN_RG, 'web-in')}/slots/qa"),
        ("function_app", "func-out", "rg:rg-out"),
        ("web_app", "web-east", "location:regioneast"),
        ("web_app", "web-id", f"id:{_site_id(IN_RG, 'web-id')}"),
        ("web_app", "web-out", "rg:rg-out"),
    ]
    assert results["excluded"][0] == {"kind": "web_app", "name": "web-east", "pattern": "location:regioneast",
                                      "reason": "resource_matched", "id": _site_id(IN_RG, "web-east"),
                                      "resource_group": "rg-in", "location": "regioneast"}
    assert [summary[k] for k in DEPLOY_BOUNDARY] == [3, 1, 1, 1]
    # Out of the boundary by pattern, versus in scope but not a web app.
    assert (summary["total_web_apps"], summary["excluded_function_apps"]) == (1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_deployments_leave_out_an_excluded_apps_slots_and_activity_log_events(monkeypatch, tmp_path):
    code, evidence, reads, _ = run_deployments(monkeypatch, tmp_path, DEPLOY_SCOPE)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    # Only web-in/stage is compared with production; the excluded qa slot and every excluded app's slots are not.
    assert (summary["total_deployment_slots"], summary["slots_matching_production"], summary["apps_with_slots"]) == (
        1, 1, 1)
    assert not {"web-in/qa", "web-out/stage", "web-east/stage", "web-id/stage"} & reads
    # The swap on web-in/stage stays; events on excluded apps, slots and sites leave every count.
    assert (summary["slot_swaps"], summary["publish_profile_downloads"], summary["package_deployments"]) == (1, 0, 0)
    assert summary["deployment_activity_by_caller_type"] == {"user": 1}
    # deleted-in and func-in are unlisted but in scope; deleted-out matches rg:rg-out by its id alone.
    assert summary["deployment_activity_on_unlisted_sites"] == 2
    assert results["activity_log"]["requests_on_excluded_sites"] == {
        "slot_swaps": 2, "publish_profile_downloads": 3, "publishing_credential_reads": 0, "package_deployments": 1}
    assert results["web_apps"][0]["slots"][0]["activity"]["slot_swaps"]["count"] == 1


@pytest.mark.parametrize("patterns", ["rg-out", "region:regioneast", "rg:rg-out, scope:x"])
def test_deployments_bare_or_unknown_pattern_fails_the_run_as_bad_config(monkeypatch, tmp_path, patterns):
    code, evidence, _, failures = run_deployments(monkeypatch, tmp_path, patterns)
    assert code == 1 and failures == ["bad_config"]
    assert [f["operation"] for f in evidence["metadata"]["api_failures"]] == [f"config {ENV}"]
