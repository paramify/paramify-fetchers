"""resource_exclusions in the App Service fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

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

def _plan(rg, name, location, zone_redundant, capacity):
    return ns(id=_plan_id(rg, name), name=name, location=location, kind="app", status="Ready",
              sku=ns(name="P1v3", tier="PremiumV3", size="P1v3", family="Pv3", capacity=capacity),
              zone_redundant=zone_redundant)


def _plan_site(rg, name, location, plan):
    return ns(id=_site_id(rg, name), name=name, location=location, kind="app", state="Running", server_farm_id=plan)


def run_plans(monkeypatch, tmp_path, patterns):
    plans = [_plan(IN_RG, "plan-in", "regionwest", True, 3), _plan(OUT_RG, "plan-out", "regionwest", True, 2),
             _plan(IN_RG, "plan-east", "regioneast", False, 1)]
    plan_in, plan_out, plan_east = (p.id for p in plans)
    sites = [_plan_site(IN_RG, "app-in", "regionwest", plan_in), _plan_site(OUT_RG, "app-out", "regionwest", plan_in),
             _plan_site(IN_RG, "app-cross", "regionwest", plan_out),
             _plan_site(OUT_RG, "app-out2", "regionwest", plan_out),
             _plan_site(IN_RG, "app-east", "regioneast", plan_east)]
    client = ns(app_service_plans=ns(list=lambda detailed: plans), web_apps=ns(list=lambda: sites))
    m = plans_fetcher
    _common(m, monkeypatch, tmp_path, patterns)
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setitem(sys.modules, "azure.mgmt.web", ns(WebSiteManagementClient=lambda **kw: client))
    code = m.main()
    return code, json.loads((tmp_path / "azure_app_service_plans_s1.json").read_text())


def test_plans_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert set(summary) - set(plans_fetcher.summarize(results["app_service_plans"])) == NEW_FIELDS | {
        "provider_registration_status", "excluded_app_service_plans", "excluded_sites",
        "in_scope_app_service_plans", "in_scope_sites"}
    assert summary["total_app_service_plans"] == summary["in_scope_app_service_plans"] == 3
    assert summary["total_sites"] == summary["in_scope_sites"] == 5
    assert summary["excluded_app_service_plans"] == summary["excluded_sites"] == 0
    assert summary["sites_on_zone_redundant_plans"] == 4


def test_plans_exclude_by_group_and_region_but_keep_an_in_scope_site_on_an_excluded_plan(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    [plan] = results["app_service_plans"]
    assert plan["name"] == "plan-in" and [s["name"] for s in plan["sites"]] == ["app-in"]
    assert sorted((e["kind"], e["name"], e["pattern"]) for e in results["excluded"]) == [
        ("app_service_plan", "plan-east", "location:regioneast"),
        ("app_service_plan", "plan-out", "rg:rg-out"),
        ("site", "app-east", "location:regioneast"),
        ("site", "app-out", "rg:rg-out"),
        ("site", "app-out2", "rg:rg-out"),
    ]
    out_plan = next(e for e in results["excluded"] if e["name"] == "plan-out")
    assert [s["name"] for s in out_plan["sites"]] == ["app-cross"]
    assert out_plan["zone_redundant"] is True and out_plan["multi_instance"] is True
    assert (summary["total_app_service_plans"], summary["zone_redundant_plans"], summary["empty_plans"]) == (1, 1, 0)
    assert (summary["total_sites"], summary["in_scope_sites"], summary["excluded_sites"]) == (2, 2, 3)
    assert (summary["sites_on_zone_redundant_plans"], summary["sites_on_multi_instance_plans"]) == (2, 2)
    assert (summary["in_scope_app_service_plans"], summary["excluded_app_service_plans"]) == (1, 2)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_plans_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_plans(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_app_service_plans"] == 3


# --- azure_app_service_backups ---

STORAGE_ID = f"{OUT_RG}/providers/Microsoft.Storage/storageAccounts/stout"
CONTAINER = "https://stout.blob.core.windows.net/backups"


BACKUP_SITES = [("rg-in", "web-in", "regionwest", "app"), ("rg-out", "web-out", "regionwest", "app"),
                ("rg-in", "web-east", "regioneast", "app"), ("rg-in", "func-in", "regionwest", "functionapp"),
                ("rg-out", "func-out", "regionwest", "functionapp")]
# Resource Graph rows carry no region here, so the regioneast slot can only follow its app.
BACKUP_SLOTS = [("rg-in", "web-in"), ("rg-out", "web-out"), ("rg-in", "web-east")]


def _table(values: dict):
    """A per-app read answering only the in-scope apps; any other call fails the run."""
    def fn(*args):
        if args not in values:
            raise AssertionError(f"unexpected call {args}")
        return values[args]
    return fn


def run_backups(monkeypatch, tmp_path, patterns, read=("web-in", "web-out", "web-east")):
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
    assert set(summary) - set(expected) == NEW_FIELDS | {
        "provider_registration_status", "excluded_web_apps", "in_scope_web_apps"}
    assert summary["total_web_apps"] == summary["in_scope_web_apps"] == summary["resource_graph_web_apps"] == 3
    assert summary["excluded_web_apps"] == 0
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
    assert (summary["total_web_apps"], summary["in_scope_web_apps"], summary["excluded_web_apps"]) == (1, 1, 2)
    assert (summary["apps_backed_up"], summary["backup_coverage_percentage"]) == (1, 100)
    assert (summary["excluded_function_apps"], summary["excluded_deployment_slots"]) == (1, 1)
    assert summary["resource_graph_web_apps"] == 1
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_backups_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_backups(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_web_apps"] == 3
