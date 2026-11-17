"""A monitoring list that could not be read gives null counts and verdicts, never 0 or false."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
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


ala = _load("activity_log_alerts")
ds = _load("diagnostic_settings")
law = _load("log_analytics_workspaces")
rds = _load("resource_diagnostic_settings")
ns = types.SimpleNamespace
RG = "/subscriptions/s1/resourceGroups/rg1"
DENIED = RuntimeError("403 AuthorizationFailed")


def _run(monkeypatch, tmp_path, module, filename):
    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)
    monkeypatch.setattr(module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(module, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(module, "credential", lambda: object())
    monkeypatch.setattr(module, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    code = module.main()
    return code, json.loads((tmp_path / filename).read_text())["summary"]


def _refuse(*a, **k):
    raise DENIED


def _fake_azure(monkeypatch, module_name, **attrs):
    monkeypatch.setitem(sys.modules, module_name, ns(**attrs))


def _not_null(summary, keys):
    return {k: summary[k] for k in keys if summary[k] is not None}


# --- activity_log_alerts ---

def test_unread_alert_list_gives_null_counts_and_coverage_maps(monkeypatch, tmp_path):
    client = ns(activity_log_alerts=ns(list_by_subscription_id=_refuse))
    _fake_azure(monkeypatch, "azure.mgmt.monitor", MonitorManagementClient=lambda **k: client)
    monkeypatch.setattr(ala, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(ala, "collect_action_groups", lambda rest, sub: {"groups": []})
    monkeypatch.setattr(ala, "collect_processing_rules", lambda rest, sub, now: {"rules": []})
    code, summary = _run(monkeypatch, tmp_path, ala, "azure_activity_log_alerts_s1.json")
    assert code == 1
    assert _not_null(summary, ala.ALERT_FIELDS) == {}
    assert summary["in_scope_activity_log_alerts"] is None and summary["excluded_activity_log_alerts"] is None


def test_read_empty_alert_list_still_counts_zero():
    summary = ala.summarize([])
    assert summary["total_activity_log_alerts"] == 0 and summary["all_monitored_operations_covered"] is False
    assert summary["service_health_alert_configured"] is False
    assert summary["monitored_operation_coverage"]["create_update_network_security_group"] is False


def test_no_subscription_reads_no_alert_list(monkeypatch, tmp_path):
    monkeypatch.setattr(ala, "resolve_subscription", lambda c: {"subscription_id": None, "subscription_source": None})
    monkeypatch.setattr(ala, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(ala, "credential", lambda: object())
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    ala.main()
    summary = json.loads((tmp_path / "azure_activity_log_alerts_unknown.json").read_text())["summary"]
    assert summary["total_activity_log_alerts"] is None and summary["all_monitored_operations_covered"] is None


# --- diagnostic_settings ---

def test_unread_setting_list_gives_null_export_verdict_and_counts(monkeypatch, tmp_path):
    client = ns(diagnostic_settings=ns(list=_refuse))
    _fake_azure(monkeypatch, "azure.mgmt.monitor", MonitorManagementClient=lambda **k: client)
    code, summary = _run(monkeypatch, tmp_path, ds, "azure_diagnostic_settings_s1.json")
    assert code == 1
    assert summary["activity_log_exported"] is None
    assert _not_null(summary, ds.SETTING_FIELDS) == {}
    assert summary["required_log_categories"] == list(ds.REQUIRED_LOG_CATEGORIES)


def test_read_empty_setting_list_is_exported_false(monkeypatch, tmp_path):
    client = ns(diagnostic_settings=ns(list=lambda resource_uri: []))
    _fake_azure(monkeypatch, "azure.mgmt.monitor", MonitorManagementClient=lambda **k: client)
    code, summary = _run(monkeypatch, tmp_path, ds, "azure_diagnostic_settings_s1.json")
    assert code == 0
    assert summary["activity_log_exported"] is False and summary["total_diagnostic_settings"] == 0


# --- resource_diagnostic_settings ---

def test_unread_inventory_gives_null_counts_and_scope_counts(monkeypatch, tmp_path):
    monkeypatch.setattr(rds, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(rds, "query_all", _refuse)  # the Resource Graph query is refused
    monkeypatch.setattr(rds, "monitor_client", lambda *a: object())
    monkeypatch.setattr(rds, "AzureRestClient", lambda cred: object())
    code, summary = _run(monkeypatch, tmp_path, rds, "azure_resource_diagnostic_settings_s1.json")
    assert code == 1
    assert _not_null(summary, rds.RESOURCE_FIELDS + rds.INGESTION_FIELDS) == {}
    for key in ("in_scope_resources", "excluded_resources", "log_analytics_destinations",
                "resource_exclusion_patterns_unmatched", "resource_graph_total_records"):
        assert summary[key] is None, key


def test_read_empty_inventory_still_counts_zero(monkeypatch, tmp_path):
    monkeypatch.setattr(rds, "enumerate_resources", lambda *a: {"rows": [], "total_records": 0, "pages": 1, "read": True})
    monkeypatch.setattr(rds, "monitor_client", lambda *a: object())
    monkeypatch.setattr(rds, "AzureRestClient", lambda cred: object())
    code, summary = _run(monkeypatch, tmp_path, rds, "azure_resource_diagnostic_settings_s1.json")
    assert code == 0
    assert (summary["resources_evaluated"], summary["in_scope_resources"], summary["excluded_resources"]) == (0, 0, 0)
    assert summary["resources_emitting_logs_without_setting"] == 0


# --- log_analytics_workspaces ---

def _workspace_client(workspaces, packs=(), tables=(), exports=()):
    def reads(rows):
        def read(rg, name):
            if callable(rows):
                return rows()
            return list(rows)
        return read

    return ns(
        workspaces=ns(list=workspaces),
        tables=ns(list_by_workspace=reads(tables)),
        data_exports=ns(list_by_workspace=reads(exports)),
        intelligence_packs=ns(list=reads(packs)),
    )


def _workspaces():
    return [ns(id=f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-{i}", name=f"law-{i}",
               location="regioneast", retention_in_days=30) for i in (1, 2)]


def _run_law(monkeypatch, tmp_path, client):
    _fake_azure(monkeypatch, "azure.mgmt.loganalytics", LogAnalyticsManagementClient=lambda **k: client)
    return _run(monkeypatch, tmp_path, law, "azure_log_analytics_workspaces_s1.json")


def test_unread_workspace_list_gives_null_counts_and_scope_counts(monkeypatch, tmp_path):
    code, summary = _run_law(monkeypatch, tmp_path, _workspace_client(_refuse))
    assert code == 1
    assert _not_null(summary, law.WORKSPACE_FIELDS) == {}
    assert summary["in_scope_workspaces"] is None and summary["excluded_workspaces"] is None


def test_sentinel_onboarded_is_null_when_no_workspace_solutions_could_be_read(monkeypatch, tmp_path):
    code, summary = _run_law(monkeypatch, tmp_path, _workspace_client(_workspaces, packs=_refuse))
    assert code == 1
    assert summary["sentinel_onboarded"] is None and summary["sentinel_onboarded_workspaces"] is None
    assert summary["total_workspaces"] == 2  # the workspace list itself was read


def test_unread_sub_lists_null_only_the_counts_built_from_them(monkeypatch, tmp_path):
    client = _workspace_client(_workspaces, packs=[ns(name="SecurityInsights", enabled=True)],
                               tables=_refuse, exports=_refuse)
    code, summary = _run_law(monkeypatch, tmp_path, client)
    assert code == 1
    assert summary["total_tables"] is None and summary["min_table_total_retention_in_days"] is None
    assert summary["total_data_exports"] is None and summary["workspaces_with_data_exports"] is None
    assert summary["sentinel_onboarded"] is True and summary["sentinel_onboarded_workspaces"] == 2


@pytest.mark.parametrize("packs, expected", [
    ([ns(name="SecurityInsights", enabled=True)], True),
    ([ns(name="SecurityInsights", enabled=False)], False),
    ([], False),
])
def test_read_solutions_keep_sentinel_onboarded_true_or_false(monkeypatch, tmp_path, packs, expected):
    code, summary = _run_law(monkeypatch, tmp_path, _workspace_client(_workspaces, packs=packs))
    assert code == 0 and summary["sentinel_onboarded"] is expected


def test_unread_processing_rule_list_leaves_suppression_unknown(monkeypatch, tmp_path):
    group_id = f"{RG}/providers/microsoft.insights/actionGroups/ag"
    alert = ala.alert_record({
        "id": f"{RG}/providers/microsoft.insights/activityLogAlerts/a1", "name": "a1", "location": "global",
        "enabled": True, "scopes": ["/subscriptions/s1"], "action_groups": [group_id],
        "condition": {"all_of": [{"field": "operationName", "equals": "Microsoft.Network/networkSecurityGroups/write"}]},
    })
    group = {"id": group_id, "enabled": True, "deliverable": True, "notifies_people": True, "receivers": []}
    monkeypatch.setattr(ala, "collect_activity_log_alerts", lambda sub, cred, collector: [dict(alert)])
    monkeypatch.setattr(ala, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(ala, "collect_action_groups", lambda rest, sub: {"groups": [group]})
    monkeypatch.setattr(ala, "collect_processing_rules", _refuse)
    code, summary = _run(monkeypatch, tmp_path, ala, "azure_activity_log_alerts_s1.json")
    evidence = json.loads((tmp_path / "azure_activity_log_alerts_s1.json").read_text())
    (record,) = evidence["results"]["activity_log_alerts"]
    assert code == 1
    assert record["suppressed"] is None and record["reaches_human"] is None
    assert _not_null(summary, ala.SUPPRESSION_FIELDS) == {}
    # what the alert list and the action groups settle is still read
    assert summary["total_activity_log_alerts"] == 1 and summary["alerts_routing_to_enabled_receiver"] == 1
    assert summary["monitored_operations_covered"] == 1


def test_unread_processing_rule_list_leaves_an_alert_without_an_own_group_unknown(monkeypatch, tmp_path):
    alert = ala.alert_record({
        "id": f"{RG}/providers/microsoft.insights/activityLogAlerts/a1", "name": "a1", "location": "global",
        "enabled": True, "scopes": ["/subscriptions/s1"], "action_groups": [],
        "condition": {"all_of": [{"field": "operationName", "equals": "Microsoft.Network/networkSecurityGroups/write"}]},
    })
    monkeypatch.setattr(ala, "collect_activity_log_alerts", lambda sub, cred, collector: [dict(alert)])
    monkeypatch.setattr(ala, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(ala, "collect_action_groups", lambda rest, sub: {"groups": []})
    monkeypatch.setattr(ala, "collect_processing_rules", _refuse)
    code, summary = _run(monkeypatch, tmp_path, ala, "azure_activity_log_alerts_s1.json")
    evidence = json.loads((tmp_path / "azure_activity_log_alerts_s1.json").read_text())
    (record,) = evidence["results"]["activity_log_alerts"]
    assert code == 1
    assert record["routes_to_enabled_receiver"] is None and record["reaches_human"] is None
    assert summary["alerts_routing_unknown"] == 1 and summary["alerts_reaching_human_unknown"] == 1
    assert summary["alerts_routing_to_enabled_receiver"] == 0


def test_unread_alert_list_keeps_the_fixed_totals():
    summary = ala.summarize(None)
    assert (summary["monitored_operations_total"], summary["change_operations_total"]) == (12, 4)


def test_read_empty_workspace_list_counts_zero_and_sentinel_false(monkeypatch, tmp_path):
    code, summary = _run_law(monkeypatch, tmp_path, _workspace_client(lambda: []))
    assert code == 0
    assert summary["total_workspaces"] == 0 and summary["in_scope_workspaces"] == 0
    assert summary["sentinel_onboarded"] is False and summary["total_tables"] == 0
