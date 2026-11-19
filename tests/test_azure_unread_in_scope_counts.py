"""In-scope counts read null when the list they count wasn't read, and 0 when it was read and is empty. Synthetic
collect results, no SDK or network."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

from resource_exclusions import ENV  # noqa: E402

NAMES = ("alert_rules", "app_service_backups", "app_service_configuration", "app_service_deployments",
         "app_service_plans", "dns_configuration", "front_door_tls", "front_door_waf_coverage", "front_door_origins",
         "key_vault_key_rotation", "log_analytics_workspaces", "policy_compliance",
         "sql_managed_instance_configuration", "vnet_egress_routing")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_in_scope_counts_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = {name: _load(name) for name in NAMES}


def _refuse(*args, **kwargs):
    raise PermissionError("(AuthorizationFailed) 403")


def _run(m, monkeypatch, tmp_path, sign_in=True, **fakes):
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    for name in ("credential", "pinned_credential"):
        if hasattr(m, name):
            monkeypatch.setattr(m, name, (lambda *a: object()) if sign_in else _refuse)
    if hasattr(m, "provider_registration_status"):
        monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    for name, fake in fakes.items():
        monkeypatch.setattr(m, name, fake)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv(ENV, raising=False)
    code = m.main()
    [path] = tmp_path.glob("azure_*.json")
    summary = json.loads(path.read_text())["summary"]
    return code, {k: v for k, v in summary.items() if k.startswith("in_scope_") and k != "in_scope_states_status"}


def _failing(operation, result):
    def collect(subscription_id, cred, collector, *args, **kwargs):
        collector.record(operation, PermissionError("(AuthorizationFailed) 403"))
        return result
    return collect


def _returning(result):
    return lambda *args, **kwargs: result


@pytest.mark.parametrize("name", NAMES)
def test_every_in_scope_count_is_null_when_sign_in_fails(name, monkeypatch, tmp_path):
    code, counts = _run(M[name], monkeypatch, tmp_path, sign_in=False)
    assert code == 1 and counts
    assert set(counts.values()) == {None}, counts


# --- one list refused, or every list read and empty ---

def _backups_result(apps):
    m = M["app_service_backups"]
    exclusions = {"function_apps": m.exclusion(None, m.FUNCTION_APP_REASON),
                  "deployment_slots": m.exclusion(None, m.SLOT_REASON)}
    return apps, None, exclusions, []


def _no_activity(*args):
    return [], {"days": 7, "complete": True, "cut_reason": None}


EMPTY_EGRESS = (([], {}, [], [], [], [], []), None)
WAF = {"collect_waf_policies": _returning(([], {}))}
CASES = {
    "sql_managed_instance_configuration": (
        {"collect": _failing("sql.managed_instances.list", (None, None))},
        {"collect": _returning(([], None))}),
    "log_analytics_workspaces": (
        {"collect_workspaces": _failing("loganalytics.workspaces.list", None)},
        {"collect_workspaces": _returning([])}),
    "app_service_configuration": (
        {"collect_web_apps": _failing("web.web_apps.list", None)},
        {"collect_web_apps": _returning([])}),
    "app_service_deployments": (
        {"collect_web_apps": _failing("web.web_apps.list", (None, 0)), "read_activity_log": _no_activity},
        {"collect_web_apps": _returning(([], 0)), "read_activity_log": _no_activity}),
    "app_service_plans": (
        {"collect_plans": _failing("web.app_service_plans.list", (None, []))},
        {"collect_plans": _returning(([], []))}),
    "app_service_backups": (
        {"collect": _failing("web.web_apps.list", _backups_result(None))},
        {"collect": _returning(_backups_result([]))}),
    "dns_configuration": (
        {"collect_public_zones": _failing("dns.zones.list", None), "collect_private_zones": _returning([])},
        {"collect_public_zones": _returning([]), "collect_private_zones": _returning([])}),
    "front_door_tls": (
        {"collect_profiles": _failing("cdn.profiles.list", (None, {}))},
        {"collect_profiles": _returning(([], {}))}),
    "front_door_waf_coverage": (
        {"collect_profiles": _failing("cdn.profiles.list", (None, {})), **WAF},
        {"collect_profiles": _returning(([], {})), **WAF}),
    "key_vault_key_rotation": (
        {"collect_key_vaults": _failing("keyvault.vaults.list_by_subscription", []),
         "collect_app_service_certificates": _returning([])},
        {"collect_key_vaults": _returning([]), "collect_app_service_certificates": _returning([])}),
    "policy_compliance": (
        {"collect_compliance": _failing("policyinsights.policy_states.summarize_for_subscription",
                                        {**M["policy_compliance"].empty_collection(), "deployments_complete": True})},
        {"collect_compliance": _returning({**M["policy_compliance"].empty_collection(), "deployments_complete": True})}),
}
# The counts left null when the case's one list is refused; the others stay 0.
REFUSED = {
    "sql_managed_instance_configuration": {"in_scope_managed_instances"},
    "log_analytics_workspaces": {"in_scope_workspaces"},
    "app_service_configuration": {"in_scope_web_apps"},
    "app_service_deployments": {"in_scope_web_apps"},
    "app_service_plans": {"in_scope_app_service_plans"},
    "app_service_backups": {"in_scope_web_apps"},
    "dns_configuration": {"in_scope_public_dns_zones", "in_scope_record_sets"},
    "front_door_tls": {"in_scope_profiles", "in_scope_hosts", "in_scope_custom_domains", "in_scope_endpoints",
                       "in_scope_routes", "in_scope_secrets"},
    "front_door_waf_coverage": {"in_scope_profiles", "in_scope_hosts", "in_scope_custom_domains",
                                "in_scope_endpoints", "in_scope_routes", "in_scope_host_routes"},
    "key_vault_key_rotation": {"in_scope_key_vaults", "in_scope_keys", "in_scope_secrets", "in_scope_certificates"},
    "policy_compliance": {"in_scope_policy_assignments"},
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_refused_list_nulls_only_the_counts_over_it(name, monkeypatch, tmp_path):
    code, counts = _run(M[name], monkeypatch, tmp_path, **CASES[name][0])
    assert code == 1
    assert {k for k, v in counts.items() if v is None} == REFUSED[name], counts
    assert all(v == 0 for k, v in counts.items() if k not in REFUSED[name]), counts


@pytest.mark.parametrize("name", sorted(CASES))
def test_lists_read_and_empty_give_zero(name, monkeypatch, tmp_path):
    code, counts = _run(M[name], monkeypatch, tmp_path, **CASES[name][1])
    assert code == 0 and counts and set(counts.values()) == {0}, counts


def test_policy_compliance_counts_are_zero_when_the_provider_is_not_registered(monkeypatch, tmp_path):
    m = M["policy_compliance"]
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "not_registered")
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv(ENV, raising=False)
    assert m.main() == 0
    [path] = tmp_path.glob("azure_*.json")
    summary = json.loads(path.read_text())["summary"]
    assert {v for k, v in summary.items() if k.startswith("in_scope_") and k != "in_scope_states_status"} == {0}


def test_dns_record_sets_are_null_while_one_zones_record_sets_are_unread(monkeypatch, tmp_path):
    zone = {"id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.com",
            "name": "example.com", "record_sets": None}
    m = M["dns_configuration"]
    _, counts = _run(m, monkeypatch, tmp_path, collect_public_zones=_failing("dns.record_sets.list_all_by_dns_zone", [zone]),
                     collect_private_zones=_returning([]), summarize=lambda *a: {})
    assert (counts["in_scope_public_dns_zones"], counts["in_scope_record_sets"]) == (1, None)


ALERT_FAKES = {"arm_rest_client": lambda cred: object(), "collect_action_groups": _returning({"groups": []}),
               "collect_processing_rules": _returning({"rules": []}), "add_referenced_groups": lambda *a: None}


def test_alert_rules_null_only_the_list_that_was_refused(monkeypatch, tmp_path):
    m = M["alert_rules"]
    code, counts = _run(m, monkeypatch, tmp_path, list_all=_refuse, **ALERT_FAKES)
    assert code == 1
    assert counts == {"in_scope_alert_rules": None, "in_scope_action_groups": 0, "in_scope_processing_rules": 0}
    code, counts = _run(m, monkeypatch, tmp_path / "groups", list_all=_returning({"items": [], "pages": 1}),
                        **{**ALERT_FAKES, "collect_action_groups": _refuse})
    assert counts == {"in_scope_alert_rules": 0, "in_scope_action_groups": None, "in_scope_processing_rules": 0}
    _, counts = _run(m, monkeypatch, tmp_path / "empty", list_all=_returning({"items": [], "pages": 1}), **ALERT_FAKES)
    assert set(counts.values()) == {0}


def test_vnet_egress_routing_nulls_only_the_list_that_was_refused(monkeypatch, tmp_path):
    m = M["vnet_egress_routing"]
    search = m.new_hub_search()
    code, counts = _run(m, monkeypatch, tmp_path,
                        collect=_failing("network.route_tables.list_all", (EMPTY_EGRESS[0], search)))
    assert code == 1
    assert {k for k, v in counts.items() if v is None} == {"in_scope_route_tables"}, counts
    code, counts = _run(m, monkeypatch, tmp_path / "empty", collect=_returning((EMPTY_EGRESS[0], search)))
    assert code == 0 and set(counts.values()) == {0}, counts


def test_scope_exclusions_null_the_excluded_count_and_unmatched_patterns_of_an_unread_list():
    from scope_exclusions import ScopeExclusions

    read = ScopeExclusions(["typo.example.com"]).summary([], ("route",), {"routes": 0})
    assert (read["excluded_routes"], read["in_scope_routes"], read["scope_exclusion_patterns_unmatched"]) == (
        0, 0, ["typo.example.com"])
    unread = ScopeExclusions(["typo.example.com"]).summary([], ("route",), {"routes": None})
    assert (unread["excluded_routes"], unread["in_scope_routes"], unread["scope_exclusion_patterns_unmatched"]) == (
        None, None, None)
