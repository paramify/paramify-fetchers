"""Existing native opt-in scopes retain foreign relationships without reading them."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, MagicMock
import hashlib
import json
import logging
import sys

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "fetchers/azure/_shared"))
sys.path.insert(0, str(ROOT / "tests"))
from azure_common import Collector

SUB = "00000000-0000-0000-0000-000000000001"
OTHER = "00000000-0000-0000-0000-000000000002"
BASE = f"/subscriptions/{SUB}/resourceGroups/synthetic/providers/"
FOREIGN = f"/subscriptions/{OTHER}/resourceGroups/synthetic/providers/"


def load(name):
    spec = spec_from_file_location(
        "bounded_" + name, ROOT / "fetchers/azure" / name / "fetcher.py"
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def strict(monkeypatch, sub=SUB):
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", sub)


def test_vnet_does_not_enumerate_other_subscriptions_when_spoke_is_unresolved(
    monkeypatch,
):
    pytest.importorskip("azure.mgmt.network")
    strict(monkeypatch)
    native = load("vnet_egress_routing")
    sdk = MagicMock()
    monkeypatch.setattr(
        "azure.mgmt.network.NetworkManagementClient", Mock(return_value=sdk)
    )
    monkeypatch.setattr(
        native, "unresolved_spokes", lambda *args: {"unresolved": "spoke"}
    )
    enumerate_subscriptions = Mock(
        side_effect=AssertionError("foreign subscription enumeration")
    )
    monkeypatch.setattr(native, "enabled_subscription_ids", enumerate_subscriptions)
    _, search = native.collect(
        SUB, object(), Collector(logging.getLogger("bounded-vnet"))
    )
    enumerate_subscriptions.assert_not_called()
    assert search["read_scope"] == "target_subscription"
    assert search["cross_subscription_search_skipped"] is True
    assert search["spokes_needing_search"] == 1


def test_waf_retains_foreign_policy_as_unknown_without_fetch(monkeypatch):
    strict(monkeypatch)
    native = load("app_gateway_waf")
    foreign = (
        FOREIGN
        + "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/foreign"
    )
    gateway = NS(
        id=BASE + "Microsoft.Network/applicationGateways/example",
        name="example",
        firewall_policy=NS(id=foreign),
    )
    monkeypatch.setattr(native, "collect_policies", lambda *args: [])
    fetch = Mock(side_effect=AssertionError("foreign policy read"))
    monkeypatch.setattr(native, "fetch_policy", fetch)
    results, _ = native.build(
        [gateway], Collector(logging.getLogger("bounded-waf")), SUB, object()
    )
    fetch.assert_not_called()
    assert results["read_scope"] == "target_subscription"
    assert any(
        row["id"] == foreign and row["read_status"] == "outside_read_scope"
        for row in results["waf_policies"]
    )


def test_private_dns_queries_explicit_target_and_keeps_foreign_link_unknown(
    monkeypatch,
):
    pytest.importorskip("azure.mgmt.privatedns")
    import test_azure_private_network_fetchers as existing

    strict(monkeypatch, existing.SUB)
    scopes = []

    class RecordingPatch:
        def setitem(self, *args, **kwargs):
            return monkeypatch.setitem(*args, **kwargs)

        def setattr(self, obj, name, value, *args, **kwargs):
            if name == "query_all":
                original = value

                def value(graph, scope, query):
                    scopes.append(scope)
                    return original(graph, scope, query)

            if name == "readable_scopes":
                value = Mock(side_effect=AssertionError("unscoped readable scopes"))
            return monkeypatch.setattr(obj, name, value, *args, **kwargs)

    foreign = f"/subscriptions/{existing.OTHER_SUB}/resourceGroups/foreign/providers/Microsoft.Network/virtualNetworks/foreign"
    zones, _, collector = existing._collect(
        RecordingPatch(), {"example.internal": [foreign]}, []
    )
    assert collector.ok and scopes and all(scope == existing.SUB for scope in scopes)
    link = zones["example.internal"]["virtual_network_links"][0]
    assert link["virtual_network_id"] == foreign
    assert link["virtual_network_status"] == "unknown"


def test_private_dns_does_not_create_foreign_zone_group_client(monkeypatch):
    pytest.importorskip("azure.mgmt.network")
    strict(monkeypatch)
    native = load("private_dns_zone_configuration")
    constructor = Mock(side_effect=AssertionError("foreign zone group client"))
    monkeypatch.setattr("azure.mgmt.network.NetworkManagementClient", constructor)
    foreign = FOREIGN + "Microsoft.Network/privateEndpoints/foreign"
    groups, failed = native.collect_zone_groups(
        object(), [foreign], Collector(logging.getLogger("bounded-zone-groups"))
    )
    assert groups == {} and failed == {foreign.lower()}
    constructor.assert_not_called()


@pytest.mark.parametrize("name", ["alert_rules", "activity_log_alerts"])
def test_alert_sources_keep_foreign_group_reference_without_read(
    monkeypatch, tmp_path, name
):
    strict(monkeypatch)
    native = load(name)
    foreign = FOREIGN + "Microsoft.Insights/actionGroups/foreign"
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(native, "credential", lambda: object())
    monkeypatch.setattr(
        native, "provider_registration_status", lambda *args: "registered"
    )
    monkeypatch.setattr(native, "arm_rest_client", lambda *args: object())
    monkeypatch.setattr(native, "collect_action_groups", lambda *args: {"groups": []})
    monkeypatch.setattr(native, "collect_processing_rules", lambda *args: {"rules": []})
    seen = []

    def references(client, ids, by_id, collector):
        seen.extend(ids)

    monkeypatch.setattr(native, "add_referenced_groups", references)
    if name == "alert_rules":
        raw = {
            "id": BASE + "Microsoft.Insights/metricAlerts/example",
            "name": "example",
            "properties": {
                "enabled": True,
                "scopes": [f"/subscriptions/{SUB}"],
                "actions": [{"actionGroupId": foreign}],
            },
        }
        monkeypatch.setattr(
            native,
            "list_all",
            lambda client, path, api: {
                "items": [raw] if path.endswith("/metricAlerts") else [],
                "pages": 1,
            },
        )
    else:
        row = native.project_activity_log_alert(
            NS(
                id=BASE + "Microsoft.Insights/activityLogAlerts/example",
                name="example",
                enabled=True,
                scopes=[f"/subscriptions/{SUB}"],
                condition=NS(all_of=[]),
                actions=NS(action_groups=[NS(action_group_id=foreign)]),
            )
        )
        monkeypatch.setattr(
            native,
            "collect_activity_log_alerts",
            lambda *args: [native.alert_record(row)],
        )
    assert native.main() == 0
    payload = json.loads(next(tmp_path.glob("azure_" + name + "_*.json")).read_text())
    assert payload["results"]["outside_read_scope_action_group_ids"] == [foreign]
    assert payload["results"]["read_scope"] == "target_subscription" and seen == []
    assert foreign in json.dumps(payload["results"])


from test_azure_sentinel_fetchers import azure, SI_A, run, ws_a, ui_connector


@pytest.mark.parametrize(
    "query",
    [
        'workspace("foreign").Heartbeat',
        "CustomParser()",
        'let x = workspace("foreign").Heartbeat; x',
    ],
)
def test_sentinel_service_query_is_retained_unmeasured_and_never_executed(
    monkeypatch, tmp_path, azure, query
):
    from test_azure_sentinel_fetchers import SUB as SENTINEL_SUB

    strict(monkeypatch, SENTINEL_SUB)
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = {
        "value": [ui_connector("unverified", [("Unverified", query)])]
    }
    code, payload = run("sentinel_data_sources", tmp_path)
    assert code == 0 and payload["metadata"]["partial_failure"] is False
    workspace = ws_a(payload)
    connector = next(
        row for row in workspace["connectors"] if row["id"] == "unverified"
    )
    observed = connector["data_types"][0]
    original = (
        query + "\n | summarize Time = max(TimeGenerated)\n | where isnotempty(Time)"
    )
    assert observed["native_last_data_query"] == original
    assert (
        observed["native_last_data_query_sha256"]
        == hashlib.sha256(original.encode()).hexdigest()
    )
    assert observed["query_execution"] == "not_executed_scope_unverified"
    assert observed["last_data_received"] is None and connector["connected"] is None
    assert workspace["connectors_connected"] is None
    assert all(query not in call[2] for call in azure.calls if call[0] == "POST")


def test_resource_diagnostic_settings_reports_strict_scope(monkeypatch, tmp_path):
    strict(monkeypatch)
    native = load("resource_diagnostic_settings")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(
        native,
        "credential",
        Mock(side_effect=RuntimeError("synthetic credential failure")),
    )
    assert native.main() == 1
    payload = json.loads(
        next(tmp_path.glob("azure_resource_diagnostic_settings_*.json")).read_text()
    )
    assert payload["results"]["read_scope"] == "target_subscription"


@pytest.mark.parametrize(
    "name",
    [
        "vnet_egress_routing",
        "app_gateway_waf",
        "alert_rules",
        "activity_log_alerts",
        "private_dns_zone_configuration",
        "resource_diagnostic_settings",
    ],
)
def test_strict_scope_requires_subscription_before_credentials(monkeypatch, name):
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", "true")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    native = load(name)
    credentials = Mock(side_effect=AssertionError("credentials must not be acquired"))
    if hasattr(native, "credential"):
        monkeypatch.setattr(native, "credential", credentials)
    with pytest.raises(ValueError, match="AZURE_SUBSCRIPTION_ID is required"):
        native.main()
    credentials.assert_not_called()
