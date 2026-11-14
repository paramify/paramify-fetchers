"""Private endpoint related reads honor the existing native subscription boundary."""

import importlib.util
import json
import logging
import re
import sys
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "fetchers/azure/_shared"))
import resource_graph  # noqa: E402
from azure_common import Collector  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

SUB = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"
RG = f"/subscriptions/{SUB}/resourceGroups/synthetic"
TARGET = f"{RG}/providers/Microsoft.Storage/storageAccounts/account"
FOREIGN = TARGET.replace(SUB, OTHER)
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/net"


def fixture(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "private_endpoint_scope", ROOT / "fetchers/azure/private_endpoint_configuration/fetcher.py"
    )
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    calls = []
    models = []
    for group in ("synthetic", "excluded"):
        models.append(NS(
            id=f"/subscriptions/{SUB}/resourceGroups/{group}/providers/Microsoft.Network/privateEndpoints/pe",
            name="pe", subnet=NS(id=f"{VNET}/subnets/endpoint"),
            private_link_service_connections=[NS(
                name=str(index), private_link_service_id=target, group_ids=["blob"],
                private_link_service_connection_state=NS(status="Approved"),
            ) for index, target in enumerate((TARGET, FOREIGN, "not-an-arm-id"))],
        ))

    def zone_groups(name, group):
        calls.append(("zone-group", group))
        return []

    sdk = ModuleType("azure.mgmt.network")
    sdk.NetworkManagementClient = lambda **kwargs: NS(
        private_endpoints=NS(list_by_subscription=lambda: models),
        private_dns_zone_groups=NS(list=zone_groups),
    )
    monkeypatch.setitem(sys.modules, "azure.mgmt.network", sdk)
    monkeypatch.setattr(native, "resource_graph_client", lambda credential: object())
    discovery = Mock(return_value={"subscriptions": {SUB, OTHER}, "resource_groups": set()})
    monkeypatch.setattr(native, "readable_scopes", discovery)

    def query(client, subscription, text):
        ids = re.findall(r"@'([^']*)'", text)
        calls.append(("graph", subscription, ids))
        rows = [{"id": TARGET, "public_network_access": "Disabled"}] if TARGET.lower() in ids else []
        return {"rows": rows}

    monkeypatch.setattr(resource_graph, "query_all", query)
    return native, calls, discovery


@pytest.mark.parametrize("strict", [False, True])
def test_related_lookups_and_discovery_use_selected_mode(monkeypatch, strict):
    native, calls, discovery = fixture(monkeypatch)
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", str(strict).lower())
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    collector = Collector(logging.getLogger("private-endpoint-scope"))
    excluded = []
    records = native.collect_endpoints(
        SUB, object(), collector, ResourceExclusions(["rg:excluded"]), excluded
    )
    assert collector.ok and len(records) == len(excluded) == 1
    assert ("zone-group", "excluded") not in calls
    queries = [call for call in calls if call[0] == "graph"]
    assert queries and all(call[1] == (SUB if strict else None) for call in queries)
    looked_up = {value for _, _, ids in queries for value in ids}
    assert TARGET.lower() in looked_up
    assert (FOREIGN.lower() in looked_up) is (not strict)
    assert ("not-an-arm-id" in looked_up) is (not strict)
    if strict:
        discovery.assert_not_called()
        foreign = next(row for row in records[0]["connections"] if row["checked_resource_id"] == FOREIGN)
        assert foreign["target_lookup_status"] == "unknown"
        assert foreign["target_public_network_access"] is None
        assert foreign["target_public_network_access_state"] == "unknown"
        assert records[0]["subnet_lookup_status"] == "unknown"
    else:
        discovery.assert_called_once()


@pytest.mark.parametrize("returned_id", [FOREIGN, "not-an-arm-id"])
def test_scoped_lookup_rejects_foreign_or_malformed_response(monkeypatch, returned_id):
    monkeypatch.setattr(resource_graph, "query_all", lambda *args: {"rows": [{"id": returned_id}]})
    collector = Collector(logging.getLogger("private-endpoint-response"))
    rows, failed = resource_graph.lookup_by_ids(
        object(), [TARGET], lambda ids: "synthetic query", "lookup", collector, subscription_id=SUB
    )
    assert not collector.ok
    assert rows == {} and failed == {TARGET.lower()}


@pytest.mark.parametrize("flag, subscription", [("true", None), ("invalid", SUB)])
def test_invalid_scope_stops_before_subscription_discovery_or_credentials(monkeypatch, flag, subscription):
    native, _, _ = fixture(monkeypatch)
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", flag)
    if subscription is None:
        monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    else:
        monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", subscription)
    discover = Mock(side_effect=AssertionError("subscription discovery must not run"))
    credentials = Mock(side_effect=AssertionError("credentials must not be acquired"))
    monkeypatch.setattr(native, "resolve_subscription", discover)
    monkeypatch.setattr(native, "credential", credentials)
    monkeypatch.setattr(native, "load_dotenv", lambda: None)
    with pytest.raises(ValueError, match="AZURE_TARGET_SUBSCRIPTION_ONLY|AZURE_SUBSCRIPTION_ID"):
        native.main()
    discover.assert_not_called()
    credentials.assert_not_called()


@pytest.mark.parametrize("strict", [False, True])
def test_main_records_lookup_scope(monkeypatch, tmp_path, strict):
    native, _, _ = fixture(monkeypatch)
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", str(strict).lower())
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(native, "credential", lambda: object())
    monkeypatch.setattr(native, "provider_registration_status", lambda *args: "registered")
    monkeypatch.setattr(native, "load_dotenv", lambda: None)
    assert native.main() == 0
    payload = json.loads(next(tmp_path.glob("azure_private_endpoint_configuration_*.json")).read_text())
    assert payload["results"]["lookup_scope"] == ("target_subscription_only" if strict else "accessible_subscriptions")
