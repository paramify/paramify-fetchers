"""Classification logic of the private endpoint and private DNS zone fetchers.

No Azure SDK, credentials or network: these are the pure functions that decide
what the evidence claims. Each row is a configuration whose verdict would be
false evidence if it regressed: a correctly configured Key Vault or AKS record
read as ip_mismatch, a dead IP hidden behind a live one, an unreadable resource
read as deleted, a staging slot judged by its parent site.

Run: ``pytest tests/test_azure_private_network_fetchers.py``
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

import azure_common  # noqa: E402


def _load(short_name: str):
    spec = importlib.util.spec_from_file_location(
        f"azure_{short_name}_under_test", AZURE / short_name / "fetcher.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dns = _load("private_dns_zone_configuration")
pe = _load("private_endpoint_configuration")

SUB = "11111111-1111-1111-1111-111111111111"
OTHER_SUB = "22222222-2222-2222-2222-222222222222"
RG = f"/subscriptions/{SUB}/resourceGroups/net"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/hub"
NIC_CONFIG = f"{RG}/providers/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1"
VNETS = dns.vnet_index([{
    "id": VNET, "address_prefixes": ["10.0.0.0/16"],
    "subnets": [{"properties": {"addressPrefix": "10.0.0.0/16", "ipConfigurations": [{"id": NIC_CONFIG}]}}],
}])
DNS_SCOPES = {"subscriptions": {SUB}, "resource_groups": {f"/subscriptions/{SUB}/resourcegroups/net"}}
APPROVED = {"pe-1": True, "pe-2": True}


def _classify(record, zone, endpoints, vnets, approvals=APPROVED, others=None, scopes=DNS_SCOPES):
    """classify_record with the lookups collect_zones supplies: approved endpoints, no other IP holders."""
    return dns.classify_record(record, zone, endpoints, vnets, approvals, {} if others is None else others, scopes)


def _record(name: str, zone: str, *ips: str) -> dict:
    return {
        "name": name,
        "record_type": "A",
        "fqdn": f"{name}.{zone}.",
        "ip_addresses": list(ips),
    }


def _endpoints(*entries: tuple) -> dict:
    """(ip, endpoint id, [fqdns]) → the index the NIC query builds."""
    return dns.endpoint_index(
        [{"ip": ip, "private_endpoint_id": pid, "fqdns": fqdns} for ip, pid, fqdns in entries]
    )


# --------------------------------------------------------------------------- #
# Private DNS: record matching
# --------------------------------------------------------------------------- #

# (zone, record name, the FQDNs Azure lists on the endpoint's NIC)
CORRECTLY_CONFIGURED = [
    # Key Vault's zone is not its public suffix: privatelink.vaultcore.azure.net
    # serves <vault>.vault.azure.net.
    ("privatelink.vaultcore.azure.net", "kv-prod", ["kv-prod.vault.azure.net"]),
    # AKS FQDNs keep the privatelink label.
    (
        "privatelink.eastus.azmk8s.io",
        "aks-prod-dns-1a2b3c4d",
        ["aks-prod-dns-1a2b3c4d.privatelink.eastus.azmk8s.io"],
    ),
    ("privatelink.blob.core.windows.net", "acct", ["acct.blob.core.windows.net"]),
    (
        "privatelink.azurewebsites.net",
        "app.scm",
        ["app.azurewebsites.net", "app.scm.azurewebsites.net"],
    ),
    ("privatelink.redis.cache.windows.net", "cache1", ["cache1.redis.cache.windows.net"]),
]


@pytest.mark.parametrize(
    "zone,name,fqdns", CORRECTLY_CONFIGURED, ids=[c[0] for c in CORRECTLY_CONFIGURED]
)
def test_correctly_configured_record_is_backed(zone, name, fqdns):
    record = _classify(
        _record(name, zone, "10.0.1.4"), zone, _endpoints(("10.0.1.4", "pe-1", fqdns)), VNETS
    )
    assert record["private_endpoint_status"] == "backed"
    assert record["private_endpoint_ids"] == ["pe-1"]


def test_ip_held_by_an_endpoint_for_another_name_is_ip_mismatch():
    zone = "privatelink.vaultcore.azure.net"
    record = _classify(
        _record("kv-prod", zone, "10.0.1.4"),
        zone,
        _endpoints(("10.0.1.4", "pe-2", ["kv-other.vault.azure.net"])),
        VNETS,
    )
    assert record["private_endpoint_status"] == "ip_mismatch"


def test_name_prefix_must_end_at_a_label():
    """`acct` must not match an endpoint serving `acct2`."""
    assert not dns.endpoint_serves("acct", "acct.privatelink.blob.core.windows.net.", ["acct2.blob.core.windows.net"])


def test_endpoint_without_fqdns_is_matched_by_ip():
    zone = "privatelink.blob.core.windows.net"
    record = _classify(
        _record("acct", zone, "10.0.1.4"), zone, _endpoints(("10.0.1.4", "pe-1", [])), VNETS
    )
    assert record["private_endpoint_status"] == "backed"


@pytest.mark.parametrize(
    "ip,endpoints,vnets,expected",
    [
        ("10.0.9.9", {}, VNETS, "stale"),  # inside a readable VNet, nothing holds it
        ("172.16.0.4", {}, VNETS, "unverified"),  # outside every readable VNet
        ("10.0.9.9", None, VNETS, "unknown"),  # endpoint query failed: never stale
        ("10.0.9.9", {}, None, "unknown"),  # VNet query failed: never stale
    ],
    ids=["stale", "unverified", "endpoints-failed", "vnets-failed"],
)
def test_unheld_ip(ip, endpoints, vnets, expected):
    zone = "privatelink.blob.core.windows.net"
    record = _classify(_record("acct", zone, ip), zone, endpoints, vnets)  # noqa: E501
    assert record["private_endpoint_status"] == expected


def test_dead_ip_next_to_live_one_is_not_hidden():
    zone = "privatelink.blob.core.windows.net"
    record = _classify(
        _record("acct", zone, "10.0.1.4", "10.0.9.9"),
        zone,
        _endpoints(("10.0.1.4", "pe-1", ["acct.blob.core.windows.net"])),
        VNETS,
    )
    assert record["private_endpoint_status"] == "partially_backed"
    assert record["ip_address_statuses"] == {"10.0.1.4": "backed", "10.0.9.9": "stale"}


def test_record_status_prefers_the_most_serious():
    assert dns.record_status(["unverified", "stale"]) == "stale"
    assert dns.record_status(["stale", "ip_mismatch"]) == "ip_mismatch"
    assert dns.record_status([]) == "no_addresses"  # an A record with no IPs: nothing failed


@pytest.mark.parametrize(
    "zone,record",
    [
        ("contoso.internal", _record("web", "contoso.internal", "10.0.1.4")),
        ("privatelink.blob.core.windows.net", {**_record("@", "x", "10.0.1.4"), "name": "@"}),
        (
            "privatelink.blob.core.windows.net",
            {**_record("acct", "x", "10.0.1.4"), "record_type": "CNAME"},
        ),
    ],
    ids=["custom-zone", "apex", "not-an-A-record"],
)
def test_out_of_scope_records_are_not_classified(zone, record):
    assert dns.classify_record(record, zone, {}, VNETS)["private_endpoint_status"] is None


def test_duplicates_span_subscriptions():
    zone_here = f"{RG}/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
    zone_there = (
        f"/subscriptions/{OTHER_SUB}/resourceGroups/spoke/providers/Microsoft.Network/"
        "privateDnsZones/privatelink.blob.core.windows.net"
    )
    spoke_vnet = f"/subscriptions/{OTHER_SUB}/resourceGroups/spoke/providers/Microsoft.Network/virtualNetworks/spoke"
    local = [{"id": zone_here, "name": "privatelink.blob.core.windows.net", "virtual_network_links": []}]
    all_zones = [
        {"id": zone_here, "name": "privatelink.blob.core.windows.net"},
        {"id": zone_there, "name": "privatelink.blob.core.windows.net"},
        {"id": "unrelated", "name": "privatelink.file.core.windows.net"},
    ]
    all_links = [
        {"zone_id": zone_here.lower(), "virtual_network_id": VNET},
        {"zone_id": zone_there.lower(), "virtual_network_id": spoke_vnet},
    ]
    [dup] = dns.duplicate_zone_names(local, all_zones, all_links)
    assert dup["zone_ids"] == sorted([zone_here, zone_there])
    assert dup["virtual_network_ids"] == sorted([VNET, spoke_vnet])


# --------------------------------------------------------------------------- #
# Shared: found / not_found / not_visible / unknown
# --------------------------------------------------------------------------- #

SCOPES = {
    "subscriptions": {SUB, OTHER_SUB},
    "resource_groups": {f"/subscriptions/{SUB}/resourcegroups/net"},
}


@pytest.mark.parametrize(
    "resource_id,found,lookup_ok,scopes,expected",
    [
        (VNET, True, True, SCOPES, "found"),
        (VNET, False, True, SCOPES, "not_found"),
        (VNET, False, False, SCOPES, "unknown"),
        (VNET, False, True, None, "unknown"),
        # Readable subscription, unreadable resource group: Reader on one group only.
        (f"/subscriptions/{SUB}/resourceGroups/app/providers/X/y/z", False, True, SCOPES, "not_visible"),
        (
            "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/net/providers/X/y/z",
            False,
            True,
            SCOPES,
            "not_visible",
        ),
    ],
    ids=["found", "deleted", "lookup-failed", "scopes-failed", "rg-unreadable", "sub-unreadable"],
)
def test_lookup_status(resource_id, found, lookup_ok, scopes, expected):
    assert azure_common.lookup_status(resource_id, found, lookup_ok, scopes) == expected


# --------------------------------------------------------------------------- #
# Private endpoints
# --------------------------------------------------------------------------- #

SITE = f"/subscriptions/{SUB}/resourceGroups/app/providers/Microsoft.Web/Sites/web1"


@pytest.mark.parametrize(
    "target,groups,expected",
    [
        (SITE, ["sites-Staging"], f"{SITE}/slots/Staging"),
        (SITE, ["sites"], SITE),
        (
            f"/subscriptions/{SUB}/resourceGroups/st/providers/Microsoft.Storage/storageAccounts/acct",
            ["blob"],
            f"/subscriptions/{SUB}/resourceGroups/st/providers/Microsoft.Storage/storageAccounts/acct",
        ),
    ],
    ids=["slot", "site", "storage"],
)
def test_slot_is_checked_on_the_slot(target, groups, expected):
    assert pe.checked_resource_id(target, groups) == expected


@pytest.mark.parametrize(
    "row,expected",
    [
        ({"public_network_access": "Disabled"}, "disabled"),
        ({"public_network_access": "Enabled"}, "enabled"),
        ({"public_network_access": None}, "unset"),
        (None, "not_visible"),
    ],
    ids=["disabled", "enabled", "unset-is-not-enabled-or-disabled", "unread"],
)
def test_public_access_state(row, expected):
    assert pe.public_access_state(row, "not_visible") == expected


@pytest.mark.parametrize(
    "policies,nsg,applies,enforced",
    [
        ("Disabled", "nsg-1", False, False),  # attached but not applied: Azure's default
        ("Enabled", "nsg-1", True, True),
        ("NetworkSecurityGroupEnabled", "nsg-1", True, True),
        ("RouteTableEnabled", "nsg-1", False, False),
        ("Enabled", None, True, False),  # policy on, nothing attached
        (None, "nsg-1", False, False),  # unread policy never reads as enforced
    ],
)
def test_subnet_nsg_enforcement(policies, nsg, applies, enforced):
    subnet = f"{VNET}/subnets/pe"
    rows = {subnet.lower(): {"policies": policies, "nsg_id": nsg, "route_table_id": None}}
    record = pe.subnet_record(subnet, rows, set(), SCOPES)
    assert record["subnet_nsg_applies_to_endpoint"] is applies
    assert record["endpoint_nsg_enforced"] is enforced


# --------------------------------------------------------------------------- #
# PR #118 review fixes
# --------------------------------------------------------------------------- #

import private_dns  # noqa: E402  (on sys.path once a fetcher is loaded)
import resource_graph  # noqa: E402

BLOB = "privatelink.blob.core.windows.net"


def test_mv_expand_is_not_capped_at_128():
    assert "mv-expand limit 2000" in pe.subnet_query(["/x"])
    assert "mv-expand limit 2000" in dns.ENDPOINT_IPS_QUERY


def test_vnet_with_more_subnets_than_returned_is_unknown():
    rows = {f"s{i}": {"vnet_id": "v1", "subnet_count": 3} for i in range(2)}
    rows["s9"] = {"vnet_id": "v2", "subnet_count": 1}
    assert pe.truncated_vnets(rows) == {"v1"}


def test_record_must_match_the_service_suffix():
    # A blob record pointing at the IP of acct's *file* endpoint, or a vault, is ip_mismatch.
    for fqdn in ("acct.file.core.windows.net", "acct.vault.azure.net"):
        record = _classify(_record("acct", BLOB, "10.0.1.4"), BLOB, _endpoints(("10.0.1.4", "pe-1", [fqdn])), VNETS)
        assert record["private_endpoint_status"] == "ip_mismatch", fqdn


def test_stale_needs_every_nic_resource_group_in_the_subnet_readable():
    hidden_nic = f"/subscriptions/{SUB}/resourceGroups/apps/providers/Microsoft.Network/networkInterfaces/n/ipConfigurations/c"
    vnets = dns.vnet_index([{
        "id": VNET, "address_prefixes": ["10.0.0.0/16"],
        "subnets": [{"properties": {"addressPrefix": "10.0.0.0/16", "ipConfigurations": [{"id": hidden_nic}]}}],
    }])
    # Reader on the network RG only: a NIC in "apps" could hold the endpoint, so the record is not stale.
    assert _classify(_record("acct", BLOB, "10.0.9.9"), BLOB, {}, vnets)["private_endpoint_status"] == "unverified"
    readable = {**DNS_SCOPES, "resource_groups": DNS_SCOPES["resource_groups"] | {f"/subscriptions/{SUB}/resourcegroups/apps"}}
    assert _classify(_record("acct", BLOB, "10.0.9.9"), BLOB, {}, vnets, scopes=readable)["private_endpoint_status"] == "stale"
    assert _classify(_record("acct", BLOB, "10.0.9.9"), BLOB, {}, vnets, scopes=None)["private_endpoint_status"] == "unknown"


@pytest.fixture
def fake_graph_models(monkeypatch):
    """query_all's request models, so these tests run where the Azure SDK is not installed (as in CI)."""
    import sys
    from types import ModuleType, SimpleNamespace

    models = ModuleType("azure.mgmt.resourcegraph.models")
    models.QueryRequest = lambda **kw: SimpleNamespace(**kw)
    models.QueryRequestOptions = lambda **kw: SimpleNamespace(**kw)
    monkeypatch.setitem(sys.modules, "azure.mgmt.resourcegraph.models", models)


class _FakeGraph:
    def __init__(self, pages):
        self.pages, self.requests = list(pages), []

    def resources(self, request):
        self.requests.append(request)
        return self.pages.pop(0)


def _page(rows, token=None, total=None):
    from types import SimpleNamespace as NS
    return NS(data=rows, skip_token=token, total_records=total, result_truncated="false")


@pytest.mark.parametrize("scope,sent", [(None, None), ("s1", ["s1"]), (["s1", "s2"], ["s1", "s2"])])
def test_query_all_accepts_unscoped_and_lists(scope, sent, fake_graph_models):
    client = _FakeGraph([_page([{"id": "a"}], token="t", total=2), _page([{"id": "b"}], total=2)])
    assert [r["id"] for r in resource_graph.query_all(client, scope, "q")["rows"]] == ["a", "b"]
    assert client.requests[0].subscriptions == sent


def test_query_all_raises_on_a_short_count(fake_graph_models):
    with pytest.raises(RuntimeError):
        resource_graph.query_all(_FakeGraph([_page([{"id": "a"}], total=5)]), None, "q")


def test_one_pager_only():
    import azure_common
    assert not hasattr(azure_common, "resource_graph_rows")
    for q in (pe.lookup_query(["/x"]), pe.subnet_query(["/x"]), dns.VNETS_QUERY, dns.ENDPOINT_IPS_QUERY,
              dns.ZONES_QUERY, dns.LINKS_QUERY, resource_graph.READABLE_RESOURCE_GROUPS_QUERY):
        assert "order by id" in q, q  # query_all needs a stable order for skip-token paging


def test_secured_by_perimeter_is_private():
    assert pe.public_access_state({"public_network_access": "SecuredByPerimeter"}, "found") == "disabled"


def _pe(zone_groups):
    endpoint = {"id": "pe", "name": "pe", "subnet_id": None, "connections": [], "network_interface_ids": []}
    return pe.endpoint_record(endpoint, zone_groups, {}, set(), {}, set(), None)


def test_unread_zone_groups_are_unknown_not_missing():
    record = _pe(None)
    assert record["has_private_dns_zone_group"] is None
    summary = pe.summarize([record])
    assert summary["endpoints_private_dns_zone_group_unknown"] == 1
    assert summary["endpoints_without_private_dns_zone_group"] == 1  # unknown is never counted as published
    assert _pe([])["has_private_dns_zone_group"] is False


def test_unread_links_and_records_are_unknown():
    zone = {"id": f"{RG}/providers/Microsoft.Network/privateDnsZones/{BLOB}", "name": BLOB}
    record = dns.zone_record(zone, None, None, {}, VNETS, DNS_SCOPES, APPROVED, {})
    summary = dns.summarize([record], [], "target_subscription")
    assert summary["zones_links_unknown"] == 1 and summary["zones_records_unknown"] == 1
    assert summary["zones_without_virtual_network_links"] == 0


def test_record_without_ips_is_no_addresses():
    assert _classify(_record("acct", BLOB), BLOB, {}, VNETS)["private_endpoint_status"] == "no_addresses"


def test_ip_held_by_an_internal_load_balancer_is_platform_managed():
    others = dns.holder_index([], [{"id": "lb", "ip": "10.0.9.9"}])
    record = _classify(_record("api", "abc.privatelink.eastus.azmk8s.io", "10.0.9.9"),
                       "abc.privatelink.eastus.azmk8s.io", {}, VNETS, others=others)
    assert record["private_endpoint_status"] == "platform_managed"
    assert dns.holder_index([], None) is None  # a failed holder query is unknown


def test_disconnected_endpoint_does_not_back_a_record():
    endpoints = _endpoints(("10.0.1.4", "pe-1", ["acct.blob.core.windows.net"]))
    record = _classify(_record("acct", BLOB, "10.0.1.4"), BLOB, endpoints, VNETS, approvals={"pe-1": False})
    assert record["private_endpoint_status"] == "endpoint_not_approved"
    approvals = dns.endpoint_approvals([
        {"id": "PE-1", "auto": [{"properties": {"privateLinkServiceConnectionState": {"status": "Disconnected"}}}]},
        {"id": "pe-2", "manual": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]},
    ])
    assert approvals == {"pe-1": False, "pe-2": True}


def test_kql_ids_are_verbatim_literals():
    assert pe.quoted_ids(["/a'b\\c"]) == "@'/a''b\\c'"


def test_link_projection_is_shared_with_dns_configuration():
    dns_config = _load("dns_configuration")
    assert dns_config.project_vnet_link is private_dns.project_vnet_link


@pytest.mark.parametrize(
    "zone,is_privatelink,suffix",
    [(BLOB, True, "blob.core.windows.net"),
     ("privatelink.vaultcore.azure.net", True, "vault.azure.net"),
     ("abc.privatelink.eastus.azmk8s.io", True, "abc.eastus.azmk8s.io"),
     ("privatelink-global.wvd.microsoft.com", True, "wvd.microsoft.com"),
     ("contoso.internal", False, "contoso.internal")],
)
def test_privatelink_zones_beyond_the_prefix(zone, is_privatelink, suffix):
    assert dns.is_privatelink_zone(zone) is is_privatelink
    assert dns.public_suffix(zone) == suffix
