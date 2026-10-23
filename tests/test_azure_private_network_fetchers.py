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
import re
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
    """classify_record with the lookups collect_zones supplies for a zone linked to VNET: approved
    endpoints, no other IP holders."""
    others = {} if others is None else others
    return dns.classify_record(record, zone, endpoints, vnets, approvals, others, scopes, {VNET.lower()})


def _record(name: str, zone: str, *ips: str) -> dict:
    return {
        "name": name,
        "record_type": "A",
        "fqdn": f"{name}.{zone}.",
        "ip_addresses": list(ips),
    }


def _endpoints(*entries: tuple) -> dict:
    """(ip, endpoint id, [fqdns]) → the index the NIC query builds, each NIC in a subnet of VNET."""
    return dns.endpoint_index(
        [
            {"ip": ip, "private_endpoint_id": pid, "fqdns": fqdns, "subnet_id": f"{VNET}/subnets/pe"}
            for ip, pid, fqdns in entries
        ]
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
    assert "mv-expand s = properties.subnets limit 2000 " in pe.subnet_query(["/x"])
    assert "mv-expand ipc = properties.ipConfigurations limit 2000 " in dns.ENDPOINT_IPS_QUERY


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
    for q in (pe.lookup_query(["/x"]), pe.subnet_query(["/x"]), dns.vnets_query(["/x"]), dns.reverse_peers_query(["/x"]),
              dns.ENDPOINT_IPS_QUERY,
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
    others = dns.holder_index([], [{"id": "lb", "ip": "10.0.9.9", "subnet_id": f"{VNET}/subnets/aks"}])
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


# --------------------------------------------------------------------------- #
# A record's IP is matched only in the networks its zone resolves for
# --------------------------------------------------------------------------- #

SPOKE = f"{RG}/providers/Microsoft.Network/virtualNetworks/spoke"
ELSEWHERE = f"{RG}/providers/Microsoft.Network/virtualNetworks/elsewhere"
UNREADABLE_NIC = f"/subscriptions/{SUB}/resourceGroups/apps/providers/Microsoft.Network/networkInterfaces/n/ipConfigurations/c"


def _vnet_row(vnet_id, prefix, nic_configs=(), peers=()):
    return {
        "id": vnet_id,
        "address_prefixes": [prefix],
        "peerings": [{"properties": {"peeringState": "Connected", "remoteVirtualNetwork": {"id": p}}} for p in peers],
        "subnets": [{"properties": {"addressPrefix": prefix, "ipConfigurations": [{"id": c} for c in nic_configs]}}],
    }


def _endpoint_row(ip, vnet_id, fqdn="acct.blob.core.windows.net"):
    return {"ip": ip, "private_endpoint_id": "pe-1", "fqdns": [fqdn], "subnet_id": f"{vnet_id}/subnets/default"}


def _zone_ip(ip, vnet_rows, linked, endpoint_rows=(), other_rows=()):
    """One privatelink A record run through zone_record, the path collect_zones takes."""
    zone = {"id": f"{RG}/providers/Microsoft.Network/privateDnsZones/{BLOB}", "name": BLOB}
    links = [{"id": f"link-{i}", "virtual_network_id": v} for i, v in enumerate(linked)]
    out = dns.zone_record(
        zone, links, [_record("acct", BLOB, ip)], dns.endpoint_index(list(endpoint_rows)),
        dns.vnet_index(vnet_rows), DNS_SCOPES, APPROVED, dns.holder_index(list(other_rows), []),
    )
    return out["record_sets"][0]


def test_an_ip_held_in_an_unlinked_network_does_not_hide_a_stale_record():
    rows = [_vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG]), _vnet_row(ELSEWHERE, "10.0.0.0/16")]
    vm_nic = [{"id": "vm-nic", "ip": "10.0.0.4", "subnet_id": f"{ELSEWHERE}/subnets/default"}]
    assert _zone_ip("10.0.0.4", rows, [VNET], other_rows=vm_nic)["private_endpoint_status"] == "stale"
    pe_rows = [_endpoint_row("10.0.0.4", ELSEWHERE)]
    assert _zone_ip("10.0.0.4", rows, [VNET], endpoint_rows=pe_rows)["private_endpoint_status"] == "stale"


def test_an_endpoint_in_a_peered_spoke_backs_a_zone_linked_to_the_hub():
    rows = [_vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG], peers=[SPOKE]), _vnet_row(SPOKE, "10.1.0.0/16")]
    record = _zone_ip("10.1.0.4", rows, [VNET], endpoint_rows=[_endpoint_row("10.1.0.4", SPOKE)])
    assert record["private_endpoint_status"] == "backed"
    assert record["ip_address_networks"] == {"10.1.0.4": [SPOKE.lower()]}


@pytest.mark.parametrize(
    "linked",
    [[], [f"/subscriptions/{OTHER_SUB}/resourceGroups/x/providers/Microsoft.Network/virtualNetworks/v"]],
    ids=["no-links", "linked-vnet-unreadable"],
)
def test_a_zone_with_no_readable_network_is_unverified_not_backed(linked):
    rows = [_vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG])]
    record = _zone_ip("10.0.1.4", rows, linked, endpoint_rows=[_endpoint_row("10.0.1.4", VNET)])
    assert record["private_endpoint_status"] == "unverified"


@pytest.mark.parametrize("order", [1, -1], ids=["sorted", "reversed"])
def test_overlapping_address_spaces_do_not_depend_on_sort_order(order):
    # ELSEWHERE overlaps the linked VNet and has a NIC in a resource group the credential cannot read.
    rows = [_vnet_row(ELSEWHERE, "10.0.0.0/16", [UNREADABLE_NIC]), _vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG])]
    assert _zone_ip("10.0.9.9", rows[::order], [VNET])["private_endpoint_status"] == "stale"


def test_an_ip_in_two_linked_networks_that_disagree_is_unverified_and_names_both():
    rows = [_vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG]), _vnet_row(ELSEWHERE, "10.0.0.0/16")]
    record = _zone_ip("10.0.1.4", rows, [VNET, ELSEWHERE], endpoint_rows=[_endpoint_row("10.0.1.4", VNET)])
    assert record["private_endpoint_status"] == "unverified"
    assert record["ip_address_networks"] == {"10.0.1.4": sorted([VNET.lower(), ELSEWHERE.lower()])}


def test_vnets_are_read_by_id_not_tenant_wide():
    query = dns.vnets_query([VNET])
    assert f"id in~ (@'{VNET}')" in query and "peerings" in query and "order by id" in query
    assert not hasattr(dns, "VNETS_QUERY")


def _collect(monkeypatch, zone_links: dict, table_rows, fail_on=None, other_rows=()):
    """collect_zones over a fake SDK and Resource Graph: {zone name: [linked VNet ids]}, one A record
    acct → 10.0.0.4 per zone. A VNet query naming `fail_on` raises, as a throttled chunk would."""
    from types import ModuleType
    from types import SimpleNamespace as NS

    zones = [NS(id=f"{RG}/providers/Microsoft.Network/privateDnsZones/{n}", name=n) for n in zone_links]
    record = NS(name="acct", type="Microsoft.Network/privateDnsZones/A", a_records=[NS(ipv4_address="10.0.0.4")])
    client = NS(
        private_zones=NS(list=lambda: zones),
        virtual_network_links=NS(
            list=lambda rg, name: [NS(id=f"{name}-{v}", name="l", virtual_network=NS(id=v)) for v in zone_links[name]]
        ),
        record_sets=NS(list=lambda rg, name: [record]),
    )
    privatedns = ModuleType("azure.mgmt.privatedns")
    privatedns.PrivateDnsManagementClient = lambda **kw: client
    monkeypatch.setitem(sys.modules, "azure.mgmt.privatedns", privatedns)

    table = {r["id"].lower(): r for r in table_rows}
    vnet_queries = []

    def fake_query_all(graph, scope, query):
        if "remoteVirtualNetwork" in query:  # reverse peering: the read VNets that peer with a listed VNet
            vnet_queries.append(query)
            remotes = lambda r: [p["properties"]["remoteVirtualNetwork"]["id"].lower() for p in r["peerings"]]  # noqa: E731
            return {"rows": [{"id": r["id"]} for r in table.values() if any(f"@'{x}'" in query.lower() for x in remotes(r))]}
        if "virtualnetworks'" in query:
            vnet_queries.append(query)
            if fail_on and f"@'{fail_on.lower()}'" in query.lower():
                raise RuntimeError("throttled")
            return {"rows": [r for i, r in table.items() if f"@'{i}'" in query.lower()]}
        if "isnull(properties.privateEndpoint)" in query:
            return {"rows": list(other_rows)}
        return {"rows": []}

    monkeypatch.setattr(dns, "query_all", fake_query_all)
    monkeypatch.setattr(resource_graph, "query_all", fake_query_all)
    monkeypatch.setattr(dns, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(dns, "readable_scopes", lambda cred, collector: DNS_SCOPES)
    collector = azure_common.Collector(dns.logger)
    out, _, _ = dns.collect_zones(SUB, object(), collector)
    return {z["name"]: z for z in out}, vnet_queries, collector


def test_collect_zones_reads_only_linked_and_peered_vnets(monkeypatch):
    rows = [
        _vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG], peers=[SPOKE]),
        _vnet_row(SPOKE, "10.1.0.0/16"),
        _vnet_row(ELSEWHERE, "10.0.0.0/16"),
    ]
    vm_nic = [{"id": "vm-nic", "ip": "10.0.0.4", "subnet_id": f"{ELSEWHERE}/subnets/default"}]
    zones, vnet_queries, collector = _collect(monkeypatch, {BLOB: [VNET]}, rows, other_rows=vm_nic)

    assert collector.ok
    assert len(vnet_queries) == 2 and "elsewhere" not in " ".join(vnet_queries).lower()
    assert f"@'{SPOKE.lower()}'" in vnet_queries[1]  # every linked VNet was readable: no reverse-peering query
    [rec] = zones[BLOB]["record_sets"]
    assert rec["private_endpoint_status"] == "stale" and rec["ip_address_networks"] == {"10.0.0.4": [VNET.lower()]}


def test_a_failed_peer_chunk_leaves_only_the_zones_that_need_it_unknown(monkeypatch):
    file_zone = "privatelink.file.core.windows.net"
    rows = [
        _vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG], peers=[SPOKE]),
        _vnet_row(SPOKE, "10.1.0.0/16"),
        _vnet_row(ELSEWHERE, "10.0.0.0/16", [NIC_CONFIG]),
    ]
    zones, _, collector = _collect(monkeypatch, {BLOB: [VNET], file_zone: [ELSEWHERE]}, rows, fail_on=SPOKE)

    assert not collector.ok
    [blob] = zones[BLOB]["record_sets"]
    assert blob["private_endpoint_status"] == "unknown" and blob["ip_address_networks"] == {"10.0.0.4": None}
    assert [link["virtual_network_status"] for link in zones[BLOB]["virtual_network_links"]] == ["found"]
    [other] = zones[file_zone]["record_sets"]
    assert other["private_endpoint_status"] == "stale"


def test_vnet_of_splits_at_the_last_subnets_segment():
    vnet = f"/subscriptions/{SUB}/resourceGroups/subnets/providers/Microsoft.Network/virtualNetworks/subnets"
    assert dns.vnet_of(f"{vnet}/subnets/default") == vnet.lower()
    rows = [_vnet_row(vnet, "10.0.0.0/16", [NIC_CONFIG])]
    record = _zone_ip("10.0.1.4", rows, [vnet], endpoint_rows=[_endpoint_row("10.0.1.4", vnet)])
    assert record["private_endpoint_status"] == "backed"  # never stale for a live endpoint


@pytest.mark.parametrize("failed", ["endpoints", "vnets", "others"])
def test_networks_are_null_when_the_lookup_they_need_failed(failed):
    rows = [_vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG])]
    zone = {"id": f"{RG}/providers/Microsoft.Network/privateDnsZones/{BLOB}", "name": BLOB}
    lookups = {
        "endpoints": dns.endpoint_index([]), "vnets": dns.vnet_index(rows), "others": dns.holder_index([], []),
    }
    lookups[failed] = None
    out = dns.zone_record(
        zone, [{"id": "l", "virtual_network_id": VNET}], [_record("acct", BLOB, "172.16.0.4")],
        lookups["endpoints"], lookups["vnets"], DNS_SCOPES, APPROVED, lookups["others"],
    )
    [rec] = out["record_sets"]
    assert rec["private_endpoint_status"] == "unknown" and rec["ip_address_networks"] == {"172.16.0.4": None}


def test_a_visible_endpoint_in_an_unreadable_linked_vnet_backs_the_record():
    unreadable = f"/subscriptions/{OTHER_SUB}/resourceGroups/x/providers/Microsoft.Network/virtualNetworks/v"
    record = _zone_ip("10.9.0.4", [], [unreadable], endpoint_rows=[_endpoint_row("10.9.0.4", unreadable)])
    assert record["private_endpoint_status"] == "backed"


UNREADABLE_HUB = f"/subscriptions/{OTHER_SUB}/resourceGroups/conn/providers/Microsoft.Network/virtualNetworks/hub"


def test_a_readable_spoke_peered_with_an_unreadable_linked_hub_backs_the_record():
    rows = [_vnet_row(SPOKE, "10.1.0.0/16", peers=[UNREADABLE_HUB])]
    record = _zone_ip("10.1.0.4", rows, [UNREADABLE_HUB], endpoint_rows=[_endpoint_row("10.1.0.4", SPOKE)])
    assert record["private_endpoint_status"] == "backed"
    assert record["ip_address_networks"] == {"10.1.0.4": [SPOKE.lower()]}


def test_collect_zones_finds_spokes_of_an_unreadable_linked_hub(monkeypatch):
    # Both zones link a hub in a subscription the run can't read (one zone also links a readable VNet). The
    # record's IP falls in a readable spoke peered with that hub, and nothing holds it.
    other_spoke = f"{RG}/providers/Microsoft.Network/virtualNetworks/spoke2"
    rows = [
        _vnet_row(SPOKE, "10.1.0.0/16", peers=[UNREADABLE_HUB]),
        _vnet_row(other_spoke, "10.0.0.0/16", [NIC_CONFIG], peers=[UNREADABLE_HUB]),
        _vnet_row(ELSEWHERE, "10.9.0.0/16"),
    ]
    file_zone = "privatelink.file.core.windows.net"
    zones, vnet_queries, collector = _collect(
        monkeypatch, {BLOB: [UNREADABLE_HUB], file_zone: [UNREADABLE_HUB, ELSEWHERE]}, rows
    )
    assert collector.ok
    assert any("remoteVirtualNetwork" in q and f"@'{UNREADABLE_HUB.lower()}'" in q for q in vnet_queries)
    [blob] = zones[BLOB]["record_sets"]
    assert blob["ip_address_networks"] == {"10.0.0.4": [other_spoke.lower()]}
    assert blob["private_endpoint_status"] == "stale"  # unheld in a fully readable spoke the zone resolves for
    assert [link["virtual_network_status"] for link in zones[BLOB]["virtual_network_links"]] == ["not_visible"]
    [other] = zones[file_zone]["record_sets"]
    assert other["private_endpoint_status"] == "stale"


def test_virtual_wan_spokes_two_hops_apart_are_unverified():
    # The zone's DNS spoke and the endpoint's spoke each peer only with the hub's managed VNet.
    hub = f"/subscriptions/{OTHER_SUB}/resourceGroups/RG_hub/providers/Microsoft.Network/virtualNetworks/HV_hub"
    rows = [_vnet_row(VNET, "10.0.0.0/16", [NIC_CONFIG], peers=[hub]), _vnet_row(SPOKE, "10.1.0.0/16", peers=[hub])]
    record = _zone_ip("10.1.0.4", rows, [VNET], endpoint_rows=[_endpoint_row("10.1.0.4", SPOKE)])
    assert record["private_endpoint_status"] == "unverified" and record["ip_address_networks"] == {"10.1.0.4": []}


# --------------------------------------------------------------------------- #
# Resource Graph query text: the strings Azure parses
# --------------------------------------------------------------------------- #

# Rendered exactly as sent; each was parse-checked against Resource Graph. KQL takes an
# mv-expand row limit after the expanded column: "mv-expand limit N x = ..." is a ParserFailure.
RENDERED_QUERIES = {
    "dns endpoint NICs": (
        lambda: dns.ENDPOINT_IPS_QUERY,
        "Resources | where type =~ 'microsoft.network/networkinterfaces' and isnotnull(properties.privateEndpoint) "
        "| mv-expand ipc = properties.ipConfigurations limit 2000 "
        "| project id, ip = tostring(ipc.properties.privateIPAddress), "
        "private_endpoint_id = tostring(properties.privateEndpoint.id), "
        "fqdns = ipc.properties.privateLinkConnectionProperties.fqdns, subnet_id = tostring(ipc.properties.subnet.id) "
        "| order by id asc, ip asc",
    ),
    "dns other NIC IPs": (
        lambda: dns.OTHER_NIC_IPS_QUERY,
        "Resources | where type =~ 'microsoft.network/networkinterfaces' and isnull(properties.privateEndpoint) "
        "| mv-expand ipc = properties.ipConfigurations limit 2000 "
        "| project id, ip = tostring(ipc.properties.privateIPAddress), subnet_id = tostring(ipc.properties.subnet.id) "
        "| where isnotempty(ip) | order by id asc, ip asc",
    ),
    "dns load balancer frontend IPs": (
        lambda: dns.LOAD_BALANCER_IPS_QUERY,
        "Resources | where type =~ 'microsoft.network/loadbalancers' "
        "| mv-expand fe = properties.frontendIPConfigurations limit 2000 "
        "| project id, ip = tostring(fe.properties.privateIPAddress), subnet_id = tostring(fe.properties.subnet.id) "
        "| where isnotempty(ip) | order by id asc, ip asc",
    ),
    "dns virtual networks by id": (
        lambda: dns.vnets_query(["/v"]),
        "Resources | where type =~ 'microsoft.network/virtualnetworks' and id in~ (@'/v') "
        "| project id, address_prefixes = properties.addressSpace.addressPrefixes, "
        "peerings = properties.virtualNetworkPeerings, subnets = properties.subnets | order by id asc",
    ),
    "dns VNets peered with unreadable linked VNets": (
        lambda: dns.reverse_peers_query(["/v"]),
        "Resources | where type =~ 'microsoft.network/virtualnetworks' "
        "| mv-expand p = properties.virtualNetworkPeerings limit 2000 "
        "| where tostring(p.properties.remoteVirtualNetwork.id) in~ (@'/v') "
        "and tostring(p.properties.peeringState) =~ 'Connected' | distinct id | order by id asc",
    ),
    "pe subnet lookup": (
        lambda: pe.subnet_query(["/v"]),
        "Resources | where id in~ (@'/v') | extend vnet_id = tolower(id), subnet_count = array_length(properties.subnets) "
        "| mv-expand s = properties.subnets limit 2000 "
        "| project id = tostring(s.id), vnet_id, subnet_count, policies = tostring(s.properties.privateEndpointNetworkPolicies), "
        "nsg_id = tostring(s.properties.networkSecurityGroup.id), route_table_id = tostring(s.properties.routeTable.id) "
        "| order by id asc",
    ),
    "pe lookup": (
        lambda: pe.lookup_query(["/v"]),
        "Resources | where id in~ (@'/v') | project id, type, public_network_access = tostring(properties.publicNetworkAccess), "
        "network_acls_default_action = tostring(properties.networkAcls.defaultAction), "
        "ip_configurations = properties.ipConfigurations | order by id asc",
    ),
}


@pytest.mark.parametrize("name", sorted(RENDERED_QUERIES))
def test_rendered_query_shape_is_pinned(name):
    render, expected = RENDERED_QUERIES[name]
    assert render() == expected


# `limit` straight after mv-expand (or its kind= / with_itemindex= options) is where KQL wants the column.
MISPLACED_MV_EXPAND_LIMIT = re.compile(r"mv-expand\s+(?:(?:kind|with_itemindex)\s*=\s*\w+\s+)*limit\b", re.IGNORECASE)


@pytest.mark.parametrize("path", sorted(AZURE.glob("*/fetcher.py")) + sorted(AZURE.glob("_shared/*.py")), ids=lambda p: p.parent.name if p.name == "fetcher.py" else p.name)
def test_no_azure_query_puts_mv_expand_limit_before_the_column(path):
    assert not MISPLACED_MV_EXPAND_LIMIT.search(path.read_text()), "use `mv-expand x = <array> limit N`"


def _verbatim_list(query: str) -> list:
    """Decode the first `in~ (...)` list of KQL verbatim literals; fails on a literal that does not close."""
    i = query.index("in~ (") + len("in~ (")
    values = []
    while True:
        assert query.startswith("@'", i), query[i : i + 20]
        i += 2
        value = ""
        while True:
            j = query.index("'", i)
            value += query[i:j]
            if query.startswith("''", j):  # a doubled quote is one quote inside the literal
                value += "'"
                i = j + 2
                continue
            i = j + 1
            break
        values.append(value)
        if query.startswith(", ", i):
            i += 2
            continue
        assert query[i] == ")", query[i : i + 20]
        return values


@pytest.mark.parametrize(
    "build", [dns.vnets_query, dns.reverse_peers_query, pe.lookup_query, pe.subnet_query], ids=lambda f: f.__name__
)
def test_id_lists_round_trip_through_kql_quoting(build):
    ids = ["/a'b", "/c\\d", "/e'),(@'f", "/g''h", "/plain"]
    assert _verbatim_list(build(ids)) == ids
    assert _verbatim_list(build([f"/v{i}" for i in range(200)])) == [f"/v{i}" for i in range(200)]


def test_unread_endpoint_nic_leaves_private_ips_unknown():
    endpoint = {"id": "pe", "name": "pe", "subnet_id": None, "connections": [], "network_interface_ids": ["/nic1"]}
    assert pe.endpoint_record(endpoint, [], {}, {"/nic1"}, {}, set(), None)["private_ip_addresses"] is None
    read = {"/nic1": {"ip_configurations": [{"properties": {"privateIPAddress": "10.0.1.4"}}]}}
    assert pe.endpoint_record(endpoint, [], read, set(), {}, set(), None)["private_ip_addresses"] == ["10.0.1.4"]
