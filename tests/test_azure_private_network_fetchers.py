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
VNETS = dns.vnet_index([{"id": VNET, "address_prefixes": ["10.0.0.0/16"]}])


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
    record = dns.classify_record(
        _record(name, zone, "10.0.1.4"), zone, _endpoints(("10.0.1.4", "pe-1", fqdns)), VNETS
    )
    assert record["private_endpoint_status"] == "backed"
    assert record["private_endpoint_ids"] == ["pe-1"]


def test_ip_held_by_an_endpoint_for_another_name_is_ip_mismatch():
    zone = "privatelink.vaultcore.azure.net"
    record = dns.classify_record(
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
    record = dns.classify_record(
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
    record = dns.classify_record(_record("acct", zone, ip), zone, endpoints, vnets)
    assert record["private_endpoint_status"] == expected


def test_dead_ip_next_to_live_one_is_not_hidden():
    zone = "privatelink.blob.core.windows.net"
    record = dns.classify_record(
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
    assert dns.record_status([]) == "unknown"


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
