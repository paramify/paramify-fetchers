"""azure_dns_configuration: public record sets, their targets and failover method, over real SDK models."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from azure.mgmt.dns import models as m

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

spec = importlib.util.spec_from_file_location("azure_dns_configuration_under_test", AZURE / "dns_configuration" / "fetcher.py")
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)

from azure_common import Collector  # noqa: E402

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-dns/providers"
AFD = f"{SUB}/Microsoft.Cdn/profiles/fd-prod/afdEndpoints/web"
TM = f"{SUB}/Microsoft.Network/trafficManagerProfiles/tm-web"
PIP = f"{SUB}/Microsoft.Network/publicIPAddresses/pip-web"
CDN = f"{SUB}/Microsoft.Cdn/profiles/cdn-prod/endpoints/static"


def record_set(record_type, name="www", ttl=300, **kw):
    rs = m.RecordSet(ttl=ttl, **kw)
    rs.name, rs.type, rs.fqdn = name, f"Microsoft.Network/dnszones/{record_type}", f"{name}.example.com."
    rs.provisioning_state = "Succeeded"
    return rs


def alias(record_type, target_id, ttl=60):
    return record_set(record_type, name="@", ttl=ttl, target_resource=m.SubResource(id=target_id))


def test_targets_per_record_type():
    cases = [
        (record_set("A", a_records=[m.ARecord(ipv4_address="203.0.113.10"), m.ARecord(ipv4_address="203.0.113.11")]),
         ["203.0.113.10", "203.0.113.11"]),
        (record_set("AAAA", aaaa_records=[m.AaaaRecord(ipv6_address="2001:db8::1")]), ["2001:db8::1"]),
        (record_set("CNAME", cname_record=m.CnameRecord(cname="app.example.net")), ["app.example.net"]),
        (record_set("MX", mx_records=[m.MxRecord(preference=10, exchange="mail.example.com")]), ["10 mail.example.com"]),
        (record_set("NS", ns_records=[m.NsRecord(nsdname="ns1-01.azure-dns.com.")]), ["ns1-01.azure-dns.com."]),
        (record_set("PTR", ptr_records=[m.PtrRecord(ptrdname="host.example.com")]), ["host.example.com"]),
        (record_set("TXT", txt_records=[m.TxtRecord(value=["v=spf1 ", "-all"]), m.TxtRecord(value=["token"])]),
         ["v=spf1 -all", "token"]),
        (record_set("SRV", srv_records=[m.SrvRecord(priority=1, weight=5, port=443, target="sip.example.com")]),
         ["1 5 443 sip.example.com"]),
        (record_set("CAA", caa_records=[m.CaaRecord(flags=0, tag="issue", value="digicert.com")]), ['0 issue "digicert.com"']),
        (record_set("SOA", soa_record=m.SoaRecord(host="ns1-01.azure-dns.com.", email="azuredns-hostmaster.microsoft.com")),
         ["ns1-01.azure-dns.com. azuredns-hostmaster.microsoft.com"]),
    ]
    for rs, targets in cases:
        record = dns.project_record_set(rs)
        assert record["targets"] == targets, record["type"]
        assert record["alias_target_resource_id"] is None and record["alias_target_type"] is None


def test_record_set_keeps_name_type_ttl_and_state():
    record = dns.project_record_set(record_set("A", name="api", ttl=3600, a_records=[m.ARecord(ipv4_address="203.0.113.1")]))
    assert record == {
        "name": "api",
        "fqdn": "api.example.com.",
        "type": "A",
        "ttl": 3600,
        "targets": ["203.0.113.1"],
        "alias_target_resource_id": None,
        "alias_target_type": None,
        "failover_method": "record_update",
        "same_zone_target": None,
        "provisioning_state": "Succeeded",
    }


def test_missing_parts_are_left_out_of_values():
    cases = [
        (record_set("MX", mx_records=[m.MxRecord(exchange="mail.example.com")]), ["mail.example.com"]),
        (record_set("SRV", srv_records=[m.SrvRecord(port=443, target="sip.example.com")]), ["443 sip.example.com"]),
        (record_set("SRV", srv_records=[m.SrvRecord()]), []),
        (record_set("CAA", caa_records=[m.CaaRecord(tag="issue")]), ["issue"]),
        (record_set("SOA", soa_record=m.SoaRecord(host="ns1-01.azure-dns.com.")), ["ns1-01.azure-dns.com."]),
    ]
    for rs, targets in cases:
        assert dns.project_record_set(rs)["targets"] == targets


@pytest.mark.parametrize("record_type, target_id, alias_type, method", [
    ("A", AFD, "front_door", "front_door"),
    ("CNAME", AFD, "front_door", "front_door"),
    ("A", f"{SUB}/Microsoft.Network/frontDoors/classic", "front_door", "front_door"),
    ("A", TM, "traffic_manager", "traffic_manager"),
    ("CNAME", CDN, "cdn_endpoint", "cdn"),
    ("A", PIP, "public_ip", "record_update"),
    ("AAAA", f"{SUB}/Microsoft.Network/loadBalancers/lb", "other", "record_update"),
    ("A", f"{SUB}/Microsoft.Network/dnszones/example.com/A/@", "record_set", "record_update"),
])
def test_alias_target_sets_failover_method(record_type, target_id, alias_type, method):
    record = dns.project_record_set(alias(record_type, target_id))
    assert record["alias_target_resource_id"] == target_id
    assert record["alias_target_type"] == alias_type
    assert record["failover_method"] == method


@pytest.mark.parametrize("cname, method", [
    ("web-abc123.z01.azurefd.net", "front_door"),
    ("WEB-ABC123.Z01.AZUREFD.NET.", "front_door"),
    ("web.trafficmanager.net", "traffic_manager"),
    ("web.usgovtrafficmanager.net", "traffic_manager"),
    ("static.azureedge.net", "cdn"),
    ("app.azurewebsites.net", "record_update"),
    ("azurefd.net.example.com", "record_update"),
])
def test_cname_host_sets_failover_method(cname, method):
    record = dns.project_record_set(record_set("CNAME", cname_record=m.CnameRecord(cname=cname)))
    assert record["failover_method"] == method


def test_failover_method_only_for_endpoint_records_with_an_answer():
    mx = dns.project_record_set(record_set("MX", mx_records=[m.MxRecord(preference=0, exchange="x.azurefd.net")]))
    empty = dns.project_record_set(record_set("A", name="stale", a_records=[]))
    assert mx["failover_method"] is None
    assert empty["targets"] == [] and empty["failover_method"] is None


def resolved(zone_name, *record_sets):
    records = dns.resolve_zone_links([dns.project_record_set(rs) for rs in record_sets], zone_name)
    return {(r["name"], r["type"]): r for r in records}


def test_cname_to_a_name_in_the_zone_takes_its_failover_method():
    records = resolved(
        "example.com",
        alias("A", AFD),
        record_set("CNAME", name="www", cname_record=m.CnameRecord(cname="Example.com.")),
        record_set("CNAME", name="api", cname_record=m.CnameRecord(cname="edge.example.com")),
        record_set("CNAME", name="edge", cname_record=m.CnameRecord(cname="api.trafficmanager.net")),
    )
    assert records[("www", "CNAME")]["same_zone_target"] == "@"
    assert records[("www", "CNAME")]["failover_method"] == "front_door"
    assert records[("api", "CNAME")]["same_zone_target"] == "edge"
    assert records[("api", "CNAME")]["failover_method"] == "traffic_manager"
    assert records[("@", "A")]["same_zone_target"] is None


def test_alias_to_a_record_set_in_the_zone_takes_its_failover_method():
    target = f"{SUB}/Microsoft.Network/dnszones/example.com/A/edge"
    records = resolved(
        "example.com",
        record_set("A", name="edge", target_resource=m.SubResource(id=TM)),
        record_set("A", name="www", target_resource=m.SubResource(id=target)),
    )
    assert records[("www", "A")]["alias_target_type"] == "record_set"
    assert records[("www", "A")]["same_zone_target"] == "edge"
    assert records[("www", "A")]["failover_method"] == "traffic_manager"


def test_zone_links_follow_one_hop_only_and_survive_loops():
    records = resolved(
        "example.com",
        alias("A", AFD),
        record_set("CNAME", name="b", cname_record=m.CnameRecord(cname="example.com")),
        record_set("CNAME", name="a", cname_record=m.CnameRecord(cname="b.example.com")),
        record_set("CNAME", name="x", cname_record=m.CnameRecord(cname="y.example.com")),
        record_set("CNAME", name="y", cname_record=m.CnameRecord(cname="x.example.com")),
        record_set("CNAME", name="self", cname_record=m.CnameRecord(cname="self.example.com")),
        record_set("CNAME", name="gone", cname_record=m.CnameRecord(cname="missing.example.com")),
    )
    assert records[("b", "CNAME")]["failover_method"] == "front_door"
    assert records[("a", "CNAME")]["failover_method"] == "record_update"
    assert {records[(n, "CNAME")]["failover_method"] for n in ("x", "y", "self", "gone")} == {"record_update"}
    assert records[("gone", "CNAME")]["same_zone_target"] is None
    assert records[("a", "CNAME")]["same_zone_target"] == "b"


def test_zone_link_with_mixed_targets_stays_record_update():
    records = resolved(
        "example.com",
        alias("A", AFD),
        record_set("AAAA", name="@", aaaa_records=[m.AaaaRecord(ipv6_address="2001:db8::1")]),
        record_set("CNAME", name="www", cname_record=m.CnameRecord(cname="example.com")),
    )
    assert records[("www", "CNAME")]["failover_method"] == "record_update"


def test_names_outside_the_zone_are_not_links():
    records = resolved(
        "example.com",
        record_set("CNAME", name="www", cname_record=m.CnameRecord(cname="notexample.com")),
        record_set("CNAME", name="app", cname_record=m.CnameRecord(cname="app.example.com.evil.net")),
        alias("A", f"{SUB}/Microsoft.Network/dnszones/other.com/A/@"),
    )
    assert all(r["same_zone_target"] is None for r in records.values())


def test_name_with_no_record_set_in_the_zone_is_not_a_link():
    records = resolved(
        "example.com",
        record_set("CNAME", name="www", cname_record=m.CnameRecord(cname="app.child.example.com")),
        record_set("CNAME", name="api", cname_record=m.CnameRecord(cname="mail.example.com")),
        record_set("MX", name="mail", mx_records=[m.MxRecord(preference=10, exchange="mx.example.net")]),
    )
    assert records[("www", "CNAME")]["same_zone_target"] is None
    assert records[("api", "CNAME")]["same_zone_target"] is None
    assert records[("www", "CNAME")]["failover_method"] == "record_update"


@pytest.mark.parametrize("resource_id, arm_type", [
    (AFD, "microsoft.cdn/profiles/afdendpoints"),
    (PIP, "microsoft.network/publicipaddresses"),
    (f"{SUB}/Microsoft.Network", None),
    ("not-an-arm-id", None),
    (None, None),
])
def test_arm_resource_type(resource_id, arm_type):
    assert dns.arm_resource_type(resource_id) == arm_type


def zone(name="example.com", record_sets=None, dnssec=None):
    projected = {"id": f"{SUB}/Microsoft.Network/dnszones/{name}", "name": name, "zone_type": "Public",
                 "tags": None, "name_servers": ["ns1-01.azure-dns.com."], "number_of_record_sets": 2}
    return dns.public_zone_record(projected, dnssec, record_sets)


EXISTING_SUMMARY_KEYS = {
    "total_public_zones", "dnssec_enabled_public_zones", "dnssec_disabled_public_zones", "dnssec_unknown_public_zones",
    "dnssec_percentage", "total_private_zones", "total_private_zone_virtual_network_links",
    "private_zones_without_links", "auto_registration_links",
}


def test_summary_counts_record_sets_and_failover_methods():
    records = [dns.project_record_set(rs) for rs in (
        alias("A", AFD),
        record_set("CNAME", name="www", cname_record=m.CnameRecord(cname="web.z01.azurefd.net")),
        record_set("CNAME", name="api", cname_record=m.CnameRecord(cname="api.trafficmanager.net")),
        record_set("A", name="vpn", a_records=[m.ARecord(ipv4_address="203.0.113.5")]),
        record_set("A", name="stale", a_records=[]),
        record_set("TXT", name="@", txt_records=[m.TxtRecord(value=["v=spf1 -all"])]),
    )]
    summary = dns.summarize([zone(record_sets=records), zone("unread.example", record_sets=None)], [])

    assert EXISTING_SUMMARY_KEYS <= set(summary)
    assert summary["total_public_zones"] == 2
    assert summary["total_public_record_sets"] == 6
    assert summary["public_zones_record_sets_unread"] == 1
    assert summary["public_record_sets_by_type"] == {"A": 3, "CNAME": 2, "TXT": 1}
    assert summary["public_alias_record_sets"] == 1
    assert summary["public_endpoint_record_sets"] == 5
    assert summary["public_endpoint_record_sets_empty"] == 1
    assert summary["public_endpoint_record_sets_by_failover_method"] == {
        "front_door": 2, "traffic_manager": 1, "cdn": 0, "record_update": 1}


def test_summary_with_no_zones_lists_every_failover_method():
    summary = dns.summarize([], [])
    assert summary["total_public_record_sets"] == 0
    assert summary["public_record_sets_by_type"] == {}
    assert summary["public_endpoint_record_sets_by_failover_method"] == {
        "front_door": 0, "traffic_manager": 0, "cdn": 0, "record_update": 0}


def test_zone_record_keeps_existing_keys_and_adds_record_sets():
    record = zone(record_sets=[])
    assert {"id", "name", "zone_type", "tags", "name_servers", "number_of_record_sets", "resource_group",
            "dnssec_provisioning_state", "dnssec_signing_keys", "dnssec_enabled",
            "delegation_signer_records"} <= set(record)
    assert record["record_sets"] == [] and record["resource_group"] == "rg-dns"


class FakeRecordSets:
    def __init__(self, by_zone):
        self.by_zone, self.calls = by_zone, []

    def list_all_by_dns_zone(self, resource_group, zone_name):
        self.calls.append((resource_group, zone_name))
        result = self.by_zone[zone_name]
        if isinstance(result, Exception):
            raise result
        return iter(result)


def fake_clients(monkeypatch, zones, by_zone):
    record_sets = FakeRecordSets(by_zone)
    dns_client = SimpleNamespace(zones=SimpleNamespace(list=lambda: iter(zones)), record_sets=record_sets)
    arm = SimpleNamespace(send_request=lambda request: SimpleNamespace(status_code=404))
    import azure.mgmt.dns
    import azure.mgmt.privatedns
    monkeypatch.setattr(azure.mgmt.dns, "DnsManagementClient", lambda **kw: dns_client)
    monkeypatch.setattr(azure.mgmt.privatedns, "PrivateDnsManagementClient", lambda **kw: arm)
    return record_sets


def sdk_zone(name):
    z = m.Zone(location="global")
    z.id, z.name = f"{SUB}/Microsoft.Network/dnszones/{name}", name
    return z


def test_collect_public_zones_lists_record_sets_sorted(monkeypatch):
    record_sets = fake_clients(monkeypatch, [sdk_zone("example.com")], {"example.com": [
        record_set("CNAME", name="www", cname_record=m.CnameRecord(cname="example.com")),
        alias("A", AFD),
        record_set("TXT", name="@", txt_records=[m.TxtRecord(value=["v=spf1 -all"])]),
    ]})
    collector = Collector(logging.getLogger("test"))
    [z] = dns.collect_public_zones("sub", object(), collector)

    assert collector.ok
    assert record_sets.calls == [("rg-dns", "example.com")]
    assert [(r["name"], r["type"]) for r in z["record_sets"]] == [("@", "A"), ("@", "TXT"), ("www", "CNAME")]
    assert z["record_sets"][2]["failover_method"] == "front_door"
    assert z["dnssec_enabled"] is False


def test_unreadable_record_sets_are_null_and_fail_the_run(monkeypatch):
    fake_clients(monkeypatch, [sdk_zone("example.com"), sdk_zone("ok.example")], {
        "example.com": PermissionError("AuthorizationFailed"),
        "ok.example": [alias("A", TM)],
    })
    collector = Collector(logging.getLogger("test"))
    zones = {z["name"]: z for z in dns.collect_public_zones("sub", object(), collector)}

    assert zones["example.com"]["record_sets"] is None
    assert zones["ok.example"]["record_sets"][0]["failover_method"] == "traffic_manager"
    assert not collector.ok
    assert "record_sets.list_all_by_dns_zone(rg-dns/example.com)" in collector.failures[0]["operation"]


# --- scope exclusions ---

def scoped_zone():
    records = [dns.project_record_set(rs) for rs in (
        alias("A", AFD),
        record_set("CNAME", name="www", cname_record=m.CnameRecord(cname="web.z01.azurefd.net")),
        record_set("CNAME", name="qa", cname_record=m.CnameRecord(cname="qa.z01.azurefd.net")),
        record_set("A", name="webdav", a_records=[m.ARecord(ipv4_address="203.0.113.5")]),
        record_set("CNAME", name="files", cname_record=m.CnameRecord(cname="files.azureedge.net")),
    )]
    return zone(record_sets=records)


def test_record_sets_match_on_relative_name_or_fqdn():
    exclusions = dns.ScopeExclusions(["QA", "webdav.example.com", "files.example.com.", "typo.example.com"])
    [z], excluded = dns.exclude_record_sets([scoped_zone()], exclusions)

    assert [r["name"] for r in z["record_sets"]] == ["@", "www"]
    assert [(e["name"], e["type"], e["pattern"]) for e in excluded] == [
        ("qa", "CNAME", "QA"), ("webdav", "A", "webdav.example.com"), ("files", "CNAME", "files.example.com.")]
    assert excluded[0] == {"kind": "record_set", "name": "qa", "pattern": "QA", "reason": "name_matched",
                           "zone": "example.com", "zone_id": z["id"], "type": "CNAME", "fqdn": "qa.example.com."}
    assert exclusions.unmatched() == ["typo.example.com"]


def test_counts_cover_only_record_sets_in_scope():
    exclusions = dns.ScopeExclusions(["qa", "webdav", "files"])
    zones, excluded = dns.exclude_record_sets([scoped_zone()], exclusions)
    summary = {**dns.summarize(zones, []), **exclusions.summary(excluded, ("record_set",))}

    assert summary["total_public_record_sets"] == 2
    assert summary["public_endpoint_record_sets_by_failover_method"] == {
        "front_door": 2, "traffic_manager": 0, "cdn": 0, "record_update": 0}
    assert summary["excluded_record_sets"] == 3
    assert summary["scope_exclusion_patterns_unmatched"] == []


def test_no_patterns_leaves_zones_untouched_and_unread_zones_null():
    zones = [scoped_zone(), zone("unread.example", record_sets=None)]
    kept, excluded = dns.exclude_record_sets(zones, dns.ScopeExclusions())
    assert kept == zones and excluded == []


def run_main(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(dns, "resolve_subscription", lambda c: {"subscription_id": "sub", "subscription_source": "env"})
    monkeypatch.setattr(dns, "credential", lambda: object())
    monkeypatch.setattr(dns, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(dns, "collect_public_zones", lambda *a: [scoped_zone()])
    monkeypatch.setattr(dns, "collect_private_zones", lambda *a: [])
    monkeypatch.setattr(dns, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(dns.SCOPE_EXCLUSIONS_ENV, raising=False)
    else:
        monkeypatch.setenv(dns.SCOPE_EXCLUSIONS_ENV, patterns)
    assert dns.main() == 0
    return json.loads((tmp_path / "azure_dns_configuration_sub.json").read_text())


def test_main_without_patterns_adds_only_empty_scope_fields(monkeypatch, tmp_path):
    evidence = run_main(monkeypatch, tmp_path, None)
    assert evidence["results"]["excluded"] == []
    assert evidence["summary"]["scope_exclusion_patterns"] == []
    assert evidence["summary"]["scope_exclusion_patterns_unmatched"] == []
    assert evidence["summary"]["excluded_record_sets"] == 0
    assert evidence["summary"]["total_public_record_sets"] == 5


def test_main_with_patterns_from_the_env(monkeypatch, tmp_path):
    evidence = run_main(monkeypatch, tmp_path, "qa, webdav.example.com")
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["qa", "webdav"]
    assert evidence["summary"]["total_public_record_sets"] == 3
    assert evidence["summary"]["scope_exclusion_patterns"] == ["qa", "webdav.example.com"]
