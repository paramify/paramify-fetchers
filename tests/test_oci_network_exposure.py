"""Rule parsing and reachability in `oci_network_exposure`, and the rules Prowler calls clean."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "network_exposure" / "fetcher.py"
IGW = "ocid1.internetgateway.oc1..igw"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_network_exposure", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


net = _load()


def _ingress(source="0.0.0.0/0", protocol="6", *, ports=(22, 22), udp=False, stateless=False):
    options = {"destination_port_range": {"min": ports[0], "max": ports[1]}} if ports else None
    rule = {"source": source, "source_type": "CIDR_BLOCK", "protocol": protocol, "is_stateless": stateless}
    rule["udp_options" if udp else "tcp_options"] = options
    return rule


def _list(name, ingress=(), egress=(), *, default=False, subnets=()):
    return net.security_list_record(
        {"id": f"ocid1.securitylist.oc1..{name}", "display_name": name, "lifecycle_state": "AVAILABLE",
         "ingress_security_rules": list(ingress), "egress_security_rules": list(egress)},
        is_default=default, attached_subnets=subnets)


def _subnet(name, *, routable=True, prohibit=False, flow=False):
    return net.subnet_record(
        {"id": f"ocid1.subnet.oc1..{name}", "display_name": name, "lifecycle_state": "AVAILABLE",
         "prohibit_internet_ingress": prohibit, "prohibit_public_ip_on_vnic": False},
        internet_routable=routable,
        flow_logs=[{"id": "l", "is_enabled": True, "configuration": {"source": {"resource": "x"}}}] if flow else [])


def test_ipv6_internet_is_recognised():
    """Prowler compares source == '0.0.0.0/0', so ::/0 passes every one of its checks."""
    rule = net.rule_record(_ingress(source="::/0"), direction="INGRESS")
    assert rule["is_internet"] and rule["sensitive_ports_exposed"] == ["SSH"]
    out = net.summarize([], [], [_list("l", [_ingress(source="::/0")])], [])
    assert out["ipv6_internet_ingress_rules"] == 1


def test_every_sensitive_port_is_named_not_just_ssh_and_rdp():
    postgres = net.rule_record(_ingress(ports=(5432, 5432)), direction="INGRESS")
    assert postgres["sensitive_ports_exposed"] == ["PostgreSQL"]
    wide = net.rule_record(_ingress(ports=(1, 65535)), direction="INGRESS")
    assert wide["opens_all_ports"] and "MySQL" in wide["sensitive_ports_exposed"]
    udp = net.rule_record(_ingress(protocol="17", ports=(11211, 11211), udp=True), direction="INGRESS")
    assert udp["protocol_name"] == "UDP" and udp["sensitive_ports_exposed"] == ["memcached"]


def test_tcp_rule_with_no_options_opens_every_port():
    rule = net.rule_record(_ingress(ports=None), direction="INGRESS")
    assert rule["port_ranges"] == [[1, 65535]] and rule["opens_all_ports"]


def test_egress_is_judged_and_not_labelled_with_port_names():
    egress = {"destination": "0.0.0.0/0", "destination_type": "CIDR_BLOCK", "protocol": "all"}
    record = net.rule_record(egress, direction="EGRESS")
    assert record["is_internet"] and record["opens_all_ports"]
    assert record["sensitive_ports_exposed"] == []
    out = net.summarize([], [], [_list("l", egress=[egress])], [])
    assert out["unrestricted_internet_egress_rules"] == 1
    assert [n.split(" (")[0] for n in out["security_lists_with_unrestricted_egress"]] == ["l"]


def test_configured_exposure_and_reachable_exposure_are_separate():
    """The staged tenancy's shape: an SSH-from-anywhere rule that nothing can reach."""
    subnet = _subnet("private", routable=False)
    unattached = _list("orphan", [_ingress()])
    attached = _list("live", [_ingress()], subnets=[subnet["id"]])
    out = net.summarize([], [subnet], [unattached, attached], [])
    assert out["internet_ingress_rules"] == 2
    assert out["reachable_internet_ingress_rules"] == 0
    assert out["internet_ingress_rules_on_unattached_lists"] == 1
    assert out["sensitive_ports_open_to_internet"] == ["SSH"]
    assert out["sensitive_ports_reachable_from_internet"] == []


def test_a_routable_subnet_makes_the_same_rule_an_exposure():
    subnet = _subnet("public", routable=True)
    out = net.summarize([], [subnet], [_list("live", [_ingress()], subnets=[subnet["id"]])], [])
    assert out["reachable_internet_ingress_rules"] == 1
    assert out["sensitive_ports_reachable_from_internet"] == ["SSH"]


def test_prohibit_internet_ingress_beats_the_rule():
    subnet = _subnet("blocked", routable=True, prohibit=True)
    out = net.summarize([], [subnet], [_list("live", [_ingress()], subnets=[subnet["id"]])], [])
    assert out["reachable_internet_ingress_rules"] == 0
    assert out["subnets_prohibiting_internet_ingress"] == 1


def test_only_an_enabled_internet_gateway_makes_a_route_public():
    table = {"route_rules": [{"destination": "0.0.0.0/0", "network_entity_id": IGW}]}
    assert net.route_table_routes_to_internet(table, enabled_gateway_ids={IGW}) is True
    assert net.route_table_routes_to_internet(table, enabled_gateway_ids=set()) is False
    nat = {"route_rules": [{"destination": "0.0.0.0/0", "network_entity_id": "ocid1.natgateway.oc1..n"}]}
    assert net.route_table_routes_to_internet(nat, enabled_gateway_ids={IGW}) is False


def test_nsg_rules_are_counted_apart_and_an_unreadable_nsg_is_not_empty():
    nsg = net.nsg_record({"id": "n", "display_name": "n", "lifecycle_state": "AVAILABLE"},
                         rules=[{**_ingress(ports=(3389, 3389)), "direction": "INGRESS"}])
    unread = net.nsg_record({"id": "u", "display_name": "u", "lifecycle_state": "AVAILABLE"}, rules=None)
    out = net.summarize([], [], [], [nsg, unread])
    assert out["nsg_internet_ingress_rules"] == 1
    assert out["nsg_sensitive_ports_open_to_internet"] == ["RDP"]
    assert out["nsgs_with_unreadable_rules"] == 1
    assert out["reachable_internet_ingress_rules"] == 0


def test_flow_logging_percentage_and_unreadable_route_tables():
    logged, unlogged = _subnet("a", flow=True), _subnet("b")
    unknown = net.subnet_record({"id": "c", "display_name": "c", "lifecycle_state": "AVAILABLE"},
                                internet_routable=None)
    out = net.summarize([], [logged, unlogged, unknown], [], [])
    assert out["flow_logging_percentage"] == 33
    assert out["subnets_with_unreadable_route_table"] == 1
