"""Azure SQL Managed Instance fetchers, driven by a fake SqlManagementClient.

Pins the two ways these fetchers could state something Azure never said: a
failover group counted once per region it spans, and a failed call read as
"off". No SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backups = _load("sql_managed_instance_backups")
configuration = _load("sql_managed_instance_configuration")
encryption = _load("sql_managed_instance_encryption")

SUB = "00000000-0000-0000-0000-000000000001"
MI_EAST = f"/subscriptions/{SUB}/resourceGroups/rg-east/providers/Microsoft.Sql/managedInstances/mi-east"
MI_WEST = f"/subscriptions/{SUB}/resourceGroups/rg-west/providers/Microsoft.Sql/managedInstances/mi-west"
NETWORK = f"/subscriptions/{SUB}/resourceGroups/rg-net/providers/Microsoft.Network"
NSG = f"{NETWORK}/networkSecurityGroups/nsg-mi"
ROUTE_TABLE = f"{NETWORK}/routeTables/rt-mi"
MAINTENANCE = f"/subscriptions/{SUB}/providers/Microsoft.Maintenance/publicMaintenanceConfigurations"
WINDOWS = {"mi-east": f"{MAINTENANCE}/SQL_EastUS_MI_1", "mi-west": f"{MAINTENANCE}/SQL_Default"}
DENIED = Exception("(AuthorizationFailed) The client does not have authorization")


class ResourceNotFoundError(Exception):
    pass


class HttpResponseError(Exception):
    def __init__(self, code, message):
        super().__init__(f"({code}) {message}")
        self.error = ns(code=code)


UNREGISTERED = HttpResponseError("MissingSubscriptionRegistration",
                                 "The subscription is not registered to use namespace 'Microsoft.Maintenance'.")


def call(table):
    def fn(*args, **kwargs):
        value = table[args or tuple(kwargs.values())]
        if isinstance(value, Exception):
            raise value
        return value

    return fn


def instance(resource_id, location):
    name = resource_id.rsplit("/", 1)[1]
    return ns(id=resource_id, name=name, location=location, state="Ready",
              current_backup_storage_redundancy="Geo", requested_backup_storage_redundancy="Geo",
              public_data_endpoint_enabled=False, minimal_tls_version="1.2",
              subnet_id=f"{NETWORK}/virtualNetworks/vnet-mi/subnets/{name}",
              maintenance_configuration_id=WINDOWS[name])


def database(instance_id, name):
    return ns(id=f"{instance_id}/databases/{name}", name=name, status="Online")


def failover_view(rg, location, role):
    return ns(
        id=f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Sql/locations/{location}"
           "/instanceFailoverGroups/fog",
        name="fog", replication_role=role, replication_state="CATCH_UP", secondary_type="Geo",
        read_write_endpoint=ns(failover_policy="Automatic", failover_with_data_loss_grace_period_minutes=60),
        managed_instance_pairs=[ns(primary_managed_instance_id=MI_EAST, partner_managed_instance_id=MI_WEST)],
        partner_regions=[ns(location="westus" if location == "eastus" else "eastus", replication_role="Secondary")],
    )


def sql_client(*, failover=None, retention=None, ltr=None, databases=None, tde=None, admins=None, labels=None):
    week = ns(weekly_retention="P4W", monthly_retention="PT0S", yearly_retention="PT0S", week_of_year=0)
    dbs = {("rg-east", "mi-east"): [database(MI_EAST, "app")], ("rg-west", "mi-west"): [database(MI_WEST, "app")]}
    dbs.update(databases or {})
    keys = [("rg-east", "mi-east", "app"), ("rg-west", "mi-west", "app")]
    return ns(
        managed_instances=ns(list=lambda: [instance(MI_EAST, "eastus"), instance(MI_WEST, "westus")]),
        managed_databases=ns(list_by_instance=call(dbs)),
        managed_backup_short_term_retention_policies=ns(get=call(
            {(*k, "default"): ns(retention_days=7) for k in keys} | (retention or {}))),
        managed_instance_long_term_retention_policies=ns(get=call(
            {(*k, "default"): week for k in keys} | (ltr or {}))),
        instance_failover_groups=ns(list_by_location=call(failover or {
            ("rg-east", "eastus"): [failover_view("rg-east", "eastus", "Primary")],
            ("rg-west", "westus"): [failover_view("rg-west", "westus", "Secondary")],
        })),
        managed_instance_encryption_protectors=ns(get=call(
            {(rg, mi, "current"): ns(server_key_type="ServiceManaged") for rg, mi, _ in keys})),
        managed_database_transparent_data_encryption=ns(get=call(
            {(*k, "current"): ns(state="Enabled") for k in keys} | (tde or {}))),
        managed_instance_administrators=ns(list_by_instance=call(admins or {
            (rg, mi): [ns(administrator_type="ActiveDirectory", login="dba")] for rg, mi, _ in keys})),
        managed_instance_azure_ad_only_authentications=ns(list_by_instance=call(
            {(rg, mi): [ns(azure_ad_only_authentication=True)] for rg, mi, _ in keys})),
        managed_database_sensitivity_labels=ns(list_current_by_database=call(
            {k: [] for k in keys} | (labels or {}))),
    )


def run_backups(monkeypatch, client):
    monkeypatch.setattr(backups, "sql_client", lambda *a: client)
    collector = backups.Collector(logging.getLogger("test"))
    instances, groups, unlisted = backups.collect(SUB, object(), collector)
    return {i["name"]: i for i in instances}, groups, backups.summarize(instances, groups, not unlisted), collector


def test_failover_group_seen_from_two_regions_counts_once(monkeypatch):
    instances, groups, summary, collector = run_backups(monkeypatch, sql_client())
    assert collector.ok
    assert len(groups) == 1
    assert groups[0]["replication_role"] == "Primary"
    assert [v["location"] for v in groups[0]["regional_views"]] == ["eastus", "westus"]
    assert summary["total_instance_failover_groups"] == 1
    assert summary["instances_in_failover_group"] == 2
    assert all(i["failover_groups"] == ["fog"] for i in instances.values())


def test_failed_retention_calls_read_null_not_false(monkeypatch):
    client = sql_client(retention={("rg-east", "mi-east", "app", "default"): DENIED},
                        ltr={("rg-east", "mi-east", "app", "default"): DENIED})
    instances, _, summary, collector = run_backups(monkeypatch, client)
    db = instances["mi-east"]["databases"][0]
    assert not collector.ok
    assert db["short_term_retention_policy_found"] is None
    assert db["short_term_retention_at_least_7_days"] is None
    assert db["long_term_retention"]["policy_found"] is None
    assert db["long_term_retention"]["configured"] is None
    assert summary["databases_retention_unknown"] == 1
    assert summary["databases_retention_below_7_days"] == 0
    assert summary["databases_long_term_retention_unknown"] == 1


def test_missing_retention_policy_is_a_known_absence(monkeypatch):
    gone = ResourceNotFoundError("(ResourceNotFound) policy not found")
    client = sql_client(retention={("rg-east", "mi-east", "app", "default"): gone},
                        ltr={("rg-east", "mi-east", "app", "default"): gone})
    instances, _, summary, collector = run_backups(monkeypatch, client)
    db = instances["mi-east"]["databases"][0]
    assert collector.ok
    assert db["short_term_retention_at_least_7_days"] is False
    assert db["long_term_retention"]["policy_found"] is False
    assert db["long_term_retention"]["configured"] is False
    assert summary["databases_missing_retention_policy"] == 1
    assert summary["databases_retention_unknown"] == 0


def test_failed_failover_group_list_reads_null_unless_another_region_answers(monkeypatch):
    client = sql_client(failover={("rg-east", "eastus"): DENIED, ("rg-west", "westus"): []})
    instances, groups, summary, _ = run_backups(monkeypatch, client)
    assert instances["mi-east"]["in_failover_group"] is None
    assert instances["mi-west"]["in_failover_group"] is False
    assert summary["total_instance_failover_groups"] is None
    assert summary["instances_failover_group_unknown"] == 1

    client = sql_client(failover={("rg-east", "eastus"): DENIED,
                                  ("rg-west", "westus"): [failover_view("rg-west", "westus", "Secondary")]})
    instances, _, _, _ = run_backups(monkeypatch, client)
    assert instances["mi-east"]["in_failover_group"] is True


def test_failed_database_list_leaves_totals_null(monkeypatch):
    client = sql_client(databases={("rg-east", "mi-east"): DENIED})
    instances, _, summary, _ = run_backups(monkeypatch, client)
    assert instances["mi-east"]["databases_collected"] is False
    assert instances["mi-east"]["total_user_databases"] is None
    assert instances["mi-east"]["databases_below_7_days"] is None
    assert summary["total_user_databases"] is None


@pytest.mark.parametrize("flags,expected", [
    ([True, True], True),
    ([True, None], None),
    ([False, None], False),
    ([], None),
])
def test_all_user_databases_tde_enabled_is_three_valued(flags, expected):
    assert encryption.all_enabled(flags) is expected


def test_failed_tde_call_is_unknown_not_unencrypted(monkeypatch):
    client = sql_client(tde={("rg-east", "mi-east", "app", "current"): DENIED})
    monkeypatch.setattr(encryption, "sql_client", lambda *a: client)
    collector = encryption.Collector(logging.getLogger("test"))
    instances = {i["name"]: i for i in encryption.collect(SUB, object(), collector)}
    summary = encryption.summarize(list(instances.values()))
    assert instances["mi-east"]["databases"][0]["tde_enabled"] is None
    assert instances["mi-east"]["all_user_databases_tde_enabled"] is None
    assert instances["mi-west"]["all_user_databases_tde_enabled"] is True
    assert summary["tde_unknown_user_databases"] == 1
    assert summary["tde_disabled_user_databases"] == 0


def rule(name, priority, direction="Inbound", access="Allow", protocol="Tcp", source="VirtualNetwork",
         destination="VirtualNetwork", port="1433", **lists):
    return ns(id=f"{NSG}/securityRules/{name}", name=name, priority=priority, direction=direction, access=access,
              protocol=protocol, source_address_prefix=source, destination_address_prefix=destination,
              destination_port_range=port, **lists)


DEFAULT_RULES = [
    rule("AllowVnetInBound", 65000, protocol="*", port="*"),
    rule("DenyAllInBound", 65500, access="Deny", protocol="*", source="*", destination="*", port="*"),
    rule("AllowInternetOutBound", 65001, "Outbound", protocol="*", source="*", destination="Internet", port="*"),
    rule("DenyAllOutBound", 65500, "Outbound", "Deny", "*", "*", "*", "*"),
]
SERVICE_AIDED_RULE = rule("Microsoft.Sql-managedInstances_UseOnly_mi-healthprobe-in", 100,
                          source="AzureLoadBalancer", port="*")


def subnet(name, nsg=NSG, route_table=ROUTE_TABLE):
    return ns(id=f"{NETWORK}/virtualNetworks/vnet-mi/subnets/{name}", name=name, address_prefix="10.0.0.0/27",
              delegations=[ns(service_name="Microsoft.Sql/managedInstances")],
              network_security_group=nsg and ns(id=nsg), route_table=route_table and ns(id=route_table))


def network(subnets=None, rules=None, routes=None):
    subnets = subnets or {("rg-net", "vnet-mi", mi): subnet(mi) for mi in ("mi-east", "mi-west")}
    group = ns(id=NSG, name="nsg-mi", security_rules=[SERVICE_AIDED_RULE, *(rules or [])],
               default_security_rules=DEFAULT_RULES)
    table = ns(id=ROUTE_TABLE, name="rt-mi", disable_bgp_route_propagation=False, routes=routes or [
        ns(name="Microsoft.Sql-managedInstances_UseOnly_subnet-to-vnetlocal", address_prefix="10.0.0.0/27",
           next_hop_type="VnetLocal"),
        ns(name="default-to-firewall", address_prefix="0.0.0.0/0", next_hop_type="VirtualAppliance",
           next_hop_ip_address="10.1.0.4"),
    ])
    return ns(subnets=ns(get=call(subnets)),
              network_security_groups=ns(get=call({("rg-net", "nsg-mi"): group})),
              route_tables=ns(get=call({("rg-net", "rt-mi"): table})))


def maintenance_config(name, recur):
    return {"id": f"{MAINTENANCE}/{name}", "name": name,
            "properties": {"maintenanceScope": "SQLManagedInstance", "maintenanceWindow": {
                "startDateTime": "2026-01-01 22:00", "expirationDateTime": "9999-12-31 23:59",
                "duration": "08:00", "timeZone": "Eastern Standard Time", "recurEvery": recur}}}


def run_configuration(monkeypatch, client, settings=None, net=None, windows=None, reads=None,
                      registration="registered", maintenance=None):
    settings = settings or {(MI_EAST.lstrip("/"),): [], (MI_WEST.lstrip("/"),): []}
    windows = windows or {
        WINDOWS["mi-east"]: maintenance_config("SQL_EastUS_MI_1", "Week Monday,Tuesday,Wednesday,Thursday"),
        WINDOWS["mi-west"]: maintenance_config("SQL_Default", "Day"),
    }

    def get_json(rest, url):
        path = url.split("?")[0]
        if reads is not None:
            reads.append(path)
        value = windows[path]
        if isinstance(value, Exception):
            raise value
        return value

    monitor = ns(diagnostic_settings=ns(list=call(settings)))
    monkeypatch.setattr(configuration, "sql_client", lambda *a: client)
    monkeypatch.setattr(configuration, "monitor_client", lambda *a: monitor)
    monkeypatch.setattr(configuration, "network_client", lambda *a: net or network())
    monkeypatch.setattr(configuration, "arm_rest_client", lambda *a: object())
    monkeypatch.setattr(configuration, "get_json", get_json)
    monkeypatch.setattr(configuration, "provider_registration_status", lambda *a: registration)
    collector = configuration.Collector(logging.getLogger("test"))
    records, maintenance_registration = configuration.collect(SUB, object(), collector)
    if maintenance is not None:
        maintenance.append(maintenance_registration)
    instances = {i["name"]: i for i in records}
    return instances, configuration.summarize(list(instances.values())), collector


def audit_setting(**destination):
    return ns(id="ds", name="ds", logs=[ns(category="SQLSecurityAuditEvents", enabled=True)], **destination)


def test_failed_admin_and_diagnostic_calls_read_null(monkeypatch):
    client = sql_client(admins={("rg-east", "mi-east"): DENIED, ("rg-west", "mi-west"): []})
    settings = {(MI_EAST.lstrip("/"),): DENIED, (MI_WEST.lstrip("/"),): []}
    instances, _, _ = run_configuration(monkeypatch, client, settings)
    east, west = instances["mi-east"], instances["mi-west"]
    assert east["entra_administrator_configured"] is None
    assert east["audit_logs_exported"] is None
    assert east["audit_log_destinations"] is None
    assert west["entra_administrator_configured"] is False
    assert west["audit_logs_exported"] is False
    assert west["audit_log_destinations"] == []


def test_event_hub_without_hub_name_is_still_a_destination(monkeypatch):
    rule = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/authorizationRules/send"
    settings = {(MI_EAST.lstrip("/"),): [audit_setting(event_hub_authorization_rule_id=rule)],
                (MI_WEST.lstrip("/"),): []}
    instances, _, _ = run_configuration(monkeypatch, sql_client(), settings)
    assert instances["mi-east"]["audit_logs_exported"] is True
    assert instances["mi-east"]["audit_log_destinations"] == [rule]


def test_subnet_rules_and_routes_are_read_with_service_aided_ones_marked(monkeypatch):
    any_to_any = rule("allow-all", 200, protocol="*", source="*", destination="*", port="*")
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), net=network(rules=[any_to_any]))
    east = instances["mi-east"]
    assert collector.ok
    assert east["subnet"]["network_security_group_id"] == NSG
    assert east["subnet_delegated_to_managed_instance"] is True
    rules = {r["name"]: r["service_aided"] for r in east["subnet_network_security_group"]["security_rules"]}
    assert rules == {SERVICE_AIDED_RULE.name: True, "allow-all": False}
    assert len(east["subnet_network_security_group"]["default_security_rules"]) == 4
    assert east["subnet_allow_any_to_any_rules"] == ["allow-all"]
    assert east["subnet_unrestricted_internet_outbound"] is True
    routes = {r["name"]: (r["next_hop_type"], r["service_aided"]) for r in east["subnet_route_table"]["routes"]}
    assert routes["default-to-firewall"] == ("VirtualAppliance", False)
    assert routes["Microsoft.Sql-managedInstances_UseOnly_subnet-to-vnetlocal"] == ("VnetLocal", True)
    assert summary["instances_subnet_network_security_group"] == 2
    assert summary["instances_subnet_allow_any_to_any_rule"] == 2
    assert summary["instances_subnet_route_table"] == 2
    assert summary["instances_subnet_unknown"] == 0
    assert summary["instances_subnet_rules_unknown"] == 0


def test_custom_outbound_deny_overrides_the_default_internet_allow(monkeypatch):
    deny = rule("deny-internet-out", 4000, "Outbound", "Deny", "*", "*", "Internet", "*")
    instances, summary, _ = run_configuration(monkeypatch, sql_client(), net=network(rules=[deny]))
    assert instances["mi-east"]["subnet_unrestricted_internet_outbound"] is False
    assert instances["mi-east"]["subnet_allow_any_to_any_rules"] == []
    assert summary["instances_subnet_unrestricted_internet_outbound"] == 0


def test_subnet_without_nsg_or_route_table_reads_false_not_null(monkeypatch):
    bare = {("rg-net", "vnet-mi", mi): subnet(mi, nsg=None, route_table=None) for mi in ("mi-east", "mi-west")}
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), net=network(subnets=bare))
    east = instances["mi-east"]
    assert collector.ok
    assert east["subnet_has_network_security_group"] is False
    assert east["subnet_network_security_group"] is None
    assert east["subnet_allow_any_to_any_rules"] == []
    assert east["subnet_smb_outbound_allow_rules"] == []
    assert east["subnet_public_all_ports_inbound_allow_rules"] == []
    assert east["subnet_unrestricted_internet_outbound"] is True
    assert east["subnet_has_route_table"] is False
    assert summary["instances_subnet_network_security_group"] == 0
    assert summary["instances_subnet_unrestricted_internet_outbound"] == 2
    assert summary["instances_subnet_rules_unknown"] == 0


def test_failed_subnet_reads_leave_subnet_fields_null(monkeypatch):
    subnets = {("rg-net", "vnet-mi", "mi-east"): DENIED, ("rg-net", "vnet-mi", "mi-west"): subnet("mi-west")}
    net = network(subnets=subnets)
    net.network_security_groups = ns(get=call({("rg-net", "nsg-mi"): DENIED}))
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), net=net)
    east, west = instances["mi-east"], instances["mi-west"]
    assert not collector.ok
    rule_fields = ("subnet_allow_any_to_any_rules", "subnet_unrestricted_internet_outbound",
                   "subnet_smb_outbound_allow_rules", "subnet_public_all_ports_inbound_allow_rules")
    for field in ("subnet", "subnet_has_network_security_group", "subnet_has_route_table", *rule_fields):
        assert east[field] is None, field
    assert west["subnet_has_network_security_group"] is True
    assert west["subnet_network_security_group"] is None
    for field in rule_fields:
        assert west[field] is None, field
    assert west["subnet_route_table"]["name"] == "rt-mi"
    assert summary["instances_subnet_unknown"] == 1
    assert summary["instances_subnet_rules_unknown"] == 2
    assert summary["instances_subnet_network_security_group"] == 1
    assert summary["instances_subnet_unrestricted_internet_outbound"] == 0
    assert summary["instances_subnet_smb_outbound_allow_rule"] == 0
    assert summary["instances_subnet_public_all_ports_inbound_allow_rule"] == 0


def test_smb_outbound_and_public_all_ports_inbound_rules_leave_service_aided_ones_out(monkeypatch):
    rules = [
        rule("smb-out", 300, "Outbound", destination="*", port="445"),
        rule("smb-range-out", 310, "Outbound", protocol="*", destination="Internet", port="400-500"),
        rule("smb-to-vnet", 320, "Outbound", destination="VirtualNetwork", port="445"),
        rule("smb-udp-out", 330, "Outbound", protocol="Udp", destination="*", port="445"),
        rule("Microsoft.Sql-managedInstances_UseOnly_mi-smb-out", 340, "Outbound", destination="*", port="445"),
        rule("partners-in", 400, source=None, port="*", source_address_prefixes=["10.0.0.0/8", "52.1.2.3"]),
        rule("split-ports-in", 410, source="Internet", port=None, destination_port_ranges=["1-1024", "1025-65535"]),
        rule("private-in", 420, source=None, port="*", source_address_prefixes=["10.0.0.0/8", "192.168.1.0/24"]),
        rule("https-in", 430, source="*", port="443"),
        rule("azure-in", 440, source="AzureCloud", port="*"),
        rule("Microsoft.Sql-managedInstances_UseOnly_mi-all-in", 450, source="*", port="*"),
    ]
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), net=network(rules=rules))
    east = instances["mi-east"]
    assert collector.ok
    assert east["subnet_smb_outbound_allow_rules"] == ["smb-out", "smb-range-out"]
    assert east["subnet_public_all_ports_inbound_allow_rules"] == ["partners-in", "split-ports-in", "azure-in"]
    assert east["subnet_allow_any_to_any_rules"] == []
    assert summary["instances_subnet_smb_outbound_allow_rule"] == 2
    assert summary["instances_subnet_public_all_ports_inbound_allow_rule"] == 2
    assert summary["instances_subnet_rules_unknown"] == 0


@pytest.mark.parametrize("prefix,expected", [
    ("*", True), ("Internet", True), ("0.0.0.0/0", True), ("52.1.2.3", True), ("10.0.0.0/7", True), ("::/0", True),
    ("10.1.0.0/16", False), ("172.16.5.0/24", False), ("100.64.0.0/10", False), ("fd00::/8", False),
    ("VirtualNetwork", False), ("AzureCloud", True), ("AzureCloud.eastus", True), ("Storage", False),
])
def test_public_source(prefix, expected):
    assert configuration.public_source(prefix) is expected


@pytest.mark.parametrize("ports,expected", [
    (["*"], True), (["0-65535"], True), (["1-65535"], True), (["1-1024", "1025-65535"], True),
    (["2-65535"], False), (["1-1024", "1026-65535"], False), (["443"], False), ([], False),
])
def test_all_ports_inbound_needs_every_port(ports, expected):
    base = {"access": "Allow", "direction": "Inbound", "source_address_prefix": "Internet",
            "destination_port_ranges": ports}
    assert configuration.allows_public_all_ports_inbound(base) is expected


@pytest.mark.parametrize("fields,expected", [
    ({}, True),
    ({"source_address_prefix": None, "source_address_prefixes": ["10.0.0.0/8", "0.0.0.0/0"]}, True),
    ({"destination_port_range": None, "destination_port_ranges": ["0-65535"]}, True),
    ({"destination_address_prefix": "Internet"}, True),
    ({"access": "Deny"}, False),
    ({"protocol": "Tcp"}, False),
    ({"destination_port_range": "443"}, False),
    ({"source_address_prefix": "VirtualNetwork"}, False),
])
def test_allows_any_to_any(fields, expected):
    base = {"access": "Allow", "protocol": "*", "source_address_prefix": "*",
            "destination_address_prefix": "*", "destination_port_range": "*"}
    assert configuration.allows_any_to_any(base | fields) is expected


def test_maintenance_windows_are_read_once_per_configuration(monkeypatch):
    reads = []
    east_id = WINDOWS["mi-east"]
    windows = {east_id: maintenance_config("SQL_EastUS_MI_1", "Week Monday,Tuesday,Wednesday,Thursday")}
    monkeypatch.setitem(WINDOWS, "mi-west", east_id)
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), windows=windows, reads=reads)
    assert collector.ok
    assert reads == [east_id]
    for mi in ("mi-east", "mi-west"):
        assert instances[mi]["maintenance_window_default"] is False
        assert instances[mi]["maintenance_window"]["recur_every"] == "Week Monday,Tuesday,Wednesday,Thursday"
        assert instances[mi]["maintenance_window"]["duration"] == "08:00"
    assert summary["instances_custom_maintenance_window"] == 2


def test_default_maintenance_window_and_unread_configurations(monkeypatch):
    windows = {WINDOWS["mi-east"]: DENIED,
               WINDOWS["mi-west"]: ResourceNotFoundError("(ResourceNotFound) configuration not found")}
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), windows=windows)
    east, west = instances["mi-east"], instances["mi-west"]
    assert [f["operation"] for f in collector.failures] == [
        "maintenance.publicMaintenanceConfigurations.get (SQL_EastUS_MI_1)"]
    assert east["maintenance_window_default"] is False
    assert east["maintenance_window"] is None
    assert west["maintenance_window_default"] is True
    assert west["maintenance_window"] is None
    assert summary["instances_custom_maintenance_window"] == 1


def test_unregistered_maintenance_provider_skips_the_window_read(monkeypatch):
    reads, maintenance = [], []
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), reads=reads,
                                                      registration="not_registered", maintenance=maintenance)
    assert collector.ok and reads == [] and maintenance == ["not_registered"]
    assert [instances[mi]["maintenance_window"] for mi in ("mi-east", "mi-west")] == [None, None]
    assert (instances["mi-east"]["maintenance_window_default"], instances["mi-west"]["maintenance_window_default"]) \
        == (False, True)
    assert summary["instances_custom_maintenance_window"] == 1


def test_missing_subscription_registration_reads_as_not_registered_not_a_failure(monkeypatch):
    windows = {WINDOWS["mi-east"]: UNREGISTERED, WINDOWS["mi-west"]: UNREGISTERED}
    maintenance = []
    instances, summary, collector = run_configuration(monkeypatch, sql_client(), windows=windows,
                                                      maintenance=maintenance)
    assert collector.ok and maintenance == ["not_registered"]
    assert [instances[mi]["maintenance_window"] for mi in ("mi-east", "mi-west")] == [None, None]
    assert instances["mi-west"]["maintenance_window_default"] is True
    assert summary["instances_custom_maintenance_window"] == 1


def test_instance_without_a_maintenance_configuration_counts_as_unknown(monkeypatch):
    monkeypatch.setitem(WINDOWS, "mi-west", None)
    instances, summary, collector = run_configuration(monkeypatch, sql_client())
    assert collector.ok
    assert instances["mi-west"]["maintenance_window_default"] is None
    assert (summary["instances_custom_maintenance_window"], summary["instances_maintenance_window_unknown"]) == (1, 1)


def test_sensitivity_labels_are_counted_per_user_database(monkeypatch):
    labels = {("rg-east", "mi-east", "app"): [
        ns(label_name="Confidential", information_type="Financial", column_name="card"),
        ns(label_name="Confidential", information_type="Contact Info", column_name="email"),
        ns(label_name="Highly Confidential", information_type=None, column_name="ssn"),
    ]}
    databases = {("rg-east", "mi-east"): [database(MI_EAST, "app"), database(MI_EAST, "master")]}
    instances, summary, collector = run_configuration(monkeypatch, sql_client(labels=labels, databases=databases))
    east, west = instances["mi-east"], instances["mi-west"]
    assert collector.ok
    assert [d["name"] for d in east["user_databases"]] == ["app"]
    app = east["user_databases"][0]
    assert app["sensitivity_labeled_columns"] == 3
    assert app["sensitivity_labels"] == {"Confidential": 2, "Highly Confidential": 1}
    assert app["information_types"] == {"Contact Info": 1, "Financial": 1}
    assert "card" not in str(app)
    assert east["user_databases_with_sensitivity_labels"] == 1
    assert west["user_databases_without_sensitivity_labels"] == 1
    assert summary["total_user_databases"] == 2
    assert summary["user_databases_with_sensitivity_labels"] == 1
    assert summary["user_databases_without_sensitivity_labels"] == 1
    assert summary["sensitivity_labeled_columns"] == 3


def test_one_failed_database_list_leaves_every_database_count_null(monkeypatch):
    labels = {("rg-east", "mi-east", "app"): [ns(label_name="Confidential", information_type="Financial")]}
    client = sql_client(labels=labels, databases={("rg-west", "mi-west"): DENIED})
    instances, summary, _ = run_configuration(monkeypatch, client)
    assert instances["mi-east"]["user_databases_with_sensitivity_labels"] == 1
    assert (summary["total_user_databases"], summary["user_databases_with_sensitivity_labels"],
            summary["user_databases_without_sensitivity_labels"]) == (None, None, None)


def test_failed_label_or_database_reads_are_unknown_not_unlabeled(monkeypatch):
    client = sql_client(labels={("rg-east", "mi-east", "app"): DENIED},
                        databases={("rg-west", "mi-west"): DENIED})
    instances, summary, collector = run_configuration(monkeypatch, client)
    east, west = instances["mi-east"], instances["mi-west"]
    assert not collector.ok
    assert east["user_databases"][0]["sensitivity_labeled_columns"] is None
    assert east["user_databases"][0]["sensitivity_labels"] is None
    assert east["user_databases_sensitivity_labels_unknown"] == 1
    assert east["user_databases_without_sensitivity_labels"] == 0
    assert east["sensitivity_labeled_columns"] is None
    assert west["user_databases"] is None
    assert west["user_databases_with_sensitivity_labels"] is None
    for field in ("total_user_databases", "user_databases_with_sensitivity_labels",
                  "user_databases_without_sensitivity_labels", "user_databases_sensitivity_labels_unknown",
                  "sensitivity_labeled_columns"):
        assert summary[field] is None, field
