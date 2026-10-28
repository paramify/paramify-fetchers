#!/usr/bin/env python3
"""Azure SQL Managed Instance network exposure, TLS, Entra authentication, audit-log export, subnet rules and routes, maintenance window and data classification."""

import ipaddress
import logging
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from arm_rest import arm_rest_client, get_json  # noqa: E402
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    credential,
    dig,
    failure_reason,
    get_optional,
    list_diagnostic_settings,
    model_attr,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    subscription_of,
    write_evidence,
)
from sql_managed_instance import (  # noqa: E402
    list_databases,
    list_instances,
    lower,
    sql_client,
)

logger = logging.getLogger("azure_sql_managed_instance_configuration")

RECOMMENDED_TLS_VERSIONS = ("1.2", "1.3")
AUDIT_CATEGORY = "sqlsecurityauditevents"
AUDIT_CATEGORY_GROUPS = ("audit", "alllogs")
ADMINISTRATOR_TYPE_ENTRA = "activedirectory"
# Rules and routes the instance's service-aided subnet configuration adds and keeps in place.
SERVICE_AIDED_PREFIX = "microsoft.sql-managedinstances_useonly_"
MANAGED_INSTANCE_DELEGATION = "microsoft.sql/managedinstances"
ANY_ADDRESS = ("*", "0.0.0.0/0", "any", "internet")
ALL_PORTS = ("*", "0-65535")
INTERNET_DESTINATIONS = ("*", "0.0.0.0/0", "internet")
SMB_PORT = 445
# Private, shared (CGNAT), loopback and link-local space; a source reaching past these includes public addresses.
NON_PUBLIC_RANGES = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128",
))
# Every Azure datacenter public address, other customers' VMs included; matches AzureCloud and AzureCloud.<region>.
PUBLIC_SERVICE_TAG = "azurecloud"
DEFAULT_MAINTENANCE_CONFIGURATION = "sql_default"
MAINTENANCE_API_VERSION = "2023-04-01"


# --- projection: azure-mgmt models in, flat dicts out ---

def project_instance(instance) -> dict:
    return {
        "id": model_attr(instance, "id"),
        "name": model_attr(instance, "name"),
        "location": model_attr(instance, "location"),
        "state": model_attr(instance, "state"),
        "fully_qualified_domain_name": model_attr(instance, "fully_qualified_domain_name"),
        "public_data_endpoint_enabled": model_attr(instance, "public_data_endpoint_enabled"),
        "proxy_override": model_attr(instance, "proxy_override"),
        "minimal_tls_version": model_attr(instance, "minimal_tls_version"),
        "subnet_id": model_attr(instance, "subnet_id"),
        "maintenance_configuration_id": model_attr(instance, "maintenance_configuration_id"),
        "private_endpoint_connections": [
            {
                "id": model_attr(pec, "id"),
                "private_endpoint_id": model_attr(
                    model_attr(model_attr(pec, "properties"), "private_endpoint"), "id"
                ),
                "status": model_attr(
                    model_attr(
                        model_attr(pec, "properties"), "private_link_service_connection_state"
                    ),
                    "status",
                ),
                "provisioning_state": model_attr(model_attr(pec, "properties"), "provisioning_state"),
            }
            for pec in (model_attr(instance, "private_endpoint_connections") or [])
        ],
    }


def project_administrator(admin) -> dict:
    return {
        "administrator_type": model_attr(admin, "administrator_type"),
        "login": model_attr(admin, "login"),
        "sid": model_attr(admin, "sid"),
        "tenant_id": model_attr(admin, "tenant_id"),
    }


def _ids(models) -> list:
    return [model_attr(m, "id") for m in (models or []) if model_attr(m, "id")]


# Same keys as azure_network_security_groups and azure_vnet_egress_routing, so the records line up.
def project_security_rule(rule) -> dict:
    return {
        "id": model_attr(rule, "id"),
        "name": model_attr(rule, "name"),
        "priority": model_attr(rule, "priority"),
        "direction": model_attr(rule, "direction"),
        "access": model_attr(rule, "access"),
        "protocol": model_attr(rule, "protocol"),
        "source_address_prefix": model_attr(rule, "source_address_prefix"),
        "source_address_prefixes": model_attr(rule, "source_address_prefixes") or [],
        "destination_address_prefix": model_attr(rule, "destination_address_prefix"),
        "destination_address_prefixes": model_attr(rule, "destination_address_prefixes") or [],
        "destination_port_range": model_attr(rule, "destination_port_range"),
        "destination_port_ranges": model_attr(rule, "destination_port_ranges") or [],
        "source_application_security_group_ids": _ids(model_attr(rule, "source_application_security_groups")),
        "destination_application_security_group_ids": _ids(
            model_attr(rule, "destination_application_security_groups")
        ),
    }


def project_security_group(group) -> dict:
    return {
        "id": model_attr(group, "id"),
        "name": model_attr(group, "name"),
        "security_rules": [project_security_rule(r) for r in (model_attr(group, "security_rules") or [])],
        "default_security_rules": [
            project_security_rule(r) for r in (model_attr(group, "default_security_rules") or [])
        ],
    }


def project_route(route) -> dict:
    ecmp = model_attr(model_attr(route, "next_hop"), "next_hop_ip_addresses") or []
    single = model_attr(route, "next_hop_ip_address")
    return {
        "name": model_attr(route, "name"),
        "address_prefix": model_attr(route, "address_prefix"),
        "next_hop_type": model_attr(route, "next_hop_type"),
        "next_hop_ip_addresses": [ip for ip in [single, *ecmp] if ip],
    }


def project_route_table(table) -> dict:
    return {
        "id": model_attr(table, "id"),
        "name": model_attr(table, "name"),
        "disable_bgp_route_propagation": model_attr(table, "disable_bgp_route_propagation"),
        "routes": [project_route(r) for r in (model_attr(table, "routes") or [])],
    }


def project_subnet(subnet) -> dict:
    single = model_attr(subnet, "address_prefix")
    return {
        "id": model_attr(subnet, "id"),
        "name": model_attr(subnet, "name"),
        "address_prefixes": [p for p in [single, *(model_attr(subnet, "address_prefixes") or [])] if p],
        "delegations": [model_attr(d, "service_name") for d in (model_attr(subnet, "delegations") or [])],
        "network_security_group_id": model_attr(model_attr(subnet, "network_security_group"), "id"),
        "route_table_id": model_attr(model_attr(subnet, "route_table"), "id"),
    }


def project_maintenance_configuration(body: dict) -> dict:
    window = dig(body, "properties", "maintenanceWindow") or {}
    return {
        "id": body.get("id"),
        "name": body.get("name"),
        "maintenance_scope": dig(body, "properties", "maintenanceScope"),
        "start_date_time": window.get("startDateTime"),
        "expiration_date_time": window.get("expirationDateTime"),
        "duration": window.get("duration"),
        "time_zone": window.get("timeZone"),
        "recur_every": window.get("recurEvery"),
    }


def project_sensitivity_label(label) -> dict:
    return {
        "label_name": model_attr(label, "label_name"),
        "information_type": model_attr(label, "information_type"),
    }


# --- pure transforms (flat dicts in, evidence records out) ---

# Proves a route, not that auditing is on; possible fix: query the destination workspace for recent SQLSecurityAuditEvents.
def exports_audit_logs(settings: list[dict] | None) -> bool | None:
    if settings is None:
        return None
    return any(
        log["enabled"]
        and (
            lower(log.get("category")) == AUDIT_CATEGORY
            or lower(log.get("category_group")) in AUDIT_CATEGORY_GROUPS
        )
        for setting in settings
        for log in setting.get("logs") or []
    )


def service_aided(name) -> bool:
    return lower(name).startswith(SERVICE_AIDED_PREFIX)


def _values(rule: dict, single: str, plural: str) -> list:
    return [v for v in [rule.get(single), *(rule.get(plural) or [])] if v]


def allows_any_to_any(rule: dict) -> bool:
    """An Allow on every protocol and port from any address to any address."""
    return (
        lower(rule.get("access")) == "allow"
        and rule.get("protocol") == "*"
        and any(p in ALL_PORTS for p in _values(rule, "destination_port_range", "destination_port_ranges"))
        and any(lower(a) in ANY_ADDRESS for a in _values(rule, "source_address_prefix", "source_address_prefixes"))
        and any(
            lower(a) in ANY_ADDRESS
            for a in _values(rule, "destination_address_prefix", "destination_address_prefixes")
        )
    )


def _port_span(value):
    if value == "*":
        return 0, 65535
    low, _, high = str(value).partition("-")
    try:
        return int(low), int(high or low)
    except ValueError:
        return None


def _covers_all_ports(values) -> bool:
    """Ranges merged, so 1-1024 plus 1025-65535 counts; port 0 is not needed."""
    reach = 0
    for low, high in sorted(s for s in map(_port_span, values) if s):
        if low > reach + 1:
            return False
        reach = max(reach, high)
    return reach >= 65535


def public_source(prefix) -> bool:
    """*, Any, Internet, 0.0.0.0/0, AzureCloud, or an address range reaching past non-public space; other service tags don't count."""
    if lower(prefix) in ANY_ADDRESS or lower(prefix).split(".")[0] == PUBLIC_SERVICE_TAG:
        return True
    try:
        net = ipaddress.ip_network(str(prefix), strict=False)
    except ValueError:
        return False
    return not any(net.version == r.version and net.subnet_of(r) for r in NON_PUBLIC_RANGES)  # type: ignore[arg-type]


def allows_smb_outbound(rule: dict) -> bool:
    """An outbound Allow on TCP (or any protocol) covering port 445 to any address."""
    return (
        lower(rule.get("access")) == "allow"
        and lower(rule.get("direction")) == "outbound"
        and lower(rule.get("protocol")) in ("tcp", "*")
        and any(
            (span := _port_span(p)) is not None and span[0] <= SMB_PORT <= span[1]
            for p in _values(rule, "destination_port_range", "destination_port_ranges")
        )
        and any(
            lower(a) in ANY_ADDRESS
            for a in _values(rule, "destination_address_prefix", "destination_address_prefixes")
        )
    )


def allows_public_all_ports_inbound(rule: dict) -> bool:
    """An inbound Allow on every port, whatever its protocol, from a source list that includes public addresses."""
    return (
        lower(rule.get("access")) == "allow"
        and lower(rule.get("direction")) == "inbound"
        and _covers_all_ports(_values(rule, "destination_port_range", "destination_port_ranges"))
        and any(public_source(a) for a in _values(rule, "source_address_prefix", "source_address_prefixes"))
    )


# Same reading as azure_network_security_groups: the first all-port, all-protocol outbound rule to the Internet decides.
def unrestricted_internet_outbound(group: dict) -> bool:
    rules = sorted(
        (*group["security_rules"], *group["default_security_rules"]),
        key=lambda r: r["priority"] if isinstance(r.get("priority"), int) else 1 << 30,
    )
    for rule in rules:
        if (
            lower(rule.get("direction")) == "outbound"
            and rule.get("protocol") == "*"
            and "*" in _values(rule, "destination_port_range", "destination_port_ranges")
            and any(
                lower(d) in INTERNET_DESTINATIONS
                for d in _values(rule, "destination_address_prefix", "destination_address_prefixes")
            )
        ):
            return lower(rule.get("access")) == "allow"
    return False


def subnet_fields(subnet: dict | None, group: dict | None, table: dict | None) -> dict:
    """Null wherever the read it needs failed; a subnet with no NSG or route table reads false."""
    has_group = None if subnet is None else subnet.get("network_security_group_id") is not None
    has_table = None if subnet is None else subnet.get("route_table_id") is not None
    if group is not None:
        group = {
            **group,
            "security_rules": [{**r, "service_aided": service_aided(r["name"])} for r in group["security_rules"]],
        }
    if table is not None:
        table = {**table, "routes": [{**r, "service_aided": service_aided(r["name"])} for r in table["routes"]]}

    def customer_rules(test) -> list | None:
        """Names of the custom rules, service-aided ones left out, that pass `test`."""
        if has_group is False:
            return []
        return None if group is None else [
            r["name"] for r in group["security_rules"] if not r["service_aided"] and test(r)
        ]

    return {
        "subnet": subnet,
        "subnet_delegated_to_managed_instance": None if subnet is None else any(
            lower(d) == MANAGED_INSTANCE_DELEGATION for d in subnet["delegations"]
        ),
        "subnet_has_network_security_group": has_group,
        "subnet_network_security_group": group,
        "subnet_allow_any_to_any_rules": (
            [] if has_group is False
            else None if group is None
            else [r["name"] for r in group["security_rules"] if allows_any_to_any(r)]
        ),
        # No NSG on the subnet filters nothing.
        "subnet_unrestricted_internet_outbound": (
            True if has_group is False
            else None if group is None
            else unrestricted_internet_outbound(group)
        ),
        "subnet_smb_outbound_allow_rules": customer_rules(allows_smb_outbound),
        "subnet_public_all_ports_inbound_allow_rules": customer_rules(allows_public_all_ports_inbound),
        "subnet_has_route_table": has_table,
        "subnet_route_table": table,
    }


def maintenance_fields(configuration_id, window: dict | None) -> dict:
    return {
        "maintenance_window_default": (
            None if not configuration_id
            else lower(basename(configuration_id)) == DEFAULT_MAINTENANCE_CONFIGURATION
        ),
        "maintenance_window": window,
    }


def database_classification(database: dict, labels: list[dict] | None) -> dict:
    return {
        "id": database.get("id"),
        "name": database.get("name"),
        "status": database.get("status"),
        "sensitivity_labeled_columns": None if labels is None else len(labels),
        "sensitivity_labels": None if labels is None else sorted_counts(
            Counter(label["label_name"] for label in labels if label["label_name"])
        ),
        "information_types": None if labels is None else sorted_counts(
            Counter(label["information_type"] for label in labels if label["information_type"])
        ),
    }


def classification_fields(databases: list[dict] | None) -> dict:
    """Per-instance counts, null when the database list failed; a database whose labels failed counts as unknown."""
    counts = [d["sensitivity_labeled_columns"] for d in databases or []]
    return {
        "user_databases": databases,
        "user_databases_with_sensitivity_labels": None if databases is None else sum(1 for c in counts if c),
        "user_databases_without_sensitivity_labels": None if databases is None else counts.count(0),
        "user_databases_sensitivity_labels_unknown": None if databases is None else counts.count(None),
        "sensitivity_labeled_columns": None if databases is None or None in counts else sum(counts),
    }


def instance_record(
    instance: dict,
    administrators: list[dict] | None,
    entra_only: bool | None,
    diagnostic_settings: list[dict] | None,
) -> dict:
    public = instance.get("public_data_endpoint_enabled")
    tls = instance.get("minimal_tls_version")
    connections = instance.get("private_endpoint_connections") or []
    return {
        **instance,
        "private_access_only": None if public is None else public is False,
        "minimal_tls_version_recommended": tls in RECOMMENDED_TLS_VERSIONS,
        "approved_private_endpoints": sum(1 for c in connections if lower(c.get("status")) == "approved"),
        "administrators": administrators,
        "entra_administrator_configured": None if administrators is None else any(
            lower(a.get("administrator_type")) == ADMINISTRATOR_TYPE_ENTRA for a in administrators
        ),
        "azure_ad_only_authentication": entra_only,
        "diagnostic_settings": diagnostic_settings,
        "audit_logs_exported": exports_audit_logs(diagnostic_settings),
        "audit_log_destinations": None if diagnostic_settings is None else sorted(
            {
                dest
                for s in diagnostic_settings
                if exports_audit_logs([s])
                for dest in (
                    s.get("workspace_id"),
                    s.get("storage_account_id"),
                    # The hub name is optional (Azure then makes one per category); the rule id is not.
                    s.get("event_hub_authorization_rule_id") or s.get("event_hub_name"),
                )
                if dest
            }
        ),
    }


def summarize(instances: list[dict]) -> dict:
    listed = all(i["user_databases"] is not None for i in instances)
    columns = [i["sensitivity_labeled_columns"] for i in instances]
    return {
        "total_managed_instances": len(instances),
        "instances_public_data_endpoint_enabled": sum(
            1 for i in instances if i.get("public_data_endpoint_enabled") is True
        ),
        "instances_private_access_only": sum(1 for i in instances if i["private_access_only"]),
        "instances_with_approved_private_endpoint": sum(
            1 for i in instances if i["approved_private_endpoints"]
        ),
        "instances_minimal_tls_recommended": sum(
            1 for i in instances if i["minimal_tls_version_recommended"]
        ),
        "instances_entra_administrator": sum(
            1 for i in instances if i["entra_administrator_configured"] is True
        ),
        "instances_entra_only_authentication": sum(
            1 for i in instances if i["azure_ad_only_authentication"] is True
        ),
        "instances_audit_logs_exported": sum(1 for i in instances if i["audit_logs_exported"] is True),
        "instances_subnet_unknown": sum(1 for i in instances if i["subnet"] is None),
        "instances_subnet_rules_unknown": sum(1 for i in instances if i["subnet_allow_any_to_any_rules"] is None),
        "instances_subnet_network_security_group": sum(
            1 for i in instances if i["subnet_has_network_security_group"] is True
        ),
        "instances_subnet_allow_any_to_any_rule": sum(1 for i in instances if i["subnet_allow_any_to_any_rules"]),
        "instances_subnet_unrestricted_internet_outbound": sum(
            1 for i in instances if i["subnet_unrestricted_internet_outbound"] is True
        ),
        "instances_subnet_smb_outbound_allow_rule": sum(1 for i in instances if i["subnet_smb_outbound_allow_rules"]),
        "instances_subnet_public_all_ports_inbound_allow_rule": sum(
            1 for i in instances if i["subnet_public_all_ports_inbound_allow_rules"]
        ),
        "instances_subnet_route_table": sum(1 for i in instances if i["subnet_has_route_table"] is True),
        "instances_custom_maintenance_window": sum(
            1 for i in instances if i["maintenance_window_default"] is False
        ),
        "total_user_databases": sum(len(i["user_databases"]) for i in instances) if listed else None,
        "user_databases_with_sensitivity_labels": sum(
            i["user_databases_with_sensitivity_labels"] or 0 for i in instances
        ),
        "user_databases_without_sensitivity_labels": sum(
            i["user_databases_without_sensitivity_labels"] or 0 for i in instances
        ),
        "user_databases_sensitivity_labels_unknown": sum(
            i["user_databases_sensitivity_labels_unknown"] or 0 for i in instances
        ),
        "sensitivity_labeled_columns": None if None in columns else sum(columns),
    }


# --- collection (lazy azure imports) ---

def network_client(subscription_id, cred):
    from azure.mgmt.network import NetworkManagementClient  # lazy

    return NetworkManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())


def _segment(resource_id, kind: str):
    parts = (resource_id or "").split("/")
    return next((parts[i + 1] for i, part in enumerate(parts[:-1]) if part.lower() == kind), None)


def read_subnet(network, collector: Collector, instance: dict) -> dict:
    """Point reads of the instance's subnet, then the NSG and route table it names."""
    name = instance["name"]

    def get(resource_id, operation, read):
        client = network(resource_id) if resource_id else None
        return None if client is None else collector.guard(f"{operation} ({name})", lambda: read(client))

    subnet_id = instance.get("subnet_id")
    subnet = get(subnet_id, "network.subnets.get", lambda c: project_subnet(c.subnets.get(
        resource_group_from_id(subnet_id), _segment(subnet_id, "virtualnetworks"), _segment(subnet_id, "subnets")
    )))
    group_id = (subnet or {}).get("network_security_group_id")
    table_id = (subnet or {}).get("route_table_id")
    group = get(group_id, "network.network_security_groups.get", lambda c: project_security_group(
        c.network_security_groups.get(resource_group_from_id(group_id), basename(group_id))
    ))
    table = get(table_id, "network.route_tables.get", lambda c: project_route_table(
        c.route_tables.get(resource_group_from_id(table_id), basename(table_id))
    ))
    return subnet_fields(subnet, group, table)


def read_maintenance_windows(cred, collector: Collector, configuration_ids) -> dict:
    """Each public maintenance configuration once, keyed by lower-cased id; a 404 reads as no window, not a failure."""
    ids = {cid.lower(): cid for cid in configuration_ids if cid}
    rest = collector.guard("arm_rest.ARMPipelineClient (init)", lambda: arm_rest_client(cred)) if ids else None
    if rest is None:
        return {}
    return {
        key: get_optional(
            collector,
            f"maintenance.publicMaintenanceConfigurations.get ({basename(cid)})",
            lambda: project_maintenance_configuration(
                get_json(rest, f"{cid}?api-version={MAINTENANCE_API_VERSION}")
            ),
        )[0]
        for key, cid in sorted(ids.items())
    }


def classify_databases(client, collector: Collector, instance: dict) -> list[dict] | None:
    """Current sensitivity labels per user database; None when the database list failed."""
    group, name = instance["resource_group"], instance["name"]
    databases = list_databases(client, collector, instance)
    if databases is None:
        return None
    rows = []
    for database in databases:
        if database["is_system_database"]:
            continue
        db = database["name"]
        labels = collector.guard(
            f"sql.managed_database_sensitivity_labels.list_current_by_database ({name}/{db})",
            lambda: [
                project_sensitivity_label(label)
                for label in client.managed_database_sensitivity_labels.list_current_by_database(group, name, db)
            ],
        )
        rows.append(database_classification(database, labels))
    return sorted(rows, key=lambda d: d.get("id") or "")


def collect(subscription_id, cred, collector: Collector) -> list[dict]:
    client = sql_client(subscription_id, cred, collector)
    if client is None:
        return []
    instances = list_instances(client, collector, project_instance)
    monitor = (
        collector.guard(
            "monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred)
        )
        if instances
        else None
    )
    networks: dict = {}

    def network(resource_id):
        sub = subscription_of(resource_id) or str(subscription_id).lower()
        if sub not in networks:
            networks[sub] = collector.guard(
                "network.NetworkManagementClient (init)", lambda: network_client(sub, cred)
            )
        return networks[sub]

    windows = read_maintenance_windows(
        cred, collector, [i.get("maintenance_configuration_id") for i in instances]
    )

    records = []
    for instance in instances:
        group, name = instance["resource_group"], instance["name"]
        administrators = collector.guard(
            f"sql.managed_instance_administrators.list_by_instance ({name})",
            lambda: [
                project_administrator(a)
                for a in client.managed_instance_administrators.list_by_instance(group, name)
            ],
        )
        entra_only = collector.guard(
            f"sql.managed_instance_azure_ad_only_authentications.list_by_instance ({name})",
            lambda: any(
                model_attr(a, "azure_ad_only_authentication") is True
                for a in client.managed_instance_azure_ad_only_authentications.list_by_instance(
                    group, name
                )
            ),
        )
        settings = (
            collector.guard(
                f"monitor.diagnostic_settings.list ({name})",
                lambda: list_diagnostic_settings(monitor, instance["id"]),
            )
            if monitor is not None
            else None
        )
        configuration_id = instance.get("maintenance_configuration_id")
        records.append({
            **instance_record(instance, administrators, entra_only, settings),
            **read_subnet(network, collector, instance),
            **maintenance_fields(configuration_id, windows.get(lower(configuration_id))),
            **classification_fields(classify_databases(client, collector, instance)),
        })

    return sorted(records, key=lambda i: i.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    instances: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Sql"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Sql is not registered on subscription %s — no SQL Managed "
                "Instance in use; reporting status not_registered",
                subscription_id,
            )
        instances = collect(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "managed_instances": instances,
            "provider_registration_status": registration,
        },
        summary={**summarize(instances), "provider_registration_status": registration},
    )

    filename = (
        f"azure_sql_managed_instance_configuration_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s", path)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
