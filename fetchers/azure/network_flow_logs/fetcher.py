#!/usr/bin/env python3
"""Azure Network Watcher and flow logs: what traffic is logged, where it goes, and which networks it misses."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_network_flow_logs")

# Flow log targets, keyed by the ARM type segment of targetResourceId.
TARGET_TYPES = {
    "networksecuritygroups": "network_security_group",
    "virtualnetworks": "virtual_network",
    "subnets": "subnet",
    "networkinterfaces": "network_interface",
}
# Platform subnets Azure does not let you attach an NSG to, so no NSG flow log can cover them.
NO_NSG_SUBNETS = {"gatewaysubnet", "azurefirewallsubnet", "azurefirewallmanagementsubnet", "routeserversubnet"}
# Subnet sub-resources that mean something is deployed in it.
IN_USE_FIELDS = (
    "ip_configurations",
    "private_endpoints",
    "service_association_links",
    "resource_navigation_links",
    "application_gateway_ip_configurations",
)
RETENTION_THRESHOLDS = (90, 365)
FULL_SOURCES = ("vnet", "subnet", "nsg")
FILTERED_SOURCES = ("vnet_filtered", "subnet_filtered")


def target_type(target_id) -> str:
    """The flow log's scope, from the second-to-last segment of its target id."""
    parts = (target_id or "").rstrip("/").split("/")
    return TARGET_TYPES.get(parts[-2].lower(), "unknown") if len(parts) >= 2 else "unknown"


def region(location) -> str:
    return (location or "").replace(" ", "").lower()


def project_watcher(watcher) -> dict:
    return {
        "id": model_attr(watcher, "id"),
        "name": model_attr(watcher, "name"),
        "location": region(model_attr(watcher, "location")),
        "provisioning_state": model_attr(watcher, "provisioning_state"),
    }


def project_flow_log(flow_log) -> dict:
    target = model_attr(flow_log, "target_resource_id")
    retention = model_attr(flow_log, "retention_policy")
    fmt = model_attr(flow_log, "format")
    analytics = model_attr(
        model_attr(flow_log, "flow_analytics_configuration"),
        "network_watcher_flow_analytics_configuration",
    )
    storage = model_attr(flow_log, "storage_id")
    policy_enabled = bool(model_attr(retention, "enabled") or False)
    days = model_attr(retention, "days")
    # Storage keeps flow log records until a retention policy deletes them, so no policy
    # (or a policy of 0 days) means they are kept indefinitely.
    indefinite = not policy_enabled or not days
    kind = target_type(target)
    return {
        "id": model_attr(flow_log, "id"),
        "name": model_attr(flow_log, "name"),
        "location": region(model_attr(flow_log, "location")),
        "enabled": bool(model_attr(flow_log, "enabled") or False),
        "provisioning_state": model_attr(flow_log, "provisioning_state"),
        "target_resource_id": target,
        "target_resource_name": basename(target),
        "target_type": kind,
        "legacy_nsg_flow_log": kind == "network_security_group",
        "enabled_filtering_criteria": model_attr(flow_log, "enabled_filtering_criteria") or None,
        "storage_account_id": storage,
        "storage_account_name": basename(storage),
        "storage_account_resource_group": resource_group_from_id(storage),
        "retention_policy_enabled": policy_enabled,
        "retained_indefinitely": indefinite,
        "retention_days": None if indefinite else days,
        "format_type": model_attr(fmt, "type"),
        "format_version": model_attr(fmt, "version"),
        "traffic_analytics_enabled": bool(model_attr(analytics, "enabled") or False),
        "traffic_analytics_interval_minutes": model_attr(analytics, "traffic_analytics_interval"),
        "traffic_analytics_workspace_id": model_attr(analytics, "workspace_resource_id"),
    }


def project_vnet(vnet) -> dict:
    return {
        "id": model_attr(vnet, "id"),
        "name": model_attr(vnet, "name"),
        "location": region(model_attr(vnet, "location")),
        "subnets": [
            {
                "id": model_attr(subnet, "id"),
                "name": model_attr(subnet, "name"),
                "address_prefix": model_attr(subnet, "address_prefix")
                or ", ".join(model_attr(subnet, "address_prefixes") or []),
                "network_security_group_id": model_attr(model_attr(subnet, "network_security_group"), "id"),
                "nsg_supported": (model_attr(subnet, "name") or "").lower() not in NO_NSG_SUBNETS,
                "in_use": any(model_attr(subnet, f) for f in IN_USE_FIELDS),
            }
            for subnet in model_attr(vnet, "subnets") or []
        ],
    }


def project_nsg(nsg) -> dict:
    return {
        "id": (model_attr(nsg, "id") or "").lower(),
        "attached": bool(model_attr(nsg, "subnets") or model_attr(nsg, "network_interfaces")),
    }


def target_attached(flow_log: dict, nsgs, vnets):
    """Whether the flow log's target exists and has traffic to log; None when that can't be told.

    `nsgs` / `vnets` are None when their list could not be read, which leaves their targets unknown.

    An NSG must be attached to a subnet or network interface; a VNet or subnet must exist.
    Network interface targets are not checked.
    """
    target = (flow_log["target_resource_id"] or "").lower()
    kind = flow_log["target_type"]
    if kind == "network_security_group":
        return None if nsgs is None else nsgs.get(target, False)
    if kind in ("virtual_network", "subnet") and vnets is None:
        return None
    if kind == "virtual_network":
        return any((v["id"] or "").lower() == target for v in vnets)
    if kind == "subnet":
        return any((s["id"] or "").lower() == target for v in vnets for s in v["subnets"])
    return None


def subnet_coverage(subnet: dict, vnet: dict, enabled_by_target: dict, uncertain_regions: set) -> dict:
    """How a subnet's traffic is flow-logged.

    vnet / subnet          — an enabled, unfiltered VNet flow log on the VNet or the subnet
    nsg                    — an enabled (legacy) NSG flow log on the subnet's NSG
    vnet_filtered / subnet_filtered — a VNet flow log that logs only traffic matching a filter
    none                   — nothing logs it
    unknown                — not covered by what was read, but flow logs in its region could not be listed

    Azure applies only the most specific VNet flow log (network interface > subnet > VNet), so a subnet's
    own log, filtered or not, replaces the VNet's. An NSG flow log is a separate mechanism and counts on
    its own. flow_log_sources still lists every log found.
    """
    sources = []
    for key, label in (
        (vnet["id"], "vnet"),
        (subnet["id"], "subnet"),
        (subnet["network_security_group_id"], "nsg"),
    ):
        log = enabled_by_target.get((key or "").lower())
        if log is not None:
            filtered = label != "nsg" and log["enabled_filtering_criteria"]
            sources.append(f"{label}_filtered" if filtered else label)
    vnet_family = [s for s in sources if s.startswith("subnet")] or [s for s in sources if s.startswith("vnet")]
    in_effect = vnet_family[:1] + [s for s in sources if s == "nsg"]
    full = [s for s in in_effect if s in FULL_SOURCES]
    if full:
        status = full[0]
    elif in_effect:
        status = in_effect[0]
    elif vnet["location"] in uncertain_regions:
        status = "unknown"
    else:
        status = "none"
    return {**subnet, "flow_log_sources": sources, "coverage": status}


def vnet_record(vnet: dict, enabled_by_target: dict, uncertain_regions: set, watcher_regions) -> dict:
    subnets = [subnet_coverage(s, vnet, enabled_by_target, uncertain_regions) for s in vnet["subnets"]]
    statuses = {s["coverage"] for s in subnets}
    if not subnets:
        # No subnets: judged on the VNet's own flow log, with the same filter and region rules as a subnet.
        log = enabled_by_target.get((vnet["id"] or "").lower())
        if log is not None:
            coverage = "partial" if log["enabled_filtering_criteria"] else "full"
        elif vnet["location"] in uncertain_regions:
            coverage = "unknown"
        else:
            coverage = "none"
    elif statuses <= set(FULL_SOURCES):
        coverage = "full"
    elif "unknown" in statuses:
        coverage = "unknown"
    elif statuses == {"none"}:
        coverage = "none"
    else:
        coverage = "partial"
    return {
        **vnet,
        "resource_group": resource_group_from_id(vnet["id"]),
        "network_watcher_in_region": None if watcher_regions is None else vnet["location"] in watcher_regions,
        "subnets": subnets,
        "coverage": coverage,
    }


def summarize(watchers, flow_logs, vnet_records) -> dict:
    """`vnet_records` is None when the VNet list could not be read; its coverage figures are then null."""
    vnets = vnet_records or []
    enabled = [f for f in flow_logs if f["enabled"]]
    subnets = [s for v in vnets for s in v["subnets"]]
    in_use = [s for s in subnets if s["in_use"]]
    finite = [f["retention_days"] for f in enabled if f["retention_days"] is not None]
    missing_watcher = sorted({v["location"] for v in vnets if v["network_watcher_in_region"] is False})

    def count(items, pred):
        return sum(1 for i in items if pred(i))

    summary = {
        "total_network_watchers": len(watchers),
        "regions_with_virtual_networks": sorted({v["location"] for v in vnets}),
        # Populated only when the watcher list was read; a failed read never reads as "missing".
        "regions_with_virtual_networks_without_network_watcher": missing_watcher,
        "regions_without_network_watcher_count": len(missing_watcher),
        "total_flow_logs": len(flow_logs),
        "enabled_flow_logs": len(enabled),
        "disabled_flow_logs": len(flow_logs) - len(enabled),
        "flow_logs_by_target_type": {
            kind: count(flow_logs, lambda f, kind=kind: f["target_type"] == kind)
            for kind in sorted({f["target_type"] for f in flow_logs})
        },
        "legacy_nsg_flow_logs": count(flow_logs, lambda f: f["legacy_nsg_flow_log"]),
        # VNet flow logs can target a VNet, a subnet or a network interface; NSG flow logs are the legacy kind.
        "vnet_flow_logs": count(
            flow_logs, lambda f: f["target_type"] in ("virtual_network", "subnet", "network_interface")
        ),
        "enabled_flow_logs_filtered": count(enabled, lambda f: f["enabled_filtering_criteria"]),
        "enabled_flow_logs_on_unattached_targets": count(enabled, lambda f: f["target_attached"] is False),
        "enabled_flow_logs_with_traffic_analytics": count(enabled, lambda f: f["traffic_analytics_enabled"]),
        "enabled_flow_logs_traffic_analytics_every_10_minutes": count(
            enabled, lambda f: f["traffic_analytics_enabled"] and f["traffic_analytics_interval_minutes"] == 10
        ),
        "enabled_flow_logs_retained_indefinitely": count(enabled, lambda f: f["retained_indefinitely"]),
        # Smallest finite retention; null when every enabled flow log keeps records indefinitely.
        "minimum_retention_days": min(finite) if finite else None,
        "total_virtual_networks": len(vnets),
        "virtual_networks_fully_covered": count(vnets, lambda v: v["coverage"] == "full"),
        "virtual_networks_partially_covered": count(vnets, lambda v: v["coverage"] == "partial"),
        "virtual_networks_not_covered": count(vnets, lambda v: v["coverage"] == "none"),
        "virtual_networks_coverage_unknown": count(vnets, lambda v: v["coverage"] == "unknown"),
        "total_subnets": len(subnets),
        "subnets_covered": count(subnets, lambda s: s["coverage"] in FULL_SOURCES),
        "subnets_covered_percentage": coverage_percentage(
            count(subnets, lambda s: s["coverage"] in FULL_SOURCES), len(subnets)
        ),
        "subnets_in_use": len(in_use),
        "subnets_in_use_covered": count(in_use, lambda s: s["coverage"] in FULL_SOURCES),
        "subnets_in_use_covered_filtered": count(in_use, lambda s: s["coverage"] in FILTERED_SOURCES),
        "subnets_in_use_not_covered": count(in_use, lambda s: s["coverage"] == "none"),
        "subnets_in_use_coverage_unknown": count(in_use, lambda s: s["coverage"] == "unknown"),
        "subnets_in_use_covered_percentage": coverage_percentage(
            count(in_use, lambda s: s["coverage"] in FULL_SOURCES), len(in_use)
        ),
        "subnets_in_use_without_nsg": count(
            in_use, lambda s: s["nsg_supported"] and not s["network_security_group_id"]
        ),
        "subnets_in_use_nsg_not_supported": count(in_use, lambda s: not s["nsg_supported"]),
        "enabled_flow_logs_target_unknown": count(enabled, lambda f: f["target_attached"] is None),
        "virtual_networks_read": vnet_records is not None,
    }
    if vnet_records is None:
        # A failed VNet read is unknown coverage, never "no networks" or "nothing covered".
        for key in list(summary):
            if key.startswith(("total_virtual_networks", "virtual_networks_", "total_subnets", "subnets_",
                               "regions_with_virtual_networks", "regions_without_network_watcher")):
                if key != "virtual_networks_read":
                    summary[key] = None
    for days in RETENTION_THRESHOLDS:
        summary[f"enabled_flow_logs_retained_under_{days}_days"] = count(
            enabled, lambda f, days=days: f["retention_days"] is not None and f["retention_days"] < days
        )
    return summary


def collect(subscription_id, cred, collector: Collector) -> tuple:
    def _client():
        from azure.mgmt.network import NetworkManagementClient  # lazy

        return NetworkManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("network.NetworkManagementClient (init)", _client)
    if client is None:
        return [], [], []
    watchers = collector.guard(
        "network.network_watchers.list_all",
        lambda: [project_watcher(w) for w in client.network_watchers.list_all()],
    )
    flow_logs, uncertain_regions = [], set()
    for watcher in watchers or []:
        rg = resource_group_from_id(watcher["id"])
        logs = collector.guard(
            f"network.flow_logs.list({rg}/{watcher['name']})",
            lambda: [project_flow_log(f) for f in client.flow_logs.list(rg, watcher["name"])],
        )
        if logs is None:
            uncertain_regions.add(watcher["location"])
        else:
            flow_logs.extend(logs)
    vnets = collector.guard(
        "network.virtual_networks.list_all",
        lambda: [project_vnet(v) for v in client.virtual_networks.list_all()],
    )
    nsgs = None
    if any(f["target_type"] == "network_security_group" for f in flow_logs):
        nsg_rows = collector.guard(
            "network.network_security_groups.list_all",
            lambda: [project_nsg(n) for n in client.network_security_groups.list_all()],
        )
        nsgs = None if nsg_rows is None else {n["id"]: n["attached"] for n in nsg_rows}
    watcher_regions = None if watchers is None else {w["location"] for w in watchers}
    if watchers is None:
        uncertain_regions.update(v["location"] for v in vnets or [])
    for f in flow_logs:
        f["target_attached"] = target_attached(f, nsgs, vnets)
    enabled_by_target = {(f["target_resource_id"] or "").lower(): f for f in flow_logs if f["enabled"]}
    records = None if vnets is None else sorted(
        (vnet_record(v, enabled_by_target, uncertain_regions, watcher_regions) for v in vnets),
        key=lambda r: r["id"] or "",
    )
    return (
        sorted(watchers or [], key=lambda r: r["id"] or ""),
        sorted(flow_logs, key=lambda r: r["id"] or ""),
        records,
    )


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

    watchers: list = []
    flow_logs: list = []
    vnets: list = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Network is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        watchers, flow_logs, vnets = collect(subscription_id, cred, collector)
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
            "network_watchers": watchers,
            "flow_logs": flow_logs,
            "virtual_networks": vnets,
            "provider_registration_status": registration,
        },
        summary={**summarize(watchers, flow_logs, vnets), "provider_registration_status": registration},
    )
    filename = f"azure_network_flow_logs_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
