#!/usr/bin/env python3
"""Control-plane changes in one subscription, each attributed to an ARM deployment or to a direct edit."""

import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    parse_time,
    report_failure,
    resolve_subscription,
    resource_graph_client,
    resource_graph_rows,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)

logger = logging.getLogger("azure_change_provenance")

MAX_LOOKBACK_DAYS = 14
DEPLOYMENT_HISTORY_CAP = 800
# Measured: Resource Graph restamps a change up to 5 minutes after the operation.
WINDOW_SLACK = timedelta(minutes=10)
CHANGE_TABLES = ("resourcechanges", "resourcecontainerchanges")

CHANGE_COLUMNS = (
    " | where todatetime(properties.changeAttributes.timestamp) > ago({days}d)"
    " | project changeId = tostring(id),"
    " targetResourceId = tostring(properties.targetResourceId),"
    " targetResourceType = tostring(properties.targetResourceType),"
    " changeType = tostring(properties.changeType),"
    " timestamp = tostring(properties.changeAttributes.timestamp),"
    " changedBy = tostring(properties.changeAttributes.changedBy),"
    " changedByType = tostring(properties.changeAttributes.changedByType),"
    " clientType = tostring(properties.changeAttributes.clientType),"
    " operation = tostring(properties.changeAttributes.operation),"
    " correlationId = tostring(properties.changeAttributes.correlationId),"
    " changesCount = toint(properties.changeAttributes.changesCount),"
    " changedProperties = bag_keys(properties.changes)"
    " | order by changeId asc"
)

_DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$")


def parse_duration(value):
    match = _DURATION.match(str(value or ""))
    if not match or not any(match.groups()):
        return None
    days, hours, minutes, seconds = match.groups()
    return timedelta(
        days=int(days or 0), hours=int(hours or 0), minutes=int(minutes or 0), seconds=float(seconds or 0)
    )


def iso(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def deployment_record(deployment, scope: str) -> dict:
    props = model_attr(deployment, "properties")
    finished = parse_time(model_attr(props, "timestamp"))
    duration = parse_duration(model_attr(props, "duration"))
    link = model_attr(props, "template_link")
    outputs = model_attr(props, "output_resources") or []
    return {
        "id": model_attr(deployment, "id"),
        "name": model_attr(deployment, "name"),
        "scope": scope,
        "resource_group": resource_group_from_id(model_attr(deployment, "id")),
        "provisioning_state": model_attr(props, "provisioning_state"),
        "started": iso(finished - duration) if finished and duration is not None else None,
        "timestamp": iso(finished),
        "duration": model_attr(props, "duration"),
        "correlation_id": model_attr(props, "correlation_id") or None,
        "mode": model_attr(props, "mode"),
        "template_hash": model_attr(props, "template_hash"),
        "template_link": model_attr(link, "uri") if link else None,
        "output_resource_ids": sorted({model_attr(r, "id") for r in outputs if model_attr(r, "id")}),
    }


def change_record(row: dict, table: str) -> dict:
    props = row.get("changedProperties")
    return {
        "change_id": row.get("changeId") or None,
        "table": table,
        "target_resource_id": row.get("targetResourceId") or None,
        "target_resource_type": row.get("targetResourceType") or None,
        "resource_group": resource_group_from_id(row.get("targetResourceId")),
        "change_type": row.get("changeType") or None,
        "timestamp": row.get("timestamp") or None,
        "changed_by": row.get("changedBy") or None,
        "changed_by_type": row.get("changedByType") or None,
        "client_type": row.get("clientType") or None,
        "operation": row.get("operation") or None,
        "correlation_id": row.get("correlationId") or None,
        "changes_count": row.get("changesCount"),
        "changed_properties": sorted(props) if isinstance(props, list) else [],
    }


def pipeline_principals() -> set:
    raw = os.environ.get("AZURE_PIPELINE_PRINCIPALS") or ""
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def anonymous(change: dict) -> bool:
    who = {(change["changed_by"] or "").lower(), (change["changed_by_type"] or "").lower()}
    return not change["changed_by"] or bool(who & {"system", "unspecified"})


def attribute(changes: list, deployments: list, pipelines: frozenset = frozenset()) -> list:
    """Mark each change as made by a deployment, a pipeline identity, the platform, or directly."""
    by_correlation = {d["correlation_id"].lower(): d for d in deployments if d["correlation_id"]}
    by_output: dict = {}
    for d in deployments:
        for rid in d["output_resource_ids"]:
            by_output.setdefault(rid.lower(), []).append(d)

    def own(change):
        deployment = by_correlation.get((change["correlation_id"] or "").lower())
        if deployment:
            return "deployment", "correlation_id", deployment
        if (change["changed_by"] or "").lower() in pipelines:
            return "pipeline", None, None
        return "direct", None, None

    named = [c for c in changes if not anonymous(c)]
    verdicts = {c["change_id"]: own(c) for c in named}
    named_by_target: dict = {}
    for c in named:
        named_by_target.setdefault((c["target_resource_id"] or "").lower(), []).append(c)

    # Measured: callerless rows reuse unrelated correlationIds, so they take the nearest named change to the resource.
    def inherited(change):
        target = (change["target_resource_id"] or "").lower()
        when = parse_time(change["timestamp"])
        near = [
            (abs(parse_time(c["timestamp"]) - when), c)
            for c in named_by_target.get(target, [])
            if when and parse_time(c["timestamp"])
        ]
        near = [n for n in near if n[0] <= WINDOW_SLACK]
        if near:
            origin, _, d = verdicts[min(near, key=lambda n: n[0])[1]["change_id"]]
            return origin, "same_resource", d
        for d in by_output.get(target, []):
            start, end = parse_time(d["started"]), parse_time(d["timestamp"])
            if when and start and end and start - WINDOW_SLACK <= when <= end + WINDOW_SLACK:
                return "deployment", "deployment_window", d
        if "system" in ((change["changed_by_type"] or "").lower(), (change["changed_by"] or "").lower()):
            return "platform", None, None
        return "unattributed", None, None

    attributed = []
    for change in changes:
        origin, how, found = inherited(change) if anonymous(change) else verdicts[change["change_id"]]
        attributed.append({
            **change,
            "origin": origin,
            "via_deployment": found is not None,
            "attribution": how,
            "deployment_id": found["id"] if found else None,
        })
    return sorted(attributed, key=lambda c: (c["timestamp"] or "", c["change_id"] or ""))


def summarize(changes: list, deployments: list, at_cap: list) -> dict:
    origins = Counter(c["origin"] for c in changes)
    direct = [c for c in changes if c["origin"] == "direct"]
    redeployed = origins["deployment"] + origins["pipeline"]
    return {
        "total_changes": len(changes),
        "changes_via_deployment": origins["deployment"],
        "changes_via_pipeline": origins["pipeline"],
        "direct_changes": origins["direct"],
        "platform_changes": origins["platform"],
        "unattributed_changes": origins["unattributed"],
        "percent_redeployed": coverage_percentage(redeployed, redeployed + origins["direct"]),
        "direct_changes_by_changed_by_type": sorted_counts(Counter(c["changed_by_type"] or "none" for c in direct)),
        "attribution_by_method": sorted_counts(Counter(c["attribution"] for c in changes if c["attribution"])),
        "direct_changes_by_client_type": sorted_counts(Counter(c["client_type"] or "none" for c in direct)),
        "direct_changes_by_changed_by": sorted_counts(Counter(c["changed_by"] or "none" for c in direct)),
        "direct_changes_by_resource_type": sorted_counts(
            Counter(c["target_resource_type"] or "unknown" for c in direct)
        ),
        "deployments_in_history": len(deployments),
        "deployments_matched_to_changes": len({c["deployment_id"] for c in changes if c["deployment_id"]}),
        "resource_groups_at_deployment_history_cap": at_cap,
    }


def lookback_days(collector: Collector) -> int:
    raw = os.environ.get("AZURE_CHANGE_LOOKBACK_DAYS") or str(MAX_LOOKBACK_DAYS)
    try:
        days = int(raw)
    except ValueError:
        collector.record(
            "config AZURE_CHANGE_LOOKBACK_DAYS",
            ValueError(f"invalid lookback {raw!r}: expected an integer from 1 to {MAX_LOOKBACK_DAYS}"),
        )
        return MAX_LOOKBACK_DAYS
    return min(max(days, 1), MAX_LOOKBACK_DAYS)


def collect_changes(subscription_id, cred, days: int, collector: Collector):
    client = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    if client is None:
        return [], {}
    changes, sources = [], {}
    for table in CHANGE_TABLES:
        query = table + CHANGE_COLUMNS.format(days=days)
        result = collector.guard(
            f"resourcegraph.resources ({table})", lambda q=query: resource_graph_rows(client, subscription_id, q)
        )
        if result is None:
            continue
        sources[table] = {
            "query": query,
            "rows": len(result["rows"]),
            "total_records_reported": result["total_records"],
            "pages": result["pages"],
        }
        changes.extend(change_record(row, table) for row in result["rows"])
    return changes, sources


def collect_deployments(subscription_id, cred, collector: Collector):
    def _clients():
        from azure.mgmt.resource.deployments import DeploymentsMgmtClient  # lazy

        try:
            from azure.mgmt.resource.resources import ResourceManagementClient  # lazy
        except ImportError:  # pragma: no cover - depends on installed SDK version
            from azure.mgmt.resource import ResourceManagementClient  # lazy

        return (
            DeploymentsMgmtClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
            ResourceManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
        )

    clients = collector.guard("deployments.DeploymentsMgmtClient (init)", _clients)
    if clients is None:
        return [], [], 0
    deploy, resources = clients

    deployments = collector.guard(
        "deployments.list_at_subscription_scope",
        lambda: [deployment_record(d, "subscription") for d in deploy.deployments.list_at_subscription_scope()],
        default=[],
    )
    groups = collector.guard(
        "resource.resource_groups.list",
        lambda: sorted(model_attr(g, "name") for g in resources.resource_groups.list()),
        default=[],
    )
    at_cap = []
    for group in groups:
        rows = collector.guard(
            f"deployments.list_by_resource_group({group})",
            lambda g=group: [deployment_record(d, "resource_group") for d in deploy.deployments.list_by_resource_group(g)],
        )
        if rows is None:
            continue
        if len(rows) >= DEPLOYMENT_HISTORY_CAP:
            at_cap.append(group)
        deployments.extend(rows)
    return sorted(deployments, key=lambda d: d["id"] or ""), at_cap, len(groups)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    days = lookback_days(collector)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    changes, sources, deployments, at_cap, groups_read = [], {}, [], [], 0
    if subscription_id and cred is not None:
        changes, sources = collect_changes(subscription_id, cred, days, collector)
        deployments, at_cap, groups_read = collect_deployments(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    pipelines = pipeline_principals()
    attributed = attribute(changes, deployments, frozenset(pipelines))
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "changes": attributed,
            "deployments": deployments,
            "lookback_days": days,
            "pipeline_principals": sorted(pipelines),
            "window_start": iso(datetime.now(timezone.utc) - timedelta(days=days)),
            "change_sources": sources,
            "resource_groups_read": groups_read,
        },
        summary=summarize(attributed, deployments, at_cap),
    )

    filename = f"azure_change_provenance_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s (%d changes, %d deployments)", path, len(attributed), len(deployments))
    return 0


if __name__ == "__main__":
    sys.exit(main())
