#!/usr/bin/env python3
"""Azure resource inventory for one subscription, from Azure Resource Graph, with each resource's Defender and Policy coverage.

One query over the `Resources` table instead of one list call per service, so the
inventory covers every resource type ARM knows about — including the ones no other
fetcher in this category reads. Two more queries read Defender for Cloud assessments
(`SecurityResources`) and Azure Policy states (`PolicyResources`); they are separate
queries joined here by resource id because Resource Graph allows one cross-table join
per query and pages `summarize` only to its first page. Resource Graph pages at most
1000 rows; every query follows `$skipToken` to the end and treats a truncated or short
result as a collection failure, never as a smaller inventory or a coverage gap.

Resource Graph is eventually consistent with ARM (typically seconds, occasionally
minutes), and returns only what the caller can read, so a Reader gap reads as a
missing resource rather than an error.
"""

import logging
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    report_failure,
    resolve_subscription,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from resource_graph import query_all, resource_graph_client  # noqa: E402

logger = logging.getLogger("azure_resource_inventory")

# `order by id` keeps paging stable across skip tokens. The provisioning state lives
# in each type's own `properties` bag, so it is lifted out as a string.
INVENTORY_QUERY = (
    "Resources"
    " | project id, name, type, location, resourceGroup, tags, sku, kind,"
    " provisioningState = tostring(properties.provisioningState)"
    " | order by id asc"
)

DEFENDER_QUERY = (
    "SecurityResources"
    " | where type =~ 'microsoft.security/assessments'"
    " | project id, resourceDetails = properties.resourceDetails,"
    " status = tostring(properties.status.code), severity = tostring(properties.metadata.severity)"
    " | order by id asc"
)

POLICY_QUERY = (
    "PolicyResources"
    " | where type =~ 'microsoft.policyinsights/policystates'"
    " | project id, resourceId = tostring(properties.resourceId),"
    " complianceState = tostring(properties.complianceState)"
    " | order by id asc"
)

ASSESSMENT_ID_MARKER = "/providers/microsoft.security/assessments/"
UNHEALTHY = "unhealthy"
# NotApplicable means the assessment did not happen (OffByPolicy and the like), so it is not coverage.
ASSESSED = frozenset({"healthy", UNHEALTHY})
HIGH_SEVERITIES = frozenset({"high", "critical"})
NON_COMPLIANT = "noncompliant"
DEFENDER_FIELDS = ("assessments", "not_applicable", "unhealthy", "unhealthy_high", "unhealthy_unknown_severity")
POLICY_FIELDS = ("evaluations", "non_compliant")


# --- pure transforms (Resource Graph rows are plain dicts already) ---

def resource_record(row: dict) -> dict:
    """Normalize one Resource Graph row into an evidence record.

    Resource Graph returns `type` and `resourceGroup` LOWERCASED and `kind` as "" on
    types without one; the empty string is read as absent so a validator does not have
    to match both. `tags` is null on an untagged resource and is emitted as {}.
    """
    tags, sku = row.get("tags"), row.get("sku")
    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "type": row.get("type"),
        "location": row.get("location") or None,
        "resource_group": row.get("resourceGroup") or None,
        "tags": tags if isinstance(tags, dict) else {},
        "sku": sku if isinstance(sku, dict) and sku else None,
        "kind": row.get("kind") or None,
        "provisioning_state": row.get("provisioningState") or None,
    }


def assessment_target(row: dict) -> str | None:
    """The resource an assessment is about: its `resourceDetails` id, else the ARM id in front of the assessment."""
    details = row.get("resourceDetails")
    if isinstance(details, dict):
        for key in ("Id", "id", "ResourceId", "resourceId"):
            if details.get(key):
                return str(details[key])
    assessment_id = row.get("id") or ""
    cut = assessment_id.lower().rfind(ASSESSMENT_ID_MARKER)
    return assessment_id[:cut] if cut > 0 else None


def foreign_source(row: dict) -> str | None:
    """`source:<platform>` for an assessment whose `resourceDetails` source is not Azure (Aws, Gcp, OnPremise).

    Its id can sit under an Azure resource such as the multicloud connector, so it never counts for one.
    """
    details = row.get("resourceDetails")
    if not isinstance(details, dict):
        return None
    source = str(details.get("Source") or details.get("source") or "").strip().lower()
    return None if source in ("", "azure") else f"source:{source}"


def inventory_key(target: str | None, inventory: set[str]) -> str | None:
    """The inventoried resource a result is about, or its nearest inventoried parent (a subnet's VNet)."""
    key = (target or "").strip().lower().rstrip("/")
    while key:
        if key in inventory:
            return key
        key = key.rpartition("/")[0]
    return None


def _arm_type(segments: list[str]) -> str:
    """The resource type an id's `providers/...` segments name, with any extension type after " > "."""
    chunks: list[list[str]] = []
    i = 0
    while i < len(segments):
        if segments[i] == "providers" and i + 1 < len(segments):
            chunks.append([segments[i + 1]])
            i += 2
        elif chunks:
            chunks[-1].append(segments[i])
            i += 2
        else:
            i += 1
    return " > ".join("/".join(chunk) for chunk in chunks) or "unparsed"


def target_kind(target: str | None, subscription_id: str | None = None) -> str:
    """What a result outside the inventory is about, by id shape only: never a name."""
    key = (target or "").strip().lower().rstrip("/")
    if not key:
        return "no_target"
    parts = key.split("/")[1:]
    if parts[:3] == ["providers", "microsoft.management", "managementgroups"]:
        return "management_group"
    if parts[:1] != ["subscriptions"] or len(parts) < 2:
        return "unparsed"
    if subscription_id and parts[1] != subscription_id.lower():
        return "other_subscription"
    rest = parts[2:]
    if not rest:
        return "subscription"
    if rest[0] == "resourcegroups":
        if len(rest) == 2:
            return "resource_group"
        return _arm_type(rest[2:]) if rest[2:3] == ["providers"] else "unparsed"
    return "subscription > " + _arm_type(rest) if rest[0] == "providers" else "unparsed"


def _tally(rows, inventory, subscription_id, target_of, count, fields, foreign_of=lambda row: None) -> dict:
    """Counts per inventoried resource, and the same counts for results about anything else, by what they target."""
    by_resource: dict[str, Counter] = {}
    outside: dict[str, Counter] = {}
    for row in rows:
        target, foreign = target_of(row), foreign_of(row)
        key = None if foreign else inventory_key(target, inventory)
        if key is None:
            count(outside.setdefault(foreign or target_kind(target, subscription_id), Counter()), row)
        else:
            count(by_resource.setdefault(key, Counter()), row)

    def total(counters) -> dict:
        summed: Counter = Counter()
        for counts in counters:
            summed.update(counts)
        return {field: summed[field] for field in fields}

    return {
        "by_resource": by_resource,
        "inside": total(by_resource.values()),
        "outside": total(outside.values()),
        "outside_by_target": {kind: total([outside[kind]]) for kind in sorted(outside)},
    }


def _count_assessment(counts: Counter, row: dict) -> None:
    status = (row.get("status") or "").lower()
    if status not in ASSESSED:
        counts["not_applicable"] += 1
        return
    counts["assessments"] += 1
    if status == UNHEALTHY:
        counts["unhealthy"] += 1
        severity = (row.get("severity") or "").lower()
        if severity in HIGH_SEVERITIES:
            counts["unhealthy_high"] += 1
        elif not severity:
            counts["unhealthy_unknown_severity"] += 1


def _count_state(counts: Counter, row: dict) -> None:
    counts["evaluations"] += 1
    if (row.get("complianceState") or "").lower() == NON_COMPLIANT:
        counts["non_compliant"] += 1


def tally_defender(rows: list[dict], inventory: set[str], subscription_id: str | None = None) -> dict:
    """Assessed (Healthy or Unhealthy), not applicable, unhealthy and unhealthy High/Critical counts per resource."""
    return _tally(rows, inventory, subscription_id, assessment_target, _count_assessment, DEFENDER_FIELDS,
                  foreign_source)


def tally_policy(rows: list[dict], inventory: set[str], subscription_id: str | None = None) -> dict:
    """Policy states (one per resource, assignment and policy) and non-compliant states per inventoried resource."""
    return _tally(rows, inventory, subscription_id, lambda row: row.get("resourceId"), _count_state, POLICY_FIELDS)


def with_coverage(resources: list[dict], defender: dict | None, policy: dict | None) -> list[dict]:
    """Add each resource's counts; None for a service whose query did not complete."""

    def count(tally, key, field):
        return None if tally is None else tally["by_resource"].get(key, Counter())[field]

    out = []
    for r in resources:
        key = (r["id"] or "").lower()
        out.append({
            **r,
            "defender_assessments": count(defender, key, "assessments"),
            "defender_not_applicable": count(defender, key, "not_applicable"),
            "defender_unhealthy": count(defender, key, "unhealthy"),
            "defender_unhealthy_high_severity": count(defender, key, "unhealthy_high"),
            "policy_evaluations": count(policy, key, "evaluations"),
            "policy_non_compliant": count(policy, key, "non_compliant"),
        })
    return out


def _coverage(resources: list[dict], tally: dict | None, field: str) -> dict:
    """Gaps among the types the service covered at least one resource of; other types are listed apart."""
    if tally is None:
        return {"in_scope": None, "covered": None, "missing": None, "other_types": None, "all": None}
    covered_types = {r["type"] for r in resources if r[field]}
    in_scope = [r for r in resources if r["type"] in covered_types]
    missing = sorted(r["id"] for r in in_scope if not r[field])
    other_types = Counter(r["type"] or "unknown" for r in resources if r["type"] not in covered_types)
    # Covering nothing (not in use, nothing assigned, or an empty inventory, which is what Resource Graph
    # returns without Reader) must not read as "no gaps".
    return {"in_scope": len(in_scope), "covered": len(in_scope) - len(missing), "missing": missing,
            "other_types": sorted_counts(other_types), "all": bool(covered_types) and not missing}


def _resources_with(resources: list[dict], field: str, tally: dict | None) -> int | None:
    return None if tally is None else sum(1 for r in resources if r[field])


def _inside(tally: dict | None, field: str) -> int | None:
    return None if tally is None else tally["inside"][field]


def _outside(tally: dict | None, field: str) -> int | None:
    return None if tally is None else tally["outside"][field]


def _total(tally: dict | None, field: str) -> int | None:
    return None if tally is None else tally["inside"][field] + tally["outside"][field]


def _service_summary(resources, tally, field, cov, names) -> dict:
    """One service's summary keys, under that service's own names; None throughout when its query failed."""
    known = tally is not None
    return {
        names["collected"]: known,
        names["total"]: _total(tally, names["count"]),
        names["outside"]: _outside(tally, names["count"]),
        names["resources"]: _resources_with(resources, field, tally),
        names["in_scope"]: cov["in_scope"],
        names["percentage"]: coverage_percentage(cov["covered"], cov["in_scope"]) if known else None,
        names["missing"]: cov["missing"],
        names["missing_count"]: len(cov["missing"]) if known else None,
        names["other_types"]: cov["other_types"],
        names["all"]: cov["all"],
    }


DEFENDER_NAMES = {
    "count": "assessments",
    "collected": "defender_coverage_collected",
    "total": "defender_assessments_total",
    "outside": "defender_assessments_outside_inventory",
    "resources": "resources_assessed_by_defender",
    "in_scope": "defender_assessable_resources",
    "percentage": "defender_assessed_percentage",
    "missing": "resources_without_defender_assessment",
    "missing_count": "resources_without_defender_assessment_count",
    "other_types": "types_without_defender_assessment",
    "all": "all_assessable_resources_assessed_by_defender",
}

POLICY_NAMES = {
    "count": "evaluations",
    "collected": "policy_coverage_collected",
    "total": "policy_evaluations_total",
    "outside": "policy_evaluations_outside_inventory",
    "resources": "resources_evaluated_by_policy",
    "in_scope": "policy_evaluable_resources",
    "percentage": "policy_evaluated_percentage",
    "missing": "resources_without_policy_evaluation",
    "missing_count": "resources_without_policy_evaluation_count",
    "other_types": "types_without_policy_evaluation",
    "all": "all_evaluable_resources_evaluated_by_policy",
}


def summarize(resources: list[dict], defender: dict | None = None, policy: dict | None = None) -> dict:
    """Total, by type, by location, how many carry no tags, and Defender and Policy coverage."""
    by_type = Counter(r["type"] or "unknown" for r in resources)
    # Global resources (DNS zones, Front Door, some identity types) report "global".
    by_location = Counter(r["location"] or "unknown" for r in resources)
    untagged = sum(1 for r in resources if not r["tags"])
    neither = None
    if defender is not None and policy is not None:
        neither = sorted_counts(Counter(
            r["type"] or "unknown" for r in resources
            if not r["defender_assessments"] and not r["policy_evaluations"]
        ))
    return {
        "total_resources": len(resources),
        "resource_type_count": len(by_type),
        "resources_by_type": sorted_counts(by_type),
        "location_count": len(by_location),
        "resources_by_location": sorted_counts(by_location),
        "resource_group_count": len({r["resource_group"] for r in resources if r["resource_group"]}),
        "untagged_resources": untagged,
        "tagged_resources": len(resources) - untagged,
        **_service_summary(resources, defender, "defender_assessments",
                           _coverage(resources, defender, "defender_assessments"), DEFENDER_NAMES),
        "defender_not_applicable_total": _total(defender, "not_applicable"),
        "resources_with_unhealthy_high_severity": _resources_with(
            resources, "defender_unhealthy_high_severity", defender),
        "unhealthy_high_severity_assessments": _inside(defender, "unhealthy_high"),
        "unhealthy_assessments_without_severity": _inside(defender, "unhealthy_unknown_severity"),
        "defender_unhealthy_outside_inventory": _outside(defender, "unhealthy"),
        "defender_unhealthy_high_severity_outside_inventory": _outside(defender, "unhealthy_high"),
        "defender_unhealthy_without_severity_outside_inventory": _outside(defender, "unhealthy_unknown_severity"),
        **_service_summary(resources, policy, "policy_evaluations",
                           _coverage(resources, policy, "policy_evaluations"), POLICY_NAMES),
        "resources_with_non_compliant_policy": _resources_with(resources, "policy_non_compliant", policy),
        "non_compliant_policy_evaluations": _inside(policy, "non_compliant"),
        "policy_non_compliant_outside_inventory": _outside(policy, "non_compliant"),
        "resources_covered_by_neither_by_type": neither,
    }


# --- collection (lazy azure imports) ---

def _query_status(query: str, result: dict | None, tally: dict | None) -> dict:
    return {
        "query": query,
        "collected": result is not None,
        "pages_read": None if result is None else result["pages"],
        "total_records_reported": None if result is None else result["total_records"],
        "outside_inventory_by_target": None if tally is None else tally["outside_by_target"],
    }


def collect(subscription_id, cred, collector: Collector) -> dict:
    """Page the inventory and both coverage queries to the end, then join them by resource id.

    A coverage query that fails or comes back truncated is recorded as a failure and
    its counts stay null, rather than every resource reading as uncovered.
    """
    empty = {"resources": [], "total_records": None, "pages": 0, "defender": None, "policy": None,
             "coverage_queries": {}}
    client = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    if client is None:
        return empty
    inventory = collector.guard(
        "resourcegraph.resources (Resources)", lambda: query_all(client, subscription_id, INVENTORY_QUERY)
    )
    if inventory is None:
        return empty
    resources = sorted((resource_record(row) for row in inventory["rows"]), key=lambda r: r.get("id") or "")
    keys = {(r["id"] or "").lower() for r in resources if r["id"]}

    def _read(label: str, query: str) -> dict | None:
        return collector.guard(f"resourcegraph.resources ({label})", lambda: query_all(client, subscription_id, query))

    assessments = _read("SecurityResources", DEFENDER_QUERY)
    states = _read("PolicyResources", POLICY_QUERY)
    defender = None if assessments is None else tally_defender(assessments["rows"], keys, subscription_id)
    policy = None if states is None else tally_policy(states["rows"], keys, subscription_id)
    return {
        "resources": with_coverage(resources, defender, policy),
        "total_records": inventory["total_records"],
        "pages": inventory["pages"],
        "defender": defender,
        "policy": policy,
        "coverage_queries": {
            "defender_assessments": _query_status(DEFENDER_QUERY, assessments, defender),
            "policy_states": _query_status(POLICY_QUERY, states, policy),
        },
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request header at INFO; warnings still get through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    collected = {"resources": [], "total_records": None, "pages": 0, "defender": None, "policy": None,
                 "coverage_queries": {}}
    if subscription_id and cred is not None:
        collected = collect(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    resources = collected["resources"]
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "resources": resources,
            "inventory_source": "azure_resource_graph",
            "query": INVENTORY_QUERY,
            "pages_read": collected["pages"],
            "total_records_reported": collected["total_records"],
            "coverage_queries": collected["coverage_queries"],
        },
        summary=summarize(resources, collected["defender"], collected["policy"]),
    )

    filename = (
        f"azure_resource_inventory_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s (%d resources)", path, len(resources))
    return 0


if __name__ == "__main__":
    sys.exit(main())
