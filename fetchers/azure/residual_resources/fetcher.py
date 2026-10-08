#!/usr/bin/env python3
"""Residual elements in one subscription: unattached disks, NICs, NSGs and public IPs, empty resource groups, and role assignments whose principal is gone."""

import asyncio
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
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    report_failure,
    resolve_subscription,
    resource_graph_client,
    resource_graph_rows,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from entra_graph import aguard, with_graph_client  # noqa: E402

logger = logging.getLogger("azure_residual_resources")

GRAPH_BATCH = 1000
_PROJECT = " | project id = tostring(id), name, type, resourceGroup, location, tags | order by id asc"

ORPHAN_QUERIES = {
    "unattached_disk": (
        "Resources | where type =~ 'microsoft.compute/disks'"
        " and tostring(properties.diskState) =~ 'Unattached'" + _PROJECT
    ),
    "unattached_nic": (
        "Resources | where type =~ 'microsoft.network/networkinterfaces'"
        " and isnull(properties.virtualMachine) and isnull(properties.privateEndpoint)"
        " and isnull(properties.privateLinkService)"
        " and coalesce(array_length(properties.hostedWorkloads), 0) == 0" + _PROJECT
    ),
    "unattached_nsg": (
        "Resources | where type =~ 'microsoft.network/networksecuritygroups'"
        " and coalesce(array_length(properties.networkInterfaces), 0) == 0"
        " and coalesce(array_length(properties.subnets), 0) == 0" + _PROJECT
    ),
    "unattached_public_ip": (
        "Resources | where type =~ 'microsoft.network/publicipaddresses'"
        " and isnull(properties.ipConfiguration) and isnull(properties.natGateway)" + _PROJECT
    ),
    "empty_resource_group": (
        "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups'"
        " | extend rg = tolower(name)"
        " | join kind=leftouter (Resources | summarize resources = count() by rg = tolower(resourceGroup)) on rg"
        " | where isnull(resources) or resources == 0"
        " | project id = tostring(id), name, type, resourceGroup = name, location, tags | order by id asc"
    ),
}

ASSIGNMENTS_QUERY = (
    "authorizationresources | where type =~ 'microsoft.authorization/roleassignments'"
    " | project id = tostring(id), principalId = tostring(properties.principalId),"
    " principalType = tostring(properties.principalType),"
    " roleDefinitionId = tostring(properties.roleDefinitionId),"
    " scope = tostring(properties.scope), createdOn = tostring(properties.createdOn)"
    " | order by id asc"
)


def _guid(resource_id) -> str:
    return (resource_id or "").rstrip("/").rsplit("/", 1)[-1].lower()


def resource_record(row: dict, kind: str) -> dict:
    tags = row.get("tags")
    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "type": row.get("type"),
        "resource_group": row.get("resourceGroup") or None,
        "location": row.get("location") or None,
        "tags": tags if isinstance(tags, dict) else {},
        "orphan_kind": kind,
    }


def assignment_record(row: dict, role_names: dict, found) -> dict:
    principal = (row.get("principalId") or "").lower()
    exists = None if found is None or not principal else principal in found
    return {
        "id": row.get("id"),
        "principal_id": row.get("principalId") or None,
        "principal_type": row.get("principalType") or None,
        "role_definition_id": row.get("roleDefinitionId") or None,
        "role_name": role_names.get(_guid(row.get("roleDefinitionId"))),
        "scope": row.get("scope") or None,
        "created_on": row.get("createdOn") or None,
        "principal_exists": exists,
        "orphan_kind": "deleted_principal_assignment" if exists is False else None,
    }


def summarize(resources: list, assignments: list, principal_check: str) -> dict:
    kinds = Counter(r["orphan_kind"] for r in resources)
    kinds.update(a["orphan_kind"] for a in assignments if a["orphan_kind"])
    principals = {a["principal_id"] for a in assignments if a["principal_id"]}
    missing = {a["principal_id"] for a in assignments if a["principal_exists"] is False}
    return {
        "total_orphans": sum(kinds.values()),
        "orphans_by_kind": sorted_counts(kinds),
        "orphaned_resources": len(resources),
        "role_assignments_checked": len(assignments),
        "deleted_principal_assignments": kinds["deleted_principal_assignment"],
        "principals_checked": len(principals),
        "principals_missing": len(missing),
        "principal_check": principal_check,
    }


def role_definition_names(subscription_id, cred) -> dict:
    # Resource Graph does not index built-in role definitions, so names come from ARM.
    from azure.mgmt.authorization import AuthorizationManagementClient  # lazy

    client = AuthorizationManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())
    return {
        str(getattr(d, "name", "") or "").lower(): getattr(d, "role_name", None)
        for d in client.role_definitions.list(scope=f"/subscriptions/{subscription_id}")
    }


async def existing_principals(collector: Collector, cred, ids: list):
    """Lower-cased ids of the principals Microsoft Graph still has, or None if the lookup failed."""
    from msgraph.generated.directory_objects.get_by_ids.get_by_ids_post_request_body import (  # lazy
        GetByIdsPostRequestBody,
    )

    async def _lookup(client):
        found = set()
        for start in range(0, len(ids), GRAPH_BATCH):
            response = await client.directory_objects.get_by_ids.post(
                GetByIdsPostRequestBody(ids=ids[start:start + GRAPH_BATCH])
            )
            found |= {str(getattr(o, "id", "") or "").lower() for o in (getattr(response, "value", None) or [])}
        return found

    async def _work(client):
        return await aguard(collector, "msgraph.directory_objects.get_by_ids", lambda: _lookup(client))

    return await with_graph_client(collector, cred, _work, default=None)


def collect(subscription_id, cred, collector: Collector):
    client = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    if client is None:
        return [], [], {}, "failed"

    sources, resources = {}, []

    def _run(label, query):
        result = collector.guard(
            f"resourcegraph.resources ({label})", lambda: resource_graph_rows(client, subscription_id, query)
        )
        if result is not None:
            sources[label] = {
                "query": query,
                "rows": len(result["rows"]),
                "total_records_reported": result["total_records"],
                "pages": result["pages"],
            }
        return result["rows"] if result is not None else None

    for kind, query in ORPHAN_QUERIES.items():
        rows = _run(kind, query)
        resources.extend(resource_record(row, kind) for row in rows or [])

    rows = _run("role_assignments", ASSIGNMENTS_QUERY)
    role_names = collector.guard(
        "authorization.role_definitions.list", lambda: role_definition_names(subscription_id, cred), default={}
    )
    if rows is None:
        return resources, [], sources, "failed"

    ids = sorted({(r.get("principalId") or "").lower() for r in rows if r.get("principalId")})
    found = asyncio.run(existing_principals(collector, cred, ids)) if ids else set()
    assignments = [assignment_record(row, role_names, found) for row in rows]
    return (
        sorted(resources, key=lambda r: (r["orphan_kind"], r["id"] or "")),
        assignments,
        sources,
        "failed" if found is None else "complete",
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

    resources, assignments, sources, principal_check = [], [], {}, "not_run"
    if subscription_id and cred is not None:
        resources, assignments, sources, principal_check = collect(subscription_id, cred, collector)
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
            "orphaned_resources": resources,
            "role_assignments": assignments,
            "sources": sources,
        },
        summary=summarize(resources, assignments, principal_check),
    )

    filename = f"azure_residual_resources_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s (%d orphans)", path, evidence["summary"]["total_orphans"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
