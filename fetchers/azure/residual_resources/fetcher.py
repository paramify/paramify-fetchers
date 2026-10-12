#!/usr/bin/env python3
"""Residual elements in one subscription: unattached disks, NICs, NSGs and public IPs, empty resource groups, unused identities, stale slots, and role assignments whose principal is gone."""

import asyncio
import logging
import os
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
    credential,
    failure_reason,
    parse_time,
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
DEFAULT_STALE_SLOT_DAYS = 90
FIC_API_VERSION = "2023-01-31"
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

IDENTITIES_QUERY = (
    "Resources | where type =~ 'microsoft.managedidentity/userassignedidentities'"
    " | project id = tostring(id), name, type, resourceGroup, location, tags,"
    " principalId = tostring(properties.principalId), clientId = tostring(properties.clientId)"
    " | order by id asc"
)

IDENTITY_REFERENCES_QUERY = (
    "Resources | where isnotnull(identity.userAssignedIdentities)"
    " | mv-expand identityId = bag_keys(identity.userAssignedIdentities)"
    " | project id = tostring(id), identityId = tolower(tostring(identityId)) | order by id asc"
)

SLOTS_QUERY = (
    "Resources | where type =~ 'microsoft.web/sites/slots'"
    " | project id = tostring(id), name, type, resourceGroup, location, tags,"
    " state = tostring(properties.state), lastModified = tostring(properties.lastModifiedTimeUtc)"
    " | order by id asc"
)

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


def stale_slot_days() -> int:
    raw = os.environ.get("AZURE_STALE_SLOT_DAYS") or ""
    return int(raw) if raw.strip().isdigit() and int(raw) > 0 else DEFAULT_STALE_SLOT_DAYS


def slot_record(row: dict, days: int, now: datetime):
    """The slot as an orphan when it is stopped or untouched for `days`; None when it is in use."""
    reasons = []
    if (row.get("state") or "").lower() != "running":
        reasons.append("not_running")
    modified = row.get("lastModified") or ""
    when = parse_time(modified)
    if when and now - when > timedelta(days=days):
        reasons.append(f"not_modified_in_{days}_days")
    if not reasons:
        return None
    return {
        **resource_record(row, "stale_deployment_slot"),
        "state": row.get("state") or None,
        "last_modified": modified or None,
        "stale_reasons": reasons,
    }


def identity_record(row: dict, attached: int, roles: int, federated) -> dict:
    unused = attached == 0 and roles == 0 and federated == 0
    return {
        **resource_record(row, "unused_identity" if unused else None),
        "principal_id": row.get("principalId") or None,
        "client_id": row.get("clientId") or None,
        "attached_resources": attached,
        "role_assignments": roles,
        "federated_credentials": federated,
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


def summarize(resources: list, assignments: list, principal_check: str, checked: dict) -> dict:
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
        "identities_checked": checked.get("identities", 0),
        "slots_checked": checked.get("slots", 0),
        "stale_slot_days": checked.get("stale_slot_days"),
    }


def role_definition_names(subscription_id, cred) -> dict:
    # Resource Graph does not index built-in role definitions, so names come from ARM.
    from azure.mgmt.authorization import AuthorizationManagementClient  # lazy

    client = AuthorizationManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())
    return {
        str(getattr(d, "name", "") or "").lower(): getattr(d, "role_name", None)
        for d in client.role_definitions.list(scope=f"/subscriptions/{subscription_id}")
    }


def federated_credential_count(arm, identity_id: str) -> int:
    from azure.core.rest import HttpRequest  # lazy

    response = arm.send_request(
        HttpRequest("GET", f"{identity_id}/federatedIdentityCredentials?api-version={FIC_API_VERSION}")
    )
    response.raise_for_status()
    return len(response.json().get("value") or [])


def identity_records(subscription_id, cred, collector: Collector, identities: list, references: list, assignments: list):
    """Identity records; federated credentials are read only for identities nothing else uses."""
    attached = Counter(r.get("identityId") for r in references)
    roles = Counter((a.get("principalId") or "").lower() for a in assignments)
    arm = None
    records = []
    for row in identities:
        n_attached = attached[(row.get("id") or "").lower()]
        n_roles = roles[(row.get("principalId") or "").lower()] if row.get("principalId") else 0
        federated = None
        if n_attached == 0 and n_roles == 0:
            if arm is None:
                # Resource Graph does not index federatedIdentityCredentials; any mgmt client is an ARM pipeline for the GET.
                from azure.mgmt.network import NetworkManagementClient  # lazy

                arm = NetworkManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())
            federated = collector.guard(
                f"managedidentity.federatedIdentityCredentials.list({row.get('name')})",
                lambda: federated_credential_count(arm, row["id"]),
            )
        records.append(identity_record(row, n_attached, n_roles, federated))
    return records


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
        return [], [], {}, "failed", {}

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

    days = stale_slot_days()
    now = datetime.now(timezone.utc)
    slots = _run("deployment_slots", SLOTS_QUERY) or []
    resources.extend(r for r in (slot_record(row, days, now) for row in slots) if r)

    rows = _run("role_assignments", ASSIGNMENTS_QUERY)
    identities = _run("user_assigned_identities", IDENTITIES_QUERY)
    references = _run("identity_references", IDENTITY_REFERENCES_QUERY)
    checked = {"slots": len(slots), "stale_slot_days": days, "identities": len(identities or [])}
    if identities is not None and references is not None and rows is not None:
        identity_rows = identity_records(subscription_id, cred, collector, identities, references, rows)
        resources.extend(r for r in identity_rows if r["orphan_kind"])

    role_names = collector.guard(
        "authorization.role_definitions.list", lambda: role_definition_names(subscription_id, cred), default={}
    )
    if rows is None:
        return resources, [], sources, "failed", checked

    ids = sorted({(r.get("principalId") or "").lower() for r in rows if r.get("principalId")})
    found = asyncio.run(existing_principals(collector, cred, ids)) if ids else set()
    assignments = [assignment_record(row, role_names, found) for row in rows]
    return (
        sorted(resources, key=lambda r: (r["orphan_kind"], r["id"] or "")),
        assignments,
        sources,
        "failed" if found is None else "complete",
        checked,
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

    resources, assignments, sources, principal_check, checked = [], [], {}, "not_run", {}
    if subscription_id and cred is not None:
        resources, assignments, sources, principal_check, checked = collect(subscription_id, cred, collector)
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
        summary=summarize(resources, assignments, principal_check, checked),
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
