#!/usr/bin/env python3
"""Azure managed identities: every user- and system-assigned identity, what it is attached to, what its roles let it do, its federated credentials and its Microsoft Graph permissions."""

import asyncio
import fnmatch
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
    arm_endpoint,
    basename,
    build_payload,
    classify_failure_code,
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
from entra_graph import with_graph_client  # noqa: E402

logger = logging.getLogger("azure_managed_identity_configuration")

# Built-in roles that grant write on everything in scope, or the power to grant access.
BROAD_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
}
GRANT_ACCESS_OPERATION = "Microsoft.Authorization/roleAssignments/write"
# Control-plane operations that hand back a credential for the data plane.
KEY_OPERATIONS = (
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.CognitiveServices/accounts/listKeys/action",
    "Microsoft.CognitiveServices/accounts/projects/connections/listSecrets/action",
    "Microsoft.Search/searchServices/listAdminKeys/action",
    "Microsoft.DocumentDB/databaseAccounts/listKeys/action",
    "Microsoft.Cache/redis/listKeys/action",
    "Microsoft.EventHub/namespaces/authorizationRules/listKeys/action",
    "Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action",
    "Microsoft.Web/sites/config/list/action",
    "Microsoft.ApiManagement/service/subscriptions/listSecrets/action",
)
# Federated credentials: the flexible (wildcard) matching expression only comes back on the
# preview API, and azure-mgmt-msi 7.1 has no field for it, so they are read as wire JSON.
FIC_API_VERSIONS = ("2025-01-31-preview", "2024-11-30")
TOKEN_EXCHANGE_AUDIENCE = "api://azureadtokenexchange"  # plus USGov / China suffixes


def scope_level(scope) -> str:
    """management_group / subscription / resource_group / resource / root for an ARM scope."""
    parts = [p for p in (scope or "").lower().split("/") if p]
    if not parts:
        return "root"
    if parts[0] == "providers" and "managementgroups" in parts:
        return "management_group"
    if parts[0] == "subscriptions":
        if len(parts) == 2:
            return "subscription"
        if len(parts) == 4 and parts[2] == "resourcegroups":
            return "resource_group"
        return "resource"
    return "root"


def issuer_kind(issuer) -> str:
    """A label for well-known federation issuers; the issuer itself is always kept."""
    value = str(issuer or "").lower()
    if "token.actions.githubusercontent.com" in value:
        return "github_actions"
    if "vstoken.dev.azure.com" in value or "app.vstoken.visualstudio.com" in value:
        return "azure_devops"
    if ".oic.prod-aks.azure.com" in value or "oidc.prod-aks.azure.com" in value:
        return "aks_workload_identity"
    if "accounts.google.com" in value:
        return "google"
    if "amazonaws.com" in value or "cognito-identity" in value:
        return "aws"
    return "other"


def github_subject_kind(subject):
    """What a GitHub Actions subject trusts: branch, tag, environment, pull_request, workflow or other."""
    value = str(subject or "").lower()
    if not value.startswith("repo:"):
        return None
    if ":pull_request" in value:
        return "pull_request"
    if ":environment:" in value:
        return "environment"
    if ":ref:refs/heads/" in value:
        return "branch"
    if ":ref:refs/tags/" in value:
        return "tag"
    if ":job_workflow_ref:" in value:
        return "workflow"
    return "other"


def operation_matches(pattern, operation) -> bool:
    """ARM action wildcard match, case-insensitive ("*" spans path segments)."""
    return fnmatch.fnmatchcase(str(operation).lower(), str(pattern or "").lower())


def grants(permissions: list, operation: str, data: bool = False) -> bool:
    """Whether any permission block allows the operation and does not exclude it."""
    allow, deny = ("data_actions", "not_data_actions") if data else ("actions", "not_actions")
    return any(
        any(operation_matches(a, operation) for a in block[allow])
        and not any(operation_matches(n, operation) for n in block[deny])
        for block in permissions
    )


def role_capabilities(role_definition) -> dict:
    """What a role definition lets its holder do, worked out from its permissions, not its name."""
    permissions = [
        {
            "actions": model_attr(p, "actions") or [],
            "not_actions": model_attr(p, "not_actions") or [],
            "data_actions": model_attr(p, "data_actions") or [],
            "not_data_actions": model_attr(p, "not_data_actions") or [],
        }
        for p in model_attr(role_definition, "permissions") or []
    ]
    return {
        "full_control": any("*" in block["actions"] for block in permissions),
        "can_grant_access": grants(permissions, GRANT_ACCESS_OPERATION),
        "can_read_keys": any(grants(permissions, op) for op in KEY_OPERATIONS),
        "full_data_access": any(
            a == "*" or a.endswith("/*") for block in permissions for a in block["data_actions"]
        ),
    }


CAPABILITIES = ("full_control", "can_grant_access", "can_read_keys", "full_data_access")


def project_user_assigned(identity) -> dict:
    return {
        "id": model_attr(identity, "id"),
        "name": model_attr(identity, "name"),
        "location": model_attr(identity, "location"),
        "resource_group": resource_group_from_id(model_attr(identity, "id")),
        "tags": model_attr(identity, "tags") or {},
        "principal_id": model_attr(identity, "principal_id"),
        "client_id": model_attr(identity, "client_id"),
        "isolation_scope": model_attr(identity, "isolation_scope"),
    }


def project_federated_credential(raw: dict) -> dict:
    props = raw.get("properties") or {}
    issuer = props.get("issuer")
    subject = props.get("subject")
    expression = (props.get("claimsMatchingExpression") or {}).get("value")
    audiences = props.get("audiences") or []
    kind = github_subject_kind(subject)
    return {
        "name": raw.get("name"),
        "issuer": issuer,
        "issuer_kind": issuer_kind(issuer),
        "subject": subject,
        "claims_matching_expression": expression,
        "github_subject_kind": kind,
        "audiences": audiences,
        # Any pull request, a wildcard expression, or a wildcard in the subject.
        "broad_subject": kind == "pull_request" or bool(expression) or "*" in str(subject or ""),
        "nonstandard_audience": not audiences
        or any(not str(a).lower().startswith(TOKEN_EXCHANGE_AUDIENCE) for a in audiences),
    }


def resource_identities(resource) -> dict:
    """The identity block of one ARM resource, normalized: system principal and user-assigned ids."""
    identity = model_attr(resource, "identity")
    kind = str(model_attr(identity, "type") or "").lower()
    user_assigned = model_attr(identity, "user_assigned_identities") or {}
    return {
        "resource_id": model_attr(resource, "id"),
        "resource_name": model_attr(resource, "name"),
        "resource_type": model_attr(resource, "type"),
        "system_assigned": "systemassigned" in kind.replace(" ", "").replace(",", ""),
        "system_principal_id": model_attr(identity, "principal_id"),
        "user_assigned_ids": sorted(k.lower() for k in user_assigned),
    }


def project_role_assignment(assignment, roles: dict) -> dict:
    """`roles` maps a role definition GUID to {"name", "capabilities"}."""
    role_id = model_attr(assignment, "role_definition_id")
    role = roles.get(basename(role_id or "").lower())
    scope = model_attr(assignment, "scope")
    caps = role["capabilities"] if role else {c: None for c in CAPABILITIES}
    name = role["name"] if role else None
    return {
        "principal_id": model_attr(assignment, "principal_id"),
        "role_definition_id": role_id,
        "role_name": name,
        "role_resolved": role is not None,
        "scope": scope,
        "scope_level": scope_level(scope),
        "broad_role": str(name or "").lower() in BROAD_ROLES,
        **caps,
        "condition": model_attr(assignment, "condition"),
    }


def privileged_graph_permission(value) -> bool:
    """Graph application permissions that can change the tenant or reach every mailbox or file."""
    text = str(value or "")
    return "ReadWrite" in text or "FullControl" in text or text in ("Mail.Send", "Mail.Send.Shared")


def identity_record(identity: dict, roles_by_principal, graph_roles) -> dict:
    """An identity with its role assignments and Graph permissions; each null when it could not be read."""
    roles = None if roles_by_principal is None else roles_by_principal.get(identity["principal_id"], [])
    graph = None if graph_roles is None else graph_roles.get(identity["principal_id"])
    record = {
        **identity,
        "role_assignments": roles,
        "has_broad_role": None if roles is None else any(r["broad_role"] for r in roles),
        "has_subscription_or_higher_role": None
        if roles is None
        else any(r["scope_level"] in ("subscription", "management_group", "root") for r in roles),
        "graph_app_roles": graph,
        "has_privileged_graph_role": None if graph is None else any(g["privileged"] for g in graph),
    }
    for cap in CAPABILITIES:
        record[f"role_{cap}"] = None if roles is None else any(r[cap] is True for r in roles)
    return record


def summarize(user_assigned: list[dict], system_assigned: list[dict], graph_access: str) -> dict:
    everyone = user_assigned + system_assigned
    fics = [f for i in user_assigned for f in i["federated_credentials"] or []]
    assignments = [r for i in everyone for r in i["role_assignments"] or []]

    def count(items, pred):
        return sum(1 for i in items if pred(i))

    summary = {
        "total_identities": len(everyone),
        "total_user_assigned_identities": len(user_assigned),
        "total_system_assigned_identities": len(system_assigned),
        "system_assigned_identities_by_resource_type": {
            t: count(system_assigned, lambda i, t=t: i["resource_type"] == t)
            for t in sorted({i["resource_type"] for i in system_assigned})
        },
        "user_assigned_identities_no_resource_attached": count(user_assigned, lambda i: i["attached_resources"] == []),
        # Standing access with nothing using it: the identity to review first.
        "unattached_identities_with_roles": count(
            user_assigned, lambda i: i["attached_resources"] == [] and bool(i["role_assignments"])
        ),
        "user_assigned_identities_with_federated_credentials": count(
            user_assigned, lambda i: i["federated_credentials"]
        ),
        "total_federated_credentials": len(fics),
        "federated_credentials_by_issuer_kind": {
            k: count(fics, lambda f, k=k: f["issuer_kind"] == k) for k in sorted({f["issuer_kind"] for f in fics})
        },
        "federated_credentials_broad_subject": count(fics, lambda f: f["broad_subject"]),
        "federated_credentials_nonstandard_audience": count(fics, lambda f: f["nonstandard_audience"]),
        "identities_with_broad_role": count(everyone, lambda i: i["has_broad_role"] is True),
        "identities_with_subscription_or_higher_role": count(
            everyone, lambda i: i["has_subscription_or_higher_role"] is True
        ),
        "identities_without_role_assignments": count(everyone, lambda i: i["role_assignments"] == []),
        "identities_role_assignments_unknown": count(everyone, lambda i: i["role_assignments"] is None),
        "role_assignments_unresolved_role": count(assignments, lambda r: not r["role_resolved"]),
        "graph_access": graph_access,
        "identities_with_privileged_graph_roles": count(everyone, lambda i: i["has_privileged_graph_role"] is True),
        "identities_with_graph_roles": count(everyone, lambda i: i["graph_app_roles"]),
        "identities_graph_roles_unknown": count(everyone, lambda i: i["graph_app_roles"] is None),
    }
    for cap in CAPABILITIES:
        summary[f"identities_{cap}"] = count(everyone, lambda i, cap=cap: i[f"role_{cap}"] is True)
    return summary


def arm_list(client, path: str) -> list:
    """Every item of an ARM list call (following nextLink) through the client's authenticated pipeline."""
    from azure.core.rest import HttpRequest  # lazy

    url, items = arm_endpoint() + path, []
    for _ in range(100):
        response = client._client.send_request(HttpRequest("GET", url))
        response.raise_for_status()
        body = response.json()
        items.extend(body.get("value") or [])
        url = body.get("nextLink")
        if not url:
            return items
    raise RuntimeError(f"ARM paging did not terminate for {path}")


def list_federated_credentials(msi, identity_id: str) -> list:
    """Federated credentials on the preview API (flexible expressions), falling back to the stable one."""
    last = None
    for version in FIC_API_VERSIONS:
        try:
            return [
                project_federated_credential(f)
                for f in arm_list(msi, f"{identity_id}/federatedIdentityCredentials?api-version={version}")
            ]
        except Exception as exc:  # noqa: BLE001 — try the next API version, re-raise the last
            if "invalidapiversion" not in str(exc).lower().replace(" ", "") and "nosuchapi" not in str(exc).lower():
                raise
            last = exc
    raise last


def is_denied(exc) -> bool:
    status = getattr(exc, "response_status_code", None)
    text = str(exc).lower()
    return status in (401, 403) or "authorization_requestdenied" in text or "insufficient privileges" in text


async def read_graph_roles(collector: Collector, cred, principal_ids: list) -> tuple:
    """principal id → its Graph app role assignments, and whether Graph could be read at all."""

    async def work(client):
        roles_by_resource: dict = {}
        results: dict = {}
        for pid in principal_ids:
            try:
                response = await client.service_principals.by_service_principal_id(pid).app_role_assignments.get()
            except Exception as exc:  # noqa: BLE001
                if is_denied(exc):
                    return None, "not_authorized"
                if getattr(exc, "response_status_code", None) == 404:
                    results[pid] = []
                    continue
                collector.record(f"msgraph.servicePrincipals.appRoleAssignments({pid})", exc)
                results[pid] = None
                continue
            assignments = []
            for a in getattr(response, "value", None) or []:
                resource_id = str(getattr(a, "resource_id", "") or "")
                if resource_id not in roles_by_resource:
                    try:
                        sp = await client.service_principals.by_service_principal_id(resource_id).get()
                        roles_by_resource[resource_id] = {
                            str(r.id): r.value for r in (getattr(sp, "app_roles", None) or [])
                        }
                    except Exception as exc:  # noqa: BLE001
                        collector.record(f"msgraph.servicePrincipals({resource_id})", exc)
                        roles_by_resource[resource_id] = {}
                value = roles_by_resource[resource_id].get(str(getattr(a, "app_role_id", "")))
                assignments.append(
                    {
                        "resource": getattr(a, "resource_display_name", None),
                        "permission": value,
                        "privileged": privileged_graph_permission(value),
                    }
                )
            results[pid] = sorted(assignments, key=lambda g: (g["resource"] or "", g["permission"] or ""))
        return results, "read"

    outcome = await with_graph_client(collector, cred, work, default=(None, "failed"))
    return outcome


def collect(subscription_id, cred, collector: Collector) -> tuple:
    def _clients():
        from azure.mgmt.authorization import AuthorizationManagementClient  # lazy
        from azure.mgmt.msi import ManagedServiceIdentityClient  # lazy

        # azure-mgmt-resource 26 moved the class under .resources; older majors re-export it.
        try:
            from azure.mgmt.resource.resources import ResourceManagementClient  # lazy
        except ImportError:  # pragma: no cover - depends on installed SDK version
            from azure.mgmt.resource import ResourceManagementClient  # lazy

        kwargs = {"credential": cred, "subscription_id": subscription_id, **arm_client_kwargs()}
        return (
            ManagedServiceIdentityClient(**kwargs),
            ResourceManagementClient(**kwargs),
            AuthorizationManagementClient(**kwargs),
        )

    clients = collector.guard("managed identity clients (init)", _clients)
    if clients is None:
        return [], [], "failed"
    msi, resource_client, authorization = clients

    user_assigned = collector.guard(
        "msi.user_assigned_identities.list_by_subscription",
        lambda: [project_user_assigned(i) for i in msi.user_assigned_identities.list_by_subscription()],
        default=[],
    )
    holders = collector.guard(
        "resource.resources.list",
        lambda: [
            resource_identities(r) for r in resource_client.resources.list() if model_attr(r, "identity") is not None
        ],
    )

    def _roles():
        roles = {
            basename(model_attr(d, "id") or "").lower(): {
                "name": model_attr(d, "role_name"),
                "capabilities": role_capabilities(d),
            }
            for d in authorization.role_definitions.list(scope=f"/subscriptions/{subscription_id}")
        }
        by_principal: dict = {}
        for a in authorization.role_assignments.list_for_subscription():
            record = project_role_assignment(a, roles)
            by_principal.setdefault(record["principal_id"], []).append(record)
        for records in by_principal.values():
            records.sort(key=lambda r: (r["scope"] or "", r["role_name"] or ""))
        return by_principal

    roles_by_principal = collector.guard("authorization.role_assignments.list_for_subscription", _roles)

    principal_ids = [i["principal_id"] for i in user_assigned if i["principal_id"]]
    principal_ids += [h["system_principal_id"] for h in holders or [] if h["system_assigned"] and h["system_principal_id"]]
    if principal_ids:
        graph_roles, graph_access = asyncio.run(read_graph_roles(collector, cred, sorted(set(principal_ids))))
    else:
        graph_roles, graph_access = {}, "not_read"  # no identities to look up: Graph was never called

    attached: dict = {}
    for holder in holders or []:
        for uai in holder["user_assigned_ids"]:
            attached.setdefault(uai, []).append(
                {"resource_id": holder["resource_id"], "resource_type": holder["resource_type"]}
            )

    ua_records = []
    for identity in user_assigned:
        fics = collector.guard(
            f"msi.federated_identity_credentials.list({identity['resource_group']}/{identity['name']})",
            lambda identity=identity: list_federated_credentials(msi, identity["id"]),
        )
        ua_records.append(
            {
                **identity_record({**identity, "kind": "user_assigned"}, roles_by_principal, graph_roles),
                # null when the resource list failed: unknown, not "attached to nothing"
                "attached_resources": None
                if holders is None
                else sorted(attached.get((identity["id"] or "").lower(), []), key=lambda r: r["resource_id"] or ""),
                "federated_credentials": None if fics is None else sorted(fics, key=lambda f: f["name"] or ""),
            }
        )

    sa_records = [
        identity_record(
            {
                "kind": "system_assigned",
                "principal_id": h["system_principal_id"],
                "resource_id": h["resource_id"],
                "resource_name": h["resource_name"],
                "resource_type": h["resource_type"],
                "resource_group": resource_group_from_id(h["resource_id"]),
            },
            roles_by_principal,
            graph_roles,
        )
        for h in holders or []
        if h["system_assigned"] and h["system_principal_id"]
    ]
    return (
        sorted(ua_records, key=lambda r: r["id"] or ""),
        sorted(sa_records, key=lambda r: r["resource_id"] or ""),
        graph_access,
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one INFO line per Graph request
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    user_assigned: list = []
    system_assigned: list = []
    graph_access = "not_read"
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.ManagedIdentity")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.ManagedIdentity is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        user_assigned, system_assigned, graph_access = collect(subscription_id, cred, collector)
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
            "user_assigned_identities": user_assigned,
            "system_assigned_identities": system_assigned,
            "provider_registration_status": registration,
        },
        summary={
            **summarize(user_assigned, system_assigned, graph_access),
            "provider_registration_status": registration,
        },
    )
    filename = f"azure_managed_identity_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
