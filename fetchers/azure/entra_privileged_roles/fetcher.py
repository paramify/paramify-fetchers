#!/usr/bin/env python3
"""
Microsoft Entra ID privileged directory roles and their members

Every ACTIVATED directory role with its members, the tenant-wide administrative roles
flagged, and the Global Administrator count. `GET /directoryRoles` returns only roles
instantiated in the tenant (which happens the first time a role is assigned), so a role
absent from the response has no members and an empty response is genuine evidence of
none rather than a truncated read.

Ported from Prowler's prowler/providers/azure/services/entra/entra_service.py
`_get_directory_roles` (Apache-2.0) and their
entra_global_admin_in_less_than_five_users check, which likewise keys Global
Administrator by display name.
"""

import asyncio
import logging
import os
import sys
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
    write_evidence,
    report_failure,
)
from entra_graph import (  # noqa: E402
    graph_attr,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_privileged_roles")

# The role Prowler's entra_global_admin_in_less_than_five_users check counts.
GLOBAL_ADMINISTRATOR = "Global Administrator"

# A SECOND way to recognize that role, never the only one — `is_privileged_role`
# matches the display name first, so a wrong constant here cannot drop the role from
# the counts.
#
# Provenance: this GUID has no upstream ancestor. Prowler's config.py carries the ARM
# *RBAC* role GUIDs (reused verbatim by rbac_role_assignments) but no Entra *directory*
# role template ids; the two are different id spaces, and Prowler's directory-role code
# matches on the display name, as this does.
GLOBAL_ADMINISTRATOR_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Entra built-in directory roles that grant tenant-wide administrative power: each can
# take over identities, grant itself more access, or alter the controls protecting the
# tenant.
#
# Matched on display name because that is the stable documented identifier Graph
# returns for a built-in role (v1.0 does not localize these), and is what Prowler
# matches on. Each record also carries `role_template_id` verbatim, so a validator can
# pin the GUID without this list asserting one.
PRIVILEGED_ROLE_NAMES = frozenset(
    {
        # --- full tenant control ---
        GLOBAL_ADMINISTRATOR,
        "Privileged Role Administrator",       # can grant any role, including GA
        "Privileged Authentication Administrator",  # can reset a GA's credentials
        # --- identity takeover ---
        "Authentication Administrator",
        "User Administrator",
        "Helpdesk Administrator",
        "Password Administrator",
        "Directory Writers",
        # --- can grant itself access via an app or a federated identity ---
        "Application Administrator",
        "Cloud Application Administrator",
        "Hybrid Identity Administrator",
        "Domain Name Administrator",
        "External Identity Provider Administrator",
        # --- controls the controls ---
        "Conditional Access Administrator",
        "Security Administrator",
        "Compliance Administrator",
        "Intune Administrator",
        # --- workload-wide data access ---
        "Exchange Administrator",
        "SharePoint Administrator",
        "Teams Administrator",
        # --- reads everything (no write, but full-tenant disclosure) ---
        "Global Reader",
        "Security Reader",
        # --- commercial control of the tenant ---
        "Billing Administrator",
        "Partner Tier2 Support",
    }
)

# The members collection is typed as directoryObject and the concrete kind shows up
# only in @odata.type. It matters: a role-assignable GROUP moves the real access
# decision elsewhere, and a SERVICE PRINCIPAL has no interactive sign-in for MFA or
# Conditional Access to gate.
_MEMBER_TYPES = {
    "#microsoft.graph.user": "User",
    "#microsoft.graph.group": "Group",
    "#microsoft.graph.servicePrincipal": "ServicePrincipal",
    "#microsoft.graph.device": "Device",
    "#microsoft.graph.orgContact": "OrgContact",
}


# --- projections: the only code here that touches a Graph model ---

def project_directory_role(role) -> dict:
    """Read a `DirectoryRole` model's attributes into a flat snake_case dict.

    `members` is NOT read here: Graph does not expand it on the collection response, so
    it arrives only from the separate per-role members call.
    """
    return {
        "id": graph_attr(role, "id"),
        "role_template_id": graph_attr(role, "role_template_id"),
        "display_name": graph_attr(role, "display_name"),
        "description": graph_attr(role, "description"),
    }


def project_member(member) -> dict:
    """Read one directory-role member (a `directoryObject`) into a flat dict.

    `directoryObject` declares only `id` and `@odata.type`, but kiota deserializes each
    entry into its concrete subclass (User, Group, ServicePrincipal), so the richer
    fields are present when the member's kind has them. `graph_attr`'s None-tolerance is
    what lets one projection read every kind — a Group has no `user_principal_name`.
    """
    return {
        "id": graph_attr(member, "id"),
        "odata_type": graph_attr(member, "odata_type"),
        "display_name": graph_attr(member, "display_name"),
        "user_principal_name": graph_attr(member, "user_principal_name"),
        "account_enabled": graph_attr(member, "account_enabled"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def member_type(odata_type: str | None) -> str:
    """Map a member's `@odata.type` to a plain principal kind.

    Falls back to the last dotted segment, so a principal kind Microsoft adds later is
    reported as itself rather than collapsing to "Unknown".
    """
    if not odata_type:
        return "Unknown"
    mapped = _MEMBER_TYPES.get(str(odata_type))
    if mapped:
        return mapped
    tail = str(odata_type).rsplit(".", 1)[-1]
    return (tail[:1].upper() + tail[1:]) if tail else "Unknown"


def is_privileged_role(role: dict) -> bool:
    """Whether this directory role grants tenant-wide administrative power.

    Name first, template id second. The redundancy is deliberate: Global Administrator
    stays recognized even if it ever came back under a different display name.
    """
    if (role.get("display_name") or "") in PRIVILEGED_ROLE_NAMES:
        return True
    return str(role.get("role_template_id") or "").lower() == GLOBAL_ADMINISTRATOR_TEMPLATE_ID


def member_record(member: dict) -> dict:
    """Normalize one projected member into an evidence record."""
    enabled = member.get("account_enabled")
    return {
        "id": member.get("id"),
        "principal_type": member_type(member.get("odata_type")),
        "display_name": member.get("display_name"),
        "user_principal_name": member.get("user_principal_name"),
        # Only user principals carry accountEnabled; None on a group or service
        # principal means "not applicable", not "disabled", so it is left None rather
        # than coerced to False.
        "account_enabled": None if enabled is None else bool(enabled),
    }


def directory_role_record(role: dict, members: list[dict]) -> dict:
    """Normalize one projected role plus its projected members into a record.

    Members are sorted by principal name (id breaking ties) so a re-run against an
    unchanged directory is byte-stable; Graph does not promise a stable member order.
    The key is lower-cased because users sort by UPN and groups by display name, and a
    case-sensitive sort would interleave them by ASCII case instead of alphabetically.
    """
    records = sorted(
        (member_record(m) for m in members),
        key=lambda r: (
            (r.get("user_principal_name") or r.get("display_name") or "").lower(),
            r.get("id") or "",
        ),
    )
    return {
        "id": role.get("id"),
        "role_template_id": role.get("role_template_id"),
        "display_name": role.get("display_name"),
        "description": role.get("description"),
        "is_privileged": is_privileged_role(role),
        "is_global_administrator": (role.get("display_name") or "") == GLOBAL_ADMINISTRATOR
        or str(role.get("role_template_id") or "").lower() == GLOBAL_ADMINISTRATOR_TEMPLATE_ID,
        "member_count": len(records),
        "members": records,
        "user_member_count": sum(1 for r in records if r["principal_type"] == "User"),
        "group_member_count": sum(1 for r in records if r["principal_type"] == "Group"),
        "service_principal_member_count": sum(
            1 for r in records if r["principal_type"] == "ServicePrincipal"
        ),
    }


def summarize(roles: list[dict]) -> dict:
    """The Global Administrator count is the headline.

    It is the number CIS Azure 1.1.3 and Prowler's
    entra_global_admin_in_less_than_five_users are written against.
    `distinct_privileged_principals` sits alongside the raw assignment count because one
    person holding six privileged roles is one human to review, not six.
    """
    privileged = [r for r in roles if r["is_privileged"]]
    global_admin_roles = [r for r in roles if r["is_global_administrator"]]
    privileged_principals = {
        m["id"] for r in privileged for m in r["members"] if m.get("id")
    }
    all_principals = {m["id"] for r in roles for m in r["members"] if m.get("id")}
    return {
        # Activated roles only — see the module docstring on why that is complete.
        "total_directory_roles_activated": len(roles),
        "total_role_assignments": sum(r["member_count"] for r in roles),
        "distinct_principals_with_a_directory_role": len(all_principals),
        # --- the headline ---
        "global_administrator_count": sum(r["member_count"] for r in global_admin_roles),
        "global_administrator_role_activated": bool(global_admin_roles),
        # --- privileged breadth ---
        "privileged_roles_activated": len(privileged),
        "privileged_roles_with_members": sum(1 for r in privileged if r["member_count"]),
        "privileged_role_names_assigned": sorted(
            r["display_name"] or "" for r in privileged if r["member_count"]
        ),
        "privileged_role_assignments": sum(r["member_count"] for r in privileged),
        "distinct_privileged_principals": len(privileged_principals),
        # --- what kind of principal holds the power ---
        "users_in_privileged_roles": sum(r["user_member_count"] for r in privileged),
        "groups_in_privileged_roles": sum(r["group_member_count"] for r in privileged),
        "service_principals_in_privileged_roles": sum(
            r["service_principal_member_count"] for r in privileged
        ),
        "privileged_assignment_percentage": coverage_percentage(
            sum(r["member_count"] for r in privileged), sum(r["member_count"] for r in roles)
        ),
        # An activated role with no members was assigned once and revoked.
        "roles_with_no_members": sum(1 for r in roles if not r["member_count"]),
    }


# --- collection (lazy msgraph imports) ---

async def _collect(collector: Collector, cred) -> tuple[list[dict], dict]:
    """One directory_roles.get(), then one members.get() per role.

    The per-role call cannot be avoided: Graph does not return members on the collection
    response and `$expand=members` is not supported on /directoryRoles. The call count
    is bounded by the ACTIVATED roles, not by the ~100 role templates.
    """

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        projected = [
            project_directory_role(r)
            for r in await paginate(
                collector, "graph.directoryRoles.get", client.directory_roles
            )
        ]

        records = []
        for role in projected:
            role_id = role.get("id")
            if not role_id:
                collector.record(
                    "graph.directoryRoles.members.get",
                    RuntimeError(f"directory role {role.get('display_name')!r} has no id"),
                )
                continue
            members = await paginate(
                collector,
                f"graph.directoryRoles({role.get('display_name')}).members.get",
                client.directory_roles.by_directory_role_id(role_id).members,
            )
            records.append(
                directory_role_record(role, [project_member(m) for m in members])
            )

        logger.info(
            "Collected %d activated directory role(s) with %d member assignment(s)",
            len(records),
            sum(r["member_count"] for r in records),
        )
        # Sorted by display name so a re-run against an unchanged directory is
        # byte-stable; Graph does not promise a stable role order.
        return sorted(records, key=lambda r: (r.get("display_name") or "", r.get("id") or "")), tenant

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], {"tenant_source": "unresolved"})


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-*, msgraph, kiota and httpx stacks log every request at INFO, which
    # would dominate the runner's stderr tail. Warnings and errors still come through.
    for noisy in ("azure", "msgraph", "kiota", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        roles: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
    else:
        roles, tenant = asyncio.run(_collect(collector, cred))

    # No `provider_registration_status()` call, deliberately: Graph is not an ARM
    # resource provider, and the "empty vs. not in use" ambiguity it resolves cannot
    # arise here — /directoryRoles returns only ACTIVATED roles.
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={
            "directory_roles": roles,
            "privileged_role_names_checked": sorted(PRIVILEGED_ROLE_NAMES),
        },
        summary=summarize(roles),
    )

    filename = f"azure_entra_privileged_roles_{tenant_filename_key(tenant)}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
