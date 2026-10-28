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
    GLOBAL_ADMINISTRATOR,
    GLOBAL_ADMINISTRATOR_TEMPLATE_ID,
    PRIVILEGED_ROLE_NAMES,
    graph_attr,
    is_privileged_role,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_privileged_roles")

# The members collection is typed as directoryObject and the concrete kind shows up
# only in @odata.type. It matters: a role-assignable GROUP moves the real access
# decision elsewhere, and a SERVICE PRINCIPAL has no interactive sign-in for MFA or
# Conditional Access to gate.
SERVICE_PRINCIPAL_ODATA_TYPE = "#microsoft.graph.servicePrincipal"
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


def merge_service_principals(members: list[dict], service_principals: list[dict] | None) -> list[dict]:
    """Add the role's service principals that the members list left out, each once."""
    seen = {m.get("id") for m in members}
    extra = []
    for sp in service_principals or []:
        if sp.get("id") not in seen:
            seen.add(sp.get("id"))
            extra.append({**sp, "odata_type": sp.get("odata_type") or SERVICE_PRINCIPAL_ODATA_TYPE})
    return members + extra


def directory_role_record(
    role: dict, members: list[dict], service_principals_read: bool = True, members_read: bool = True
) -> dict:
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
        "members_read": members_read,
        "service_principal_members_read": service_principals_read,
    }


def summarize(roles: list[dict], roles_read: bool = True) -> dict:
    """The Global Administrator count is the headline.

    It is the number CIS Azure 1.1.3 and Prowler's
    entra_global_admin_in_less_than_five_users are written against.
    `distinct_privileged_principals` sits alongside the raw assignment count because one
    person holding six privileged roles is one human to review, not six. A figure is None,
    not 0, when the role list or a members read it depends on failed.
    """
    privileged = [r for r in roles if r["is_privileged"]]
    global_admin_roles = [r for r in roles if r["is_global_administrator"]]
    privileged_principals = {
        m["id"] for r in privileged for m in r["members"] if m.get("id")
    }
    all_principals = {m["id"] for r in roles for m in r["members"] if m.get("id")}

    def known(value, rows=(), read="members_read"):
        return value if roles_read and all(r[read] for r in rows) else None

    return {
        # Activated roles only — see the module docstring on why that is complete.
        "total_directory_roles_activated": known(len(roles)),
        "total_role_assignments": known(sum(r["member_count"] for r in roles), roles),
        "distinct_principals_with_a_directory_role": known(len(all_principals), roles),
        # --- the headline ---
        "global_administrator_count": known(
            sum(r["member_count"] for r in global_admin_roles), global_admin_roles
        ),
        "global_administrator_role_activated": known(bool(global_admin_roles)),
        # --- privileged breadth ---
        "privileged_roles_activated": known(len(privileged)),
        "privileged_roles_with_members": known(
            sum(1 for r in privileged if r["member_count"]), privileged
        ),
        "privileged_role_names_assigned": known(
            sorted(r["display_name"] or "" for r in privileged if r["member_count"]), privileged
        ),
        "privileged_role_assignments": known(sum(r["member_count"] for r in privileged), privileged),
        "distinct_privileged_principals": known(len(privileged_principals), privileged),
        # --- what kind of principal holds the power ---
        "users_in_privileged_roles": known(sum(r["user_member_count"] for r in privileged), privileged),
        "groups_in_privileged_roles": known(sum(r["group_member_count"] for r in privileged), privileged),
        # Only the servicePrincipal cast lists every service principal, so only it must be read.
        "service_principals_in_privileged_roles": known(
            sum(r["service_principal_member_count"] for r in privileged),
            privileged,
            "service_principal_members_read",
        ),
        "privileged_assignment_percentage": known(
            coverage_percentage(
                sum(r["member_count"] for r in privileged), sum(r["member_count"] for r in roles)
            ),
            roles,
        ),
        # An activated role with no members was assigned once and revoked.
        "roles_with_no_members": known(sum(1 for r in roles if not r["member_count"]), roles),
    }


# --- collection (lazy msgraph imports) ---

async def _collect(collector: Collector, cred) -> tuple[list[dict], dict, bool]:
    """One directory_roles.get(), then members.get() and the servicePrincipal cast per role.

    The per-role calls cannot be avoided: Graph does not return members on the collection
    response and `$expand=members` is not supported on /directoryRoles. The call count
    is bounded by the ACTIVATED roles, not by the ~100 role templates. On a real tenant,
    v1.0 members.get() left out every service principal holding the role, which beta and
    the /members/microsoft.graph.servicePrincipal cast both listed, so the cast is read too.
    """

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        before = len(collector.failures)
        projected = [
            project_directory_role(r)
            for r in await paginate(
                collector, "graph.directoryRoles.get", client.directory_roles
            )
        ]

        # A role left out below would read as one with no members, so the list counts as unread.
        roles_read = len(collector.failures) == before and all(r.get("id") for r in projected)
        records = []
        for role in projected:
            role_id = role.get("id")
            if not role_id:
                collector.record(
                    "graph.directoryRoles.members.get",
                    RuntimeError(f"directory role {role.get('display_name')!r} has no id"),
                )
                continue
            name = role.get("display_name")
            members_builder = client.directory_roles.by_directory_role_id(role_id).members
            before = len(collector.failures)
            members = await paginate(collector, f"graph.directoryRoles({name}).members.get", members_builder)
            members_read = len(collector.failures) == before
            try:
                service_principals = await paginate(
                    collector,
                    f"graph.directoryRoles({name}).members.graphServicePrincipal.get",
                    members_builder.graph_service_principal,
                    raise_on_error=True,
                )
            except Exception as exc:  # noqa: BLE001 — boundary: record it, and the count reads unknown
                collector.record(f"graph.directoryRoles({name}).members.graphServicePrincipal.get", exc)
                service_principals = None
            records.append(
                directory_role_record(
                    role,
                    merge_service_principals(
                        [project_member(m) for m in members],
                        None if service_principals is None else [project_member(m) for m in service_principals],
                    ),
                    service_principals_read=service_principals is not None,
                    members_read=members_read,
                )
            )

        logger.info(
            "Collected %d activated directory role(s) with %d member assignment(s)",
            len(records),
            sum(r["member_count"] for r in records),
        )
        # Sorted by display name so a re-run against an unchanged directory is
        # byte-stable; Graph does not promise a stable role order.
        records = sorted(records, key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
        return records, tenant, roles_read

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], {"tenant_source": "unresolved"}, False)


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
        roles_read = False
    else:
        roles, tenant, roles_read = asyncio.run(_collect(collector, cred))

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
        summary=summarize(roles, roles_read),
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
