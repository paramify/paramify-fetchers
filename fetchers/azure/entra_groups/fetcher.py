#!/usr/bin/env python3
"""Microsoft Entra ID groups: members, owners, and whether membership is by rule, by hand or synced."""

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
    credential,
    failure_reason,
    report_failure,
    write_evidence,
)
from entra_graph import (  # noqa: E402
    graph_attr,
    graph_host,
    graph_list,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_groups")

GROUP_SELECT = (
    "id",
    "displayName",
    "description",
    "groupTypes",
    "securityEnabled",
    "mailEnabled",
    "isAssignableToRole",
    "membershipRule",
    "membershipRuleProcessingState",
    "onPremisesSyncEnabled",
    "visibility",
    "createdDateTime",
)
PRINCIPAL_SELECT = ("id", "displayName", "userPrincipalName", "accountEnabled", "userType")
MEMBERS_EXPAND = f"members($select={','.join(PRINCIPAL_SELECT)})"
OWNERS_EXPAND = f"owners($select={','.join(PRINCIPAL_SELECT)})"

# Graph returns at most 20 expanded directory objects and no nextLink for the rest.
EXPAND_LIMIT = 20

GROUP_TYPE_UNIFIED = "Unified"
GROUP_TYPE_DYNAMIC = "DynamicMembership"
RULE_PAUSED = "Paused"
VISIBILITY_HIDDEN_MEMBERSHIP = "HiddenMembership"
USER_TYPE_GUEST = "Guest"

KIND_MICROSOFT_365 = "microsoft_365"
KIND_SECURITY = "security"
KIND_MAIL_ENABLED_SECURITY = "mail_enabled_security"
KIND_DISTRIBUTION = "distribution"
KIND_OTHER = "other"


# --- projections: the only code here that touches a Graph model ---

def project_group(group) -> dict:
    return {
        "id": graph_attr(group, "id"),
        "display_name": graph_attr(group, "display_name"),
        "description": graph_attr(group, "description"),
        "group_types": graph_list(group, "group_types"),
        "security_enabled": graph_attr(group, "security_enabled"),
        "mail_enabled": graph_attr(group, "mail_enabled"),
        "is_assignable_to_role": graph_attr(group, "is_assignable_to_role"),
        "membership_rule": graph_attr(group, "membership_rule"),
        "membership_rule_processing_state": graph_attr(group, "membership_rule_processing_state"),
        "on_premises_sync_enabled": graph_attr(group, "on_premises_sync_enabled"),
        "visibility": graph_attr(group, "visibility"),
        "created_date_time": graph_attr(group, "created_date_time"),
    }


def project_principal(obj) -> dict:
    """A member or owner: a user, group, service principal, device or contact."""
    return {
        "id": graph_attr(obj, "id"),
        "odata_type": graph_attr(obj, "odata_type"),
        "display_name": graph_attr(obj, "display_name"),
        "user_principal_name": graph_attr(obj, "user_principal_name"),
        "account_enabled": graph_attr(obj, "account_enabled"),
        "user_type": graph_attr(obj, "user_type"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def principal_type(odata_type) -> str:
    """'#microsoft.graph.servicePrincipal' -> 'ServicePrincipal'."""
    tail = str(odata_type or "").rsplit(".", 1)[-1]
    return (tail[:1].upper() + tail[1:]) if tail else "Unknown"


def principal_record(p: dict) -> dict:
    enabled = p.get("account_enabled")
    return {
        "id": p.get("id"),
        "principal_type": principal_type(p.get("odata_type")),
        "display_name": p.get("display_name"),
        "user_principal_name": p.get("user_principal_name"),
        "user_type": p.get("user_type"),
        "account_enabled": None if enabled is None else bool(enabled),
    }


def _principals(items: list[dict] | None) -> list[dict] | None:
    if items is None:
        return None
    return sorted(
        (principal_record(p) for p in items),
        key=lambda r: ((r["user_principal_name"] or r["display_name"] or "").lower(), r["id"] or ""),
    )


def group_kind(group: dict) -> str:
    if GROUP_TYPE_UNIFIED in (group.get("group_types") or []):
        return KIND_MICROSOFT_365
    security, mail = bool(group.get("security_enabled")), bool(group.get("mail_enabled"))
    if security:
        return KIND_MAIL_ENABLED_SECURITY if mail else KIND_SECURITY
    return KIND_DISTRIBUTION if mail else KIND_OTHER


def _limited(users: list[dict]) -> bool:
    """A user read without User.Read.All comes back as an id and a type only; a nested
    $select can also drop fields silently (a Graph known issue)."""
    return any(
        u["user_principal_name"] is None or u["user_type"] is None or u["account_enabled"] is None
        for u in users
    )


def owners_in_graph(group: dict) -> bool:
    """Graph returns no owners for synced groups, distribution groups or groups created in Exchange."""
    return not group.get("on_premises_sync_enabled") and group_kind(group) not in (
        KIND_DISTRIBUTION, KIND_MAIL_ENABLED_SECURITY,
    )


def _enabled_owner(owners: list[dict] | None) -> bool | None:
    if owners is None:
        return None
    if any(o["account_enabled"] for o in owners):
        return True
    return None if any(o["account_enabled"] is None for o in owners) else False


def group_record(group: dict, members: list[dict] | None, owners: list[dict] | None) -> dict:
    hidden = group.get("visibility") == VISIBILITY_HIDDEN_MEMBERSHIP
    # Without Member.Read.Hidden, Graph returns a hidden group's members as an empty list, no error.
    hidden_unread = hidden and members == []
    visible_owners = owners_in_graph(group)
    members = None if hidden_unread else _principals(members)
    owners = _principals(owners) if visible_owners else None
    dynamic = GROUP_TYPE_DYNAMIC in (group.get("group_types") or [])
    users = [m for m in members or [] if m["principal_type"] == "User"]

    def count(kind):
        return None if members is None else sum(1 for m in members if m["principal_type"] == kind)

    details = members is not None and not _limited(users)
    guests = sum(1 for u in users if u["user_type"] == USER_TYPE_GUEST)
    disabled = sum(1 for u in users if u["account_enabled"] is False)
    return {
        "id": group.get("id"),
        "display_name": group.get("display_name"),
        "description": group.get("description"),
        "kind": group_kind(group),
        "group_types": sorted(group.get("group_types") or []),
        "security_enabled": bool(group.get("security_enabled")),
        "mail_enabled": bool(group.get("mail_enabled")),
        "is_role_assignable": bool(group.get("is_assignable_to_role")),
        "membership_type": "dynamic" if dynamic else "assigned",
        "membership_rule": group.get("membership_rule"),
        "membership_rule_processing_state": group.get("membership_rule_processing_state"),
        "dynamic_rule_paused": dynamic and group.get("membership_rule_processing_state") == RULE_PAUSED,
        "is_synced": bool(group.get("on_premises_sync_enabled")),
        "hidden_membership": hidden,
        "hidden_members_unread": hidden_unread,
        "visibility": group.get("visibility"),
        "created_date_time": group.get("created_date_time"),
        "members": members,
        "member_count": None if members is None else len(members),
        "user_member_count": count("User"),
        "group_member_count": count("Group"),
        "service_principal_member_count": count("ServicePrincipal"),
        "device_member_count": count("Device"),
        "guest_member_count": guests if details else None,
        "disabled_user_member_count": disabled if details else None,
        "owners_in_graph": visible_owners,
        "owners": owners,
        "owner_count": None if owners is None else len(owners),
        "has_owner": None if owners is None else bool(owners),
        "has_enabled_owner": _enabled_owner(owners),
    }


def build_records(groups: list[dict], members: dict | None, owners: dict | None) -> list[dict]:
    """`members` and `owners` map group id -> principals; None means unreadable."""
    records = [
        group_record(
            g,
            None if members is None else members.get(g["id"], []),
            # A group missing from the owner pass (created between the two reads) is unknown.
            None if owners is None else owners.get(g["id"]),
        )
        for g in groups
    ]
    return sorted(records, key=lambda r: ((r["display_name"] or "").lower(), r["id"] or ""))


FLAG_KEYS = (
    "groups_readable", "members_readable", "member_details_readable", "owners_readable", "owner_details_readable",
)


def summarize(
    records: list[dict], groups_readable: bool, members_readable: bool, owners_readable: bool
) -> dict:
    """Group counts; a figure that needs an unreadable read is None, not 0."""
    def n(predicate, rows=records):
        return sum(1 for r in rows if predicate(r))

    def when(ok, value):
        return value if ok else None

    read = [r for r in records if r["members"] is not None]
    details_ok = members_readable and all(r["guest_member_count"] is not None for r in read)
    owner_details_ok = owners_readable and all(
        o["account_enabled"] is not None for r in records for o in r["owners"] or []
    )
    role_assignable = [r for r in records if r["is_role_assignable"]]
    cloud = [r for r in records if not r["is_synced"]]
    summary = {
        # --- what was checked ---
        "total_groups": len(records),
        "groups_readable": groups_readable,
        "members_readable": members_readable,
        "member_details_readable": details_ok,
        "owners_readable": owners_readable,
        "owner_details_readable": owner_details_ok,
        # --- what kinds of groups exist ---
        "security_groups": n(lambda r: r["kind"] == KIND_SECURITY),
        "mail_enabled_security_groups": n(lambda r: r["kind"] == KIND_MAIL_ENABLED_SECURITY),
        "microsoft_365_groups": n(lambda r: r["kind"] == KIND_MICROSOFT_365),
        "distribution_groups": n(lambda r: r["kind"] == KIND_DISTRIBUTION),
        # --- which groups can hold directory roles ---
        "role_assignable_groups": len(role_assignable),
        "role_assignable_groups_without_owner": when(
            owners_readable, n(lambda r: r["has_owner"] is False, role_assignable)
        ),
        "role_assignable_groups_with_guest_members": when(
            details_ok, n(lambda r: r["guest_member_count"], role_assignable)
        ),
        "users_in_role_assignable_groups": when(
            members_readable,
            len({
                m["id"] for r in role_assignable for m in r["members"] or []
                if m["principal_type"] == "User"
            }),
        ),
        # --- how membership is managed ---
        "dynamic_groups": n(lambda r: r["membership_type"] == "dynamic"),
        "dynamic_groups_paused": n(lambda r: r["dynamic_rule_paused"]),
        "assigned_groups": n(lambda r: r["membership_type"] == "assigned"),
        "synced_groups": n(lambda r: r["is_synced"]),
        "cloud_groups": len(cloud),
        "hidden_membership_groups": n(lambda r: r["hidden_membership"]),
        "hidden_membership_groups_unread": when(members_readable, n(lambda r: r["hidden_members_unread"])),
        # --- who owns each group ---
        "groups_with_owners_not_in_graph": n(lambda r: not r["owners_in_graph"]),
        "groups_without_owner": when(owners_readable, n(lambda r: r["has_owner"] is False)),
        "cloud_groups_without_owner": when(owners_readable, n(lambda r: r["has_owner"] is False, cloud)),
        "groups_with_only_disabled_owners": when(
            owner_details_ok, n(lambda r: r["has_owner"] and r["has_enabled_owner"] is False)
        ),
        # --- who is in them ---
        "total_direct_memberships": when(
            members_readable, sum(r["member_count"] or 0 for r in records)
        ),
        "empty_groups": when(members_readable, n(lambda r: r["member_count"] == 0)),
        "groups_with_guest_members": when(details_ok, n(lambda r: r["guest_member_count"])),
        "groups_with_disabled_user_members": when(
            details_ok, n(lambda r: r["disabled_user_member_count"])
        ),
        "groups_with_nested_groups": when(members_readable, n(lambda r: r["group_member_count"])),
        "groups_with_service_principal_members": when(
            members_readable, n(lambda r: r["service_principal_member_count"])
        ),
    }
    if not groups_readable:
        # A partial group list would pass for the whole tenant.
        summary = {k: (v if k in FLAG_KEYS else None) for k, v in summary.items()}
    return summary


# --- collection (lazy msgraph imports) ---

async def _expanded(collector, operation, builder, config, attr, item_reader):
    """(groups, {group id: projected principals}, whole list read) from one paged $expand read.

    A group at EXPAND_LIMIT is re-read on its own, paged. The map is None if any read
    failed, since a partial membership would understate every count built on it.
    """
    before = len(collector.failures)
    listed = await paginate(collector, operation, builder, config)
    list_ok = len(collector.failures) == before
    groups, related = [], {}
    for group in listed:
        gid = graph_attr(group, "id")
        items = list(getattr(group, attr, None) or [])
        if len(items) >= EXPAND_LIMIT:
            items = await item_reader(gid)
        groups.append(group)
        related[gid] = [project_principal(p) for p in items]
    return groups, (related if len(collector.failures) == before else None), list_ok


async def _collect(collector: Collector, cred):
    """Groups with their members, then their owners, re-reading any group at the expand limit."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        from kiota_abstractions.base_request_configuration import RequestConfiguration
        from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder

        query = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters
        select = ",".join(PRINCIPAL_SELECT)

        # v1.0 /members and /owners leave out service principals; beta and $expand don't.
        async def members_of(gid):
            url = f"{graph_host()}/beta/groups/{gid}/members?$select={select}&$top=999"
            return await paginate(
                collector,
                f"graph.groups({gid}).members.get(beta)",
                client.groups.by_group_id(gid).members.with_url(url),
            )

        async def owners_of(gid):
            url = f"{graph_host()}/beta/groups/{gid}/owners?$select={select}&$top=999"
            return await paginate(
                collector,
                f"graph.groups({gid}).owners.get(beta)",
                client.groups.by_group_id(gid).owners.with_url(url),
            )

        groups, members, groups_ok = await _expanded(
            collector,
            "graph.groups.get($expand=members)",
            client.groups,
            RequestConfiguration(
                query_parameters=query(select=list(GROUP_SELECT), expand=[MEMBERS_EXPAND])
            ),
            "members",
            members_of,
        )
        owners = None
        if groups or members is not None:
            _, owners, _ = await _expanded(
                collector,
                "graph.groups.get($expand=owners)",
                client.groups,
                RequestConfiguration(query_parameters=query(select=["id"], expand=[OWNERS_EXPAND])),
                "owners",
                owners_of,
            )
        logger.info("Collected %d group(s)", len(groups))
        records = build_records([project_group(g) for g in groups], members, owners)
        return records, tenant, groups_ok, members is not None, owners is not None

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], {"tenant_source": "unresolved"}, False, False, False)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    for noisy in ("azure", "msgraph", "kiota", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        records: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
        groups_ok = members_ok = owners_ok = False
    else:
        records, tenant, groups_ok, members_ok, owners_ok = asyncio.run(_collect(collector, cred))

    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={"groups": records},
        summary=summarize(records, groups_ok, members_ok, owners_ok),
    )

    filename = f"azure_entra_groups_{tenant_filename_key(tenant)}.json"
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
