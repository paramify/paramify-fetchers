#!/usr/bin/env python3
"""
Microsoft Entra ID multi-factor authentication coverage

Every user with whether the account is enabled, when it last signed in, and whether it is
MFA-capable — the fact the Entra admin center's "MFA capable" column reports. Two Graph
reads are joined because neither answers alone: `users` has no MFA field, and
`reports/authenticationMethods/userRegistrationDetails` says nothing about whether the
account is still enabled.

Who is an admin comes from the directory, not from the registration report: the
privileged directory roles' members (`GET /directoryRoles`, then each privileged role's
members, with a role-assignable group expanded to its users). The report's own `isAdmin`
flag exists only on users that have a report row, so an admin who never registered a
method would drop out of the admin denominator entirely and overstate admin coverage.
Only ACTIVE assignments are visible there; a PIM-eligible admin who has not activated
counts as an admin only if the report's flag says so.

Projections and the join ported from Prowler's
prowler/providers/azure/services/entra/entra_service.py `_get_users` and
`_get_user_registration_details` (Apache-2.0), including their `$select` projection and
manual `odata_next_link` pagination.
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
    graph_list,
    is_privileged_role,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_mfa_status")

# Prowler's list plus userPrincipalName and userType. Not just a size optimization:
# signInActivity is only returned when ASKED for by name, so omitting the $select would
# silently produce a null last_sign_in for every user.
USER_SELECT = (
    "id",
    "displayName",
    "userPrincipalName",
    "accountEnabled",
    "userType",
    "signInActivity",
)

# Graph's userType for an invited external identity. Counted separately because guest
# MFA is often owned by the inviting tenant.
GUEST_USER_TYPE = "guest"

# Directory-role members arrive as directoryObject; the concrete kind is only in
# @odata.type. A user holds the role directly; a role-assignable group passes it on to
# every user in it.
ODATA_USER = "#microsoft.graph.user"
ODATA_GROUP = "#microsoft.graph.group"


# --- projections: the only code here that touches a Graph model ---

def project_user(user) -> dict:
    """Read a `User` model's attributes into a flat snake_case dict.

    `sign_in_activity` is absent both for an account that has never signed in and on a
    tenant without AuditLog.Read.All; `graph_attr`'s None-tolerance covers both.

    `last_successful_sign_in` is kept alongside `last_sign_in` because
    `lastSignInDateTime` records the last sign-in ATTEMPT, so a stale account being
    password-sprayed looks recently active by that field alone.
    """
    sign_in_activity = graph_attr(user, "sign_in_activity")
    return {
        "id": graph_attr(user, "id"),
        "display_name": graph_attr(user, "display_name"),
        "user_principal_name": graph_attr(user, "user_principal_name"),
        "account_enabled": graph_attr(user, "account_enabled"),
        "user_type": graph_attr(user, "user_type"),
        "last_sign_in": graph_attr(sign_in_activity, "last_sign_in_date_time"),
        "last_successful_sign_in": graph_attr(
            sign_in_activity, "last_successful_sign_in_date_time"
        ),
        "last_non_interactive_sign_in": graph_attr(
            sign_in_activity, "last_non_interactive_sign_in_date_time"
        ),
    }


def project_registration_details(detail) -> dict:
    """Read a `UserRegistrationDetails` model's attributes into a flat dict.

    Prowler takes only `is_mfa_capable`. The rest arrive in the SAME response body at no
    extra cost, so they are projected rather than discarded.
    """
    return {
        "id": graph_attr(detail, "id"),
        "is_mfa_capable": graph_attr(detail, "is_mfa_capable"),
        "is_mfa_registered": graph_attr(detail, "is_mfa_registered"),
        "is_passwordless_capable": graph_attr(detail, "is_passwordless_capable"),
        "is_sspr_capable": graph_attr(detail, "is_sspr_capable"),
        "is_sspr_registered": graph_attr(detail, "is_sspr_registered"),
        "is_admin": graph_attr(detail, "is_admin"),
        "methods_registered": graph_list(detail, "methods_registered"),
        "last_updated": graph_attr(detail, "last_updated_date_time"),
        "user_preferred_method_for_secondary_authentication": graph_attr(
            detail, "user_preferred_method_for_secondary_authentication"
        ),
    }


def project_directory_role(role) -> dict:
    return {
        "id": graph_attr(role, "id"),
        "role_template_id": graph_attr(role, "role_template_id"),
        "display_name": graph_attr(role, "display_name"),
    }


def project_directory_object(obj) -> dict:
    """A role or group member: only its id and concrete kind are needed here."""
    return {"id": graph_attr(obj, "id"), "odata_type": graph_attr(obj, "odata_type")}


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def admin_roles_by_user(assignments: list[dict]) -> dict[str, list[str]]:
    """User object id -> the privileged directory roles that user holds, sorted.

    `assignments` is one entry per privileged role, `{"role": name, "user_ids": [...]}`,
    with group members already expanded to their users.
    """
    by_user: dict[str, set[str]] = {}
    for assignment in assignments:
        for user_id in assignment.get("user_ids") or []:
            if user_id:
                by_user.setdefault(user_id, set()).add(assignment.get("role") or "")
    return {user_id: sorted(roles) for user_id, roles in by_user.items()}


def user_record(
    user: dict, registration: dict | None, admin_roles: list[str] | None = None
) -> dict:
    """Join one projected user with its projected registration details.

    Every boolean is coerced with `bool(x or False)` so both absences read as `false`,
    not `null`: Graph omits a false-y field rather than sending `false`, and a user with
    no registration-details row has registered nothing. A validator regex asserting
    `"is_mfa_capable": false` would not match `null`. `has_registration_details` keeps
    the two absences distinguishable.

    `account_enabled` defaults the other way, as Prowler does: `accountEnabled` is only
    omitted when it was not selected, and an account assumed disabled would drop out of
    the coverage denominator and understate exposure. Absent therefore reads as enabled.

    `is_admin` is true when the user holds a privileged directory role OR the
    registration report flags them. `admin_roles` is None when role membership could not
    be read, and then only the report's flag is left to go on.
    """
    details = registration if isinstance(registration, dict) else {}
    enabled = user.get("account_enabled")
    report_admin = bool(details.get("is_admin") or False)
    return {
        "id": user.get("id"),
        "display_name": user.get("display_name"),
        "user_principal_name": user.get("user_principal_name"),
        "account_enabled": True if enabled is None else bool(enabled),
        "user_type": user.get("user_type"),
        "is_guest": str(user.get("user_type") or "").lower() == GUEST_USER_TYPE,
        "last_sign_in": user.get("last_sign_in"),
        "last_successful_sign_in": user.get("last_successful_sign_in"),
        "last_non_interactive_sign_in": user.get("last_non_interactive_sign_in"),
        "has_registration_details": bool(details),
        "is_mfa_capable": bool(details.get("is_mfa_capable") or False),
        "is_mfa_registered": bool(details.get("is_mfa_registered") or False),
        "is_passwordless_capable": bool(details.get("is_passwordless_capable") or False),
        "is_sspr_capable": bool(details.get("is_sspr_capable") or False),
        "is_sspr_registered": bool(details.get("is_sspr_registered") or False),
        "is_admin": bool(admin_roles) or report_admin,
        "privileged_directory_roles": admin_roles,
        "is_admin_in_registration_report": report_admin,
        "methods_registered": sorted(details.get("methods_registered") or []),
        "preferred_secondary_method": details.get(
            "user_preferred_method_for_secondary_authentication"
        ),
        "registration_last_updated": details.get("last_updated"),
    }


def join_users(
    users: list[dict],
    registrations: list[dict],
    admin_roles: dict[str, list[str]] | None = None,
) -> list[dict]:
    """Join the users list against the registration report on the user's object id.

    `userRegistrationDetails.id` IS the user's object id, which makes the join a plain
    dict lookup; Prowler relies on the same identity. `admin_roles` (from
    `admin_roles_by_user`) is joined on the same id; None means role membership could
    not be read, which every record then says with `privileged_directory_roles: null`.

    Sorted by UPN (falling back to id) for byte-stable re-runs: Graph promises no stable
    order across pages, so an unsorted list would make every run look like a change.
    """
    by_id = {r.get("id"): r for r in registrations if r.get("id")}
    records = [
        user_record(
            u,
            by_id.get(u.get("id")),
            None if admin_roles is None else admin_roles.get(u.get("id"), []),
        )
        for u in users
    ]
    return sorted(records, key=lambda r: (r.get("user_principal_name") or "", r.get("id") or ""))


# Figures that rely on the registration report, null when it couldn't be read in full.
REGISTRATION_FIGURES = (
    "mfa_capable_users",
    "mfa_capable_enabled_users",
    "mfa_coverage_percentage",
    "mfa_coverage_percentage_all_users",
    "enabled_users_without_mfa",
    "mfa_registered_enabled_users",
    "passwordless_capable_enabled_users",
    "passwordless_coverage_percentage",
    "sspr_registered_enabled_users",
    "mfa_capable_enabled_member_users",
    "member_mfa_coverage_percentage",
    "mfa_capable_admin_users",
    "admin_mfa_coverage_percentage",
    "admin_users_without_mfa",
    "admin_users_without_registration_details",
    "users_with_registration_details",
    "users_without_registration_details",
)


def summarize(
    users: list[dict],
    admin_roles_readable: bool = True,
    users_read: bool = True,
    registrations_read: bool = True,
) -> dict:
    """MFA coverage over ENABLED users is the headline.

    A disabled account cannot sign in, so counting it as uncovered makes a well-run
    tenant with years of deprovisioned accounts look worse than a small neglected one.
    Coverage over all users is reported too, so neither reading looks cherry-picked. It
    leaves out users with no registration-report row: the report omits disabled accounts,
    so their MFA is unknown, not absent.

    The admin figures are None when directory-role membership could not be read in
    full: the registration report alone misses every admin without a report row, which
    is exactly the admin most likely to have no MFA. Likewise every figure is None when
    the users list wasn't read in full, and the report's figures when the report wasn't.
    """
    enabled = [u for u in users if u["account_enabled"]]
    enabled_members = [u for u in enabled if not u["is_guest"]]
    reported = [u for u in users if u["has_registration_details"]]
    admins = [u for u in users if u["is_admin"]]

    def admin_figure(value):
        return value if admin_roles_readable else None

    summary = {
        "total_users": len(users),
        "enabled_users": len(enabled),
        "disabled_users": len(users) - len(enabled),
        "guest_users": sum(1 for u in users if u["is_guest"]),
        "mfa_capable_users": sum(1 for u in users if u["is_mfa_capable"]),
        "mfa_capable_enabled_users": sum(1 for u in enabled if u["is_mfa_capable"]),
        # The headline: of the accounts that can sign in, how many can MFA.
        "mfa_coverage_percentage": coverage_percentage(
            sum(1 for u in enabled if u["is_mfa_capable"]), len(enabled)
        ),
        "mfa_coverage_percentage_all_users": coverage_percentage(
            sum(1 for u in reported if u["is_mfa_capable"]), len(reported)
        ),
        "enabled_users_without_mfa": sum(1 for u in enabled if not u["is_mfa_capable"]),
        "mfa_registered_enabled_users": sum(1 for u in enabled if u["is_mfa_registered"]),
        "passwordless_capable_enabled_users": sum(
            1 for u in enabled if u["is_passwordless_capable"]
        ),
        "passwordless_coverage_percentage": coverage_percentage(
            sum(1 for u in enabled if u["is_passwordless_capable"]), len(enabled)
        ),
        "sspr_registered_enabled_users": sum(1 for u in enabled if u["is_sspr_registered"]),
        # Guests split out: an unenforced guest is often the inviting tenant's to fix.
        "enabled_member_users": len(enabled_members),
        "mfa_capable_enabled_member_users": sum(
            1 for u in enabled_members if u["is_mfa_capable"]
        ),
        "member_mfa_coverage_percentage": coverage_percentage(
            sum(1 for u in enabled_members if u["is_mfa_capable"]), len(enabled_members)
        ),
        # Admins carry the most risk per account, so they get their own coverage.
        # Admins are privileged directory role holders, so one with no registration
        # row counts as an admin without MFA.
        "admin_role_membership_readable": admin_roles_readable,
        "admin_users": admin_figure(len(admins)),
        "mfa_capable_admin_users": admin_figure(sum(1 for u in admins if u["is_mfa_capable"])),
        "admin_mfa_coverage_percentage": admin_figure(
            coverage_percentage(sum(1 for u in admins if u["is_mfa_capable"]), len(admins))
        ),
        "admin_users_without_mfa": admin_figure(
            sum(1 for u in admins if not u["is_mfa_capable"])
        ),
        "admin_users_without_registration_details": admin_figure(
            sum(1 for u in admins if not u["has_registration_details"])
        ),
        # A user missing from the report counts as uncovered in the enabled and admin figures
        # and as unknown in the all-users one; this says how many that is.
        "users_with_registration_details": len(reported),
        "users_without_registration_details": sum(
            1 for u in users if not u["has_registration_details"]
        ),
        "users_never_signed_in": sum(1 for u in users if not u["last_sign_in"]),
    }
    if not registrations_read:
        summary.update(dict.fromkeys(REGISTRATION_FIGURES))
    if not users_read:
        summary.update(dict.fromkeys(k for k in summary if k != "admin_role_membership_readable"))
    return summary


# --- collection (lazy msgraph imports) ---

NOTHING_READ = {"admin_roles_readable": False, "users_read": False, "registrations_read": False}

async def _privileged_role_assignments(collector: Collector, client) -> list[dict] | None:
    """Each privileged directory role with the user ids holding it; None if incomplete.

    One `directoryRoles` list (activated roles only, so a role absent from it has no
    members), then one members call per PRIVILEGED role, then one `transitiveMembers`
    call per distinct role-assignable group. Any failure along the way is recorded and
    makes the whole answer None: a partial admin list would understate the denominator
    just as the registration report does.
    """
    before = len(collector.failures)
    roles = [
        project_directory_role(r)
        for r in await paginate(collector, "graph.directoryRoles.get", client.directory_roles)
    ]
    group_users: dict[str, list[str]] = {}
    assignments = []
    for role in roles:
        if not is_privileged_role(role):
            continue
        name = role.get("display_name") or role.get("role_template_id") or ""
        role_id = role.get("id")
        if not role_id:
            collector.record(
                "graph.directoryRoles.members.get",
                RuntimeError(f"directory role {name!r} has no id"),
            )
            continue
        members = [
            project_directory_object(m)
            for m in await paginate(
                collector,
                f"graph.directoryRoles({name}).members.get",
                client.directory_roles.by_directory_role_id(role_id).members,
            )
        ]
        user_ids = [m["id"] for m in members if m["odata_type"] == ODATA_USER]
        for group in members:
            gid = group["id"]
            if group["odata_type"] != ODATA_GROUP or not gid:
                continue
            if gid not in group_users:
                group_users[gid] = [
                    o["id"]
                    for o in (
                        project_directory_object(x)
                        for x in await paginate(
                            collector,
                            f"graph.groups({gid}).transitiveMembers.get",
                            client.groups.by_group_id(gid).transitive_members,
                        )
                    )
                    if o["odata_type"] == ODATA_USER
                ]
            user_ids.extend(group_users[gid])
        assignments.append({"role": name, "user_ids": user_ids})
    if len(collector.failures) > before:
        return None
    return assignments


async def _collect(collector: Collector, cred) -> tuple[list[dict], dict, dict[str, bool]]:
    """Resolve the tenant, read users, registration details and admin roles, join them."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        from kiota_abstractions.base_request_configuration import RequestConfiguration
        from msgraph.generated.users.users_request_builder import UsersRequestBuilder

        request_configuration = RequestConfiguration(
            query_parameters=UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=list(USER_SELECT)
            )
        )
        before = len(collector.failures)
        users = [
            project_user(u)
            for u in await paginate(
                collector, "graph.users.get", client.users, request_configuration
            )
        ]
        users_read = len(collector.failures) == before
        before = len(collector.failures)
        registrations = [
            project_registration_details(d)
            for d in await paginate(
                collector,
                "graph.reports.authenticationMethods.userRegistrationDetails.get",
                client.reports.authentication_methods.user_registration_details,
            )
        ]
        registrations_read = len(collector.failures) == before
        assignments = await _privileged_role_assignments(collector, client)
        admin_roles = admin_roles_by_user(assignments) if assignments is not None else None
        logger.info(
            "Collected %d users, %d registration-detail rows and %s privileged role holders",
            len(users),
            len(registrations),
            len(admin_roles) if admin_roles is not None else "unreadable",
        )
        read = {
            "admin_roles_readable": admin_roles is not None,
            "users_read": users_read,
            "registrations_read": registrations_read,
        }
        return join_users(users, registrations, admin_roles), tenant, read

    # `with_graph_client` records a construction/transport failure itself and returns the
    # default, so nothing here can raise.
    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], {"tenant_source": "unresolved"}, NOTHING_READ)


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
        users: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
        read = NOTHING_READ
    else:
        users, tenant, read = asyncio.run(_collect(collector, cred))

    # No `provider_registration_status()` call, deliberately: Graph is not an ARM
    # resource provider, and an Entra tenant always exists.
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={"users": users},
        summary=summarize(users, **read),
    )

    filename = f"azure_entra_mfa_status_{tenant_filename_key(tenant)}.json"
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
