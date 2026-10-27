#!/usr/bin/env python3
"""
Microsoft Entra ID service principals: the tenant's non-user accounts and how they authenticate

Every service principal (the identity an application or managed identity signs in as)
with its type, who owns the application behind it, and every credential it can present:
secrets and certificates held on the service principal itself, and, for an application
registered in THIS tenant, the application's own secrets, certificates and federated
identity credentials. What the evidence answers is how each non-user account
authenticates: platform-managed (managed identity), federated (no stored secret),
certificate, or client secret. It also answers whether each stored credential expires.

It also records who owns each application and service principal, and which API
permissions each non-Microsoft principal holds: application permissions (app role
assignments) and delegated grants, with privileged Microsoft Graph permissions flagged.

Paged collection reads, never one per principal except past `$expand`'s 20-item limit:

- `GET /servicePrincipals` returns every principal with its SP-held credentials. Most
  of them in a typical tenant are Microsoft first-party apps, which hold nothing locally
  and are never read individually.
- `GET /applications?$expand=federatedIdentityCredentials` returns only the
  applications registered in this tenant, which are the only ones whose application
  credentials this tenant controls, with their federated credentials inline. Graph caps
  an application at 20 federated credentials, and 20 is also `$expand`'s per-collection
  limit, so the expansion is complete. No per-application
  `/federatedIdentityCredentials` call is needed.
- `$expand=owners` on both collections and `$expand=appRoleAssignments` on the
  principals (Graph allows one `$expand` per request), `GET /oauth2PermissionGrants`,
  and one read per resource principal to name its app roles.

The two are joined on `appId`. The credential expiry classification mirrors
azure_entra_app_registrations (itself ported from Prowler's
entra_app_registration_credential_not_expired check, Apache-2.0): expired, expiring
inside 30 days, and no expiry date are three separate states.
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
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
    write_evidence,
)
from entra_graph import (  # noqa: E402
    DEFAULT_ACCESS_ROLE_ID,
    PRIVILEGED_APPLICATION_GRAPH_SUBSTRINGS,
    PRIVILEGED_GRAPH_PERMISSIONS,
    TENANT_DATA_GRAPH_PERMISSIONS,
    aguard,
    graph_attr,
    graph_list,
    is_denied,
    is_graph_resource,
    is_privileged_graph_permission,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_service_principals")

# The same rotation window as azure_entra_app_registrations (Prowler's
# EXPIRY_WARNING_DAYS), so the two fetchers classify a credential identically.
EXPIRY_WARNING_DAYS = 30

# `servicePrincipalType` values, verbatim from Graph.
SP_TYPE_APPLICATION = "Application"
SP_TYPE_MANAGED_IDENTITY = "ManagedIdentity"
SP_TYPE_LEGACY = "Legacy"
SP_TYPE_SOCIAL_IDP = "SocialIdp"

# `appOwnerOrganizationId` of Microsoft's own first-party applications: the Microsoft
# Services tenant, and the Microsoft corporate tenant that owns some older ones. A
# principal owned by any other foreign tenant is reported as `other_tenant`, not assumed
# to be a third-party vendor.
MICROSOFT_OWNER_TENANTS = frozenset(
    {
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        "72f988bf-86f1-41af-91ab-2d7cd011db47",
    }
)

OWNER_MICROSOFT = "microsoft_first_party"
OWNER_THIS_TENANT = "this_tenant"
OWNER_OTHER_TENANT = "other_tenant"
OWNER_MANAGED_IDENTITY = "managed_identity"
OWNER_UNKNOWN = "unknown"

SP_SELECT = (
    "id",
    "appId",
    "displayName",
    "servicePrincipalType",
    "accountEnabled",
    "appOwnerOrganizationId",
    "alternativeNames",
    "passwordCredentials",
    "keyCredentials",
)

# `federatedIdentityCredentials` is a navigation property: naming it in $select alone
# returns nothing for it, silently. It arrives only through $expand, which is why a
# missing APP_EXPAND would make every application look non-federated.
APP_SELECT = (
    "id",
    "appId",
    "displayName",
    "passwordCredentials",
    "keyCredentials",
)
APP_EXPAND = ("federatedIdentityCredentials",)

CREDENTIAL_PASSWORD = "password"
CREDENTIAL_CERTIFICATE = "certificate"

# Where a credential lives. An SP-held credential and an application credential both
# let the principal sign in, but they are managed in different places in the portal.
HELD_ON_SERVICE_PRINCIPAL = "service_principal"
HELD_ON_APPLICATION = "application"

# The `alternativeNames` entry that says whether a managed identity is user-assigned
# ("isExplicit=True") or system-assigned ("isExplicit=False").
IS_EXPLICIT_PREFIX = "isexplicit="

# Graph returns at most 20 expanded directory objects and no nextLink for the rest.
EXPAND_LIMIT = 20
OWNER_SELECT = ("id", "displayName", "userPrincipalName", "accountEnabled")
OWNERS_EXPAND = f"owners($select={','.join(OWNER_SELECT)})"
RESOURCE_SELECT = ("id", "appId", "displayName", "appRoles")

CONSENT_ALL_PRINCIPALS = "AllPrincipals"
PRIVILEGED_APPLICATION_GRAPH_PERMISSIONS = PRIVILEGED_GRAPH_PERMISSIONS | TENANT_DATA_GRAPH_PERMISSIONS


# --- projections: the only code here that touches a Graph model ---

def project_credential(cred_model, credential_type: str) -> dict:
    """Read a `PasswordCredential` or `KeyCredential` into a flat snake_case dict.

    The certificate body (`key`) is deliberately not projected: it is the public
    certificate, large, and says nothing about rotation. `secret_text` is never returned
    on a read, so naming it would only add an always-null field.
    """
    return {
        "display_name": graph_attr(cred_model, "display_name"),
        "credential_type": credential_type,
        "key_id": graph_attr(cred_model, "key_id"),
        "start_date_time": graph_attr(cred_model, "start_date_time"),
        "end_date_time": graph_attr(cred_model, "end_date_time"),
        "usage": graph_attr(cred_model, "usage"),
        "certificate_type": graph_attr(cred_model, "type"),
    }


def _project_credentials(model) -> list[dict]:
    """Both credential collections off a ServicePrincipal or Application model.

    Graph omits an empty collection rather than sending `[]`, hence the `or []`.
    """
    return [
        project_credential(c, CREDENTIAL_PASSWORD)
        for c in (getattr(model, "password_credentials", None) or [])
    ] + [
        project_credential(c, CREDENTIAL_CERTIFICATE)
        for c in (getattr(model, "key_credentials", None) or [])
    ]


def project_service_principal(sp) -> dict:
    """Read a `ServicePrincipal` model's attributes into a flat snake_case dict."""
    return {
        "id": graph_attr(sp, "id"),
        "app_id": graph_attr(sp, "app_id"),
        "display_name": graph_attr(sp, "display_name"),
        "service_principal_type": graph_attr(sp, "service_principal_type"),
        "account_enabled": graph_attr(sp, "account_enabled"),
        "app_owner_organization_id": graph_attr(sp, "app_owner_organization_id"),
        "alternative_names": graph_list(sp, "alternative_names"),
        "credentials": _project_credentials(sp),
    }


def project_federated_credential(fic) -> dict:
    """Read a `FederatedIdentityCredential` into a flat dict.

    `issuer` + `subject` are the whole trust: any token that issuer signs for that
    subject signs in as the application, so both are evidence, not detail.
    """
    return {
        "name": graph_attr(fic, "name"),
        "issuer": graph_attr(fic, "issuer"),
        "subject": graph_attr(fic, "subject"),
        "audiences": sorted(graph_list(fic, "audiences")),
        "description": graph_attr(fic, "description"),
    }


def project_application(app) -> dict:
    """Read an `Application` model, with its expanded federated credentials."""
    return {
        "id": graph_attr(app, "id"),
        "app_id": graph_attr(app, "app_id"),
        "display_name": graph_attr(app, "display_name"),
        "credentials": _project_credentials(app),
        "federated_identity_credentials": [
            project_federated_credential(f)
            for f in (getattr(app, "federated_identity_credentials", None) or [])
        ],
    }


def project_owner(owner) -> dict:
    """An owner is a user or a service principal; only users carry a UPN."""
    return {
        "id": graph_attr(owner, "id"),
        "odata_type": graph_attr(owner, "odata_type"),
        "display_name": graph_attr(owner, "display_name"),
        "user_principal_name": graph_attr(owner, "user_principal_name"),
        "account_enabled": graph_attr(owner, "account_enabled"),
    }


def project_app_role_assignment(assignment) -> dict:
    return {
        "id": graph_attr(assignment, "id"),
        "app_role_id": graph_attr(assignment, "app_role_id"),
        "resource_id": graph_attr(assignment, "resource_id"),
        "resource_display_name": graph_attr(assignment, "resource_display_name"),
        "created_date_time": graph_attr(assignment, "created_date_time"),
    }


def project_permission_grant(grant) -> dict:
    return {
        "id": graph_attr(grant, "id"),
        "client_id": graph_attr(grant, "client_id"),
        "consent_type": graph_attr(grant, "consent_type"),
        "principal_id": graph_attr(grant, "principal_id"),
        "resource_id": graph_attr(grant, "resource_id"),
        "scope": graph_attr(grant, "scope"),
    }


def project_resource(sp) -> dict:
    """A resource principal (an API such as Microsoft Graph) with its app role names."""
    return {
        "id": graph_attr(sp, "id"),
        "app_id": graph_attr(sp, "app_id"),
        "display_name": graph_attr(sp, "display_name"),
        "app_roles": {
            str(graph_attr(r, "id")): graph_attr(r, "value")
            for r in (getattr(sp, "app_roles", None) or [])
        },
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _parse_timestamp(value) -> datetime | None:
    """Parse an ISO-8601 timestamp to an aware datetime, or None.

    Naive values are assumed UTC, as Graph always sends UTC. Anything unparseable reads
    as None and so lands in the conservative no-expiry bucket rather than aborting the
    run.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def credential_record(cred: dict, now: datetime, held_on: str, platform_managed: bool) -> dict:
    """Classify one projected credential against `now`.

    Same three-way classification as azure_entra_app_registrations. `platform_managed`
    marks the certificate Azure issues to every managed identity and rotates itself.
    It is kept in the evidence so nothing is hidden, and left out of the expiry counts
    because no one in the tenant can rotate it or let it lapse.
    """
    end = _parse_timestamp(cred.get("end_date_time"))
    if end is None:
        days_until_expiry = None
        expired = False
        expiring_soon = False
    else:
        days_until_expiry = (end - now).days
        expired = end <= now
        expiring_soon = not expired and days_until_expiry <= EXPIRY_WARNING_DAYS

    return {
        "display_name": cred.get("display_name") or None,
        "credential_type": cred.get("credential_type"),
        "held_on": held_on,
        "platform_managed": platform_managed,
        "key_id": cred.get("key_id"),
        "start_date_time": cred.get("start_date_time"),
        "end_date_time": cred.get("end_date_time"),
        "usage": cred.get("usage"),
        "certificate_type": cred.get("certificate_type"),
        "has_expiry": end is not None,
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "expiring_soon": expiring_soon,
        "rotation_threshold_days": EXPIRY_WARNING_DAYS,
        "healthy": end is not None and not expired and not expiring_soon,
    }


def _sort_credentials(credentials: list[dict]) -> list[dict]:
    """Soonest expiry first, nulls last, then key id, for byte-stable re-runs."""
    return sorted(
        credentials,
        key=lambda c: (
            c["end_date_time"] is None,
            c["end_date_time"] or "",
            c["held_on"],
            c["key_id"] or "",
        ),
    )


def ownership(sp: dict, tenant_id: str | None, tenant_app_ids: set) -> str:
    """Who owns the application behind this service principal.

    A managed identity has no `appOwnerOrganizationId` at all, and is its own class.
    "This tenant" is decided by `appId` being among the tenant's own application
    registrations first, and by the owner id matching the tenant second, so the answer
    survives a run where the tenant id could not be resolved.
    """
    if sp.get("service_principal_type") == SP_TYPE_MANAGED_IDENTITY:
        return OWNER_MANAGED_IDENTITY
    owner = str(sp.get("app_owner_organization_id") or "").lower()
    if sp.get("app_id") in tenant_app_ids or (tenant_id and owner == str(tenant_id).lower()):
        return OWNER_THIS_TENANT
    if owner in MICROSOFT_OWNER_TENANTS:
        return OWNER_MICROSOFT
    if owner:
        return OWNER_OTHER_TENANT
    return OWNER_UNKNOWN


def managed_identity_details(alternative_names: list) -> tuple[str | None, str | None]:
    """(kind, ARM resource id) for a managed identity, from `alternativeNames`.

    Graph encodes both there: an `isExplicit=True|False` entry (user- vs
    system-assigned) and the ARM id of the identity or of the resource it belongs to.
    """
    kind = None
    resource_id = None
    for name in alternative_names or []:
        text = str(name or "")
        if text.lower().startswith(IS_EXPLICIT_PREFIX):
            explicit = text[len(IS_EXPLICIT_PREFIX):].strip().lower()
            kind = "user_assigned" if explicit == "true" else "system_assigned"
        elif text.startswith("/subscriptions/"):
            resource_id = text
    return kind, resource_id


def service_principal_record(
    sp: dict, app: dict | None, owner: str, now: datetime
) -> dict:
    """One evidence record per service principal.

    `app` is the application registration in THIS tenant with the same `appId`, or None.
    Its credentials authenticate as this principal, so they are included. A
    first-party or other-tenant principal has no local application, so only its
    SP-held credentials count.

    The `uses_*` flags are not exclusive: one principal can hold a secret AND a
    federated credential, and that combination is worth seeing, since the federated
    credential removes no risk while the secret still exists.
    """
    is_mi = sp.get("service_principal_type") == SP_TYPE_MANAGED_IDENTITY
    credentials = [
        credential_record(c, now, HELD_ON_SERVICE_PRINCIPAL, platform_managed=is_mi)
        for c in sp.get("credentials") or []
    ]
    federated = []
    if app is not None:
        credentials += [
            credential_record(c, now, HELD_ON_APPLICATION, platform_managed=False)
            for c in app.get("credentials") or []
        ]
        federated = sorted(
            app.get("federated_identity_credentials") or [],
            key=lambda f: (f.get("name") or "", f.get("issuer") or "", f.get("subject") or ""),
        )
    credentials = _sort_credentials(credentials)
    managed = [c for c in credentials if not c["platform_managed"]]

    mi_kind, mi_resource_id = managed_identity_details(sp.get("alternative_names"))
    enabled = sp.get("account_enabled")
    uses_secret = any(c["credential_type"] == CREDENTIAL_PASSWORD for c in managed)
    uses_certificate = any(c["credential_type"] == CREDENTIAL_CERTIFICATE for c in managed)
    return {
        "id": sp.get("id"),
        "app_id": sp.get("app_id"),
        "display_name": sp.get("display_name"),
        "service_principal_type": sp.get("service_principal_type"),
        # Graph omits accountEnabled only when unselected; absent reads as enabled, the
        # conservative reading for an account inventory.
        "account_enabled": True if enabled is None else bool(enabled),
        "app_owner_organization_id": sp.get("app_owner_organization_id"),
        "ownership": owner,
        "is_managed_identity": is_mi,
        "managed_identity_kind": mi_kind if is_mi else None,
        "managed_identity_resource_id": mi_resource_id if is_mi else None,
        "application_object_id": app.get("id") if app else None,
        "credentials": credentials,
        "federated_identity_credentials": federated,
        "credential_count": len(managed),
        "federated_identity_credential_count": len(federated),
        "uses_managed_identity": is_mi,
        "uses_federated_credential": bool(federated),
        "uses_certificate": uses_certificate,
        "uses_secret": uses_secret,
        "has_expired_credential": any(c["expired"] for c in managed),
        "has_credential_expiring_soon": any(c["expiring_soon"] for c in managed),
        "has_credential_without_expiry": any(not c["has_expiry"] for c in managed),
    }


def unmatched_application_record(app: dict) -> dict:
    """An application registered here with no service principal in this tenant.

    It cannot sign in to this tenant as it stands, but a multi-tenant app can sign in
    elsewhere, and a service principal can be created for it at any time. So its
    federated credentials are still counted, apart from the principals.
    """
    return {
        "id": app.get("id"),
        "app_id": app.get("app_id"),
        "display_name": app.get("display_name"),
        "credential_count": len(app.get("credentials") or []),
        "federated_identity_credential_count": len(
            app.get("federated_identity_credentials") or []
        ),
    }


def _principal_type(odata_type) -> str:
    """'#microsoft.graph.servicePrincipal' -> 'ServicePrincipal'."""
    tail = str(odata_type or "").rsplit(".", 1)[-1]
    return (tail[:1].upper() + tail[1:]) if tail else "Unknown"


def owner_record(owner: dict) -> dict:
    enabled = owner.get("account_enabled")
    return {
        "id": owner.get("id"),
        "principal_type": _principal_type(owner.get("odata_type")),
        "display_name": owner.get("display_name"),
        "user_principal_name": owner.get("user_principal_name"),
        "account_enabled": None if enabled is None else bool(enabled),
    }


def _owner_records(owners: list[dict] | None) -> list[dict] | None:
    if owners is None:
        return None
    return sorted(
        (owner_record(o) for o in owners),
        key=lambda r: ((r["user_principal_name"] or r["display_name"] or "").lower(), r["id"] or ""),
    )


def _judged(resource: dict) -> bool | None:
    """Only Microsoft Graph permissions are judged privileged or not; None when the API is unknown."""
    app_id = resource.get("app_id")
    return None if not app_id else is_graph_resource(app_id)


def application_permission_record(assignment: dict, resources: dict) -> dict:
    """One app role assignment, named from the resource's appRoles.

    `privileged` is null on an API other than Graph (`judged` false) and for an unnamed role.
    """
    resource = resources.get(assignment.get("resource_id")) or {}
    role_id = str(assignment.get("app_role_id") or "")
    default_access = role_id == DEFAULT_ACCESS_ROLE_ID
    permission = None if default_access else (resource.get("app_roles") or {}).get(role_id)
    judged = True if default_access else _judged(resource)
    privileged: bool | None = None
    if default_access:
        privileged = False
    elif judged and permission is not None:
        privileged = is_privileged_graph_permission(permission)
    return {
        "resource_id": assignment.get("resource_id"),
        "resource_app_id": resource.get("app_id"),
        "resource_display_name": assignment.get("resource_display_name") or resource.get("display_name"),
        "app_role_id": assignment.get("app_role_id"),
        "permission": permission,
        "default_access": default_access,
        "privileged": privileged,
        "judged": judged,
        "created_date_time": assignment.get("created_date_time"),
    }


def delegated_grant_record(grant: dict, resources: dict) -> dict:
    """One delegated grant: AllPrincipals is admin consent for every user, Principal one user.

    `privileged_scopes` is null on an API other than Graph (`judged` false).
    """
    resource = resources.get(grant.get("resource_id")) or {}
    scopes = sorted({s for s in str(grant.get("scope") or "").split() if s})
    judged = _judged(resource)
    return {
        "resource_id": grant.get("resource_id"),
        "resource_app_id": resource.get("app_id"),
        "resource_display_name": resource.get("display_name"),
        "consent_type": grant.get("consent_type"),
        "principal_id": grant.get("principal_id"),
        "scopes": scopes,
        "privileged_scopes": (
            [s for s in scopes if is_privileged_graph_permission(s, application=False)] if judged else None
        ),
        "judged": judged,
    }


def _privileged_flag(app_perms: list | None, grants: list | None) -> bool | None:
    """True if either holds a privileged permission; None if that can't be ruled out (unread, unnamed or not Graph)."""
    if any(p["privileged"] for p in app_perms or []) or any(
        g["privileged_scopes"] for g in grants or []
    ):
        return True
    if app_perms is None or grants is None:
        return None
    if any(p["privileged"] is None for p in app_perms) or any(g["privileged_scopes"] is None for g in grants):
        return None
    return False


def _enabled_owner_flag(has_owner: bool | None, owners: list[dict]) -> bool | None:
    """Whether any owner is an enabled account; None if owners or their account state are unread."""
    if has_owner is None:
        return None
    if any(o["account_enabled"] for o in owners):
        return True
    if any(o["account_enabled"] is None for o in owners):
        return None
    return False


def add_access(records: list[dict], unmatched: list[dict], access: dict) -> None:
    """Attach owners and granted API permissions; a None input means it was unreadable.

    `access` holds `sp_owners` and `app_owners` (object id -> owners),
    `app_role_assignments` (principal id -> assignments), `grants` (client principal id
    -> grants) and `resources` (resource principal id -> projected resource).
    """
    sp_owners, app_owners = access.get("sp_owners"), access.get("app_owners")
    assignments, grants = access.get("app_role_assignments"), access.get("grants")
    resources = access.get("resources") or {}
    # An object missing from a second-pass read (deleted between the reads) is unknown, not empty.
    for r in records:
        owners = _owner_records((sp_owners or {}).get(r["id"]))
        app_id = r["application_object_id"]
        if not app_id:
            application_owners: list[dict] | None = []  # no app registration in this tenant
        else:
            application_owners = _owner_records((app_owners or {}).get(app_id))
        r["owner_eligible"] = r["ownership"] not in (OWNER_MICROSOFT, OWNER_MANAGED_IDENTITY)
        r["owners"] = owners
        r["application_owners"] = application_owners
        if owners is None or application_owners is None:
            r["has_owner"] = None
        else:
            r["has_owner"] = bool(owners or application_owners)
        r["has_enabled_owner"] = _enabled_owner_flag(r["has_owner"], (owners or []) + (application_owners or []))

        held = (assignments or {}).get(r["id"])
        app_perms = None
        if held is not None:
            app_perms = sorted(
                (application_permission_record(a, resources) for a in held),
                key=lambda p: (
                    p["resource_display_name"] or "", p["permission"] or "", str(p["app_role_id"] or "")
                ),
            )
        sp_grants = None
        if grants is not None:
            sp_grants = sorted(
                (delegated_grant_record(g, resources) for g in grants.get(r["id"], [])),
                key=lambda g: (
                    g["resource_display_name"] or "", g["consent_type"] or "", g["principal_id"] or ""
                ),
            )
        r["application_permissions"] = app_perms
        r["delegated_permission_grants"] = sp_grants
        r["privileged_application_permissions"] = (
            None if app_perms is None else sorted({p["permission"] for p in app_perms if p["privileged"]})
        )
        r["privileged_delegated_permissions"] = (
            None if sp_grants is None else sorted({s for g in sp_grants for s in g["privileged_scopes"] or []})
        )
        r["has_privileged_permission"] = _privileged_flag(app_perms, sp_grants)

    for a in unmatched:
        owners = _owner_records((app_owners or {}).get(a["id"]))
        a["owners"] = owners
        a["has_owner"] = None if owners is None else bool(owners)
        a["has_enabled_owner"] = _enabled_owner_flag(a["has_owner"], owners or [])


def build_records(
    service_principals: list[dict], applications: list[dict], tenant_id: str | None, now: datetime
) -> tuple[list[dict], list[dict]]:
    """Join principals to this tenant's applications on appId; sort both lists."""
    apps_by_app_id = {a.get("app_id"): a for a in applications if a.get("app_id")}
    records = []
    for sp in service_principals:
        owner = ownership(sp, tenant_id, set(apps_by_app_id))
        app = apps_by_app_id.get(sp.get("app_id")) if owner == OWNER_THIS_TENANT else None
        records.append(service_principal_record(sp, app, owner, now))
    records.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))

    sp_app_ids = {sp.get("app_id") for sp in service_principals}
    unmatched = sorted(
        (unmatched_application_record(a) for a in applications if a.get("app_id") not in sp_app_ids),
        key=lambda a: (a.get("display_name") or "", a.get("id") or ""),
    )
    return records, unmatched


def summarize(records: list[dict], unmatched_apps: list[dict], readable: dict | None = None) -> dict:
    """Counts of how the tenant's non-user accounts authenticate, and credential health.

    The authentication-method counts overlap on purpose (see `service_principal_record`),
    so they do not sum to the total. Credential expiry is counted over credentials
    someone in the tenant manages. The platform-rotated certificate of a managed identity
    is excluded, because it can neither lapse nor be rotated by hand.
    """
    credentials = [c for r in records for c in r["credentials"] if not c["platform_managed"]]
    healthy = sum(1 for c in credentials if c["healthy"])
    by_type = lambda t: sum(1 for r in records if r["service_principal_type"] == t)  # noqa: E731
    by_owner = lambda o: sum(1 for r in records if r["ownership"] == o)  # noqa: E731
    tenant_owned = [r for r in records if r["ownership"] == OWNER_THIS_TENANT]
    return {
        "total_service_principals": len(records),
        "disabled_service_principals": sum(1 for r in records if not r["account_enabled"]),
        # --- by servicePrincipalType ---
        "application_service_principals": by_type(SP_TYPE_APPLICATION),
        "managed_identities": by_type(SP_TYPE_MANAGED_IDENTITY),
        "system_assigned_managed_identities": sum(
            1 for r in records if r["managed_identity_kind"] == "system_assigned"
        ),
        "user_assigned_managed_identities": sum(
            1 for r in records if r["managed_identity_kind"] == "user_assigned"
        ),
        "legacy_service_principals": by_type(SP_TYPE_LEGACY),
        "social_idp_service_principals": by_type(SP_TYPE_SOCIAL_IDP),
        # --- by who owns the application ---
        "microsoft_first_party_service_principals": by_owner(OWNER_MICROSOFT),
        "tenant_owned_service_principals": by_owner(OWNER_THIS_TENANT),
        "other_tenant_service_principals": by_owner(OWNER_OTHER_TENANT),
        "unknown_owner_service_principals": by_owner(OWNER_UNKNOWN),
        # --- how non-user accounts authenticate (overlapping) ---
        "federated_service_principals": sum(1 for r in records if r["uses_federated_credential"]),
        "certificate_based_service_principals": sum(1 for r in records if r["uses_certificate"]),
        "secret_based_service_principals": sum(1 for r in records if r["uses_secret"]),
        # A tenant-owned principal with nothing to present cannot sign in as itself;
        # counted so an empty-looking inventory is not mistaken for a credential-free one.
        "tenant_owned_service_principals_without_credentials": sum(
            1
            for r in tenant_owned
            if not r["credential_count"] and not r["federated_identity_credential_count"]
        ),
        "federated_identity_credentials": sum(
            r["federated_identity_credential_count"] for r in records
        ),
        # --- credential health, over credentials someone in the tenant manages ---
        "total_credentials": len(credentials),
        "service_principal_held_credentials": sum(
            1 for c in credentials if c["held_on"] == HELD_ON_SERVICE_PRINCIPAL
        ),
        "application_held_credentials": sum(
            1 for c in credentials if c["held_on"] == HELD_ON_APPLICATION
        ),
        "password_credentials": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_PASSWORD
        ),
        "certificate_credentials": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_CERTIFICATE
        ),
        "expired_credentials": sum(1 for c in credentials if c["expired"]),
        "credentials_expiring_soon": sum(1 for c in credentials if c["expiring_soon"]),
        "credentials_without_expiry": sum(1 for c in credentials if not c["has_expiry"]),
        "healthy_credentials": healthy,
        "rotation_threshold_days": EXPIRY_WARNING_DAYS,
        "credential_rotation_compliance_percentage": coverage_percentage(
            healthy, len(credentials)
        ),
        "platform_managed_credentials": sum(
            1 for r in records for c in r["credentials"] if c["platform_managed"]
        ),
        # --- applications registered here that have no principal in this tenant ---
        "tenant_applications_without_service_principal": len(unmatched_apps),
        "federated_identity_credentials_on_applications_without_service_principal": sum(
            a["federated_identity_credential_count"] for a in unmatched_apps
        ),
        **access_summary(records, unmatched_apps, readable),
    }


def access_summary(records: list[dict], unmatched_apps: list[dict], readable: dict | None) -> dict:
    """Owner and API-permission counts; a figure that needs an unreadable read is None."""
    readable = readable or {}
    owners_ok = readable.get("owners", False)
    perms_ok = readable.get("application_permissions", False)
    grants_ok = readable.get("delegated_grants", False)
    eligible = [r for r in records if r.get("owner_eligible")]
    ownerless = [r for r in eligible if r.get("has_owner") is False]
    non_microsoft = [r for r in records if r["ownership"] != OWNER_MICROSOFT]
    owned = [r for r in eligible + unmatched_apps if r.get("has_owner")]
    details_ok = owners_ok and all(r.get("has_enabled_owner") is not None for r in owned)

    def held(r):
        return r["credential_count"] or r["federated_identity_credential_count"]

    def when(ok, value):
        return value if ok else None

    with_priv_app = [r for r in non_microsoft if r.get("privileged_application_permissions")]
    unnamed = [
        p for r in non_microsoft for p in r.get("application_permissions") or []
        if p["permission"] is None and not p["default_access"]
    ]
    return {
        # --- who owns each app and service principal ---
        "owners_readable": owners_ok,
        "owner_details_readable": details_ok,
        "owner_eligible_service_principals": len(eligible),
        "service_principals_without_owner": when(owners_ok, len(ownerless)),
        "tenant_owned_service_principals_without_owner": when(
            owners_ok, sum(1 for r in ownerless if r["ownership"] == OWNER_THIS_TENANT)
        ),
        "ownerless_service_principals_with_credentials": when(
            owners_ok, sum(1 for r in ownerless if held(r))
        ),
        "service_principals_with_only_disabled_owners": when(
            details_ok, sum(1 for r in eligible if r.get("has_owner") and r.get("has_enabled_owner") is False)
        ),
        "ownerless_applications_without_service_principal": when(
            owners_ok, sum(1 for a in unmatched_apps if a.get("has_owner") is False)
        ),
        # --- which API permissions non-Microsoft service principals hold ---
        "application_permissions_readable": perms_ok,
        "delegated_grants_readable": grants_ok,
        "delegated_grants_status": readable.get("delegated_grants_status", "failed"),
        "service_principals_with_application_permissions": when(
            perms_ok, sum(1 for r in non_microsoft if r.get("application_permissions"))
        ),
        "application_permission_assignments": when(
            perms_ok, sum(len(r.get("application_permissions") or []) for r in non_microsoft)
        ),
        "unnamed_graph_application_permissions": when(perms_ok, len([p for p in unnamed if p["judged"] is not False])),
        "unnamed_other_application_permissions": when(perms_ok, len([p for p in unnamed if p["judged"] is False])),
        "service_principals_with_delegated_grants": when(
            grants_ok, sum(1 for r in non_microsoft if r.get("delegated_permission_grants"))
        ),
        "delegated_permission_grants": when(
            grants_ok, sum(len(r.get("delegated_permission_grants") or []) for r in non_microsoft)
        ),
        "admin_consented_delegated_grants": when(
            grants_ok,
            sum(
                1
                for r in non_microsoft
                for g in r.get("delegated_permission_grants") or []
                if g["consent_type"] == CONSENT_ALL_PRINCIPALS
            ),
        ),
        # --- which of them hold privileged Microsoft Graph permissions ---
        "service_principals_with_privileged_application_permissions": when(perms_ok, len(with_priv_app)),
        "managed_identities_with_privileged_application_permissions": when(
            perms_ok, sum(1 for r in with_priv_app if r["is_managed_identity"])
        ),
        "ownerless_service_principals_with_privileged_application_permissions": when(
            perms_ok and owners_ok,
            sum(1 for r in with_priv_app if r.get("owner_eligible") and r.get("has_owner") is False),
        ),
        "privileged_application_permissions_held": when(
            perms_ok, sorted({p for r in with_priv_app for p in r["privileged_application_permissions"]})
        ),
        "service_principals_with_privileged_delegated_grants": when(
            grants_ok, sum(1 for r in non_microsoft if r.get("privileged_delegated_permissions"))
        ),
        "privileged_delegated_permissions_granted": when(
            grants_ok,
            sorted({s for r in non_microsoft for s in r.get("privileged_delegated_permissions") or []}),
        ),
    }


# --- collection (lazy msgraph imports) ---

class _Deferred:
    """Holds failures from an optional read so a 403 can be told apart from the rest."""

    def __init__(self):
        self.calls: list[tuple[str, BaseException]] = []

    def record(self, operation: str, exc: BaseException) -> None:
        self.calls.append((operation, exc))


async def _expanded(
    collector, operation, builder, config, attr, item_reader, incomplete=None
) -> dict | None:
    """{object id: related models} from one paged $expand read; None if any read failed.

    An object whose expansion hit EXPAND_LIMIT is re-read on its own, paged, because
    Graph drops the rest without a nextLink; so is one with an `incomplete` item. One
    deleted before its re-read maps to None (`_reread`), not a failure.
    """
    before = len(collector.failures)
    related = {}
    for obj in await paginate(collector, operation, builder, config):
        oid = graph_attr(obj, "id")
        items = list(getattr(obj, attr, None) or [])
        if len(items) >= EXPAND_LIMIT or (incomplete and any(incomplete(i) for i in items)):
            items = await item_reader(oid)
        related[oid] = items
    return related if len(collector.failures) == before else None


async def _reread(collector, operation, builder, request_configuration=None) -> list | None:
    """One object's whole related list; None if the object was deleted since the collection read (404)."""
    try:
        return await paginate(collector, operation, builder, request_configuration, raise_on_error=True)
    except Exception as exc:  # noqa: BLE001 — a 404 is that object alone; anything else is recorded
        if getattr(exc, "response_status_code", None) != 404:
            collector.record(operation, exc)
        return None


async def _access(collector: Collector, client, service_principals: list[dict]) -> tuple[dict, dict]:
    """Owners, app role assignments, delegated grants, and the app role names they need."""
    from kiota_abstractions.base_request_configuration import RequestConfiguration
    from msgraph.generated.applications.applications_request_builder import (
        ApplicationsRequestBuilder,
    )
    from msgraph.generated.applications.item.owners.owners_request_builder import (
        OwnersRequestBuilder as AppOwners,
    )
    from msgraph.generated.service_principals.item.owners.owners_request_builder import (
        OwnersRequestBuilder as SpOwners,
    )
    from msgraph.generated.service_principals.item.service_principal_item_request_builder import (
        ServicePrincipalItemRequestBuilder as SpItem,
    )
    from msgraph.generated.service_principals.service_principals_request_builder import (
        ServicePrincipalsRequestBuilder,
    )

    apps_query = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters
    sps_query = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters

    def expand(query, expansion):
        return RequestConfiguration(query_parameters=query(select=["id"], expand=[expansion]))

    async def app_owners_of(oid):
        return await _reread(
            collector,
            f"graph.applications({oid}).owners.get",
            client.applications.by_application_id(oid).owners,
            RequestConfiguration(
                query_parameters=AppOwners.OwnersRequestBuilderGetQueryParameters(select=list(OWNER_SELECT))
            ),
        )

    async def sp_owners_of(oid):
        return await _reread(
            collector,
            f"graph.servicePrincipals({oid}).owners.get",
            client.service_principals.by_service_principal_id(oid).owners,
            RequestConfiguration(
                query_parameters=SpOwners.OwnersRequestBuilderGetQueryParameters(select=list(OWNER_SELECT))
            ),
        )

    async def assignments_of(oid):
        return await _reread(
            collector,
            f"graph.servicePrincipals({oid}).appRoleAssignments.get",
            client.service_principals.by_service_principal_id(oid).app_role_assignments,
        )

    def projected(related, projection):
        if related is None:
            return None
        return {oid: None if models is None else [projection(m) for m in models] for oid, models in related.items()}

    app_owners = projected(
        await _expanded(
            collector,
            "graph.applications.get($expand=owners)",
            client.applications,
            expand(apps_query, OWNERS_EXPAND),
            "owners",
            app_owners_of,
        ),
        project_owner,
    )
    sp_owners = projected(
        await _expanded(
            collector,
            "graph.servicePrincipals.get($expand=owners)",
            client.service_principals,
            expand(sps_query, OWNERS_EXPAND),
            "owners",
            sp_owners_of,
        ),
        project_owner,
    )

    before = len(collector.failures)
    assignments = projected(
        await _expanded(
            collector,
            "graph.servicePrincipals.get($expand=appRoleAssignments)",
            client.service_principals,
            expand(sps_query, "appRoleAssignments"),
            "app_role_assignments",
            assignments_of,
            # Measured: the expansion can return an assignment with resourceId null that
            # the principal's own /appRoleAssignments returns whole.
            incomplete=lambda a: graph_attr(a, "resource_id") is None,
        ),
        project_app_role_assignment,
    )
    # Names and appIds come from the principal list; only app role names need a read.
    resources = {
        sp["id"]: {
            "id": sp["id"], "app_id": sp["app_id"], "display_name": sp["display_name"], "app_roles": {}
        }
        for sp in service_principals
    }
    resource_config = RequestConfiguration(
        query_parameters=SpItem.ServicePrincipalItemRequestBuilderGetQueryParameters(
            select=list(RESOURCE_SELECT)
        )
    )
    resource_ids = {a["resource_id"] for items in (assignments or {}).values() for a in items or []}
    for rid in sorted(r for r in resource_ids if r):
        model = await aguard(
            collector,
            f"graph.servicePrincipals({rid}).get(appRoles)",
            lambda rid=rid: client.service_principals.by_service_principal_id(rid).get(
                request_configuration=resource_config
            ),
        )
        if model is not None:
            resources[rid] = project_resource(model)
    permissions_ok = assignments is not None and len(collector.failures) == before

    # Delegated grants need DelegatedPermissionGrant.Read.All (or Directory.Read.All), which
    # Application.Read.All does not cover, so a 403 leaves them unreadable instead of failing the run.
    deferred = _Deferred()
    grant_models = await paginate(
        deferred, "graph.oauth2PermissionGrants.get", client.oauth2_permission_grants
    )
    grants: dict | None = None
    if not deferred.calls:
        grants_status = "ok"
        grants = {}
        for g in (project_permission_grant(m) for m in grant_models):
            grants.setdefault(g["client_id"], []).append(g)
    elif all(is_denied(exc) for _, exc in deferred.calls):
        grants_status = "not_authorized"
        logger.warning(
            "Delegated permission grants are unreadable without DelegatedPermissionGrant.Read.All "
            "(or Directory.Read.All)"
        )
    else:
        grants_status = "failed"
        for operation, exc in deferred.calls:
            collector.record(operation, exc)

    access = {
        "sp_owners": sp_owners,
        "app_owners": app_owners,
        "app_role_assignments": assignments if permissions_ok else None,
        "grants": grants,
        "resources": resources,
    }
    readable = {
        "owners": sp_owners is not None and app_owners is not None,
        "application_permissions": permissions_ok,
        "delegated_grants": grants is not None,
        "delegated_grants_status": grants_status,
    }
    return access, readable


async def _collect(collector: Collector, cred, now: datetime):
    """Principals and this tenant's applications, joined, then owners and permissions."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        from kiota_abstractions.base_request_configuration import RequestConfiguration
        from msgraph.generated.applications.applications_request_builder import (
            ApplicationsRequestBuilder,
        )
        from msgraph.generated.service_principals.service_principals_request_builder import (
            ServicePrincipalsRequestBuilder,
        )

        sp_config = RequestConfiguration(
            query_parameters=ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
                select=list(SP_SELECT)
            )
        )
        service_principals = [
            project_service_principal(sp)
            for sp in await paginate(
                collector, "graph.servicePrincipals.get", client.service_principals, sp_config
            )
        ]

        app_config = RequestConfiguration(
            query_parameters=ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                select=list(APP_SELECT), expand=list(APP_EXPAND)
            )
        )
        applications = [
            project_application(a)
            for a in await paginate(
                collector,
                "graph.applications.get($expand=federatedIdentityCredentials)",
                client.applications,
                app_config,
            )
        ]
        logger.info(
            "Collected %d service principal(s) and %d tenant application(s)",
            len(service_principals),
            len(applications),
        )
        records, unmatched = build_records(
            service_principals, applications, tenant.get("tenant_id"), now
        )
        access, readable = await _access(collector, client, service_principals)
        add_access(records, unmatched, access)
        return records, unmatched, tenant, readable

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], [], {"tenant_source": "unresolved"}, {})


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

    # One instant for the whole run, so two credentials sharing an end date cannot land
    # in different buckets.
    now = datetime.now(timezone.utc)

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        records: list[dict] = []
        unmatched: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
        readable: dict = {}
    else:
        records, unmatched, tenant, readable = asyncio.run(_collect(collector, cred, now))

    # No `provider_registration_status()` call, deliberately: Graph is not an ARM
    # resource provider, and every tenant has service principals (Microsoft's own apps
    # are provisioned into it), so an empty list is never a valid "not in use".
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={
            "service_principals": records,
            "applications_without_service_principal": unmatched,
            "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "privileged_application_graph_permissions_checked": sorted(PRIVILEGED_APPLICATION_GRAPH_PERMISSIONS),
            "privileged_application_graph_permission_substrings": list(PRIVILEGED_APPLICATION_GRAPH_SUBSTRINGS),
            "privileged_delegated_graph_permissions_checked": sorted(PRIVILEGED_GRAPH_PERMISSIONS),
        },
        summary=summarize(records, unmatched, readable),
    )

    filename = f"azure_entra_service_principals_{tenant_filename_key(tenant)}.json"
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
