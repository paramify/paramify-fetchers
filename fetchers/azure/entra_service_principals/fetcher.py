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

Two Graph reads, never one per principal:

- `GET /servicePrincipals` returns every principal with its SP-held credentials. Most
  of them in a typical tenant are Microsoft first-party apps, which hold nothing locally
  and are never read individually.
- `GET /applications?$expand=federatedIdentityCredentials` returns only the
  applications registered in this tenant, which are the only ones whose application
  credentials this tenant controls, with their federated credentials inline. Graph caps
  an application at 20 federated credentials, and 20 is also `$expand`'s per-collection
  limit, so the expansion is complete. No per-application
  `/federatedIdentityCredentials` call is needed.

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
    write_evidence,
    report_failure,
)
from entra_graph import (  # noqa: E402
    graph_attr,
    graph_list,
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


def summarize(records: list[dict], unmatched_apps: list[dict]) -> dict:
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
    }


# --- collection (lazy msgraph imports) ---

async def _collect(collector: Collector, cred, now: datetime):
    """Two paged reads (service principals; this tenant's applications), joined."""

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
        return records, unmatched, tenant

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], [], {"tenant_source": "unresolved"})


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
    else:
        records, unmatched, tenant = asyncio.run(_collect(collector, cred, now))

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
        },
        summary=summarize(records, unmatched),
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
