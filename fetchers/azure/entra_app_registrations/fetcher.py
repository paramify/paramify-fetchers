#!/usr/bin/env python3
"""
Microsoft Entra ID app registration credentials and their expiry

Every app registration's client secrets and certificate credentials with each expiry, so
rotation is evidenceable per credential. A null `endDateTime` never appears in an
"expiring soon" report by construction, so it is counted separately and never folded
into expired or expiring-soon.

Ported from Prowler's prowler/providers/azure/services/entra/entra_service.py
`_get_app_registrations` (Apache-2.0) and their
entra_app_registration_credential_not_expired check, whose 30-day threshold and
three-way classification this reproduces.
"""

import asyncio
import calendar
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
from azure_rest import bounded_int_config  # noqa: E402
from entra_graph import (  # noqa: E402
    graph_attr,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_app_registrations")

# Prowler's EXPIRY_WARNING_DAYS, from their
# entra_app_registration_credential_not_expired check.
EXPIRY_WARNING_DAYS = 30

# Longest issued lifetime counted as within the approved interval. 365 is a convention
# (FedRAMP KSI-SVC-ASM asks for regular rotation and sets no number); the tenant's own
# policy overrides it through AZURE_ENTRA_APPROVED_CREDENTIAL_DAYS.
APPROVED_LIFETIME_ENV = "AZURE_ENTRA_APPROVED_CREDENTIAL_DAYS"
DEFAULT_APPROVED_LIFETIME_DAYS = 365
MAX_APPROVED_LIFETIME_DAYS = 3650

# $select'ed explicitly to keep the response small: an app registration's full
# representation is large and most of it is irrelevant to credential rotation.
APP_SELECT = (
    "id",
    "appId",
    "displayName",
    "createdDateTime",
    "signInAudience",
    "passwordCredentials",
    "keyCredentials",
)

CREDENTIAL_PASSWORD = "password"
CREDENTIAL_CERTIFICATE = "certificate"


# --- projections: the only code here that touches a Graph model ---

def project_credential(cred_model, credential_type: str) -> dict:
    """Read a `PasswordCredential` or `KeyCredential` into a flat snake_case dict.

    One projection covers both: the rotation fields are spelled identically on the two
    models. `usage` and `type` exist only on KeyCredential and read as None on a password
    credential.

    `secret_text` is deliberately NOT projected. Graph returns it only in the response
    that CREATES a secret, never on a read, so naming it would put an always-null
    `secret_text` field into the evidence schema.
    """
    return {
        "display_name": graph_attr(cred_model, "display_name"),
        "credential_type": credential_type,
        # graph_attr renders a UUID as its string form and a datetime as ISO-8601 with a
        # Z, matching what Graph put on the wire.
        "key_id": graph_attr(cred_model, "key_id"),
        "start_date_time": graph_attr(cred_model, "start_date_time"),
        "end_date_time": graph_attr(cred_model, "end_date_time"),
        "usage": graph_attr(cred_model, "usage"),
        "certificate_type": graph_attr(cred_model, "type"),
    }


def project_application(app) -> dict:
    """Read an `Application` model's attributes into a flat snake_case dict.

    Graph omits both credential collections when empty rather than sending `[]`, so each
    is read through `or []`.

    `app_id` and `id` are different identifiers and both are kept: `id` is the directory
    object id the Graph URL uses, `appId` the client id that appears in sign-in logs and
    in whatever config file holds the secret.
    """
    return {
        "id": graph_attr(app, "id"),
        "app_id": graph_attr(app, "app_id"),
        "display_name": graph_attr(app, "display_name"),
        "created_date_time": graph_attr(app, "created_date_time"),
        "sign_in_audience": graph_attr(app, "sign_in_audience"),
        "credentials": [
            project_credential(c, CREDENTIAL_PASSWORD)
            for c in (getattr(app, "password_credentials", None) or [])
        ]
        + [
            project_credential(c, CREDENTIAL_CERTIFICATE)
            for c in (getattr(app, "key_credentials", None) or [])
        ],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _parse_timestamp(value) -> datetime | None:
    """Parse an ISO-8601 timestamp back to an aware datetime, or None.

    Naive values are assumed UTC — Graph always sends UTC, and Prowler assumes the same.

    Returns None for anything unparseable rather than raising: one malformed timestamp
    must not abort collection of every other credential, and a None lands in
    `credentials_without_expiry`, the conservative bucket.
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


def _leap_days(start: datetime, end: datetime) -> int:
    """29 Februaries (00:00 UTC) falling within [start, end]."""
    return sum(
        1
        for year in range(start.year, end.year + 1)
        if calendar.isleap(year) and start <= datetime(year, 2, 29, tzinfo=timezone.utc) <= end
    )


def credential_record(cred: dict, now: datetime, approved_days: int = DEFAULT_APPROVED_LIFETIME_DAYS) -> dict:
    """Classify one projected credential against `now`.

    `now` is passed in so every credential in a run is judged against ONE instant, and so
    the transform is testable.

    `has_expiry` is not redundant: `expired` and `expiring_soon` are both False for a
    never-expiring credential, so a reader checking only those two would see a clean
    record.
    """
    end = _parse_timestamp(cred.get("end_date_time"))
    if end is None:
        days_until_expiry = None
        expired = False
        expiring_soon = False
    else:
        # Truncating toward zero matches Prowler's `(end - now).days`.
        days_until_expiry = (end - now).days
        expired = end <= now
        expiring_soon = not expired and days_until_expiry <= EXPIRY_WARNING_DAYS

    start = _parse_timestamp(cred.get("start_date_time"))
    # Raw end minus start; null (never 0) when either date is missing or the end precedes the start.
    lifetime_days = (end - start).days if start is not None and end is not None and end >= start else None
    if start is None or (end is not None and end < start):
        beyond = None
    elif end is None:
        # No end date: it never expires, so it is beyond any interval.
        beyond = True
    else:
        # A 29 February in the span doesn't count, so a one-year credential issued across one isn't flagged.
        beyond = lifetime_days - _leap_days(start, end) > approved_days

    return {
        "display_name": cred.get("display_name") or None,
        "credential_type": cred.get("credential_type"),
        "key_id": cred.get("key_id"),
        "start_date_time": cred.get("start_date_time"),
        "end_date_time": cred.get("end_date_time"),
        "usage": cred.get("usage"),
        "certificate_type": cred.get("certificate_type"),
        "has_expiry": end is not None,
        "lifetime_days": lifetime_days,
        "issued_beyond_approved_lifetime": beyond,
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "expiring_soon": expiring_soon,
        "rotation_threshold_days": EXPIRY_WARNING_DAYS,
        # The field a validator asserts on: an expiry date beyond the threshold.
        "healthy": end is not None and not expired and not expiring_soon,
    }


def application_record(app: dict, now: datetime, approved_days: int = DEFAULT_APPROVED_LIFETIME_DAYS) -> dict:
    """Normalize one projected application and classify all of its credentials.

    Sorted by end date (nulls last, then key id) for byte-stable re-runs, soonest first.
    """
    credentials = [credential_record(c, now, approved_days) for c in (app.get("credentials") or [])]
    credentials.sort(
        key=lambda c: (
            c["end_date_time"] is None,
            c["end_date_time"] or "",
            c["key_id"] or "",
        )
    )
    return {
        "id": app.get("id"),
        "app_id": app.get("app_id"),
        "display_name": app.get("display_name"),
        "created_date_time": app.get("created_date_time"),
        "sign_in_audience": app.get("sign_in_audience"),
        # Multi-tenant and personal-account audiences widen who can authenticate, so a
        # leaked credential on one of those reaches further.
        "is_single_tenant": str(app.get("sign_in_audience") or "") == "AzureADMyOrg",
        "credential_count": len(credentials),
        "password_credential_count": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_PASSWORD
        ),
        "certificate_credential_count": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_CERTIFICATE
        ),
        "credentials": credentials,
        "has_expired_credential": any(c["expired"] for c in credentials),
        "has_credential_expiring_soon": any(c["expiring_soon"] for c in credentials),
        "has_credential_without_expiry": any(not c["has_expiry"] for c in credentials),
        # An app with no credentials is compliant by construction, not by rotation, and
        # is excluded from the summary percentage.
        "has_credentials": bool(credentials),
        "all_credentials_healthy": bool(credentials) and all(c["healthy"] for c in credentials),
    }


def summarize(
    apps: list[dict], approved_days: int = DEFAULT_APPROVED_LIFETIME_DAYS, read_complete: bool = True
) -> dict:
    """Rotation compliance is measured over CREDENTIALS, not over apps.

    An app with one healthy secret and one that expired two years ago has one credential
    to clean up, not half a problem.

    The denominator excludes apps with no credentials at all (Prowler skips them too):
    they have nothing to rotate, and counting them as compliant would let a tenant
    improve its score by registering unused apps.
    """
    credentials = [c for a in apps for c in a["credentials"]]
    healthy = sum(1 for c in credentials if c["healthy"])
    unknown_lifetime = sum(1 for c in credentials if c["lifetime_days"] is None)
    unknown_verdict = any(c["issued_beyond_approved_lifetime"] is None for c in credentials)
    return {
        "total_app_registrations": len(apps),
        "apps_with_credentials": sum(1 for a in apps if a["has_credentials"]),
        "apps_without_credentials": sum(1 for a in apps if not a["has_credentials"]),
        "multi_tenant_apps": sum(1 for a in apps if not a["is_single_tenant"]),
        # --- credential inventory ---
        "total_credentials": len(credentials),
        "password_credentials": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_PASSWORD
        ),
        "certificate_credentials": sum(
            1 for c in credentials if c["credential_type"] == CREDENTIAL_CERTIFICATE
        ),
        # --- the three expiry states, kept separate ---
        "expired_credentials": sum(1 for c in credentials if c["expired"]),
        "credentials_expiring_soon": sum(1 for c in credentials if c["expiring_soon"]),
        "credentials_without_expiry": sum(1 for c in credentials if not c["has_expiry"]),
        "healthy_credentials": healthy,
        # Null after a failed or partial applications read, and the count while any credential's
        # verdict is unknown: it could be short.
        "credentials_without_lifetime": unknown_lifetime if read_complete else None,
        "credentials_issued_beyond_approved_lifetime": sum(
            1 for c in credentials if c["issued_beyond_approved_lifetime"]
        ) if read_complete and not unknown_verdict else None,
        "approved_lifetime_days": approved_days,
        "rotation_threshold_days": EXPIRY_WARNING_DAYS,
        "credential_rotation_compliance_percentage": coverage_percentage(
            healthy, len(credentials)
        ),
        # --- rolled up per app, for chasing owners ---
        "apps_with_expired_credentials": sum(1 for a in apps if a["has_expired_credential"]),
        "apps_with_credentials_expiring_soon": sum(
            1 for a in apps if a["has_credential_expiring_soon"]
        ),
        "apps_with_credentials_without_expiry": sum(
            1 for a in apps if a["has_credential_without_expiry"]
        ),
        "apps_with_all_credentials_healthy": sum(1 for a in apps if a["all_credentials_healthy"]),
    }


# --- collection (lazy msgraph imports) ---

async def _collect(collector: Collector, cred, now: datetime, approved_days: int) -> tuple[list[dict], dict, bool]:
    """One applications.get() with a $select projection, paged to the end.

    The third value is False when the applications read failed or stopped part-way."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        from kiota_abstractions.base_request_configuration import RequestConfiguration
        from msgraph.generated.applications.applications_request_builder import (
            ApplicationsRequestBuilder,
        )

        request_configuration = RequestConfiguration(
            query_parameters=ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                select=list(APP_SELECT)
            )
        )
        failures_before = len(collector.failures)
        raw_apps = await paginate(
            collector,
            "graph.applications.get",
            client.applications,
            request_configuration,
        )
        complete = len(collector.failures) == failures_before
        apps = [application_record(project_application(a), now, approved_days) for a in raw_apps]
        logger.info(
            "Collected %d app registration(s) with %d credential(s)",
            len(apps),
            sum(a["credential_count"] for a in apps),
        )
        # Sorted for byte-stable re-runs; Graph promises no stable application order.
        return (
            sorted(apps, key=lambda a: (a.get("display_name") or "", a.get("id") or "")),
            tenant,
            complete,
        )

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

    # One instant for the whole run, so two credentials sharing an end date cannot land
    # in different buckets.
    now = datetime.now(timezone.utc)
    approved_days, _ = bounded_int_config(
        collector, APPROVED_LIFETIME_ENV, DEFAULT_APPROVED_LIFETIME_DAYS, MAX_APPROVED_LIFETIME_DAYS
    )

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        apps: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
        read_complete = False
    else:
        apps, tenant, read_complete = asyncio.run(_collect(collector, cred, now, approved_days))

    # No `provider_registration_status()` call, deliberately: Graph is not an ARM
    # resource provider, and a tenant with no app registrations genuinely has none.
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={"app_registrations": apps, "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
        summary=summarize(apps, approved_days, read_complete),
    )

    filename = f"azure_entra_app_registrations_{tenant_filename_key(tenant)}.json"
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
