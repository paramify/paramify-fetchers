"""Defender for Cloud recommendations (assessments): the projection and collection azure_defender_assessments and
azure_defender_sql_vulnerability_report share, so both read the same records."""

from datetime import datetime, timezone
from typing import Any, Optional

from azure_common import Collector, arm_client_kwargs, model_attr
from resource_graph import query_all, resource_graph_client

# Same marker azure_defender_plans matches on: Microsoft.Security raises this on an
# unregistered subscription rather than returning an empty list.
PROVIDER_NOT_REGISTERED_MARKER = "subscription not registered"

# The three states `provider_registration_status` can be in the output evidence.
REGISTERED = "registered"        # Microsoft.Security is registered — real assessment data below
NOT_REGISTERED = "not_registered"  # Defender for Cloud has never been turned on for this subscription
UNKNOWN = "unknown"                # we couldn't tell either way (auth failed, network error, etc.)


# --- projection: the only code here that touches an azure-mgmt model ---
# "Projection" = reading fields off the SDK's response objects into plain dicts.
# Everything below this section works with plain dicts/lists only, which is what
# keeps the rest of the file testable without a live Azure connection.

def _iso(value: Any) -> Optional[str]:
    """Render a `datetime` attribute (status_change_date, first_evaluation_date) as one UTC ISO-8601 string.

    Matches the format the rest of the azure/* category already standardizes on
    (see backup_recovery_status/fetcher.py's `_timestamp` and
    key_vault_key_rotation/fetcher.py's `_iso8601_timestamp`): always UTC, always
    "%Y-%m-%dT%H:%M:%SZ". A bare `value.isoformat()` would instead keep whatever
    offset the SDK's `datetime` carries (e.g. "...+00:00"), which reads as the same
    moment but doesn't match the category's Z-suffixed convention.
    """
    if not isinstance(value, datetime):
        return value
    moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _enum_list(values: Any) -> list:
    """`categories`/`threats` are lists of string enums — unwrap each member.

    `model_attr` (imported above) only unwraps a SINGLE enum-valued attribute. For
    a list attribute like `categories`, the list itself isn't an Enum, so
    `model_attr` would hand it back with SDK enum objects still inside. This walks
    the list and, for each entry, swaps it out for its plain `.value` string.
    """
    return [v.value if hasattr(v, "value") else v for v in (values or [])]


ASSESSMENT_ID_MARKER = "/providers/microsoft.security/assessments/"

# Each assessment's own severity; the subscription's metadata catalogue can rate a check lower.
SEVERITY_QUERY = (
    "SecurityResources"
    " | where type =~ 'microsoft.security/assessments'"
    " | project id, severity = tostring(properties.metadata.severity)"
    " | order by id asc"
)
SEVERITY_OPERATION = "resourcegraph.resources (SecurityResources)"
FROM_ASSESSMENT = "assessment"
FROM_CATALOGUE = "catalogue"


def _id_key(assessment_id: Optional[str]) -> str:
    return (assessment_id or "").strip().lower().rstrip("/")


def _raw_detail(resource_details, key: str) -> Any:
    """A `resource_details` field the SDK failed to deserialize.

    The service returns resourceDetails with PascalCase keys (`Source`, `Id`), so
    the SDK can't find its `source` discriminator, falls back to the base
    `ResourceDetails` class, and parks every field in `additional_properties` —
    leaving `.source`/`.id` None on every record.
    """
    extra = getattr(resource_details, "additional_properties", None) or {}
    return extra.get(key)


def _resource_id_from_assessment_id(assessment_id: Optional[str]) -> Optional[str]:
    """The assessed resource is the ARM id in front of `/providers/Microsoft.Security/assessments/<guid>`."""
    if not assessment_id:
        return None
    cut = assessment_id.lower().rfind(ASSESSMENT_ID_MARKER)
    return assessment_id[:cut] if cut > 0 else None


def project_assessment(
    assessment, metadata_by_name: Optional[dict] = None, severity_by_id: Optional[dict] = None
) -> dict:
    """Read one `SecurityAssessmentResponse` model's attributes into a flat dict.

    `assessments.list` does not return `metadata` (only `get` takes
    `expand=metadata`), so severity/categories/type would all be null. Severity
    comes from `severity_by_id`, each assessment's own from Resource Graph keyed
    by lowercased assessment id; the subscription's assessment definitions, keyed
    by `name` (the GUID the assessment and its metadata share), fill in the other
    fields and are the fallback severity. `severity_source` says which one it was.

    `resource_details`, `status`, and `metadata` are nested models (sub-objects),
    so each needs its own `model_attr` reads rather than one flat pass over
    `assessment` — you can't read `assessment.status.code` directly on an SDK
    model the way you would on a plain dict, hence going through `model_attr`
    at each level. `model_attr`/`_enum_list` already return None/[] when handed
    a None model (`getattr(None, name, None)` is None), so a missing
    `resource_details`/`status`/`metadata` needs no extra guard here — the calls
    below degrade to all-None/all-empty on their own.
    """
    # Pull the three nested sub-objects off the assessment once, up front, so the
    # dict below doesn't repeat the same three model_attr(assessment, ...) calls.
    resource_details = model_attr(assessment, "resource_details")
    status = model_attr(assessment, "status")
    own_metadata = model_attr(assessment, "metadata")
    metadata = own_metadata or (metadata_by_name or {}).get(model_attr(assessment, "name"))
    severity = model_attr(own_metadata, "severity") or (severity_by_id or {}).get(
        _id_key(model_attr(assessment, "id"))
    )
    severity_source: Optional[str] = FROM_ASSESSMENT if severity else None
    if not severity:
        severity = model_attr(metadata, "severity")
        severity_source = FROM_CATALOGUE if severity else None

    return {
        # --- identity: which check, on which resource ---
        "id": model_attr(assessment, "id"),               # ARM resource id of this assessment record
        "name": model_attr(assessment, "name"),             # GUID identifying the check itself
        "display_name": model_attr(assessment, "display_name"),  # human-readable check name

        # --- what was assessed ---
        "resource_source": (  # "Azure" or "OnPremise"
            model_attr(resource_details, "source") or _raw_detail(resource_details, "Source")
        ),
        # `id` only exists on the Azure-resource subtype of resource_details — the
        # OnPremise/OnPremiseSql subtypes (Arc-connected machines) have no `id` at
        # all, only machine_name/vmuuid/workspace_id. Without this fallback every
        # on-prem assessment's resource_id would be silently null. The last two
        # fallbacks cover the undeserialized PascalCase payload (see _raw_detail).
        "resource_id": (
            model_attr(resource_details, "id")
            or model_attr(resource_details, "machine_name")
            or model_attr(resource_details, "vmuuid")
            or _raw_detail(resource_details, "Id")
            or _resource_id_from_assessment_id(model_attr(assessment, "id"))
        ),

        # --- the pass/fail result itself ---
        "status_code": model_attr(status, "code"),               # "Healthy" / "Unhealthy" / "NotApplicable"
        "status_cause": model_attr(status, "cause"),             # why it's in that state, machine-readable
        "status_description": model_attr(status, "description"),  # why it's in that state, human-readable
        "status_change_date": _iso(model_attr(status, "status_change_date")),     # when the status last flipped
        "first_evaluation_date": _iso(model_attr(status, "first_evaluation_date")),  # when Defender first checked this

        # --- static info about the check (severity, what it's checking for, how hard to fix) ---
        "severity": severity,                                         # "Low" / "Medium" / "High"
        "severity_source": severity_source,  # "assessment" / "catalogue" / None when unknown
        "categories": _enum_list(model_attr(metadata, "categories")),  # e.g. ["Compute"], ["Networking"]
        "threats": _enum_list(model_attr(metadata, "threats")),        # e.g. ["dataExfiltration"]
        "assessment_type": model_attr(metadata, "assessment_type"),  # BuiltIn / CustomPolicy / etc.
        "user_impact": model_attr(metadata, "user_impact"),          # disruption cost of remediating
        "implementation_effort": model_attr(metadata, "implementation_effort"),  # effort to remediate
        "policy_definition_id": model_attr(metadata, "policy_definition_id"),    # the Azure Policy backing this check
    }


# --- collection (lazy azure imports) ---
# "Lazy" = `from azure.mgmt.security import SecurityCenter` happens INSIDE the
# function, not at module top. This keeps the module importable (e.g. for tests)
# even in an environment without the azure SDK installed, since the import only
# actually runs once collection starts.

def is_provider_not_registered(exc: BaseException) -> bool:
    """Is this the benign "Microsoft.Security was never registered" answer?

    Checked by substring match on the lowercased exception message/text rather
    than by exception type, because the SDK doesn't raise a dedicated exception
    class for this — it's a generic error whose message happens to contain this
    phrase.
    """
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return PROVIDER_NOT_REGISTERED_MARKER in message


def _own_severities(cred, subscription_id) -> dict:
    """Each assessment's own severity, keyed by lowercased assessment id, paged to the end."""
    rows = query_all(resource_graph_client(cred), subscription_id, SEVERITY_QUERY)["rows"]
    return {_id_key(row.get("id")): row.get("severity") or None for row in rows}


def collect_assessments(subscription_id, cred, collector: Collector) -> tuple[list[dict], str]:
    """assessments.list, the metadata catalogue and one paged Resource Graph query; returns (assessments, status)."""
    from azure.mgmt.security import SecurityCenter

    # `collector.guard(...)` runs `_client()`, and if it raises, records the
    # failure on `collector` and returns None instead of propagating the
    # exception — that's what lets one bad call fail this fetcher's exit code
    # without crashing the whole script.
    def _client():
        return SecurityCenter(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("security.SecurityCenter (init)", _client)
    if client is None:
        return [], UNKNOWN

    # client.assessments.list(...) returns a lazy, auto-paging iterator (an Azure
    # `ItemPaged`) — iterating it is what actually triggers the HTTP calls, one
    # page at a time. Appending inside the loop (rather than a list comprehension
    # bound only after it fully completes) means a failure on a LATER page still
    # keeps every record from the pages already fetched, instead of discarding
    # them all — this call can span many pages on a subscription with thousands
    # of assessment results, where a mid-pagination throttle/timeout is real.
    raw: list = []
    try:
        for assessment in client.assessments.list(scope=f"subscriptions/{subscription_id}"):
            raw.append(assessment)
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_provider_not_registered(exc):
            # Deliberately NOT collector.record(): Defender not being in use is the
            # finding, so this must stay exit 0 with empty assessments.
            collector.logger.warning(
                "Microsoft.Security is not registered on subscription %s — "
                "Defender for Cloud is not in use; reporting status %s",
                subscription_id,
                NOT_REGISTERED,
            )
            return [], NOT_REGISTERED
        # Any OTHER exception (auth failure, network error, permissions, etc.) is
        # a real collection failure — record it so the run exits non-zero, but
        # keep whatever assessments earlier pages already yielded.
        collector.record("security.assessments.list", exc)
        return [project_assessment(a) for a in raw], UNKNOWN

    # Fetched only after the list succeeded, so an unregistered subscription is
    # still classified above instead of being recorded as a metadata failure. A
    # failure here is recorded: without it categories and type are null and
    # severity has no fallback.
    metadata_by_name = collector.guard(
        "security.assessments_metadata.list_by_subscription",
        lambda: {model_attr(m, "name"): m for m in client.assessments_metadata.list_by_subscription()},
        default={},
    )
    # Recorded too on failure: the catalogue's severities alone understate some checks.
    severity_by_id: dict = {}
    if raw:
        severity_by_id = collector.guard(
            SEVERITY_OPERATION,
            lambda: _own_severities(cred, subscription_id),
            default={},
        )
    assessments = [project_assessment(a, metadata_by_name, severity_by_id) for a in raw]

    # Sorted for a deterministic, diffable evidence file — otherwise the API's
    # own ordering (not guaranteed stable) would shuffle the JSON between runs.
    return (
        sorted(assessments, key=lambda r: (r.get("display_name") or "", r.get("resource_id") or "")),
        REGISTERED,
    )
