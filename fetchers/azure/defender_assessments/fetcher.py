#!/usr/bin/env python3
"""Microsoft Defender for Cloud security assessment results for one subscription.

One record per (resource, check) pair — the per-resource pass/fail detail behind
the secure score. A subscription that never registered Microsoft.Security reports
`provider_registration_status: not_registered` and still exits 0 — "not enabled" is
a finding, not a broken run, matching azure_defender_plans.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

# Every azure/* fetcher shares one helper module instead of each reimplementing
# auth, retries, and output formatting. It isn't a normal importable package (no
# azure/_shared/__init__.py entry on the path by default), so we manually add
# fetchers/azure/_shared/ to sys.path before importing from it below.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,           # accumulates API failures without crashing the run
    build_payload,        # assembles the final evidence dict (metadata + results + summary)
    classify_failure_code,  # maps a failure onto a stable error "code" for the status file
    coverage_percentage,  # integer percentage helper, 0-safe on an empty denominator
    credential,            # returns azure.identity.DefaultAzureCredential()
    failure_reason,        # renders the Collector's failures into one status-file message
    model_attr,            # reads one attribute off an azure-mgmt SDK model, enum-safe
    resolve_subscription,  # figures out which subscription_id to collect from
    sanitize_for_filename,  # makes a subscription id safe to use in a filename
    write_evidence,        # writes the evidence dict to disk as JSON
    report_failure,        # logs the reason AND writes $FETCHER_STATUS_FILE
)

logger = logging.getLogger("azure_defender_assessments")

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


def project_assessment(assessment) -> dict:
    """Read one `SecurityAssessmentResponse` model's attributes into a flat dict.

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
    metadata = model_attr(assessment, "metadata")

    return {
        # --- identity: which check, on which resource ---
        "id": model_attr(assessment, "id"),               # ARM resource id of this assessment record
        "name": model_attr(assessment, "name"),             # GUID identifying the check itself
        "display_name": model_attr(assessment, "display_name"),  # human-readable check name

        # --- what was assessed ---
        "resource_source": model_attr(resource_details, "source"),  # "Azure" or "OnPremise"
        # `id` only exists on the Azure-resource subtype of resource_details — the
        # OnPremise/OnPremiseSql subtypes (Arc-connected machines) have no `id` at
        # all, only machine_name/vmuuid/workspace_id. Without this fallback every
        # on-prem assessment's resource_id would be silently null.
        "resource_id": (
            model_attr(resource_details, "id")
            or model_attr(resource_details, "machine_name")
            or model_attr(resource_details, "vmuuid")
        ),

        # --- the pass/fail result itself ---
        "status_code": model_attr(status, "code"),               # "Healthy" / "Unhealthy" / "NotApplicable"
        "status_cause": model_attr(status, "cause"),             # why it's in that state, machine-readable
        "status_description": model_attr(status, "description"),  # why it's in that state, human-readable
        "status_change_date": _iso(model_attr(status, "status_change_date")),     # when the status last flipped
        "first_evaluation_date": _iso(model_attr(status, "first_evaluation_date")),  # when Defender first checked this

        # --- static info about the check (severity, what it's checking for, how hard to fix) ---
        "severity": model_attr(metadata, "severity"),                # "Low" / "Medium" / "High"
        "categories": _enum_list(model_attr(metadata, "categories")),  # e.g. ["Compute"], ["Networking"]
        "threats": _enum_list(model_attr(metadata, "threats")),        # e.g. ["dataExfiltration"]
        "assessment_type": model_attr(metadata, "assessment_type"),  # BuiltIn / CustomPolicy / etc.
        "user_impact": model_attr(metadata, "user_impact"),          # disruption cost of remediating
        "implementation_effort": model_attr(metadata, "implementation_effort"),  # effort to remediate
        "policy_definition_id": model_attr(metadata, "policy_definition_id"),    # the Azure Policy backing this check
    }


# --- pure transform: flat dicts in, summary out ---
# No SDK objects touched here — just counting over the plain dicts project_assessment
# already produced. This is what makes `summarize` easy to unit-test on its own.

def summarize(assessments: list[dict], registration_status: str) -> dict:
    """Healthy/Unhealthy/NotApplicable counts are the headline — unhealthy is what needs fixing."""
    total = len(assessments)
    # Counter tallies how many records have each status_code value in one pass,
    # e.g. Counter({"Healthy": 40, "Unhealthy": 12, "NotApplicable": 3}).
    by_status = Counter(a["status_code"] for a in assessments)
    # Same idea, but scoped to only the failing checks, bucketed by severity —
    # this is what tells someone "how many High-severity things are broken".
    unhealthy_severities = Counter(
        a["severity"] for a in assessments if a["status_code"] == "Unhealthy" and a["severity"]
    )
    return {
        "provider_registration_status": registration_status,
        "total_assessments": total,
        "healthy_count": by_status.get("Healthy", 0),
        "unhealthy_count": by_status.get("Unhealthy", 0),
        "not_applicable_count": by_status.get("NotApplicable", 0),
        "healthy_percentage": coverage_percentage(by_status.get("Healthy", 0), total),
        "unhealthy_by_severity": dict(unhealthy_severities),
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


def collect_assessments(subscription_id, cred, collector: Collector) -> tuple[list[dict], str]:
    """One assessments.list(scope=...) call; returns (assessments, registration_status)."""
    from azure.mgmt.security import SecurityCenter

    # `collector.guard(...)` runs `_client()`, and if it raises, records the
    # failure on `collector` and returns None instead of propagating the
    # exception — that's what lets one bad call fail this fetcher's exit code
    # without crashing the whole script.
    def _client():
        return SecurityCenter(credential=cred, subscription_id=subscription_id)

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
    assessments: list[dict] = []
    try:
        for assessment in client.assessments.list(scope=f"subscriptions/{subscription_id}"):
            assessments.append(project_assessment(assessment))
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_provider_not_registered(exc):
            # Deliberately NOT collector.record(): Defender not being in use is the
            # finding, so this must stay exit 0 with empty assessments.
            logger.warning(
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
        return assessments, UNKNOWN

    # Sorted for a deterministic, diffable evidence file — otherwise the API's
    # own ordering (not guaranteed stable) would shuffle the JSON between runs.
    return (
        sorted(assessments, key=lambda r: (r.get("display_name") or "", r.get("resource_id") or "")),
        REGISTERED,
    )


def main() -> int:
    # Standard logging setup — LOG_LEVEL is an env var the runner can override.
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # bury this fetcher's own lines and dominate the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    # Interim v0.x: the fetcher loads its own .env for local/manual runs. In
    # production the runner resolves secrets and injects them as real env vars
    # directly, so this is a no-op there.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    # One Collector instance tracks every API failure across this whole run —
    # it's threaded through resolve_subscription, credential(), and
    # collect_assessments below so failures from any of those three steps all
    # land in the same place.
    collector = Collector(logger)

    # Step 1: which subscription are we collecting from? Either an explicit
    # AZURE_SUBSCRIPTION_ID (set by the runner from a manifest target) or,
    # failing that, the first enabled subscription the ambient credential can see.
    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    # Step 2: get an Azure credential (DefaultAzureCredential — tries env vars,
    # managed identity, `az login` cache, etc., in order). collector.guard means
    # a bad/missing credential is recorded as a failure, not a crash.
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    assessments: list[dict] = []
    registration_status = UNKNOWN
    if subscription_id and cred is not None:
        # Step 3: the actual API call + projection + sort, described above.
        assessments, registration_status = collect_assessments(subscription_id, cred, collector)
    elif not subscription_id:
        # We never even got a subscription to try — record that explicitly so
        # the status file says WHY nothing was collected, instead of silently
        # writing an empty evidence file. Deliberately avoids the phrase "no
        # subscription": classify_failure_code (azure_common.py) ORs its message
        # markers across ALL accumulated failures, and "no subscription" is one
        # of its bad_config markers — if that phrase were present here, it would
        # win the classification even when the real, more specific cause is a
        # different recorded failure (e.g. a missing dependency, which has its
        # own internal_error classification that this text must not shadow).
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "could not resolve which Azure subscription to use (set "
                "AZURE_SUBSCRIPTION_ID or configure an ambient Azure credential "
                "that can list subscriptions)"
            ),
        )

    # Step 4: assemble the raw evidence dict. build_payload wraps our
    # results/summary with the standard metadata block (subscription id, when
    # this ran, whether anything failed) — the runner then wraps THIS whole
    # dict again in its own envelope before it reaches Paramify.
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "assessments": assessments,
            # Also in results so a validator can assert the service is in use at all.
            "provider_registration_status": registration_status,
        },
        summary=summarize(assessments, registration_status),
    )

    # Step 5: write the evidence file. The subscription id is baked into the
    # filename because this fetcher fans out per-subscription (supports_targets:
    # true) — every target's run shares one output directory, so a fixed
    # filename would let each subscription's file overwrite the last.
    filename = f"azure_defender_assessments_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    # Step 6: decide the exit code. `collector.ok` is False if ANY step above
    # (resolve_subscription, credential(), or collect_assessments) recorded a
    # failure. On failure we still keep the evidence file we already wrote
    # (partial data can still be useful) but additionally report the failure and
    # exit 1, which is what the runner reads to mark this run as failed.
    #
    # report_failure is the WHOLE failure path: it logs the reason at error
    # level and writes $FETCHER_STATUS_FILE. Do not add a logger.error before
    # it — the reason would appear twice, and failure_reason() already opens
    # with the failure count.
    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    # This INFO line must be the LAST thing logged on the success path: the
    # runner's fallback error reporting reads the TAIL of stderr, so if a
    # failure line were logged after this one, this "saved" message would win
    # and mask the real error.
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
