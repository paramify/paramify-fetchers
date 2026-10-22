#!/usr/bin/env python3
"""Microsoft Defender for Cloud regulatory compliance for one subscription.

Defender for Cloud grades a subscription against compliance standards — the Microsoft
cloud security benchmark by default, plus any added — and groups its assessment
results under each standard's controls. Three nested reads (azure-mgmt-security
SecurityCenter):

  regulatory_compliance_standards.list()                       every standard, graded
  regulatory_compliance_controls.list(standard)                 its controls, graded
  regulatory_compliance_assessments.list(standard, control)     the assessments behind each

so the evidence reads standard -> control -> assessment, with passed / failed /
skipped counts at each level. That is the benchmark-control view that
azure_defender_assessments (one flat row per resource x check) does not give.

Two answers are "not in use", not a broken run, and exit 0 with an empty result:
Microsoft.Security never registered (as in azure_defender_plans), and regulatory
compliance not offered because no Defender plan is on the Standard tier — the service
refuses the standards list outright on a free-tier subscription (confirmed live).
"""

import logging
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_defender_regulatory_compliance")

# Same marker azure_defender_plans and azure_defender_assessments match on:
# Microsoft.Security raises this on an unregistered subscription rather than
# returning an empty list.
PROVIDER_NOT_REGISTERED_MARKER = "subscription not registered"

# What the standards list raises on a subscription with no Standard-tier Defender
# plan, verbatim from the live error: code "Subscription with no standard pricing
# bundle", message "Regulatory compliance is not supported for subscription ... as it
# has no standard pricing bundle". Either phrase identifies it.
FREE_TIER_MARKERS = ("no standard pricing bundle", "regulatory compliance is not supported")

# provider_registration_status, as in the other two Defender fetchers.
REGISTERED = "registered"
NOT_REGISTERED = "not_registered"
UNKNOWN = "unknown"

# regulatory_compliance_status: whether the feature answered at all.
AVAILABLE = "available"
NOT_AVAILABLE_FREE_TIER = "not_available_free_tier"
PROVIDER_NOT_REGISTERED = "provider_not_registered"

# The default standard every Defender-enabled subscription is graded against.
MCSB_STANDARD = "microsoft-cloud-security-benchmark"

# Result states at every level (standard, control, assessment).
PASSED, FAILED, SKIPPED, UNSUPPORTED = "Passed", "Failed", "Skipped", "Unsupported"
STATES = (PASSED, FAILED, SKIPPED, UNSUPPORTED)


# --- projections: the only code here that touches an azure-mgmt model ---

def project_standard(standard) -> dict:
    """Read a `RegulatoryComplianceStandard` into a flat dict."""
    return {
        "id": model_attr(standard, "id"),
        "name": model_attr(standard, "name"),
        "state": model_attr(standard, "state"),
        "passed_controls": model_attr(standard, "passed_controls"),
        "failed_controls": model_attr(standard, "failed_controls"),
        "skipped_controls": model_attr(standard, "skipped_controls"),
        "unsupported_controls": model_attr(standard, "unsupported_controls"),
    }


def project_control(control) -> dict:
    """Read a `RegulatoryComplianceControl` into a flat dict."""
    return {
        "id": model_attr(control, "id"),
        "name": model_attr(control, "name"),
        "description": model_attr(control, "description"),
        "state": model_attr(control, "state"),
        "passed_assessments": model_attr(control, "passed_assessments"),
        "failed_assessments": model_attr(control, "failed_assessments"),
        "skipped_assessments": model_attr(control, "skipped_assessments"),
    }


def project_assessment(assessment) -> dict:
    """Read a `RegulatoryComplianceAssessment` into a flat dict."""
    return {
        "id": model_attr(assessment, "id"),
        "name": model_attr(assessment, "name"),
        "description": model_attr(assessment, "description"),
        "assessment_type": model_attr(assessment, "assessment_type"),
        "assessment_details_link": model_attr(assessment, "assessment_details_link"),
        "state": model_attr(assessment, "state"),
        "passed_resources": model_attr(assessment, "passed_resources"),
        "failed_resources": model_attr(assessment, "failed_resources"),
        "skipped_resources": model_attr(assessment, "skipped_resources"),
        "unsupported_resources": model_attr(assessment, "unsupported_resources"),
    }


# --- pure transforms (flat dicts in, evidence records out) ---

def _message(exc: BaseException) -> str:
    return f"{getattr(exc, 'message', '') or ''} {exc}".lower()


def is_provider_not_registered(exc: BaseException) -> bool:
    """Is this the benign "Microsoft.Security was never registered" answer?"""
    return PROVIDER_NOT_REGISTERED_MARKER in _message(exc)


def is_free_tier_unavailable(exc: BaseException) -> bool:
    """Is this "regulatory compliance needs a Standard-tier plan"?"""
    message = _message(exc)
    return any(marker in message for marker in FREE_TIER_MARKERS)


def is_mcsb(standard: dict) -> bool:
    return str(standard.get("name") or "").lower() == MCSB_STANDARD


def _state_counts(records: list[dict]) -> dict:
    counts = Counter(str(r.get("state") or "Unknown") for r in records)
    return {state: counts.get(state, 0) for state in STATES} | {
        k: v for k, v in counts.items() if k not in STATES
    }


def standard_record(standard: dict, controls: list[dict]) -> dict:
    """A standard with its controls nested, and their counts recomputed from them.

    The standard's own passed/failed/skipped counts are kept as the service reported
    them; `controls_by_state` is counted from the controls actually listed, so the two
    disagreeing is visible rather than hidden.
    """
    return {
        **standard,
        "is_microsoft_cloud_security_benchmark": is_mcsb(standard),
        "control_count": len(controls),
        "controls_by_state": _state_counts(controls),
        "controls": controls,
    }


def control_record(control: dict, assessments: list[dict]) -> dict:
    """A control with its assessments nested."""
    return {
        **control,
        "assessment_count": len(assessments),
        "assessments_by_state": _state_counts(assessments),
        "failed_resources": sum(a.get("failed_resources") or 0 for a in assessments),
        "assessments": assessments,
    }


def summarize(standards: list[dict], compliance_status: str, registration_status: str) -> dict:
    """Failed controls are the headline, the benchmark's own first."""
    controls = [c for s in standards for c in s["controls"]]
    assessments = [a for c in controls for a in c["assessments"]]
    mcsb = next((s for s in standards if s["is_microsoft_cloud_security_benchmark"]), None)
    mcsb_controls = (mcsb or {}).get("controls") or []
    mcsb_passed = sum(1 for c in mcsb_controls if c.get("state") == PASSED)
    mcsb_failed = sum(1 for c in mcsb_controls if c.get("state") == FAILED)
    return {
        "provider_registration_status": registration_status,
        "regulatory_compliance_status": compliance_status,
        # --- standards ---
        "total_standards": len(standards),
        "standards_by_state": _state_counts(standards),
        "standards_failed": [s["name"] for s in standards if s.get("state") == FAILED],
        # --- controls, across every standard ---
        "total_controls": len(controls),
        "controls_by_state": _state_counts(controls),
        "failed_controls": sum(1 for c in controls if c.get("state") == FAILED),
        "control_pass_percentage": coverage_percentage(
            sum(1 for c in controls if c.get("state") == PASSED),
            sum(1 for c in controls if c.get("state") in (PASSED, FAILED)),
        ),
        # --- assessments ---
        "total_assessments": len(assessments),
        "assessments_by_state": _state_counts(assessments),
        "failed_resources": sum(a.get("failed_resources") or 0 for a in assessments),
        # --- the Microsoft cloud security benchmark ---
        "mcsb_standard_present": mcsb is not None,
        "mcsb_state": (mcsb or {}).get("state"),
        "mcsb_total_controls": len(mcsb_controls),
        "mcsb_passed_controls": mcsb_passed,
        "mcsb_failed_controls": mcsb_failed,
        "mcsb_control_pass_percentage": coverage_percentage(mcsb_passed, mcsb_passed + mcsb_failed),
        "mcsb_failed_control_names": sorted(
            c["name"] for c in mcsb_controls if c.get("state") == FAILED and c.get("name")
        ),
    }


# --- collection (lazy azure imports) ---

def collect_regulatory_compliance(
    subscription_id, cred, collector: Collector
) -> tuple[list[dict], str, str]:
    """Standards, then each standard's controls, then each control's assessments.

    Returns (standards, regulatory_compliance_status, provider_registration_status).
    A failure below the standards list is recorded and leaves that one standard or
    control with what it had, so one unreadable control does not empty the evidence.
    """
    from azure.mgmt.security import SecurityCenter  # lazy

    def _client():
        return SecurityCenter(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("security.SecurityCenter (init)", _client)
    if client is None:
        return [], UNKNOWN, UNKNOWN

    try:
        # ItemPaged throughout: the SDK follows nextLink itself.
        standards = [project_standard(s) for s in client.regulatory_compliance_standards.list()]
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_provider_not_registered(exc):
            # Deliberately NOT collector.record(): Defender not being in use is the finding.
            logger.warning(
                "Microsoft.Security is not registered on subscription %s — "
                "Defender for Cloud is not in use; reporting status %s",
                subscription_id,
                PROVIDER_NOT_REGISTERED,
            )
            return [], PROVIDER_NOT_REGISTERED, NOT_REGISTERED
        if is_free_tier_unavailable(exc):
            # Also a finding, not a failure: the provider answered, and said the
            # feature needs a Standard-tier Defender plan this subscription lacks.
            logger.warning(
                "Regulatory compliance is not available on subscription %s (no "
                "Standard-tier Defender plan); reporting status %s",
                subscription_id,
                NOT_AVAILABLE_FREE_TIER,
            )
            return [], NOT_AVAILABLE_FREE_TIER, REGISTERED
        collector.record("security.regulatory_compliance_standards.list", exc)
        return [], UNKNOWN, UNKNOWN

    records = []
    for standard in standards:
        name = standard.get("name")
        controls = collector.guard(
            f"security.regulatory_compliance_controls.list({name})",
            lambda: [
                project_control(c) for c in client.regulatory_compliance_controls.list(name)
            ],
            default=[],
        )
        control_records = []
        for control in controls:
            control_name = control.get("name")
            assessments = collector.guard(
                f"security.regulatory_compliance_assessments.list({name}, {control_name})",
                lambda: [
                    project_assessment(a)
                    for a in client.regulatory_compliance_assessments.list(name, control_name)
                ],
                default=[],
            )
            control_records.append(
                control_record(control, sorted(assessments, key=lambda a: a.get("name") or ""))
            )
        records.append(
            standard_record(standard, sorted(control_records, key=lambda c: c.get("name") or ""))
        )
    logger.info(
        "Collected %d standard(s), %d control(s), %d assessment(s)",
        len(records),
        sum(r["control_count"] for r in records),
        sum(c["assessment_count"] for r in records for c in r["controls"]),
    )
    return sorted(records, key=lambda r: r.get("name") or ""), AVAILABLE, REGISTERED


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # bury this fetcher's own lines and dominate the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    standards: list[dict] = []
    compliance_status, registration_status = UNKNOWN, UNKNOWN
    if subscription_id and cred is not None:
        standards, compliance_status, registration_status = collect_regulatory_compliance(
            subscription_id, cred, collector
        )
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "could not resolve which Azure subscription to use (set "
                "AZURE_SUBSCRIPTION_ID or configure an ambient Azure credential "
                "that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "standards": standards,
            # Also in results so a validator can assert the feature is in use at all.
            "regulatory_compliance_status": compliance_status,
            "provider_registration_status": registration_status,
        },
        summary=summarize(standards, compliance_status, registration_status),
    )

    filename = (
        "azure_defender_regulatory_compliance_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
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
