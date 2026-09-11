#!/usr/bin/env python3
"""Microsoft Defender for Cloud plan coverage for one subscription.

A subscription that never registered Microsoft.Security reports
`provider_registration_status: not_registered` and still exits 0 — "not enabled" is a
finding, not a broken run, as in the AWS fetchers.
Ported from prowler/providers/azure/services/defender/defender_service.py (Apache-2.0).
"""

import logging
import os
import sys
from datetime import timedelta
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

logger = logging.getLogger("azure_defender_plans")

# Prowler matches this phrase on ResourceNotFoundError; we match it on any exception,
# so a differently-typed wrapper from another SDK version still reads as "not in use"
# rather than "collection failed".
PROVIDER_NOT_REGISTERED_MARKER = "subscription not registered"

# The tier that actually protects resources; "Free" is the default no-op tier.
PROTECTED_TIER = "standard"

REGISTERED = "registered"
NOT_REGISTERED = "not_registered"
UNKNOWN = "unknown"


# --- projection: the only code here that touches an azure-mgmt model ---

def _iso8601_duration(value) -> str | None:
    """Render a `timedelta` as the ISO-8601 duration string the wire carries.

    azure-mgmt-security types `freeTrialRemainingTime` as a duration, so the SDK hands
    the attribute over already parsed into a `timedelta` — where the removed
    `as_dict()` used to re-serialize it to "P25D". Without this the evidence would
    carry `json.dump(default=str)`'s "25 days, 0:00:00" instead. Matches the SDK
    serializer exactly: zero-valued components omitted, a bare zero is "P0D",
    fractional seconds keep no trailing zeros ("P2DT30.5S"). Non-timedeltas (a plain
    string from a future SDK, or None) pass straight through.
    """
    if not isinstance(value, timedelta):
        return value
    hours, remainder = divmod(value.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    date_part = f"{value.days}D" if value.days else ""
    time_part = ""
    if hours:
        time_part += f"{hours}H"
    if minutes:
        time_part += f"{minutes}M"
    if seconds or value.microseconds:
        if value.microseconds:
            fractional = f"{seconds + value.microseconds / 1_000_000:.6f}"
            time_part += fractional.rstrip("0").rstrip(".") + "S"
        else:
            time_part += f"{seconds}S"
    if not date_part and not time_part:
        return "P0D"
    return f"P{date_part}" + (f"T{time_part}" if time_part else "")


def project_pricing(pricing) -> dict:
    """Read a `Pricing` model's attributes into a flat snake_case dict."""
    return {
        "id": model_attr(pricing, "id"),
        "name": model_attr(pricing, "name"),
        "pricing_tier": model_attr(pricing, "pricing_tier"),
        "free_trial_remaining_time": _iso8601_duration(
            model_attr(pricing, "free_trial_remaining_time")
        ),
        "extensions": [
            {
                "name": model_attr(ext, "name"),
                "is_enabled": model_attr(ext, "is_enabled"),
            }
            for ext in (model_attr(pricing, "extensions") or [])
        ],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _as_bool(value) -> bool:
    """Coerce azure-mgmt-security's STRING boolean enums to a real bool.

    `Extension.is_enabled` is typed `str` and carries the `IsEnabled` enum whose
    members are the literal strings "True" and "False", so a plain `bool(value)`
    reports a DISABLED extension as enabled (`bool("False") is True`). Storage and
    network return real JSON booleans.
    """
    if isinstance(value, bool) or value is None:
        return bool(value)
    return str(value).strip().lower() in ("true", "1", "yes", "on", "enabled")


def pricing_record(pricing: dict) -> dict:
    """Normalize one projected Defender plan — Prowler's five-field projection.

    `extensions` collapses the SDK's list of {name, is_enabled, ...} objects into a
    flat {name: bool} map, which is how Prowler's checks read it.
    """
    extensions = pricing.get("extensions") or []
    return {
        "resource_id": pricing.get("id"),
        "resource_name": pricing.get("name"),
        "pricing_tier": pricing.get("pricing_tier"),
        "free_trial_remaining_time": pricing.get("free_trial_remaining_time"),
        "extensions": {
            ext.get("name"): _as_bool(ext.get("is_enabled"))
            for ext in extensions
            if ext.get("name")
        },
    }


def summarize(plans: list[dict], registration_status: str) -> dict:
    """Standard-tier coverage is the headline: how many plans actually protect."""
    total = len(plans)
    standard = sum(1 for p in plans if str(p["pricing_tier"] or "").lower() == PROTECTED_TIER)
    return {
        "provider_registration_status": registration_status,
        "total_plans": total,
        "standard_tier_plans": standard,
        "free_tier_plans": total - standard,
        "standard_tier_percentage": coverage_percentage(standard, total),
        "plans_with_enabled_extensions": sum(
            1 for p in plans if any(p["extensions"].values())
        ),
        "total_enabled_extensions": sum(
            1 for p in plans for enabled in p["extensions"].values() if enabled
        ),
    }


# --- collection (lazy azure imports) ---

def is_provider_not_registered(exc: BaseException) -> bool:
    """Is this the benign "Microsoft.Security was never registered" answer?"""
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return PROVIDER_NOT_REGISTERED_MARKER in message


def collect_pricings(subscription_id, cred, collector: Collector) -> tuple[list[dict], str]:
    """One pricings.list(scope_id=...) call; returns (plans, registration_status).

    The response is a single PricingList with a `.value` array — not an ItemPaged —
    so there is nothing to paginate.
    """
    from azure.mgmt.security import SecurityCenter

    def _client():
        return SecurityCenter(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("security.SecurityCenter (init)", _client)
    if client is None:
        return [], UNKNOWN

    try:
        response = client.pricings.list(scope_id=f"subscriptions/{subscription_id}")
        plans = [
            pricing_record(project_pricing(pricing))
            for pricing in (getattr(response, "value", None) or [])
        ]
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_provider_not_registered(exc):
            # Deliberately NOT collector.record(): Defender not being in use is the
            # finding, so this must stay exit 0 with empty plans.
            logger.warning(
                "Microsoft.Security is not registered on subscription %s — "
                "Defender for Cloud is not in use; reporting status %s",
                subscription_id,
                NOT_REGISTERED,
            )
            return [], NOT_REGISTERED
        collector.record("security.pricings.list", exc)
        return [], UNKNOWN

    return sorted(plans, key=lambda r: r.get("resource_name") or ""), REGISTERED


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

    plans: list[dict] = []
    registration_status = UNKNOWN
    if subscription_id and cred is not None:
        plans, registration_status = collect_pricings(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "defender_plans": plans,
            # Also in results so a validator can assert the service is in use at all.
            "provider_registration_status": registration_status,
        },
        summary=summarize(plans, registration_status),
    )

    filename = f"azure_defender_plans_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
