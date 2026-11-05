#!/usr/bin/env python3
"""Microsoft Defender for Cloud plan coverage for one subscription.

A subscription that never registered Microsoft.Security reports
`provider_registration_status: not_registered` and still exits 0 — "not enabled" is a
finding, not a broken run, as in the AWS fetchers.
Ported from prowler/providers/azure/services/defender/defender_service.py (Apache-2.0).
"""

import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
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

FULLY_COVERED = "fullycovered"
COVERAGE_UNKNOWN = "unknown"

_SCOPE_PATTERNS = (
    ("management_group", re.compile(r"^/providers/microsoft\.management/managementgroups/[^/]+$")),
    ("subscription", re.compile(r"^/subscriptions/[^/]+$")),
    ("resource_group", re.compile(r"^/subscriptions/[^/]+/resourcegroups/[^/]+$")),
)


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


def _iso8601_timestamp(value) -> str | None:
    """A `datetime` as the category's UTC "%Y-%m-%dT%H:%M:%SZ"; anything else passes through."""
    if not isinstance(value, datetime):
        return value
    moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def project_pricing(pricing) -> dict:
    """Read a `Pricing` model's attributes into a flat snake_case dict."""
    return {
        "id": model_attr(pricing, "id"),
        "name": model_attr(pricing, "name"),
        "pricing_tier": model_attr(pricing, "pricing_tier"),
        "sub_plan": model_attr(pricing, "sub_plan"),
        "free_trial_remaining_time": _iso8601_duration(
            model_attr(pricing, "free_trial_remaining_time")
        ),
        "enablement_time": _iso8601_timestamp(model_attr(pricing, "enablement_time")),
        "enforce": model_attr(pricing, "enforce"),
        "inherited": model_attr(pricing, "inherited"),
        "inherited_from": model_attr(pricing, "inherited_from"),
        "resources_coverage_status": model_attr(pricing, "resources_coverage_status"),
        "deprecated": model_attr(pricing, "deprecated"),
        "replaced_by": list(model_attr(pricing, "replaced_by") or []),
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


def _optional_bool(value) -> bool | None:
    """Like `_as_bool`, but a field the API left out stays None rather than False."""
    return None if value is None else _as_bool(value)


def _scope_id(value) -> str | None:
    """`inheritedFrom` is documented as the string "Null" when not inherited."""
    text = str(value or "").strip()
    return None if text.lower() in ("", "null", "none") else text


def scope_type(scope_id: str | None) -> str | None:
    """Which kind of ARM scope an `inheritedFrom` id names."""
    if not scope_id:
        return None
    normalized = scope_id.lower().rstrip("/")
    for name, pattern in _SCOPE_PATTERNS:
        if pattern.match(normalized):
            return name
    return "resource" if normalized.startswith("/subscriptions/") else "other"


def pricing_record(pricing: dict) -> dict:
    """Normalize one projected Defender plan.

    `extensions` collapses the SDK's list of {name, is_enabled, ...} objects into a
    flat {name: bool} map, which is how Prowler's checks read it.
    """
    extensions = pricing.get("extensions") or []
    inherited_from = _scope_id(pricing.get("inherited_from"))
    return {
        "resource_id": pricing.get("id"),
        "resource_name": pricing.get("name"),
        "pricing_tier": pricing.get("pricing_tier"),
        "enabled": str(pricing.get("pricing_tier") or "").lower() == PROTECTED_TIER,
        "sub_plan": pricing.get("sub_plan") or None,
        "enablement_time": pricing.get("enablement_time"),
        "free_trial_remaining_time": pricing.get("free_trial_remaining_time"),
        "resources_coverage_status": pricing.get("resources_coverage_status"),
        "enforce": _optional_bool(pricing.get("enforce")),
        "inherited": _optional_bool(pricing.get("inherited")),
        "inherited_from": inherited_from,
        "inherited_from_scope": scope_type(inherited_from),
        "deprecated": bool(pricing.get("deprecated")),
        "replaced_by": sorted(pricing.get("replaced_by") or []),
        "extensions": {
            ext.get("name"): _as_bool(ext.get("is_enabled"))
            for ext in extensions
            if ext.get("name")
        },
    }


def _names(rows) -> list[str]:
    return sorted(p["resource_name"] or "" for p in rows)


def summarize(plans: list[dict], registration_status: str) -> dict:
    """Standard-tier coverage is the headline: how many plans actually protect."""
    total = len(plans)
    enabled = [p for p in plans if p["enabled"]]
    standard = len(enabled)
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
            1 for p in plans for on in p["extensions"].values() if on
        ),
        "enabled_plans": _names(enabled),
        "enabled_plan_sub_plans": {p["resource_name"]: p["sub_plan"] for p in enabled},
        "enabled_plan_enablement_times": {
            p["resource_name"]: p["enablement_time"] for p in enabled
        },
        # A plan Azure gave no coverage status is listed as unknown, never read as covered.
        "enabled_plans_not_fully_covered": {
            p["resource_name"]: p["resources_coverage_status"] or COVERAGE_UNKNOWN
            for p in enabled
            if str(p["resources_coverage_status"] or "").lower() != FULLY_COVERED
        },
        "plans_not_enabled": _names(
            p for p in plans if not p["enabled"] and not p["deprecated"]
        ),
        "deprecated_plans": _names(p for p in plans if p["deprecated"]),
        "deprecated_plans_enabled": {
            p["resource_name"]: p["replaced_by"] for p in enabled if p["deprecated"]
        },
        "enforced_plans": _names(p for p in plans if p["enforce"]),
        "plans_reporting_inheritance": sum(1 for p in plans if p["inherited"] is not None),
        "inherited_plans": _names(p for p in plans if p["inherited"]),
        "plans_inherited_from_management_group": _names(
            p for p in plans if p["inherited"] and p["inherited_from_scope"] == "management_group"
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


# --- security contacts (who Defender for Cloud notifies) ----------------------

def project_security_contact(contact) -> dict:
    """Read a `SecurityContact`: addresses, phone presence, alert notification settings and role routing."""
    alerts = model_attr(contact, "alert_notifications")
    by_role = model_attr(contact, "notifications_by_role")
    return {
        "name": model_attr(contact, "name"),
        "emails": model_attr(contact, "emails"),
        "phone": model_attr(contact, "phone"),
        "alert_notifications_state": model_attr(alerts, "state"),
        "alert_notifications_minimal_severity": model_attr(alerts, "minimal_severity"),
        "notifications_by_role_state": model_attr(by_role, "state"),
        "notifications_by_role_roles": model_attr(by_role, "roles"),
    }


def security_contact_record(contact: dict) -> dict:
    """Normalize one projected security contact.

    `emails` is a semicolon-separated string in ARM; it is split and counted, and the
    addresses are kept because they are the evidence (who is notified). The phone
    number is reduced to whether one is set.
    """
    raw_emails = contact.get("emails") or ""
    emails = sorted({e.strip() for e in str(raw_emails).split(";") if e.strip()})
    state = contact.get("alert_notifications_state")
    role_state = contact.get("notifications_by_role_state")
    return {
        "name": contact.get("name"),
        "emails": emails,
        "email_count": len(emails),
        "phone_set": bool(contact.get("phone")),
        "alert_notifications_state": state,
        "alert_notifications_minimal_severity": contact.get("alert_notifications_minimal_severity"),
        "alert_notifications_on": (None if state is None else str(state).lower() == "on"),
        "notifications_by_role_state": role_state,
        "notifications_by_role_roles": sorted(str(r) for r in (contact.get("notifications_by_role_roles") or [])),
        "notifications_by_role_on": (None if role_state is None else str(role_state).lower() == "on"),
    }


def summarize_security_contacts(contacts: list[dict] | None) -> dict:
    """Counts for the contacts; every key null when the list could not be read (None), 0 when it is empty."""
    if contacts is None:
        return {"security_contacts": None, "security_contacts_with_alert_notifications_on": None,
                "security_contacts_with_role_notifications_on": None, "security_contact_emails": None,
                "alert_notification_minimal_severities": None}
    return {
        "security_contacts": len(contacts),
        "security_contacts_with_alert_notifications_on": sum(1 for c in contacts if c["alert_notifications_on"]),
        "security_contacts_with_role_notifications_on": sum(1 for c in contacts if c["notifications_by_role_on"]),
        "security_contact_emails": sum(c["email_count"] for c in contacts),
        "alert_notification_minimal_severities": sorted(
            {str(c["alert_notifications_minimal_severity"]) for c in contacts
             if c["alert_notifications_minimal_severity"] is not None}),
    }


def collect_security_contacts(subscription_id, cred, collector: Collector) -> list[dict] | None:
    """security_contacts.list(): the subscription's Defender for Cloud notification contacts.

    Returns None (not []) when the read failed, so the summary reads null rather than
    "no contacts". A subscription where Microsoft.Security is not registered has no
    contacts to read and is reported as [] without a failure, matching collect_pricings.
    """
    from azure.mgmt.security import SecurityCenter

    def _client():
        return SecurityCenter(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("security.SecurityCenter (init)", _client)
    if client is None:
        return None
    try:
        contacts = [security_contact_record(project_security_contact(c)) for c in client.security_contacts.list()]
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_provider_not_registered(exc):
            return []
        collector.record("security.security_contacts.list", exc)
        return None
    return sorted(contacts, key=lambda c: c.get("name") or "")


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
    contacts: list[dict] | None = None
    if subscription_id and cred is not None:
        plans, registration_status = collect_pricings(subscription_id, cred, collector)
        contacts = collect_security_contacts(subscription_id, cred, collector)
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
            # None when the read failed (recorded in api_failures), [] when there are none.
            "security_contacts": contacts,
        },
        summary={**summarize(plans, registration_status), **summarize_security_contacts(contacts)},
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
