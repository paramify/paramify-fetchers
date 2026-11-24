#!/usr/bin/env python3
"""Azure Front Door Standard/Premium WAF policies for one subscription."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
)
from frontdoor import (  # noqa: E402
    collect_waf_policies,
    definition_index,
    null_unread,
    select_front_door,
    waf_policy_record,
)
from resource_exclusions import ResourceExclusions  # noqa: E402

logger = logging.getLogger("azure_front_door_waf_policies")

# Summary fields by the lists they are built from; each reads null when one of those lists wasn't read. Blocking, rule
# groups and the newest version come from the managed rule-set definitions.
FIELDS_BY_LISTS = (
    (("waf_policies",), (
        "total_waf_policies", "premium_waf_policies", "standard_waf_policies", "associated_waf_policies",
        "unassociated_waf_policies", "policies_disabled", "policies_in_detection_mode", "policies_mode_unset",
        "policies_without_default_rule_set", "policies_default_rule_set_log_only", "policies_with_allow_all_custom_rule",
        "waf_policies_with_rate_limit_rules", "total_disabled_managed_rules", "total_disabled_managed_rule_groups",
        "skipped_policies_by_sku")),
    (("waf_policies", "rule_set_definitions"), (
        "blocking_waf_policies", "waf_policies_not_blocking", "associated_waf_policies_not_blocking",
        "policies_rule_groups_not_blocking", "policies_rule_definition_not_found",
        "policies_with_fully_disabled_rule_groups", "associated_policies_with_fully_disabled_rule_groups",
        "policies_on_older_default_rule_set")),
)


def summarize(policies: list[dict], skipped_by_sku: dict, unread=frozenset()) -> dict:
    """`unread` names the lists that weren't read (see FIELDS_BY_LISTS)."""
    def count(pred) -> int:
        return sum(1 for p in policies if pred(p))

    summary = {
        "total_waf_policies": len(policies),
        "premium_waf_policies": count(lambda p: p["sku"] == "Premium_AzureFrontDoor"),
        "standard_waf_policies": count(lambda p: p["sku"] == "Standard_AzureFrontDoor"),
        "blocking_waf_policies": count(lambda p: p["blocking"]),
        "waf_policies_not_blocking": count(lambda p: not p["blocking"]),
        "associated_waf_policies": count(lambda p: p["associated"]),
        "associated_waf_policies_not_blocking": count(lambda p: p["associated"] and not p["blocking"]),
        "unassociated_waf_policies": count(lambda p: not p["associated"]),
        "policies_disabled": count(lambda p: "policy_disabled" in p["not_blocking_reasons"]),
        "policies_in_detection_mode": count(lambda p: "mode_detection" in p["not_blocking_reasons"]),
        "policies_mode_unset": count(lambda p: "mode_unset" in p["not_blocking_reasons"]),
        "policies_without_default_rule_set": count(lambda p: "no_default_rule_set" in p["not_blocking_reasons"]),
        "policies_default_rule_set_log_only": count(
            lambda p: "default_rule_set_log_only" in p["not_blocking_reasons"]
        ),
        "policies_rule_groups_not_blocking": count(lambda p: "rule_groups_not_blocking" in p["not_blocking_reasons"]),
        "policies_rule_definition_not_found": count(lambda p: "rule_definition_not_found" in p["not_blocking_reasons"]),
        "policies_with_allow_all_custom_rule": count(lambda p: "allow_all_custom_rule" in p["not_blocking_reasons"]),
        "waf_policies_with_rate_limit_rules": count(lambda p: p["rate_limit_rules"] > 0),
        "total_disabled_managed_rules": sum(p["disabled_managed_rules"] for p in policies),
        "total_disabled_managed_rule_groups": sum(p["disabled_managed_rule_groups"] for p in policies),
        "policies_with_fully_disabled_rule_groups": count(lambda p: bool(p["default_rule_set_fully_disabled_groups"])),
        "associated_policies_with_fully_disabled_rule_groups": count(
            lambda p: p["associated"] and bool(p["default_rule_set_fully_disabled_groups"])
        ),
        "policies_on_older_default_rule_set": count(
            lambda p: p["default_rule_set_version"] is not None
            and p["default_rule_set_latest_version"] not in (None, p["default_rule_set_version"])
        ),
        "skipped_policies_by_sku": skipped_by_sku,
    }
    return null_unread(summary, FIELDS_BY_LISTS, unread)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure SDKs log every HTTP request at INFO, which would bury the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    projected: list[dict] | None = None
    definitions = definition_index(None)
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Network is not registered on subscription %s", subscription_id)
        projected, definitions = collect_waf_policies(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    listed = projected is not None
    front_door, skipped_by_sku = select_front_door(projected or [])
    # A policy linked to an excluded profile's security policy still reads associated.
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)
    front_door, excluded = exclusions.split(sorted(front_door, key=lambda p: (p["id"] or "").lower()), "waf_policy")
    if not listed:
        exclusions.mark_unread()
    exclusions.warn_unmatched(logger)
    policies = sorted((waf_policy_record(p, definitions) for p in front_door), key=lambda r: (r["id"] or "").lower())

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={"waf_policies": policies, "provider_registration_status": registration, "excluded": excluded},
        summary={**summarize(policies, skipped_by_sku, {name for name, read in (
                    ("waf_policies", listed), ("rule_set_definitions", definitions.get("read", True))) if not read}),
                 "provider_registration_status": registration,
                 **exclusions.summary(excluded, ("waf_policy",), {"waf_policies": len(policies) if listed else None})},
    )
    filename = f"azure_front_door_waf_policies_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
