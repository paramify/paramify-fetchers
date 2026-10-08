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
    select_front_door,
    waf_policy_record,
)

logger = logging.getLogger("azure_front_door_waf_policies")


def summarize(policies: list[dict], skipped_by_sku: dict) -> dict:
    def count(pred) -> int:
        return sum(1 for p in policies if pred(p))

    return {
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

    projected: list[dict] = []
    definitions = definition_index([])
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

    front_door, skipped_by_sku = select_front_door(projected)
    policies = sorted((waf_policy_record(p, definitions) for p in front_door), key=lambda r: (r["id"] or "").lower())

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={"waf_policies": policies, "provider_registration_status": registration},
        summary={**summarize(policies, skipped_by_sku), "provider_registration_status": registration},
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
