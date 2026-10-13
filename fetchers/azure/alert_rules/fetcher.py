#!/usr/bin/env python3
"""Azure Monitor metric, log search and smart detector alert rules, and whether each reaches an enabled receiver."""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
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
    coverage_percentage,
    credential,
    failure_reason,
    provider_registration_status,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)
from alert_routing import (  # noqa: E402
    add_referenced_groups,
    collect_action_groups,
    collect_processing_rules,
    route,
    tri_state,
)
from arm_rest import arm_rest_client, list_all  # noqa: E402

logger = logging.getLogger("azure_alert_rules")

METRIC_ALERT_API = "2018-03-01"
LOG_ALERT_API = "2023-12-01"
SMART_DETECTOR_API = "2021-04-01"

RULE_METRIC = "metric"
RULE_LOG_SEARCH = "log_search"
RULE_SMART_DETECTOR = "smart_detector"

# Read by REST: 6.0.2 drops nextLink on metric alerts, defaults log alerts to the 2018 schema, and has no smart detector op.
SOURCES = (
    (RULE_METRIC, "Microsoft.Insights", "Microsoft.Insights/metricAlerts", METRIC_ALERT_API),
    (RULE_LOG_SEARCH, "Microsoft.Insights", "Microsoft.Insights/scheduledQueryRules", LOG_ALERT_API),
    (RULE_SMART_DETECTOR, "Microsoft.AlertsManagement", "microsoft.alertsManagement/smartDetectorAlertRules", SMART_DETECTOR_API),
)


# --- pure transforms ---

def _severity(value):
    text = str(value if value is not None else "").strip()
    if text.lower().startswith("sev"):
        text = text[3:]
    return int(text) if text.isdigit() else None


def metric_rule(raw: dict) -> dict:
    props = raw.get("properties") or {}
    criteria = props.get("criteria") or {}
    return {
        "rule_type": RULE_METRIC,
        "kind": criteria.get("odata.type"),
        "enabled": props.get("enabled") is True,
        "severity": _severity(props.get("severity")),
        "scopes": props.get("scopes") or [],
        "description": props.get("description"),
        "evaluation_frequency": props.get("evaluationFrequency"),
        "condition": [
            {k: c.get(k) for k in ("name", "metricNamespace", "metricName", "operator", "threshold", "timeAggregation", "criterionType")}
            for c in criteria.get("allOf") or []
        ],
        "action_group_ids": [a.get("actionGroupId") for a in props.get("actions") or [] if a.get("actionGroupId")],
        "mute_actions_duration": None,
        "is_alerting_rule": True,
    }


def log_search_rule(raw: dict) -> dict:
    props = raw.get("properties") or {}
    kind = raw.get("kind") or "LogAlert"
    return {
        "rule_type": RULE_LOG_SEARCH,
        "kind": kind,
        "enabled": props.get("enabled") is True,
        "severity": _severity(props.get("severity")),
        "scopes": props.get("scopes") or [],
        "description": props.get("description") or props.get("displayName"),
        "evaluation_frequency": props.get("evaluationFrequency"),
        "condition": [
            {k: c.get(k) for k in ("query", "timeAggregation", "operator", "threshold")}
            for c in (props.get("criteria") or {}).get("allOf") or []
        ],
        "action_group_ids": [g for g in (props.get("actions") or {}).get("actionGroups") or [] if g],
        "mute_actions_duration": props.get("muteActionsDuration"),
        # LogToMetric rules publish a metric and never notify.
        "is_alerting_rule": kind != "LogToMetric",
    }


def smart_detector_rule(raw: dict) -> dict:
    props = raw.get("properties") or {}
    return {
        "rule_type": RULE_SMART_DETECTOR,
        "kind": (props.get("detector") or {}).get("id"),
        "enabled": str(props.get("state") or "").lower() == "enabled",
        "severity": _severity(props.get("severity")),
        "scopes": props.get("scope") or [],
        "description": props.get("description"),
        "evaluation_frequency": props.get("frequency"),
        "condition": [],
        "action_group_ids": [g for g in (props.get("actionGroups") or {}).get("groupIds") or [] if g],
        "mute_actions_duration": (props.get("throttling") or {}).get("duration"),
        "is_alerting_rule": True,
    }


PROJECT = {RULE_METRIC: metric_rule, RULE_LOG_SEARCH: log_search_rule, RULE_SMART_DETECTOR: smart_detector_rule}


def rule_record(rule_type: str, raw: dict, groups: dict, processing_rules: list[dict]) -> dict:
    rule = {"id": raw.get("id"), "name": raw.get("name"), **PROJECT[rule_type](raw)}
    return {**rule, **route(rule["enabled"], rule["action_group_ids"], rule["scopes"], groups, processing_rules)}


def _count(rules: list[dict], field: str, value) -> int:
    return sum(1 for r in rules if r[field] is value)


def summarize(rules: list[dict], groups: list[dict], processing_rules: list[dict]) -> dict:
    """Unknown (null) verdicts are counted apart, never folded into "no"."""
    alerting = [r for r in rules if r["is_alerting_rule"]]
    enabled = [r for r in alerting if r["enabled"]]
    reaching = _count(enabled, "reaches_human", True)
    by_type = Counter(r["rule_type"] for r in rules)
    return {
        "total_alert_rules": len(rules),
        "rules_by_type": {t: by_type[t] for t in sorted(by_type)},
        "alerting_rules": len(alerting),
        "enabled_alerting_rules": len(enabled),
        "disabled_alerting_rules": len(alerting) - len(enabled),
        "enabled_rules_without_action_groups": sum(1 for r in enabled if not r["resolved_action_groups"]),
        "enabled_rules_routing_to_enabled_receiver": _count(enabled, "routes_to_enabled_receiver", True),
        "enabled_rules_routing_unknown": _count(enabled, "routes_to_enabled_receiver", None),
        "enabled_rules_routing_to_person": _count(enabled, "routes_to_person", True),
        "enabled_rules_suppressed": _count(enabled, "suppressed", True),
        "enabled_rules_possibly_suppressed": _count(enabled, "suppressed", None),
        "enabled_rules_reaching_human": reaching,
        "enabled_rules_reaching_human_unknown": _count(enabled, "reaches_human", None),
        "enabled_rules_not_reaching_human": _count(enabled, "reaches_human", False),
        "reaching_human_percentage": coverage_percentage(reaching, len(enabled)),
        "all_enabled_rules_reach_human": tri_state(r["reaches_human"] for r in enabled) if enabled else False,
        "log_search_rules_enabled": sum(1 for r in enabled if r["rule_type"] == RULE_LOG_SEARCH),
        "action_groups": len(groups),
        "deliverable_action_groups": sum(1 for g in groups if g["deliverable"]),
        "action_groups_notifying_people": sum(1 for g in groups if g["notifies_people"]),
        "processing_rules": len(processing_rules),
        "suppressing_processing_rules_active": sum(
            1 for p in processing_rules if p["suppresses_notifications"] and p["active_now"] is not False
        ),
    }


# --- collection ---

def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request header at INFO; warnings still get through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    now = datetime.now(timezone.utc)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    rules: list[dict] = []
    group_records: list[dict] = []
    processing_rules: list[dict] = []
    pages: dict = {}
    registration = {ns: REGISTRATION_UNKNOWN for ns in ("Microsoft.Insights", "Microsoft.AlertsManagement")}
    if subscription_id and cred is not None:
        for ns in registration:
            registration[ns] = provider_registration_status(collector, subscription_id, cred, ns)
        rest = collector.guard("arm_rest.ARMPipelineClient (init)", lambda: arm_rest_client(cred))
        insights = registration["Microsoft.Insights"] != NOT_REGISTERED
        alerts_mgmt = registration["Microsoft.AlertsManagement"] != NOT_REGISTERED
        raw_rules: list[tuple[str, dict]] = []
        if rest is not None:
            for rule_type, ns, path, api in SOURCES:
                if registration[ns] == NOT_REGISTERED:
                    continue
                listed = collector.guard(
                    f"{path} list",
                    lambda path=path, api=api: list_all(rest, f"/subscriptions/{subscription_id}/providers/{path}", api),
                )
                if listed:
                    pages[rule_type] = listed["pages"]
                    raw_rules.extend((rule_type, r) for r in listed["items"])
            if insights:
                groups = collector.guard("Microsoft.Insights/actionGroups list", lambda: collect_action_groups(rest, subscription_id))
                group_records = groups["groups"] if groups else []
            if alerts_mgmt:
                apr = collector.guard(
                    "Microsoft.AlertsManagement/actionRules list",
                    lambda: collect_processing_rules(rest, subscription_id, now),
                )
                processing_rules = apr["rules"] if apr else []
            by_id = {(g["id"] or "").lower(): g for g in group_records}
            referenced = [gid for t, r in raw_rules for gid in PROJECT[t](r)["action_group_ids"]]
            referenced += [gid for p in processing_rules for gid in p["added_action_group_ids"]]
            add_referenced_groups(rest, referenced, by_id, collector)
            rules = [rule_record(t, r, by_id, processing_rules) for t, r in raw_rules]
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    rules.sort(key=lambda r: (r["id"] or "").lower())
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "alert_rules": rules,
            "action_groups": sorted(group_records, key=lambda g: (g["id"] or "").lower()),
            "processing_rules": sorted(processing_rules, key=lambda p: (p["id"] or "").lower()),
            "pages_read": pages,
            "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "provider_registration_status": registration,
        },
        summary={**summarize(rules, group_records, processing_rules), "provider_registration_status": registration},
    )

    filename = f"azure_alert_rules_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s (%d rules)", path, len(rules))

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
