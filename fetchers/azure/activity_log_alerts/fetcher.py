#!/usr/bin/env python3
"""Azure activity log alert rules for one subscription, with a derived map of which
control-plane operations they cover — one evidence set in place of eleven checks.

Ported from prowler/providers/azure/services/monitor/monitor_service.py
`get_alert_rules` and lib/monitor_alerts.py `check_alert_rule` (Apache-2.0). Two
deviations, both against under-reporting: the `anyOf` / `containsAny` condition forms
are decoded too (Prowler reads only `equals`, so an alert listing several operations
under one `anyOf` would read as covering nothing), and operation names are compared
case-insensitively.
"""

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
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_activity_log_alerts")

# The ARM condition field an operation alert keys on.
OPERATION_NAME_FIELD = "operationname"
CATEGORY_FIELD = "category"
INCIDENT_TYPE_FIELD = "properties.incidenttype"

# The control-plane operations Prowler has a dedicated check for, keyed by what the
# alert is FOR so the coverage map reads as evidence. Some keys map to two operations
# because Azure kept a classic namespace alongside the ARM one; either counts, as
# monitor_alert_delete_nsg reads it.
MONITORED_OPERATIONS = {
    # monitor_alert_create_update_nsg
    "create_update_network_security_group": ("Microsoft.Network/networkSecurityGroups/write",),
    # monitor_alert_delete_nsg
    "delete_network_security_group": (
        "Microsoft.Network/networkSecurityGroups/delete",
        "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
    ),
    # CIS Azure "Create or Update Network Security Group Rule" / its delete twin.
    # Prowler master folded these into the NSG checks; kept separate because an
    # NSG-scoped alert does NOT fire on a rule edit, so folding overstates coverage.
    "create_update_network_security_group_rule": (
        "Microsoft.Network/networkSecurityGroups/securityRules/write",
    ),
    "delete_network_security_group_rule": (
        "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    ),
    # monitor_alert_create_update_public_ip_address_rule / ..._delete_...
    "create_update_public_ip_address": ("Microsoft.Network/publicIPAddresses/write",),
    "delete_public_ip_address": ("Microsoft.Network/publicIPAddresses/delete",),
    # monitor_alert_create_policy_assignment / monitor_alert_delete_policy_assignment
    "create_update_policy_assignment": ("Microsoft.Authorization/policyAssignments/write",),
    "delete_policy_assignment": ("Microsoft.Authorization/policyAssignments/delete",),
    # monitor_alert_create_update_sqlserver_fr / monitor_alert_delete_sqlserver_fr
    "create_update_sql_server_firewall_rule": ("Microsoft.Sql/servers/firewallRules/write",),
    "delete_sql_server_firewall_rule": ("Microsoft.Sql/servers/firewallRules/delete",),
    # monitor_alert_create_update_security_solution / ..._delete_...
    "create_update_security_solution": ("Microsoft.Security/securitySolutions/write",),
    "delete_security_solution": ("Microsoft.Security/securitySolutions/delete",),
}

# monitor_alert_service_health_exists is not an operationName alert: it needs BOTH
# category == ServiceHealth and properties.incidentType == Incident on one rule.
SERVICE_HEALTH_CATEGORY = "servicehealth"
SERVICE_HEALTH_INCIDENT_TYPE = "incident"


# --- projection: the only code that touches an azure-mgmt model ---

def project_leaf_condition(condition) -> dict:
    """Read one `AlertRuleLeafCondition` (an `any_of` member) into a flat dict."""
    return {
        "field": model_attr(condition, "field"),
        "equals": model_attr(condition, "equals"),
        "contains_any": model_attr(condition, "contains_any"),
    }


def project_condition(condition) -> dict:
    """Read one `AlertRuleAnyOfOrLeafCondition` into a flat dict.

    Three mutually exclusive forms: `field` + `equals`, `field` + `contains_any`, or an
    `any_of` group. Prowler keeps only the first; all three are carried so the coverage
    decoder cannot miss an alert that used the others.
    """
    return {
        "field": model_attr(condition, "field"),
        "equals": model_attr(condition, "equals"),
        "contains_any": model_attr(condition, "contains_any"),
        "any_of": [
            project_leaf_condition(leaf) for leaf in (model_attr(condition, "any_of") or [])
        ],
    }


def project_activity_log_alert(alert) -> dict:
    """Read an `ActivityLogAlertResource` model's attributes into a flat dict.

    This API version is msrest-generated and FLATTENS `properties.*` onto the model
    (`enabled` maps to `properties.enabled`), per the installed SDK's `_attribute_map`.
    """
    condition = model_attr(alert, "condition")
    actions = model_attr(alert, "actions")
    return {
        "id": model_attr(alert, "id"),
        "name": model_attr(alert, "name"),
        "location": model_attr(alert, "location"),
        "enabled": model_attr(alert, "enabled"),
        "description": model_attr(alert, "description"),
        "scopes": model_attr(alert, "scopes"),
        "condition": {
            "all_of": [
                project_condition(c) for c in (model_attr(condition, "all_of") or [])
            ],
        },
        "action_groups": [
            model_attr(group, "action_group_id")
            for group in (model_attr(actions, "action_groups") or [])
        ],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _condition_values(condition: dict, field: str) -> set[str]:
    """Every value one projected condition matches for `field`, case-folded.

    Decodes all three ARM forms. ARM echoes an operation name back in whatever case it
    was written in, so Prowler's exact `==` reports a correctly-configured alert as
    missing when the operator typed it lowercase.
    """
    values: set[str] = set()
    for entry in (condition, *(condition.get("any_of") or [])):
        if str(entry.get("field") or "").strip().lower() != field:
            continue
        if entry.get("equals"):
            values.add(str(entry["equals"]).strip().lower())
        for value in entry.get("contains_any") or []:
            values.add(str(value).strip().lower())
    return values


def alert_operation_names(alert: dict) -> list[str]:
    """The operationName values one alert fires on, sorted and case-folded."""
    conditions = ((alert.get("condition") or {}).get("all_of")) or []
    names: set[str] = set()
    for condition in conditions:
        names |= _condition_values(condition, OPERATION_NAME_FIELD)
    return sorted(names)


def is_service_health_alert(alert: dict) -> bool:
    """Prowler's monitor_alert_service_health_exists predicate.

    Needs BOTH conditions on the same rule: category == ServiceHealth and
    properties.incidentType == Incident. Category alone also fires on maintenance and
    advisory notices.
    """
    conditions = ((alert.get("condition") or {}).get("all_of")) or []
    categories: set[str] = set()
    incident_types: set[str] = set()
    for condition in conditions:
        categories |= _condition_values(condition, CATEGORY_FIELD)
        incident_types |= _condition_values(condition, INCIDENT_TYPE_FIELD)
    return (
        SERVICE_HEALTH_CATEGORY in categories
        and SERVICE_HEALTH_INCIDENT_TYPE in incident_types
    )


def alert_record(alert: dict) -> dict:
    """Normalize one projected alert rule into an evidence record.

    `enabled` is coerced: ARM omits it on a rule created disabled, and a falsy value
    means the rule covers nothing — a disabled rule never fires.
    """
    resource_id = alert.get("id")
    enabled = bool(alert.get("enabled") or False)
    operations = alert_operation_names(alert)
    return {
        "id": resource_id,
        "name": alert.get("name"),
        "location": alert.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "enabled": enabled,
        "description": alert.get("description"),
        "scopes": alert.get("scopes") or [],
        "condition": {"all_of": (alert.get("condition") or {}).get("all_of") or []},
        "action_groups": [group for group in (alert.get("action_groups") or []) if group],
        # Decoded so downstream need not re-implement ARM's condition grammar. Only
        # an ENABLED rule contributes coverage.
        "monitored_operations": operations if enabled else [],
        "service_health_alert": enabled and is_service_health_alert(alert),
    }


def operation_coverage(alerts: list[dict]) -> dict:
    """Which of MONITORED_OPERATIONS at least one enabled alert fires on."""
    covered = {name for alert in alerts for name in alert["monitored_operations"]}
    return {
        key: any(operation.lower() in covered for operation in operations)
        for key, operations in MONITORED_OPERATIONS.items()
    }


def summarize(alerts: list[dict]) -> dict:
    """Coverage of the monitored operations is the headline, not the alert count."""
    coverage = operation_coverage(alerts)
    covered = sum(1 for is_covered in coverage.values() if is_covered)
    total_monitored = len(MONITORED_OPERATIONS)
    enabled = [alert for alert in alerts if alert["enabled"]]
    return {
        "total_activity_log_alerts": len(alerts),
        "enabled_alerts": len(enabled),
        "disabled_alerts": len(alerts) - len(enabled),
        "alerts_with_action_groups": sum(1 for alert in alerts if alert["action_groups"]),
        "alerts_without_action_groups": sum(
            1 for alert in alerts if not alert["action_groups"]
        ),
        "monitored_operation_coverage": coverage,
        "monitored_operations_covered": covered,
        "monitored_operations_total": total_monitored,
        "monitored_operation_percentage": coverage_percentage(covered, total_monitored),
        "all_monitored_operations_covered": covered == total_monitored,
        "uncovered_monitored_operations": sorted(
            key for key, is_covered in coverage.items() if not is_covered
        ),
        "service_health_alert_configured": any(alert["service_health_alert"] for alert in alerts),
    }


# --- collection (lazy azure imports) ---

def collect_activity_log_alerts(subscription_id, cred, collector: Collector) -> list[dict]:
    """One activity_log_alerts.list_by_subscription_id() call."""
    from azure.mgmt.monitor import MonitorManagementClient

    def _client():
        return MonitorManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("monitor.MonitorManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself.
        return [
            alert_record(project_activity_log_alert(a))
            for a in client.activity_log_alerts.list_by_subscription_id()
        ]

    alerts = collector.guard(
        "monitor.activity_log_alerts.list_by_subscription_id", _list, default=[]
    )
    return sorted(alerts, key=lambda r: r.get("id") or "")


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

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    alerts: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # ARM returns an empty list, not an error, for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Insights"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Insights is not registered on subscription %s — no "
                "activity log alerts can exist; reporting status not_registered",
                subscription_id,
            )
        alerts = collect_activity_log_alerts(subscription_id, cred, collector)
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
            "activity_log_alerts": alerts,
            # Emitted so the evidence carries the list it is judged against.
            "monitored_operations": {
                key: list(operations) for key, operations in MONITORED_OPERATIONS.items()
            },
            "provider_registration_status": registration,
        },
        summary={**summarize(alerts), "provider_registration_status": registration},
    )

    filename = (
        f"azure_activity_log_alerts_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
