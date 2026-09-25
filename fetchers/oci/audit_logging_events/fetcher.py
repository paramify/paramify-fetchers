#!/usr/bin/env python3
"""
OCI audit, logging and events — what is recorded, what is watched, and who is told

The tenancy's audit retention, every log group and log with what it captures and
whether it is enabled, every Events rule with its condition parsed into the
event types it matches, and every notification topic with the state of its
subscriptions — joined end to end, so a rule that fires into a topic nobody
subscribes to is reported as notifying nobody.

Evidence for KSI-MLA-LET, "a list of information resources and event types that
will be logged, monitored, and audited is maintained and persistently reviewed
to ensure these activities occur", and KSI-MLA-OSM for the centralized audit
trail and its retention.

Ported from Prowler's OCI audit, logging and events services (Apache-2.0,
prowler/providers/oraclecloud/services/{audit,logging,events}, commit 5fe1a67) —
the 365-day audit retention check, the eleven `events_rule_*` change-monitoring
checks and the notification-topic check. Prowler handles the "no rule at all"
case correctly; these three departures are about rules that exist:

  * WILDCARD EVENT TYPES ARE MISSED. Oracle's rule conditions support the
    asterisk — its own documentation gives
    `"eventType": "com.oraclecloud.objectstorage.*bucket"` and says it "matches
    all types of bucket events". Prowler tests `required_type in event_types`,
    exact string membership, so a tenancy monitoring a whole service by wildcard
    is reported as monitoring nothing.

  * A BARE STRING CONDITION IS MISSED. `eventType` may be a single string rather
    than a list — again Oracle's own example. Prowler requires
    `isinstance(event_types, list)` and returns False otherwise.

  * RULES AND TOPICS ARE NEVER JOINED. Prowler asks whether a rule has actions,
    and separately whether some topic somewhere has a subscription. A rule whose
    ONS action points at a topic with no ACTIVE subscription notifies nobody,
    which is exactly the live tenancy's state: one enabled rule, one enabled ONS
    action, one topic, zero subscriptions. `notifying` walks the whole chain.

ALSO NOT COUNTED AS NOTIFICATION: a disabled action, and a Streaming or
Functions action. Prowler counts any non-empty action list. Streams and
functions are recorded separately — they are real destinations, but they are not
someone being told.

A PENDING SUBSCRIPTION IS NOT A SUBSCRIBER. An emailed confirmation that was
never clicked sits in PENDING forever and receives nothing.
"""

import json
import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    as_bool,
    build_payload,
    coverage_percentage,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    resolve_scope,
    sanitize_for_filename,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_audit_logging_events")

# CIS OCI Foundations' audit retention requirement, and Prowler's threshold.
AUDIT_RETENTION_DAYS = 365

NOTIFICATION_ACTION = "ONS"
ACTIVE_SUBSCRIPTION = "ACTIVE"

# The change categories Prowler covers with one check each, as the event-type
# prefixes that evidence them. A category is covered when a rule matches any of
# its types — Oracle emits create/update/delete as separate types.
MONITORED_CATEGORIES = {
    "iam_policy_changes": ("com.oraclecloud.identitycontrolplane.createpolicy",
                           "com.oraclecloud.identitycontrolplane.updatepolicy",
                           "com.oraclecloud.identitycontrolplane.deletepolicy"),
    "iam_group_changes": ("com.oraclecloud.identitycontrolplane.creategroup",
                          "com.oraclecloud.identitycontrolplane.updategroup",
                          "com.oraclecloud.identitycontrolplane.deletegroup"),
    "iam_user_changes": ("com.oraclecloud.identitycontrolplane.createuser",
                         "com.oraclecloud.identitycontrolplane.updateuser",
                         "com.oraclecloud.identitycontrolplane.deleteuser"),
    "identity_provider_changes": ("com.oraclecloud.identitycontrolplane.createidentityprovider",
                                  "com.oraclecloud.identitycontrolplane.updateidentityprovider",
                                  "com.oraclecloud.identitycontrolplane.deleteidentityprovider"),
    "idp_group_mapping_changes": ("com.oraclecloud.identitycontrolplane.createidpgroupmapping",
                                  "com.oraclecloud.identitycontrolplane.updateidpgroupmapping",
                                  "com.oraclecloud.identitycontrolplane.deleteidpgroupmapping"),
    "local_user_authentication": ("com.oraclecloud.identitysignon.interactivelogin",),
    "vcn_changes": ("com.oraclecloud.virtualnetwork.createvcn",
                    "com.oraclecloud.virtualnetwork.updatevcn",
                    "com.oraclecloud.virtualnetwork.deletevcn"),
    "route_table_changes": ("com.oraclecloud.virtualnetwork.createroutetable",
                            "com.oraclecloud.virtualnetwork.updateroutetable",
                            "com.oraclecloud.virtualnetwork.deleteroutetable"),
    "security_list_changes": ("com.oraclecloud.virtualnetwork.createsecuritylist",
                              "com.oraclecloud.virtualnetwork.updatesecuritylist",
                              "com.oraclecloud.virtualnetwork.deletesecuritylist"),
    "network_security_group_changes": ("com.oraclecloud.virtualnetwork.createnetworksecuritygroup",
                                       "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup",
                                       "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup"),
    "network_gateway_changes": ("com.oraclecloud.virtualnetwork.createinternetgateway",
                                "com.oraclecloud.virtualnetwork.updateinternetgateway",
                                "com.oraclecloud.virtualnetwork.deleteinternetgateway",
                                "com.oraclecloud.natgateway.createnatgateway",
                                "com.oraclecloud.natgateway.deletenatgateway"),
    "cloud_guard_problems": ("com.oraclecloud.cloudguard.problemdetected",),
}


# --- pure transforms ---

def event_type_matches(pattern: str, event_type: str) -> bool:
    """True when an Events rule pattern matches a concrete event type.

    Oracle supports `*` in a condition value — its own documentation gives
    `com.oraclecloud.objectstorage.*bucket` and calls it a match for every
    bucket event. Prowler compares for equality, so a wildcard rule reads as
    monitoring nothing.
    """
    pattern, event_type = str(pattern).strip().lower(), str(event_type).strip().lower()
    if "*" not in pattern:
        return pattern == event_type
    expression = "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", pattern))
    return re.fullmatch(expression, event_type) is not None


def parse_condition(condition) -> dict:
    """The event types a rule condition matches, plus whether it parsed.

    `eventType` may be a list or a single string — both are in Oracle's docs.
    Prowler accepts only the list form.
    """
    if not condition:
        return {"parsed": False, "event_types": [], "has_data_filter": False}
    try:
        parsed = json.loads(condition)
    except (TypeError, ValueError):
        return {"parsed": False, "event_types": [], "has_data_filter": False}
    if not isinstance(parsed, dict):
        return {"parsed": False, "event_types": [], "has_data_filter": False}

    raw: object = next((parsed[key] for key in parsed if key.lower() == "eventtype"), [])
    types: list[str]
    if isinstance(raw, str):
        types = [raw]
    else:
        types = [t for t in (raw or []) if isinstance(t, str)] if isinstance(raw, list) else []
    return {
        "parsed": True,
        "event_types": types,
        # A data filter narrows a rule to particular resources, so a rule can
        # match the event type and still not fire for most of the estate.
        "has_data_filter": bool(parsed.get("data")),
    }


def action_record(action: dict) -> dict:
    kind = action.get("action_type")
    enabled = action.get("is_enabled") is True and action.get("lifecycle_state") == "ACTIVE"
    return {
        "action_type": kind,
        "is_enabled": action.get("is_enabled") is True,
        "lifecycle_state": action.get("lifecycle_state"),
        "is_active": enabled,
        "topic_id": action.get("topic_id"),
        "stream_id": action.get("stream_id"),
        "function_id": action.get("function_id"),
        "notifies": enabled and kind == NOTIFICATION_ACTION and bool(action.get("topic_id")),
    }


def rule_record(rule: dict, *, topics_with_subscribers=frozenset()) -> dict:
    """One Events rule, with its condition parsed and its chain to a subscriber.

    `topics_with_subscribers` is the set of topic OCIDs holding at least one
    ACTIVE subscription, which is what makes an ONS action reach a person.
    """
    condition = parse_condition(rule.get("condition"))
    actions = [action_record(a) for a in (rule.get("actions") or {}).get("actions") or []]
    active = rule.get("is_enabled") is True and rule.get("lifecycle_state") == "ACTIVE"
    notifying_actions = [a for a in actions if a["notifies"] and a["topic_id"] in topics_with_subscribers]

    covered = sorted(
        name for name, types in MONITORED_CATEGORIES.items()
        if any(event_type_matches(pattern, event_type)
               for pattern in condition["event_types"] for event_type in types)
    )
    return {
        "id": rule.get("id"),
        "display_name": rule.get("display_name"),
        "compartment_id": rule.get("compartment_id"),
        "lifecycle_state": rule.get("lifecycle_state"),
        "is_enabled": rule.get("is_enabled") is True,
        "is_active": active,
        "condition": rule.get("condition"),
        "condition_parsed": condition["parsed"],
        "event_types": condition["event_types"],
        "uses_wildcard_event_type": any("*" in t for t in condition["event_types"]),
        "has_data_filter": condition["has_data_filter"],
        "monitored_categories": covered,
        "actions": actions,
        "has_notification_action": any(a["notifies"] for a in actions),
        # The whole chain: enabled rule -> enabled ONS action -> topic with a
        # confirmed subscriber. Prowler checks the first two links separately
        # and never the third.
        "notifying": bool(active and notifying_actions),
        "streams_or_functions_only": bool(actions) and not any(a["notifies"] for a in actions),
        "time_created": iso(rule.get("time_created")),
    }


def topic_record(topic: dict, *, subscriptions=None) -> dict:
    records = [{
        "id": s.get("id"),
        "protocol": s.get("protocol"),
        "lifecycle_state": s.get("lifecycle_state"),
        "is_active": s.get("lifecycle_state") == ACTIVE_SUBSCRIPTION,
        "created_time": iso(s.get("created_time")),
    } for s in subscriptions] if subscriptions is not None else None
    active = [s for s in records or [] if s["is_active"]]
    return {
        "topic_id": topic.get("topic_id"),
        "name": topic.get("name"),
        "compartment_id": topic.get("compartment_id"),
        "lifecycle_state": topic.get("lifecycle_state"),
        "subscriptions": records,
        "subscriptions_read": records is not None,
        "active_subscriptions": len(active) if records is not None else None,
        # A PENDING subscription is an unconfirmed invitation, not a subscriber.
        "pending_subscriptions": (
            sum(1 for s in records if not s["is_active"]) if records is not None else None
        ),
        "has_subscriber": bool(active) if records is not None else None,
        "protocols": sorted({s["protocol"] for s in active if s["protocol"]}),
    }


def log_record(log: dict) -> dict:
    source = (log.get("configuration") or {}).get("source") or {}
    return {
        "id": log.get("id"),
        "display_name": log.get("display_name"),
        "log_group_id": log.get("log_group_id"),
        "log_type": log.get("log_type"),
        "is_enabled": log.get("is_enabled") is True,
        "retention_duration_days": log.get("retention_duration"),
        "service": source.get("service"),
        "category": source.get("category"),
        "resource": source.get("resource"),
        "lifecycle_state": log.get("lifecycle_state"),
        "time_created": iso(log.get("time_created")),
    }


def log_group_record(group: dict, *, logs=()) -> dict:
    entries = list(logs)
    return {
        "id": group.get("id"),
        "display_name": group.get("display_name"),
        "compartment_id": group.get("compartment_id"),
        "lifecycle_state": group.get("lifecycle_state"),
        "time_created": iso(group.get("time_created")),
        "logs": entries,
        "log_count": len(entries),
        "enabled_log_count": sum(1 for entry in entries if entry["is_enabled"]),
    }


def audit_record(configuration: dict) -> dict:
    retention = configuration.get("retention_period_days")
    return {
        "retention_period_days": retention,
        "meets_365_day_retention": retention is not None and retention >= AUDIT_RETENTION_DAYS,
    }


def summarize(audit, log_groups, rules, topics, *, audit_retention_skipped: bool = False) -> dict:
    logs = [entry for group in log_groups for entry in group["logs"]]
    enabled_logs = [entry for entry in logs if entry["is_enabled"]]
    active_rules = [r for r in rules if r["is_active"]]
    read_topics = [t for t in topics if t["subscriptions_read"]]

    def category_state(name):
        matching = [r for r in active_rules if name in r["monitored_categories"]]
        return {
            "monitored": bool(matching),
            "notifying": any(r["notifying"] for r in matching),
            "rules": sorted(r["display_name"] for r in matching if r["display_name"]),
        }

    coverage = {name: category_state(name) for name in sorted(MONITORED_CATEGORIES)}
    monitored = [name for name, state in coverage.items() if state["monitored"]]
    notifying = [name for name, state in coverage.items() if state["notifying"]]

    return {
        # Audit.
        "audit_retention_period_days": audit["retention_period_days"] if audit else None,
        "audit_meets_365_day_retention": audit["meets_365_day_retention"] if audit else None,
        # True when the deployment chose not to read retention (see collect()),
        # so a None above is a decision, not a failure.
        "audit_retention_skipped_by_configuration": audit_retention_skipped,
        # Logging.
        "total_log_groups": len(log_groups),
        "total_logs": len(logs),
        "enabled_logs": len(enabled_logs),
        "disabled_logs": len(logs) - len(enabled_logs),
        "logged_services": sorted({entry["service"] for entry in enabled_logs if entry["service"]}),
        "log_categories": sorted({entry["category"] for entry in enabled_logs if entry["category"]}),
        "shortest_log_retention_days": min(
            (entry["retention_duration_days"] for entry in enabled_logs
             if entry["retention_duration_days"] is not None), default=None
        ),
        # Events.
        "total_rules": len(rules),
        "active_rules": len(active_rules),
        "rules_with_unparseable_condition": sum(1 for r in rules if not r["condition_parsed"]),
        "rules_using_wildcard_event_types": sum(1 for r in rules if r["uses_wildcard_event_type"]),
        "rules_with_data_filters": sum(1 for r in active_rules if r["has_data_filter"]),
        "active_rules_notifying_nobody": sum(1 for r in active_rules if not r["notifying"]),
        "rules_delivering_only_to_streams_or_functions": sum(
            1 for r in active_rules if r["streams_or_functions_only"]
        ),
        # The coverage matrix, monitored vs actually reaching a person.
        "monitored_change_categories": monitored,
        "notifying_change_categories": notifying,
        "unmonitored_change_categories": sorted(set(MONITORED_CATEGORIES) - set(monitored)),
        "monitored_but_not_notifying": sorted(set(monitored) - set(notifying)),
        "change_category_coverage_percentage": coverage_percentage(len(monitored), len(MONITORED_CATEGORIES)),
        "change_category_notification_percentage": coverage_percentage(
            len(notifying), len(MONITORED_CATEGORIES)
        ),
        "change_category_detail": coverage,
        # Notifications.
        "total_topics": len(topics),
        "topics_with_unreadable_subscriptions": len(topics) - len(read_topics),
        "topics_with_active_subscribers": sum(1 for t in read_topics if t["has_subscriber"]),
        "topics_with_only_pending_subscriptions": sum(
            1 for t in read_topics if not t["has_subscriber"] and t["pending_subscriptions"]
        ),
        "topics_with_no_subscriptions": sum(
            1 for t in read_topics if not t["subscriptions"]
        ),
        "notification_protocols_in_use": sorted({p for t in read_topics for p in t["protocols"]}),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool,
            skip_audit_retention: bool = False):
    import oci  # lazy

    tenancy = auth.get("tenancy")
    identity = make_client(oci.identity.IdentityClient, auth)
    audit_client = make_client(oci.audit.AuditClient, auth)
    logging_client = make_client(oci.logging.LoggingManagementClient, auth)
    events_client = make_client(oci.events.EventsClient, auth)
    topics_client = make_client(oci.ons.NotificationControlPlaneClient, auth)
    subscriptions_client = make_client(oci.ons.NotificationDataPlaneClient, auth)

    # Reading retention needs {AUDIT_CONFIGURATION}, and that permission also
    # allows UpdateConfiguration — tested live: the collector's update returned
    # 202, and scoping the grant to GetConfiguration denies the read too. A
    # deployment that keeps its collector strictly read-only opts out here; the
    # call is then recorded as skipped, not failed.
    if skip_audit_retention:
        collector.skip("audit.get_configuration", RuntimeError(
            "not collected: OCI_SKIP_AUDIT_RETENTION is set (the permission that reads "
            "retention also allows changing it)"))
        raw_audit = None
    else:
        raw_audit = collector.guard(
            "audit.get_configuration",
            lambda: audit_client.get_configuration(tenancy).data,
        )
    audit = audit_record(to_plain(raw_audit)) if raw_audit is not None else None

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=tenancy,
    )

    log_groups: list[dict] = []
    topics: list[dict] = []
    raw_rules: list[dict] = []

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        for group in collector.guard(
            f"logging.list_log_groups ({cname})",
            lambda c=cid: list_all(logging_client.list_log_groups, c),
            default=[],
        ) or []:
            plain = to_plain(group)
            entries = collector.guard(
                f"logging.list_logs ({plain.get('display_name')})",
                lambda g=plain["id"]: list_all(logging_client.list_logs, g),
                default=[],
            ) or []
            log_groups.append(log_group_record(plain, logs=[log_record(to_plain(e)) for e in entries]))

        for topic in collector.guard(
            f"ons.list_topics ({cname})",
            lambda c=cid: list_all(topics_client.list_topics, c),
            default=[],
        ) or []:
            plain = to_plain(topic)
            subscriptions = collector.guard(
                f"ons.list_subscriptions ({plain.get('name')})",
                lambda c=cid, t=plain["topic_id"]: list_all(
                    subscriptions_client.list_subscriptions, c, topic_id=t),
            )
            topics.append(topic_record(
                plain,
                subscriptions=[to_plain(s) for s in subscriptions] if subscriptions is not None else None,
            ))

        for rule in collector.guard(
            f"events.list_rules ({cname})",
            lambda c=cid: list_all(events_client.list_rules, c),
            default=[],
        ) or []:
            # Mandatory second call: RuleSummary carries no actions, and the
            # action chain is the point of this fetcher.
            detail = collector.guard(
                f"events.get_rule ({short_ocid(rule.id)})",
                lambda r=rule.id: events_client.get_rule(r).data,
            )
            raw_rules.append(to_plain(detail if detail is not None else rule))

    subscribed_topics = {t["topic_id"] for t in topics if t["has_subscriber"]}
    rules = [rule_record(r, topics_with_subscribers=subscribed_topics) for r in raw_rules]

    log_groups.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    rules.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    topics.sort(key=lambda r: (r.get("name") or "", r.get("topic_id") or ""))
    return audit, log_groups, rules, topics, len(compartments)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    include_sub = as_bool(os.environ.get("OCI_INCLUDE_SUBCOMPARTMENTS"), default=True)
    skip_retention = as_bool(os.environ.get("OCI_SKIP_AUDIT_RETENTION"), default=False)

    auth: dict = {}
    scope: dict = {"compartment_id": None, "compartment_source": "unresolved"}
    audit = None
    log_groups: list = []
    rules: list = []
    topics: list = []
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                audit, log_groups, rules, topics, scanned = collect(
                    auth, scope, collector, include_sub=include_sub,
                    skip_audit_retention=skip_retention)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("audit_logging_events.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "audit_configuration": audit,
            "log_groups": log_groups,
            "event_rules": rules,
            "notification_topics": topics,
        },
        summary=summarize(audit, log_groups, rules, topics,
                          audit_retention_skipped=skip_retention),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_audit_logging_events_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
