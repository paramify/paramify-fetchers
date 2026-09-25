"""Condition parsing and the rule-to-subscriber join in `oci_audit_logging_events`."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "audit_logging_events" / "fetcher.py"
TOPIC = "ocid1.onstopic.oc1..t"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_audit_logging_events", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


al = _load()


def _rule(condition, *, actions=(("ONS", True, TOPIC),), enabled=True, name="r"):
    return {
        "id": f"ocid1.eventrule.oc1..{name}", "display_name": name, "lifecycle_state": "ACTIVE",
        "is_enabled": enabled, "condition": condition,
        "actions": {"actions": [
            {"action_type": kind, "is_enabled": on, "lifecycle_state": "ACTIVE",
             "topic_id": target if kind == "ONS" else None,
             "stream_id": target if kind == "OSS" else None}
            for kind, on, target in actions]},
    }


def _topic(*, active=0, pending=0):
    subs = [{"id": f"s{i}", "protocol": "EMAIL", "lifecycle_state": "ACTIVE"} for i in range(active)]
    subs += [{"id": f"p{i}", "protocol": "EMAIL", "lifecycle_state": "PENDING"} for i in range(pending)]
    return al.topic_record({"topic_id": TOPIC, "name": "t", "lifecycle_state": "ACTIVE"}, subscriptions=subs)


def test_wildcard_event_types_match_as_oracle_defines_them():
    """Oracle's own docs: com.oraclecloud.objectstorage.*bucket matches every bucket
    event. Prowler tests exact membership, so a wildcard rule reads as monitoring nothing."""
    assert al.event_type_matches("com.oraclecloud.identitycontrolplane.*",
                                 "com.oraclecloud.identitycontrolplane.createpolicy")
    assert al.event_type_matches("com.oraclecloud.objectstorage.*bucket",
                                 "com.oraclecloud.objectstorage.createbucket")
    assert not al.event_type_matches("com.oraclecloud.virtualnetwork.*",
                                     "com.oraclecloud.identitycontrolplane.createpolicy")
    assert not al.event_type_matches("com.oraclecloud.identitycontrolplane.createuser",
                                     "com.oraclecloud.identitycontrolplane.deleteuser")

    rule = al.rule_record(_rule(json.dumps({"eventType": ["com.oraclecloud.identitycontrolplane.*"]})),
                          topics_with_subscribers={TOPIC})
    assert "iam_policy_changes" in rule["monitored_categories"]
    assert "iam_user_changes" in rule["monitored_categories"]
    assert rule["uses_wildcard_event_type"] is True


def test_a_single_string_condition_is_parsed():
    """Also Oracle's own example; Prowler requires isinstance(event_types, list)."""
    rule = al.rule_record(_rule(json.dumps({"eventType": "com.oraclecloud.cloudguard.problemdetected"})),
                          topics_with_subscribers={TOPIC})
    assert rule["condition_parsed"] and rule["monitored_categories"] == ["cloud_guard_problems"]


def test_a_rule_notifying_a_topic_with_no_subscriber_notifies_nobody():
    """The live tenancy's exact shape: enabled rule, enabled ONS action, empty topic."""
    rule = al.rule_record(_rule(json.dumps({"eventType": ["com.oraclecloud.identitycontrolplane.createuser"]})),
                          topics_with_subscribers=set())
    assert rule["has_notification_action"] is True
    assert rule["notifying"] is False

    out = al.summarize(None, [], [rule], [_topic()])
    assert out["monitored_change_categories"] == ["iam_user_changes"]
    assert out["notifying_change_categories"] == []
    assert out["monitored_but_not_notifying"] == ["iam_user_changes"]
    assert out["active_rules_notifying_nobody"] == 1
    assert out["topics_with_no_subscriptions"] == 1


def test_a_confirmed_subscriber_completes_the_chain():
    rule = al.rule_record(_rule(json.dumps({"eventType": ["com.oraclecloud.identitycontrolplane.createuser"]})),
                          topics_with_subscribers={TOPIC})
    out = al.summarize(None, [], [rule], [_topic(active=1)])
    assert out["notifying_change_categories"] == ["iam_user_changes"]
    assert out["topics_with_active_subscribers"] == 1
    assert out["change_category_notification_percentage"] == 8


def test_a_pending_subscription_is_not_a_subscriber():
    topic = _topic(pending=2)
    assert topic["has_subscriber"] is False and topic["pending_subscriptions"] == 2
    out = al.summarize(None, [], [], [topic])
    assert out["topics_with_only_pending_subscriptions"] == 1
    assert out["topics_with_active_subscribers"] == 0


def test_disabled_actions_and_stream_actions_are_not_notification():
    disabled = al.rule_record(_rule(json.dumps({"eventType": ["com.oraclecloud.virtualnetwork.createvcn"]}),
                                    actions=(("ONS", False, TOPIC),)), topics_with_subscribers={TOPIC})
    stream = al.rule_record(_rule(json.dumps({"eventType": ["com.oraclecloud.virtualnetwork.createvcn"]}),
                                  actions=(("OSS", True, "ocid1.stream.oc1..s"),)),
                            topics_with_subscribers={TOPIC})
    assert disabled["has_notification_action"] is False and disabled["notifying"] is False
    assert stream["streams_or_functions_only"] is True and stream["notifying"] is False
    out = al.summarize(None, [], [disabled, stream], [_topic(active=1)])
    assert out["rules_delivering_only_to_streams_or_functions"] == 2
    assert out["monitored_but_not_notifying"] == ["vcn_changes"]


def test_a_disabled_rule_monitors_nothing():
    rule = al.rule_record(_rule(json.dumps({"eventType": ["com.oraclecloud.identitycontrolplane.createuser"]}),
                                enabled=False), topics_with_subscribers={TOPIC})
    out = al.summarize(None, [], [rule], [_topic(active=1)])
    assert out["active_rules"] == 0
    assert out["monitored_change_categories"] == []
    assert "iam_user_changes" in out["unmonitored_change_categories"]


def test_an_unparseable_condition_is_counted_not_guessed():
    rule = al.rule_record(_rule("not json at all"), topics_with_subscribers={TOPIC})
    assert rule["condition_parsed"] is False and rule["monitored_categories"] == []
    assert al.summarize(None, [], [rule], [])["rules_with_unparseable_condition"] == 1


def test_audit_retention_and_log_inventory():
    audit = al.audit_record({"retention_period_days": 90})
    assert audit["meets_365_day_retention"] is False
    assert al.audit_record({"retention_period_days": 365})["meets_365_day_retention"] is True

    log = al.log_record({"id": "l", "display_name": "flow", "is_enabled": True, "retention_duration": 30,
                         "configuration": {"source": {"service": "flowlogs", "category": "all"}}})
    group = al.log_group_record({"id": "g", "display_name": "g"}, logs=[log])
    out = al.summarize(audit, [group], [], [])
    assert out["audit_meets_365_day_retention"] is False
    assert out["logged_services"] == ["flowlogs"] and out["shortest_log_retention_days"] == 30
    assert out["enabled_logs"] == 1 and out["disabled_logs"] == 0
