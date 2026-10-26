"""The judgments `oci_cloud_guard_posture` makes, each of which fails silently.

Inputs are shaped by `oci.util.to_dict()` on the real models, so the field names
are the ones `tools/oci_schema_check.py` already verifies. What these pin is the
reading: a recipe is not a rule, a responder is not an enforcer, and a disabled
service is evidence rather than a failure.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "cloud_guard_posture" / "fetcher.py"
TENANCY = "ocid1.tenancy.oc1..root"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_cloud_guard_posture", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cg = _load()


def _detector_rule(enabled, detector="IAAS_CONFIGURATION_DETECTOR", risk="HIGH"):
    return {"detector_rule_id": "r", "detector": detector, "details": {"is_enabled": enabled, "risk_level": risk}}


def _responder_rule(enabled, mode, rule_type="REMEDIATION"):
    return {"responder_rule_id": "r", "type": rule_type, "details": {"is_enabled": enabled, "mode": mode}}


def _target(detector_rules, responder_rules=(), resource_id=TENANCY):
    return {
        "id": "ocid1.cloudguardtarget.oc1..t",
        "display_name": "root",
        "compartment_id": TENANCY,
        "target_resource_type": "COMPARTMENT",
        "target_resource_id": resource_id,
        "lifecyle_details": "ok",
        "target_detector_recipes": [
            {"detector": "IAAS_CONFIGURATION_DETECTOR", "effective_detector_rules": list(detector_rules)}
        ],
        "target_responder_recipes": [{"effective_responder_rules": list(responder_rules)}],
    }


def test_an_attached_recipe_with_every_rule_disabled_assesses_nothing():
    record = cg.target_record(_target([_detector_rule(False), _detector_rule(False)]))
    assert record["detail_read"] is True
    assert record["enabled_detector_rules"] == 0
    assert record["assesses_configuration"] is False


def test_useraction_responders_do_not_count_as_enforcement():
    record = cg.target_record(_target(
        [_detector_rule(True)],
        [_responder_rule(True, "USERACTION"), _responder_rule(False, "AUTOACTION")],
    ))
    assert record["auto_remediating_rules"] == 0

    record = cg.target_record(_target([_detector_rule(True)], [_responder_rule(True, "AUTOACTION")]))
    assert record["auto_remediating_rules"] == 1


def test_target_lifecycle_details_is_read_from_oracles_misspelling():
    assert cg.target_record(_target([]))["lifecycle_details"] == "ok"


def test_a_summary_standing_in_for_a_failed_detail_is_not_read_as_unmonitored():
    summary = {k: v for k, v in _target([]).items() if not k.startswith("target_detector")}
    del summary["target_responder_recipes"]
    record = cg.target_record(summary)
    assert record["detail_read"] is False

    out = cg.summarize(cg.configuration_record({"status": "ENABLED"}), [record], [], [], tenancy_id=TENANCY)
    assert out["targets_with_unreadable_detail"] == 1
    assert out["targets_with_no_enabled_detector_rules"] == 0
    assert out["tenancy_root_is_target"] is False


def test_disabled_is_a_complete_answer_and_an_unread_configuration_is_unknown():
    disabled = cg.summarize(cg.configuration_record({"status": "DISABLED"}), [], [], [])
    assert disabled["cloud_guard_enabled"] is False

    unknown = cg.summarize(None, [], [], [])
    assert unknown["cloud_guard_enabled"] is None
    assert unknown["cloud_guard_status"] is None


def test_root_target_is_recognised_only_on_the_tenancy_itself():
    root = cg.target_record(_target([_detector_rule(True)]))
    child = cg.target_record(_target([_detector_rule(True)], resource_id="ocid1.compartment.oc1..child"))
    assert cg.summarize(cg.configuration_record({"status": "ENABLED"}), [root], [], [], tenancy_id=TENANCY)[
        "tenancy_root_is_target"
    ] is True
    assert cg.summarize(cg.configuration_record({"status": "ENABLED"}), [child], [], [], tenancy_id=TENANCY)[
        "tenancy_root_is_target"
    ] is False


def test_open_problems_are_bucketed_by_risk_and_age():
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 9, 15, tzinfo=timezone.utc)
    old = {"risk_level": "CRITICAL", "lifecycle_detail": "OPEN", "time_first_detected": now - timedelta(days=45)}
    new = {"risk_level": "LOW", "lifecycle_detail": "OPEN", "time_first_detected": now - timedelta(days=2)}
    problems = [cg.problem_record(p, now=now) for p in (old, new)]

    out = cg.summarize(cg.configuration_record({"status": "ENABLED"}), [], [], problems)
    assert out["open_problems"] == 2
    assert out["open_problems_by_risk"]["CRITICAL"] == 1
    assert out["open_problems_older_than_30_days"] == 1
    assert out["oldest_open_problem_days"] == 45


def test_a_zone_whose_recipe_was_unreadable_is_not_reported_as_enforcing_nothing():
    zone = {"id": "z", "display_name": "prod", "lifecycle_state": "ACTIVE"}
    assert cg.security_zone_record(zone)["enforced_policy_count"] is None
    assert cg.security_zone_record(zone, recipe={"security_policies": ["p1", "p2"]})["enforced_policy_count"] == 2


def test_an_autoaction_notification_is_not_remediation():
    """Oracle's managed responder recipe, as read from a live tenancy: EVENT in
    AUTOACTION, every REMEDIATION rule in USERACTION. That enforces nothing."""
    oracle_default = [_responder_rule(True, "AUTOACTION", "EVENT")] + [
        _responder_rule(True, "USERACTION") for _ in range(9)
    ]
    record = cg.target_record(_target([_detector_rule(True)], oracle_default))
    assert record["auto_remediating_rules"] == 0
