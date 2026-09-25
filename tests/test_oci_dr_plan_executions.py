"""Recovery-test judgements in `oci_dr_plan_executions`.

No tenancy has produced a real drill for this — Full Stack DR needs a second
region — so these pin the rules against Oracle's documented shapes: the
execution types, and `step_status_counts` as `DrPlanExecutionStepStatusCounts`
nests them.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "dr_plan_executions" / "fetcher.py"
NOW = datetime(2026, 9, 21, tzinfo=timezone.utc)


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_dr_plan_executions", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dr = _load()


def _execution(kind="START_DRILL", *, state="SUCCEEDED", plan="p1", days_ago=10, duration=600, counts=None):
    return {"id": f"ocid1.drplanexecution.oc1..{kind.lower()}{days_ago}", "plan_id": plan,
            "plan_execution_type": kind, "lifecycle_state": state,
            "time_ended": NOW - timedelta(days=days_ago), "execution_duration_in_sec": duration,
            "step_status_counts": counts or {"total_steps": 4, "successful_steps": {"total_successful": 4}}}


def _record(*args, **kwargs):
    return dr.execution_record(_execution(*args, **kwargs), now=NOW)


def _plan(pid, kind):
    return dr.plan_record({"id": pid, "type": kind, "lifecycle_state": "ACTIVE"})


def test_a_drill_is_one_test_not_two():
    """START_DRILL brings the standby up; STOP_DRILL tears it down. Counting both
    made one drill two tests."""
    start, stop = _record("START_DRILL", days_ago=10), _record("STOP_DRILL", days_ago=9, duration=90)
    assert start["is_recovery_test"] and not start["is_drill_cleanup"]
    assert stop["is_drill_cleanup"] and not stop["is_recovery_test"]
    out = dr.summarize([], [], [start, stop])
    assert out["recovery_tests_executed"] == 1
    assert out["recovery_tests_succeeded"] == 1
    assert out["drill_cleanups_executed"] == 1


def test_teardown_time_is_never_reported_as_recovery_time():
    """The later STOP_DRILL must not become the 'last successful test', or its
    teardown duration is the one an assessor reads against the RTO."""
    out = dr.summarize([], [], [_record("START_DRILL", days_ago=10, duration=600),
                                _record("STOP_DRILL", days_ago=9, duration=90)])
    assert out["last_successful_test_type"] == "START_DRILL"
    assert out["last_successful_test_duration_sec"] == 600
    assert out["longest_successful_test_duration_sec"] == 600


def test_a_stop_drill_plan_is_not_an_untested_drill_plan():
    plans = [_plan("p1", "START_DRILL"), _plan("p2", "STOP_DRILL")]
    out = dr.summarize([], plans, [_record("START_DRILL", plan="p1")])
    assert out["drill_plans"] == 1
    assert out["drill_plans_never_tested"] == 0
    assert out["drill_plan_test_coverage_percentage"] == 100


def test_prechecks_and_real_recoveries_are_never_tests():
    records = [_record("START_DRILL_PRECHECK"), _record("FAILOVER"), _record("SWITCHOVER_PRECHECK")]
    out = dr.summarize([], [], records)
    assert out["recovery_tests_executed"] == 0
    assert out["prechecks_executed"] == 2
    assert out["actual_recoveries_executed"] == 1


def test_a_passed_drill_that_ignored_failed_steps_is_named():
    counts = {"total_steps": 5, "successful_steps": {"total_successful": 3},
              "skipped_steps": {"total_skipped": 2, "failed_ignored": 1, "timed_out_ignored": 1}}
    record = _record(counts=counts)
    assert record["ignored_failure_steps"] == 2
    out = dr.summarize([], [], [record, _record(days_ago=20)])
    assert out["recovery_tests_succeeded"] == 2
    assert out["successful_tests_with_ignored_failures"] == 1


def test_an_in_flight_or_failed_drill_is_not_a_success():
    out = dr.summarize([], [], [_record(state="IN_PROGRESS"), _record(state="FAILED", days_ago=5)])
    assert out["recovery_tests_executed"] == 2
    assert out["recovery_tests_succeeded"] == 0
    assert out["recovery_tests_failed"] == 1
    assert out["tested_within_365_days"] is None


def test_currency_is_measured_from_the_last_successful_test():
    old = dr.summarize([], [], [_record(days_ago=400)])
    recent = dr.summarize([], [], [_record(days_ago=400), _record(days_ago=30)])
    assert old["tested_within_365_days"] is False
    assert recent["tested_within_365_days"] is True
    assert recent["days_since_last_successful_test"] == 30


def test_no_protection_groups_reads_as_nothing_tested_not_as_passing():
    out = dr.summarize([], [], [])
    assert out["recovery_tests_succeeded"] == 0
    assert out["tested_within_365_days"] is None
    assert out["last_successful_test"] is None
