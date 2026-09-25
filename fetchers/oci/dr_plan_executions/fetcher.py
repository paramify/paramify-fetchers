#!/usr/bin/env python3
"""
OCI Full Stack Disaster Recovery — plans and their recorded executions

Every DR protection group in scope, the recovery plans defined against it, and
the executions of those plans: what type of recovery was run, whether it
succeeded, when, and how long it actually took.

This is the evidence for KSI-RPL-TRC, "the capability to recover from incidents
and contingencies aligned with defined recovery objectives is persistently
tested" — an indicator no other fetcher in the repo covers, because AWS, Azure
and GCP have no equivalent API. Elastic Disaster Recovery, Azure Site Recovery
and GCP have backup and replication state; only OCI records the *drill* as a
first-class resource with an outcome and a measured duration.

Two distinctions carry the whole evidence set:

  * A DRILL is a test; a FAILOVER is an incident. `START_DRILL` / `STOP_DRILL`
    stand up the standby in an isolated environment and tear it down again, so a
    completed drill proves the capability was exercised without proving anything
    went wrong. A FAILOVER proves recovery happened, but under duress — it is
    not a test. Both are reported, counted separately, and never summed.
    Within a drill only the START_DRILL is the test: the STOP_DRILL is its
    cleanup, counted as `drill_cleanups_executed`, and its teardown time is
    never reported as a recovery time.

  * A PRECHECK is not an execution. Every plan type has a `*_PRECHECK` variant
    that validates the plan without moving anything. Prechecks are real evidence
    of persistent review, but a tenancy whose only records are prechecks has
    never actually tested recovery, so they are counted apart from the
    executions that did.

`execution_duration_in_sec` is the measured wall-clock recovery time. That is
the number an assessor compares against a documented RTO, so it is surfaced per
execution and as a max/latest in the summary rather than left in the record.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    age_in_days,
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
    service_not_subscribed,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_dr_plan_executions")

# A drill exercises recovery without an incident; a failover/switchover IS the
# recovery. Only the first kind is a test, and the KSI asks about testing.
DRILL_TYPES = frozenset({"START_DRILL", "STOP_DRILL"})
RECOVERY_TYPES = frozenset({"SWITCHOVER", "FAILOVER"})

# Of the two drill types, only START_DRILL tests recovery. Oracle's own step
# types say so: START_DRILL runs *_RESTORE_STANDBY, *_CREATE_CLONE_STANDBY and
# *_SCALE_UP_STANDBY; STOP_DRILL runs *_CLEANUP_STANDBY, *_DELETE_CLONE_STANDBY
# and *_SCALE_DOWN_STANDBY. Counting both made every drill two tests, and put
# the teardown's duration among the measured recovery times.
TEST_TYPE = "START_DRILL"
CLEANUP_TYPE = "STOP_DRILL"

# Terminal states. Anything else (ACCEPTED, IN_PROGRESS, WAITING, PAUSED…) is an
# execution still in flight, which is neither a pass nor a fail and must not be
# counted as either.
SUCCEEDED = "SUCCEEDED"
FAILED = "FAILED"
TERMINAL_STATES = frozenset({SUCCEEDED, FAILED, "CANCELED"})

# How recent a test has to be to count as current. FedRAMP expects contingency
# plan testing at least annually; 365 days is that line, and it is a fixed,
# documented constant rather than a config knob so the evidence means the same
# thing in every tenancy.
TEST_CURRENCY_DAYS = 365


# --- pure transforms ---

def is_precheck(execution_type: str | None) -> bool:
    """True for a `*_PRECHECK` execution — a plan validation, not a recovery."""
    return str(execution_type or "").upper().endswith("_PRECHECK")


def base_type(execution_type: str | None) -> str | None:
    """The execution type with any `_PRECHECK` suffix removed."""
    text = str(execution_type or "").upper()
    if not text:
        return None
    return text[: -len("_PRECHECK")] if text.endswith("_PRECHECK") else text


def classify(execution_type: str | None) -> str:
    """`drill`, `recovery`, or `unknown` — the two kinds that must never be summed.

    Reads the base type, so `START_DRILL_PRECHECK` classifies as a drill and is
    separated from real drills by `is_precheck` instead.
    """
    root = base_type(execution_type)
    if root in DRILL_TYPES:
        return "drill"
    if root in RECOVERY_TYPES:
        return "recovery"
    return "unknown"


def step_counts(counts: dict) -> dict:
    """Flatten `step_status_counts` into the five totals plus their breakdowns.

    The API nests these one level deeper than the obvious spelling: the model is
    `total_steps` alongside five sub-objects, each carrying its own `total_*`
    plus a per-reason split. Verified against the generated models —
    `DrPlanExecutionStepStatusCounts` and its five children — after an earlier
    revision of this function invented flat `succeeded`/`failed`/`ignored` keys
    that do not exist and would have silently read None for every execution.
    """
    remaining = counts.get("remaining_steps") or {}
    skipped = counts.get("skipped_steps") or {}
    successful = counts.get("successful_steps") or {}
    warning = counts.get("warning_steps") or {}
    failed = counts.get("failed_steps") or {}

    return {
        "total": counts.get("total_steps"),
        "successful": successful.get("total_successful"),
        "failed": failed.get("total_failed"),
        "failed_outright": failed.get("failed"),
        "timed_out": failed.get("timed_out"),
        "warnings": warning.get("total_warnings"),
        "warnings_ignored": warning.get("warnings_ignored"),
        "skipped": skipped.get("total_skipped"),
        "skipped_disabled": skipped.get("disabled"),
        "skipped_failed_ignored": skipped.get("failed_ignored"),
        "skipped_timed_out_ignored": skipped.get("timed_out_ignored"),
        "skipped_canceled": skipped.get("canceled"),
        "remaining": remaining.get("total_remaining"),
        "queued": remaining.get("queued"),
        "paused": remaining.get("paused"),
        "in_progress": remaining.get("in_progress"),
    }


def ignored_failures(counts: dict) -> int:
    """Steps that failed, timed out or warned but were ignored by the plan.

    Non-zero here on a SUCCEEDED drill is the finding: the execution passed
    because the plan was configured to tolerate those steps, not because they
    worked. Missing sub-counts read as zero — an older API version omitting a
    field must not make this None and disappear from the summary arithmetic.
    """
    skipped = counts.get("skipped_steps") or {}
    warning = counts.get("warning_steps") or {}
    return sum(
        int(value or 0)
        for value in (
            skipped.get("failed_ignored"),
            skipped.get("timed_out_ignored"),
            warning.get("warnings_ignored"),
        )
    )


def execution_record(execution: dict, *, now=None) -> dict:
    """Normalize one DR plan execution into an evidence record."""
    execution_type = execution.get("plan_execution_type")
    state = execution.get("lifecycle_state")
    ended = execution.get("time_ended")
    counts = execution.get("step_status_counts") or {}

    return {
        "id": execution.get("id"),
        "display_name": execution.get("display_name"),
        "compartment_id": execution.get("compartment_id"),
        "plan_id": execution.get("plan_id"),
        "dr_protection_group_id": execution.get("dr_protection_group_id"),
        "peer_dr_protection_group_id": execution.get("peer_dr_protection_group_id"),
        "peer_region": execution.get("peer_region"),
        "execution_type": execution_type,
        "execution_kind": classify(execution_type),
        "is_precheck": is_precheck(execution_type),
        # A START_DRILL is the test this KSI asks for; its STOP_DRILL is cleanup.
        "is_recovery_test": base_type(execution_type) == TEST_TYPE and not is_precheck(execution_type),
        "is_drill_cleanup": base_type(execution_type) == CLEANUP_TYPE and not is_precheck(execution_type),
        "lifecycle_state": state,
        "lifecycle_details": execution.get("life_cycle_details"),
        "succeeded": state == SUCCEEDED,
        "is_terminal": state in TERMINAL_STATES,
        # Scheduled rather than hand-run — automation is what "persistently" asks for.
        "is_automatic": bool(execution.get("is_automatic")),
        "time_created": iso(execution.get("time_created")),
        "time_started": iso(execution.get("time_started")),
        "time_ended": iso(ended),
        # The measured recovery time an assessor reads against a documented RTO.
        "execution_duration_in_sec": execution.get("execution_duration_in_sec"),
        "days_since_execution": age_in_days(ended, now=now),
        "step_counts": step_counts(counts),
        # A SUCCEEDED execution can still contain steps that failed or timed out
        # and were ignored by the plan's own error handling. Counting those is
        # the difference between "the drill passed" and "the drill exercised
        # what it claims to have exercised".
        "ignored_failure_steps": ignored_failures(counts),
        # Full step-by-step output lands in Object Storage, not in the API
        # response. The pointer is the evidence trail to it.
        "log_location": (execution.get("log_location") or {}).get("bucket"),
    }


def plan_record(plan: dict) -> dict:
    """Normalize one DR plan."""
    return {
        "id": plan.get("id"),
        "display_name": plan.get("display_name"),
        "compartment_id": plan.get("compartment_id"),
        "type": plan.get("type"),
        "plan_kind": classify(plan.get("type")),
        "dr_protection_group_id": plan.get("dr_protection_group_id"),
        "peer_dr_protection_group_id": plan.get("peer_dr_protection_group_id"),
        "peer_region": plan.get("peer_region"),
        "lifecycle_state": plan.get("lifecycle_state"),
        "lifecycle_sub_state": plan.get("lifecycle_sub_state"),
        "time_created": iso(plan.get("time_created")),
        "time_updated": iso(plan.get("time_updated")),
    }


def protection_group_record(group: dict, *, now=None) -> dict:
    """Normalize one DR protection group."""
    return {
        "id": group.get("id"),
        "display_name": group.get("display_name"),
        "compartment_id": group.get("compartment_id"),
        # PRIMARY runs the workload; STANDBY is the recovery target. A tenancy
        # with no STANDBY group has nowhere to recover to.
        "role": group.get("role"),
        "peer_id": group.get("peer_id"),
        "peer_region": group.get("peer_region"),
        "lifecycle_state": group.get("lifecycle_state"),
        "lifecycle_sub_state": group.get("lifecycle_sub_state"),
        "lifecycle_details": group.get("life_cycle_details"),
        "time_created": iso(group.get("time_created")),
        "time_updated": iso(group.get("time_updated")),
        "days_since_update": age_in_days(group.get("time_updated"), now=now),
    }


def _latest(records: list[dict]) -> dict | None:
    """The record with the most recent `time_ended`, or None."""
    dated = [r for r in records if r.get("time_ended")]
    return max(dated, key=lambda r: r["time_ended"]) if dated else None


def summarize(
    groups: list[dict],
    plans: list[dict],
    executions: list[dict],
    *,
    api_readable: bool = True,
) -> dict:
    """Aggregate the three lists into the answer an assessor reads first."""
    tests = [e for e in executions if e["is_recovery_test"]]
    successful_tests = [e for e in tests if e["succeeded"]]
    prechecks = [e for e in executions if e["is_precheck"]]
    recoveries = [e for e in executions if e["execution_kind"] == "recovery" and not e["is_precheck"]]

    latest_test = _latest(successful_tests)
    days_since = latest_test["days_since_execution"] if latest_test else None

    durations = [
        e["execution_duration_in_sec"]
        for e in successful_tests
        if isinstance(e.get("execution_duration_in_sec"), int)
    ]

    # A plan is "tested" when a drill against it succeeded. Coverage over plans,
    # not over executions: ten drills of one plan leave the other nine untested.
    # STOP_DRILL plans are left out of the denominator — they can never run a test.
    tested_plan_ids = {e["plan_id"] for e in successful_tests if e.get("plan_id")}
    drill_plans = [p for p in plans if base_type(p["type"]) == TEST_TYPE]

    return {
        # False when Full Stack DR is not subscribed in this tenancy (recorded in
        # metadata.skipped_calls) or the list call failed — not "no DR plans".
        "dr_service_readable": api_readable,
        "total_protection_groups": len(groups),
        "primary_protection_groups": sum(1 for g in groups if g["role"] == "PRIMARY"),
        "standby_protection_groups": sum(1 for g in groups if g["role"] == "STANDBY"),
        "protection_groups_with_peer": sum(1 for g in groups if g["peer_id"]),
        "peer_regions": sorted({g["peer_region"] for g in groups if g["peer_region"]}),
        "total_plans": len(plans),
        "drill_plans": len(drill_plans),
        "failover_plans": sum(1 for p in plans if base_type(p["type"]) == "FAILOVER"),
        "switchover_plans": sum(1 for p in plans if base_type(p["type"]) == "SWITCHOVER"),
        "total_executions": len(executions),
        # The four numbers the indicator turns on.
        "recovery_tests_executed": len(tests),
        "recovery_tests_succeeded": len(successful_tests),
        "recovery_tests_failed": sum(1 for e in tests if e["lifecycle_state"] == FAILED),
        # A drill that reports SUCCEEDED while ignoring failed or timed-out steps
        # tested less than its state claims. Surfaced because an assessor reading
        # only `recovery_tests_succeeded` would never see it.
        "successful_tests_with_ignored_failures": sum(
            1 for e in successful_tests if e["ignored_failure_steps"]
        ),
        "prechecks_executed": len(prechecks),
        "drill_cleanups_executed": sum(1 for e in executions if e["is_drill_cleanup"]),
        # Real recoveries, reported separately and never counted as tests.
        "actual_recoveries_executed": len(recoveries),
        "automatic_executions": sum(1 for e in executions if e["is_automatic"]),
        "plans_with_a_successful_test": len(tested_plan_ids),
        "drill_plans_never_tested": sum(
            1 for p in drill_plans if p["id"] not in tested_plan_ids
        ),
        "drill_plan_test_coverage_percentage": coverage_percentage(
            sum(1 for p in drill_plans if p["id"] in tested_plan_ids), len(drill_plans)
        ),
        "last_successful_test": latest_test["time_ended"] if latest_test else None,
        "last_successful_test_type": latest_test["execution_type"] if latest_test else None,
        "days_since_last_successful_test": days_since,
        # None when nothing has ever been tested — deliberately not False, which
        # would read as "tested, and out of date".
        "tested_within_365_days": (days_since <= TEST_CURRENCY_DAYS) if days_since is not None else None,
        # Measured recovery times, for comparison against a documented RTO.
        "longest_successful_test_duration_sec": max(durations) if durations else None,
        "last_successful_test_duration_sec": (
            latest_test["execution_duration_in_sec"] if latest_test else None
        ),
        "protection_groups_by_name": sorted(
            f"{g['display_name']} ({short_ocid(g['id'])})" for g in groups if g["display_name"]
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool) -> tuple:
    """Groups, plans and executions across every compartment in scope.

    Returns (groups, plans, executions, compartments_scanned), with the three
    lists None when Full Stack DR could not be read at all — distinct from the
    empty lists a tenancy that simply has no DR configured produces.
    """
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    dr = make_client(oci.disaster_recovery.DisasterRecoveryClient, auth)

    compartments = walk_compartments(
        identity,
        scope["compartment_id"],
        collector,
        include_subcompartments=include_sub,
        # Lets the walk choose the subtree listing, which OCI accepts only when
        # the root IS the tenancy.
        tenancy=auth.get("tenancy"),
    )

    groups: list[dict] = []
    unreadable = 0
    for comp in compartments:
        def _list_groups(cid=comp["id"]):
            return list_all(dr.list_dr_protection_groups, cid)

        found = collector.guard(
            f"disaster_recovery.list_dr_protection_groups ({comp['name']})",
            _list_groups,
            tolerate=service_not_subscribed,
        )
        if found is None:
            unreadable += 1
            continue
        groups.extend(protection_group_record(to_plain(g)) for g in found)

    # Every compartment refused the call — the service is off, not empty.
    if compartments and unreadable == len(compartments):
        return None, None, None, len(compartments)

    plans: list[dict] = []
    executions: list[dict] = []
    for group in groups:
        gid = group["id"]

        def _list_plans(g=gid):
            return list_all(dr.list_dr_plans, g)

        def _list_execs(g=gid):
            return list_all(dr.list_dr_plan_executions, g)

        for plan in collector.guard(
            f"disaster_recovery.list_dr_plans ({short_ocid(gid)})", _list_plans, default=[]
        ) or []:
            plans.append(plan_record(to_plain(plan)))

        for execution in collector.guard(
            f"disaster_recovery.list_dr_plan_executions ({short_ocid(gid)})",
            _list_execs,
            default=[],
        ) or []:
            executions.append(execution_record(to_plain(execution)))

    groups.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    plans.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    # Newest execution first: the most recent test is the one being looked for.
    executions.sort(key=lambda r: (r.get("time_created") or "", r.get("id") or ""), reverse=True)
    return groups, plans, executions, len(compartments)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    include_sub = as_bool(os.environ.get("OCI_INCLUDE_SUBCOMPARTMENTS"), default=True)

    auth: dict = {}
    scope: dict = {"compartment_id": None, "compartment_source": "unresolved"}
    groups = plans = executions = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            # Guarded as a whole, not just per API call: building a client parses
            # the signing key, so a malformed OCI_PRIVATE_KEY raises here rather
            # than inside any collector.guard() below. Unguarded, that traceback
            # exits non-zero with no evidence file and no status file, and the
            # runner falls back to the tail of stderr for its reason.
            try:
                groups, plans, executions, scanned = collect(
                    auth, scope, collector, include_sub=include_sub
                )
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
                collector.record("disaster_recovery.collect", exc)
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
            "dr_protection_groups": groups or [],
            "dr_plans": plans or [],
            "dr_plan_executions": executions or [],
        },
        summary=summarize(
            groups or [], plans or [], executions or [], api_readable=groups is not None
        ),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_dr_plan_executions_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)

    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
