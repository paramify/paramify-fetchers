#!/usr/bin/env python3
"""
OCI Operator Access Control and Delegate Access Control — Oracle staff access

Oracle's own operators cannot touch Exadata infrastructure governed by these
services until the customer approves, and every request, approval and session is
a record. This collects the controls, which resources they govern, and the
access requests Oracle staff have raised against them.

This is the evidence for KSI-IAM-JIT ("a least-privileged ... just-in-time
security authorization model ... for all user and non-user accounts and
services") applied to the one set of accounts a customer normally cannot see —
the cloud provider's — and for KSI-SCR-MIT, since the provider is the supplier
with the most access. No other cloud exposes this as an API.

Two services, one shape. Operator Access Control governs Exadata Cloud@Customer
and Exadata infrastructure; Delegate Access Control governs the VM clusters on
it. Each has a control (who approves, what is pre-approved), a binding of the
control to resources, and access requests with an approval outcome.

The findings are the ways the approval gate is turned off while still looking
present:

  * `is_fully_pre_approved` — every operator action is approved in advance, so
    the control records access but gates none of it.
  * pre-approved action lists — the same, for some actions only.
  * `is_auto_approve_during_maintenance` — approval is skipped in maintenance
    windows, which is when operators are most likely to be on the system.
  * an assignment that is not `is_enforced_always` governs the resource only
    inside its time window.
  * `is_auto_approved` on a request — the request that was actually let through
    without a human.

VERIFIED AGAINST SDK MODELS ONLY. These services govern Exadata resources, which
no trial tenancy can create, so every list call here has only ever returned an
empty collection from a live tenancy. The request shapes are live-verified —
including two traps below — but the record fields come from the SDK's generated
models (`tools/oci_schema_check.py`), not from a recorded response. Most
tenancies own none of these resource types; an empty result then means "no
Oracle-operated infrastructure to govern", which is reported as such and never
as a control in place.

Request traps, all measured against a live tenancy. Operator Access Control's
`num_days` is capped at 90, so its window is sent as `time_start` + `time_end`.
Delegate Access Control refuses those two together (400), and its time-filtered
list did not page consistently, so DAC is listed unfiltered and the window is
applied here. Every list result is also checked against the compartment queried:
anything naming another compartment is dropped and counted
(`records_outside_requested_compartment`), never reported as this tenancy's.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    age_in_days,
    as_bool,
    build_payload,
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

logger = logging.getLogger("oci_operator_access_control")

# How far back access requests are read. A year matches the annual review cycle
# the other OCI fetchers use, and is well inside what OAC accepts (measured).
REQUEST_WINDOW_DAYS = 365

DELETED = "DELETED"
# Assignment states in which the control is not actually in force.
ASSIGNMENT_FAILED_STATES = frozenset({"APPLYFAILED", "UPDATEFAILED", "DELETIONFAILED"})
# Access request outcome, read from the CURRENT state. Most states come after
# approval: Oracle documents EXPIRED as "access request approval time period has
# expired", and REVOKED and COMPLETED likewise end an approved request, so a
# year of history is mostly those. Counting only APPROVED would report nearly
# every granted request as not granted. OAC and DAC spell the same states
# differently (APPROVEDFORFUTURE / APPROVED_FOR_FUTURE). Every value either SDK
# enum declares is in exactly one set (pinned by a test); anything else is
# `unknown`, never guessed.
PENDING_STATES = frozenset({
    "CREATED", "APPROVALWAITING", "APPROVAL_WAITING", "MOREINFO", "INREVIEW",
    "OPERATOR_ASSIGNMENT_WAITING",
})
REJECTED_STATES = frozenset({"REJECTED"})
GRANTED_STATES = frozenset({
    "PREAPPROVED", "APPROVED", "APPROVEDFORFUTURE", "APPROVED_FOR_FUTURE",
    "DEPLOYED", "DEPLOYFAILED", "DEPLOY_FAILED", "UNDEPLOYED", "UNDEPLOYFAILED", "UNDEPLOY_FAILED",
    "EXTENDING", "EXTENDED", "EXTENSIONREJECTED", "EXTENSION_REJECTED", "EXTENSION_FAILED",
    "REVOKING", "REVOKED", "REVOKEFAILED", "REVOKE_FAILED",
    "EXPIRED", "EXPIRYFAILED", "EXPIRY_FAILED",
    "COMPLETING", "COMPLETED", "CLOSEFAILED", "CLOSE_FAILED",
})
NON_PROVIDER_REQUESTERS = frozenset({"CUSTOMER", "SYSTEM"})


# --- pure transforms ---

def request_outcome(state: str | None) -> str:
    """`granted`, `pending`, `rejected` or `unknown` for an access request state."""
    if state in GRANTED_STATES:
        return "granted"
    if state in PENDING_STATES:
        return "pending"
    if state in REJECTED_STATES:
        return "rejected"
    return "unknown"


def _count(values) -> int | None:
    """Length of a list field, or None when the field was not read at all."""
    return None if values is None else len(values)


def operator_control_record(summary: dict, detail: dict | None) -> dict:
    """One operator control. `detail` is the full GET; None when it failed.

    Approvers and pre-approved actions exist only on the full model, so without
    the detail those read None (unknown) rather than zero (none configured).
    """
    full = detail or {}
    pre_approved = full.get("pre_approved_op_action_list") if detail else None
    approvers = full.get("approvers_list") if detail else None
    approver_groups = full.get("approver_groups_list") if detail else None
    return {
        "id": summary.get("id"),
        "name": summary.get("operator_control_name"),
        "compartment_id": summary.get("compartment_id"),
        "resource_type": summary.get("resource_type"),
        "lifecycle_state": summary.get("lifecycle_state"),
        "detail_read": detail is not None,
        # The gate switched off entirely: every action is approved in advance.
        "is_fully_pre_approved": summary.get("is_fully_pre_approved"),
        "number_of_approvers": summary.get("number_of_approvers"),
        # Counts only: the lists hold user and group OCIDs, and the evidence
        # question is whether anyone approves, not who.
        "approver_count": _count(approvers),
        "approver_group_count": _count(approver_groups),
        "pre_approved_actions": sorted(pre_approved) if pre_approved else ([] if detail else None),
        "approval_required_actions": (
            sorted(full.get("approval_required_op_action_list") or []) if detail else None
        ),
        "is_default_operator_control": full.get("is_default_operator_control") if detail else None,
        "time_created": iso(summary.get("time_of_creation")),
        "time_modified": iso(summary.get("time_of_modification")),
    }


def assignment_record(summary: dict, detail: dict | None) -> dict:
    """One binding of an operator control to a resource."""
    full = detail or {}
    return {
        "id": summary.get("id"),
        "operator_control_id": summary.get("operator_control_id"),
        "operator_control_name": summary.get("op_control_name"),
        "resource_id": summary.get("resource_id"),
        "resource_name": summary.get("resource_name"),
        "resource_type": summary.get("resource_type"),
        "compartment_id": summary.get("compartment_id"),
        "lifecycle_state": summary.get("lifecycle_state"),
        "lifecycle_details": summary.get("lifecycle_details"),
        "detail_read": detail is not None,
        # False means the control governs the resource only between
        # time_assignment_from and time_assignment_to.
        "is_enforced_always": summary.get("is_enforced_always"),
        "time_assignment_from": iso(summary.get("time_assignment_from")),
        "time_assignment_to": iso(summary.get("time_assignment_to")),
        # Only on the full model; None when the detail read failed.
        "is_auto_approve_during_maintenance": (
            full.get("is_auto_approve_during_maintenance") if detail else None
        ),
        # Operator session logs forwarded to the customer's own syslog — the
        # record of what Oracle staff did, held somewhere Oracle does not run.
        "is_log_forwarded": summary.get("is_log_forwarded"),
        "is_hypervisor_log_forwarded": summary.get("is_hypervisor_log_forwarded"),
        "error_message": summary.get("error_message"),
        "time_of_assignment": iso(summary.get("time_of_assignment")),
    }


def access_request_record(request: dict, *, now=None) -> dict:
    """One Oracle operator's request to access an OAC-governed resource."""
    state = request.get("lifecycle_state")
    return {
        "service": "operator_access_control",
        "id": request.get("id"),
        "request_id": request.get("request_id"),
        "resource_id": request.get("resource_id"),
        "resource_name": request.get("resource_name"),
        "resource_type": request.get("resource_type"),
        "compartment_id": request.get("compartment_id"),
        "reason_summary": request.get("access_reason_summary"),
        "requested_actions": sorted(request.get("action_requests_list") or []),
        "severity": request.get("severity"),
        "state": state,
        "requester_type": "OPERATOR",
        # The lasting record of pre-approval: the state moves on to EXPIRED or
        # COMPLETED, this flag does not.
        "is_auto_approved": request.get("is_auto_approved"),
        "outcome": request_outcome(state),
        "duration_hours": request.get("duration"),
        "time_created": iso(request.get("time_of_creation")),
        "days_since_created": age_in_days(request.get("time_of_creation"), now=now),
    }


def delegation_control_record(summary: dict, detail: dict | None) -> dict:
    """One Delegate Access Control control. Approval settings are detail-only."""
    full = detail or {}
    pre_approved = full.get("pre_approved_service_provider_action_names") if detail else None
    return {
        "id": summary.get("id"),
        "name": summary.get("display_name"),
        "compartment_id": summary.get("compartment_id"),
        "resource_type": summary.get("resource_type"),
        "lifecycle_state": summary.get("lifecycle_state"),
        "detail_read": detail is not None,
        "num_approvals_required": full.get("num_approvals_required") if detail else None,
        "pre_approved_actions": sorted(pre_approved) if pre_approved else ([] if detail else None),
        "is_auto_approve_during_maintenance": (
            full.get("is_auto_approve_during_maintenance") if detail else None
        ),
        "governed_resource_count": _count(full.get("resource_ids")) if detail else None,
        "resource_ids": sorted(full.get("resource_ids") or []) if detail else None,
        "time_created": iso(summary.get("time_created")),
        "time_updated": iso(summary.get("time_updated")),
    }


def delegated_request_record(request: dict, *, now=None) -> dict:
    """One Delegate Access Control request."""
    status = request.get("request_status")
    return {
        "service": "delegate_access_control",
        "id": request.get("id"),
        "request_id": request.get("display_name"),
        "resource_id": request.get("resource_id"),
        "resource_name": request.get("resource_name"),
        "resource_type": request.get("resource_type"),
        "compartment_id": request.get("compartment_id"),
        "delegation_control_id": request.get("delegation_control_id"),
        "reason_summary": request.get("reason_for_request"),
        "requested_actions": sorted(request.get("requested_action_names") or []),
        "severity": request.get("severity"),
        "state": status,
        # OPERATOR is Oracle staff; CUSTOMER and SYSTEM are not provider access.
        "requester_type": request.get("requester_type"),
        "is_auto_approved": request.get("is_auto_approved"),
        "outcome": request_outcome(status),
        "duration_hours": request.get("duration_in_hours"),
        "time_created": iso(request.get("time_access_requested") or request.get("time_created")),
        "days_since_created": age_in_days(
            request.get("time_access_requested") or request.get("time_created"), now=now
        ),
    }


def _live(records: list[dict]) -> list[dict]:
    return [r for r in records if r.get("lifecycle_state") != DELETED]


def summarize(
    operator_controls: list[dict],
    assignments: list[dict],
    delegation_controls: list[dict],
    requests: list[dict],
    *,
    oac_readable: bool = True,
    dac_readable: bool = True,
    out_of_scope: int = 0,
) -> dict:
    """Aggregate the four lists into the answer an assessor reads first."""
    controls = _live(operator_controls)
    bindings = _live(assignments)
    delegations = _live(delegation_controls)
    # CUSTOMER and SYSTEM requests are not provider access. An absent
    # requester_type (optional in the model) counts as provider, never dropped.
    provider_requests = [r for r in requests if r["requester_type"] not in NON_PROVIDER_REQUESTERS]

    governed = {a["resource_id"] for a in bindings if a.get("resource_id")}
    for d in delegations:
        governed.update(d.get("resource_ids") or [])

    return {
        # False when the list call failed — not "no controls". Empty lists with
        # these True mean the tenancy has no Oracle-operated infrastructure here.
        "operator_access_control_readable": oac_readable,
        "delegate_access_control_readable": dac_readable,
        "governed_resources": len(governed),
        "total_operator_controls": len(controls),
        "operator_controls_fully_pre_approved": sum(1 for c in controls if c["is_fully_pre_approved"]),
        "operator_controls_with_pre_approved_actions": sum(1 for c in controls if c["pre_approved_actions"]),
        # Unknown, not zero: a failed detail read leaves the approval settings unread.
        "operator_controls_with_unread_detail": sum(1 for c in controls if not c["detail_read"]),
        "total_operator_control_assignments": len(bindings),
        "assignments_not_always_enforced": sum(1 for a in bindings if a["is_enforced_always"] is False),
        "assignments_auto_approving_during_maintenance": sum(
            1 for a in bindings if a["is_auto_approve_during_maintenance"]
        ),
        "assignments_not_forwarding_operator_logs": sum(1 for a in bindings if a["is_log_forwarded"] is False),
        "assignments_failed_to_apply": sum(
            1 for a in bindings if a["lifecycle_state"] in ASSIGNMENT_FAILED_STATES
        ),
        "assignments_with_unread_detail": sum(1 for a in bindings if not a["detail_read"]),
        "total_delegation_controls": len(delegations),
        "delegation_controls_with_pre_approved_actions": sum(
            1 for d in delegations if d["pre_approved_actions"]
        ),
        "delegation_controls_auto_approving_during_maintenance": sum(
            1 for d in delegations if d["is_auto_approve_during_maintenance"]
        ),
        "delegation_controls_with_unread_detail": sum(1 for d in delegations if not d["detail_read"]),
        "access_request_window_days": REQUEST_WINDOW_DAYS,
        "total_access_requests": len(requests),
        "provider_access_requests": len(provider_requests),
        # Granted includes every state after approval (EXPIRED, REVOKED,
        # COMPLETED…): the question is whether Oracle staff got in, not whether
        # they are in right now.
        "provider_requests_granted": sum(1 for r in provider_requests if r["outcome"] == "granted"),
        "provider_requests_pending": sum(1 for r in provider_requests if r["outcome"] == "pending"),
        "provider_requests_rejected": sum(1 for r in provider_requests if r["outcome"] == "rejected"),
        "provider_requests_in_unrecognized_state": sum(
            1 for r in provider_requests if r["outcome"] == "unknown"
        ),
        # Let through by pre-approval or maintenance auto-approval, no person.
        "provider_requests_auto_approved": sum(1 for r in provider_requests if r["is_auto_approved"]),
        "requests_by_state": dict(sorted(Counter(r["state"] or "unknown" for r in requests).items())),
        # Records the API returned that named a different compartment, dropped
        # rather than reported as this tenancy's. Non-zero is an API anomaly
        # worth raising with Oracle, not a finding about this tenancy.
        "records_outside_requested_compartment": out_of_scope,
        "requests_by_severity": dict(sorted(Counter(r["severity"] or "unknown" for r in requests).items())),
    }


# --- collection ---

def request_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    end = now or datetime.now(timezone.utc)
    return end - timedelta(days=REQUEST_WINDOW_DAYS), end


def in_scope(items: list[dict], compartment_id: str, seen: set) -> tuple[list[dict], int]:
    """Records that belong to the compartment queried, each id once.

    Returns (kept, dropped). A record naming a DIFFERENT compartment is dropped
    and counted — Delegate Access Control has been measured returning
    records outside the compartment a list was scoped to (see collect()).
    A record with no compartment_id is kept: it came from our query, and the
    field is optional on some of these models.
    """
    kept, dropped = [], 0
    for item in items:
        owner = item.get("compartment_id")
        if owner and owner != compartment_id:
            dropped += 1
            continue
        if item.get("id") in seen:
            continue
        seen.add(item.get("id"))
        kept.append(item)
    return kept, dropped


def within_window(record: dict) -> bool:
    """True when a request was created inside the window, or has no date.

    Reads the parsed day count, not the timestamp string: `iso()` passes a
    string through untouched, and a string compare breaks on another format.
    """
    days = record.get("days_since_created")
    return days is None or days <= REQUEST_WINDOW_DAYS


def _details(collector: Collector, operation: str, get_fn, ids: list) -> dict:
    """Full model per id; a failed read is recorded and leaves that id out."""
    found = {}
    for rid in ids:
        detail = collector.guard(f"{operation} ({short_ocid(rid)})", lambda r=rid: get_fn(r).data)
        if detail is not None:
            found[rid] = to_plain(detail)
    return found


def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool, now=None) -> dict:
    """Controls, assignments and requests from both services, per compartment.

    Each service's lists are None when that service could not be read in any
    compartment, distinct from the empty lists a tenancy with no Exadata has.
    """
    import oci  # lazy

    oac = oci.operator_access_control
    identity = make_client(oci.identity.IdentityClient, auth)
    controls_client = make_client(oac.OperatorControlClient, auth)
    assignments_client = make_client(oac.OperatorControlAssignmentClient, auth)
    requests_client = make_client(oac.AccessRequestsClient, auth)
    dac = make_client(oci.delegate_access_control.DelegateAccessControlClient, auth)

    compartments = walk_compartments(
        identity,
        scope["compartment_id"],
        collector,
        include_subcompartments=include_sub,
        tenancy=auth.get("tenancy"),
    )
    start, end = request_window(now)

    control_summaries, assignment_summaries, delegation_summaries = [], [], []
    requests: list[dict] = []
    oac_read = dac_read = 0
    seen: set = set()
    out_of_scope = 0

    def keep(found, cid):
        nonlocal out_of_scope
        kept, dropped = in_scope([to_plain(item) for item in found or []], cid, seen)
        out_of_scope += dropped
        return kept
    for comp in compartments:
        cid, label = comp["id"], comp["name"]

        oac_calls = (
            collector.guard(f"operator_access_control.list_operator_controls ({label})",
                            lambda c=cid: list_all(controls_client.list_operator_controls, c)),
            collector.guard(f"operator_access_control.list_operator_control_assignments ({label})",
                            lambda c=cid: list_all(assignments_client.list_operator_control_assignments, c)),
            # OAC takes start and end together; `num_days` is capped at 90.
            collector.guard(f"operator_access_control.list_access_requests ({label})",
                            lambda c=cid: list_all(requests_client.list_access_requests, c,
                                                   time_start=start, time_end=end)),
        )
        if all(result is not None for result in oac_calls):
            oac_read += 1
        found_controls, found_assignments, found_requests = oac_calls
        control_summaries.extend(keep(found_controls, cid))
        assignment_summaries.extend(keep(found_assignments, cid))
        requests.extend(access_request_record(r, now=now) for r in keep(found_requests, cid))

        dac_calls = (
            collector.guard(f"delegate_access_control.list_delegation_controls ({label})",
                            lambda c=cid: list_all(dac.list_delegation_controls, c)),
            # No time filter here, deliberately: filtered, this list paged
            # inconsistently (measured 2026-09-24). The window is applied below
            # instead, and in_scope() drops anything naming another compartment.
            collector.guard(f"delegate_access_control.list_delegated_resource_access_requests ({label})",
                            lambda c=cid: list_all(dac.list_delegated_resource_access_requests, c)),
        )
        if all(result is not None for result in dac_calls):
            dac_read += 1
        found_delegations, found_delegated = dac_calls
        delegation_summaries.extend(keep(found_delegations, cid))
        delegated = (delegated_request_record(r, now=now) for r in keep(found_delegated, cid))
        requests.extend(r for r in delegated if within_window(r))

    if out_of_scope:
        logger.warning("Dropped %d record(s) naming a compartment other than the one queried",
                       out_of_scope)

    control_details = _details(collector, "operator_access_control.get_operator_control",
                               controls_client.get_operator_control,
                               [c["id"] for c in control_summaries if c.get("lifecycle_state") != DELETED])
    assignment_details = _details(collector, "operator_access_control.get_operator_control_assignment",
                                  assignments_client.get_operator_control_assignment,
                                  [a["id"] for a in assignment_summaries if a.get("lifecycle_state") != DELETED])
    delegation_details = _details(collector, "delegate_access_control.get_delegation_control",
                                  dac.get_delegation_control,
                                  [d["id"] for d in delegation_summaries if d.get("lifecycle_state") != DELETED])

    def by_name(records):
        return sorted(records, key=lambda r: (r.get("name") or r.get("resource_name") or "", r.get("id") or ""))

    return {
        "operator_controls": by_name(
            operator_control_record(c, control_details.get(c["id"])) for c in control_summaries
        ),
        "operator_control_assignments": by_name(
            assignment_record(a, assignment_details.get(a["id"])) for a in assignment_summaries
        ),
        "delegation_controls": by_name(
            delegation_control_record(d, delegation_details.get(d["id"])) for d in delegation_summaries
        ),
        # Newest first: the most recent provider access is the one looked for.
        "access_requests": sorted(requests, key=lambda r: (r["time_created"] or "", r["id"] or ""), reverse=True),
        "oac_readable": bool(compartments) and oac_read > 0,
        "dac_readable": bool(compartments) and dac_read > 0,
        "records_outside_requested_compartment": out_of_scope,
        "compartments_scanned": len(compartments),
    }


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
    collected: dict = {}

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            # Guarded as a whole: building a client parses the signing key, so a
            # malformed OCI_PRIVATE_KEY raises here rather than inside a guard.
            try:
                collected = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
                collector.record("operator_access_control.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    controls = collected.get("operator_controls", [])
    assignments = collected.get("operator_control_assignments", [])
    delegations = collected.get("delegation_controls", [])
    requests = collected.get("access_requests", [])

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "operator_controls": controls,
            "operator_control_assignments": assignments,
            "delegation_controls": delegations,
            "access_requests": requests,
        },
        summary=summarize(
            controls, assignments, delegations, requests,
            oac_readable=collected.get("oac_readable", False),
            dac_readable=collected.get("dac_readable", False),
            out_of_scope=collected.get("records_outside_requested_compartment", 0),
        ),
        compartments_scanned=collected.get("compartments_scanned"),
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_operator_access_control_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)

    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
