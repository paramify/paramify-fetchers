"""Approval-gate judgements and request scoping in `oci_operator_access_control`.

No trial tenancy can own the Exadata resources these services govern, so the
records here follow the SDK's generated models (checked by
tools/oci_schema_check.py). The request-side rules are from a live tenancy: the
OAC time window, and the Delegate Access Control list that paged inconsistently
when given `time_start`.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "operator_access_control" / "fetcher.py"
NOW = datetime(2026, 9, 24, tzinfo=timezone.utc)
OURS = "ocid1.compartment.oc1..ours"
THEIRS = "ocid1.compartment.oc1..elsewhere"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_operator_access_control", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oac = _load()


def _control(cid="c1", *, fully=False, pre=None, detail=True, state="ASSIGNED"):
    summary = {"id": cid, "operator_control_name": cid, "compartment_id": OURS,
               "is_fully_pre_approved": fully, "lifecycle_state": state, "number_of_approvers": 1}
    full = {"approvers_list": ["u1"], "approver_groups_list": [], "pre_approved_op_action_list": pre or [],
            "approval_required_op_action_list": ["OP_FULL"]}
    return oac.operator_control_record(summary, full if detail else None)


def _assignment(aid="a1", *, always=True, maintenance=False, forwarded=True, state="APPLIED", detail=True):
    summary = {"id": aid, "operator_control_id": "c1", "resource_id": f"r-{aid}", "compartment_id": OURS,
               "is_enforced_always": always, "is_log_forwarded": forwarded, "lifecycle_state": state}
    return oac.assignment_record(summary, {"is_auto_approve_during_maintenance": maintenance} if detail else None)


def _request(rid="q1", *, state="APPROVED", auto=False):
    return oac.access_request_record(
        {"id": rid, "resource_id": "r1", "compartment_id": OURS, "lifecycle_state": state,
         "is_auto_approved": auto, "severity": "S2", "time_of_creation": NOW - timedelta(days=3)}, now=NOW)


def _delegated(rid="d1", *, status="APPROVED", requester="OPERATOR", auto=False):
    record = {"id": rid, "resource_id": "r1", "compartment_id": OURS, "delegation_control_id": "dc1",
              "request_status": status, "is_auto_approved": auto,
              "time_access_requested": NOW - timedelta(days=3)}
    if requester is not None:
        record["requester_type"] = requester
    return oac.delegated_request_record(record, now=NOW)


def test_a_fully_pre_approved_control_is_named():
    """The gate exists but approves everything in advance."""
    out = oac.summarize([_control(fully=True), _control("c2")], [], [], [])
    assert out["total_operator_controls"] == 2
    assert out["operator_controls_fully_pre_approved"] == 1


def test_partial_pre_approval_is_counted_apart_from_full():
    out = oac.summarize([_control(pre=["OP_READ"]), _control("c2")], [], [], [])
    assert out["operator_controls_with_pre_approved_actions"] == 1
    assert out["operator_controls_fully_pre_approved"] == 0


def test_an_unread_detail_is_unknown_not_none_configured():
    """Approval settings exist only on the full model. A failed GET must not read
    as 'no pre-approved actions'."""
    unread = _control(detail=False)
    assert unread["pre_approved_actions"] is None
    assert unread["approver_count"] is None
    out = oac.summarize([unread], [], [], [])
    assert out["operator_controls_with_unread_detail"] == 1
    assert out["operator_controls_with_pre_approved_actions"] == 0


def test_deleted_controls_and_assignments_are_not_posture():
    out = oac.summarize([_control(fully=True, state="DELETED")],
                        [_assignment(always=False, state="DELETED")], [], [])
    assert out["total_operator_controls"] == 0
    assert out["operator_controls_fully_pre_approved"] == 0
    assert out["assignments_not_always_enforced"] == 0


def test_assignment_findings():
    out = oac.summarize([], [
        _assignment("a1", always=False),
        _assignment("a2", maintenance=True),
        _assignment("a3", forwarded=False),
        _assignment("a4", state="APPLYFAILED"),
    ], [], [])
    assert out["assignments_not_always_enforced"] == 1
    assert out["assignments_auto_approving_during_maintenance"] == 1
    assert out["assignments_not_forwarding_operator_logs"] == 1
    assert out["assignments_failed_to_apply"] == 1
    assert out["governed_resources"] == 4


def test_an_absent_log_forwarding_flag_is_not_a_finding():
    """is_log_forwarded is optional on the model: absent is unknown, not off."""
    record = _assignment(forwarded=None)
    assert oac.summarize([], [record], [], [])["assignments_not_forwarding_operator_logs"] == 0


def test_maintenance_auto_approval_is_unknown_without_the_detail():
    record = _assignment(detail=False)
    assert record["is_auto_approve_during_maintenance"] is None
    assert oac.summarize([], [record], [], [])["assignments_with_unread_detail"] == 1


def test_request_outcomes_across_both_services():
    requests = [
        _request("q1", auto=True),
        _request("q2", state="PREAPPROVED"),
        _request("q3", state="REJECTED"),
        _request("q4", state="APPROVALWAITING"),
        _delegated("d1", status="APPROVED_FOR_FUTURE"),
        _delegated("d2", status="EXTENSION_REJECTED"),
    ]
    out = oac.summarize([], [], [], requests)
    assert out["provider_access_requests"] == 6
    assert out["provider_requests_auto_approved"] == 1
    assert out["provider_requests_granted"] == 4
    assert out["provider_requests_pending"] == 1
    assert out["provider_requests_rejected"] == 1


def test_a_request_that_expired_or_was_revoked_was_still_granted():
    """Oracle: EXPIRED is "access request approval time period has expired".
    A year of history is mostly EXPIRED/REVOKED/COMPLETED; reading only APPROVED
    reported almost every request Oracle staff got through as not granted."""
    requests = [_request("q1", state="EXPIRED"), _request("q2", state="REVOKED"),
                _delegated("d1", status="COMPLETED")]
    assert oac.summarize([], [], [], requests)["provider_requests_granted"] == 3


def test_an_extension_rejected_is_not_a_rejected_request():
    """The original access was granted; only the extension was refused."""
    out = oac.summarize([], [], [], [_request(state="EXTENSIONREJECTED")])
    assert out["provider_requests_granted"] == 1
    assert out["provider_requests_rejected"] == 0


def test_an_unrecognized_state_is_counted_not_guessed():
    out = oac.summarize([], [], [], [_request(state="SOMETHING_NEW"), _request("q2", state=None)])
    assert out["provider_requests_in_unrecognized_state"] == 2
    assert out["provider_requests_granted"] == out["provider_requests_rejected"] == 0


def test_every_sdk_request_state_has_exactly_one_outcome():
    """Both enums, read from the SDK. A state Oracle adds later fails this, so
    it is classified on purpose instead of landing in `unknown` unnoticed."""
    import pytest
    oci = pytest.importorskip("oci")
    states = set()
    for model, attr in ((oci.operator_access_control.models.AccessRequestSummary, "LIFECYCLE_STATE_"),
                        (oci.delegate_access_control.models.DelegatedResourceAccessRequestSummary,
                         "REQUEST_STATUS_")):
        states |= {v for k, v in vars(model).items() if k.startswith(attr) and isinstance(v, str)}
    assert len(states) > 30
    for state in states:
        buckets = [state in oac.GRANTED_STATES, state in oac.PENDING_STATES, state in oac.REJECTED_STATES]
        assert buckets.count(True) == 1, state


def test_customer_and_system_requests_are_not_provider_access():
    out = oac.summarize([], [], [], [_delegated("d1", requester="CUSTOMER"), _delegated("d2", requester="SYSTEM")])
    assert out["total_access_requests"] == 2
    assert out["provider_access_requests"] == 0


def test_a_request_with_no_requester_type_still_counts_as_provider_access():
    """requester_type is optional; dropping those would under-report Oracle access."""
    assert oac.summarize([], [], [], [_delegated(requester=None)])["provider_access_requests"] == 1


def test_an_empty_tenancy_reads_as_nothing_governed_not_a_control_in_place():
    out = oac.summarize([], [], [], [])
    assert out["operator_access_control_readable"] is True
    assert out["governed_resources"] == 0
    assert out["total_operator_controls"] == 0


def test_in_scope_drops_records_naming_another_compartment():
    seen: set = set()
    kept, dropped = oac.in_scope(
        [{"id": "a", "compartment_id": OURS}, {"id": "b", "compartment_id": THEIRS},
         {"id": "c"}, {"id": "a", "compartment_id": OURS}],
        OURS, seen,
    )
    assert [r["id"] for r in kept] == ["a", "c"]
    assert dropped == 1


def test_the_request_window_is_applied_to_unfiltered_delegated_requests():
    days = oac.REQUEST_WINDOW_DAYS
    old = oac.delegated_request_record(
        {"id": "old", "time_access_requested": NOW - timedelta(days=days + 1)}, now=NOW)
    edge = oac.delegated_request_record(
        {"id": "edge", "time_access_requested": NOW - timedelta(days=days)}, now=NOW)
    assert not oac.within_window(old)
    assert oac.within_window(edge)
    assert oac.within_window(_delegated())
    assert oac.within_window(oac.delegated_request_record({"id": "undated"}, now=NOW))


def test_the_window_holds_for_a_timestamp_that_arrives_as_a_string():
    """iso() passes strings through. 20:00 at -07:00 on the day before the
    window opens is 03:00 UTC inside it; a string compare against the Z-format
    start reads it as a day early and drops it."""
    start = NOW - timedelta(days=oac.REQUEST_WINDOW_DAYS)
    local = (start - timedelta(hours=4)).astimezone(timezone(timedelta(hours=-7)))
    inside = start + timedelta(hours=3)
    assert local.isoformat() < start.strftime("%Y-%m-%dT%H:%M:%SZ")  # the trap is real
    assert (inside - start).total_seconds() > 0
    record = oac.delegated_request_record(
        {"id": "s", "time_access_requested": inside.astimezone(timezone(timedelta(hours=-7))).isoformat()},
        now=NOW)
    assert record["time_created"] < start.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert oac.within_window(record)


# --- collect(), against fake clients ---

class _Fake:
    """One SDK client: every list/get call is recorded and answered from `data`."""

    def __init__(self, calls, data):
        self._calls, self._data = calls, data

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self._calls.append((name, args, kwargs))
            value = self._data.get(name, [])
            return SimpleNamespace(data=value) if name.startswith("get_") else value
        return call


def _collect(monkeypatch, data):
    calls: list = []
    # collect() imports the SDK only to name client classes, which the fake
    # make_client ignores. A stand-in keeps these tests running in CI's general
    # job, which does not install `oci`.
    monkeypatch.setitem(sys.modules, "oci", SimpleNamespace(
        identity=SimpleNamespace(IdentityClient=object),
        operator_access_control=SimpleNamespace(
            OperatorControlClient=object, OperatorControlAssignmentClient=object, AccessRequestsClient=object),
        delegate_access_control=SimpleNamespace(DelegateAccessControlClient=object),
    ))
    monkeypatch.setattr(oac, "make_client", lambda cls, auth: _Fake(calls, data))
    monkeypatch.setattr(oac, "walk_compartments", lambda *a, **k: [{"id": OURS, "name": "ours"}])
    monkeypatch.setattr(oac, "list_all", lambda fn, *a, **k: fn(*a, **k))
    monkeypatch.setattr(oac, "to_plain", lambda item: item)
    collector = oac.Collector(oac.logger)
    result = oac.collect({"tenancy": "t"}, {"compartment_id": OURS}, collector, include_sub=True, now=NOW)
    return result, calls, collector


def test_oac_requests_are_asked_for_a_window_and_dac_requests_are_not(monkeypatch):
    """OAC takes time_start + time_end (num_days caps at 90). DAC paged
    inconsistently with time_start, so it must be listed unfiltered."""
    _, calls, _ = _collect(monkeypatch, {})
    oac_call = next(kw for name, _, kw in calls if name == "list_access_requests")
    assert oac_call["time_end"] - oac_call["time_start"] == timedelta(days=oac.REQUEST_WINDOW_DAYS)
    dac_call = next(kw for name, _, kw in calls if name == "list_delegated_resource_access_requests")
    assert "time_start" not in dac_call and "time_end" not in dac_call


def test_out_of_scope_requests_never_reach_the_evidence(monkeypatch):
    """Records naming another compartment are dropped, counted, and never
    reported as this tenancy's."""
    foreign = {"id": "x", "compartment_id": THEIRS, "request_status": "APPROVED",
               "requester_type": "OPERATOR", "time_access_requested": NOW - timedelta(days=5)}
    own = {"id": "y", "compartment_id": OURS, "request_status": "APPROVED",
           "requester_type": "OPERATOR", "time_access_requested": NOW - timedelta(days=5)}
    result, _, collector = _collect(monkeypatch, {"list_delegated_resource_access_requests": [foreign, own]})
    assert [r["id"] for r in result["access_requests"]] == ["y"]
    assert result["records_outside_requested_compartment"] == 1
    assert collector.ok


def test_approval_settings_come_from_the_full_control(monkeypatch):
    summary = {"id": "c1", "operator_control_name": "c1", "compartment_id": OURS, "lifecycle_state": "ASSIGNED"}
    full = {"pre_approved_op_action_list": ["OP_READ"], "approvers_list": ["u"]}
    result, calls, _ = _collect(monkeypatch, {"list_operator_controls": [summary], "get_operator_control": full})
    assert ("get_operator_control", ("c1",), {}) in calls
    assert result["operator_controls"][0]["pre_approved_actions"] == ["OP_READ"]
