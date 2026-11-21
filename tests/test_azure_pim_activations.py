"""azure_pim_activations: request and activation records, the summary, and the no-PIM and failure paths. No network."""
from __future__ import annotations

import importlib.util
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load():
    spec = importlib.util.spec_from_file_location("azure_pim_activations_under_test", AZURE / "pim_activations" / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pa = _load()
ArmError = sys.modules["azure_rest"].ArmError
Collector = sys.modules["azure_common"].Collector

SUB = "00000000-0000-0000-0000-000000000000"
SCOPE = f"/subscriptions/{SUB}"
RG = f"{SCOPE}/resourceGroups/rg-app"
OWNER = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
READER = "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
NOW = datetime(2026, 11, 4, 20, 0, tzinfo=timezone.utc)


def req(n, *, kind="SelfActivate", status="Provisioned", role=OWNER, role_name="Owner", scope=SCOPE,
        justification="change CHG-12", ticket=None, approval=None, duration="PT8H", created="2026-11-01T10:00:00Z",
        principal="u1"):
    return {
        "id": f"{scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/{n}",
        "properties": {
            "requestType": kind, "status": status, "createdOn": created, "principalId": principal,
            "principalType": "User", "requestorId": principal, "roleDefinitionId": role, "scope": scope,
            "scheduleInfo": {"startDateTime": created, "expiration": {"type": "AfterDuration", "duration": duration}},
            "justification": justification, "ticketInfo": {"ticketNumber": ticket} if ticket else {},
            "approvalId": approval,
            "expandedProperties": {
                "principal": {"displayName": f"User {principal}", "email": f"{principal}@example.com", "type": "User"},
                "roleDefinition": {"displayName": role_name, "type": "BuiltInRole"},
                "scope": {"displayName": "sub", "type": "subscription"},
            },
        },
    }


def inst(n, *, assignment_type="Activated", role=OWNER, role_name="Owner", end="2026-11-04T23:00:00Z"):
    return {
        "id": f"{SCOPE}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances/{n}",
        "properties": {
            "assignmentType": assignment_type, "status": "Provisioned", "principalId": "u1", "principalType": "User",
            "roleDefinitionId": role, "scope": SCOPE, "startDateTime": "2026-11-04T15:00:00Z", "endDateTime": end,
            "memberType": "Direct",
            "expandedProperties": {"principal": {"displayName": "User u1", "email": "u1@example.com"},
                                   "roleDefinition": {"displayName": role_name}},
        },
    }


class FakeClient:
    def __init__(self, requests=None, instances=None, fail=None):
        self.requests = requests or []
        self.instances = instances or []
        self.fail = fail or {}
        self.calls = []

    def list(self, path, api_version, params=None):
        kind = path.rsplit("/", 1)[-1]
        self.calls.append((path, api_version, dict(params or {})))
        if kind in self.fail:
            raise self.fail[kind]
        return self.requests if kind == "roleAssignmentScheduleRequests" else self.instances


def run(client):
    collector = Collector(logging.getLogger("t"))
    results, summary = pa.collect(client, SUB, collector)
    return results, summary, collector


# --- records -----------------------------------------------------------------


def test_request_record_fields():
    r = pa.request_record(req(1, ticket="INC-7", approval="appr-1"), SUB)
    assert r["request_type"] == "SelfActivate" and r["outcome"] == "granted"
    assert r["role_name"] == "Owner" and r["is_over_broad_builtin"] is True
    assert r["scope_level"] == "subscription" and r["principal_upn"] == "u1@example.com"
    assert r["requested_duration_hours"] == 8.0 and r["has_justification"] and r["has_ticket"]
    assert r["went_through_approval"] is True


def test_duration_falls_back_to_start_and_end():
    raw = req(2, duration=None)
    raw["properties"]["scheduleInfo"]["expiration"] = {"type": "AfterDateTime", "endDateTime": "2026-11-01T14:30:00Z"}
    r = pa.request_record(raw, SUB)
    assert r["requested_duration_hours"] == 4.5


@pytest.mark.parametrize("value,hours", [("PT8H", 8.0), ("PT30M", 0.5), ("P1D", 24.0), ("P1DT2H", 26.0), ("nonsense", None), (None, None)])
def test_duration_hours(value, hours):
    assert pa.duration_hours(value) == hours


@pytest.mark.parametrize("status,out", [("Provisioned", "granted"), ("Denied", "denied_or_failed"), ("PendingApproval", "pending"),
                                        ("Revoked", "revoked"), ("Accepted", "pending"), ("ScheduleCreated", "granted"),
                                        ("Mystery", "unknown"), (None, "unknown")])
def test_outcome(status, out):
    assert pa.outcome(status) == out


@pytest.mark.parametrize("scope,level", [(SCOPE, "subscription"), (RG, "resource_group"), (RG + "/providers/Microsoft.KeyVault/vaults/kv", "resource"),
                                         ("/providers/Microsoft.Management/managementGroups/mg", "management_group"), ("/", "root"),
                                         ("/subscriptions/11111111-1111-1111-1111-111111111111", "other_subscription")])
def test_scope_level(scope, level):
    assert pa.scope_level(scope, SUB) == level


# --- collect and summary -------------------------------------------------------


def test_collect_summary_counts():
    client = FakeClient(
        requests=[
            req(1, ticket="INC-1", approval="a1"),
            req(2, justification="", role=READER, role_name="Reader", scope=RG, created="2026-10-30T09:00:00Z", principal="u2"),
            req(3, status="Denied", created="2026-11-02T12:00:00Z"),
            req(4, kind="AdminAssign", status="Provisioned", duration="P1D"),
            req(5, kind="AdminRemove", status="Provisioned"),
            req(6, status="PendingApproval", approval="a2", created="2026-11-03T08:00:00Z", principal="u3"),
        ],
        instances=[inst(1), inst(2, assignment_type="Assigned"), inst(3, role=READER, role_name="Reader", end=None)],
    )
    results, summary, collector = run(client)
    assert collector.ok
    assert summary["pim_available"] is True
    assert summary["requests_total"] == 6 and summary["self_activations"] == 4
    assert summary["self_activations_granted"] == 2 and summary["self_activations_denied_or_failed"] == 1
    assert summary["self_activations_pending"] == 1
    assert summary["self_activations_without_justification"] == 1
    assert summary["self_activations_without_ticket"] == 3
    assert summary["self_activations_without_approval"] == 2
    assert summary["self_activations_of_over_broad_roles"] == 3
    assert summary["over_broad_activations_without_approval"] == 1
    assert summary["principals_who_activated"] == 2
    assert summary["self_activations_by_role"] == {"Owner": 3, "Reader": 1}
    assert summary["self_activations_by_scope_level"] == {"resource_group": 1, "subscription": 3}
    assert summary["admin_assign_requests"] == 1 and summary["admin_assign_requests_of_over_broad_roles"] == 1
    assert summary["admin_remove_requests"] == 1
    assert summary["activation_duration_hours_max"] == 8.0
    assert summary["oldest_request_created_on"] == "2026-10-30T09:00:00Z"
    assert summary["newest_request_created_on"] == "2026-11-03T08:00:00Z"
    assert summary["currently_active_activations"] == 2, "Assigned instances are standing grants, not activations"
    assert summary["currently_active_over_broad_activations"] == 1
    assert summary["currently_active_activations_without_end"] == 1
    assert results["role_assignment_schedule_requests"][0]["created_on"] == "2026-11-03T08:00:00Z", "newest first"
    assert all(c[2] == {} and c[1] == pa.PIM_API for c in client.calls), "no $filter: the subscription and below"


def test_summary_fields_are_documented(assert_summary_documented):
    statuses = ["Provisioned", "Revoked", "Denied", "PendingApproval", "SomethingNew"]
    _, summary, _ = run(FakeClient(requests=[req(i, status=st) for i, st in enumerate(statuses, 1)]))
    assert set(summary["requests_by_outcome"]) == {"granted", "revoked", "denied_or_failed", "pending", "unknown"}
    assert_summary_documented("azure/pim_activations", summary)


def test_no_pim_is_a_state_not_a_failure():
    err = ArmError(400, "AadPremiumLicenseRequired", "Entra ID P2 licence required")
    client = FakeClient(fail={"roleAssignmentScheduleRequests": err, "roleAssignmentScheduleInstances": err})
    results, summary, collector = run(client)
    assert collector.ok and summary["pim_available"] is False
    assert summary["requests_total"] == 0 and summary["currently_active_activations"] == 0
    assert results["role_assignment_schedule_requests"] == [] and len(results["notes"]) == 2


def test_failed_read_leaves_keys_null_and_fails_run():
    client = FakeClient(requests=[req(1)], fail={"roleAssignmentScheduleInstances": ArmError(403, "AuthorizationFailed", "no")})
    results, summary, collector = run(client)
    assert not collector.ok
    assert summary["requests_total"] == 1 and summary["currently_active_activations"] is None
    assert results["active_activations"] is None and summary["pim_available"] is True


def test_empty_window_is_zero_not_null():
    results, summary, collector = run(FakeClient())
    assert collector.ok and summary["requests_total"] == 0 and summary["oldest_request_created_on"] is None
    assert summary["activation_duration_hours_max"] is None and summary["principals_who_activated"] == 0


def test_revoked_activation_still_counts_as_activated():
    client = FakeClient(requests=[req(1, status="Revoked"), req(2, status="Denied", principal="u2")])
    _, summary, collector = run(client)
    assert collector.ok
    assert summary["self_activations_granted"] == 1 and summary["self_activations_revoked_early"] == 1
    assert summary["self_activations_denied_or_failed"] == 1 and summary["principals_who_activated"] == 1
    assert summary["requests_by_outcome"] == {"denied_or_failed": 1, "revoked": 1}


def test_one_list_failed_and_the_other_unlicensed_keeps_the_failure_visible():
    client = FakeClient(fail={"roleAssignmentScheduleRequests": ArmError(500, "InternalServerError", "boom"),
                              "roleAssignmentScheduleInstances": ArmError(400, "AadPremiumLicenseRequired", "P2 required")})
    results, summary, collector = run(client)
    assert not collector.ok and summary["pim_available"] is False
    assert summary["requests_total"] is None, "a failed read must not be masked as an empty list"
    assert summary["currently_active_activations"] == 0


def test_admin_assign_without_expiration_is_counted():
    raw = req(1, kind="AdminAssign", duration=None)
    raw["properties"]["scheduleInfo"]["expiration"] = {"type": "NoExpiration"}
    _, summary, _ = run(FakeClient(requests=[raw, req(2, kind="AdminAssign")]))
    assert summary["admin_assign_requests"] == 2 and summary["admin_assign_requests_without_expiration"] == 1


def test_justification_is_bounded_and_control_characters_dropped():
    raw = req(1, justification="line one\x00\x07 \n" + "x" * 5000)
    r = pa.request_record(raw, SUB)
    assert "\x00" not in r["justification"] and "\x07" not in r["justification"]
    assert r["justification"].startswith("line one") and len(r["justification"]) == pa.JUSTIFICATION_MAX_CHARS


def test_no_secret_like_fields_are_copied():
    raw = req(1)
    raw["properties"]["secretValue"] = "should-not-appear"
    raw["properties"]["expandedProperties"]["principal"]["password"] = "nope"
    r = pa.request_record(raw, SUB)
    assert "should-not-appear" not in str(r) and "nope" not in str(r)


def test_both_lists_failed_leaves_pim_available_unknown():
    err = ArmError(500, "InternalServerError", "boom")
    _, summary, collector = run(FakeClient(fail={"roleAssignmentScheduleRequests": err,
                                                 "roleAssignmentScheduleInstances": err}))
    assert not collector.ok and summary["pim_available"] is None
    assert summary["requests_total"] is None and summary["currently_active_activations"] is None


@pytest.mark.parametrize("code, message", [
    ("InvalidFilter", "The filter is not supported for premium accounts"),
    ("BadRequest", "The license check service is unavailable"),
])
def test_an_unrelated_400_mentioning_a_licence_or_premium_is_a_failure(code, message):
    err = ArmError(400, code, message)
    _, summary, collector = run(FakeClient(fail={"roleAssignmentScheduleRequests": err,
                                                 "roleAssignmentScheduleInstances": err}))
    assert not collector.ok and summary["pim_available"] is None and summary["requests_total"] is None


def test_the_licence_codes_still_read_as_no_pim():
    for code in ("AadPremiumLicenseRequired", "TenantNotOnboarded"):
        err = ArmError(400, code, "not available")
        _, summary, collector = run(FakeClient(fail={"roleAssignmentScheduleRequests": err,
                                                     "roleAssignmentScheduleInstances": err}))
        assert collector.ok and summary["pim_available"] is False, code
