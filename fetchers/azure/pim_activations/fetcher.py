#!/usr/bin/env python3
"""
Azure resource PIM activity on one subscription: who activated what, when, and how.

`azure_rbac_role_assignments` already shows the PIM *configuration*: which grants
are permanent or eligible, and the activation rules on the over-broad roles. This
fetcher shows the PIM *activity* those rules produced: every role assignment
schedule request Azure still holds for the subscription and the scopes under it
(self-activations, admin assignments, extensions, renewals, removals) with the
requester, role, scope, justification, ticket, approval outcome, requested
duration and result, plus the activations in force right now.

Read-only, ARM only, Reader is enough:
  GET {scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2020-10-01
  GET {scope}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01
Listed with no $filter, which returns the subscription scope and every scope
below it (resource groups and resources). Requests made on a management group
or the tenant root are not included; atScope() would return those instead of
the child scopes, and the activity inside the subscription is what this
evidence is for. Both come back with expandedProperties (principal, role
definition, scope names), so no Microsoft Graph call is needed. Azure keeps schedule requests for a limited,
non-configurable window; the evidence records the oldest and newest request it
saw rather than assuming what the window is.

A tenant without Entra ID P2 or ID Governance has no PIM: the lists answer 400
with a licence marker, which is reported as pim_available: false, a state rather
than a collection failure. Any other failed read leaves the dependent summary keys
null and fails the run.
"""

import logging
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import ArmError, parse_time, run_subscription  # noqa: E402

NAME = "azure_pim_activations"
PIM_API = "2020-10-01"
# Built-in role definition GUIDs, the same four azure_rbac_role_assignments flags.
OVER_BROAD_BUILTIN_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
}
# Without Entra ID P2 or ID Governance the PIM lists answer 400 with one of these error codes: a state, not a
# failure. Only the code is matched, never the message, so an unrelated 400 that mentions a licence or "premium"
# stays a recorded failure instead of reading as "no PIM".
PIM_UNAVAILABLE_CODES = ("aadpremiumlicenserequired", "tenantnotonboarded")
SELF_ACTIVATION = "SelfActivate"
ADMIN_ASSIGN = "AdminAssign"
# Outcomes a request can end in (the Status enum of the 2020-10-01 API); anything else is reported as it came back.
GRANTED_STATUSES = {"provisioned", "granted", "adminapproved", "schedulecreated"}
# Revoked is a request that WAS granted and then ended early (a deactivation or an admin removal): it still
# counts as an activation that happened, so it is kept apart from the denials.
REVOKED_STATUSES = {"revoked", "pendingrevocation"}
DENIED_STATUSES = {"denied", "admindenied", "canceled", "cancelled", "failed", "timedout", "invalid",
                   "failedasresourceislocked"}
# Accepted is the initial state before evaluation, not a grant.
PENDING_STATUSES = {"accepted", "pendingapproval", "pendingapprovalprovisioning", "pendingadmindecision",
                    "pendingevaluation", "pendingprovisioning", "pendingschedulecreation", "provisioningstarted"}
ACTIVATED_OUTCOMES = {"granted", "revoked"}
JUSTIFICATION_MAX_CHARS = 1000

logger = logging.getLogger(NAME)


def pim_unavailable(exc: BaseException) -> bool:
    code = (getattr(exc, "code", None) or "").lower()
    return isinstance(exc, ArmError) and exc.status == 400 and any(code.startswith(c) for c in PIM_UNAVAILABLE_CODES)


def _iso(value: Any) -> Optional[str]:
    ts = parse_time(value)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def role_definition_guid(role_definition_id: Optional[str]) -> Optional[str]:
    if not role_definition_id:
        return None
    return role_definition_id.rstrip("/").rsplit("/", 1)[-1].lower()


def scope_level(scope: Optional[str], subscription_id: str) -> str:
    s = (scope or "").rstrip("/").lower()
    if s == "" or s == "/":
        return "root"
    if "/providers/microsoft.management/managementgroups/" in s:
        return "management_group"
    parts = [p for p in s.split("/") if p]
    if len(parts) == 2 and parts[0] == "subscriptions":
        return "subscription" if parts[1] == subscription_id.lower() else "other_subscription"
    if len(parts) == 4 and parts[2] == "resourcegroups":
        return "resource_group"
    return "resource"


def outcome(status: Optional[str]) -> str:
    s = (status or "").lower()
    if s in GRANTED_STATUSES:
        return "granted"
    if s in REVOKED_STATUSES:
        return "revoked"
    if s in DENIED_STATUSES:
        return "denied_or_failed"
    if s in PENDING_STATUSES:
        return "pending"
    return "unknown"


def duration_hours(value: Optional[str]) -> Optional[float]:
    """ISO 8601 duration such as PT8H, PT30M, P1D, P1DT2H -> hours; None when unparseable."""
    if not value or not value.startswith("P"):
        return None
    hours = 0.0
    date_part, _, time_part = value[1:].partition("T")
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)([DWMY])", date_part):
        hours += float(num) * {"D": 24, "W": 168, "M": 30 * 24, "Y": 365 * 24}[unit]
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)([HMS])", time_part):
        hours += float(num) * {"H": 1, "M": 1 / 60, "S": 1 / 3600}[unit]
    return round(hours, 3)


def _expanded(props: Dict[str, Any], key: str) -> Dict[str, Any]:
    return ((props.get("expandedProperties") or {}).get(key)) or {}


def request_record(item: Dict[str, Any], subscription_id: str) -> Dict[str, Any]:
    props = item.get("properties") or {}
    principal = _expanded(props, "principal")
    role = _expanded(props, "roleDefinition")
    scope = props.get("scope")
    guid = role_definition_guid(props.get("roleDefinitionId"))
    schedule = props.get("scheduleInfo") or {}
    expiration = schedule.get("expiration") or {}
    ticket = props.get("ticketInfo") or {}
    # Free text typed by the requester: kept as evidence, bounded, with control characters removed.
    justification = "".join(ch for ch in str(props.get("justification") or "") if ch >= " " or ch == "\n").strip()
    justification = justification[:JUSTIFICATION_MAX_CHARS]
    end = _iso(expiration.get("endDateTime"))
    start = _iso(schedule.get("startDateTime"))
    hours = duration_hours(expiration.get("duration"))
    if hours is None and start and end:
        hours = round((parse_time(end) - parse_time(start)).total_seconds() / 3600, 3)
    return {
        "id": item.get("id"),
        "request_type": props.get("requestType"),
        "status": props.get("status"),
        "outcome": outcome(props.get("status")),
        "created_on": _iso(props.get("createdOn")),
        "principal_id": props.get("principalId"),
        "principal_type": props.get("principalType") or principal.get("type"),
        "principal_name": principal.get("displayName"),
        "principal_upn": principal.get("email"),
        "requestor_id": props.get("requestorId"),
        "role_definition_id": props.get("roleDefinitionId"),
        "role_name": role.get("displayName") or OVER_BROAD_BUILTIN_ROLES.get(guid or ""),
        "is_over_broad_builtin": guid in OVER_BROAD_BUILTIN_ROLES,
        "scope": scope,
        "scope_level": scope_level(scope, subscription_id),
        "scope_name": _expanded(props, "scope").get("displayName"),
        "start_date_time": start,
        "end_date_time": end,
        "expiration_type": expiration.get("type"),
        "requested_duration": expiration.get("duration"),
        "requested_duration_hours": hours,
        "justification": justification or None,
        "has_justification": bool(justification),
        "ticket_number": ticket.get("ticketNumber"),
        "ticket_system": ticket.get("ticketSystem"),
        "has_ticket": bool(ticket.get("ticketNumber")),
        "approval_id": props.get("approvalId"),
        "went_through_approval": bool(props.get("approvalId")),
        "linked_eligibility_id": props.get("linkedRoleEligibilityScheduleId"),
        "target_schedule_id": props.get("targetRoleAssignmentScheduleId"),
        "condition": props.get("condition"),
    }


def active_activation_record(item: Dict[str, Any], subscription_id: str) -> Dict[str, Any]:
    props = item.get("properties") or {}
    principal = _expanded(props, "principal")
    role = _expanded(props, "roleDefinition")
    guid = role_definition_guid(props.get("roleDefinitionId"))
    return {
        "id": item.get("id"),
        "assignment_type": props.get("assignmentType"),
        "status": props.get("status"),
        "principal_id": props.get("principalId"),
        "principal_type": props.get("principalType") or principal.get("type"),
        "principal_name": principal.get("displayName"),
        "principal_upn": principal.get("email"),
        "role_name": role.get("displayName") or OVER_BROAD_BUILTIN_ROLES.get(guid or ""),
        "is_over_broad_builtin": guid in OVER_BROAD_BUILTIN_ROLES,
        "scope": props.get("scope"),
        "scope_level": scope_level(props.get("scope"), subscription_id),
        "start_date_time": _iso(props.get("startDateTime")),
        "end_date_time": _iso(props.get("endDateTime")),
        "member_type": props.get("memberType"),
        "linked_eligibility_id": props.get("linkedRoleEligibilityScheduleInstanceId"),
    }


def summarize(requests: Optional[List[Dict[str, Any]]], activations: Optional[List[Dict[str, Any]]],
              pim_available: Optional[bool], now: datetime) -> Dict[str, Any]:
    def figure(records, value):
        return None if records is None else value

    reqs = requests or []
    self_acts = [r for r in reqs if r["request_type"] == SELF_ACTIVATION]
    # An activation that happened: granted, or granted and later revoked.
    granted_acts = [r for r in self_acts if r["outcome"] in ACTIVATED_OUTCOMES]
    admin_assigns = [r for r in reqs if r["request_type"] == ADMIN_ASSIGN]
    over_broad_acts = [r for r in self_acts if r["is_over_broad_builtin"]]
    hours = [r["requested_duration_hours"] for r in self_acts if r["requested_duration_hours"] is not None]
    created = [r["created_on"] for r in reqs if r["created_on"]]
    acts = activations or []
    return {
        "pim_available": pim_available,
        "requests_total": figure(requests, len(reqs)),
        "requests_by_type": figure(requests, dict(sorted(Counter(r["request_type"] or "unknown" for r in reqs).items()))),
        "requests_by_status": figure(requests, dict(sorted(Counter(r["status"] or "unknown" for r in reqs).items()))),
        "requests_by_outcome": figure(requests, dict(sorted(Counter(r["outcome"] for r in reqs).items()))),
        "oldest_request_created_on": figure(requests, min(created) if created else None),
        "newest_request_created_on": figure(requests, max(created) if created else None),
        "self_activations": figure(requests, len(self_acts)),
        "self_activations_granted": figure(requests, len(granted_acts)),
        "self_activations_revoked_early": figure(requests, sum(1 for r in self_acts if r["outcome"] == "revoked")),
        "self_activations_denied_or_failed": figure(requests, sum(1 for r in self_acts if r["outcome"] == "denied_or_failed")),
        "self_activations_pending": figure(requests, sum(1 for r in self_acts if r["outcome"] == "pending")),
        "self_activations_without_justification": figure(requests, sum(1 for r in self_acts if not r["has_justification"])),
        "self_activations_without_ticket": figure(requests, sum(1 for r in self_acts if not r["has_ticket"])),
        "self_activations_without_approval": figure(requests, sum(1 for r in self_acts if not r["went_through_approval"])),
        "self_activations_of_over_broad_roles": figure(requests, len(over_broad_acts)),
        "over_broad_activations_without_justification": figure(
            requests, sum(1 for r in over_broad_acts if not r["has_justification"])),
        "over_broad_activations_without_approval": figure(
            requests, sum(1 for r in over_broad_acts if not r["went_through_approval"])),
        "principals_who_activated": figure(requests, len({r["principal_id"] for r in granted_acts if r["principal_id"]})),
        "self_activations_by_role": figure(
            requests, dict(sorted(Counter(r["role_name"] or "unknown" for r in self_acts).items()))),
        "self_activations_by_scope_level": figure(
            requests, dict(sorted(Counter(r["scope_level"] for r in self_acts).items()))),
        "activation_duration_hours_max": figure(requests, max(hours) if hours else None),
        "activation_duration_hours_median": figure(requests, sorted(hours)[len(hours) // 2] if hours else None),
        # Direct (non-JIT) admin assignments made through PIM in the window: standing access being granted.
        "admin_assign_requests": figure(requests, len(admin_assigns)),
        "admin_assign_requests_of_over_broad_roles": figure(
            requests, sum(1 for r in admin_assigns if r["is_over_broad_builtin"])),
        # A direct assignment with no expiry is permanent access granted through PIM.
        "admin_assign_requests_without_expiration": figure(
            requests, sum(1 for r in admin_assigns if not r["end_date_time"] and not r["requested_duration"])),
        "admin_remove_requests": figure(requests, sum(1 for r in reqs if r["request_type"] == "AdminRemove")),
        "currently_active_activations": figure(activations, len(acts)),
        "currently_active_over_broad_activations": figure(activations, sum(1 for a in acts if a["is_over_broad_builtin"])),
        "currently_active_activations_without_end": figure(activations, sum(1 for a in acts if not a["end_date_time"])),
        "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def collect(client, subscription_id: str, collector) -> tuple:
    scope = f"/subscriptions/{subscription_id}"
    pim_available: Optional[bool] = True
    notes: List[str] = []

    def _list(kind: str):
        try:
            return client.list(f"{scope}/providers/Microsoft.Authorization/{kind}", PIM_API)
        except ArmError as exc:
            if pim_unavailable(exc):
                notes.append(f"{kind} not read: PIM is not available on this tenant ({exc})")
                return "unavailable"
            collector.record(f"authorization.{kind}.list(atScope)", exc)
            return None
        except Exception as exc:  # noqa: BLE001 - record, don't crash the run
            collector.record(f"authorization.{kind}.list(atScope)", exc)
            return None

    raw_requests = _list("roleAssignmentScheduleRequests")
    raw_instances = _list("roleAssignmentScheduleInstances")
    if raw_requests == "unavailable" or raw_instances == "unavailable":
        pim_available = False
    elif raw_requests is None and raw_instances is None:
        # Both lists failed for another reason: whether PIM is in use is unknown, not true.
        pim_available = None
    requests = None
    if isinstance(raw_requests, list):
        requests = sorted((request_record(r, subscription_id) for r in raw_requests),
                          key=lambda r: (r["created_on"] or "", r["id"] or ""), reverse=True)
    activations = None
    if isinstance(raw_instances, list):
        activations = [active_activation_record(i, subscription_id) for i in raw_instances
                       if ((i.get("properties") or {}).get("assignmentType") or "").lower() == "activated"]
        activations.sort(key=lambda a: (a["role_name"] or "", a["principal_name"] or a["principal_id"] or ""))
    # A list PIM refused for want of a licence is empty by definition; a list that failed for any
    # other reason stays None so its summary keys read null and the recorded failure exits non-zero.
    if raw_requests == "unavailable":
        requests = []
    if raw_instances == "unavailable":
        activations = []

    now = datetime.now(timezone.utc)
    results = {
        "role_assignment_schedule_requests": requests,
        "active_activations": activations,
        "notes": notes,
    }
    return results, summarize(requests, activations, pim_available, now)


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
