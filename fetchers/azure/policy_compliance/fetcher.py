#!/usr/bin/env python3
"""
Azure Policy compliance state on one subscription — what the assigned policies found.

azure_policy_assignments says which policies are assigned and what their effects can
do; this is the result of evaluating them. Reads from azure-mgmt-policyinsights:

  policy_states.summarize_for_subscription   non-compliant resource and policy counts,
                                             subscription-wide and per assignment
  policy_states.list_query_results_...       the non-compliant (resource, policy)
                                             records themselves, bounded
  policy_states.list_query_results_for_resource
                                             each listed resource's evaluated
                                             expressions (actual vs target), bounded;
                                             a read refused twice is a status, not a failure
  policy_states ("default", grouped)         30 days of history, for recurrence
  remediations.list_for_subscription         remediation tasks and their deployments
  remediations.list_deployments_at_...       each task's per-resource deployments

The non-compliant list and the summary read the "latest" policy states, over the
service's default window (the last day of evaluations — Azure re-evaluates every 24
hours). The window the service used is recorded from the summary's query URI, so a
reader can tell "0 non-compliant" from "nothing evaluated in the window". A
subscription with Microsoft.PolicyInsights unregistered reports
`provider_registration_status: not_registered` and exits 0.
"""

import json
import logging
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    arm_id_key,
    basename,
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
    sorted_counts,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_policy_compliance")

# The policy states "latest" resource: the most recent state of each (resource,
# policy) pair, rather than "default", which is every evaluation in the window.
LATEST = "latest"

# Compliance states as the service spells them in ComplianceDetail.compliance_state
# and PolicyState.compliance_state. Compared lower-cased.
NON_COMPLIANT = "noncompliant"
COMPLIANT = "compliant"

# How many non-compliant (resource, policy) records to keep. The summary counts are
# complete regardless; this bounds only the itemized list, which on a large estate
# runs to hundreds of thousands of rows.
DEFAULT_MAX_NON_COMPLIANT = 1000
MAX_NON_COMPLIANT_ENV = "AZURE_POLICY_MAX_NON_COMPLIANT"

# $expand=PolicyEvaluationDetails needs a resource scope (the service refuses it on a
# subscription), so it costs one query per listed resource; this bounds how many.
EVALUATION_DETAILS = "PolicyEvaluationDetails"
DEFAULT_MAX_DETAIL_RESOURCES = 100
MAX_DETAIL_RESOURCES_ENV = "AZURE_POLICY_MAX_EVALUATION_DETAIL_RESOURCES"
MAX_EXPRESSIONS_PER_STATE = 20
MAX_VALUE_CHARS = 500

# "default" is every evaluation in the window, not only the latest one.
HISTORY = "default"
RECURRENCE_WINDOW_DAYS = 30
# Grouped history rows read before stopping: one per (resource, policy, state).
MAX_HISTORY_ROWS = 50000
HISTORY_GROUP_KEYS = ("ResourceId, PolicyAssignmentId, PolicyDefinitionId, "
                      "PolicyDefinitionReferenceId, ComplianceState")
# Pairs seen both compliant and non-compliant each cost one ordered-history query.
DEFAULT_MAX_RECURRENCE_PAIRS = 100
MAX_RECURRENCE_PAIRS_ENV = "AZURE_POLICY_MAX_RECURRENCE_PAIRS"
COMPLIANCE_FILTER = "(ComplianceState eq 'NonCompliant' or ComplianceState eq 'Compliant')"

# Azure deletes a remediation task 60 days after its last change, so older ones are gone.
DEFAULT_MAX_REMEDIATION_DEPLOYMENTS = 1000
MAX_REMEDIATION_DEPLOYMENTS_ENV = "AZURE_POLICY_MAX_REMEDIATION_DEPLOYMENTS"
REMEDIATIONS_SEGMENT = "/providers/microsoft.policyinsights/remediations/"
# Remediated resource ids per latest-state query, as `ResourceId eq ... or ...`.
RESOURCE_FILTER_BATCH = 20

# evaluation_details_status on each listed non-compliant state.
DETAILS_COLLECTED = "collected"
# Always the case for Resource Provider mode policies (Microsoft.KeyVault.Data and the
# like), whose results Azure keeps per component ($expand=components, not read here).
DETAILS_NOT_RETURNED = "not_returned"
# The resource's query came back without this state, e.g. re-evaluated in between.
DETAILS_NOT_IN_RESULT = "not_in_detail_result"
DETAILS_NOT_REQUESTED = "not_requested"
DETAILS_UNSUPPORTED_SCOPE = "unsupported_scope"
DETAILS_FAILED = "failed"
# Policy Insights refused the resource's read, and again on one retry. Enrichment only, so it
# is recorded on the states and does not fail the run; any other error still does.
DETAILS_NOT_AUTHORIZED = "not_authorized"
# Read from the parsed ARM error, never the message: Policy Insights has answered
# AuthorizationFailed as a 409, and refusals have cleared on a later read.
REFUSAL_CODES = {"authorizationfailed", "linkedauthorizationfailed"}
REFUSAL_RETRY_SECONDS = 5


# --- projections: the only code here that touches an azure-mgmt model ---

def _iso(value):
    """datetime -> UTC "%Y-%m-%dT%H:%M:%SZ", the category's convention; else as-is."""
    if not isinstance(value, datetime):
        return value
    moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compliance_details(details) -> dict:
    """[ComplianceDetail] -> {compliance_state: count}."""
    counts = {}
    for detail in details or []:
        state = model_attr(detail, "compliance_state")
        if state:
            counts[str(state)] = counts.get(str(state), 0) + (model_attr(detail, "count") or 0)
    return dict(sorted(counts.items()))


def project_summary_results(results) -> dict:
    """Read a `SummaryResults` model into a flat dict."""
    return {
        "query_results_uri": model_attr(results, "query_results_uri"),
        "non_compliant_resources": model_attr(results, "non_compliant_resources"),
        "non_compliant_policies": model_attr(results, "non_compliant_policies"),
        "resource_details": _compliance_details(model_attr(results, "resource_details")),
        "policy_details": _compliance_details(model_attr(results, "policy_details")),
        "policy_group_details": _compliance_details(model_attr(results, "policy_group_details")),
    }


def project_assignment_summary(summary) -> dict:
    """Read a `PolicyAssignmentSummary` — one assignment's results and its members'."""
    return {
        "policy_assignment_id": model_attr(summary, "policy_assignment_id"),
        "policy_set_definition_id": model_attr(summary, "policy_set_definition_id"),
        "results": project_summary_results(model_attr(summary, "results")),
        "policy_definitions": [
            {
                "policy_definition_id": model_attr(definition, "policy_definition_id"),
                "policy_definition_reference_id": model_attr(
                    definition, "policy_definition_reference_id"
                ),
                "effect": model_attr(definition, "effect"),
                "results": project_summary_results(model_attr(definition, "results")),
            }
            for definition in model_attr(summary, "policy_definitions") or []
        ],
    }


def project_policy_state(state) -> dict:
    """Read one `PolicyState` (a non-compliant resource x policy pair) into a flat dict."""
    return {
        "resource_id": model_attr(state, "resource_id"),
        "resource_type": model_attr(state, "resource_type"),
        "resource_location": model_attr(state, "resource_location"),
        "compliance_state": model_attr(state, "compliance_state"),
        "policy_assignment_id": model_attr(state, "policy_assignment_id"),
        "policy_assignment_name": model_attr(state, "policy_assignment_name"),
        "policy_assignment_scope": model_attr(state, "policy_assignment_scope"),
        "policy_definition_id": model_attr(state, "policy_definition_id"),
        "policy_definition_name": model_attr(state, "policy_definition_name"),
        "policy_definition_reference_id": model_attr(state, "policy_definition_reference_id"),
        # The effect the evaluation ran under ("deny", "audit", ...).
        "policy_definition_action": model_attr(state, "policy_definition_action"),
        "policy_set_definition_id": model_attr(state, "policy_set_definition_id"),
        "policy_set_definition_name": model_attr(state, "policy_set_definition_name"),
        "timestamp": _iso(model_attr(state, "timestamp")),
    }


def _bounded_value(value):
    """(value, truncated): a compared value as-is, or a JSON preview when it is long."""
    text = json.dumps(value, default=str)
    if len(text) <= MAX_VALUE_CHARS:
        return value, False
    return text[:MAX_VALUE_CHARS], True


def project_evaluation_details(details) -> dict | None:
    """Read `PolicyEvaluationDetails`: each evaluated expression, and any ifNotExists lookup."""
    if details is None:
        return None
    raw = model_attr(details, "evaluated_expressions") or []
    expressions = []
    for expression in raw[:MAX_EXPRESSIONS_PER_STATE]:
        actual, actual_cut = _bounded_value(model_attr(expression, "expression_value"))
        target, target_cut = _bounded_value(model_attr(expression, "target_value"))
        expressions.append(
            {
                "expression": model_attr(expression, "expression"),
                "expression_kind": model_attr(expression, "expression_kind"),
                "path": model_attr(expression, "path"),
                "operator": model_attr(expression, "operator"),
                "actual_value": actual,
                "target_value": target,
                # "True" when the condition matched the resource.
                "result": model_attr(expression, "result"),
                "value_truncated": actual_cut or target_cut,
            }
        )
    if_not_exists = model_attr(details, "if_not_exists_details")
    return {
        "evaluated_expressions": expressions,
        "evaluated_expressions_truncated": len(raw) > MAX_EXPRESSIONS_PER_STATE,
        "if_not_exists_resource_id": model_attr(if_not_exists, "resource_id"),
        "if_not_exists_total_resources": model_attr(if_not_exists, "total_resources"),
    }


def project_detail_state(state) -> dict:
    """One per-resource state read with $expand=PolicyEvaluationDetails."""
    return {
        "resource_id": model_attr(state, "resource_id"),
        "policy_assignment_id": model_attr(state, "policy_assignment_id"),
        "policy_definition_id": model_attr(state, "policy_definition_id"),
        "policy_definition_reference_id": model_attr(state, "policy_definition_reference_id"),
        "evaluation_details": project_evaluation_details(
            model_attr(state, "policy_evaluation_details")
        ),
    }


def project_history_group(row) -> dict:
    """One grouped history row; the $apply count arrives as an unmapped property."""
    extra = model_attr(row, "additional_properties") or {}
    return {
        "resource_id": model_attr(row, "resource_id"),
        "policy_assignment_id": model_attr(row, "policy_assignment_id"),
        "policy_definition_id": model_attr(row, "policy_definition_id"),
        "policy_definition_reference_id": model_attr(row, "policy_definition_reference_id"),
        "compliance_state": model_attr(row, "compliance_state"),
        "evaluations": extra.get("evaluations") or 0,
    }


def project_group_count(row):
    """The `$count as n` of a groupby(...)/aggregate query: how many groups there are."""
    n = (model_attr(row, "additional_properties") or {}).get("n")
    return int(n) if n is not None else None


def project_resource_state(state) -> dict:
    """A remediated resource's latest state, and when it was evaluated."""
    return {
        "resource_id": model_attr(state, "resource_id"),
        "compliance_state": model_attr(state, "compliance_state"),
        "timestamp": _iso(model_attr(state, "timestamp")),
    }


def project_timeline_point(state) -> dict:
    return {
        "timestamp": _iso(model_attr(state, "timestamp")),
        "compliance_state": model_attr(state, "compliance_state"),
    }


def project_remediation_deployment(deployment) -> dict:
    """Read one `RemediationDeployment`: the resource it remediated and how it went."""
    error = model_attr(deployment, "error")
    message = model_attr(error, "message")
    return {
        "remediated_resource_id": model_attr(deployment, "remediated_resource_id"),
        "deployment_id": model_attr(deployment, "deployment_id"),
        "status": model_attr(deployment, "status"),
        "resource_location": model_attr(deployment, "resource_location"),
        "error_code": model_attr(error, "code"),
        "error_message": " ".join(str(message).split())[:300] if message else None,
        "created_on": _iso(model_attr(deployment, "created_on")),
        "last_updated_on": _iso(model_attr(deployment, "last_updated_on")),
    }


def project_remediation(remediation) -> dict:
    """Read a `Remediation` task into a flat dict."""
    status = model_attr(remediation, "deployment_status")
    return {
        "id": model_attr(remediation, "id"),
        "name": model_attr(remediation, "name"),
        "policy_assignment_id": model_attr(remediation, "policy_assignment_id"),
        "policy_definition_reference_id": model_attr(
            remediation, "policy_definition_reference_id"
        ),
        "provisioning_state": model_attr(remediation, "provisioning_state"),
        "resource_discovery_mode": model_attr(remediation, "resource_discovery_mode"),
        "total_deployments": model_attr(status, "total_deployments"),
        "successful_deployments": model_attr(status, "successful_deployments"),
        "failed_deployments": model_attr(status, "failed_deployments"),
        "created_on": _iso(model_attr(remediation, "created_on")),
        "last_updated_on": _iso(model_attr(remediation, "last_updated_on")),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def evaluation_window(query_results_uri) -> dict:
    """The $from/$to the service applied, read back off the summary's query URI.

    The summary does not return the window as a field, only inside this link.
    """
    query = parse_qs(urlparse(str(query_results_uri or "")).query)
    return {
        "from": (query.get("$from") or [None])[0],
        "to": (query.get("$to") or [None])[0],
    }


def compliant_resource_counts(resource_details: dict) -> tuple[int, int]:
    """(compliant, non_compliant) resource counts from a {state: count} map."""
    lowered = {str(k).lower(): v for k, v in (resource_details or {}).items()}
    return lowered.get(COMPLIANT, 0), lowered.get(NON_COMPLIANT, 0)


def assignment_record(summary: dict) -> dict:
    """One assignment's compliance, with only its non-compliant member policies itemized.

    An initiative carries a row per member; the compliant ones add nothing a reader
    acts on, and the member count alone is kept.
    """
    results = summary.get("results") or {}
    compliant, non_compliant = compliant_resource_counts(results.get("resource_details"))
    members = summary.get("policy_definitions") or []
    failing = [
        {
            "policy_definition_id": m.get("policy_definition_id"),
            "policy_definition_name": basename(m.get("policy_definition_id")),
            "policy_definition_reference_id": m.get("policy_definition_reference_id"),
            "effect": m.get("effect"),
            "non_compliant_resources": (m.get("results") or {}).get("non_compliant_resources") or 0,
        }
        for m in members
        if ((m.get("results") or {}).get("non_compliant_resources") or 0) > 0
    ]
    return {
        "policy_assignment_id": summary.get("policy_assignment_id"),
        "policy_assignment_name": basename(summary.get("policy_assignment_id")),
        "policy_set_definition_id": summary.get("policy_set_definition_id") or None,
        "is_initiative": bool(summary.get("policy_set_definition_id")),
        "non_compliant_resources": results.get("non_compliant_resources") or 0,
        "non_compliant_policies": results.get("non_compliant_policies") or 0,
        "resource_details": results.get("resource_details") or {},
        "compliant_resources": compliant,
        "compliance_percentage": coverage_percentage(compliant, compliant + non_compliant),
        "is_compliant": (results.get("non_compliant_resources") or 0) == 0,
        "member_policy_count": len(members),
        "non_compliant_member_policies": sorted(
            failing,
            key=lambda m: (-m["non_compliant_resources"], m.get("policy_definition_reference_id") or ""),
        ),
    }


def state_record(state: dict) -> dict:
    """A non-compliant policy state, with the resource group split out for grouping."""
    return {**state, "resource_group": resource_group_from_id(state.get("resource_id"))}


PAIR_FIELDS = ("resource_id", "policy_assignment_id", "policy_definition_id",
               "policy_definition_reference_id")


def pair_key(record: dict) -> tuple:
    """One policy on one resource, lower-cased: ARM is inconsistent about id casing."""
    return tuple(arm_id_key(record.get(field)) for field in PAIR_FIELDS)


def is_resource_scope(resource_id) -> bool:
    """False for a subscription or resource group, whose states cannot be expanded."""
    return "providers" in [s.lower() for s in str(resource_id or "").split("/") if s]


def detail_resources(states: list[dict]) -> list[str]:
    """The listed states' distinct resources that can be expanded, most states first."""
    counts: Counter = Counter()
    spelling: dict[str, str] = {}
    for state in states:
        resource_id = state.get("resource_id")
        if resource_id and is_resource_scope(resource_id):
            counts[arm_id_key(resource_id)] += 1
            spelling.setdefault(arm_id_key(resource_id), resource_id)
    return [spelling[key] for key in sorted(counts, key=lambda k: (-counts[k], k))]


def has_evaluation_details(details) -> bool:
    """An evaluated expression or an ifNotExists lookup; a returned state can carry neither."""
    return bool(details) and bool(
        details.get("evaluated_expressions")
        or details.get("if_not_exists_resource_id")
        or details.get("if_not_exists_total_resources") is not None
    )


def _error_code(exc: BaseException) -> str:
    return str(getattr(getattr(exc, "error", None), "code", None) or "")


def is_not_authorized(exc: BaseException) -> bool:
    """A refused read (403, or an AuthorizationFailed error code), as opposed to a broken call."""
    return getattr(exc, "status_code", None) == 403 or _error_code(exc).lower() in REFUSAL_CODES


def refusal_reason(exc: BaseException) -> str:
    """What was refused: the error code and the action Azure names; never the principal or a scope."""
    code = _error_code(exc)
    code = code if re.fullmatch(r"[A-Za-z]+", code) else f"HTTP {getattr(exc, 'status_code', None)}"
    action = re.search(r"\baction '([A-Za-z][\w.-]*(?:/[\w.-]+)+)'", " ".join(str(exc).split()))
    return f"Policy Insights refused the read ({code})" + (f" on {action.group(1)}" if action else "")


def attach_evaluation_details(
    states: list[dict], results: dict[str, list[dict] | None], refused: dict[str, str] | None = None
) -> None:
    """Give each listed state its evaluation details, or the reason it has none.

    `results` maps each queried resource id (lower-cased) to its detail states, or to
    None when the query failed; `refused` maps each one the identity may not read to why.
    """
    refused = refused or {}
    for state in states:
        resource_id = arm_id_key(state.get("resource_id"))
        details, status, reason = None, DETAILS_NOT_REQUESTED, None
        if not is_resource_scope(resource_id):
            status = DETAILS_UNSUPPORTED_SCOPE
        elif resource_id in refused:
            status, reason = DETAILS_NOT_AUTHORIZED, refused[resource_id]
        elif resource_id in results:
            found = results[resource_id]
            if found is None:
                status = DETAILS_FAILED
            else:
                # Each row under its own resource id, so a nested resource's row can't stand in.
                by_pair = {pair_key({**d, "resource_id": d.get("resource_id") or resource_id}): d
                           for d in found}
                match = by_pair.get(pair_key(state))
                details = (match or {}).get("evaluation_details")
                if not has_evaluation_details(details):
                    details = None
                if match is None:
                    status = DETAILS_NOT_IN_RESULT
                else:
                    status = DETAILS_COLLECTED if details else DETAILS_NOT_RETURNED
        state["evaluation_details"] = details
        state["evaluation_details_status"] = status
        state["evaluation_details_reason"] = reason


def _odata(value) -> str:
    return str(value or "").replace("'", "''")


def timeline_filter(pair: dict) -> str:
    """$filter for one pair's compliant and non-compliant history records."""
    parts = [
        f"ResourceId eq '{_odata(pair.get('resource_id'))}'",
        f"PolicyAssignmentId eq '{_odata(pair.get('policy_assignment_id'))}'",
        f"PolicyDefinitionId eq '{_odata(pair.get('policy_definition_id'))}'",
    ]
    if pair.get("policy_definition_reference_id"):
        parts.append(
            f"PolicyDefinitionReferenceId eq '{_odata(pair['policy_definition_reference_id'])}'"
        )
    return " and ".join(parts + [COMPLIANCE_FILTER])


def history_pairs(rows: list[dict]) -> dict[tuple, dict]:
    """Grouped history rows -> one record per (resource, policy) with its evaluation counts."""
    pairs: dict[tuple, dict] = {}
    for row in rows:
        pair = pairs.setdefault(
            pair_key(row),
            {**{field: row.get(field) for field in PAIR_FIELDS},
             "non_compliant_evaluations": 0, "compliant_evaluations": 0},
        )
        state = str(row.get("compliance_state") or "").lower()
        if state == NON_COMPLIANT:
            pair["non_compliant_evaluations"] += row.get("evaluations") or 0
        elif state == COMPLIANT:
            pair["compliant_evaluations"] += row.get("evaluations") or 0
    return pairs


def intermittent_pairs(pairs: dict[tuple, dict]) -> list[dict]:
    """Pairs seen both non-compliant and compliant in the window, most non-compliant first."""
    return sorted(
        (p for p in pairs.values() if p["non_compliant_evaluations"] and p["compliant_evaluations"]),
        key=lambda p: (-p["non_compliant_evaluations"], pair_key(p)),
    )


def recurrence_record(pair: dict, timeline: list[dict]) -> dict:
    """Count a pair's separate non-compliant episodes from its ordered history.

    An episode is a run of non-compliant evaluations; `times_fell_non_compliant`
    leaves out one already running when the window opened.
    """
    ordered = sorted(timeline, key=lambda p: p.get("timestamp") or "")
    episodes = fell = 0
    previous = None
    non_compliant_at = []
    for point in ordered:
        state = str(point.get("compliance_state") or "").lower()
        if state == NON_COMPLIANT:
            non_compliant_at.append(point.get("timestamp"))
            if previous != NON_COMPLIANT:
                episodes += 1
                if previous == COMPLIANT:
                    fell += 1
        previous = state
    return {
        **pair,
        "non_compliant_episodes": episodes,
        "times_fell_non_compliant": fell,
        "recurring": episodes > 1,
        "first_non_compliant_at": non_compliant_at[0] if non_compliant_at else None,
        "last_non_compliant_at": non_compliant_at[-1] if non_compliant_at else None,
        "latest_compliance_state": ordered[-1].get("compliance_state") if ordered else None,
    }


def remediation_scope(remediation_id) -> tuple[str, str | None]:
    """Which list_deployments_at_* reads a remediation task, and its scope argument."""
    text = str(remediation_id or "")
    cut = text.lower().find(REMEDIATIONS_SEGMENT)
    segments = [s for s in (text[:cut] if cut >= 0 else "").split("/") if s]
    lowered = [s.lower() for s in segments]
    if lowered[:3] == ["providers", "microsoft.management", "managementgroups"] and len(segments) == 4:
        return "management_group", segments[3]
    if lowered[:1] != ["subscriptions"] or len(segments) < 2:
        return "unknown", None
    if len(segments) == 2:
        return "subscription", None
    if len(segments) == 4 and lowered[2] == "resourcegroups":
        return "resource_group", segments[3]
    return "resource", text[:cut]


def latest_states_by_resource(rows: list[dict]) -> dict[str, dict]:
    """{resource id: its latest state row}; NonCompliant wins when a resource has two."""
    states: dict[str, dict] = {}
    for row in rows:
        resource_id = arm_id_key(row.get("resource_id"))
        if resource_id and (
            resource_id not in states or str(row.get("compliance_state")).lower() == NON_COMPLIANT
        ):
            states[resource_id] = row
    return states


def deployment_record(deployment: dict, task: dict, current_states: dict[str, dict]) -> dict:
    """A remediation deployment, checked against its resource's latest compliance state.

    A state evaluated before the deployment last changed says nothing about it: Azure
    re-evaluates a deployIfNotExists target only in its 24-hour cycle.
    """
    current = current_states.get(arm_id_key(deployment.get("remediated_resource_id"))) or {}
    state, evaluated_at = current.get("compliance_state"), current.get("timestamp")
    deployed_at = deployment.get("last_updated_on") or deployment.get("created_on")
    # Both are _iso strings, so they compare as times.
    reevaluated = evaluated_at >= deployed_at if evaluated_at and deployed_at else None
    lowered = str(state or "").lower()
    now_compliant = True if lowered == COMPLIANT else False if lowered == NON_COMPLIANT else None
    return {
        "remediation_task_id": task.get("id"),
        "policy_assignment_id": task.get("policy_assignment_id"),
        "policy_definition_reference_id": task.get("policy_definition_reference_id"),
        **deployment,
        "current_compliance_state": state,
        "current_state_evaluated_at": evaluated_at,
        "reevaluated_since_deployment": reevaluated,
        "now_compliant": None if reevaluated is False else now_compliant,
    }


def _deployed_at(deployment: dict) -> str:
    return deployment.get("last_updated_on") or deployment.get("created_on") or ""


def latest_deployment_per_resource(deployments: list[dict]) -> list[dict]:
    """Each remediated resource's newest deployment, which decides its remediation counts."""
    newest: dict[str, dict] = {}
    for index, deployment in enumerate(deployments):
        key = arm_id_key(deployment.get("remediated_resource_id")) or f"#{index}"
        if key not in newest or _deployed_at(deployment) > _deployed_at(newest[key]):
            newest[key] = deployment
    return list(newest.values())


def summarize(
    subscription_results: dict,
    assignments: list[dict],
    states: list[dict],
    states_truncated: bool,
    remediations: list[dict],
) -> dict:
    """Subscription-wide counts first (from the service), then what was itemized."""
    compliant, non_compliant = compliant_resource_counts(
        subscription_results.get("resource_details")
    )
    by_state: dict[str, int] = {}
    for remediation in remediations:
        key = str(remediation.get("provisioning_state") or "Unknown")
        by_state[key] = by_state.get(key, 0) + 1
    return {
        # --- the headline: the service's own subscription-wide counts ---
        "non_compliant_resources": subscription_results.get("non_compliant_resources") or 0,
        "non_compliant_policies": subscription_results.get("non_compliant_policies") or 0,
        "compliant_resources": compliant,
        # Zero here means nothing was evaluated in the window, which is what tells
        # "0 non-compliant" (a finding) from "0 non-compliant, nothing assessed".
        "resources_evaluated": sum((subscription_results.get("resource_details") or {}).values()),
        "resource_compliance_percentage": coverage_percentage(compliant, compliant + non_compliant),
        "resources_by_compliance_state": subscription_results.get("resource_details") or {},
        "policies_by_compliance_state": subscription_results.get("policy_details") or {},
        # --- per assignment ---
        "assignments_evaluated": len(assignments),
        "non_compliant_assignments": sum(1 for a in assignments if not a["is_compliant"]),
        "compliant_assignments": sum(1 for a in assignments if a["is_compliant"]),
        # --- the itemized list ---
        "listed_non_compliant_states": len(states),
        "listed_distinct_non_compliant_resources": len(
            {str(s.get("resource_id") or "").lower() for s in states if s.get("resource_id")}
        ),
        "non_compliant_states_truncated": states_truncated,
        # --- remediation ---
        "remediation_tasks": len(remediations),
        "remediation_tasks_by_provisioning_state": dict(sorted(by_state.items())),
        "remediation_failed_deployments": sum(r.get("failed_deployments") or 0 for r in remediations),
        "remediation_successful_deployments": sum(
            r.get("successful_deployments") or 0 for r in remediations
        ),
    }


def summarize_evaluation_details(states: list[dict], details: dict) -> dict:
    by_status = Counter(s.get("evaluation_details_status") or DETAILS_NOT_REQUESTED for s in states)
    return {
        "evaluation_details_eligible_resources": details["eligible"],
        "evaluation_details_resources_queried": details["requested"],
        "evaluation_details_truncated": details["truncated"],
        "evaluation_details_not_authorized_resources": details["not_authorized"],
        "non_compliant_states_with_evaluation_details": by_status[DETAILS_COLLECTED],
        "non_compliant_states_by_evaluation_details_status": sorted_counts(by_status),
    }


def summarize_recurrence(
    pairs: dict[tuple, dict], records: list[dict], history_truncated: bool, pairs_truncated: bool,
    history_collected: bool = True,
) -> dict:
    """None throughout when the history read failed, so it can't read as no non-compliance."""
    non_compliant = [p for p in pairs.values() if p["non_compliant_evaluations"]]
    persistent = [p for p in non_compliant if not p["compliant_evaluations"]]
    counts = {
        "history_non_compliant_pairs": len(non_compliant),
        "history_persistently_non_compliant_pairs": len(persistent),
        "history_intermittently_non_compliant_pairs": len(non_compliant) - len(persistent),
        "history_truncated": history_truncated,
        "recurrence_pairs_read": len(records),
        "recurrence_pairs_truncated": pairs_truncated,
        "recurring_non_compliant_pairs": sum(1 for r in records if r["recurring"]),
        # Any non-compliant pair had at least one episode, read or not.
        "max_non_compliant_episodes": max(
            [r["non_compliant_episodes"] for r in records] + [1 if non_compliant else 0]
        ),
    }
    return {
        "recurrence_window_days": RECURRENCE_WINDOW_DAYS,
        "history_collected": history_collected,
        **{key: value if history_collected else None for key, value in counts.items()},
    }


def summarize_remediation_deployments(deployments: list[dict], truncated: bool) -> dict:
    """Deployments by status; the remediated_* counts are per resource, its latest deployment deciding."""
    resources = latest_deployment_per_resource(deployments)
    return {
        "remediation_deployments_listed": len(deployments),
        "remediation_deployments_truncated": truncated,
        "remediation_deployments_by_status": sorted_counts(
            Counter(str(d.get("status") or "Unknown") for d in deployments)
        ),
        "remediated_resources_listed": len(resources),
        "remediated_resources_now_compliant": sum(1 for d in resources if d["now_compliant"] is True),
        # Includes resources fixed and later drifted back.
        "remediated_resources_now_non_compliant": sum(
            1 for d in resources if d["now_compliant"] is False
        ),
        "succeeded_remediations_now_non_compliant": sum(
            1 for d in resources
            if d["now_compliant"] is False and str(d.get("status") or "").lower() == "succeeded"
        ),
        # The state read predates the deployment; the next evaluation will tell.
        "remediated_resources_not_yet_reevaluated": sum(
            1 for d in resources if d.get("reevaluated_since_deployment") is False
        ),
        "remediated_resources_compliance_unknown": sum(
            1 for d in resources
            if d["now_compliant"] is None and d.get("reevaluated_since_deployment") is not False
        ),
    }


def config_limit(env: str, default: int) -> int:
    """A list bound from config; a bad value falls back to the default."""
    raw = (os.environ.get(env) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", env, raw, default)
        return default
    return max(value, 0)


# --- collection (lazy azure imports) ---

def empty_collection() -> dict:
    return {
        "subscription_results": project_summary_results(None),
        "assignments": [],
        "states": [],
        "states_truncated": False,
        "remediations": [],
        "details": {"eligible": 0, "requested": 0, "truncated": False, "not_authorized": 0},
        "recurrence": {"window": None, "pairs": {}, "records": [], "history_collected": False,
                       "history_truncated": False, "pairs_truncated": False},
        "deployments": [],
        "deployments_truncated": False,
    }


def collect_evaluation_details(client, states: list[dict], limit: int, collector: Collector) -> dict:
    """One $expand=PolicyEvaluationDetails query per listed resource, up to `limit`."""
    from azure.mgmt.policyinsights.models import QueryOptions  # lazy

    eligible = detail_resources(states)
    selected = eligible[:limit]
    results: dict[str, list[dict] | None] = {}
    refused: dict[str, str] = {}
    for resource_id in selected:
        def _read(resource_id=resource_id):
            options = QueryOptions(filter="ComplianceState eq 'NonCompliant'", expand=EVALUATION_DETAILS)
            return [
                project_detail_state(s)
                for s in client.policy_states.list_query_results_for_resource(
                    LATEST, resource_id.lstrip("/"), query_options=options
                )
            ]

        operation = f"policyinsights.policy_states.list_query_results_for_resource({basename(resource_id)})"
        key = arm_id_key(resource_id)
        try:
            try:
                results[key] = _read()
            except Exception as exc:  # noqa: BLE001 — a refusal is retried once, anything else is not
                if not is_not_authorized(exc):
                    raise
                logger.info("%s: %s; retrying once", operation, refusal_reason(exc))
                time.sleep(REFUSAL_RETRY_SECONDS)
                results[key] = _read()
        except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
            if not is_not_authorized(exc):
                collector.record(operation, exc)
                results[key] = None
                continue
            refused[key] = refusal_reason(exc)
            logger.warning("%s: %s; recorded on its states", operation, refused[key])
    attach_evaluation_details(states, results, refused)
    # A limit of 0 skips them, which is not truncation.
    return {"eligible": len(eligible), "requested": len(selected),
            "truncated": limit > 0 and len(eligible) > limit, "not_authorized": len(refused)}


def collect_recurrence(client, subscription_id, limit: int, collector: Collector, now=None) -> dict:
    """30 days of history grouped per (resource, policy, state), then each flipping pair's order."""
    from azure.mgmt.policyinsights.models import QueryOptions  # lazy

    end = now or datetime.now(timezone.utc)
    start = end - timedelta(days=RECURRENCE_WINDOW_DAYS)
    truncated = False

    def _groups():
        nonlocal truncated
        rows: list[dict] = []
        options = QueryOptions(
            from_property=start,
            to=end,
            filter=COMPLIANCE_FILTER,
            apply=f"groupby(({HISTORY_GROUP_KEYS}), aggregate($count as evaluations))",
        )
        for row in client.policy_states.list_query_results_for_subscription(
            HISTORY, subscription_id, query_options=options
        ):
            if len(rows) >= MAX_HISTORY_ROWS:
                truncated = True
                break
            rows.append(project_history_group(row))
        return rows

    def _group_count():
        # No $apply example shows a nextLink, so check every group came back.
        # Counted first: a record landing late, between the two queries, then only adds a row.
        options = QueryOptions(
            from_property=start,
            to=end,
            filter=COMPLIANCE_FILTER,
            apply=f"groupby(({HISTORY_GROUP_KEYS}))/aggregate($count as n)",
        )
        for row in client.policy_states.list_query_results_for_subscription(
            HISTORY, subscription_id, query_options=options
        ):
            return project_group_count(row)
        return None

    expected = collector.guard(
        "policyinsights.policy_states.list_query_results_for_subscription (history group count)",
        _group_count,
    )
    history = collector.guard(
        "policyinsights.policy_states.list_query_results_for_subscription (history)", _groups
    )
    rows = history or []
    if not truncated and expected is not None and len(rows) < expected:
        logger.warning("history query returned %d of %d groups", len(rows), expected)
        truncated = True
    pairs = history_pairs(rows)
    flipping = intermittent_pairs(pairs)
    records = []
    for pair in flipping[:limit]:
        def _timeline(pair=pair):
            options = QueryOptions(from_property=start, to=end, filter=timeline_filter(pair),
                                   select="Timestamp, ComplianceState", order_by="Timestamp asc")
            return [
                project_timeline_point(s)
                for s in client.policy_states.list_query_results_for_subscription(
                    HISTORY, subscription_id, query_options=options
                )
            ]

        timeline = collector.guard(
            f"policyinsights.policy_states.list_query_results_for_subscription "
            f"(history of {basename(pair.get('resource_id'))})",
            _timeline,
        )
        if timeline is not None:
            records.append(recurrence_record(pair, timeline))
    return {
        "window": {"from": _iso(start), "to": _iso(end), "days": RECURRENCE_WINDOW_DAYS},
        "pairs": pairs,
        "records": sorted(
            records,
            key=lambda r: (-r["non_compliant_episodes"], -r["non_compliant_evaluations"], pair_key(r)),
        ),
        "history_collected": history is not None,
        "history_truncated": truncated,
        "pairs_truncated": limit > 0 and len(flipping) > limit,
    }


def collect_remediation_deployments(
    client, subscription_id, remediations: list[dict], limit: int, collector: Collector
) -> tuple[list[dict], bool]:
    """Each task's per-resource deployments, checked against the latest states, up to `limit`."""
    from azure.mgmt.policyinsights.models import QueryOptions  # lazy

    if limit <= 0:
        return [], False
    listers = {
        "subscription": lambda name, scope: client.remediations.list_deployments_at_subscription(name),
        "resource_group": lambda name, scope: client.remediations.list_deployments_at_resource_group(
            scope, name),
        "management_group": lambda name, scope: (
            client.remediations.list_deployments_at_management_group(scope, name)),
        "resource": lambda name, scope: client.remediations.list_deployments_at_resource(
            scope.lstrip("/"), name),
    }
    deployments: list[dict] = []
    truncated = False

    def _current(policy: tuple, resource_ids: list[str]) -> dict:
        assignment, reference = policy
        clauses = [f"PolicyAssignmentId eq '{_odata(assignment)}'"]
        if reference:
            clauses.append(f"PolicyDefinitionReferenceId eq '{_odata(reference)}'")
        clauses.append("(" + " or ".join(f"ResourceId eq '{_odata(r)}'" for r in resource_ids) + ")")
        # "latest" holds one row per resource for one assignment and reference id.
        options = QueryOptions(filter=" and ".join(clauses), select="ResourceId, ComplianceState, Timestamp")
        return latest_states_by_resource([
            project_resource_state(s)
            for s in client.policy_states.list_query_results_for_subscription(
                LATEST, subscription_id, query_options=options
            )
        ])

    # Latest states per policy, lower-cased (assignment, reference id) as policy states hold
    # them; a resource remediated again by a later task on the same policy is not re-read.
    current_by_policy: dict[tuple, dict] = {}
    read_by_policy: dict[tuple, set] = {}
    for task in remediations:
        remaining = limit - len(deployments)
        if remaining <= 0:
            truncated = truncated or task.get("total_deployments") != 0
            continue
        kind, scope = remediation_scope(task.get("id"))
        name = task.get("name")
        if kind not in listers:
            logger.warning("remediation %s has an unrecognised scope; deployments not read", task.get("id"))
            continue

        def _list(kind=kind, scope=scope, name=name, remaining=remaining):
            nonlocal truncated
            rows = []
            for deployment in listers[kind](name, scope):
                if len(rows) >= remaining:
                    truncated = True
                    break
                rows.append(project_remediation_deployment(deployment))
            return rows

        rows = collector.guard(f"policyinsights.remediations.list_deployments_at_{kind}({name})", _list,
                               default=[])
        if not rows:
            continue

        policy = (arm_id_key(task.get("policy_assignment_id")),
                  arm_id_key(task.get("policy_definition_reference_id")))
        read = read_by_policy.setdefault(policy, set())
        current = current_by_policy.setdefault(policy, {})
        unread = sorted({arm_id_key(d.get("remediated_resource_id")) for d in rows} - read - {""})
        for at in range(0, len(unread), RESOURCE_FILTER_BATCH):
            batch = unread[at:at + RESOURCE_FILTER_BATCH]
            read.update(batch)
            current.update(collector.guard(
                f"policyinsights.policy_states.list_query_results_for_subscription (remediated {name})",
                lambda policy=policy, batch=batch: _current(policy, batch),
                default={},
            ) or {})
        deployments.extend(deployment_record(d, task, current) for d in rows)
    return sorted(deployments, key=lambda d: (d.get("remediation_task_id") or "",
                                              d.get("remediated_resource_id") or "")), truncated


def collect_compliance(subscription_id, cred, collector: Collector, limits: dict) -> dict:
    """The policyinsights reads, each guarded on its own.

    A failure in one still leaves the others in the evidence, and still fails the run.
    """
    from azure.mgmt.policyinsights import PolicyInsightsClient  # lazy
    from azure.mgmt.policyinsights.models import QueryOptions  # lazy

    collected = empty_collection()
    client = collector.guard(
        "policyinsights.PolicyInsightsClient (init)",
        lambda: PolicyInsightsClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        ),
    )
    if client is None:
        return collected

    def _summarize():
        # One Summary for the subscription; `value` is a list by API shape.
        response = client.policy_states.summarize_for_subscription(LATEST, subscription_id)
        summaries = model_attr(response, "value") or []
        first = summaries[0] if summaries else None
        return (
            project_summary_results(model_attr(first, "results")),
            [
                assignment_record(project_assignment_summary(a))
                for a in (model_attr(first, "policy_assignments") or [])
            ],
        )

    summarized = collector.guard("policyinsights.policy_states.summarize_for_subscription", _summarize)
    subscription_results, assignments = summarized or (collected["subscription_results"], [])

    limit = limits["non_compliant"]
    states: list[dict] = []
    truncated = False
    if limit > 0:
        def _states():
            nonlocal truncated
            # top = limit + 1: the one extra row is how truncation is detected
            # without a second count query. ItemPaged follows nextLink.
            options = QueryOptions(filter="complianceState eq 'NonCompliant'", top=limit + 1)
            for state in client.policy_states.list_query_results_for_subscription(
                LATEST, subscription_id, query_options=options
            ):
                if len(states) >= limit:
                    truncated = True
                    break
                states.append(state_record(project_policy_state(state)))

        collector.guard("policyinsights.policy_states.list_query_results_for_subscription", _states)

    remediations = collector.guard(
        "policyinsights.remediations.list_for_subscription",
        lambda: [project_remediation(r) for r in client.remediations.list_for_subscription()],
        default=[],
    )
    details = collect_evaluation_details(client, states, limits["detail_resources"], collector)
    recurrence = collect_recurrence(client, subscription_id, limits["recurrence_pairs"], collector)
    deployments, deployments_truncated = collect_remediation_deployments(
        client, subscription_id, remediations, limits["remediation_deployments"], collector
    )

    logger.info(
        "Summarized %d assignment(s): %s non-compliant resource(s); itemized %d state(s)%s, "
        "evaluation details for %d of %d resource(s); %d (resource, policy) pair(s) in %d-day "
        "history, %d read for recurrence; %d remediation task(s), %d deployment(s)",
        len(assignments),
        subscription_results.get("non_compliant_resources"),
        len(states),
        " (truncated)" if truncated else "",
        details["requested"],
        details["eligible"],
        len(recurrence["pairs"]),
        RECURRENCE_WINDOW_DAYS,
        len(recurrence["records"]),
        len(remediations),
        len(deployments),
    )
    return {
        "subscription_results": subscription_results,
        "assignments": sorted(assignments, key=lambda a: a.get("policy_assignment_id") or ""),
        "states": sorted(
            states,
            key=lambda s: (s.get("resource_id") or "", s.get("policy_assignment_id") or "",
                           s.get("policy_definition_reference_id") or ""),
        ),
        "states_truncated": truncated,
        "remediations": sorted(remediations, key=lambda r: r.get("id") or ""),
        "details": details,
        "recurrence": recurrence,
        "deployments": deployments,
        "deployments_truncated": deployments_truncated,
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # dominate the runner's stderr tail. Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    limits = {
        "non_compliant": config_limit(MAX_NON_COMPLIANT_ENV, DEFAULT_MAX_NON_COMPLIANT),
        "detail_resources": config_limit(MAX_DETAIL_RESOURCES_ENV, DEFAULT_MAX_DETAIL_RESOURCES),
        "recurrence_pairs": config_limit(MAX_RECURRENCE_PAIRS_ENV, DEFAULT_MAX_RECURRENCE_PAIRS),
        "remediation_deployments": config_limit(
            MAX_REMEDIATION_DEPLOYMENTS_ENV, DEFAULT_MAX_REMEDIATION_DEPLOYMENTS
        ),
    }

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    collected = empty_collection()
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked first: with Microsoft.PolicyInsights unregistered there is no compliance
        # data to read, which is "not in use", not a failed collection.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.PolicyInsights"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.PolicyInsights is not registered on subscription %s — "
                "reporting status not_registered",
                subscription_id,
            )
        else:
            collected = collect_compliance(subscription_id, cred, collector, limits)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "could not resolve which Azure subscription to use (set "
                "AZURE_SUBSCRIPTION_ID or configure an ambient Azure credential "
                "that can list subscriptions)"
            ),
        )

    subscription_results = collected["subscription_results"]
    recurrence = collected["recurrence"]
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "subscription_compliance": subscription_results,
            "evaluation_window": evaluation_window(subscription_results.get("query_results_uri")),
            "policy_states_resource": LATEST,
            "assignment_compliance": collected["assignments"],
            "non_compliant_states": collected["states"],
            "non_compliant_states_limit": limits["non_compliant"],
            "evaluation_details_resource_limit": limits["detail_resources"],
            "remediation_tasks": collected["remediations"],
            "remediation_deployments": collected["deployments"],
            "remediation_deployment_limit": limits["remediation_deployments"],
            "recurrence_window": recurrence["window"],
            "non_compliance_recurrence": recurrence["records"],
            "recurrence_pair_limit": limits["recurrence_pairs"],
            "provider_registration_status": registration,
        },
        summary={
            **summarize(
                subscription_results,
                collected["assignments"],
                collected["states"],
                collected["states_truncated"],
                collected["remediations"],
            ),
            **summarize_evaluation_details(collected["states"], collected["details"]),
            **summarize_recurrence(
                recurrence["pairs"], recurrence["records"], recurrence["history_truncated"],
                recurrence["pairs_truncated"], recurrence["history_collected"],
            ),
            **summarize_remediation_deployments(
                collected["deployments"], collected["deployments_truncated"]
            ),
            "provider_registration_status": registration,
        },
    )

    filename = f"azure_policy_compliance_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
