#!/usr/bin/env python3
"""
Azure Policy compliance state on one subscription — what the assigned policies found.

azure_policy_assignments says which policies are assigned and what their effects can
do; this is the result of evaluating them. Three reads from azure-mgmt-policyinsights:

  policy_states.summarize_for_subscription   non-compliant resource and policy counts,
                                             subscription-wide and per assignment
  policy_states.list_query_results_...       the non-compliant (resource, policy)
                                             records themselves, bounded
  remediations.list_for_subscription         remediation tasks and their deployments

Everything reads the "latest" policy states, over the service's default window (the
last day of evaluations — Azure re-evaluates every 24 hours). The window the service
used is recorded from the summary's query URI, so a reader can tell "0 non-compliant"
from "nothing evaluated in the window". A subscription with Microsoft.PolicyInsights
unregistered reports `provider_registration_status: not_registered` and exits 0.
"""

import logging
import os
import sys
from datetime import datetime, timezone
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


def max_non_compliant() -> int:
    """The itemized-list bound from config; a bad value falls back to the default."""
    raw = (os.environ.get(MAX_NON_COMPLIANT_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_NON_COMPLIANT
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", MAX_NON_COMPLIANT_ENV, raw,
                       DEFAULT_MAX_NON_COMPLIANT)
        return DEFAULT_MAX_NON_COMPLIANT
    return max(value, 0)


# --- collection (lazy azure imports) ---

def collect_compliance(subscription_id, cred, collector: Collector, limit: int) -> dict:
    """The three policyinsights reads, each guarded on its own.

    A failure in one still leaves the others in the evidence, and still fails the run.
    """
    from azure.mgmt.policyinsights import PolicyInsightsClient  # lazy
    from azure.mgmt.policyinsights.models import QueryOptions  # lazy

    empty = {"subscription_results": project_summary_results(None), "assignments": [],
             "states": [], "states_truncated": False, "remediations": []}

    client = collector.guard(
        "policyinsights.PolicyInsightsClient (init)",
        lambda: PolicyInsightsClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        ),
    )
    if client is None:
        return empty

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
    subscription_results, assignments = summarized or (empty["subscription_results"], [])

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

    logger.info(
        "Summarized %d assignment(s): %s non-compliant resource(s); itemized %d state(s)%s; "
        "%d remediation task(s)",
        len(assignments),
        subscription_results.get("non_compliant_resources"),
        len(states),
        " (truncated)" if truncated else "",
        len(remediations),
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
    limit = max_non_compliant()

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    collected = {
        "subscription_results": project_summary_results(None),
        "assignments": [],
        "states": [],
        "states_truncated": False,
        "remediations": [],
    }
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
            collected = collect_compliance(subscription_id, cred, collector, limit)
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
            "non_compliant_states_limit": limit,
            "remediation_tasks": collected["remediations"],
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
