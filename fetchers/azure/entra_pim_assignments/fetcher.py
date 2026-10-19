#!/usr/bin/env python3
"""Entra ID PIM for directory roles: who is eligible, who holds standing or activated access, and each role's activation rules."""

import asyncio
import logging
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    report_failure,
    write_evidence,
)
from entra_graph import (  # noqa: E402
    GLOBAL_ADMINISTRATOR,
    GLOBAL_ADMINISTRATOR_TEMPLATE_ID,
    PRIVILEGED_ROLE_NAMES,
    graph_attr,
    graph_list,
    is_privileged_role,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

NAME = "azure_entra_pim_assignments"
POLICY_FILTER = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
# Without Entra ID P2 (or ID Governance) the PIM endpoints refuse with a licence error, which is a state, not a failure.
UNLICENSED_MARKERS = ("aadpremiumlicenserequired", "licens", "tenantnotonboarded", "not onboarded to pim")
MFA, JUSTIFICATION, TICKETING = "MultiFactorAuthentication", "Justification", "Ticketing"

logger = logging.getLogger(NAME)


# --- projections: the only code here that touches a Graph model ---

def iso_duration(value: Any) -> Optional[str]:
    """kiota parses Graph's ISO-8601 durations into timedelta; render them back."""
    if value is None or not isinstance(value, timedelta):
        return value
    hours, rest = divmod(value.seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    time = "".join(f"{n}{unit}" for n, unit in ((hours, "H"), (minutes, "M"), (seconds, "S")) if n)
    date = f"{value.days}D" if value.days else ""
    return f"P{date}T{time}" if time else (f"P{date}" if date else "PT0S")


def duration_hours(value: Optional[str]) -> Optional[float]:
    if not value or not value.startswith("P"):
        return None
    date, _, time = value[1:].partition("T")
    total = float(date[:-1]) * 24 if date.endswith("D") else 0.0
    number = ""
    for ch in time:
        if ch.isdigit() or ch == ".":
            number += ch
            continue
        total += float(number or 0) * {"H": 1, "M": 1 / 60, "S": 1 / 3600}.get(ch, 0)
        number = ""
    return round(total, 2)


def principal_kind(odata_type: Optional[str]) -> Optional[str]:
    tail = str(odata_type or "").rsplit(".", 1)[-1]
    return (tail[:1].upper() + tail[1:]) or None


def project_role_definition(definition) -> Dict[str, Any]:
    return {
        "id": graph_attr(definition, "id"),
        "template_id": graph_attr(definition, "template_id"),
        "display_name": graph_attr(definition, "display_name"),
        "is_built_in": graph_attr(definition, "is_built_in"),
        "is_enabled": graph_attr(definition, "is_enabled"),
    }


def project_instance(instance) -> Dict[str, Any]:
    principal = getattr(instance, "principal", None)
    return {
        "id": graph_attr(instance, "id"),
        "principal_id": graph_attr(instance, "principal_id"),
        "principal_type": principal_kind(graph_attr(principal, "odata_type")) if principal is not None else None,
        "principal_display_name": graph_attr(principal, "display_name"),
        "principal_user_principal_name": graph_attr(principal, "user_principal_name"),
        "role_definition_id": graph_attr(instance, "role_definition_id"),
        "directory_scope_id": graph_attr(instance, "directory_scope_id"),
        "app_scope_id": graph_attr(instance, "app_scope_id"),
        "member_type": graph_attr(instance, "member_type"),
        "assignment_type": graph_attr(instance, "assignment_type"),
        "start_date_time": graph_attr(instance, "start_date_time"),
        "end_date_time": graph_attr(instance, "end_date_time"),
    }


def project_rule(rule) -> Dict[str, Any]:
    setting = getattr(rule, "setting", None)
    projected = {
        "id": graph_attr(rule, "id"),
        "rule_type": principal_kind(graph_attr(rule, "odata_type")),
        "is_expiration_required": graph_attr(rule, "is_expiration_required"),
        "maximum_duration": iso_duration(getattr(rule, "maximum_duration", None)),
        "enabled_rules": graph_list(rule, "enabled_rules") if getattr(rule, "enabled_rules", None) is not None else None,
        "is_enabled": graph_attr(rule, "is_enabled"),
        "claim_value": graph_attr(rule, "claim_value"),
        "approval": None if setting is None else {
            "is_approval_required": graph_attr(setting, "is_approval_required"),
            "is_approval_required_for_extension": graph_attr(setting, "is_approval_required_for_extension"),
            "is_requestor_justification_required": graph_attr(setting, "is_requestor_justification_required"),
            "approval_mode": graph_attr(setting, "approval_mode"),
            "stages": [
                {
                    "primary_approver_count": len(getattr(stage, "primary_approvers", None) or []),
                    "is_escalation_enabled": graph_attr(stage, "is_escalation_enabled"),
                    "approval_stage_time_out_in_days": graph_attr(stage, "approval_stage_time_out_in_days"),
                }
                for stage in getattr(setting, "approval_stages", None) or []
            ],
        },
    }
    return {k: v for k, v in projected.items() if v is not None}


def project_policy_assignment(assignment) -> Dict[str, Any]:
    policy = getattr(assignment, "policy", None)
    return {
        "role_definition_id": graph_attr(assignment, "role_definition_id"),
        "policy_id": graph_attr(assignment, "policy_id"),
        "is_organization_default": graph_attr(policy, "is_organization_default"),
        "last_modified_date_time": graph_attr(policy, "last_modified_date_time"),
        "rules": [project_rule(r) for r in getattr(policy, "rules", None) or []],
    }


# --- pure transforms ---

def role_index(definitions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for d in definitions:
        for key in (d.get("id"), d.get("template_id")):
            if key:
                index[str(key).lower()] = d
    return index


def role_fields(index: Dict[str, Dict[str, Any]], role_definition_id: Optional[str]) -> Dict[str, Any]:
    d = index.get(str(role_definition_id or "").lower()) or {}
    role = {"display_name": d.get("display_name"), "role_template_id": d.get("template_id") or role_definition_id}
    return {
        "role_name": d.get("display_name"),
        "role_definition_id": role_definition_id,
        "role_template_id": role["role_template_id"],
        "is_built_in": d.get("is_built_in"),
        "is_privileged": is_privileged_role(role),
        "is_global_administrator": role["display_name"] == GLOBAL_ADMINISTRATOR
        or str(role["role_template_id"] or "").lower() == GLOBAL_ADMINISTRATOR_TEMPLATE_ID,
    }


def standing(instance: Dict[str, Any]) -> str:
    if (instance.get("assignment_type") or "").lower() == "activated":
        return "pim_activated"
    return "permanent" if not instance.get("end_date_time") else "time_bound"


def assignment_record(instance: Dict[str, Any], index: Dict[str, Dict[str, Any]], active: bool) -> Dict[str, Any]:
    record = {
        **{k: v for k, v in instance.items() if active or k != "assignment_type"},
        **role_fields(index, instance.get("role_definition_id")),
        "tenant_wide": (instance.get("directory_scope_id") or "/") == "/",
        "is_permanent": not instance.get("end_date_time"),
    }
    if active:
        record["standing"] = standing(instance)
    return record


def _enabled(rules: Dict[str, Dict[str, Any]], rule_id: str, value: str) -> Optional[bool]:
    rule = rules.get(rule_id)
    return None if rule is None else value in (rule.get("enabled_rules") or [])


def _allows_permanent(rules: Dict[str, Dict[str, Any]], rule_id: str) -> Optional[bool]:
    required = (rules.get(rule_id) or {}).get("is_expiration_required")
    return None if required is None else not required


def policy_record(assignment: Dict[str, Any], index: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    rules = {r.get("id"): r for r in assignment["rules"]}
    activation = rules.get("Expiration_EndUser_Assignment") or {}
    approval = (rules.get("Approval_EndUser_Assignment") or {}).get("approval") or {}
    context = rules.get("AuthenticationContext_EndUser_Assignment") or {}
    return {
        **role_fields(index, assignment.get("role_definition_id")),
        "policy_id": assignment.get("policy_id"),
        "is_organization_default": assignment.get("is_organization_default"),
        "last_modified_date_time": assignment.get("last_modified_date_time"),
        "activation_maximum_duration": activation.get("maximum_duration"),
        "activation_maximum_hours": duration_hours(activation.get("maximum_duration")),
        "activation_requires_mfa": _enabled(rules, "Enablement_EndUser_Assignment", MFA),
        "activation_requires_justification": _enabled(rules, "Enablement_EndUser_Assignment", JUSTIFICATION),
        "activation_requires_ticket": _enabled(rules, "Enablement_EndUser_Assignment", TICKETING),
        "activation_requires_approval": approval.get("is_approval_required"),
        "activation_approver_count": sum(s["primary_approver_count"] for s in approval.get("stages") or []) if approval else None,
        "activation_authentication_context": context.get("claim_value") if context.get("is_enabled") else None,
        "permanent_eligible_assignment_allowed": _allows_permanent(rules, "Expiration_Admin_Eligibility"),
        "eligible_assignment_maximum_duration": (rules.get("Expiration_Admin_Eligibility") or {}).get("maximum_duration"),
        "permanent_active_assignment_allowed": _allows_permanent(rules, "Expiration_Admin_Assignment"),
        "active_assignment_maximum_duration": (rules.get("Expiration_Admin_Assignment") or {}).get("maximum_duration"),
        "active_assignment_requires_mfa": _enabled(rules, "Enablement_Admin_Assignment", MFA),
        "active_assignment_requires_justification": _enabled(rules, "Enablement_Admin_Assignment", JUSTIFICATION),
        "rules": sorted(
            (r for r in assignment["rules"] if not str(r.get("id") or "").startswith("Notification_")),
            key=lambda r: r.get("id") or "",
        ),
    }


def _sort_key(record: Dict[str, Any]) -> tuple:
    return (
        record.get("role_name") or "",
        (record.get("principal_user_principal_name") or record.get("principal_display_name") or "").lower(),
        record.get("principal_id") or "",
        record.get("start_date_time") or "",
    )


def summarize(eligible: List[Dict[str, Any]], active: List[Dict[str, Any]], policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    priv_eligible = [e for e in eligible if e["is_privileged"]]
    priv_active = [a for a in active if a["is_privileged"]]
    priv_permanent = [a for a in priv_active if a["standing"] == "permanent"]
    priv_policies = [p for p in policies if p["is_privileged"]]

    def names(records, pred=lambda r: True):
        return sorted({r["role_name"] or r["role_definition_id"] or "" for r in records if pred(r)})

    return {
        "pim_available": True,
        "eligible_assignments": len(eligible),
        "eligible_privileged_assignments": len(priv_eligible),
        "permanently_eligible_privileged_assignments": sum(1 for e in priv_eligible if e["is_permanent"]),
        "principals_eligible_for_privileged_roles": len({e["principal_id"] for e in priv_eligible}),
        "privileged_roles_with_eligible_holders": names(priv_eligible),
        "active_assignments": len(active),
        "active_privileged_assignments": len(priv_active),
        "active_privileged_by_standing": {
            s: sum(1 for a in priv_active if a["standing"] == s) for s in ("permanent", "pim_activated", "time_bound")
        },
        "permanent_active_privileged_assignments": len(priv_permanent),
        "permanent_active_privileged_user_assignments": sum(1 for a in priv_permanent if a["principal_type"] == "User"),
        "principals_with_permanent_privileged_access": len({a["principal_id"] for a in priv_permanent}),
        "privileged_roles_with_permanent_active_holders": names(priv_permanent),
        "global_administrator_eligible": sum(1 for e in eligible if e["is_global_administrator"]),
        "global_administrator_permanent_active": sum(1 for a in priv_permanent if a["is_global_administrator"]),
        "privileged_role_policies": len(priv_policies),
        "privileged_roles_activation_without_mfa_or_auth_context": names(
            priv_policies, lambda p: p["activation_requires_mfa"] is False and not p["activation_authentication_context"]
        ),
        "privileged_roles_activation_without_justification": names(
            priv_policies, lambda p: p["activation_requires_justification"] is False
        ),
        "privileged_roles_activation_without_approval": names(priv_policies, lambda p: p["activation_requires_approval"] is False),
        "privileged_roles_allowing_permanent_active_assignment": names(
            priv_policies, lambda p: p["permanent_active_assignment_allowed"] is True
        ),
        "privileged_roles_allowing_permanent_eligible_assignment": names(
            priv_policies, lambda p: p["permanent_eligible_assignment_allowed"] is True
        ),
        "max_privileged_activation_hours": max(
            (p["activation_maximum_hours"] for p in priv_policies if p["activation_maximum_hours"] is not None), default=None
        ),
    }


# --- collection (lazy msgraph imports) ---

def _query(builder, **params):
    from kiota_abstractions.base_request_configuration import RequestConfiguration

    parameters = getattr(type(builder), f"{type(builder).__name__}GetQueryParameters")
    return RequestConfiguration(query_parameters=parameters(**params))


def _each(project, items: Optional[List[Any]]) -> Optional[List[Dict[str, Any]]]:
    return None if items is None else [project(i) for i in items]


async def _read(collector: Collector, unlicensed: List[str], operation: str, builder, config=None) -> Optional[List[Any]]:
    """`paginate`, with a licence refusal noted rather than recorded; None when the read failed."""
    probe = Collector(logger)
    items = await paginate(probe, operation, builder, config)
    failed = False
    for failure in probe.failures:
        if any(m in (failure.get("message") or "").lower() for m in UNLICENSED_MARKERS):
            unlicensed.append(f"{operation}: {failure.get('message')}")
        else:
            collector.failures.append(failure)
            failed = True
    return None if failed else items


async def _collect(collector: Collector, cred) -> tuple:
    async def _work(client):
        tenant = await resolve_tenant(collector, client)
        directory = client.role_management.directory
        unlicensed: List[str] = []

        async def read(operation: str, builder, project, **params):
            config = _query(builder, **params) if params else None
            return _each(project, await _read(collector, unlicensed, f"graph.{operation}.get", builder, config))

        definitions = await read(
            "roleManagement.directory.roleDefinitions", directory.role_definitions, project_role_definition
        )
        eligible = await read(
            "roleManagement.directory.roleEligibilityScheduleInstances",
            directory.role_eligibility_schedule_instances,
            project_instance,
            expand=["principal"],
        )
        active = await read(
            "roleManagement.directory.roleAssignmentScheduleInstances",
            directory.role_assignment_schedule_instances,
            project_instance,
            expand=["principal"],
        )
        policies = await read(
            "policies.roleManagementPolicyAssignments",
            client.policies.role_management_policy_assignments,
            project_policy_assignment,
            filter=POLICY_FILTER,
            expand=["policy($expand=rules)"],
        )
        return tenant, definitions, eligible, active, policies, unlicensed

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ({"tenant_source": "unresolved"}, None, None, None, None, [])


def build(definitions, eligible, active, policies, unlicensed) -> tuple:
    if unlicensed:
        notes = ["PIM is not available in this tenant (Entra ID P2 or ID Governance is required)", *unlicensed]
        return {"pim_available": False, "notes": notes}, {"pim_available": False}
    index = role_index(definitions or [])
    eligible_records = None if eligible is None else sorted((assignment_record(i, index, False) for i in eligible), key=_sort_key)
    active_records = None if active is None else sorted((assignment_record(i, index, True) for i in active), key=_sort_key)
    assigned = {r["role_definition_id"] for r in (eligible_records or []) + (active_records or [])}
    policy_records = None if policies is None else sorted(
        (p for p in (policy_record(a, index) for a in policies) if p["is_privileged"] or p["role_definition_id"] in assigned),
        key=lambda p: (p["role_name"] or "", p["role_definition_id"] or ""),
    )
    complete = None not in (definitions, eligible_records, active_records, policy_records)
    results = {
        "pim_available": True if complete else None,
        "eligible_assignments": eligible_records,
        "active_assignments": active_records,
        "role_policies": policy_records,
        "role_definitions_read": None if definitions is None else len(definitions),
        "privileged_role_names_checked": sorted(PRIVILEGED_ROLE_NAMES),
    }
    # A failed read would turn into zero standing admins, so no figures are given unless every read succeeded.
    if not complete:
        return results, {"pim_available": None, "collection_complete": False}
    return results, {"collection_complete": True, **summarize(eligible_records, active_records, policy_records)}


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("azure", "msgraph", "kiota", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        tenant: Dict[str, Any] = {"tenant_source": "unresolved"}
        results: Dict[str, Any] = {}
        summary: Dict[str, Any] = {}
    else:
        tenant, definitions, eligible, active, policies, unlicensed = asyncio.run(_collect(collector, cred))
        results, summary = build(definitions, eligible, active, policies, unlicensed)

    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results=results,
        summary=summary,
    )
    path = write_evidence(output_dir, f"{NAME}_{tenant_filename_key(tenant)}.json", evidence)
    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
