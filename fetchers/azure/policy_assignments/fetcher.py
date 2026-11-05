#!/usr/bin/env python3
"""
Azure Policy assignments in effect on one subscription — its own and the ones
inherited from a management group.

Prowler's prowler/providers/azure/services/policy/policy_service.py (Apache-2.0) keeps
only `id`, `name` and `enforcement_mode`, and its single check asserts that the
SecurityCenterBuiltIn assignment is enforcing. This fetcher goes past that: the scope
and notScopes, the parameters, the assignment identity, the resolved definition
(display name, BuiltIn / Custom / Static) and the summary are ours. Resolution is
best-effort by design — a management-group-scoped custom definition is frequently
unreadable with subscription-scoped Reader and the assignment record is complete
without it, so a failed lookup is reported as `policy_definition.status: "unavailable"`
and does NOT fail the run. Every other API call here is guarded normally.

`enforced` says only that enforcementMode is Default. Whether an assignment can change
anything is the definition's EFFECT: an enforced assignment of an audit-effect policy
blocks nothing. So each assignment also carries `policy_effects` — the effect of its
definition, or of every member of its initiative, resolved through the parameter chain
(assignment value, then initiative default, then definition default) — and
`actually_enforces`, which needs both an enforcing effect and enforcementMode Default.
Resolution is best-effort in the same way as the display name.

Policy exemptions (Microsoft.Authorization/policyExemptions, Defender recommendation
exemptions included) exist only in preview api-versions, which the stable SDK does not
ship, so they are listed by a raw ARM GET pinned to EXEMPTIONS_API_VERSION.
"""

import logging
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from arm_rest import arm_rest_client, list_all  # noqa: E402
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    dig,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
)
from resource_exclusions import ResourceExclusions  # noqa: E402

logger = logging.getLogger("azure_policy_assignments")

# enforcementMode. "Default" enforces the effect (deny / deployIfNotExists act);
# "DoNotEnforce" is the portal's "Disabled" — still evaluates, changes nothing. ARM omits
# the field at its "Default" service default, so absent reads as enforced.
ENFORCED_MODE = "default"

# Defender for Cloud's own subscription-scope assignment — the only one Prowler's policy
# check looks at.
SECURITY_CENTER_BUILTIN_ASSIGNMENT = "SecurityCenterBuiltIn"

# policy_definition.status values.
RESOLVED = "resolved"
UNAVAILABLE = "unavailable"
UNSUPPORTED = "unsupported"

# An assignment points at one definition or at an initiative (policy set) bundling many.
# Matched case-insensitively: ARM returns the path upper-cased for some management-group
# assignments (confirmed live).
DEFINITION_SEGMENT = "policydefinitions"
SET_DEFINITION_SEGMENT = "policysetdefinitions"
DEFINITION_KIND = "policy_definition"
SET_DEFINITION_KIND = "policy_set_definition"

# Where the referenced definition lives, which decides WHICH getter can read it.
BUILT_IN_SCOPE = "built_in"
SUBSCRIPTION_SCOPE = "subscription"
MANAGEMENT_GROUP_SCOPE = "management_group"
UNKNOWN_SCOPE = "unknown"

# Policy effects, keyed by their lower-case form: ARM compares effects
# case-insensitively and definitions spell them every way ("Deny", "deny",
# "DeployIfNotExists"), so the evidence carries one canonical spelling.
CANONICAL_EFFECTS = {
    "deny": "deny",
    "denyaction": "denyAction",
    "modify": "modify",
    "deployifnotexists": "deployIfNotExists",
    "append": "append",
    "mutate": "mutate",
    "addtonetworkgroup": "addToNetworkGroup",
    "enforcesetting": "enforceSetting",
    "audit": "audit",
    "auditaction": "auditAction",
    "auditifnotexists": "auditIfNotExists",
    "manual": "manual",
    "disabled": "disabled",
}
# The effects that change or block a request, or remediate a resource. `append` and
# `denyAction` are included: they alter or refuse the request just as deny/modify do.
# mutate, addToNetworkGroup and enforceSetting change the resource's configuration.
ENFORCING_EFFECTS = frozenset(
    {"deny", "denyAction", "modify", "deployIfNotExists", "append", "mutate",
     "addToNetworkGroup", "enforceSetting"}
)
# The effects that only report. `manual` is attestation, which enforces nothing.
AUDIT_EFFECTS = frozenset({"audit", "auditAction", "auditIfNotExists", "manual"})
DISABLED_EFFECT = "disabled"
UNRESOLVED_EFFECT = "unresolved"

# Assignment-level effect classes (`effect_class`).
EFFECT_CLASS_ENFORCING = "enforcing"
EFFECT_CLASS_AUDIT_ONLY = "audit_only"
EFFECT_CLASS_DISABLED = "disabled"
EFFECT_CLASS_UNRESOLVED = "unresolved"

# Where a resolved effect's value came from (`effect_source`).
SOURCE_LITERAL = "literal"
SOURCE_ASSIGNMENT = "assignment_parameter"
SOURCE_INITIATIVE_REFERENCE = "initiative_reference"
SOURCE_INITIATIVE_DEFAULT = "initiative_default"
SOURCE_DEFINITION_DEFAULT = "definition_default"

# "[parameters('effect')]" — the one expression form the effect chain can follow.
# Anything else ("[if(...)]", a concat) is reported as unresolved with its raw text.
PARAMETER_REFERENCE = re.compile(r"^\[\s*parameters\(\s*'([^']+)'\s*\)\s*\]$", re.IGNORECASE)

# Exemptions have no GA api-version; ARM refusing this one reads as unknown, not as none.
EXEMPTIONS_API_VERSION = "2024-12-01-preview"
API_VERSION_REFUSAL_CODES = {"invalidapiversionparameter", "noregisteredproviderfound", "invalidresourcetype"}
ARM_CODE_PREFIX = re.compile(r"^\s*\((\w+)\)")
EXEMPTION_SEGMENT = "/providers/microsoft.authorization/policyexemptions/"
CANONICAL_CATEGORIES = {"waiver": "Waiver", "mitigated": "Mitigated"}

# lifts_enforcement_unknown_reason values.
LIFT_ASSIGNMENTS_UNREAD = "assignments_unread"
LIFT_ASSIGNMENT_NOT_LISTED = "assignment_not_listed"
LIFT_INITIATIVE_UNREAD = "initiative_members_unread"
LIFT_MEMBER_NOT_IN_INITIATIVE = "member_not_in_initiative"
LIFT_EFFECT_UNRESOLVED = "effect_unresolved"
EXPIRING_SOON_DAYS = 30
EXCLUDED_KINDS = ("policy_exemption",)

# exemptions_read_status values.
EXEMPTIONS_READ = "read"
EXEMPTIONS_FAILED = "failed"
EXEMPTIONS_API_UNAVAILABLE = "api_version_unavailable"
EXEMPTIONS_NOT_READ = "not_read"
FRACTION = re.compile(r"(\.\d{6})\d+")


# --- projection: the only azure-mgmt model access ---

def _parameter_values(parameters) -> dict:
    """Unwrap {name: ParameterValuesValue} into a plain {name: value} map.

    The SDK wraps every assignment parameter in a one-field model, so a raw projection
    would write the model's repr (`{"tagName": {}}`) into the evidence, not the value.
    """
    if not parameters:
        return {}
    values = {}
    for name, holder in parameters.items():
        value = model_attr(holder, "value")
        if value is None and hasattr(holder, "get"):
            value = holder.get("value")
        values[str(name)] = value
    return values


def project_policy_assignment(assignment) -> dict:
    """Read a `PolicyAssignment` model's attributes into a flat snake_case dict.

    `enforcement_mode` is an SDK `str` enum, which `model_attr` unwraps to
    "Default"/"DoNotEnforce" — left wrapped, the evidence would carry
    "EnforcementMode.DEFAULT" and the comparison below would silently stop matching.
    """
    identity = model_attr(assignment, "identity")
    return {
        "id": model_attr(assignment, "id"),
        "name": model_attr(assignment, "name"),
        "type": model_attr(assignment, "type"),
        "display_name": model_attr(assignment, "display_name"),
        "description": model_attr(assignment, "description"),
        "policy_definition_id": model_attr(assignment, "policy_definition_id"),
        "scope": model_attr(assignment, "scope"),
        "not_scopes": model_attr(assignment, "not_scopes"),
        "enforcement_mode": model_attr(assignment, "enforcement_mode"),
        "parameters": _parameter_values(model_attr(assignment, "parameters")),
        "location": model_attr(assignment, "location"),
        "identity_type": model_attr(identity, "type"),
    }


def _get_ci(mapping, key):
    """Case-insensitive dict read — policy rule keys and parameter names are both."""
    if not isinstance(mapping, dict):
        return None
    if key in mapping:
        return mapping[key]
    lowered = str(key).lower()
    for name, value in mapping.items():
        if str(name).lower() == lowered:
            return value
    return None


def _parameter_defaults(parameters) -> dict:
    """{name: defaultValue} from a definition's {name: ParameterDefinitionsValue}.

    A parameter with no default maps to None, so "declared without a default" and "not
    declared" stay distinguishable (`in` vs a None value).
    """
    if not parameters:
        return {}
    defaults = {}
    for name, holder in parameters.items():
        value = model_attr(holder, "default_value")
        if value is None and hasattr(holder, "get"):
            value = holder.get("defaultValue")
        defaults[str(name)] = value
    return defaults


def project_policy_definition(definition) -> dict:
    """Read a `PolicyDefinition` / `PolicySetDefinition` into a flat dict. `policy_type` is
    an SDK `str` enum ("BuiltIn", "Custom", "Static") that `model_attr` unwraps.

    `effect_expression` is the raw `policyRule.then.effect` (a literal or a
    "[parameters('...')]" reference), `parameter_defaults` the definition's declared
    defaults, and `members` an initiative's definition references with the parameter
    values it passes each one. `policy_rule` arrives as a plain dict on every SDK
    generation — it is free-form JSON in the API — so it is read with dict access.
    None of these reach the evidence's `policy_definition` block; they feed the effect
    resolution.
    """
    rule = model_attr(definition, "policy_rule")
    members = []
    for reference in model_attr(definition, "policy_definitions") or []:
        members.append(
            {
                "reference_id": model_attr(reference, "policy_definition_reference_id"),
                "policy_definition_id": model_attr(reference, "policy_definition_id"),
                "parameters": _parameter_values(model_attr(reference, "parameters")),
            }
        )
    return {
        "display_name": model_attr(definition, "display_name"),
        "policy_type": model_attr(definition, "policy_type"),
        "description": model_attr(definition, "description"),
        "effect_expression": _get_ci(_get_ci(rule, "then"), "effect"),
        "parameter_defaults": _parameter_defaults(model_attr(definition, "parameters")),
        "members": members,
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def parse_definition_reference(definition_id) -> dict:
    """Work out what a `policyDefinitionId` points at and which getter can read it.

    The same field carries five shapes:
      /providers/Microsoft.Authorization/policyDefinitions/<name>          built-in
      /providers/Microsoft.Authorization/policySetDefinitions/<name>       built-in initiative
      /subscriptions/<sub>/providers/.../policyDefinitions/<name>          subscription custom
      /providers/Microsoft.Management/managementGroups/<mg>/providers/...  MG custom
      (anything else)                                                     unknown
    """
    segments = [s for s in str(definition_id or "").split("/") if s]
    lowered = [s.lower() for s in segments]

    kind, name = None, None
    for index, segment in enumerate(lowered):
        if segment in (DEFINITION_SEGMENT, SET_DEFINITION_SEGMENT) and index + 1 < len(segments):
            kind = DEFINITION_KIND if segment == DEFINITION_SEGMENT else SET_DEFINITION_KIND
            name = segments[index + 1]
            break

    scope_kind, management_group_id, subscription_id = UNKNOWN_SCOPE, None, None
    if lowered[:1] == ["subscriptions"] and len(segments) > 1:
        scope_kind, subscription_id = SUBSCRIPTION_SCOPE, segments[1]
    elif lowered[:3] == ["providers", "microsoft.management", "managementgroups"] and (
        len(segments) > 3
    ):
        scope_kind, management_group_id = MANAGEMENT_GROUP_SCOPE, segments[3]
    elif lowered[:2] == ["providers", "microsoft.authorization"]:
        scope_kind = BUILT_IN_SCOPE

    return {
        "kind": kind,
        "name": name,
        "source_scope": scope_kind,
        "management_group_id": management_group_id,
        "subscription_id": subscription_id,
    }


def scope_kind(scope) -> str:
    """Classify an assignment's own scope: subscription, resource group, MG, resource."""
    segments = [s.lower() for s in str(scope or "").split("/") if s]
    if segments[:1] == ["providers"] and segments[1:3] == ["microsoft.management", "managementgroups"]:
        return MANAGEMENT_GROUP_SCOPE
    if segments[:1] == ["subscriptions"]:
        if len(segments) == 2:
            return SUBSCRIPTION_SCOPE
        if len(segments) == 4 and segments[2] == "resourcegroups":
            return "resource_group"
        return "resource"
    return UNKNOWN_SCOPE


def definition_block(status: str, reference: dict, definition: dict | None, reason=None) -> dict:
    """The resolved-definition block, in one shape whether or not the lookup worked."""
    definition = definition or {}
    return {
        "status": status,
        "reason": " ".join(str(reason).split())[:200] if reason else None,
        "kind": reference.get("kind"),
        "name": reference.get("name"),
        "source_scope": reference.get("source_scope"),
        "display_name": definition.get("display_name"),
        "policy_type": definition.get("policy_type"),
    }


def canonical_effect(value):
    """A resolved effect value in its canonical spelling, or None if it is not one."""
    if not isinstance(value, str):
        return None
    return CANONICAL_EFFECTS.get(value.strip().lower())


def parameter_reference(value):
    """The parameter name in "[parameters('name')]", else None."""
    if not isinstance(value, str):
        return None
    match = PARAMETER_REFERENCE.match(value.strip())
    return match.group(1) if match else None


def _has_ci(mapping: dict, key: str) -> bool:
    return any(str(name).lower() == str(key).lower() for name in (mapping or {}))


def _is_expression(value) -> bool:
    return isinstance(value, str) and value.strip().startswith("[")


def _resolved(value, source):
    effect = canonical_effect(value)
    if effect is None:
        return UNRESOLVED_EFFECT, None, f"unknown effect value {value!r}"[:200]
    return effect, source


def resolve_definition_effect(
    definition: dict | None,
    assignment_parameters: dict,
    reference_parameters: dict | None = None,
    initiative_defaults: dict | None = None,
) -> dict:
    """Follow a definition's effect through the parameter chain to a concrete value.

    A single definition assigned directly reads its parameter from the assignment,
    else the definition's default. An initiative member is one hop longer: the
    initiative passes the member a value (`reference_parameters`), usually itself
    "[parameters('<initiative param>')]", which then reads from the assignment, else
    the initiative's default. A member parameter the initiative does not pass falls
    back to the member definition's own default. Returns the effect, where it came
    from, and the raw expression, so an unresolved one says why.
    """
    if not definition:
        return {"effect": UNRESOLVED_EFFECT, "effect_source": None, "effect_expression": None,
                "reason": "definition not readable"}
    expression = definition.get("effect_expression")
    record = {"effect_expression": expression, "reason": None}

    def _done(effect, source, reason=None):
        return {**record, "effect": effect, "effect_source": source,
                "reason": reason if effect == UNRESOLVED_EFFECT else None}

    if expression is not None and not _is_expression(expression):
        return _done(*_resolved(expression, SOURCE_LITERAL))
    name = parameter_reference(expression)
    if name is None:
        return _done(UNRESOLVED_EFFECT, None, "effect is not a literal or a parameter reference")

    defaults = definition.get("parameter_defaults") or {}
    if reference_parameters is None:
        # Assigned directly: the assignment's value, else the definition's default.
        if _has_ci(assignment_parameters, name):
            return _done(*_resolved(_get_ci(assignment_parameters, name), SOURCE_ASSIGNMENT))
        if _get_ci(defaults, name) is not None:
            return _done(*_resolved(_get_ci(defaults, name), SOURCE_DEFINITION_DEFAULT))
        return _done(UNRESOLVED_EFFECT, None, f"parameter '{name}' has no value or default")

    # An initiative member.
    if not _has_ci(reference_parameters, name):
        if _get_ci(defaults, name) is not None:
            return _done(*_resolved(_get_ci(defaults, name), SOURCE_DEFINITION_DEFAULT))
        return _done(UNRESOLVED_EFFECT, None, f"parameter '{name}' has no value or default")
    passed = _get_ci(reference_parameters, name)
    if not _is_expression(passed):
        return _done(*_resolved(passed, SOURCE_INITIATIVE_REFERENCE))
    outer = parameter_reference(passed)
    if outer is None:
        return _done(UNRESOLVED_EFFECT, None, "initiative passes an expression, not a parameter")
    if _has_ci(assignment_parameters, outer):
        return _done(*_resolved(_get_ci(assignment_parameters, outer), SOURCE_ASSIGNMENT))
    if _get_ci(initiative_defaults or {}, outer) is not None:
        return _done(*_resolved(_get_ci(initiative_defaults, outer), SOURCE_INITIATIVE_DEFAULT))
    return _done(UNRESOLVED_EFFECT, None, f"initiative parameter '{outer}' has no value or default")


def effect_class(member_effects: list[str], enforced: bool) -> str:
    """Classify an assignment by what its effects can actually do.

    enforcementMode DoNotEnforce evaluates every effect but acts on none, so any
    non-disabled effect under it is audit-only. Under Default, one enforcing member
    makes the assignment enforcing. Only resolved effects count; with none resolved,
    or with unresolved members and nothing but `disabled` resolved, the class is
    unresolved rather than a guess.
    """
    resolved = [e for e in member_effects if e != UNRESOLVED_EFFECT]
    if not resolved:
        return EFFECT_CLASS_UNRESOLVED
    active = [e for e in resolved if e != DISABLED_EFFECT]
    if not active:
        return (
            EFFECT_CLASS_UNRESOLVED
            if len(resolved) < len(member_effects)
            else EFFECT_CLASS_DISABLED
        )
    if enforced and any(e in ENFORCING_EFFECTS for e in active):
        return EFFECT_CLASS_ENFORCING
    return EFFECT_CLASS_AUDIT_ONLY


def effects_block(
    assignment: dict, reference: dict, definition: dict | None, members: list[dict] | None
) -> dict:
    """The assignment's `policy_effects`: one member for a definition, N for an initiative.

    `members` are the initiative's references, each already paired with its looked-up
    member definition (`definition` key); None for a single-definition assignment.
    """
    params = assignment.get("parameters") or {}
    rows = []
    if reference.get("kind") == DEFINITION_KIND:
        rows.append(
            {
                "reference_id": None,
                "policy_definition_name": reference.get("name"),
                "display_name": (definition or {}).get("display_name"),
                **resolve_definition_effect(definition, params),
            }
        )
    elif reference.get("kind") == SET_DEFINITION_KIND and definition:
        initiative_defaults = definition.get("parameter_defaults") or {}
        for member in members or []:
            member_definition = member.get("definition")
            rows.append(
                {
                    "reference_id": member.get("reference_id"),
                    "policy_definition_name": parse_definition_reference(
                        member.get("policy_definition_id")
                    ).get("name"),
                    "display_name": (member_definition or {}).get("display_name"),
                    **resolve_definition_effect(
                        member_definition,
                        params,
                        reference_parameters=member.get("parameters") or {},
                        initiative_defaults=initiative_defaults,
                    ),
                }
            )
    effects = [row["effect"] for row in rows]
    counts = {name: 0 for name in sorted(set(CANONICAL_EFFECTS.values()))}
    counts[UNRESOLVED_EFFECT] = 0
    for effect in effects:
        counts[effect] = counts.get(effect, 0) + 1
    unresolved = counts[UNRESOLVED_EFFECT]
    klass = effect_class(effects, assignment.get("enforced", True))
    return {
        "status": (
            UNAVAILABLE if not rows or unresolved == len(rows)
            else "partial" if unresolved else RESOLVED
        ),
        "effect_class": klass,
        "member_count": len(rows),
        "resolved_member_count": len(rows) - unresolved,
        "enforcing_member_count": sum(1 for e in effects if e in ENFORCING_EFFECTS),
        "audit_member_count": sum(1 for e in effects if e in AUDIT_EFFECTS),
        "disabled_member_count": counts[DISABLED_EFFECT],
        "effect_counts": counts,
        "members": sorted(
            rows, key=lambda r: (r.get("reference_id") or "", r.get("policy_definition_name") or "")
        ),
    }


def apply_effects(record: dict, block: dict) -> None:
    """Attach the effects block and its two headline fields to an assignment record."""
    record["policy_effects"] = block
    record["effect_class"] = block["effect_class"]
    record["actually_enforces"] = block["effect_class"] == EFFECT_CLASS_ENFORCING
    # Enforcing effects that enforcementMode DoNotEnforce is holding back.
    record["enforcing_effects_not_enforced"] = (
        not record.get("enforced", True) and block["enforcing_member_count"] > 0
    )


def assignment_record(assignment: dict) -> dict:
    """Normalize one projected policy assignment into an evidence record.

    `enforced` is the fact Prowler's one check asserts, made an explicit boolean so a
    validator need not know that "Default" enforces and "DoNotEnforce" is audit-only. An
    absent enforcement_mode reads as enforced: ARM omits the field at its service default.
    """
    scope = assignment.get("scope")
    mode = assignment.get("enforcement_mode")
    reference = parse_definition_reference(assignment.get("policy_definition_id"))
    kind = scope_kind(scope)
    return {
        "id": assignment.get("id"),
        "name": assignment.get("name"),
        "display_name": assignment.get("display_name"),
        "description": assignment.get("description"),
        "policy_definition_id": assignment.get("policy_definition_id"),
        "scope": scope,
        "scope_kind": kind,
        # A management-group assignment shows up in every subscription under it; this
        # keeps "we assigned this" separate from "this reached us".
        "inherited_from_management_group": kind == MANAGEMENT_GROUP_SCOPE,
        "not_scopes": list(assignment.get("not_scopes") or []),
        "excluded_scope_count": len(assignment.get("not_scopes") or []),
        "parameters": assignment.get("parameters") or {},
        "enforcement_mode": mode,
        "enforced": str(mode or ENFORCED_MODE).lower() == ENFORCED_MODE,
        "assignment_identity_type": assignment.get("identity_type"),
        "location": assignment.get("location"),
        # Filled in by the definition enrichment; always present, so the evidence never
        # has two layouts to read.
        "policy_definition": definition_block(UNAVAILABLE, reference, None, "not resolved"),
        # Filled in by the effect resolution; present from the start for the same reason.
        "effect_class": EFFECT_CLASS_UNRESOLVED,
        "actually_enforces": False,
        "enforcing_effects_not_enforced": False,
        "policy_effects": None,
    }


def summarize(assignments: list[dict] | None) -> dict:
    """Enforcement coverage plus what kind of governance is actually assigned; all null when unlisted."""
    if assignments is None:
        return dict.fromkeys(summarize([]), None)
    total = len(assignments)
    enforced = sum(1 for a in assignments if a["enforced"])
    return {
        "total_policy_assignments": total,
        "enforced_assignments": enforced,
        "audit_only_assignments": total - enforced,
        "enforced_percentage": coverage_percentage(enforced, total),
        "initiative_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "kind") == SET_DEFINITION_KIND
        ),
        "single_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "kind") == DEFINITION_KIND
        ),
        "built_in_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "policy_type") == "BuiltIn"
        ),
        "custom_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "policy_type") == "Custom"
        ),
        "unresolved_definition_assignments": sum(
            1 for a in assignments if dig(a, "policy_definition", "status") != RESOLVED
        ),
        "subscription_scoped_assignments": sum(
            1 for a in assignments if a["scope_kind"] == SUBSCRIPTION_SCOPE
        ),
        "resource_group_scoped_assignments": sum(
            1 for a in assignments if a["scope_kind"] == "resource_group"
        ),
        "inherited_assignments": sum(
            1 for a in assignments if a["inherited_from_management_group"]
        ),
        "assignments_with_excluded_scopes": sum(
            1 for a in assignments if a["excluded_scope_count"] > 0
        ),
        "assignments_with_parameters": sum(1 for a in assignments if a["parameters"]),
        # Prowler's single policy check, in two fields.
        "security_center_builtin_assigned": any(
            a["name"] == SECURITY_CENTER_BUILTIN_ASSIGNMENT for a in assignments
        ),
        "security_center_builtin_enforced": any(
            a["name"] == SECURITY_CENTER_BUILTIN_ASSIGNMENT and a["enforced"]
            for a in assignments
        ),
        **summarize_effects(assignments),
    }


def summarize_effects(assignments: list[dict]) -> dict:
    """What the assignments can DO, by effect — beside `enforced_assignments`, not instead.

    New keys throughout: `audit_only_assignments` already means enforcementMode
    DoNotEnforce, which is a different fact from "every effect is audit".
    """
    total = len(assignments)
    by_class = {
        klass: 0
        for klass in (
            EFFECT_CLASS_ENFORCING,
            EFFECT_CLASS_AUDIT_ONLY,
            EFFECT_CLASS_DISABLED,
            EFFECT_CLASS_UNRESOLVED,
        )
    }
    member_counts: dict[str, int] = {}
    unresolved_not_enforced = 0
    for assignment in assignments:
        by_class[assignment["effect_class"]] = by_class.get(assignment["effect_class"], 0) + 1
        for effect, count in ((assignment.get("policy_effects") or {}).get("effect_counts") or {}).items():
            member_counts[effect] = member_counts.get(effect, 0) + count
            if effect == UNRESOLVED_EFFECT and not assignment["enforced"]:
                unresolved_not_enforced += count
    actually = by_class[EFFECT_CLASS_ENFORCING]
    return {
        "actually_enforcing_assignments": actually,
        "actually_enforcing_percentage": coverage_percentage(actually, total),
        "audit_effect_only_assignments": by_class[EFFECT_CLASS_AUDIT_ONLY],
        "disabled_effect_assignments": by_class[EFFECT_CLASS_DISABLED],
        "unresolved_effect_assignments": by_class[EFFECT_CLASS_UNRESOLVED],
        "assignments_by_effect_class": by_class,
        "enforcing_effects_not_enforced_assignments": sum(
            1 for a in assignments if a["enforcing_effects_not_enforced"]
        ),
        # Across every assignment's members; an initiative assigned twice counts twice.
        "member_policy_effect_counts": dict(sorted(member_counts.items())),
        # Unresolved members, which effect_class and enforcing_effects_not_enforced ignore.
        "unresolved_member_policies": member_counts.get(UNRESOLVED_EFFECT, 0),
        "unresolved_member_policies_not_enforced": unresolved_not_enforced,
    }


# --- policy exemptions (wire JSON in, evidence records out) ---

def project_policy_exemption(item: dict) -> dict:
    """Flatten one policyExemptions list item (raw ARM JSON, not an SDK model)."""
    props = item.get("properties") or {}
    system = item.get("systemData") or {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "display_name": props.get("displayName"),
        "description": props.get("description"),
        "policy_assignment_id": props.get("policyAssignmentId"),
        "policy_definition_reference_ids": list(props.get("policyDefinitionReferenceIds") or []),
        "exemption_category": props.get("exemptionCategory"),
        "expires_on": props.get("expiresOn"),
        "metadata": props.get("metadata"),
        "assignment_scope_validation": props.get("assignmentScopeValidation"),
        "resource_selectors": list(props.get("resourceSelectors") or []),
        "created_by": system.get("createdBy"),
        "created_by_type": system.get("createdByType"),
        "created_at": system.get("createdAt"),
        "last_modified_by": system.get("lastModifiedBy"),
        "last_modified_at": system.get("lastModifiedAt"),
    }


def exemption_scope(exemption_id) -> str | None:
    """The scope an exemption was made at: its id up to /providers/Microsoft.Authorization/policyExemptions/."""
    text = str(exemption_id or "")
    index = text.lower().rfind(EXEMPTION_SEGMENT)
    if index < 0:
        return None
    return text[:index] or None


def parse_time(value) -> datetime | None:
    """An ARM timestamp as an aware UTC datetime; ARM writes up to 7 fractional digits."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(FRACTION.sub(r"\1", value.strip()).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _arm_id_key(value) -> str:
    return str(value or "").lower().rstrip("/")


def canonical_category(value):
    """Waiver or Mitigated in that spelling; ARM accepts any case and returns it as stored."""
    return CANONICAL_CATEGORIES.get(str(value or "").strip().lower(), value)


def _initiative_members(assignment: dict | None) -> dict | None:
    """The assignment's initiative members by lower-cased reference id; None when they weren't read."""
    block = (assignment or {}).get("policy_effects") or {}
    if dig(assignment or {}, "policy_definition", "kind") != SET_DEFINITION_KIND or not block.get("member_count"):
        return None
    return {str(m.get("reference_id") or "").lower(): m for m in block.get("members") or [] if m.get("reference_id")}


def _exempted_members(reference_ids: list, assignment: dict | None) -> list[dict]:
    """Each exempted initiative member, joined to the assignment's resolved member by reference id.

    `in_initiative` is False for a reference id the initiative's current definition doesn't have: a member since
    removed, or one in an older version the assignment still uses.
    """
    members = _initiative_members(assignment)
    rows = []
    for reference_id in reference_ids:
        member = (members or {}).get(str(reference_id).lower()) or {}
        rows.append({
            "reference_id": reference_id,
            "in_initiative": None if members is None else bool(member),
            "policy_definition_name": member.get("policy_definition_name"),
            "display_name": member.get("display_name"),
            "effect": member.get("effect"),
        })
    return rows


def _lifts_enforcement(whole: bool, members: list[dict], assignment: dict | None, found) -> tuple:
    """(True when the exemption covers an enforcing effect of an enforced assignment, False when it can't, None
    when unknown; why it is unknown)."""
    if found is None:
        return None, LIFT_ASSIGNMENTS_UNREAD
    if assignment is None:
        return None, LIFT_ASSIGNMENT_NOT_LISTED
    if not assignment.get("enforced", True):
        return False, None
    if whole:
        block = assignment.get("policy_effects") or {}
        if block.get("enforcing_member_count"):
            return True, None
        return (False, None) if block and block.get("status") == RESOLVED else (None, LIFT_EFFECT_UNRESOLVED)
    if any(m.get("effect") in ENFORCING_EFFECTS for m in members):
        return True, None
    for reason, unknown in (
        (LIFT_INITIATIVE_UNREAD, lambda m: m.get("in_initiative") is None),
        (LIFT_MEMBER_NOT_IN_INITIATIVE, lambda m: m.get("in_initiative") is False),
        (LIFT_EFFECT_UNRESOLVED, lambda m: m.get("effect") in (None, UNRESOLVED_EFFECT)),
    ):
        if any(unknown(m) for m in members):
            return None, reason
    return False, None


def exemption_record(exemption: dict, assignments_by_id: dict | None, now: datetime) -> dict:
    """Normalize one projected exemption, joined to the assignment it exempts.

    `assignments_by_id` is None when the assignment list could not be read, which makes
    every assignment-derived field unknown rather than "not found".
    """
    scope = exemption_scope(exemption.get("id"))
    kind = scope_kind(scope)
    assignment_id = exemption.get("policy_assignment_id")
    assignment = (assignments_by_id or {}).get(_arm_id_key(assignment_id))
    found = None if assignments_by_id is None else assignment is not None
    reference_ids = exemption.get("policy_definition_reference_ids") or []
    whole = not reference_ids
    members = [] if whole else _exempted_members(reference_ids, assignment)
    if whole:
        member_count = ((assignment or {}).get("policy_effects") or {}).get("member_count")
    else:
        member_count = len(reference_ids)
    assignment_name = str(assignment_id or "").rstrip("/").rsplit("/", 1)[-1] or None
    lifts, lift_reason = _lifts_enforcement(whole, members, assignment, found)
    expires = parse_time(exemption.get("expires_on"))
    no_expiry = not exemption.get("expires_on")
    days_left = None if expires is None else math.floor((expires - now).total_seconds() / 86400)
    return {
        "id": exemption.get("id"),
        "name": exemption.get("name"),
        "display_name": exemption.get("display_name"),
        "description": exemption.get("description"),
        "scope": scope,
        "scope_kind": kind,
        "inherited_from_management_group": kind == MANAGEMENT_GROUP_SCOPE,
        "policy_assignment_id": assignment_id,
        "policy_assignment_name": assignment_name,
        "assignment_found": found,
        "assignment_display_name": (assignment or {}).get("display_name"),
        "on_defender_benchmark_assignment": (
            str(assignment_name or "").lower() == SECURITY_CENTER_BUILTIN_ASSIGNMENT.lower()
        ),
        "exemption_category": canonical_category(exemption.get("exemption_category")),
        "policy_definition_reference_ids": reference_ids,
        "exempts_whole_assignment": whole,
        "exempted_member_count": member_count,
        "exempted_members": members,
        "names_members_not_in_initiative": any(m["in_initiative"] is False for m in members),
        "lifts_enforcement": lifts,
        "lifts_enforcement_unknown_reason": lift_reason,
        "expires_on": exemption.get("expires_on"),
        "no_expiry": no_expiry,
        # An expiry that doesn't parse leaves expired unknown, never false.
        "expired": None if expires is None and not no_expiry else (expires is not None and expires <= now),
        "days_until_expiry": days_left,
        "metadata": exemption.get("metadata"),
        "assignment_scope_validation": exemption.get("assignment_scope_validation"),
        "resource_selectors": exemption.get("resource_selectors") or [],
        "created_by": exemption.get("created_by"),
        "created_by_type": exemption.get("created_by_type"),
        "created_at": exemption.get("created_at"),
        "last_modified_by": exemption.get("last_modified_by"),
        "last_modified_at": exemption.get("last_modified_at"),
    }


def apply_exemption_counts(assignments: list[dict], exemptions: list[dict] | None) -> None:
    """Each assignment's in-scope exemption count; null when the exemptions were not read."""
    counts: dict[str, int] = {}
    for exemption in exemptions or []:
        key = _arm_id_key(exemption.get("policy_assignment_id"))
        counts[key] = counts.get(key, 0) + 1
    for assignment in assignments:
        assignment["exemption_count"] = (
            None if exemptions is None else counts.get(_arm_id_key(assignment.get("id")), 0)
        )


def summarize_exemptions(exemptions: list[dict] | None, status: str) -> dict:
    """Exemption counts over the in-scope exemptions; every count is null when they were not read."""
    known = exemptions is not None
    rows = exemptions or []

    def count(predicate):
        return sum(1 for e in rows if predicate(e)) if known else None

    by_scope = None
    if known:
        by_scope = {k: 0 for k in (MANAGEMENT_GROUP_SCOPE, SUBSCRIPTION_SCOPE, "resource_group", "resource",
                                   UNKNOWN_SCOPE)}
        for e in rows:
            by_scope[e["scope_kind"]] = by_scope.get(e["scope_kind"], 0) + 1
    unknown_assignments = any(e["assignment_found"] is None for e in rows)
    return {
        "exemptions_read_status": status,
        "exemptions_api_version": EXEMPTIONS_API_VERSION,
        "total_policy_exemptions": len(rows) if known else None,
        "waiver_exemptions": count(lambda e: e["exemption_category"] == "Waiver"),
        "mitigated_exemptions": count(lambda e: e["exemption_category"] == "Mitigated"),
        "active_exemptions": count(lambda e: e["expired"] is False),
        "expired_exemptions": count(lambda e: e["expired"] is True),
        "exemptions_with_unreadable_expiry": count(lambda e: e["expired"] is None),
        "exemptions_without_expiry": count(lambda e: e["no_expiry"]),
        f"exemptions_expiring_within_{EXPIRING_SOON_DAYS}_days": count(
            lambda e: e["expired"] is False and e["days_until_expiry"] is not None
            and e["days_until_expiry"] < EXPIRING_SOON_DAYS
        ),
        "whole_assignment_exemptions": count(lambda e: e["exempts_whole_assignment"]),
        "inherited_exemptions": count(lambda e: e["inherited_from_management_group"]),
        "exemptions_by_scope_kind": by_scope,
        "defender_benchmark_exemptions": count(lambda e: e["on_defender_benchmark_assignment"]),
        "active_exemptions_lifting_enforcement": (
            None if not known or unknown_assignments
            else count(lambda e: e["expired"] is False and e["lifts_enforcement"] is True)
        ),
        "exemptions_lifting_enforcement_unknown": count(lambda e: e["lifts_enforcement"] is None),
        "exemptions_naming_members_not_in_initiative": count(lambda e: e["names_members_not_in_initiative"]),
        "exemptions_of_unlisted_assignments": (
            None if not known or unknown_assignments else count(lambda e: e["assignment_found"] is False)
        ),
        "unlisted_assignments_with_exemptions": (
            len({_arm_id_key(e["policy_assignment_id"]) for e in rows if e["assignment_found"] is False})
            if known and not unknown_assignments else None
        ),
        "assignments_with_exemptions": (
            len({_arm_id_key(e["policy_assignment_id"]) for e in rows if e["assignment_found"]})
            if known and not unknown_assignments else None
        ),
    }


# --- collection (lazy azure imports) ---

def policy_client(cred, subscription_id):
    """Build a PolicyClient, tolerating the class's two remaining import paths.

    `azure.mgmt.resource.policy` is where the split-out `azure-mgmt-resource-policy`
    distribution puts it (and where azure-mgmt-resource <= 24.x also had it); the root
    re-export Prowler imports existed only through 24.x. azure-mgmt-resource 25.x and
    26.x ship neither — only `resources` — so this fetcher needs
    `azure-mgmt-resource-policy` installed alongside a modern azure-mgmt-resource.
    """
    try:
        from azure.mgmt.resource.policy import PolicyClient  # lazy
    except ImportError:  # pragma: no cover - depends on installed SDK version
        from azure.mgmt.resource import PolicyClient  # lazy

    return PolicyClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())


def _lookup_definition(client, reference: dict, subscription_id):
    """Read the referenced definition, or say why it could not be read.

    Returns (projected_definition | None, status, reason). Deliberately NOT routed through
    `Collector.guard`: failing the run over an enrichment lookup would turn a normal
    permission boundary into a red run.
    """
    kind, name, scope = reference.get("kind"), reference.get("name"), reference.get("source_scope")
    if not kind or not name:
        return None, UNSUPPORTED, "policy_definition_id is not a recognized definition reference"

    operations = (
        client.policy_definitions if kind == DEFINITION_KIND else client.policy_set_definitions
    )
    if scope == BUILT_IN_SCOPE:
        getter = lambda: operations.get_built_in(name)  # noqa: E731
    elif scope == MANAGEMENT_GROUP_SCOPE:
        getter = lambda: operations.get_at_management_group(  # noqa: E731
            reference["management_group_id"], name
        )
    elif scope == SUBSCRIPTION_SCOPE:
        if reference.get("subscription_id") != subscription_id:
            # The client is bound to one subscription; a definition custom to another one
            # is not reachable from here.
            return (
                None,
                UNSUPPORTED,
                f"definition is custom to subscription {reference.get('subscription_id')}",
            )
        getter = lambda: operations.get(name)  # noqa: E731
    else:
        return None, UNSUPPORTED, "definition reference scope not recognized"

    try:
        return project_policy_definition(getter()), RESOLVED, None
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        logger.warning(
            "policy.%s lookup failed for %s (%s) — reporting the assignment without "
            "the definition's display name: %s",
            "policy_definitions" if kind == DEFINITION_KIND else "policy_set_definitions",
            name,
            scope,
            " ".join(str(exc).split())[:200],
        )
        return None, UNAVAILABLE, exc


def _built_in_definitions(client) -> dict[str, dict]:
    """Every built-in policy definition, projected, keyed by lower-cased name.

    One paged list (about 3,700 definitions, a couple of seconds) instead of one GET per
    initiative member: a single Microsoft cloud security benchmark assignment has over
    200 members. Best-effort like the other lookups — on failure the members fall back
    to individual GETs.
    """
    try:
        return {
            str(model_attr(d, "name") or "").lower(): project_policy_definition(d)
            for d in client.policy_definitions.list_built_in()
        }
    except Exception as exc:  # noqa: BLE001 — boundary: enrichment only
        logger.warning(
            "policy.policy_definitions.list_built_in failed — resolving initiative members "
            "one at a time: %s",
            " ".join(str(exc).split())[:200],
        )
        return {}


def collect_policy_assignments(subscription_id, cred, collector: Collector) -> list[dict] | None:
    """One policy_assignments.list(), then one cached definition GET per definition.

    `list()` at subscription scope returns the subscription's own assignments AND the ones
    it inherits from its management groups — what "in effect here" means. Lookups are
    cached by definition id, so an initiative assigned five times costs one GET.

    Initiative members are then read to resolve effects: built-ins from one
    list_built_in(), anything else by the same getters as above, cached by id.
    """
    client = collector.guard("policy.PolicyClient (init)", lambda: policy_client(cred, subscription_id))
    if client is None:
        return None

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            assignment_record(project_policy_assignment(assignment))
            for assignment in client.policy_assignments.list()
        ]

    assignments = collector.guard("policy.policy_assignments.list", _list)
    if assignments is None:
        return None

    cache: dict[str, dict] = {}
    projected: dict[str, dict | None] = {}
    for assignment in assignments:
        definition_id = assignment.get("policy_definition_id") or ""
        if definition_id not in cache:
            reference = parse_definition_reference(definition_id)
            definition, status, reason = _lookup_definition(client, reference, subscription_id)
            cache[definition_id] = definition_block(status, reference, definition, reason)
            projected[definition_id] = definition
        assignment["policy_definition"] = cache[definition_id]

    # --- effects: read each initiative's members, then resolve per assignment ---
    has_initiative = any(
        (d or {}).get("members") for d in projected.values()
    )
    built_ins = _built_in_definitions(client) if has_initiative else {}
    member_cache: dict[str, dict | None] = {}

    def _member_definition(member_id: str):
        key = member_id.lower()
        if key not in member_cache:
            reference = parse_definition_reference(member_id)
            found = (
                built_ins.get(str(reference.get("name") or "").lower())
                if reference.get("source_scope") == BUILT_IN_SCOPE
                else None
            )
            if found is None:
                found, _, _ = _lookup_definition(client, reference, subscription_id)
            member_cache[key] = found
        return member_cache[key]

    for assignment in assignments:
        definition_id = assignment.get("policy_definition_id") or ""
        definition = projected.get(definition_id)
        reference = parse_definition_reference(definition_id)
        members = [
            {**member, "definition": _member_definition(member.get("policy_definition_id") or "")}
            for member in (definition or {}).get("members") or []
        ]
        apply_effects(assignment, effects_block(assignment, reference, definition, members))

    return sorted(assignments, key=lambda r: r.get("id") or "")


def _status_code(exc) -> int | None:
    return getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)


def _arm_error_code(exc) -> str:
    code = getattr(getattr(exc, "error", None), "code", None)
    if not code:
        match = ARM_CODE_PREFIX.match(str(exc))
        code = match.group(1) if match else ""
    return str(code)


def api_version_refused(exc) -> bool:
    return _status_code(exc) in (400, 404) and _arm_error_code(exc).lower() in API_VERSION_REFUSAL_CODES


def collect_policy_exemptions(subscription_id, cred, collector: Collector) -> tuple[list[dict] | None, str]:
    """Every exemption in effect on the subscription: its own, inherited, and those on anything inside it.

    The unfiltered list at subscription scope returns all three, expired ones included. Any error fails
    the run; ARM refusing the pinned preview api-version (InvalidApiVersionParameter,
    NoRegisteredProviderFound, InvalidResourceType) is told apart as api_version_unavailable.
    """
    def _list():
        client = arm_rest_client(cred)
        path = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyExemptions"
        return [project_policy_exemption(item) for item in list_all(client, path, EXEMPTIONS_API_VERSION)["items"]]

    try:
        return _list(), EXEMPTIONS_READ
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        collector.record("policy.policy_exemptions.list", exc)
        return None, EXEMPTIONS_API_UNAVAILABLE if api_version_refused(exc) else EXEMPTIONS_FAILED


def exemption_results(
    projected: list[dict] | None, assignments: list[dict] | None, exclusions: ResourceExclusions, now: datetime
) -> tuple[list[dict] | None, list[dict]]:
    """(in-scope exemption records or None, excluded entries). An exemption follows the scope it was made at:
    rg: and id: patterns match it through its own id; it carries no region, so location: never does."""
    if projected is None:
        return None, []
    kept, excluded = exclusions.split(projected, "policy_exemption", location=lambda e: None)
    by_id = None if assignments is None else {_arm_id_key(a.get("id")): a for a in assignments}
    records = [exemption_record(e, by_id, now) for e in kept]
    return sorted(records, key=lambda r: r.get("id") or ""), excluded


def boundary_summary(exclusions: ResourceExclusions, excluded: list[dict], exemptions: list[dict] | None) -> dict:
    """The patterns, the unmatched ones, and excluded / in-scope exemption counts, null when none were read."""
    in_scope = None if exemptions is None else len(exemptions)
    summary = exclusions.summary(excluded, EXCLUDED_KINDS, {"policy_exemptions": in_scope})
    if exemptions is None:
        summary["excluded_policy_exemptions"] = None
    return summary


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

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)

    listed: list[dict] | None = None
    projected_exemptions: list[dict] | None = None
    exemptions_status = EXEMPTIONS_NOT_READ
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Microsoft.Authorization is registered on every subscription in practice, but the
        # field is collected anyway so zero assignments reads as "no governance assigned".
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Authorization"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Authorization is not registered on subscription %s — "
                "reporting status not_registered",
                subscription_id,
            )
        listed = collect_policy_assignments(subscription_id, cred, collector)
        projected_exemptions, exemptions_status = collect_policy_exemptions(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    assignments = listed or []
    exemptions, excluded = exemption_results(projected_exemptions, listed, exclusions, datetime.now(timezone.utc))
    apply_exemption_counts(assignments, exemptions)
    exclusions.warn_unmatched(logger)
    boundary = boundary_summary(exclusions, excluded, exemptions)

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "policy_assignments": assignments,
            "policy_exemptions": exemptions,
            "provider_registration_status": registration,
            "excluded": excluded,
        },
        summary={
            **summarize(listed),
            **summarize_exemptions(exemptions, exemptions_status),
            "provider_registration_status": registration,
            **boundary,
        },
    )

    filename = (
        f"azure_policy_assignments_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
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
