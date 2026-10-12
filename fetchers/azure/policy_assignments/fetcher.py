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
"""

import logging
import re
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
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
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

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
    "audit": "audit",
    "auditifnotexists": "auditIfNotExists",
    "manual": "manual",
    "disabled": "disabled",
}
# The effects that change or block a request, or remediate a resource. `append` and
# `denyAction` are included: they alter or refuse the request just as deny/modify do.
ENFORCING_EFFECTS = frozenset({"deny", "denyAction", "modify", "deployIfNotExists", "append"})
# The effects that only report. `manual` is attestation, which enforces nothing.
AUDIT_EFFECTS = frozenset({"audit", "auditIfNotExists", "manual"})
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


def _resolved(value, source):
    effect = canonical_effect(value)
    if effect is None:
        return UNRESOLVED_EFFECT, None
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

    if canonical_effect(expression):
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
    if canonical_effect(passed):
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


def summarize(assignments: list[dict]) -> dict:
    """Enforcement coverage plus what kind of governance is actually assigned."""
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
    for assignment in assignments:
        by_class[assignment["effect_class"]] = by_class.get(assignment["effect_class"], 0) + 1
        for effect, count in ((assignment.get("policy_effects") or {}).get("effect_counts") or {}).items():
            member_counts[effect] = member_counts.get(effect, 0) + count
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


def collect_policy_assignments(subscription_id, cred, collector: Collector) -> list[dict]:
    """One policy_assignments.list(), then one cached definition GET per definition.

    `list()` at subscription scope returns the subscription's own assignments AND the ones
    it inherits from its management groups — what "in effect here" means. Lookups are
    cached by definition id, so an initiative assigned five times costs one GET.

    Initiative members are then read to resolve effects: built-ins from one
    list_built_in(), anything else by the same getters as above, cached by id.
    """
    client = collector.guard("policy.PolicyClient (init)", lambda: policy_client(cred, subscription_id))
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            assignment_record(project_policy_assignment(assignment))
            for assignment in client.policy_assignments.list()
        ]

    assignments = collector.guard("policy.policy_assignments.list", _list, default=[])

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

    assignments: list[dict] = []
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
        assignments = collect_policy_assignments(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "policy_assignments": assignments,
            "provider_registration_status": registration,
        },
        summary={**summarize(assignments), "provider_registration_status": registration},
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
