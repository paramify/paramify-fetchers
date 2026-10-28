#!/usr/bin/env python3
"""
Microsoft Entra ID Conditional Access policies

Every Conditional Access policy with its enforcement state, who and what it applies to,
who is excluded, and what it requires or blocks. A policy in
`enabledForReportingButNotEnforced` (report-only) logs what it WOULD have done and
enforces nothing, so the three states are reported separately, never merged.

Projections ported from Prowler's
prowler/providers/azure/services/entra/entra_service.py
`_get_conditional_access_policy` (Apache-2.0), with one deliberate DEVIATION in how
grant controls are split into grant vs. block — see `split_access_controls()`.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    report_failure,
    write_evidence,
)
from entra_graph import (  # noqa: E402
    aguard,
    graph_attr,
    graph_list,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_conditional_access_policies")

# conditionalAccessPolicyState, verbatim from Graph. Report-only is a THIRD state, not
# a flavor of enabled.
STATE_ENABLED = "enabled"
STATE_DISABLED = "disabled"
STATE_REPORT_ONLY = "enabledForReportingButNotEnforced"

# The only member of conditionalAccessGrantControl that denies access; every other is a
# requirement to satisfy — see `split_access_controls()`.
BLOCK_CONTROL = "block"

# Authentication-strength policies express the same intent through
# `grant_controls.authentication_strength` instead, and are handled separately.
MFA_CONTROLS = frozenset({"mfa"})

# Target-resource identifiers from Prowler's prowler/providers/azure/config.py: what
# Graph returns in conditions.applications.includeApplications for the two resources the
# CIS Azure benchmark names. MICROSOFT_ADMIN_PORTALS is a named app GROUP and comes back
# as this literal string, not as a GUID.
MICROSOFT_ADMIN_PORTALS = "MicrosoftAdminPortals"
WINDOWS_AZURE_SERVICE_MANAGEMENT_API = "797f4846-ba00-4fd7-ba43-dac1f8f63013"

# conditions.applications.includeApplications value meaning "every cloud app".
ALL_APPLICATIONS = "All"
# conditions.users.includeUsers value meaning "every user in the tenant".
ALL_USERS = "All"

# conditions.clientAppTypes values for the pre-modern-auth protocols, which cannot
# present an MFA challenge at all.
LEGACY_CLIENT_APP_TYPES = frozenset({"exchangeActiveSync", "other"})

# authenticationMethodModes bound to the sign-in origin, so a look-alike site can't relay them.
PHISHING_RESISTANT_MODES = frozenset({"fido2", "windowshelloforbusiness", "x509certificatemultifactor"})
MFA_REQUIREMENT = "mfa"


# --- projections: the only code here that touches a Graph model ---

def project_conditional_access_policy(policy) -> dict:
    """Read a `ConditionalAccessPolicy` model's attributes into a flat dict.

    Any nested model can be absent — `grant_controls` is None on a session-controls-only
    policy, and unset `conditions` sub-blocks are omitted — so every hop is a
    None-tolerant `graph_attr` read, and `graph_list` returns `[]` because Graph omits
    empty collections rather than sending them.

    `state` and every `built_in_controls` member are plain (non-str) `Enum`s, so leaving
    them unwrapped would put "ConditionalAccessPolicyState.Enabled" into the evidence
    and break every downstream comparison. See `split_access_controls()` for the bug that
    causes in Prowler.
    """
    conditions = graph_attr(policy, "conditions")
    applications = graph_attr(conditions, "applications")
    users = graph_attr(conditions, "users")
    platforms = graph_attr(conditions, "platforms")
    locations = graph_attr(conditions, "locations")
    grant_controls = graph_attr(policy, "grant_controls")
    session_controls = graph_attr(policy, "session_controls")
    strength = graph_attr(grant_controls, "authentication_strength")

    return {
        "id": graph_attr(policy, "id"),
        "display_name": graph_attr(policy, "display_name"),
        "state": graph_attr(policy, "state"),
        "created_date_time": graph_attr(policy, "created_date_time"),
        "modified_date_time": graph_attr(policy, "modified_date_time"),
        # --- who it applies to ---
        "include_users": graph_list(users, "include_users"),
        "exclude_users": graph_list(users, "exclude_users"),
        "include_groups": graph_list(users, "include_groups"),
        "exclude_groups": graph_list(users, "exclude_groups"),
        "include_roles": graph_list(users, "include_roles"),
        "exclude_roles": graph_list(users, "exclude_roles"),
        # --- what it applies to ---
        "include_applications": graph_list(applications, "include_applications"),
        "exclude_applications": graph_list(applications, "exclude_applications"),
        "include_user_actions": graph_list(applications, "include_user_actions"),
        # --- the rest of the conditions ---
        "client_app_types": graph_list(conditions, "client_app_types"),
        "sign_in_risk_levels": graph_list(conditions, "sign_in_risk_levels"),
        "user_risk_levels": graph_list(conditions, "user_risk_levels"),
        "include_platforms": graph_list(platforms, "include_platforms"),
        "exclude_platforms": graph_list(platforms, "exclude_platforms"),
        "include_locations": graph_list(locations, "include_locations"),
        "exclude_locations": graph_list(locations, "exclude_locations"),
        # --- what it requires or denies ---
        "built_in_controls": graph_list(grant_controls, "built_in_controls"),
        "grant_controls_operator": graph_attr(grant_controls, "operator"),
        "authentication_strength": graph_attr(strength, "display_name"),
        "authentication_strength_id": graph_attr(strength, "id"),
        "authentication_strength_requirements": graph_list(strength, "requirements_satisfied"),
        "terms_of_use": graph_list(grant_controls, "terms_of_use"),
        # --- session controls (present = the policy constrains the session) ---
        "has_sign_in_frequency": graph_attr(session_controls, "sign_in_frequency") is not None,
        "has_persistent_browser": graph_attr(session_controls, "persistent_browser") is not None,
        "has_application_enforced_restrictions": graph_attr(
            session_controls, "application_enforced_restrictions"
        )
        is not None,
        "has_cloud_app_security": graph_attr(session_controls, "cloud_app_security") is not None,
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def split_access_controls(built_in_controls: list) -> dict:
    """Split grant controls into the ones that DENY and the ones that REQUIRE.

    DELIBERATE DEVIATION from Prowler. Their `_get_conditional_access_policy` sorts each
    control with `if "Grant" in str(access_control)`, meaning to test the value — but
    these are plain `Enum` members, so `str()` renders the member's repr,
    "ConditionalAccessGrantControl.Block". The CLASS NAME contains "Grant", so the test
    is true for every member including Block: their `block` list is always empty and
    their `grant` list always holds everything. (Their MFA check still passes because
    "ConditionalAccessGrantControl.Mfa".lower() happens to contain "mfa".)

    This splits on the wire VALUE, which `graph_attr` has already unwrapped these to:
    exactly one member, `block`, denies access. Porting the bug would have made
    `policies_blocking_access` a constant zero — a field that looks collected and is
    meaningless.
    """
    controls = [str(c) for c in (built_in_controls or []) if c]
    return {
        "block": sorted(c for c in controls if c.lower() == BLOCK_CONTROL),
        "grant": sorted(c for c in controls if c.lower() != BLOCK_CONTROL),
    }


def combination_is_phishing_resistant(combination: str) -> bool:
    """A combination ("fido2", "password,sms") whose every method is phishing-resistant."""
    modes = [m.strip().lower() for m in str(combination or "").split(",") if m.strip()]
    return bool(modes) and all(m in PHISHING_RESISTANT_MODES for m in modes)


def strength_record(raw: dict) -> dict:
    """One authentication strength policy from the raw JSON, where multi-method combinations keep their names."""
    combinations = sorted(str(c) for c in raw.get("allowedCombinations") or [])
    requirements = raw.get("requirementsSatisfied")
    return {
        "id": raw.get("id"),
        "display_name": raw.get("displayName"),
        "policy_type": raw.get("policyType"),
        "requirements_satisfied": requirements,
        "allowed_combinations": combinations,
        "phishing_resistant": bool(combinations) and all(combination_is_phishing_resistant(c) for c in combinations),
    }


def policy_record(policy: dict, strengths: dict | None = None) -> dict:
    """Normalize one projected policy into an evidence record.

    `target_resources.include` follows Prowler: `includeApplications` when set, otherwise
    `includeUserActions` — a policy can target a user ACTION (registering a security key)
    instead of an application, and reading only the applications field would report such
    a policy as targeting nothing.

    `state` defaults to "disabled", not None: Graph always returns it, so an absent value
    means it could not be read, and treating that as enforcing would overstate the
    tenant's posture.
    """
    access_controls = split_access_controls(policy.get("built_in_controls"))
    include_apps = policy.get("include_applications") or policy.get("include_user_actions") or []
    exclude_apps = policy.get("exclude_applications") or []
    state = policy.get("state") or STATE_DISABLED

    grant = access_controls["grant"]
    strength_id = policy.get("authentication_strength_id")
    strength = (strengths or {}).get(str(strength_id).lower()) if strength_id else None
    requirements = policy.get("authentication_strength_requirements") or str(
        (strength or {}).get("requirements_satisfied") or ""
    ).split(",")
    # A strength counts as MFA only when it says so; a custom one can allow a password alone.
    requires_mfa = any(c.lower() in MFA_CONTROLS for c in grant) or (
        bool(strength_id) and MFA_REQUIREMENT in {str(r).strip().lower() for r in requirements}
    )
    if not strength_id:
        phishing_resistant: bool | None = False
    elif strength is None:
        phishing_resistant = None
    else:
        # Under OR, any other grant control satisfies the policy instead of the strength.
        either = str(policy.get("grant_controls_operator") or "").upper() == "OR" and bool(grant)
        phishing_resistant = strength["phishing_resistant"] and not either

    return {
        "id": policy.get("id"),
        "display_name": policy.get("display_name"),
        "state": state,
        "is_enforced": state == STATE_ENABLED,
        "is_report_only": state == STATE_REPORT_ONLY,
        "created_date_time": policy.get("created_date_time"),
        "modified_date_time": policy.get("modified_date_time"),
        "users": {
            "include": sorted(policy.get("include_users") or []),
            "exclude": sorted(policy.get("exclude_users") or []),
            "include_groups": sorted(policy.get("include_groups") or []),
            "exclude_groups": sorted(policy.get("exclude_groups") or []),
            "include_roles": sorted(policy.get("include_roles") or []),
            "exclude_roles": sorted(policy.get("exclude_roles") or []),
        },
        "target_resources": {
            "include": sorted(include_apps),
            "exclude": sorted(exclude_apps),
        },
        "access_controls": {
            "grant": grant,
            "block": access_controls["block"],
            "operator": policy.get("grant_controls_operator"),
            "authentication_strength": policy.get("authentication_strength"),
            "authentication_strength_id": strength_id,
            "authentication_strength_combinations": strength["allowed_combinations"] if strength else None,
            "terms_of_use": sorted(policy.get("terms_of_use") or []),
        },
        "conditions": {
            "client_app_types": sorted(policy.get("client_app_types") or []),
            "sign_in_risk_levels": sorted(policy.get("sign_in_risk_levels") or []),
            "user_risk_levels": sorted(policy.get("user_risk_levels") or []),
            "include_platforms": sorted(policy.get("include_platforms") or []),
            "exclude_platforms": sorted(policy.get("exclude_platforms") or []),
            "include_locations": sorted(policy.get("include_locations") or []),
            "exclude_locations": sorted(policy.get("exclude_locations") or []),
        },
        "session_controls": {
            "sign_in_frequency": bool(policy.get("has_sign_in_frequency")),
            "persistent_browser": bool(policy.get("has_persistent_browser")),
            "application_enforced_restrictions": bool(
                policy.get("has_application_enforced_restrictions")
            ),
            "cloud_app_security": bool(policy.get("has_cloud_app_security")),
        },
        # --- derived flags ---
        "requires_mfa": requires_mfa,
        "requires_phishing_resistant_mfa": phishing_resistant,
        "blocks_access": bool(access_controls["block"]),
        "requires_compliant_device": any(
            c.lower() in ("compliantdevice", "domainjoineddevice") for c in grant
        ),
        "targets_all_users": ALL_USERS in (policy.get("include_users") or []),
        "targets_all_applications": ALL_APPLICATIONS in include_apps,
        "has_user_exclusions": bool(
            (policy.get("exclude_users") or [])
            or (policy.get("exclude_groups") or [])
            or (policy.get("exclude_roles") or [])
        ),
        "targets_legacy_authentication": bool(
            LEGACY_CLIENT_APP_TYPES.intersection(
                str(t) for t in (policy.get("client_app_types") or [])
            )
        ),
    }


def _protects(policy: dict, resource: str) -> bool:
    """Whether an ENFORCED policy requires MFA for all users on `resource`.

    Ported from Prowler's entra_conditional_access_policy_require_mfa_for_admin_portals
    and ..._for_management_api: enabled (not report-only), includes All users, targets
    that resource, and grants on MFA. All four are needed — an enabled MFA policy scoped
    to one pilot group protects nobody in particular.

    Deviation: a policy targeting `All` applications covers the resource too, which
    Prowler's literal membership test misses.
    """
    if not policy["is_enforced"] or not policy["requires_mfa"]:
        return False
    if not policy["targets_all_users"]:
        return False
    included = policy["target_resources"]["include"]
    return resource in included or ALL_APPLICATIONS in included


def phishing_resistant_summary(enforced: list[dict], strengths_readable: bool, policies_readable: bool) -> dict:
    """Null when the policies or any enforced policy's strength couldn't be read, so unread never reads as absent."""
    known = policies_readable and strengths_readable and all(
        p["requires_phishing_resistant_mfa"] is not None for p in enforced
    )
    strong = [p for p in enforced if p["requires_phishing_resistant_mfa"]]
    return {
        "authentication_strengths_readable": strengths_readable,
        "enforced_policies_requiring_phishing_resistant_mfa": len(strong) if known else None,
        "enforced_phishing_resistant_mfa_for_all_users_and_apps": sum(
            1 for p in strong if p["targets_all_users"] and p["targets_all_applications"]
        ) if known else None,
        "phishing_resistant_mfa_role_template_ids": sorted(
            {r for p in strong if p["targets_all_applications"] for r in p["users"]["include_roles"]}
        ) if known else None,
    }


def summarize(policies: list[dict], strengths_readable: bool = True, policies_readable: bool = True) -> dict:
    """Enforced policies are the denominator that matters.

    Every "enforced_policies_*" count is over enforced policies only, because a disabled
    or report-only policy demonstrates intent, not enforcement. The raw state breakdown
    is reported separately so the gap stays visible.
    """
    enforced = [p for p in policies if p["is_enforced"]]
    return {
        "total_policies": len(policies),
        # --- state breakdown: report-only is never folded into enabled ---
        "enabled_policies": len(enforced),
        "disabled_policies": sum(1 for p in policies if p["state"] == STATE_DISABLED),
        "report_only_policies": sum(1 for p in policies if p["is_report_only"]),
        "enforced_percentage": coverage_percentage(len(enforced), len(policies)),
        # --- what the enforced policies actually do ---
        "enforced_policies_requiring_mfa": sum(1 for p in enforced if p["requires_mfa"]),
        "enforced_policies_blocking_access": sum(1 for p in enforced if p["blocks_access"]),
        "enforced_policies_requiring_compliant_device": sum(
            1 for p in enforced if p["requires_compliant_device"]
        ),
        "enforced_policies_with_authentication_strength": sum(
            1 for p in enforced if p["access_controls"]["authentication_strength_id"]
        ),
        **phishing_resistant_summary(enforced, strengths_readable, policies_readable),
        "enforced_policies_with_session_controls": sum(
            1 for p in enforced if any(p["session_controls"].values())
        ),
        # --- breadth of coverage ---
        "enforced_policies_targeting_all_users": sum(
            1 for p in enforced if p["targets_all_users"]
        ),
        "enforced_policies_targeting_all_applications": sum(
            1 for p in enforced if p["targets_all_applications"]
        ),
        "enforced_mfa_for_all_users_and_apps": sum(
            1
            for p in enforced
            if p["requires_mfa"] and p["targets_all_users"] and p["targets_all_applications"]
        ),
        # --- the two resources the CIS Azure benchmark names ---
        "mfa_required_for_admin_portals": any(
            _protects(p, MICROSOFT_ADMIN_PORTALS) for p in policies
        ),
        "mfa_required_for_azure_management_api": any(
            _protects(p, WINDOWS_AZURE_SERVICE_MANAGEMENT_API) for p in policies
        ),
        "enforced_policies_targeting_legacy_authentication": sum(
            1 for p in enforced if p["targets_legacy_authentication"]
        ),
        # --- the exclusions that undo the above ---
        "enforced_policies_with_exclusions": sum(1 for p in enforced if p["has_user_exclusions"]),
        "distinct_excluded_principals": len(
            {
                principal
                for p in enforced
                for key in ("exclude", "exclude_groups", "exclude_roles")
                for principal in p["users"][key]
            }
        ),
    }


# --- collection (lazy msgraph imports) ---

async def read_strengths(client) -> list[dict]:
    """GET /policies/authenticationStrengthPolicies as raw JSON: the SDK reads "password,sms" as None."""
    from msgraph.generated.models.o_data_errors.o_data_error import ODataError

    builder = client.policies.authentication_strength_policies
    info = builder.to_get_request_information()
    items: list[dict] = []
    while info is not None:
        raw = await builder.request_adapter.send_primitive_async(info, "bytes", {"XXX": ODataError})
        body = json.loads(raw or b"{}")
        items.extend(body.get("value") or [])
        next_link = body.get("@odata.nextLink")
        info = builder.with_url(next_link).to_get_request_information() if next_link else None
    return items


async def _collect(collector: Collector, cred) -> tuple[list[dict], dict, list[dict], bool, bool]:
    """identity.conditional_access.policies.get() paged to the end, then the strengths they use."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)
        before = len(collector.failures)
        projected = [
            project_conditional_access_policy(p)
            for p in await paginate(
                collector,
                "graph.identity.conditionalAccess.policies.get",
                client.identity.conditional_access.policies,
            )
        ]
        policies_readable = len(collector.failures) == before
        strengths: list[dict] = []
        readable = True
        if any(p.get("authentication_strength_id") for p in projected):
            raw = await aguard(collector, "graph.policies.authenticationStrengthPolicies.get",
                               lambda: read_strengths(client), default=None)
            readable = raw is not None
            strengths = sorted((strength_record(s) for s in raw or []),
                               key=lambda s: (s["display_name"] or "", s["id"] or ""))
        by_id = {str(s["id"]).lower(): s for s in strengths} if readable else None
        policies = [policy_record(p, by_id) for p in projected]
        logger.info("Collected %d Conditional Access policy/policies", len(policies))
        # Sorted for byte-stable re-runs; Graph promises no stable policy order.
        return (
            sorted(policies, key=lambda p: (p.get("display_name") or "", p.get("id") or "")),
            tenant,
            strengths,
            readable,
            policies_readable,
        )

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ([], {"tenant_source": "unresolved"}, [], True, False)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-*, msgraph, kiota and httpx stacks log every request at INFO, which
    # would dominate the runner's stderr tail. Warnings and errors still come through.
    for noisy in ("azure", "msgraph", "kiota", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        policies: list[dict] = []
        tenant = {"tenant_source": "unresolved"}
        strengths: list[dict] = []
        strengths_readable, policies_readable = True, False
    else:
        policies, tenant, strengths, strengths_readable, policies_readable = asyncio.run(_collect(collector, cred))

    # No `provider_registration_status()` call, deliberately: Graph is not an ARM
    # resource provider.
    #
    # The equivalent ambiguity here is NOT resolvable from this endpoint: a tenant on the
    # free Entra tier cannot create policies at all (they need Entra ID P1/P2) and returns
    # an empty list rather than an error, so `total_policies: 0` means either "no policies
    # configured" or "not licensed". Resolving it needs a subscribedSkus call and
    # permission; not collected here.
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={"conditional_access_policies": policies, "authentication_strengths": strengths},
        summary=summarize(policies, strengths_readable, policies_readable),
    )

    filename = f"azure_entra_conditional_access_policies_{tenant_filename_key(tenant)}.json"
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
