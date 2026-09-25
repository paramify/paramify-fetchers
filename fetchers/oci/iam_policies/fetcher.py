#!/usr/bin/env python3
"""
OCI IAM policies — every statement parsed, and the broad grants counted

Every IAM policy in scope with each statement parsed into its subject, verb or
permissions, resource, location and condition, plus the tenancy's dynamic
groups (workload identities that authenticate without a stored key).

Evidence for KSI-IAM-ELP, "each user or device can only access the resources
they need", and KSI-IAM-SNU for the dynamic groups — a workload using an
instance or resource principal holds no key to leak or rotate.

Ported from Prowler's OCI identity service (Apache-2.0,
prowler/providers/oraclecloud/services/identity, commit c0fdd5b) — the
`identity_tenancy_admin_permissions_limited`,
`identity_iam_admins_cannot_update_tenancy_admins`,
`identity_service_level_admins_exist` and `identity_instance_principal_used`
checks. Prowler matches substrings of upper-cased statements; this port parses
the documented grammar instead, because the substrings miss real grants:

  * `allow any-user to manage all-resources in tenancy` is not flagged — every
    Prowler test starts with "ALLOW GROUP". Nor is a dynamic group.
  * The Administrators-guard check splits on lowercase "where", so a statement
    written with WHERE is read as having no condition — a false failure.
  * `manage groups in tenancy` is only caught when the same statement also
    mentions users.
  * The default admin policy is exempted by NAME alone, so any policy renamed
    "Tenant Admin Policy" is exempt. Here it must also sit in the tenancy root
    and hold exactly Oracle's one default statement.

ANY-USER IS NOT AUTOMATICALLY A FINDING. Oracle's own managed CloudGuardPolicies
contain `Allow any-user to { WLP_BOM_READ } in tenancy where all {
request.principal.type = 'workloadprotectionagent', ... }` — read off a live
tenancy. That is a narrowly conditioned service grant. Only an any-user or
any-group grant with no `where` clause is counted as unconditional.

Statements the parser does not recognise are kept verbatim, counted, and never
read as narrow.
"""

import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
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

logger = logging.getLogger("oci_iam_policies")

DEFAULT_ADMIN_POLICY_NAME = "tenant admin policy"
DEFAULT_ADMIN_STATEMENT = "allow group administrators to manage all-resources in tenancy"

# Resource types that change who can do what.
IAM_RESOURCES = frozenset({
    "all-resources", "users", "groups", "policies", "dynamic-groups", "domains",
    "identity-providers", "authentication-policies", "network-sources",
})

# Prowler's instance-principal markers, plus the resource-principal families
# the OCI docs list for dynamic group matching rules.
WORKLOAD_RULE_MARKERS = ("instance", "fnfunc", "autonomousdatabase", "resource.compartment.id",
                         "resource.type", "resource.id")

_STATEMENT = re.compile(
    r"^(?P<action>allow|endorse|admit)\s+(?P<subject>.+?)\s+to\s+"
    r"(?:(?P<verb>inspect|read|use|manage)\s+(?P<resource>\S.*?)|(?P<permissions>\{[^}]*\}))"
    r"\s+in\s+(?P<location>any-tenancy|tenancy(?:\s+\S+)?|compartment\s+(?:id\s+)?\S+)"
    r"(?:\s+where\s+(?P<where>.+))?$",
    re.IGNORECASE,
)


# --- pure transforms ---

def _normalize(text: str) -> str:
    return " ".join(str(text).split())


def classify_subject(subject: str) -> str:
    s = subject.strip().lower()
    if s.startswith(("any-user", "any-group")):
        return "any"
    if s.startswith("service"):
        return "service"
    if s.startswith("dynamic-group"):
        return "dynamic_group"
    if s.startswith("group"):
        return "group"
    return "unknown"


def _guards_administrators(where) -> bool:
    """True when the condition excludes the Administrators group as a target."""
    if not where:
        return False
    compact = re.sub(r"[\s'\"]", "", where).lower()
    return "target.group.name!=administrators" in compact


def parse_statement(statement: str) -> dict:
    text = _normalize(statement)
    match = _STATEMENT.match(text)
    if not match:
        return {"statement": text, "parsed": False}

    verb = (match["verb"] or "").lower() or None
    resource = (match["resource"] or "").lower() or None
    location = match["location"].lower()
    where = match["where"]
    subject_kind = classify_subject(match["subject"])
    tenancy_wide = location.startswith("tenancy") or location == "any-tenancy"
    manages = verb in ("manage", "use")

    return {
        "statement": text,
        "parsed": subject_kind != "unknown",
        "action": match["action"].lower(),
        "subject": match["subject"],
        "subject_kind": subject_kind,
        "verb": verb,
        "permissions": match["permissions"],
        "resource": resource,
        "location": match["location"],
        "condition": where,
        "tenancy_wide": tenancy_wide,
        "cross_tenancy": match["action"].lower() in ("endorse", "admit"),
        "manages_all_resources": verb == "manage" and resource == "all-resources",
        "unconditional_any_principal": subject_kind == "any" and not where,
        # Prowler's check, applied to every principal kind but services.
        "manages_iam_without_administrators_guard": (
            manages and resource in IAM_RESOURCES and tenancy_wide
            and subject_kind in ("group", "dynamic_group", "any")
            and not _guards_administrators(where)
        ),
    }


def policy_record(policy: dict, *, tenancy_id=None) -> dict:
    statements = [parse_statement(s) for s in policy.get("statements") or []]
    name = (policy.get("name") or "").strip().lower()
    # The default admin policy is recognised by what it IS, not what it is called.
    is_default_admin = (
        name == DEFAULT_ADMIN_POLICY_NAME
        and tenancy_id is not None and policy.get("compartment_id") == tenancy_id
        and [s["statement"].lower() for s in statements] == [DEFAULT_ADMIN_STATEMENT]
    )
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "compartment_id": policy.get("compartment_id"),
        "lifecycle_state": policy.get("lifecycle_state"),
        "time_created": iso(policy.get("time_created")),
        "version_date": iso(policy.get("version_date")),
        "is_default_tenant_admin_policy": is_default_admin,
        "statements": statements,
    }


def dynamic_group_record(group: dict) -> dict:
    rule = group.get("matching_rule") or ""
    lowered = rule.lower()
    return {
        "id": group.get("id"),
        "name": group.get("name"),
        "lifecycle_state": group.get("lifecycle_state"),
        "matching_rule": _normalize(rule),
        "matches_workloads": any(marker in lowered for marker in WORKLOAD_RULE_MARKERS),
    }


def summarize(policies: list[dict], dynamic_groups: list[dict]) -> dict:
    active = [p for p in policies if p["lifecycle_state"] == "ACTIVE"]

    def statements(where_policy=lambda p: True):
        return [s for p in active if where_policy(p) for s in p["statements"]]

    everything = statements()
    parsed = [s for s in everything if s["parsed"]]
    outside_default = [s for s in statements(lambda p: not p["is_default_tenant_admin_policy"]) if s["parsed"]]
    broad = [s for s in outside_default if s["manages_all_resources"] and s["tenancy_wide"]]

    return {
        "total_policies": len(policies),
        "active_policies": len(active),
        "total_statements": len(everything),
        "unparsed_statements": len(everything) - len(parsed),
        "default_tenant_admin_policy_present": any(p["is_default_tenant_admin_policy"] for p in active),
        # Prowler identity_tenancy_admin_permissions_limited
        "manage_all_resources_in_tenancy_outside_default_admin_policy": len(broad),
        # Prowler identity_service_level_admins_exist (any location)
        "manage_all_resources_statements_outside_default_admin_policy": sum(
            1 for s in outside_default if s["manages_all_resources"]
        ),
        # Prowler identity_iam_admins_cannot_update_tenancy_admins
        "iam_management_statements_without_administrators_guard": sum(
            1 for s in outside_default if s["manages_iam_without_administrators_guard"]
        ),
        "unconditional_any_principal_statements": sum(1 for s in parsed if s["unconditional_any_principal"]),
        "conditional_any_principal_statements": sum(
            1 for s in parsed if s["subject_kind"] == "any" and not s["unconditional_any_principal"]
        ),
        "cross_tenancy_statements": sum(1 for s in parsed if s["cross_tenancy"]),
        "statements_by_subject_kind": {
            kind: sum(1 for s in parsed if s["subject_kind"] == kind)
            for kind in ("group", "dynamic_group", "service", "any")
        },
        "policies_with_broad_grants": sorted(
            f"{p['name']} ({short_ocid(p['id'])})" for p in active
            if not p["is_default_tenant_admin_policy"]
            and any(s["parsed"] and (s["manages_all_resources"] or s["unconditional_any_principal"]
                                     or s["manages_iam_without_administrators_guard"])
                    for s in p["statements"])
        ),
        # Prowler identity_instance_principal_used
        "dynamic_groups": len(dynamic_groups),
        "dynamic_groups_matching_workloads": sum(1 for g in dynamic_groups if g["matches_workloads"]),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    import oci  # lazy

    tenancy = auth.get("tenancy")
    identity = make_client(oci.identity.IdentityClient, auth)

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=tenancy,
    )
    policies = []
    for comp in compartments:
        for policy in collector.guard(
            f"identity.list_policies ({comp['name']})",
            lambda c=comp["id"]: list_all(identity.list_policies, c),
            default=[],
        ) or []:
            policies.append(policy_record(to_plain(policy), tenancy_id=tenancy))

    # Dynamic groups exist only at the tenancy root.
    groups = collector.guard(
        "identity.list_dynamic_groups",
        lambda: list_all(identity.list_dynamic_groups, tenancy),
        default=[],
    ) or []
    dynamic = [dynamic_group_record(to_plain(g)) for g in groups]

    policies.sort(key=lambda r: (r.get("name") or "", r.get("id") or ""))
    dynamic.sort(key=lambda r: r.get("name") or "")
    return policies, dynamic, len(compartments)


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
    policies = dynamic = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                policies, dynamic, scanned = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("identity.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"policies": policies or [], "dynamic_groups": dynamic or []},
        summary=summarize(policies or [], dynamic or []),
        compartments_scanned=scanned,
        regional=False,  # IAM lives in the home region and answers tenancy-wide
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_iam_policies_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
