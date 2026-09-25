#!/usr/bin/env python3
"""
OCI Cloud Guard — whether the tenancy continuously assesses itself, and enforces

Cloud Guard's tenancy configuration, every target it monitors with the detector
and responder rules actually in force on it, every Security Zone and the policy
set its recipe enforces, and the open problems Cloud Guard has raised.

This is the evidence for KSI-CNA-EIS, "automated services are used to
persistently assess the security of all machine-based information resources and
automatically enforce their intended operational state", and KSI-MLA-EVC,
"the configuration of machine-based information resources is persistently
evaluated". The indicator has two verbs, and Cloud Guard has a mechanism for
each, so each is reported apart:

  * ASSESS — detector rules. A target with the configuration detector enabled
    re-evaluates every resource beneath it and raises a problem on drift.

  * ENFORCE — two different mechanisms, and only one is preventive. A responder
    rule in AUTOACTION mode remediates after the fact; in USERACTION mode it only
    proposes a fix a human must approve, which is assessment wearing the word
    "responder". A Security Zone is the preventive one: OCI refuses to create a
    resource in that compartment that violates the zone's recipe at all.

WHAT MAKES THIS EVIDENCE RATHER THAN AN INVENTORY: a target whose recipe is
attached but whose rules are all disabled monitors nothing, and a responder
recipe full of USERACTION rules enforces nothing. Both are counted from the
rules' own `is_enabled` and `mode`, never from the presence of a recipe.

DISABLED IS THE FINDING, NOT A FAILURE. A tenancy that never turned Cloud Guard
on answers `get_configuration` with status DISABLED and 404s the rest of the
service. That is recorded as `cloud_guard_enabled: false`, the remaining calls
are not made, and the run exits 0 — the evidence is complete and says no.

AN N+1 THAT IS NOT AN OVERSIGHT: `list_targets` returns TargetSummary, which
carries a `recipe_count` and nothing else about the recipes. The rules — the
only part that says whether anything is being assessed — are on `get_target`.
Targets are few (typically one per top-level compartment), so this stays small.

A TRAP IN ORACLE'S OWN MODEL: targets spell it `lifecyle_details`, missing the
second "c". Security zones, recipes and every other model spell it correctly.
Reading the correct spelling off a target returns None forever.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    age_in_days,
    as_bool,
    build_payload,
    coverage_percentage,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    resolve_scope,
    sanitize_for_filename,
    service_not_subscribed,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_cloud_guard_posture")

# The detector that re-evaluates resource configuration — the MLA-EVC half.
CONFIGURATION_DETECTOR = "IAAS_CONFIGURATION_DETECTOR"
ACTIVITY_DETECTOR = "IAAS_ACTIVITY_DETECTOR"

AUTOACTION = "AUTOACTION"
# Responder rule types. EVENT only emits a notification; only REMEDIATION changes
# the resource. Oracle's managed recipe ships EVENT in AUTOACTION and every
# REMEDIATION rule in USERACTION, so counting by mode alone reports enforcement
# on a tenancy where nothing is enforced — caught against the live recipe.
REMEDIATION = "REMEDIATION"

RISK_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINOR")

# Above this age an open problem has been seen and left, which is a different
# finding from a problem that was raised this week.
STALE_PROBLEM_DAYS = 30


# --- pure transforms ---

def configuration_record(configuration: dict) -> dict:
    """The tenancy-level switch every other section depends on."""
    status = configuration.get("status")
    return {
        "status": status,
        "enabled": status == "ENABLED",
        "reporting_region": configuration.get("reporting_region"),
        # True means the customer wrote Cloud Guard's IAM policies themselves
        # rather than letting Oracle create them.
        "self_manage_resources": configuration.get("self_manage_resources"),
    }


def detector_rule_facts(rule: dict) -> dict:
    """One detector rule as it is actually in force on a target."""
    details = rule.get("details") or {}
    return {
        "detector_rule_id": rule.get("detector_rule_id"),
        "detector": rule.get("detector"),
        "resource_type": rule.get("resource_type"),
        "is_enabled": details.get("is_enabled") is True,
        "risk_level": details.get("risk_level"),
    }


def responder_rule_facts(rule: dict) -> dict:
    """One responder rule as it is actually in force on a target."""
    details = rule.get("details") or {}
    mode = details.get("mode")
    enabled = details.get("is_enabled") is True
    return {
        "responder_rule_id": rule.get("responder_rule_id"),
        "type": rule.get("type"),
        "is_enabled": enabled,
        "mode": mode,
        # Only an enabled REMEDIATION rule in AUTOACTION changes anything without a human.
        "auto_remediates": enabled and mode == AUTOACTION and rule.get("type") == REMEDIATION,
        "auto_notifies": enabled and mode == AUTOACTION and rule.get("type") != REMEDIATION,
    }


def detector_recipe_record(recipe: dict) -> dict:
    """A detector recipe attached to a target, reduced to its enabled rules.

    `effective_detector_rules` is the recipe merged with the target's own
    overrides, which is what Cloud Guard evaluates. `detector_rules` alone is
    the recipe before overrides, and is used only when the effective list is
    absent, so a target-level disable is never read as enabled.
    """
    rules = recipe.get("effective_detector_rules") or recipe.get("detector_rules") or []
    facts = [detector_rule_facts(r) for r in rules]
    enabled = [f for f in facts if f["is_enabled"]]
    return {
        "id": recipe.get("id"),
        "display_name": recipe.get("display_name"),
        "detector_recipe_id": recipe.get("detector_recipe_id"),
        "detector": recipe.get("detector"),
        "owner": recipe.get("owner"),
        "detector_recipe_type": recipe.get("detector_recipe_type"),
        "lifecycle_state": recipe.get("lifecycle_state"),
        "total_rules": len(facts),
        "enabled_rules": len(enabled),
        "enabled_rules_by_risk": {
            level: sum(1 for f in enabled if f["risk_level"] == level) for level in RISK_LEVELS
        },
    }


def responder_recipe_record(recipe: dict) -> dict:
    """A responder recipe attached to a target, split by what its rules do."""
    rules = recipe.get("effective_responder_rules") or recipe.get("responder_rules") or []
    facts = [responder_rule_facts(r) for r in rules]
    return {
        "id": recipe.get("id"),
        "display_name": recipe.get("display_name"),
        "responder_recipe_id": recipe.get("responder_recipe_id"),
        "owner": recipe.get("owner"),
        "total_rules": len(facts),
        "enabled_rules": sum(1 for f in facts if f["is_enabled"]),
        "auto_remediating_rules": sum(1 for f in facts if f["auto_remediates"]),
        "auto_remediating_rule_types": sorted(
            {f["type"] for f in facts if f["auto_remediates"] and f["type"]}
        ),
    }


def target_record(target: dict) -> dict:
    """Normalize one target (from `get_target`) into an evidence record."""
    raw_detectors = target.get("target_detector_recipes")
    detectors = [detector_recipe_record(r) for r in raw_detectors or []]
    responders = [responder_recipe_record(r) for r in target.get("target_responder_recipes") or []]

    enabled_by_detector: dict = {}
    for recipe in detectors:
        key = recipe["detector"] or "UNKNOWN"
        enabled_by_detector[key] = enabled_by_detector.get(key, 0) + recipe["enabled_rules"]

    return {
        "id": target.get("id"),
        "display_name": target.get("display_name"),
        "compartment_id": target.get("compartment_id"),
        "target_resource_type": target.get("target_resource_type"),
        "target_resource_id": target.get("target_resource_id"),
        "lifecycle_state": target.get("lifecycle_state"),
        # Oracle's spelling, not a typo here — see the module docstring.
        "lifecycle_details": target.get("lifecyle_details"),
        "inherited_by_compartments": len(target.get("inherited_by_compartments") or []),
        "recipe_count": target.get("recipe_count"),
        "detector_recipes": detectors,
        "responder_recipes": responders,
        "enabled_detector_rules": sum(r["enabled_rules"] for r in detectors),
        "enabled_rules_by_detector": dict(sorted(enabled_by_detector.items())),
        "assesses_configuration": enabled_by_detector.get(CONFIGURATION_DETECTOR, 0) > 0,
        "assesses_activity": enabled_by_detector.get(ACTIVITY_DETECTOR, 0) > 0,
        "auto_remediating_rules": sum(r["auto_remediating_rules"] for r in responders),
        "time_created": iso(target.get("time_created")),
        "time_updated": iso(target.get("time_updated")),
        # False when get_target failed and this is the summary standing in; the
        # recipe fields above are then empty and must not read as "no rules".
        "detail_read": raw_detectors is not None,
    }


def security_zone_record(zone: dict, *, recipe=None) -> dict:
    """Normalize one security zone, joined to the recipe it enforces."""
    recipe = recipe or {}
    policies = recipe.get("security_policies") if recipe else None
    return {
        "id": zone.get("id"),
        "display_name": zone.get("display_name"),
        "compartment_id": zone.get("compartment_id"),
        "security_zone_recipe_id": zone.get("security_zone_recipe_id"),
        "lifecycle_state": zone.get("lifecycle_state"),
        "lifecycle_details": zone.get("lifecycle_details"),
        # None when the recipe could not be read, which is not "zero policies".
        "enforced_policy_count": len(policies) if policies is not None else None,
        "time_created": iso(zone.get("time_created")),
    }


def security_recipe_record(recipe: dict, *, policy_names=None) -> dict:
    """A Security Zone recipe, with its policies named.

    The recipe carries bare policy OCIDs, which tell an assessor nothing.
    `list_security_policies` names them (`deny public_buckets`); an OCID that
    does not resolve is kept as-is rather than dropped.
    """
    policy_names = policy_names or {}
    policy_ids = recipe.get("security_policies") or []
    return {
        "id": recipe.get("id"),
        "display_name": recipe.get("display_name"),
        "owner": recipe.get("owner"),
        "lifecycle_state": recipe.get("lifecycle_state"),
        "security_policy_count": len(policy_ids),
        "security_policies": sorted(policy_names.get(pid) or pid for pid in policy_ids),
    }


def problem_record(problem: dict, *, now=None) -> dict:
    """Normalize one Cloud Guard problem."""
    return {
        "id": problem.get("id"),
        "compartment_id": problem.get("compartment_id"),
        "target_id": problem.get("target_id"),
        "detector_id": problem.get("detector_id"),
        "detector_rule_id": problem.get("detector_rule_id"),
        "risk_level": problem.get("risk_level"),
        "resource_type": problem.get("resource_type"),
        "resource_id": problem.get("resource_id"),
        "resource_name": problem.get("resource_name"),
        "lifecycle_state": problem.get("lifecycle_state"),
        "lifecycle_detail": problem.get("lifecycle_detail"),
        "region": problem.get("region"),
        "time_first_detected": iso(problem.get("time_first_detected")),
        "time_last_detected": iso(problem.get("time_last_detected")),
        "days_open": age_in_days(problem.get("time_first_detected"), now=now),
    }


def summarize(
    configuration,
    targets: list[dict],
    zones: list[dict],
    problems: list[dict],
    *,
    compartments_in_scope: int = 0,
    tenancy_id=None,
) -> dict:
    """Aggregate into the two questions the indicator asks: assessed? enforced?"""
    enabled = bool(configuration and configuration["enabled"])
    read = [t for t in targets if t["detail_read"]]
    assessing = [t for t in read if t["assesses_configuration"]]
    active_zones = [z for z in zones if z["lifecycle_state"] == "ACTIVE"]
    # Listed with lifecycle_detail=OPEN, so only an explicit other answer closes
    # one: matched on == "OPEN", a problem missing the field dropped out.
    open_problems = [p for p in problems if p["lifecycle_detail"] in ("OPEN", None)]

    return {
        # None when get_configuration itself failed — unknown, not disabled.
        "cloud_guard_status": configuration["status"] if configuration else None,
        "cloud_guard_enabled": enabled if configuration else None,
        "reporting_region": configuration["reporting_region"] if configuration else None,
        # ASSESS
        "total_targets": len(targets),
        "targets_with_unreadable_detail": len(targets) - len(read),
        "targets_assessing_configuration": len(assessing),
        "targets_assessing_activity": sum(1 for t in read if t["assesses_activity"]),
        "targets_with_no_enabled_detector_rules": sum(
            1 for t in read if t["enabled_detector_rules"] == 0
        ),
        "configuration_assessment_percentage": coverage_percentage(len(assessing), len(read)),
        # Targets inherit down the compartment tree, so a target on the tenancy
        # root assesses every compartment, including ones created later.
        "tenancy_root_is_target": bool(tenancy_id) and any(
            t["target_resource_type"] == "COMPARTMENT" and t["target_resource_id"] == tenancy_id
            for t in read
        ),
        "compartments_in_scope": compartments_in_scope,
        # ENFORCE, reactive
        "targets_with_auto_remediation": sum(1 for t in read if t["auto_remediating_rules"] > 0),
        "total_auto_remediating_rules": sum(t["auto_remediating_rules"] for t in read),
        # ENFORCE, preventive
        "total_security_zones": len(zones),
        "active_security_zones": len(active_zones),
        "security_zone_names": sorted(
            f"{z['display_name']} ({short_ocid(z['id'])})" for z in zones if z["display_name"]
        ),
        # PROBLEMS
        "open_problems": len(open_problems),
        "open_problems_by_risk": {
            level: sum(1 for p in open_problems if p["risk_level"] == level)
            for level in RISK_LEVELS
        },
        "open_problems_with_unknown_risk": sum(1 for p in open_problems if p["risk_level"] not in RISK_LEVELS),
        "open_problems_older_than_30_days": sum(
            1 for p in open_problems
            if p["days_open"] is not None and p["days_open"] > STALE_PROBLEM_DAYS
        ),
        "oldest_open_problem_days": max(
            (p["days_open"] for p in open_problems if p["days_open"] is not None), default=None
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool) -> dict:
    """Configuration first; everything else only if Cloud Guard is on."""
    import oci  # lazy

    out: dict = {
        "configuration": None,
        "targets": [],
        "security_zones": [],
        "security_recipes": [],
        "problems": [],
        # None until the tree is walked, so a disabled service never claims a scan.
        "compartments": None,
    }
    tenancy = auth.get("tenancy")
    cloud_guard = make_client(oci.cloud_guard.CloudGuardClient, auth)

    raw = collector.guard(
        "cloud_guard.get_configuration",
        lambda: cloud_guard.get_configuration(tenancy).data,
    )
    if raw is None:
        return out
    out["configuration"] = configuration_record(to_plain(raw))
    if not out["configuration"]["enabled"]:
        logger.info("Cloud Guard is DISABLED for this tenancy — recording that and stopping")
        return out

    # Targets and problems live in the reporting region; a client pointed
    # anywhere else would read an empty service.
    region = out["configuration"]["reporting_region"]
    if region and region != (auth.get("config") or {}).get("region"):
        cloud_guard.base_client.set_region(region)

    identity = make_client(oci.identity.IdentityClient, auth)
    compartments = walk_compartments(
        identity,
        scope["compartment_id"],
        collector,
        include_subcompartments=include_sub,
        tenancy=tenancy,
    )
    out["compartments"] = len(compartments)

    # Recipes are defined once and referenced by zones anywhere in the tree, so
    # they are read from the tenancy root rather than per compartment.
    recipes = collector.guard(
        "cloud_guard.list_security_recipes",
        lambda: list_all(cloud_guard.list_security_recipes, tenancy),
        default=[],
    ) or []
    policy_names = {
        policy.id: policy.friendly_name or policy.display_name
        for policy in collector.guard(
            "cloud_guard.list_security_policies",
            lambda: list_all(cloud_guard.list_security_policies, tenancy),
            default=[],
        ) or []
    }
    recipes_by_id = {}
    for recipe in recipes:
        plain = to_plain(recipe)
        recipes_by_id[plain.get("id")] = plain
        out["security_recipes"].append(security_recipe_record(plain, policy_names=policy_names))

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        for summary in collector.guard(
            f"cloud_guard.list_targets ({cname})",
            lambda c=cid: list_all(cloud_guard.list_targets, c, lifecycle_state="ACTIVE"),
            default=[],
            tolerate=service_not_subscribed,
        ) or []:
            # Mandatory second call: the summary carries no recipe rules.
            detail = collector.guard(
                f"cloud_guard.get_target ({short_ocid(summary.id)})",
                lambda t=summary.id: cloud_guard.get_target(t).data,
            )
            out["targets"].append(target_record(to_plain(detail if detail is not None else summary)))

        for zone in collector.guard(
            f"cloud_guard.list_security_zones ({cname})",
            lambda c=cid: list_all(cloud_guard.list_security_zones, c),
            default=[],
            tolerate=service_not_subscribed,
        ) or []:
            plain = to_plain(zone)
            out["security_zones"].append(
                security_zone_record(plain, recipe=recipes_by_id.get(plain.get("security_zone_recipe_id")))
            )

        for problem in collector.guard(
            f"cloud_guard.list_problems ({cname})",
            lambda c=cid: list_all(
                cloud_guard.list_problems, c, lifecycle_state="ACTIVE", lifecycle_detail="OPEN"
            ),
            default=[],
            tolerate=service_not_subscribed,
        ) or []:
            out["problems"].append(problem_record(to_plain(problem)))

    out["targets"].sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    out["security_zones"].sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    out["security_recipes"].sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    out["problems"].sort(
        key=lambda r: (RISK_LEVELS.index(r["risk_level"]) if r["risk_level"] in RISK_LEVELS else 99,
                       r.get("time_first_detected") or "", r.get("id") or ""),
    )
    return out


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
    collected: dict = {}

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                collected = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("cloud_guard.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    configuration = collected.get("configuration")
    targets = collected.get("targets") or []
    zones = collected.get("security_zones") or []
    problems = collected.get("problems") or []

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "configuration": configuration,
            "targets": targets,
            "security_zones": zones,
            "security_recipes": collected.get("security_recipes") or [],
            "problems": problems,
        },
        summary=summarize(
            configuration, targets, zones, problems,
            compartments_in_scope=collected.get("compartments") or 0,
            tenancy_id=auth.get("tenancy"),
        ),
        compartments_scanned=collected.get("compartments"),
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_cloud_guard_posture_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)

    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
