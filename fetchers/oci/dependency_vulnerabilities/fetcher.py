#!/usr/bin/env python3
"""
OCI Application Dependency Management — third-party dependency risk

Every ADM knowledge base, vulnerability audit, remediation recipe and
remediation run in scope: which third-party dependencies were found vulnerable,
how severe, whether anything was suppressed, and whether a run actually fixed
them.

This is the evidence for KSI-SCR-MIT, "persistently identify, review, and
mitigate potential supply chain risks", and KSI-SCR-MON, "third party software
information resources are automatically monitored for upstream vulnerabilities".
SCR-MIT is uncovered across the whole repo. ADM's remediation-run stages are
that statement almost verbatim — DETECT identifies, RECOMMEND reviews, APPLY
mitigates, VERIFY confirms — so the stage a run reached is the evidence for how
far the process actually got.

THE SUPPRESSION GAP is the finding this fetcher exists to surface. ADM reports
every severity and count twice: `max_observed_severity` excludes vulnerabilities
the team chose to ignore, `max_observed_severity_with_ignored` includes them.
A project can drive its headline severity to NONE by suppressing findings rather
than fixing them, and the audit still reports success. The difference between
the two numbers is exactly what was suppressed, so both are reported and the
delta is derived rather than left for a reader to spot.

SCOPE LIMIT, stated because overclaiming here would be worse than a gap: ADM's
`build_type` enum is MAVEN or UNSET, so it covers Java/Maven dependency trees
and nothing else. A tenancy whose services are Python or Go will have no audits,
and that is a real absence of coverage rather than a clean bill of health. The
summary says so via `knowledge_bases_configured`, so "0 vulnerabilities" is
never mistaken for "0 vulnerabilities found by a scanner that was looking".
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
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_dependency_vulnerabilities")

# ADM's own severity ladder, ordered so the worst can be picked across audits.
SEVERITY_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Severities that should not sit unremediated in a FedRAMP boundary.
ACTIONABLE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})

# The four stages an ADM remediation run moves through, in order. Reaching
# VERIFY is the only one that evidences a mitigation actually landed.
STAGE_ORDER = ("DETECT", "RECOMMEND", "APPLY", "VERIFY")

# An audit older than this is stale as evidence of *persistent* monitoring.
AUDIT_CURRENCY_DAYS = 90


# --- pure transforms ---

def severity_rank(severity: str | None) -> int:
    """Position on the severity ladder; -1 for an unrecognised or absent value.

    Unknown sorts below NONE deliberately: a severity this fetcher does not
    recognise must never win a `max()` and silently become the headline.
    """
    try:
        return SEVERITY_ORDER.index(str(severity or "").upper())
    except ValueError:
        return -1


def worst_severity(severities) -> str | None:
    """The highest severity present, or None when none is recognisable."""
    ranked = [(severity_rank(s), s) for s in severities if severity_rank(s) >= 0]
    return max(ranked)[1].upper() if ranked else None


def suppression_delta(audit: dict) -> dict:
    """What the ignore-list is hiding, as a count and a severity step.

    `*_with_ignored` is the honest number; the bare field is what the team
    chose to look at. Reported as a delta because a reader comparing two
    similarly-named fields by eye is exactly how a suppression goes unnoticed.
    """
    visible_count = audit.get("vulnerable_artifacts_count")
    total_count = audit.get("vulnerable_artifacts_count_with_ignored")
    visible_sev = audit.get("max_observed_severity")
    total_sev = audit.get("max_observed_severity_with_ignored")
    # A CVSS ceiling cannot hide a finding that carries no score: on a live audit
    # tolerating CVSS 10.0, a MEDIUM with no score stayed visible over three
    # hidden criticals. So the scores are reported alongside, not instead of,
    # the severity pair.
    visible_v3 = audit.get("max_observed_cvss_v3_score")
    total_v3 = audit.get("max_observed_cvss_v3_score_with_ignored")

    hidden = None
    if isinstance(visible_count, int) and isinstance(total_count, int):
        hidden = max(total_count - visible_count, 0)

    return {
        "vulnerable_artifacts_visible": visible_count,
        "vulnerable_artifacts_including_ignored": total_count,
        "vulnerable_artifacts_suppressed": hidden,
        "max_severity_visible": visible_sev,
        "max_severity_including_ignored": total_sev,
        "max_cvss_v3_visible": visible_v3,
        "max_cvss_v3_including_ignored": total_v3,
        # True when suppression changed the headline severity, not merely the
        # count — the case where an audit reads clean and is not.
        "suppression_lowered_max_severity": (
            severity_rank(total_sev) > severity_rank(visible_sev)
            if visible_sev is not None and total_sev is not None
            else None
        ),
        "has_suppressed_findings": bool(hidden) if hidden is not None else None,
    }


def audit_record(audit: dict, *, now=None) -> dict:
    """Normalize one vulnerability audit into an evidence record."""
    created = audit.get("time_created")
    age = age_in_days(created, now=now)
    delta = suppression_delta(audit)
    state = str(audit.get("lifecycle_state") or "").upper()

    return {
        "id": audit.get("id"),
        "display_name": audit.get("display_name"),
        "compartment_id": audit.get("compartment_id"),
        "knowledge_base_id": audit.get("knowledge_base_id"),
        "lifecycle_state": audit.get("lifecycle_state"),
        # Whether the scan ran is the lifecycle, not `is_success`: ACTIVE is a
        # finished audit, FAILED a scan that did not complete, CREATING one in
        # progress.
        "scan_completed": state == "ACTIVE",
        "scan_failed": state == "FAILED",
        # `is_success` is Oracle's "succeeded according to the configuration":
        # the audit found nothing above the thresholds and outside the ignore
        # list the team set. A policy verdict, and one the team controls, so it
        # is reported beside the suppression delta rather than trusted alone.
        # None while CREATING. (Read as "the scan ran" until a live tenancy
        # showed three finished audits all reporting False.)
        "passes_own_thresholds": (
            audit["is_success"] if isinstance(audit.get("is_success"), bool) else None
        ),
        "build_type": audit.get("build_type"),
        "max_observed_cvss_v2_score": audit.get("max_observed_cvss_v2_score"),
        "max_observed_cvss_v3_score": audit.get("max_observed_cvss_v3_score"),
        "time_created": iso(created),
        "time_updated": iso(audit.get("time_updated")),
        "days_since_audit": age,
        "is_current": (age <= AUDIT_CURRENCY_DAYS) if age is not None else None,
        "has_actionable_findings": delta["max_severity_visible"] in ACTIONABLE_SEVERITIES,
        **delta,
    }


def remediation_run_record(run: dict, *, now=None) -> dict:
    """Normalize one remediation run — the `mitigate` half of the indicator."""
    stage = str(run.get("current_stage_type") or "").upper()
    finished = run.get("time_finished")

    return {
        "id": run.get("id"),
        "display_name": run.get("display_name"),
        "compartment_id": run.get("compartment_id"),
        "remediation_recipe_id": run.get("remediation_recipe_id"),
        "lifecycle_state": run.get("lifecycle_state"),
        "current_stage": stage or None,
        # DETECT -> RECOMMEND -> APPLY -> VERIFY. Only a run that reached VERIFY
        # evidences a fix that was applied AND confirmed.
        "stage_index": STAGE_ORDER.index(stage) if stage in STAGE_ORDER else None,
        "reached_apply": stage in ("APPLY", "VERIFY"),
        "reached_verify": stage == "VERIFY",
        # Scheduled rather than hand-run — "persistently" asks for automation.
        "run_source": run.get("remediation_run_source"),
        "time_created": iso(run.get("time_created")),
        "time_started": iso(run.get("time_started")),
        "time_finished": iso(finished),
        "days_since_run": age_in_days(finished, now=now),
    }


def knowledge_base_record(kb: dict) -> dict:
    """Normalize one knowledge base — the vulnerability source an audit reads."""
    return {
        "id": kb.get("id"),
        "display_name": kb.get("display_name"),
        "compartment_id": kb.get("compartment_id"),
        "lifecycle_state": kb.get("lifecycle_state"),
        "time_created": iso(kb.get("time_created")),
        "time_updated": iso(kb.get("time_updated")),
    }


def recipe_record(recipe: dict) -> dict:
    """Normalize one remediation recipe."""
    return {
        "id": recipe.get("id"),
        "display_name": recipe.get("display_name"),
        "compartment_id": recipe.get("compartment_id"),
        "knowledge_base_id": recipe.get("knowledge_base_id"),
        "lifecycle_state": recipe.get("lifecycle_state"),
        # A recipe that never runs on a schedule is not persistent monitoring.
        "is_run_triggered_on_kb_change": recipe.get("is_run_triggered_on_kb_change"),
        "time_created": iso(recipe.get("time_created")),
        "time_updated": iso(recipe.get("time_updated")),
    }


def summarize(
    knowledge_bases: list[dict],
    audits: list[dict],
    recipes: list[dict],
    runs: list[dict],
    *,
    api_readable: bool = True,
) -> dict:
    """Aggregate into the identify / review / mitigate story SCR-MIT asks for."""
    completed = [a for a in audits if a["scan_completed"]]
    passing = [a for a in audits if a["passes_own_thresholds"] is True]
    current = [a for a in completed if a["is_current"]]
    suppressed = [a for a in audits if a["has_suppressed_findings"]]
    masked = [a for a in audits if a["suppression_lowered_max_severity"]]
    actionable = [a for a in audits if a["has_actionable_findings"]]

    newest = max((a for a in audits if a["time_created"]), key=lambda a: a["time_created"], default=None)
    verified_runs = [r for r in runs if r["reached_verify"]]

    return {
        # False when ADM is not subscribed (recorded in metadata.skipped_calls)
        # or the list call failed — not "no dependency scanning".
        "adm_service_readable": api_readable,
        # The denominator question. Zero knowledge bases means nothing is being
        # scanned at all, which is not the same as nothing being found.
        "knowledge_bases_configured": len(knowledge_bases),
        "total_audits": len(audits),
        "audits_completed": len(completed),
        "audits_failed_to_scan": sum(1 for a in audits if a["scan_failed"]),
        "audits_passing_own_thresholds": len(passing),
        # A pass the ignore list paid for: the audit reads as succeeded while
        # findings it would otherwise report are being hidden.
        "audits_passing_with_suppressed_findings": sum(
            1 for a in passing if a["has_suppressed_findings"]
        ),
        "audits_within_90_days": len(current),
        "audit_currency_percentage": coverage_percentage(len(current), len(completed)),
        "latest_audit": newest["time_created"] if newest else None,
        "days_since_latest_audit": newest["days_since_audit"] if newest else None,
        # Identify.
        "audits_with_actionable_findings": len(actionable),
        # A clean audit says NONE; a finished one with no severity at all cannot
        # be counted as actionable or as clean.
        "completed_audits_with_unknown_severity": sum(
            1 for a in completed if severity_rank(a["max_severity_visible"]) < 0
        ),
        "worst_severity_observed": worst_severity(a["max_severity_visible"] for a in audits),
        "worst_severity_including_suppressed": worst_severity(
            a["max_severity_including_ignored"] for a in audits
        ),
        "total_vulnerable_artifacts": sum(
            a["vulnerable_artifacts_visible"] or 0 for a in audits
        ),
        # The suppression gap — the finding an assessor would otherwise miss.
        "audits_with_suppressed_findings": len(suppressed),
        "total_suppressed_artifacts": sum(
            a["vulnerable_artifacts_suppressed"] or 0 for a in audits
        ),
        "audits_where_suppression_lowered_severity": len(masked),
        # Review and mitigate.
        "remediation_recipes": len(recipes),
        "recipes_triggered_on_knowledge_base_change": sum(
            1 for r in recipes if r["is_run_triggered_on_kb_change"]
        ),
        "total_remediation_runs": len(runs),
        "remediation_runs_reaching_apply": sum(1 for r in runs if r["reached_apply"]),
        "remediation_runs_reaching_verify": len(verified_runs),
        "last_verified_remediation": max(
            (r["time_finished"] for r in verified_runs if r["time_finished"]), default=None
        ),
        "build_types_scanned": sorted({a["build_type"] for a in audits if a["build_type"]}),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    """Knowledge bases, audits, recipes and runs across every compartment in scope."""
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    adm = make_client(oci.adm.ApplicationDependencyManagementClient, auth)

    compartments = walk_compartments(
        identity,
        scope["compartment_id"],
        collector,
        include_subcompartments=include_sub,
        # Lets the walk choose the subtree listing, which OCI accepts only when
        # the root IS the tenancy.
        tenancy=auth.get("tenancy"),
    )

    knowledge_bases: list[dict] = []
    audits: list[dict] = []
    recipes: list[dict] = []
    runs: list[dict] = []
    unreadable = 0

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        kbs = collector.guard(
            f"adm.list_knowledge_bases ({cname})",
            lambda c=cid: list_all(adm.list_knowledge_bases, compartment_id=c),
            tolerate=service_not_subscribed,
        )
        if kbs is None:
            unreadable += 1
            continue
        knowledge_bases.extend(knowledge_base_record(to_plain(k)) for k in kbs)

        for audit in collector.guard(
            f"adm.list_vulnerability_audits ({cname})",
            lambda c=cid: list_all(adm.list_vulnerability_audits, compartment_id=c),
            default=[],
        ) or []:
            audits.append(audit_record(to_plain(audit)))

        for recipe in collector.guard(
            f"adm.list_remediation_recipes ({cname})",
            lambda c=cid: list_all(adm.list_remediation_recipes, compartment_id=c),
            default=[],
        ) or []:
            recipes.append(recipe_record(to_plain(recipe)))

        for run in collector.guard(
            f"adm.list_remediation_runs ({cname})",
            lambda c=cid: list_all(adm.list_remediation_runs, compartment_id=c),
            default=[],
        ) or []:
            runs.append(remediation_run_record(to_plain(run)))

    if compartments and unreadable == len(compartments):
        return None, None, None, None, len(compartments)

    knowledge_bases.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    recipes.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    # Newest first: the current state of dependency risk is what is being asked.
    audits.sort(key=lambda r: (r.get("time_created") or "", r.get("id") or ""), reverse=True)
    runs.sort(key=lambda r: (r.get("time_created") or "", r.get("id") or ""), reverse=True)
    return knowledge_bases, audits, recipes, runs, len(compartments)


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
    kbs = audits = recipes = runs = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            # Guarded as a whole: building a client parses the signing key, so a
            # malformed OCI_PRIVATE_KEY raises here rather than inside a guard.
            try:
                kbs, audits, recipes, runs, scanned = collect(
                    auth, scope, collector, include_sub=include_sub
                )
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("adm.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "knowledge_bases": kbs or [],
            "vulnerability_audits": audits or [],
            "remediation_recipes": recipes or [],
            "remediation_runs": runs or [],
        },
        summary=summarize(
            kbs or [], audits or [], recipes or [], runs or [], api_readable=kbs is not None
        ),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_dependency_vulnerabilities_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)

    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
