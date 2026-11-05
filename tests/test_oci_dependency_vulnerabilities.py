"""Audit, suppression and remediation judgements in `oci_dependency_vulnerabilities`.

The audit dicts carry the values three real ADM audits returned on 2026-09-21
(log4j-core 2.14.1, commons-text 1.9, jackson-databind 2.9.8): one with no
configuration, one excluding Log4Shell, one tolerating every CVSS score.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "dependency_vulnerabilities" / "fetcher.py"
NOW = datetime(2026, 9, 21, 20, tzinfo=timezone.utc)
CREATED = datetime(2026, 9, 21, 19, 16, tzinfo=timezone.utc)


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_dependency_vulnerabilities", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adm = _load()


def _audit(name="a", *, state="ACTIVE", success=False, sev="CRITICAL", sev_all="CRITICAL",
           count=3, count_all=3, v3=10.0, v3_all=10.0, created=CREATED):
    return {"id": f"ocid1.admvulnerabilityaudit.oc1..{name}", "display_name": name,
            "lifecycle_state": state, "is_success": success, "build_type": "MAVEN",
            "max_observed_severity": sev, "max_observed_severity_with_ignored": sev_all,
            "vulnerable_artifacts_count": count, "vulnerable_artifacts_count_with_ignored": count_all,
            "max_observed_cvss_v3_score": v3, "max_observed_cvss_v3_score_with_ignored": v3_all,
            "time_created": created}


PLAIN = _audit("plain")
SUPPRESSED = _audit("suppressed", count=2, v3=9.8)
MASKED = _audit("masked", sev="MEDIUM", count=1, v3=None)


def test_a_finished_audit_that_found_vulnerabilities_is_still_completed():
    """Live: all three audits ACTIVE with is_success False. Read as "scan ran",
    that made audits_completed 0 and audit currency 0% on a tenancy scanned an
    hour earlier."""
    records = [adm.audit_record(a, now=NOW) for a in (PLAIN, SUPPRESSED, MASKED)]
    assert all(r["scan_completed"] for r in records)
    assert not any(r["passes_own_thresholds"] for r in records)
    out = adm.summarize([{}], records, [], [])
    assert out["audits_completed"] == 3
    assert out["audits_within_90_days"] == 3
    assert out["audit_currency_percentage"] == 100
    assert out["audits_passing_own_thresholds"] == 0


def test_an_audit_in_progress_has_no_verdict_yet():
    record = adm.audit_record(_audit(state="CREATING", success=None), now=NOW)
    assert record["scan_completed"] is False
    assert record["passes_own_thresholds"] is None


def test_a_failed_scan_is_counted_and_is_not_a_completed_audit():
    out = adm.summarize([{}], [adm.audit_record(_audit(state="FAILED", success=None), now=NOW)], [], [])
    assert out["audits_failed_to_scan"] == 1
    assert out["audits_completed"] == 0


def test_a_cvss_ceiling_lowers_the_headline_severity_and_that_is_named():
    record = adm.audit_record(MASKED, now=NOW)
    assert record["suppression_lowered_max_severity"] is True
    assert record["vulnerable_artifacts_suppressed"] == 2
    assert record["max_cvss_v3_visible"] is None
    assert record["max_cvss_v3_including_ignored"] == 10.0
    out = adm.summarize([{}], [record], [], [])
    assert out["worst_severity_observed"] == "MEDIUM"
    assert out["worst_severity_including_suppressed"] == "CRITICAL"


def test_an_exclusion_that_leaves_the_headline_unchanged_is_suppression_but_not_masking():
    record = adm.audit_record(SUPPRESSED, now=NOW)
    assert record["has_suppressed_findings"] is True
    assert record["suppression_lowered_max_severity"] is False


def test_a_pass_bought_with_the_ignore_list_is_counted_apart_from_a_clean_pass():
    bought = adm.audit_record(_audit("bought", success=True, sev="NONE", count=0), now=NOW)
    clean = adm.audit_record(_audit("clean", success=True, sev="NONE", sev_all="NONE",
                                    count=0, count_all=0, v3=None, v3_all=None), now=NOW)
    out = adm.summarize([{}], [bought, clean], [], [])
    assert out["audits_passing_own_thresholds"] == 2
    assert out["audits_passing_with_suppressed_findings"] == 1


def test_an_unrecognised_severity_never_becomes_the_headline():
    assert adm.worst_severity(["SEVERE", "LOW"]) == "LOW"
    assert adm.worst_severity(["SEVERE", None]) is None


def test_only_a_run_that_reached_verify_evidences_a_confirmed_fix():
    applied = adm.remediation_run_record({"current_stage_type": "APPLY"}, now=NOW)
    verified = adm.remediation_run_record({"current_stage_type": "verify",
                                           "time_finished": CREATED}, now=NOW)
    unknown = adm.remediation_run_record({"current_stage_type": "SOMETHING_NEW"}, now=NOW)
    assert applied["reached_apply"] and not applied["reached_verify"]
    assert verified["reached_verify"] and verified["stage_index"] == 3
    assert unknown["stage_index"] is None and not unknown["reached_apply"]
    out = adm.summarize([{}], [], [], [applied, verified, unknown])
    assert out["remediation_runs_reaching_apply"] == 2
    assert out["remediation_runs_reaching_verify"] == 1


def test_no_knowledge_base_is_not_a_clean_result():
    out = adm.summarize([], [], [], [])
    assert out["knowledge_bases_configured"] == 0
    assert out["worst_severity_observed"] is None
    assert out["audit_currency_percentage"] in (0, None)
