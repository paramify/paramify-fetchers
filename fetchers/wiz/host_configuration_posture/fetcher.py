#!/usr/bin/env python3
"""
Wiz Host Configuration Posture (OS benchmarks, DISA STIG by default)

Wiz Host Configuration Rule assessments: operating-system benchmark checks Wiz
runs inside VMs and images (DISA STIG and CIS benchmarks for Windows Server,
RHEL, Ubuntu, Oracle Linux and others). Summarizes, for the benchmarks that
match WIZ_HOST_BENCHMARK_MATCH (default "DISA,STIG"), pass/fail counts per
benchmark and per host, open failures by severity and age, and the rules that
fail most.

Assessments that belong to no matching benchmark are still counted in
`scope.assessments_by_benchmark`, so nothing is dropped silently.

Speaks to KSI-SVC-ACM and KSI-MLA-EVC. It reports results; the verdict is
Paramify's.
"""

import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizClient,
    age_days,
    collect_guarded,
    env_int,
    env_list,
    evidence,
    run_fetcher,
)
from vuln_summary import sla_days  # type: ignore  # noqa: E402

logger = logging.getLogger("wiz_host_configuration_posture")

# Wiz returns an internal error on some pages when each assessment also pulls
# its rule's framework mapping (rule.securitySubCategories), so assessments are
# read with rule and host fields only, and the benchmark comes from a separate,
# best-effort rule lookup. The rule's shortName already names its benchmark
# (for example "RedHatEnterpriseLinux8.DISA.STIG.V1R12/RHEL-08-010010"), so a
# failed lookup still leaves every row labelled.
_ASSESSMENT_FIELDS = "id result severity status firstSeen analyzedAt"
_QUERY_TEMPLATE = """
query WizHostConfigurationAssessments($first: Int, $after: String, $filterBy: HostConfigurationRuleAssessmentFilters) {
  hostConfigurationRuleAssessments(first: $first, after: $after, filterBy: $filterBy) {
    nodes { %s }
    pageInfo { hasNextPage endCursor }
  }
}
"""
ASSESSMENTS_QUERY = _QUERY_TEMPLATE % (_ASSESSMENT_FIELDS + " rule { id name shortName externalId } resource { id name type }")
# Lighter versions tried, for one page at a time, only when the full query keeps failing.
FALLBACK_QUERIES = [
    _QUERY_TEMPLATE % (_ASSESSMENT_FIELDS + " rule { id name shortName externalId } resource { id name }"),
    _QUERY_TEMPLATE % (_ASSESSMENT_FIELDS + " rule { id name shortName externalId }"),
    # Last resort: no nested objects at all. Rows read this way have no rule, so
    # they are counted under "(no benchmark mapping)" rather than dropped.
    _QUERY_TEMPLATE % _ASSESSMENT_FIELDS,
]

RULES_QUERY = """
query WizHostConfigurationRuleBenchmarks($first: Int, $after: String, $filterBy: HostConfigurationRuleFilters) {
  hostConfigurationRules(first: $first, after: $after, filterBy: $filterBy) {
    nodes { id securitySubCategories { category { framework { name } } } }
    pageInfo { hasNextPage endCursor }
  }
}
"""

RESULTS = ["PASS", "FAIL", "ERROR", "NOT_ASSESSED"]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "NONE"]


def benchmark_from_short_name(short_name: Any) -> str:
    """'RedHatEnterpriseLinux5.CIS.V2.2.0.1/1.1.14' -> 'RedHatEnterpriseLinux5.CIS.V2.2.0.1'."""
    text = (short_name or "").strip()
    return text.split("/", 1)[0] if text else ""


def frameworks_by_rule(client: WizClient, rule_ids: List[str]) -> Tuple[Dict[str, List[str]], List[Dict[str, Any]]]:
    """
    Best-effort lookup of each rule's framework names. Errors here never fail
    the run: they are returned separately and reported in scope, because the
    rule shortName already carries the benchmark.
    """
    mapping: Dict[str, List[str]] = {}
    errors: List[Dict[str, Any]] = []
    chunk = env_int("WIZ_HOST_RULE_LOOKUP_CHUNK", 20)
    for i in range(0, len(rule_ids), chunk):
        ids = rule_ids[i:i + chunk]
        before = len(client.api_failures)
        nodes = client.paginate("hostConfigurationRules", RULES_QUERY, "hostConfigurationRules",
                                variables={"filterBy": {"id": ids}})
        if len(client.api_failures) > before:
            errors.extend(client.api_failures[before:])
            del client.api_failures[before:]
            if not nodes and not mapping:
                # The very first lookup failed outright (for example the filter
                # shape differs in this tenant); stop rather than repeat it.
                break
        for n in nodes:
            names = set()
            for sub in n.get("securitySubCategories") or []:
                fw = ((sub or {}).get("category") or {}).get("framework") or {}
                if fw.get("name"):
                    names.add(fw["name"])
            if n.get("id"):
                mapping[n["id"]] = sorted(names)
    return mapping, errors


def benchmarks_of(assessment: Dict[str, Any], rule_frameworks: Dict[str, List[str]]) -> List[str]:
    rule = assessment.get("rule") or {}
    names = list(rule_frameworks.get(rule.get("id") or "", []))
    if not names:
        label = benchmark_from_short_name(rule.get("shortName"))
        if label:
            names = [label]
    return names


def matches(names: List[str], rule: Dict[str, Any], needles: List[str]) -> List[str]:
    """Benchmark names that match; the rule shortName counts too, so a STIG rule
    is kept even when its framework name does not say DISA."""
    hits = [n for n in names if any(x in n.lower() for x in needles)]
    if not hits and any(x in (rule.get("shortName") or "").lower() for x in needles):
        hits = [benchmark_from_short_name(rule.get("shortName"))]
    return hits


def slim(a: Dict[str, Any], benchmark: str, now: datetime) -> Dict[str, Any]:
    rule = a.get("rule") or {}
    res = a.get("resource") or {}
    return {
        "id": a.get("id"),
        "benchmark": benchmark,
        "result": a.get("result"),
        "severity": a.get("severity"),
        "status": a.get("status"),
        "rule_id": rule.get("externalId") or rule.get("shortName") or rule.get("id"),
        "rule_name": rule.get("name"),
        "host": res.get("name"),
        "host_type": res.get("type"),
        "first_seen": a.get("firstSeen"),
        "open_age_days": age_days(a.get("firstSeen"), now),
        "analyzed_at": a.get("analyzedAt"),
    }


def summarize(rows: List[Dict[str, Any]], sample_size: int = 25) -> Dict[str, Any]:
    windows = sla_days()
    per_bench: Dict[str, Counter] = defaultdict(Counter)
    per_host: Dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        per_bench[r["benchmark"]][r.get("result") or "UNKNOWN"] += 1
        per_host[r.get("host") or "unknown"][r.get("result") or "UNKNOWN"] += 1

    def rate(c: Counter):
        p, f = c.get("PASS", 0), c.get("FAIL", 0)
        return round(100.0 * p / (p + f), 1) if (p + f) else None

    results = Counter(r.get("result") or "UNKNOWN" for r in rows)
    open_fail = [r for r in rows if r.get("result") == "FAIL" and r.get("status") in {"OPEN", "IN_PROGRESS"}]
    past = Counter(r["severity"] for r in open_fail
                   if r.get("severity") in windows and (r.get("open_age_days") or 0) > windows[r["severity"]])
    worst = sorted(open_fail, key=lambda r: (SEVERITIES.index(r["severity"]) if r.get("severity") in SEVERITIES else 99,
                                             -(r.get("open_age_days") or 0)))[:sample_size]
    last = [r.get("analyzed_at") for r in rows if r.get("analyzed_at")]
    return {
        "assessments_evaluated": len(rows),
        "by_result": dict(results),
        "pass_rate_pct": rate(results),
        "hosts_assessed": len(per_host),
        "benchmarks": {b: {"by_result": dict(c), "pass_rate_pct": rate(c)} for b, c in per_bench.items()},
        "hosts": {h: {"by_result": dict(c), "pass_rate_pct": rate(c)} for h, c in per_host.items()},
        "open_failures": len(open_fail),
        "open_failures_by_severity": {s: n for s, n in Counter(r.get("severity") for r in open_fail).items() if s},
        "remediation_windows_days": windows,
        "open_failures_past_window_by_severity": dict(past),
        "top_failing_rules": Counter(r.get("rule_name") or "unknown" for r in open_fail).most_common(15),
        "most_recent_analysis_at": max(last) if last else None,
        "worst_open_failures_sample": worst,
    }


def body(client: WizClient) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    needles = [x.lower() for x in env_list("WIZ_HOST_BENCHMARK_MATCH", ["DISA", "STIG"]) if x]
    client.page_size = min(client.page_size, env_int("WIZ_HOST_PAGE_SIZE", 25))
    cap = env_int("WIZ_MAX_RECORDS", 50000)

    # One pass per result value, so a page Wiz cannot serve only affects that slice.
    raw: List[Dict[str, Any]] = []
    by_result_fetched: Dict[str, int] = {}
    for result in RESULTS:
        part = client.paginate("hostConfigurationRuleAssessments", ASSESSMENTS_QUERY,
                               "hostConfigurationRuleAssessments", variables={"filterBy": {"result": result}},
                               max_records=cap, fallback_queries=FALLBACK_QUERIES)
        by_result_fetched[result] = len(part)
        raw.extend(part)

    rule_ids = sorted({(a.get("rule") or {}).get("id") for a in raw if (a.get("rule") or {}).get("id")})
    lookup_on = os.environ.get("WIZ_HOST_RULE_LOOKUP", "true").strip().lower() not in {"false", "0", "no"}
    rule_frameworks, lookup_errors = frameworks_by_rule(client, rule_ids) if lookup_on else ({}, [])

    all_benchmarks: Counter = Counter()
    rows: List[Dict[str, Any]] = []
    for a in raw:
        names = benchmarks_of(a, rule_frameworks) or ["(no benchmark mapping)"]
        for n in names:
            all_benchmarks[n] += 1
        for n in matches(names, a.get("rule") or {}, needles):
            rows.append(slim(a, n, now))

    label = ", ".join(repr(x) for x in needles)
    if client.api_failures:
        empty = ("Collection did not complete (see api_failures), so an empty or short result here "
                 "does NOT mean there are no matching assessments.")
    else:
        empty = (f"No host configuration assessments belong to a benchmark matching {label}. "
                 "See scope.assessments_by_benchmark for what Wiz did assess.")
    include = os.environ.get("WIZ_INCLUDE_RAW_FINDINGS", "true").strip().lower() not in {"false", "0", "no"}
    return evidence(
        client=client,
        operations=["hostConfigurationRuleAssessments", "hostConfigurationRules"],
        records=rows,
        analysis=summarize(rows),
        empty_message=empty,
        include_records=include,
        scope={
            "benchmark_match": needles,
            "assessments_in_tenant_query": len(raw),
            "assessments_by_result_fetched": by_result_fetched,
            "assessments_by_benchmark": dict(all_benchmarks.most_common()),
            "pages_served_by_lighter_query": client.fallback_pages,
            "lighter_query_note": ("Pages Wiz could not serve with host type included were re-read without it; "
                                   "those rows may lack host_type or host name."),
            "benchmark_source": ("Wiz framework mapping per rule, falling back to the rule shortName prefix"
                                 if rule_frameworks else "rule shortName prefix"),
            "rules_resolved_to_frameworks": len(rule_frameworks),
            "rule_lookup_errors": lookup_errors,
        },
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_host_configuration_posture.json", logger))
