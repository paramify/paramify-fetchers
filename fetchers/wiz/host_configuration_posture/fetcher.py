#!/usr/bin/env python3
"""
Wiz Host Configuration Posture (OS benchmarks, DISA STIG by default)

Wiz Host Configuration Rule assessments: operating-system benchmark checks Wiz
runs inside VMs and images (DISA STIG and CIS benchmarks for Windows Server,
RHEL, Ubuntu, Oracle Linux and others). Summarizes, for the benchmarks that
match WIZ_HOST_BENCHMARK_MATCH (default "DISA"), pass/fail counts per
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
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizClient,
    age_days,
    collect_guarded,
    env_int,
    evidence,
    run_fetcher,
)
from vuln_summary import sla_days  # type: ignore  # noqa: E402

logger = logging.getLogger("wiz_host_configuration_posture")

ASSESSMENTS_QUERY = """
query WizHostConfigurationAssessments($first: Int, $after: String) {
  hostConfigurationRuleAssessments(first: $first, after: $after) {
    nodes {
      id
      result
      severity
      status
      firstSeen
      analyzedAt
      rule {
        id
        name
        shortName
        externalId
        securitySubCategories { category { framework { name } } }
      }
      resource { id name type }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "NONE"]


def benchmarks_of(assessment: Dict[str, Any]) -> List[str]:
    rule = assessment.get("rule") or {}
    names = set()
    for sub in rule.get("securitySubCategories") or []:
        fw = ((sub or {}).get("category") or {}).get("framework") or {}
        if fw.get("name"):
            names.add(fw["name"])
    return sorted(names)


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
    match = os.environ.get("WIZ_HOST_BENCHMARK_MATCH", "").strip() or "DISA"
    raw = client.paginate("hostConfigurationRuleAssessments", ASSESSMENTS_QUERY,
                          "hostConfigurationRuleAssessments", max_records=env_int("WIZ_MAX_RECORDS", 50000))

    all_benchmarks: Counter = Counter()
    rows: List[Dict[str, Any]] = []
    for a in raw:
        names = benchmarks_of(a) or ["(no benchmark mapping)"]
        for n in names:
            all_benchmarks[n] += 1
        matched = [n for n in names if match.lower() in n.lower()]
        for n in matched:
            rows.append(slim(a, n, now))

    include = os.environ.get("WIZ_INCLUDE_RAW_FINDINGS", "true").strip().lower() not in {"false", "0", "no"}
    return evidence(
        client=client,
        operations=["hostConfigurationRuleAssessments"],
        records=rows,
        analysis=summarize(rows),
        empty_message=f"No host configuration assessments belong to a benchmark matching {match!r}. "
                      "See scope.assessments_by_benchmark for what Wiz did assess.",
        include_records=include,
        scope={"benchmark_match": match, "assessments_in_tenant_query": len(raw),
               "assessments_by_benchmark": dict(all_benchmarks.most_common())},
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_host_configuration_posture.json", logger))
