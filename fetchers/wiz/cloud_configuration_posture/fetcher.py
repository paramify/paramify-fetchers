#!/usr/bin/env python3
"""
Wiz Cloud Configuration Posture

Wiz Cloud Configuration Rule (CSPM) results for one security framework, by
default NIST SP 800-53 Revision 5: how many resource checks pass and fail,
which rules fail most, how severe the open failures are and how long they have
been open, broken down by cloud account.

Why a framework and not "DISA STIG": in Wiz, DISA STIG benchmarks are
operating-system benchmarks (see wiz_host_configuration_posture). For cloud
control-plane settings the FedRAMP-relevant mappings are NIST 800-53 and
FedRAMP. Set WIZ_SECURITY_FRAMEWORK to change it; the name is looked up at run
time, never hard-coded as an ID.

Wiz stops returning configurationFindings after 10,000 rows per query. A
result count that lands exactly on that number is recorded as a failure,
because it almost certainly means truncation.

Speaks to KSI-MLA-EVC and KSI-CNA-EIS. It reports results; it does not decide
whether the pass rate is acceptable.
"""

import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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


logger = logging.getLogger("wiz_cloud_configuration_posture")

WIZ_ROW_CAP = 10000
DEFAULT_FRAMEWORK = "NIST SP 800-53 Revision 5"

FRAMEWORKS_QUERY = """
query WizFrameworks($first: Int, $after: String) {
  securityFrameworks(first: $first, after: $after) {
    nodes { id name enabled }
    pageInfo { hasNextPage endCursor }
  }
}
"""

FINDINGS_QUERY = """
query WizConfigurationFindings($first: Int, $after: String, $filterBy: ConfigurationFindingFilters) {
  configurationFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      name
      result
      severity
      status
      firstSeenAt
      analyzedAt
      rule { id shortId name }
      resource { id name type nativeType region cloudPlatform subscription { name externalId } }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "NONE"]


def find_framework(frameworks: List[Dict[str, Any]], wanted: str) -> Optional[Dict[str, Any]]:
    exact = [f for f in frameworks if (f.get("name") or "").strip().lower() == wanted.strip().lower()]
    if exact:
        return exact[0]
    partial = [f for f in frameworks if wanted.strip().lower() in (f.get("name") or "").lower()]
    return partial[0] if len(partial) == 1 else None


def slim(f: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    rule = f.get("rule") or {}
    res = f.get("resource") or {}
    sub = res.get("subscription") or {}
    return {
        "id": f.get("id"),
        "result": f.get("result"),
        "severity": f.get("severity"),
        "status": f.get("status"),
        "rule_id": rule.get("shortId") or rule.get("id"),
        "rule_name": rule.get("name") or f.get("name"),
        "resource_name": res.get("name"),
        "resource_type": res.get("nativeType") or res.get("type"),
        "cloud_platform": res.get("cloudPlatform"),
        "region": res.get("region"),
        "account": sub.get("name") or sub.get("externalId"),
        "first_seen_at": f.get("firstSeenAt"),
        "open_age_days": age_days(f.get("firstSeenAt"), now),
        "analyzed_at": f.get("analyzedAt"),
    }


def summarize(rows: List[Dict[str, Any]], sample_size: int = 25) -> Dict[str, Any]:
    windows = sla_days()
    results = Counter(r.get("result") or "UNKNOWN" for r in rows)
    passed, failed = results.get("PASS", 0), results.get("FAIL", 0)
    open_fail = [r for r in rows if r.get("result") == "FAIL" and r.get("status") in {"OPEN", "IN_PROGRESS"}]
    past = Counter(r["severity"] for r in open_fail
                   if r.get("severity") in windows and (r.get("open_age_days") or 0) > windows[r["severity"]])

    per_account: Dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        per_account[r.get("account") or "unknown"][r.get("result") or "UNKNOWN"] += 1

    rules_checked = {r.get("rule_id") for r in rows if r.get("rule_id")}
    failing_rules = Counter(r.get("rule_name") or "unknown" for r in open_fail)
    worst = sorted(open_fail, key=lambda r: (SEVERITIES.index(r["severity"]) if r.get("severity") in SEVERITIES else 99,
                                             -(r.get("open_age_days") or 0)))[:sample_size]
    last = [r.get("analyzed_at") for r in rows if r.get("analyzed_at")]

    return {
        "checks_evaluated": len(rows),
        "by_result": dict(results),
        "pass_count": passed,
        "fail_count": failed,
        "pass_rate_pct": round(100.0 * passed / (passed + failed), 1) if (passed + failed) else None,
        "rules_evaluated": len(rules_checked),
        "resources_evaluated": len({r.get("resource_name") for r in rows if r.get("resource_name")}),
        "open_failures": len(open_fail),
        "open_failures_by_severity": {s: n for s, n in Counter(r.get("severity") for r in open_fail).items() if s},
        "remediation_windows_days": windows,
        "open_failures_past_window_by_severity": dict(past),
        "top_failing_rules": failing_rules.most_common(15),
        "by_account": {a: dict(c) for a, c in per_account.items()},
        "most_recent_analysis_at": max(last) if last else None,
        "worst_open_failures_sample": worst,
    }


def body(client: WizClient) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    wanted = os.environ.get("WIZ_SECURITY_FRAMEWORK", "").strip() or DEFAULT_FRAMEWORK
    frameworks = client.paginate("securityFrameworks", FRAMEWORKS_QUERY, "securityFrameworks")
    fw = find_framework(frameworks, wanted)
    if fw is None:
        client.api_failures.append({
            "operation": "securityFrameworks", "type": "FrameworkNotFound",
            "message": f"no single Wiz framework matches {wanted!r}; set WIZ_SECURITY_FRAMEWORK to an exact name",
        })
        return evidence(client=client, operations=["securityFrameworks"], records=[], analysis={},
                        empty_message=f"Framework {wanted!r} not found.", framework={"requested": wanted})

    raw = client.paginate(
        "configurationFindings", FINDINGS_QUERY, "configurationFindings",
        {"filterBy": {"securityFramework": fw["id"], "result": ["PASS", "FAIL"]}},
        max_records=env_int("WIZ_MAX_RECORDS", 50000),
    )
    if len(raw) == WIZ_ROW_CAP:
        client.api_failures.append({
            "operation": "configurationFindings", "type": "WizRowCapReached",
            "message": "exactly 10,000 findings returned; Wiz caps this query at 10,000 rows, so the "
                       "evidence is probably truncated. Narrow the scope (framework or account).",
        })
    rows = [slim(f, now) for f in raw]
    include = os.environ.get("WIZ_INCLUDE_RAW_FINDINGS", "true").strip().lower() not in {"false", "0", "no"}
    return evidence(
        client=client,
        operations=["securityFrameworks", "configurationFindings"],
        records=rows,
        analysis=summarize(rows),
        empty_message=f"Wiz returned no PASS/FAIL configuration results for {fw['name']}. "
                      "Check wiz_scan_coverage and that the framework applies to this cloud.",
        include_records=include,
        framework={"requested": wanted, "id": fw["id"], "name": fw["name"],
                   "enabled_in_tenant": fw.get("enabled")},
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_cloud_configuration_posture.json", logger))
