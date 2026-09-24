#!/usr/bin/env python3
"""
Wiz STIG compliance report: one CSV row per STIG control, per rule, per resource.

Pulls pass/fail results for one enabled Wiz security framework (a DISA STIG such
as "Okta IDaaS STIG", or a CIS STIG benchmark) and writes them as a CSV for a
Paramify CONFIGURATION assessment. This is the per-asset checklist shape a ConMon
assessor expects: every rule the framework maps, on every resource it applies to,
with its result.

Two Wiz sources, both read with GraphQL *queries* only:

  cloud  configurationFindings filtered to the framework (cloud configuration
         rules: Okta, AWS, Azure, ... settings)
  host   hostConfigurationRuleAssessments whose rule maps to the framework
         (OS benchmark checks inside VMs and images). Skipped when
         WIZ_STIG_INCLUDE_HOST=false.

READ-ONLY, and why this CSV is ours rather than Wiz's. Wiz's own "Compliance
Assessment" CSV only exists as a saved report, and creating or rerunning a report
is a write to the tenant. This fetcher must never write to Wiz (the shared client
refuses to send a mutation), so it assembles the rows itself from read-only
queries. The columns are fixed and documented in README.md, so the Paramify
intake preset can map them once. Change COLUMNS only with a version bump.

Rows are sorted, so the same Wiz state always produces the same bytes.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizAuthError,
    WizClient,
    WizConfigError,
    build_client,
    env_int,
    report_failure,
)

logger = logging.getLogger("wiz_stig_compliance_report")

# The file contract. Paramify's intake preset maps these by header name.
COLUMNS = [
    "Record ID",          # finding id + control id: unique per row, stable across runs
    "Framework",
    "Control ID",         # e.g. V-273186
    "Control Title",      # e.g. SRG-APP-000003
    "Rule Type",          # Cloud Configuration | Host Configuration
    "Rule ID",
    "Rule Name",
    "Result",             # PASS | FAIL (as Wiz reports it)
    "Status",
    "Severity",
    "Resource ID",
    "Resource Name",
    "Resource Type",
    "Cloud Platform",
    "Region",
    "Subscription",
    "Subscription ID",
    "First Seen",
    "Last Analyzed",
    "Finding ID",
]

WIZ_ROW_CAP = 10000  # Wiz stops returning configurationFindings at 10,000 rows per query
RESULTS = ["PASS", "FAIL"]

FRAMEWORKS_QUERY = """
query WizFrameworks($first: Int, $after: String) {
  securityFrameworks(first: $first, after: $after) {
    nodes { id name enabled }
    pageInfo { hasNextPage endCursor }
  }
}
"""

_SUBCATS = "securitySubCategories { externalId title category { framework { id } } }"
_CLOUD_TEMPLATE = """
query WizStigConfigurationFindings($first: Int, $after: String, $filterBy: ConfigurationFindingFilters) {
  configurationFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id result severity status firstSeenAt analyzedAt
      rule { id shortId name %s }
      resource { id name type nativeType region cloudPlatform subscription { name externalId } }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""
CLOUD_QUERY = _CLOUD_TEMPLATE % _SUBCATS
# Used for a page only if the full query keeps failing. Rows read this way carry
# no control mapping and are counted in the log, never silently written blank.
CLOUD_FALLBACKS = [_CLOUD_TEMPLATE % ""]

_HOST_TEMPLATE = """
query WizStigHostAssessments($first: Int, $after: String, $filterBy: HostConfigurationRuleAssessmentFilters) {
  hostConfigurationRuleAssessments(first: $first, after: $after, filterBy: $filterBy) {
    nodes { id result severity status firstSeen analyzedAt %s }
    pageInfo { hasNextPage endCursor }
  }
}
"""
HOST_QUERY = _HOST_TEMPLATE % "rule { id name shortName externalId } resource { id name type }"
HOST_FALLBACKS = [_HOST_TEMPLATE % "rule { id name shortName externalId } resource { id name }"]

HOST_RULES_QUERY = """
query WizStigHostRules($first: Int, $after: String, $filterBy: HostConfigurationRuleFilters) {
  hostConfigurationRules(first: $first, after: $after, filterBy: $filterBy) {
    nodes { id securitySubCategories { externalId title category { framework { id } } } }
    pageInfo { hasNextPage endCursor }
  }
}
"""


class StigError(Exception):
    def __init__(self, message: str, code: str = "partial_failure"):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- helpers


def truthy(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw not in {"false", "0", "no", "off"}


def find_framework(frameworks: List[Dict[str, Any]], wanted: str) -> Dict[str, Any]:
    """Resolve by exact id (wf-id-305) or exact name, case-insensitively. Never fuzzy."""
    w = wanted.strip().lower()
    hits = [f for f in frameworks if (f.get("id") or "").lower() == w or (f.get("name") or "").strip().lower() == w]
    if len(hits) != 1:
        close = sorted(f.get("name") or "" for f in frameworks if "stig" in (f.get("name") or "").lower())
        raise StigError(
            f"no single Wiz framework matches {wanted!r}. STIG frameworks visible: {close or 'none'}",
            "bad_config",
        )
    return hits[0]


def controls_for(subcats: Iterable[Dict[str, Any]], framework_id: str) -> List[Tuple[str, str]]:
    """(control id, title) pairs of a rule that belong to this framework, sorted and de-duplicated."""
    out = set()
    for sub in subcats or []:
        fw = ((sub or {}).get("category") or {}).get("framework") or {}
        if fw.get("id") == framework_id:
            out.add(((sub.get("externalId") or "").strip(), (sub.get("title") or "").strip()))
    return sorted(out)


def target_suffix(framework: str) -> str:
    """One filename per target: every target writes into the same issue-reports/ dir."""
    return "_" + re.sub(r"[^A-Za-z0-9._-]+", "_", framework.strip()).strip("_") if framework.strip() else ""


def check(client: WizClient, before: int) -> None:
    """Turn failures the shared client recorded since `before` into a hard stop.

    A partial compliance CSV is worse than none: intake reads a missing row as a
    resolved finding. So any recorded failure fails the whole run.
    """
    failures = client.api_failures[before:]
    if not failures:
        return
    text = "; ".join(f"{f.get('operation')}: {f.get('type')}: {f.get('message')}" for f in failures[:3])
    lowered = text.lower()
    if any(s in lowered for s in ("permission", "unauthorized", "not authorized", "forbidden", "http 403")):
        code = "not_authorized"
    elif "http 429" in lowered or "rate" in lowered:
        code = "rate_limited"
    elif "connectionerror" in lowered:
        code = "target_unreachable"
    else:
        code = "partial_failure"
    raise StigError(f"Wiz read failed, no report written: {text}", code)


# --------------------------------------------------------------------------- collection


def cloud_rows(client: WizClient, fw: Dict[str, Any]) -> Tuple[List[Dict[str, str]], int]:
    before = len(client.api_failures)
    fallback_before = client.fallback_pages
    nodes = client.paginate(
        "configurationFindings", CLOUD_QUERY, "configurationFindings",
        {"filterBy": {"securityFramework": fw["id"], "result": RESULTS}},
        max_records=env_int("WIZ_MAX_RECORDS", 50000), fallback_queries=CLOUD_FALLBACKS,
    )
    check(client, before)
    if len(nodes) == WIZ_ROW_CAP:
        raise StigError("exactly 10,000 cloud findings returned; Wiz caps this query at 10,000 rows, so the "
                        "report would be truncated. Scope the framework or tenant down.")
    if client.fallback_pages > fallback_before:
        raise StigError("Wiz could not return STIG control mappings for some cloud findings "
                        f"({client.fallback_pages - fallback_before} page(s)); refusing to write rows without "
                        "control IDs. Retry, or lower WIZ_PAGE_SIZE.")

    rows: List[Dict[str, str]] = []
    unmapped = 0
    for n in nodes:
        rule = n.get("rule") or {}
        res = n.get("resource") or {}
        sub = res.get("subscription") or {}
        pairs = controls_for(rule.get("securitySubCategories"), fw["id"])
        if not pairs:
            unmapped += 1
            continue
        for control_id, title in pairs:
            rows.append(row(fw, control_id, title, "Cloud Configuration", rule.get("shortId") or rule.get("id"),
                            rule.get("name"), n, res.get("id"), res.get("name"),
                            res.get("nativeType") or res.get("type"), res.get("cloudPlatform"),
                            res.get("region"), sub.get("name"), sub.get("externalId"),
                            n.get("firstSeenAt"), n.get("analyzedAt")))
    return rows, unmapped


def host_rows(client: WizClient, fw: Dict[str, Any]) -> Tuple[List[Dict[str, str]], int]:
    # One pass per result value, the filter shape wiz_host_configuration_posture
    # uses against the live tenant (a single value, not a list).
    nodes: List[Dict[str, Any]] = []
    for result in RESULTS:
        before = len(client.api_failures)
        nodes.extend(client.paginate(
            "hostConfigurationRuleAssessments", HOST_QUERY, "hostConfigurationRuleAssessments",
            {"filterBy": {"result": result}},
            max_records=env_int("WIZ_MAX_RECORDS", 50000), fallback_queries=HOST_FALLBACKS,
        ))
        check(client, before)

    rule_ids = sorted({(n.get("rule") or {}).get("id") for n in nodes if (n.get("rule") or {}).get("id")})
    mapping: Dict[str, List[Tuple[str, str]]] = {}
    chunk = max(1, env_int("WIZ_HOST_RULE_LOOKUP_CHUNK", 20))
    for i in range(0, len(rule_ids), chunk):
        before = len(client.api_failures)
        rules = client.paginate("hostConfigurationRules", HOST_RULES_QUERY, "hostConfigurationRules",
                                {"filterBy": {"id": rule_ids[i:i + chunk]}})
        check(client, before)
        for r in rules:
            pairs = controls_for(r.get("securitySubCategories"), fw["id"])
            if pairs and r.get("id"):
                mapping[r["id"]] = pairs

    rows: List[Dict[str, str]] = []
    for n in nodes:
        rule = n.get("rule") or {}
        res = n.get("resource") or {}
        for control_id, title in mapping.get(rule.get("id") or "", []):
            rows.append(row(fw, control_id, title, "Host Configuration",
                            rule.get("externalId") or rule.get("shortName") or rule.get("id"), rule.get("name"),
                            n, res.get("id"), res.get("name"), res.get("type"), None, None, None, None,
                            n.get("firstSeen"), n.get("analyzedAt")))
    return rows, len(nodes)


def row(fw, control_id, title, rule_type, rule_id, rule_name, node, res_id, res_name, res_type,
        platform, region, sub_name, sub_id, first_seen, analyzed) -> Dict[str, str]:
    values = {
        "Record ID": f"{node.get('id')}:{control_id}",
        "Framework": fw.get("name"),
        "Control ID": control_id,
        "Control Title": title,
        "Rule Type": rule_type,
        "Rule ID": rule_id,
        "Rule Name": rule_name,
        "Result": node.get("result"),
        "Status": node.get("status"),
        "Severity": node.get("severity"),
        "Resource ID": res_id,
        "Resource Name": res_name,
        "Resource Type": res_type,
        "Cloud Platform": platform,
        "Region": region,
        "Subscription": sub_name,
        "Subscription ID": sub_id,
        "First Seen": first_seen,
        "Last Analyzed": analyzed,
        "Finding ID": node.get("id"),
    }
    return {k: "" if v is None else str(v) for k, v in values.items()}


def render_csv(rows: List[Dict[str, str]]) -> bytes:
    rows = sorted(rows, key=lambda r: (r["Control ID"], r["Rule Type"], r["Resource Name"], r["Rule ID"],
                                       r["Record ID"]))
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


def collect(client: WizClient, wanted: str, include_host: bool) -> Tuple[bytes, Dict[str, Any]]:
    before = len(client.api_failures)
    frameworks = client.paginate("securityFrameworks", FRAMEWORKS_QUERY, "securityFrameworks")
    check(client, before)
    fw = find_framework(frameworks, wanted)
    if fw.get("enabled") is False:
        raise StigError(f"Wiz framework {fw['name']!r} ({fw['id']}) is not enabled, so Wiz assesses nothing "
                        "against it. Enable it in Wiz (Policies > Frameworks) first.", "bad_config")

    rows, unmapped = cloud_rows(client, fw)
    stats: Dict[str, Any] = {"framework": fw, "cloud_rows": len(rows), "cloud_findings_without_control": unmapped}
    if include_host:
        h_rows, scanned = host_rows(client, fw)
        rows.extend(h_rows)
        stats.update(host_rows=len(h_rows), host_assessments_scanned=scanned)

    if not rows:
        # Intake reads an empty report as "no findings" and would resolve every open
        # issue on the assessment. Never hand it one.
        raise StigError(f"Wiz returned no PASS/FAIL results mapped to {fw['name']!r}; check that its rules "
                        "apply to resources this service account can see (wiz_scan_coverage).")
    return render_csv(rows), stats


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    wanted = os.environ.get("WIZ_STIG_FRAMEWORK", "").strip()
    if not wanted:
        report_failure("WIZ_STIG_FRAMEWORK is not set (a Wiz framework id like wf-id-305, or its exact name)",
                       "bad_config")
        return 1

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_path = output_dir / f"wiz_stig_compliance_report{target_suffix(wanted)}.csv"
    try:
        client = build_client()
        content, stats = collect(client, wanted, truthy("WIZ_STIG_INCLUDE_HOST", True))
    except WizConfigError as e:
        report_failure(str(e), "bad_config")
        return 1
    except WizAuthError as e:
        report_failure(str(e), "auth_failed")
        return 1
    except StigError as e:
        report_failure(str(e), e.code)
        return 1
    except Exception as e:  # noqa: BLE001 - last-resort reason for the operator
        report_failure(f"unexpected error: {type(e).__name__}: {e}", "internal_error")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(content)
    fw = stats["framework"]
    logger.info("Report saved to %s (%d rows: %d cloud, %s host) for %s (%s); %d cloud findings had no "
                "control in this framework", output_path, stats["cloud_rows"] + stats.get("host_rows", 0),
                stats["cloud_rows"], stats.get("host_rows", "skipped"), fw["name"], fw["id"],
                stats["cloud_findings_without_control"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
