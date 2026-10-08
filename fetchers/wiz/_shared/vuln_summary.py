#!/usr/bin/env python3
"""
Vulnerability-finding collection and summary shared by
wiz_infrastructure_vulnerabilities and wiz_container_vulnerabilities.

Both fetchers read the same Wiz ``vulnerabilityFindings`` connection and differ
only in which vulnerable-asset types they keep. The split is done here, on the
``vulnerableAsset.type`` Wiz returns, rather than with a server-side filter,
because the asset-type filter field has not been verified against a live
tenant yet. The ``by_asset_type`` breakdown in every summary shows exactly what
was kept, so a reviewer can see if a type landed in the wrong bucket.

Nothing here decides pass or fail. Remediation-deadline numbers are reported
against configurable windows (defaults follow FedRAMP's usual 30/90/180 days for
critical-high/moderate/low); whether they are acceptable is Paramify's call.
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from wiz_client import WizClient, age_days, env_int, env_list

VULN_QUERY = """
query WizVulnerabilityFindings($first: Int, $after: String, $filterBy: VulnerabilityFindingFilters) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      name
      severity
      status
      firstDetectedAt
      lastDetectedAt
      detectionMethod
      fixedVersion
      hasCisaKevExploit
      vulnerableAsset {
        ... on VulnerableAssetBase { id type name }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "NONE"]

CONTAINER_TYPES = {"CONTAINER_IMAGE", "CONTAINER", "POD"}
# Wiz Code findings (repositories, IaC) are application/code evidence, not host
# or container scanning; they are counted but excluded from both fetchers.
CODE_TYPE_MARKERS = ("REPOSITORY", "CODE", "BRANCH")


def asset_bucket(asset_type: Optional[str]) -> str:
    t = (asset_type or "").upper()
    if not t:
        return "unknown"
    if t in CONTAINER_TYPES or "CONTAINER" in t:
        return "container"
    if any(marker in t for marker in CODE_TYPE_MARKERS):
        return "code"
    return "infrastructure"


def sla_days() -> Dict[str, int]:
    return {
        "CRITICAL": env_int("WIZ_SLA_CRITICAL_DAYS", 30),
        "HIGH": env_int("WIZ_SLA_HIGH_DAYS", 30),
        "MEDIUM": env_int("WIZ_SLA_MEDIUM_DAYS", 90),
        "LOW": env_int("WIZ_SLA_LOW_DAYS", 180),
    }


def fetch_findings(client: WizClient) -> List[Dict[str, Any]]:
    statuses = env_list("WIZ_VULN_STATUSES", ["OPEN"])
    return client.paginate(
        "vulnerabilityFindings",
        VULN_QUERY,
        "vulnerabilityFindings",
        variables={"filterBy": {"status": statuses}},
        max_records=env_int("WIZ_MAX_RECORDS", 50000),
    )


def slim(finding: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    asset = finding.get("vulnerableAsset") or {}
    return {
        "id": finding.get("id"),
        "cve": finding.get("name"),
        "severity": finding.get("severity"),
        "status": finding.get("status"),
        "first_detected_at": finding.get("firstDetectedAt"),
        "last_detected_at": finding.get("lastDetectedAt"),
        "age_days": age_days(finding.get("firstDetectedAt"), now),
        "fix_available": bool(finding.get("fixedVersion")),
        "cisa_kev": bool(finding.get("hasCisaKevExploit")),
        "detection_method": finding.get("detectionMethod"),
        "asset_id": asset.get("id"),
        "asset_type": asset.get("type"),
        "asset_name": asset.get("name"),
    }


def summarize(records: Iterable[Dict[str, Any]], now: Optional[datetime] = None, sample_size: int = 25) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    rows = list(records)
    windows = sla_days()

    by_severity = Counter((r.get("severity") or "UNKNOWN") for r in rows)
    past_window = Counter()
    oldest: Dict[str, Optional[int]] = {}
    for r in rows:
        sev = r.get("severity") or "UNKNOWN"
        age = r.get("age_days")
        if age is None:
            continue
        if oldest.get(sev) is None or age > oldest[sev]:
            oldest[sev] = age
        if sev in windows and age > windows[sev]:
            past_window[sev] += 1

    assets = {r.get("asset_id") for r in rows if r.get("asset_id")}
    last_seen = [r.get("last_detected_at") for r in rows if r.get("last_detected_at")]
    kev = [r for r in rows if r.get("cisa_kev")]
    worst = sorted(
        rows,
        key=lambda r: (SEVERITIES.index(r["severity"]) if r.get("severity") in SEVERITIES else 99,
                       -(r.get("age_days") or 0)),
    )[:sample_size]

    return {
        "open_findings": len(rows),
        "open_by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES if by_severity.get(s)},
        "affected_asset_count": len(assets),
        "by_asset_type": dict(Counter(r.get("asset_type") or "unknown" for r in rows)),
        "by_detection_method": dict(Counter(r.get("detection_method") or "unknown" for r in rows)),
        "cisa_kev_open": len(kev),
        "fix_available_count": sum(1 for r in rows if r.get("fix_available")),
        "remediation_windows_days": windows,
        "past_remediation_window_by_severity": dict(past_window),
        "oldest_open_age_days_by_severity": oldest,
        "most_recent_detection_at": max(last_seen) if last_seen else None,
        "highest_risk_sample": worst,
        "sample_note": f"highest_risk_sample lists up to {sample_size} findings, worst severity then oldest first",
    }


def collect_bucket(client: WizClient, bucket: str) -> Dict[str, Any]:
    """Fetch all open findings once and keep one asset bucket."""
    now = datetime.now(timezone.utc)
    raw = fetch_findings(client)
    all_rows = [slim(f, now) for f in raw]
    bucket_counts = Counter(asset_bucket(r.get("asset_type")) for r in all_rows)
    kept = [r for r in all_rows if asset_bucket(r.get("asset_type")) == bucket]
    return {
        "rows": kept,
        "analysis": summarize(kept, now),
        "scope": {
            "asset_bucket": bucket,
            "statuses_queried": env_list("WIZ_VULN_STATUSES", ["OPEN"]),
            "findings_in_tenant_query": len(all_rows),
            "findings_by_bucket": dict(bucket_counts),
        },
    }
