#!/usr/bin/env python3
"""
Wiz Attack Surface Findings (external / web application scanning)

Summarizes Wiz Attack Surface Management findings: weaknesses the Wiz Attack
Surface Scanner found on internet-facing endpoints and web applications, by
severity, rule, technology and status, with the oldest open ones listed.

This is the Wiz evidence for "application vulnerability scanning" of what is
exposed. It is not source-code scanning (see wiz_code_findings) and it is not a
penetration test.

Requires Wiz Attack Surface Management and read:attack_surface. NOT YET RUN
against a tenant with ASM data: the query follows Wiz's published Get Attack
Surface Findings reference and every field is checked against the tenant's
schema at run time; anything missing is listed in scope.fields_not_available.
Status is filtered here, not server-side, because the filter's shape is not
verified.

Speaks to KSI-CNA-MAT and KSI-SVC-EIS.
"""

import logging
import sys
from collections import Counter
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
    env_list,
    evidence,
    run_fetcher,
)
from schema_fields import Schema, connection_query  # type: ignore  # noqa: E402
from vuln_summary import SEVERITIES, sla_days  # type: ignore  # noqa: E402

logger = logging.getLogger("wiz_attack_surface_findings")

FIELDS = [
    "id", "name", "type", "severity", "status", "origin", "firstSeenAt", "createdAt", "updatedAt",
    ("resource", ["id", "name", "type"]),
    ("rule", ["id", "name"]),
    ("technologies", ["id", "name"]),
    ("weaknesses", ["id", "name"]),
]
PUBLISHED = [
    "id", "name", "type", "severity", "status", "origin",
    ("resource", ["id", "name", "type"]),
    ("technologies", ["id", "name"]),
    ("weaknesses", ["id", "name"]),
]


def slim(f: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    first = f.get("firstSeenAt") or f.get("createdAt")
    res = f.get("resource") or {}
    return {
        "id": f.get("id"),
        "name": f.get("name"),
        "type": f.get("type"),
        "severity": f.get("severity"),
        "status": f.get("status"),
        "origin": f.get("origin"),
        "first_seen_at": first,
        "age_days": age_days(first, now),
        "rule_name": (f.get("rule") or {}).get("name") or f.get("name"),
        "resource_id": res.get("id"),
        "resource_name": res.get("name"),
        "resource_type": res.get("type"),
        "technologies": [t.get("name") for t in (f.get("technologies") or []) if t.get("name")],
        "weaknesses": [w.get("name") or w.get("id") for w in (f.get("weaknesses") or [])],
    }


def summarize(rows: List[Dict[str, Any]], open_statuses: List[str], sample_size: int = 25) -> Dict[str, Any]:
    windows = sla_days()
    open_rows = [r for r in rows if (r.get("status") or "OPEN").upper() in open_statuses]
    past = Counter(r["severity"] for r in open_rows
                   if r.get("severity") in windows and (r.get("age_days") or 0) > windows[r["severity"]])
    worst = sorted(open_rows, key=lambda r: (SEVERITIES.index(r["severity"]) if r.get("severity") in SEVERITIES
                                             else 99, -(r.get("age_days") or 0)))[:sample_size]
    return {
        "findings_total": len(rows),
        "by_status": dict(Counter(r.get("status") or "unknown" for r in rows)),
        "open_findings": len(open_rows),
        "open_by_severity": {s: n for s, n in Counter(r.get("severity") or "UNKNOWN" for r in open_rows).items()},
        "exposed_resources_with_open_findings": len({r["resource_id"] for r in open_rows if r.get("resource_id")}),
        "top_open_rules": Counter(r.get("rule_name") or "unknown" for r in open_rows).most_common(15),
        "top_technologies": Counter(t for r in open_rows for t in r.get("technologies") or []).most_common(10),
        "remediation_windows_days": windows,
        "open_past_window_by_severity": dict(past),
        "highest_risk_sample": worst,
    }


def body(client: WizClient) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    cap = env_int("WIZ_MAX_RECORDS", 20000)
    open_statuses = env_list("WIZ_ASM_OPEN_STATUSES", ["OPEN", "IN_PROGRESS"])
    schema = Schema(client)
    sel, missing = schema.selection("AttackSurfaceFinding", FIELDS, fallback=PUBLISHED)
    raw = client.paginate("attackSurfaceFindings",
                          connection_query("WizAttackSurfaceFindings", "attackSurfaceFindings",
                                           "AttackSurfaceFindingFilters", sel),
                          "attackSurfaceFindings", variables={"filterBy": {}}, max_records=cap)
    rows = [slim(f, now) for f in raw]
    include = env_list("WIZ_INCLUDE_RAW_FINDINGS", ["TRUE"])[0] not in {"FALSE", "0", "NO"}
    return evidence(
        client=client,
        operations=["attackSurfaceFindings"],
        records=rows,
        analysis=summarize(rows, open_statuses),
        empty_message=("Wiz returned no attack surface findings. With ASM licensed and scanning, this means no "
                       "exposed weaknesses were found; otherwise check the license and read:attack_surface."),
        include_records=include,
        scope={
            "open_statuses": open_statuses,
            "fields_not_available": missing,
            "schema_checked": not schema.unavailable,
            "validation_status": "Query follows Wiz's published reference; not yet run against a tenant "
                                 "with Attack Surface Management data.",
        },
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_attack_surface_findings.json", logger))
