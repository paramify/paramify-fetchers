#!/usr/bin/env python3
"""
Wiz Code Findings (SAST)

Summarizes Wiz Code static analysis (SAST) findings on the connected source
repositories: open findings by severity, repository and weakness (CWE), their
age against remediation windows, and the oldest open ones.

Code snippets, descriptions and remediation text are deliberately not
collected: they can contain source code or secrets, and the evidence only needs
the finding, where it is and how old it is.

Requires Wiz Code and read:sast_findings. The query follows Wiz's published
Get SAST Findings reference and every field is checked against the tenant's
schema at run time. Status is filtered here, not server-side, because the
filter's shape is not verified.

Speaks to KSI-CMT-VTD and KSI-PIY-RSD.
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

logger = logging.getLogger("wiz_code_findings")

PUBLISHED = [
    "id", "name", "severity", "status", "createdAt", "filePath", "startLine", "origin",
    ("repository", ["id", "name"]),
    ("repositoryBranch", ["id", "name"]),
    ("weaknesses", ["id", "name"]),
]


def slim(f: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    return {
        "id": f.get("id"),
        "rule": f.get("name"),
        "severity": f.get("severity"),
        "status": f.get("status"),
        "created_at": f.get("createdAt"),
        "age_days": age_days(f.get("createdAt"), now),
        "repository": (f.get("repository") or {}).get("name"),
        "branch": (f.get("repositoryBranch") or {}).get("name"),
        "file_path": f.get("filePath"),
        "start_line": f.get("startLine"),
        "weaknesses": [w.get("name") or w.get("id") for w in (f.get("weaknesses") or [])],
        "origin": f.get("origin"),
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
        "open_by_severity": dict(Counter(r.get("severity") or "UNKNOWN" for r in open_rows)),
        "repositories_with_open_findings": len({r["repository"] for r in open_rows if r.get("repository")}),
        "open_by_repository": dict(Counter(r.get("repository") or "unknown" for r in open_rows).most_common(20)),
        "top_weaknesses": Counter(w for r in open_rows for w in r.get("weaknesses") or []).most_common(15),
        "remediation_windows_days": windows,
        "open_past_window_by_severity": dict(past),
        "highest_risk_sample": worst,
    }


def body(client: WizClient) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    cap = env_int("WIZ_MAX_RECORDS", 50000)
    open_statuses = env_list("WIZ_CODE_OPEN_STATUSES", ["OPEN", "IN_PROGRESS"])
    schema = Schema(client)
    sel, missing = schema.selection("SASTFinding", PUBLISHED, fallback=PUBLISHED)
    raw = client.paginate("sastFindings",
                          connection_query("WizSastFindings", "sastFindings", "SASTFindingFilters", sel),
                          "sastFindings", variables={"filterBy": {}}, max_records=cap)
    rows = [slim(f, now) for f in raw]
    include = env_list("WIZ_INCLUDE_RAW_FINDINGS", ["TRUE"])[0] not in {"FALSE", "0", "NO"}
    return evidence(
        client=client,
        operations=["sastFindings"],
        records=rows,
        analysis=summarize(rows, open_statuses),
        empty_message=("Wiz returned no SAST findings. With Wiz Code connected to the repositories this means "
                       "nothing was found; otherwise check the Wiz Code connection and read:sast_findings."),
        include_records=include,
        scope={
            "open_statuses": open_statuses,
            "fields_not_available": missing,
            "schema_checked": not schema.unavailable,
            "validation_status": "Query follows Wiz's published reference; not yet run with read:sast_findings.",
        },
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_code_findings.json", logger))
