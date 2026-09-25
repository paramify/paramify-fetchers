#!/usr/bin/env python3
"""
Wiz Threat Detections (Wiz Defend)

Summarizes the Detections Wiz Defend raised in a look-back window (default 30
days) and the Threat issues that group them: how many, how severe, which rules
fired, on which resources, and whether open Threats are linked to a ticket
(ServiceNow / Jira via Wiz's serviceTickets link).

This is evidence that suspicious activity is detected and routed for triage.
It reports what Wiz saw; whether each was handled correctly is Paramify's and
the assessor's call.

Requires a Wiz Defend license and read:detections (plus read:threat_issues for
the Threat issues). NOT YET RUN against a tenant with Wiz Defend data: the
query follows Wiz's published Get Detections reference, and every field is
checked against the tenant's schema at run time (see schema_fields.py), so a
field Wiz renamed is reported in scope.fields_not_available instead of failing.

Speaks to KSI-MLA-OSM, KSI-IAM-SUS and KSI-INR-RPI.
"""

import logging
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
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
from vuln_summary import SEVERITIES  # type: ignore  # noqa: E402

logger = logging.getLogger("wiz_threat_detections")

# Descriptions and raw event payloads are left out on purpose: they can carry
# command lines, user names and log records that the evidence does not need.
DETECTION_FIELDS = [
    "id", "type", "severity", "createdAt", "updatedAt", "origins",
    ("primaryResource", ["id", "name", "type", "region"]),
    ("issue", ["id"]),
    ("ruleMatch", [("rule", ["id", "name", "builtin"])]),
]

THREAT_FIELDS = [
    "id", "type", "status", "severity", "createdAt", "statusChangedAt", "resolvedAt",
    ("serviceTickets", ["externalId", "name"]),
]

OPEN_STATUSES = ["OPEN", "IN_PROGRESS"]


def window_filter(schema: Schema, since_iso: str) -> Dict[str, Any]:
    """Server-side time filter, using whichever time field the schema offers."""
    inputs = schema.input_fields("DetectionFilters") or {}
    for field in ("createdAt", "startedAt"):
        if field in inputs:
            return {field: {"after": since_iso}}
    return {}


def slim_detection(d: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    res = d.get("primaryResource") or {}
    rule = ((d.get("ruleMatch") or {}).get("rule")) or {}
    return {
        "id": d.get("id"),
        "type": d.get("type"),
        "severity": d.get("severity"),
        "created_at": d.get("createdAt"),
        "age_days": age_days(d.get("createdAt"), now),
        "origins": d.get("origins"),
        "rule_id": rule.get("id"),
        "rule_name": rule.get("name"),
        "resource_id": res.get("id"),
        "resource_name": res.get("name"),
        "resource_type": res.get("type"),
        "threat_issue_id": (d.get("issue") or {}).get("id"),
    }


def summarize(detections: List[Dict[str, Any]], threats: List[Dict[str, Any]], window_days: int,
              sample_size: int = 25) -> Dict[str, Any]:
    by_sev = Counter(r.get("severity") or "UNKNOWN" for r in detections)
    created = [r["created_at"] for r in detections if r.get("created_at")]
    open_threats = [t for t in threats if t.get("status") in OPEN_STATUSES]
    ticketed = [t for t in open_threats if t.get("serviceTickets")]
    worst = sorted(detections, key=lambda r: (SEVERITIES.index(r["severity"]) if r.get("severity") in SEVERITIES
                                              else 99, -(r.get("age_days") or 0)))[:sample_size]
    return {
        "window_days": window_days,
        "detections_in_window": len(detections),
        "detections_by_severity": {s: by_sev[s] for s in SEVERITIES if by_sev.get(s)},
        "detections_by_type": dict(Counter(r.get("type") or "unknown" for r in detections)),
        "detections_by_origin": dict(Counter(o for r in detections for o in (r.get("origins") or []) or ["unknown"])),
        "top_rules": Counter(r.get("rule_name") or "unknown" for r in detections).most_common(15),
        "resources_with_detections": len({r["resource_id"] for r in detections if r.get("resource_id")}),
        "detections_grouped_into_threats": sum(1 for r in detections if r.get("threat_issue_id")),
        "most_recent_detection_at": max(created) if created else None,
        "open_threats": len(open_threats),
        "open_threats_by_severity": dict(Counter(t.get("severity") or "UNKNOWN" for t in open_threats)),
        "open_threats_with_ticket": len(ticketed),
        "threats_resolved_in_window": sum(1 for t in threats if t.get("status") == "RESOLVED"),
        "highest_severity_sample": worst,
        "note": "Detections are Wiz alerts; Threats group related detections. Wiz auto-resolves a Threat "
                "90 days after its last detection.",
    }


def body(client: WizClient) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    window = env_int("WIZ_DETECTION_WINDOW_DAYS", 30)
    since = (now - timedelta(days=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cap = env_int("WIZ_MAX_RECORDS", 20000)
    schema = Schema(client)

    sel, missing = schema.selection("Detection", DETECTION_FIELDS)
    filt = window_filter(schema, since)
    severities = env_list("WIZ_DETECTION_SEVERITIES", [])
    if severities and "severity" in (schema.input_fields("DetectionFilters") or {"severity": 1}):
        filt["severity"] = {"equals": severities}
    raw = client.paginate("detections", connection_query("WizDetections", "detections", "DetectionFilters", sel),
                          "detections", variables={"filterBy": filt}, max_records=cap)
    rows = [slim_detection(d, now) for d in raw]
    if not filt.get("createdAt") and not filt.get("startedAt"):
        # No server-side time filter in this schema: apply the window here.
        rows = [r for r in rows if r.get("age_days") is not None and r["age_days"] <= window]

    tsel, tmissing = schema.selection("Issue", THREAT_FIELDS)
    threats: List[Dict[str, Any]] = []
    if env_list("WIZ_INCLUDE_THREAT_ISSUES", ["TRUE"])[0] not in {"FALSE", "0", "NO"}:
        tq = connection_query("WizThreatIssues", "issuesV2", "IssueFilters", tsel)
        threats = client.paginate("issuesV2", tq, "issuesV2", variables={"filterBy": {
            "type": ["THREAT_DETECTION"], "status": OPEN_STATUSES}}, max_records=cap)
        threats += client.paginate("issuesV2", tq, "issuesV2", variables={"filterBy": {
            "type": ["THREAT_DETECTION"], "status": ["RESOLVED"], "statusChangedAt": {"after": since}}},
            max_records=cap)

    include = env_list("WIZ_INCLUDE_RAW_FINDINGS", ["TRUE"])[0] not in {"FALSE", "0", "NO"}
    return evidence(
        client=client,
        operations=["detections", "issuesV2"],
        records=rows,
        analysis=summarize(rows, threats, window),
        empty_message=(f"Wiz returned no detections in the last {window} days. If Wiz Defend is licensed and "
                       "sensors or cloud log sources are connected, this means nothing fired; otherwise check "
                       "the license and read:detections."),
        include_records=include,
        scope={
            "window_days": window,
            "since": since,
            "server_side_filter": filt,
            "fields_not_available": missing + [f"threat.{m}" for m in tmissing],
            "schema_checked": not schema.unavailable,
            "validation_status": "Query follows Wiz's published reference; not yet run against a tenant "
                                 "with Wiz Defend data.",
        },
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_threat_detections.json", logger))
