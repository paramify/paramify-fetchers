#!/usr/bin/env python3
"""
Wiz File Integrity Monitoring (Runtime Sensor)

Two things an assessor needs for file integrity monitoring:

1. Coverage: which workloads run the Wiz Runtime Sensor, and whether each
   sensor has checked in recently. A FIM claim is only as good as the sensor
   footprint behind it.
2. Activity: the Detections raised in a look-back window (default 30 days) by
   rules whose name matches WIZ_FIM_RULE_MATCH (default "file integrity,file
   modification,FIM"), grouped by rule and resource.

What this does NOT show: that a change was blocked. The Wiz Runtime Sensor
detects and alerts; evidence of prevention (for a "File Integrity Protection"
claim) has to come from whatever enforces the change window.

Requires the Wiz Runtime Sensor (Wiz Defend) and read:sensors, read:detections.
NOT YET RUN against a tenant with sensors deployed: field names are checked
against the tenant's schema at run time and anything missing is listed in
scope.fields_not_available.

Speaks to KSI-SVC-VRI and KSI-MLA-OSM.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
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
from schema_fields import Schema, connection_query  # type: ignore  # noqa: E402

logger = logging.getLogger("wiz_file_integrity_monitoring")

SENSOR_FIELDS = [
    "id", "name", "status", "version", "type", "lastSeenAt", "lastSeen", "installedAt", "createdAt",
    ("resource", ["id", "name", "type"]),
    ("workload", ["id", "name", "type"]),
]

DETECTION_FIELDS = [
    "id", "type", "severity", "createdAt",
    ("primaryResource", ["id", "name", "type"]),
    ("ruleMatch", [("rule", ["id", "name"])]),
]

HEALTHY = {"CONNECTED", "HEALTHY", "ACTIVE", "RUNNING", "OK"}


def rule_needles() -> List[str]:
    raw = os.environ.get("WIZ_FIM_RULE_MATCH", "").strip() or "file integrity,file modification,FIM"
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def sensor_row(s: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    target = s.get("resource") or s.get("workload") or {}
    seen = s.get("lastSeenAt") or s.get("lastSeen")
    return {
        "id": s.get("id"),
        "name": s.get("name") or target.get("name"),
        "status": s.get("status"),
        "version": s.get("version"),
        "type": s.get("type"),
        "workload_id": target.get("id"),
        "workload_type": target.get("type"),
        "last_seen_at": seen,
        "days_since_seen": age_days(seen, now),
    }


def summarize(sensors: List[Dict[str, Any]], fim: List[Dict[str, Any]], stale_days: int,
              window: int) -> Dict[str, Any]:
    stale = [s for s in sensors if s["days_since_seen"] is not None and s["days_since_seen"] > stale_days]
    unhealthy = [s for s in sensors if s.get("status") and str(s["status"]).upper() not in HEALTHY]
    return {
        "sensor_count": len(sensors),
        "sensors_by_status": dict(Counter(s.get("status") or "unknown" for s in sensors)),
        "sensors_by_version": dict(Counter(s.get("version") or "unknown" for s in sensors).most_common(10)),
        "stale_sensor_threshold_days": stale_days,
        "stale_sensors": [{"name": s["name"], "last_seen_at": s["last_seen_at"]} for s in stale],
        "sensors_not_healthy": [{"name": s["name"], "status": s["status"]} for s in unhealthy],
        "window_days": window,
        "fim_detections_in_window": len(fim),
        "fim_detections_by_severity": dict(Counter(r.get("severity") or "UNKNOWN" for r in fim)),
        "fim_top_rules": Counter(r.get("rule_name") or "unknown" for r in fim).most_common(15),
        "fim_resources": len({r["resource_id"] for r in fim if r.get("resource_id")}),
        "coverage_note": "Compare sensor_count with the in-boundary host inventory (wiz_scan_coverage, "
                         "wiz_infrastructure_vulnerabilities); hosts without a sensor are not file-monitored.",
        "prevention_note": "The Wiz Runtime Sensor detects and alerts. This evidence does not show that "
                           "changes were blocked.",
    }


def body(client: WizClient) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    window = env_int("WIZ_DETECTION_WINDOW_DAYS", 30)
    stale_days = env_int("WIZ_STALE_SENSOR_DAYS", 3)
    since = (now - timedelta(days=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cap = env_int("WIZ_MAX_RECORDS", 20000)
    schema = Schema(client)
    needles = rule_needles()

    ssel, smissing = schema.selection("Sensor", SENSOR_FIELDS, fallback=["id", "name", "status"])
    sensors_raw = client.paginate("sensors", connection_query("WizSensors", "sensors", None, ssel),
                                  "sensors", max_records=cap)
    sensors = [sensor_row(s, now) for s in sensors_raw]

    dsel, dmissing = schema.selection("Detection", DETECTION_FIELDS)
    inputs: Optional[Dict[str, str]] = schema.input_fields("DetectionFilters")
    filt: Dict[str, Any] = {}
    for field in ("createdAt", "startedAt"):
        if inputs and field in inputs:
            filt[field] = {"after": since}
            break
    fim: List[Dict[str, Any]] = []
    queries = [dict(filt, matchedRuleName={"contains": n}) for n in needles] \
        if inputs and "matchedRuleName" in inputs else [filt]
    seen_ids = set()
    for f in queries:
        for d in client.paginate("detections", connection_query("WizFimDetections", "detections",
                                                                "DetectionFilters", dsel),
                                 "detections", variables={"filterBy": f}, max_records=cap):
            rule = ((d.get("ruleMatch") or {}).get("rule")) or {}
            name = (rule.get("name") or "").lower()
            created = d.get("createdAt")
            age = age_days(created, now)
            if d.get("id") in seen_ids or not any(n in name for n in needles):
                continue
            if age is not None and age > window:
                continue
            seen_ids.add(d.get("id"))
            res = d.get("primaryResource") or {}
            fim.append({"id": d.get("id"), "severity": d.get("severity"), "created_at": created,
                        "rule_name": rule.get("name"), "resource_id": res.get("id"),
                        "resource_name": res.get("name"), "resource_type": res.get("type")})

    records = sensors
    return evidence(
        client=client,
        operations=["sensors", "detections"],
        records=records,
        analysis=summarize(sensors, fim, stale_days, window),
        empty_message=("Wiz returned no Runtime Sensors. Without sensors there is no file integrity "
                       "monitoring from Wiz; check that the sensor is deployed and read:sensors is granted."),
        fim_detections=fim,
        scope={
            "rule_match": needles,
            "window_days": window,
            "server_side_filter": queries,
            "fields_not_available": [f"sensor.{m}" for m in smissing] + [f"detection.{m}" for m in dmissing],
            "schema_checked": not schema.unavailable,
            "validation_status": "Not yet run against a tenant with the Wiz Runtime Sensor deployed.",
        },
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_file_integrity_monitoring.json", logger))
