#!/usr/bin/env python3
"""Azure service availability: Resource Health history per App Service app, Front Door profile and SQL Managed Instance,
and App Service health-check results."""

import logging
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_service import is_web_app  # noqa: E402
from azure_common import arm_id_key, resource_group_from_id, sorted_counts  # noqa: E402
from azure_rest import int_config, parse_time, run_subscription  # noqa: E402
from frontdoor import FRONT_DOOR_SKUS  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_service_availability"
WEB_API = "2024-04-01"
CDN_API = "2024-09-01"
SQL_API = "2023-08-01"
HEALTH_API = "2025-05-01"
METRICS_API = "2023-10-01"
PROVIDERS_API = "2021-04-01"
HEALTH_PROVIDER = "Microsoft.ResourceHealth"

LOOKBACK_ENV = "AZURE_SERVICE_AVAILABILITY_LOOKBACK_DAYS"
RTO_ENV = "AZURE_RECOVERY_TIME_OBJECTIVE_HOURS"
DEFAULT_LOOKBACK_DAYS = 30
# Resource Health keeps 30 days of history.
MAX_LOOKBACK_DAYS = 30
HEALTH_CHECK_METRIC = "HealthCheckStatus"
HEALTHY = 100.0
# "Last hour" must fall in the window's last this-many hours; older data leaves it unknown.
LAST_HOUR_BUCKETS = 3
MAX_WINDOWS = 100
MAX_UNHEALTHY_HOURS = 100
WORKERS = 4

APP, FRONT_DOOR, SQL_MI = "app_service", "front_door", "sql_managed_instance"
RESOURCE_TYPES = (APP, FRONT_DOOR, SQL_MI)
EXCLUDED_KIND = {APP: "app", FRONT_DOOR: "front_door_profile", SQL_MI: "sql_managed_instance"}
WEB_APP, FUNCTION_APP = "web_app", "function_app"
AVAILABLE, UNAVAILABLE, DEGRADED, UNKNOWN = "Available", "Unavailable", "Degraded", "Unknown"
STATES = {s.lower(): s for s in (AVAILABLE, UNAVAILABLE, DEGRADED, UNKNOWN)}
CUSTOMER, PLATFORM, UNATTRIBUTED = "customer", "platform", "unknown"

READ, NOT_READ, NO_DATA = "read", "not_read", "no_data"
NOT_SUPPORTED, NOT_FOUND = "not_supported", "not_found"
NOT_AUTHORIZED, NOT_REGISTERED, ERROR = "not_authorized", "not_registered", "error"
REGISTERED, REGISTRATION_UNKNOWN = "registered", "unknown"
# Statuses that leave availability unknown without failing the run.
QUIET = (NOT_SUPPORTED, NOT_FOUND)
# Resource Health judges a Front Door profile by whether its origins answer health probes, not by whether it serves.
ORIGIN_PROBES, RESOURCE_SIGNAL = "origin_health_probes", "resource"
FAILING = (UNAVAILABLE, DEGRADED)

LIMITATIONS = [
    f"Resource Health keeps {MAX_LOOKBACK_DAYS} days of history, so the lookback is capped there; history_from shows "
    "how far back each resource's history reaches.",
    "Availability is what Resource Health reports from Microsoft's own checks for the resource type, not an "
    "end-to-end probe of the application.",
    "Periods the customer started (a stop, restart or scale: Resource Health names the customer or user as the "
    "cause) are listed but are not outages and do not count against the recovery time objective.",
    "Recovery time is the length of a continuous Unavailable period; a Degraded resource still serves requests.",
    "Unknown periods (Resource Health had no information) are not counted as available: availability is measured "
    "over known hours, and an Unknown period longer than the recovery time objective leaves the objective unknown.",
    "Deployment slots are not read: production apps only.",
    "Resource Health judges a Front Door profile by whether its origins answer health probes, not by whether Front "
    "Door serves requests, so one failing origin makes the profile Unavailable or Degraded while the others serve. "
    "Front Door periods are listed as origin probe failures and never counted as outages; per-origin health and "
    "traffic are in azure_front_door_origins. Classic Front Door and CDN profiles are not read.",
    f"Each resource lists its {MAX_WINDOWS} newest periods; windows_total and every count cover all of them.",
    "Health-check results are hourly HealthCheckStatus values for apps with a health check path; apps without one "
    "have no health-check data.",
]
RELATED_EVIDENCE = [
    "Front Door origin health and traffic per origin and region (OriginHealthPercentage, OriginRequestCount) are in "
    "azure_front_door_origins.",
    "Subscription Service Health events (service issues, planned maintenance, health and security advisories) are "
    "in azure_service_health_advisories.",
]

logger = logging.getLogger(NAME)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def lower(value) -> str:
    return str(value or "").lower()


def iso(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def hours(delta: timedelta) -> float:
    return round(max(delta.total_seconds(), 0) / 3600, 2)


def region_key(location) -> str:
    return lower(location).replace(" ", "") or "unknown"


def all_true(values):
    if any(v is False for v in values):
        return False
    return None if not values or any(v is None for v in values) else True


def biggest(values):
    values = [v for v in values if v is not None]
    return max(values) if values else None


def smallest(values):
    values = [v for v in values if v is not None]
    return min(values) if values else None


def read_settings(collector) -> dict:
    days = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    if days > MAX_LOOKBACK_DAYS:
        logger.warning("%s=%d is past the %d days Resource Health keeps; using %d",
                       LOOKBACK_ENV, days, MAX_LOOKBACK_DAYS, MAX_LOOKBACK_DAYS)
        days = MAX_LOOKBACK_DAYS
    raw = (os.environ.get(RTO_ENV) or "").strip()
    rto = None
    if raw:
        try:
            rto = float(raw)
        except ValueError:
            rto = None
        if rto is None or rto <= 0:
            collector.record(f"config {RTO_ENV}", ValueError(f"invalid recovery time objective {raw!r}: expected hours > 0"))
            rto = None
    return {"lookback_days": days, "recovery_time_objective_hours": rto}


# --- resources ---

def project_resource(resource: dict, resource_type: str) -> dict:
    rid, props = resource.get("id"), resource.get("properties") or {}
    record = {
        "id": rid,
        "name": resource.get("name"),
        "resource_type": resource_type,
        "app_type": None,
        "resource_group": resource_group_from_id(rid),
        "location": resource.get("location"),
        "region": region_key(resource.get("location")),
        "sku": (resource.get("sku") or {}).get("name"),
        "state": props.get("state"),
    }
    if resource_type == APP:
        record.update(app_type=WEB_APP if is_web_app(resource.get("kind")) else FUNCTION_APP,
                      sku=props.get("sku"), app_service_plan_id=props.get("serverFarmId"))
    elif resource_type == FRONT_DOOR:
        record["state"] = props.get("resourceState")
    return record


def is_front_door(profile: dict) -> bool:
    return (profile.get("sku") or {}).get("name") in FRONT_DOOR_SKUS


# --- Resource Health ---

def canonical_state(value):
    """None when the status carries no state (an impacting event, not a transition)."""
    if value is None or value == "":
        return None
    return STATES.get(lower(value), UNKNOWN)


def occurred(props: dict):
    # The API spells it occuredTime; accept the corrected spelling too.
    return parse_time(props.get("occuredTime") or props.get("occurredTime"))


def initiated_by(props: dict) -> str:
    # reasonType Unplanned says nothing about who caused it: Front Door reports origin failures that way.
    text = " ".join(str(props.get(k) or "") for k in ("context", "reasonType", "healthEventCause")).lower()
    if "customer" in text or "user" in text:
        return CUSTOMER
    return PLATFORM if "platform" in text else UNATTRIBUTED


def impacting_events(props: dict) -> list[dict]:
    out = []
    for event in props.get("serviceImpactingEvents") or []:
        incident = event.get("incidentProperties") or {}
        out.append({
            "correlation_id": event.get("correlationId"),
            "title": incident.get("title"),
            "service": incident.get("service"),
            "region": incident.get("region"),
            "incident_type": incident.get("incidentType"),
            "status": (event.get("status") or {}).get("value"),
            "started": iso(parse_time(event.get("eventStartTime"))),
            "last_modified": iso(parse_time(event.get("eventStatusLastModifiedTime"))),
        })
    return out


def distinct_events(events) -> list[dict]:
    seen: dict = {}
    for event in events:
        key = (event.get("correlation_id"), event.get("title"), event.get("region"))
        seen.setdefault(key, event)
    return list(seen.values())


def health_event(at, props: dict) -> dict:
    return {
        "occurred": iso(at),
        "title": props.get("title"),
        "summary": props.get("summary"),
        "health_event_type": props.get("healthEventType"),
        "health_event_cause": props.get("healthEventCause"),
        "health_event_category": props.get("healthEventCategory"),
        "health_event_id": props.get("healthEventId"),
    }


def timeline(statuses: list[dict]):
    """(segments oldest first, impacting events, statuses without a time). A transition lasts until the next one, the
    newest until now (end None); adjacent transitions to the same state merge into one segment."""
    transitions: list[tuple] = []
    events: list[tuple] = []
    untimed, seen = 0, set()
    for status in statuses:
        key = arm_id_key(status.get("id"))
        if key and key in seen:
            continue
        seen.add(key)
        props = status.get("properties") or {}
        at = occurred(props)
        if at is None:
            untimed += 1
            continue
        state = canonical_state(props.get("availabilityState"))
        (events if state is None else transitions).append((at, state, props))
    transitions.sort(key=lambda t: t[0])
    segments: list[dict] = []
    for i, (at, state, props) in enumerate(transitions):
        end = transitions[i + 1][0] if i + 1 < len(transitions) else None
        if segments and segments[-1]["state"] == state:
            segments[-1]["end"] = end
            segments[-1]["statuses"].append(props)
        else:
            segments.append({"state": state, "start": at, "end": end, "statuses": [props]})
    return segments, sorted(events, key=lambda e: e[0]), untimed


def window_record(segment: dict, events: list, now: datetime, window_start: datetime) -> dict:
    start, end = segment["start"], segment["end"]
    statuses = segment["statuses"]
    attributed = [initiated_by(p) for p in statuses]
    first = statuses[0]
    return {
        "state": segment["state"],
        "start": iso(start),
        "end": iso(end),
        "ongoing": end is None,
        "duration_hours": hours((end or now) - start),
        "hours_in_window": hours((end or now) - max(start, window_start)),
        "initiated_by": next((a for a in attributed if a != UNATTRIBUTED), UNATTRIBUTED),
        "context": first.get("context"),
        "category": first.get("category"),
        "reason_type": first.get("reasonType"),
        "reason_chronicity": first.get("reasonChronicity"),
        "title": first.get("title"),
        "summary": first.get("summary"),
        "health_event_cause": first.get("healthEventCause"),
        "root_cause_attribution_time": iso(parse_time(first.get("rootCauseAttributionTime"))),
        "resolution_eta": iso(parse_time(first.get("resolutionETA"))),
        "service_impacting_events": distinct_events(e for p in statuses for e in impacting_events(p)),
        "health_events": [health_event(at, p) for at, _, p in events if start <= at < (end or now)],
    }


def unread_health(status: str, error=None, signal: str = RESOURCE_SIGNAL) -> dict:
    return {
        "status": status, "error": error, "signal": signal, "statuses_read": None, "statuses_without_time": None,
        "current_state": None, "current_since": None, "current_title": None, "current_summary": None,
        "last_checked": None, "history_from": None, "observed_hours": None, "known_hours": None,
        "availability_percentage": None, "unavailable_hours_in_window": None, "degraded_hours_in_window": None,
        "unknown_hours_in_window": None, "outages": None, "ongoing_outage": None, "longest_outage_hours": None,
        "customer_initiated_unavailable_windows": None, "degraded_windows": None, "unknown_windows": None,
        "longest_degraded_hours": None, "longest_unknown_hours": None,
        "origin_probe_failure_windows": None, "origin_probe_failure_hours_in_window": None,
        "longest_origin_probe_failure_hours": None, "failing_origin_probes_now": None,
        "windows_total": None, "windows_listed": None, "windows": [], "recently_resolved": None,
        "service_impacting_events": [],
    }


def health_record(statuses: list[dict], now: datetime, window_start: datetime, origin_driven: bool = False) -> dict:
    """Outage fields stay null when the signal is origin probes (Front Door): those periods aren't outages."""
    signal = ORIGIN_PROBES if origin_driven else RESOURCE_SIGNAL
    segments, events, untimed = timeline(statuses)
    if not segments:
        return {**unread_health(NO_DATA, signal=signal), "statuses_read": len(statuses),
                "statuses_without_time": untimed}
    relevant = [s for s in segments if (s["end"] or now) > window_start]
    windows = [window_record(s, events, now, window_start) for s in relevant if s["state"] != AVAILABLE]
    for w in windows:
        w["counts_as_outage"] = not origin_driven and w["state"] == UNAVAILABLE and w["initiated_by"] != CUSTOMER
    outages = [w for w in windows if w["counts_as_outage"]]
    current = segments[-1]
    latest = current["statuses"][-1]
    history_from = segments[0]["start"]
    observed = hours(now - max(window_start, history_from))
    resolved = latest.get("recentlyResolved") or None

    def in_window(states):
        return round(sum(w["hours_in_window"] for w in windows if w["state"] in states), 2)

    def longest(states):
        return biggest(w["duration_hours"] for w in windows if w["state"] in states) or 0.0

    unknown = in_window((UNKNOWN,))
    record = {
        **unread_health(READ, signal=signal),
        "statuses_read": len(statuses),
        "statuses_without_time": untimed,
        "current_state": current["state"],
        "current_since": iso(current["start"]),
        "current_title": latest.get("title"),
        "current_summary": latest.get("summary"),
        "last_checked": iso(parse_time(latest.get("reportedTime"))),
        "history_from": iso(history_from),
        "observed_hours": observed,
        "known_hours": round(max(observed - unknown, 0), 2),
        "degraded_hours_in_window": in_window((DEGRADED,)),
        "unknown_hours_in_window": unknown,
        "degraded_windows": sum(1 for w in windows if w["state"] == DEGRADED),
        "unknown_windows": sum(1 for w in windows if w["state"] == UNKNOWN),
        "longest_degraded_hours": longest((DEGRADED,)),
        "longest_unknown_hours": longest((UNKNOWN,)),
        "windows_total": len(windows),
        "windows_listed": min(len(windows), MAX_WINDOWS),
        "windows": windows[-MAX_WINDOWS:],
        "recently_resolved": None if not resolved else {
            "unavailable_since": iso(parse_time(resolved.get("unavailableOccuredTime")
                                                or resolved.get("unavailableOccurredTime"))),
            "resolved": iso(parse_time(resolved.get("resolvedTime"))),
            "summary": resolved.get("unavailableSummary"),
        },
        "service_impacting_events": distinct_events(e for w in windows for e in w["service_impacting_events"]),
    }
    if origin_driven:
        record.update({
            "origin_probe_failure_windows": sum(1 for w in windows if w["state"] in FAILING),
            "origin_probe_failure_hours_in_window": in_window(FAILING),
            "longest_origin_probe_failure_hours": longest(FAILING),
            "failing_origin_probes_now": None if current["state"] == UNKNOWN else current["state"] in FAILING,
        })
        return record
    down = round(sum(w["hours_in_window"] for w in outages), 2)
    known = record["known_hours"]
    record.update({
        "availability_percentage": round(100 * (known - down) / known, 3) if known else None,
        "unavailable_hours_in_window": down,
        "outages": len(outages),
        "ongoing_outage": any(w["ongoing"] for w in outages),
        "longest_outage_hours": biggest(w["duration_hours"] for w in outages) or 0.0,
        "customer_initiated_unavailable_windows": sum(
            1 for w in windows if w["state"] == UNAVAILABLE and w["initiated_by"] == CUSTOMER),
    })
    return record


def available_now(health: dict):
    state = health["current_state"]
    if health["signal"] == ORIGIN_PROBES:
        return None
    if state in (AVAILABLE, DEGRADED):
        return True
    return False if state == UNAVAILABLE else None


def meets_objective(health: dict, rto):
    if rto is None or health["status"] != READ or health["outages"] is None:
        return None
    if health["longest_outage_hours"] > rto:
        return False
    # An Unknown period longer than the objective could hide an outage that misses it.
    if not health["known_hours"] or health["longest_unknown_hours"] > rto:
        return None
    return True


def classify(exc: BaseException) -> str:
    status, code, text = getattr(exc, "status", None), lower(getattr(exc, "code", "")), lower(exc)
    if status == 403:
        return NOT_AUTHORIZED
    # Measured: an unregistered Microsoft.ResourceHealth answers 409 AuthError naming the registration.
    if status == 409 and "regist" in text:
        return NOT_REGISTERED
    if "notsupported" in code or "unsupported" in code:
        return NOT_SUPPORTED
    return NOT_FOUND if status == 404 else ERROR


def error_text(exc: BaseException) -> str:
    return " ".join(str(exc).split())[:300]


# --- health check ---

def project_points(metrics: list[dict]) -> list[dict]:
    """Hourly points across the metric's series: the mean of the averages and the lowest minimum per hour."""
    by_hour: dict = {}
    for metric in metrics or []:
        if lower((metric.get("name") or {}).get("value")) != HEALTH_CHECK_METRIC.lower():
            continue
        for series in metric.get("timeseries") or []:
            for point in series.get("data") or []:
                slot = by_hour.setdefault(iso(parse_time(point.get("timeStamp"))), {"averages": [], "minimums": []})
                if point.get("average") is not None:
                    slot["averages"].append(point["average"])
                if point.get("minimum") is not None:
                    slot["minimums"].append(point["minimum"])
    return [
        {"time": t,
         "average": round(sum(v["averages"]) / len(v["averages"]), 2) if v["averages"] else None,
         "minimum": min(v["minimums"]) if v["minimums"] else None}
        for t, v in sorted(by_hour.items()) if t
    ]


def healthy_point(point: dict) -> bool:
    value = point["minimum"] if point["minimum"] is not None else point["average"]
    return value >= HEALTHY


def health_check_record(config_status: str, path, metric_status: str, points, window_end: datetime,
                        stopped: bool = False) -> dict:
    """A stopped app has no instances to answer the probe, so its results get no healthy or unhealthy verdict."""
    enabled = None if config_status != READ else bool(path)
    read = metric_status == READ
    data = [p for p in points or [] if p["average"] is not None or p["minimum"] is not None]
    averages = [p["average"] for p in data if p["average"] is not None]
    unhealthy = [p for p in data if not healthy_point(p)]
    floor = iso(window_end - timedelta(hours=LAST_HOUR_BUCKETS))
    recent = [p for p in data if p["time"] >= floor]
    last = recent[-1] if recent else None
    return {
        "app_stopped": stopped,
        "config_status": config_status,
        "health_check_path": path or None,
        "health_check_enabled": enabled,
        "metric_status": metric_status,
        "hours_with_data": len(data) if read else None,
        "hours_healthy": len(data) - len(unhealthy) if read else None,
        "hours_unhealthy": len(unhealthy) if read else None,
        "healthy_percentage": round(100 * (len(data) - len(unhealthy)) / len(data), 2) if read and data else None,
        "average_status": round(sum(averages) / len(averages), 2) if read and averages else None,
        "lowest_status": smallest(p["minimum"] for p in data) if read else None,
        "last_hour": last["time"] if last else None,
        "healthy_last_hour": healthy_point(last) if last and not stopped else None,
        "unhealthy_hours": [p["time"] for p in unhealthy][-MAX_UNHEALTHY_HOURS:],
    }


# --- rollups ---

def resource_record(resource: dict, health: dict, check, rto) -> dict:
    return {
        **resource,
        "available_now": available_now(health),
        "outages_in_window": health["outages"],
        "longest_outage_hours": health["longest_outage_hours"],
        "availability_percentage": health["availability_percentage"],
        "meets_recovery_time_objective": meets_objective(health, rto),
        "resource_health": health,
        "health_check": check,
    }


def measured(records: list[dict]) -> list[dict]:
    """Resources whose Resource Health state is their own availability: apps and SQL Managed Instances."""
    return [r for r in records if r["resource_type"] != FRONT_DOOR]


def running_checks(records: list[dict]) -> list[dict]:
    return [r["health_check"] for r in records if r["health_check"] and not r["health_check"]["app_stopped"]]


def region_records(records: list[dict]) -> list[dict]:
    regions: dict = {}
    for r in records:
        regions.setdefault(r["region"], []).append(r)
    out = []
    for name, members in sorted(regions.items()):
        own = measured(members)
        checks = [m["health_check"] for m in members if m["health_check"]]
        out.append({
            "region": name,
            "resources": len(members),
            "by_type": sorted_counts(Counter(m["resource_type"] for m in members)),
            "available_now": sum(1 for m in own if m["available_now"] is True),
            "unavailable_now": sum(1 for m in own if m["available_now"] is False),
            "availability_unknown_now": sum(1 for m in own if m["available_now"] is None),
            "outages_in_window": sum(m["outages_in_window"] or 0 for m in own),
            "longest_outage_hours": biggest(m["longest_outage_hours"] for m in own),
            "front_door_profiles_failing_origin_probes_now": sum(
                1 for m in members if m["resource_health"]["failing_origin_probes_now"] is True),
            "apps_with_health_check": sum(1 for c in checks if c["health_check_enabled"] is True),
            "apps_health_check_healthy_last_hour": sum(1 for c in checks if c["healthy_last_hour"] is True),
            "apps_health_check_unhealthy_last_hour": sum(1 for c in checks if c["healthy_last_hour"] is False),
        })
    return out


def summarize(records: list[dict], listed: dict, settings: dict, registration: str) -> dict:
    health = [r["resource_health"] for r in records]
    read = [h for h in health if h["status"] == READ]
    own = measured(records)
    own_read = [r["resource_health"] for r in own if r["resource_health"]["status"] == READ]
    doors = [r["resource_health"] for r in records
             if r["resource_type"] == FRONT_DOOR and r["resource_health"]["status"] == READ]
    apps = [r for r in records if r["resource_type"] == APP]
    checks = [r["health_check"] for r in apps]
    running = running_checks(apps)
    rto = settings["recovery_time_objective_hours"]
    lists_ok = all(listed[t] is not None for t in RESOURCE_TYPES)
    measured_lists_ok = listed[APP] is not None and listed[SQL_MI] is not None

    def typed(resource_type, app_type=None):
        if listed[resource_type] is None:
            return None
        return sum(1 for r in records if r["resource_type"] == resource_type and app_type in (None, r["app_type"]))

    return {
        "lookback_days": settings["lookback_days"],
        "recovery_time_objective_hours": rto,
        "resource_health_registration": registration,
        "resources": len(records) if lists_ok else None,
        "app_services": typed(APP),
        "web_apps": typed(APP, WEB_APP),
        "function_apps": typed(APP, FUNCTION_APP),
        "front_door_profiles": typed(FRONT_DOOR),
        "sql_managed_instances": typed(SQL_MI),
        "resource_health_read": len(read),
        "resource_health_unknown": len(health) - len(read),
        "resource_health_by_status": sorted_counts(Counter(h["status"] for h in health)),
        "windows_not_listed": sum(h["windows_total"] - h["windows_listed"] for h in read),
        "resources_available_now": sum(1 for r in own if r["available_now"] is True),
        "resources_unavailable_now": sum(1 for r in own if r["available_now"] is False),
        "resources_degraded_now": sum(1 for r in own if r["resource_health"]["current_state"] == DEGRADED),
        "resources_availability_unknown_now": sum(1 for r in own if r["available_now"] is None),
        "resources_with_outage_in_window": sum(1 for h in own_read if h["outages"]),
        "outages_in_window": sum(h["outages"] for h in own_read),
        "ongoing_outages": sum(1 for h in own_read if h["ongoing_outage"]),
        "customer_initiated_unavailable_windows": sum(h["customer_initiated_unavailable_windows"] for h in own_read),
        "longest_outage_hours": biggest(h["longest_outage_hours"] for h in own_read),
        "longest_degraded_hours": biggest(h["longest_degraded_hours"] for h in own_read),
        "longest_unknown_hours": biggest(h["longest_unknown_hours"] for h in own_read),
        "lowest_availability_percentage": smallest(h["availability_percentage"] for h in own_read),
        "resources_without_availability": sum(1 for h in own_read if h["availability_percentage"] is None),
        "resources_with_unknown_hours": sum(1 for h in own_read if h["unknown_hours_in_window"]),
        "service_impacting_events": len(distinct_events(e for h in read for e in h["service_impacting_events"])),
        "resources_meeting_recovery_time_objective": sum(
            1 for r in own if r["meets_recovery_time_objective"] is True),
        "resources_missing_recovery_time_objective": sum(
            1 for r in own if r["meets_recovery_time_objective"] is False),
        "resources_recovery_time_objective_unknown": None if rto is None else sum(
            1 for r in own if r["meets_recovery_time_objective"] is None),
        "all_resources_meet_recovery_time_objective": None if rto is None or not measured_lists_ok else all_true(
            [r["meets_recovery_time_objective"] for r in own]),
        "front_door_profiles_failing_origin_probes_now": sum(1 for h in doors if h["failing_origin_probes_now"]),
        "front_door_origin_probe_failure_windows": sum(h["origin_probe_failure_windows"] for h in doors),
        "front_door_longest_origin_probe_failure_hours": biggest(h["longest_origin_probe_failure_hours"] for h in doors),
        "apps_stopped": sum(1 for r in apps if lower(r["state"]) == "stopped"),
        "apps_with_health_check": sum(1 for c in checks if c["health_check_enabled"] is True),
        "apps_without_health_check": sum(1 for c in checks if c["health_check_enabled"] is False),
        "apps_health_check_unknown": sum(1 for c in checks if c["health_check_enabled"] is None),
        "all_apps_have_health_check": None if listed[APP] is None else all_true(
            [c["health_check_enabled"] for c in checks]),
        "apps_health_check_healthy_last_hour": sum(1 for c in running if c["healthy_last_hour"] is True),
        "apps_health_check_unhealthy_last_hour": sum(1 for c in running if c["healthy_last_hour"] is False),
        "apps_health_check_without_recent_data": sum(
            1 for c in running if c["health_check_enabled"] is not False and c["healthy_last_hour"] is None),
        "apps_with_unhealthy_hours": sum(1 for c in running if c["hours_unhealthy"]),
        "health_check_metric_unread": sum(1 for c in checks if c["metric_status"] == ERROR),
        "regions": sorted({r["region"] for r in records}),
    }


def boundary_summary(scope: ResourceExclusions, excluded: list[dict], records: list[dict], listed: dict) -> dict:
    """Boundary counts per kind; null when that kind's list failed."""
    out = {
        "resource_exclusion_patterns": list(scope.patterns),
        "resource_exclusion_patterns_unmatched": scope.unmatched(),
    }
    for resource_type, kind in EXCLUDED_KIND.items():
        ok = listed[resource_type] is not None
        out[f"excluded_{kind}s"] = sum(1 for e in excluded if e["kind"] == kind) if ok else None
        out[f"in_scope_{kind}s"] = sum(1 for r in records if r["resource_type"] == resource_type) if ok else None
    return out


# --- collection ---

def list_resources(client, subscription_id: str, collector) -> tuple[dict, int | None]:
    """Projected resources per type (None when the list failed), and CDN profiles that are not Front Door."""
    base = f"/subscriptions/{subscription_id}/providers"
    sites = collector.guard("web.sites.list", lambda: client.list(f"{base}/Microsoft.Web/sites", WEB_API))
    profiles = collector.guard("cdn.profiles.list", lambda: client.list(f"{base}/Microsoft.Cdn/profiles", CDN_API))
    instances = collector.guard("sql.managedInstances.list",
                                lambda: client.list(f"{base}/Microsoft.Sql/managedInstances", SQL_API))

    def projected(items, resource_type):
        if items is None:
            return None
        return sorted((project_resource(i, resource_type) for i in items), key=lambda r: arm_id_key(r["id"]))

    listed = {
        APP: projected(sites, APP),
        FRONT_DOOR: projected(None if profiles is None else [p for p in profiles if is_front_door(p)], FRONT_DOOR),
        SQL_MI: projected(instances, SQL_MI),
    }
    return listed, None if profiles is None else sum(1 for p in profiles if not is_front_door(p))


def health_registration(client, subscription_id: str) -> str:
    try:
        body = client.get(f"/subscriptions/{subscription_id}/providers/{HEALTH_PROVIDER}", PROVIDERS_API)
    except Exception as exc:  # noqa: BLE001 — the per-resource reads still show whether Resource Health answers
        logger.warning("%s registration could not be read (%s)", HEALTH_PROVIDER, exc)
        return REGISTRATION_UNKNOWN
    state = lower(body.get("registrationState"))
    return NOT_REGISTERED if state in ("notregistered", "unregistered") else REGISTERED


def read_health(client, collector, resource: dict, now: datetime, window_start: datetime) -> dict:
    origin_driven = resource["resource_type"] == FRONT_DOOR
    signal = ORIGIN_PROBES if origin_driven else RESOURCE_SIGNAL
    try:
        statuses = client.list(f"{resource['id']}/providers/{HEALTH_PROVIDER}/availabilityStatuses", HEALTH_API)
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        status = classify(exc)
        if status in QUIET:
            logger.warning("Resource Health for %s: %s (%s)", resource["name"], status, exc)
        elif status != NOT_REGISTERED:
            collector.record(f"resourcehealth.availabilityStatuses.list({resource['name']})", exc)
        return unread_health(status, error_text(exc), signal)
    return health_record(statuses, now, window_start, origin_driven)


def read_health_check(client, collector, resource: dict, window: tuple[datetime, datetime]) -> dict:
    name, stopped = resource["name"], lower(resource.get("state")) == "stopped"
    path, config_status = None, READ
    try:
        path = ((client.get(f"{resource['id']}/config/web", WEB_API) or {}).get("properties") or {}).get(
            "healthCheckPath")
    except Exception as exc:  # noqa: BLE001 — a failed or refused read leaves the setting unknown
        config_status = NOT_AUTHORIZED if getattr(exc, "status", None) == 403 else ERROR
        collector.record(f"web.sites.config.web({name})", exc)
    if config_status == READ and not path:
        return health_check_record(config_status, None, NOT_READ, None, window[1], stopped)
    params = {
        "metricnames": HEALTH_CHECK_METRIC,
        "metricnamespace": "Microsoft.Web/sites",
        "aggregation": "Average,Minimum",
        "interval": "PT1H",
        "timespan": f"{iso(window[0])}/{iso(window[1])}",
    }
    metrics = collector.guard(
        f"insights.metrics.list({HEALTH_CHECK_METRIC}, {name})",
        lambda: client.list(f"{resource['id']}/providers/Microsoft.Insights/metrics", METRICS_API, params),
    )
    status = ERROR if metrics is None else READ
    return health_check_record(config_status, path, status, project_points(metrics or []), window[1], stopped)


def metrics_window(now: datetime, days: int) -> tuple[datetime, datetime]:
    # Whole hours only: the current hour's bucket is still filling.
    end = now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    return end - timedelta(days=days), end


def collect_resource(client, collector, resource: dict, registration: str, settings: dict, now: datetime) -> dict:
    window_start = now - timedelta(days=settings["lookback_days"])
    if registration == NOT_REGISTERED:
        health = unread_health(NOT_REGISTERED, f"{HEALTH_PROVIDER} is not registered on the subscription",
                               ORIGIN_PROBES if resource["resource_type"] == FRONT_DOOR else RESOURCE_SIGNAL)
    else:
        health = read_health(client, collector, resource, now, window_start)
    check = None
    if resource["resource_type"] == APP:
        check = read_health_check(client, collector, resource, metrics_window(now, settings["lookback_days"]))
    return resource_record(resource, health, check, settings["recovery_time_objective_hours"])


def collect(client, subscription_id: str, collector) -> tuple:
    now = utc_now()
    settings = read_settings(collector)
    scope = ResourceExclusions.from_env()
    scope.record_invalid(collector)

    listed, other_cdn_profiles = list_resources(client, subscription_id, collector)
    excluded: list[dict] = []
    in_scope: list[dict] = []
    for resource_type in RESOURCE_TYPES:
        kept, out = scope.split(listed[resource_type] or [], EXCLUDED_KIND[resource_type])
        in_scope += kept
        excluded += out
    scope.warn_unmatched(logger)

    registration = health_registration(client, subscription_id)
    if registration == NOT_REGISTERED and in_scope:
        collector.record(f"resourcehealth.registration({subscription_id})", RuntimeError(
            f"{HEALTH_PROVIDER} is not registered on the subscription, so no availability history can be read"))
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        records = list(pool.map(
            lambda r: collect_resource(client, collector, r, registration, settings, now), in_scope))
    rh_not_registered = [r for r in records if r["resource_health"]["status"] == NOT_REGISTERED]
    if registration != NOT_REGISTERED and rh_not_registered:
        collector.record("resourcehealth.availabilityStatuses.list", RuntimeError(
            f"{HEALTH_PROVIDER} answered as not registered for {len(rh_not_registered)} resource(s)"))

    window_start = now - timedelta(days=settings["lookback_days"])
    results = {
        "evaluated_at": iso(now),
        "settings": {**settings, "window_start": iso(window_start), "window_end": iso(now)},
        "resource_health_registration": registration,
        "resources": records,
        "regions": region_records(records),
        "cdn_profiles_not_front_door": other_cdn_profiles,
        "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id"))),
        "limitations": LIMITATIONS,
        "related_evidence": RELATED_EVIDENCE,
    }
    summary = {
        **summarize(records, listed, settings, registration),
        **boundary_summary(scope, excluded, records, listed),
    }
    return results, summary


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
