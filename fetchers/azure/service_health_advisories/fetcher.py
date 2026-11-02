#!/usr/bin/env python3
"""Microsoft Service Health events on the subscription over a lookback window, with the resources each one names."""

import html
import logging
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_id_key,
    basename,
    provider_registration_status,
    resource_group_from_id,
    sorted_counts,
)
from azure_rest import int_config, parse_time, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402
from resource_graph import query_all, resource_graph_client  # noqa: E402
from scope_exclusions import excluded_item  # noqa: E402

NAME = "azure_service_health_advisories"
logger = logging.getLogger(NAME)

API = "2025-05-01"
NAMESPACE = "Microsoft.ResourceHealth"
LOOKBACK_ENV = "AZURE_SERVICE_HEALTH_LOOKBACK_DAYS"
# Measured: 180 days answers, 270 days gets 502 BadGateway at once, every time.
MAX_LOOKBACK_DAYS = 180
DEFAULT_LOOKBACK_DAYS = MAX_LOOKBACK_DAYS
# Measured: Resource Graph's last update can differ from the event's by over two weeks; a by-id GET from years back
# still answers, so a wide margin costs nothing.
BY_ID_MARGIN_DAYS = 30
WORKERS = 4
# Summaries and updates are HTML written by Microsoft; a long incident runs to many kilobytes.
MAX_TEXT = 1000

SERVICE_ISSUE = "ServiceIssue"
PLANNED_MAINTENANCE = "PlannedMaintenance"
HEALTH_ADVISORY = "HealthAdvisory"
SECURITY_ADVISORY = "SecurityAdvisory"
BILLING = "Billing"
RETIREMENT = "Retirement"
ACTIVE = "active"
ACTION_RECOMMENDED_TAG = "action recommended"
HIGH_SEVERITY_LEVELS = ("critical", "error")
ADVISORIES = (HEALTH_ADVISORY, SECURITY_ADVISORY)

READ = "read"
NOT_FOUND = "not_found"
NOT_AUTHORIZED = "not_authorized"
ERROR = "error"
NOT_NEEDED = "not_needed"

LISTED = "event_list"
GRAPH = "resource_graph"
# Resource Graph keeps these times as ticks (Microsoft's samples read them with todatetime(tolong(...))).
EVENTS_QUERY = (
    "ServiceHealthResources | where type =~ 'microsoft.resourcehealth/events' "
    "| extend lastUpdateTime = coalesce(todatetime(tolong(properties.LastUpdateTime)), "
    "todatetime(tostring(properties.LastUpdateTime))) | project id, lastUpdateTime | order by id asc"
)
# Measured: the REST impactedResources list came back empty for events Resource Graph lists resources for.
IMPACTED_QUERY = (
    "ServiceHealthResources | where type =~ 'microsoft.resourcehealth/events/impactedresources' "
    "| project id, properties | order by id asc"
)

EVENT_KIND = "event"
RESOURCE_KIND = "impacted_resource"
DETAILS_ACTION = "Microsoft.ResourceHealth/events/fetchEventDetails/action"
ADVISORY_RESOURCES_ACTION = "Microsoft.ResourceHealth/events/listSecurityAdvisoryImpactedResources/action"

LIMITATIONS = [
    "Shows what Microsoft reported to the subscription, not whether anyone reviewed it: review disposition and "
    "change tracking are kept outside Azure.",
    "Lists events last updated within the lookback window (at most 180 days: the event list answers 502 Bad Gateway "
    "for a longer one), plus any older event Resource Graph still holds, such as a retirement announced long ago, "
    "read by its tracking id from its last update. One that read can't find is counted, not listed. An older event "
    "Resource Graph no longer holds is not in the evidence.",
    f"Security advisory summaries and updates need {DETAILS_ACTION}, and their impacted resources need "
    f"{ADVISORY_RESOURCES_ACTION}; Reader has neither, so without them those fields read unknown.",
    "Billing communications are left out: they concern charges, not service health.",
    "resource_exclusions patterns apply to the resources an event names, not to the regions a service-wide event "
    "lists.",
]

# Null, not 0, when the event list was not read.
EVENT_COUNTS = (
    "events", "events_by_type", "events_by_status", "events_by_level", "retirement_advisories",
    "billing_events_skipped", "open_events", "open_events_by_type", "open_service_issues",
    "open_security_advisories", "open_health_advisories", "open_retirement_advisories",
    "upcoming_planned_maintenance", "open_events_action_recommended", "open_high_severity_advisories",
    "sensitive_events", "sensitive_event_details_read", "sensitive_event_details_not_authorized",
    "events_impacted_resources_unread", "events_impacted_resources_not_authorized", "events_from_resource_graph",
    "events_in_resource_graph_not_found",
)
# Null, not a partial count, while any event's impacted resources are unread.
RESOURCE_COUNTS = (
    "impacted_resources", "impacted_resources_by_type", "events_with_impacted_resources",
    "open_events_with_impacted_resources",
)
TAG = re.compile(r"<[^>]+>")


# --- pure transforms ---

def plain(text):
    """HTML reduced to one line of text, capped and marked when cut."""
    if not isinstance(text, str):
        return None
    flat = " ".join(html.unescape(TAG.sub(" ", text)).split())
    if len(flat) <= MAX_TEXT:
        return flat or None
    return f"{flat[:MAX_TEXT]}… [truncated from {len(flat)} characters]"


def query_start(start: datetime) -> str:
    """queryStartTime takes M/D/YYYY; without it the list returns only the last 3 days."""
    return f"{start.month}/{start.day}/{start.year}"


def _lower(value) -> str:
    return str(value or "").lower()


def stamp(value):
    """The time as given, or None when absent or unparsable; Microsoft writes 0001-01-01 for a time not set."""
    parsed = parse_time(value)
    return value if parsed and parsed.year > 1900 else None


def is_open(event_type, status, mitigation, now: datetime) -> bool:
    """Microsoft's own 'active' rule: a service issue by its status, other events until their impact ends."""
    end = parse_time(stamp(mitigation))
    if event_type == SERVICE_ISSUE or end is None:
        return _lower(status) == ACTIVE
    return end > now


def _service(impact: dict) -> dict:
    regions = impact.get("impactedRegions") or []
    return {
        "service": impact.get("impactedService"),
        "regions": sorted({r.get("impactedRegion") for r in regions if r.get("impactedRegion")}, key=_lower),
        "active_regions": sorted({r.get("impactedRegion") for r in regions
                                  if r.get("impactedRegion") and _lower(r.get("status")) == ACTIVE}, key=_lower),
    }


def _updates(props: dict) -> list[dict]:
    """Each update once, oldest first; the same update repeats under every region it went to."""
    seen, out = set(), []
    for impact in props.get("impact") or []:
        for region in impact.get("impactedRegions") or []:
            for update in region.get("updates") or []:
                key = (update.get("updateDateTime"), update.get("summary"))
                if key not in seen:
                    seen.add(key)
                    out.append(update)
    return sorted(out, key=lambda u: (parse_time(u.get("updateDateTime")) is None,
                                      parse_time(u.get("updateDateTime")) or 0))


def event_record(raw: dict, now: datetime) -> dict:
    p = raw.get("properties") or {}
    updates = _updates(p)
    dated = [u for u in updates if stamp(u.get("updateDateTime"))]
    latest = dated[-1] if dated else None
    recommended = p.get("recommendedActions") or {}
    actions = [plain(a.get("actionText")) for a in recommended.get("actions") or [] if plain(a.get("actionText"))]
    tags = [t for t in p.get("eventTags") or [] if t]
    event_type = p.get("eventType")
    return {
        "tracking_id": raw.get("name"),
        "event_type": event_type,
        "event_sub_type": p.get("eventSubType"),
        "event_source": p.get("eventSource"),
        "status": p.get("status"),
        "event_level": p.get("eventLevel"),
        "level": p.get("level"),
        "priority": p.get("priority"),
        "title": p.get("title"),
        "summary": plain(p.get("summary")),
        "impact_type": p.get("impactType"),
        "impact_start_time": stamp(p.get("impactStartTime")),
        "impact_mitigation_time": stamp(p.get("impactMitigationTime")),
        "last_update_time": stamp(p.get("lastUpdateTime")),
        "published_at": dated[0].get("updateDateTime") if dated else None,
        "update_count": len(updates),
        "latest_update": {"at": latest.get("updateDateTime"), "summary": plain(latest.get("summary"))} if latest else None,
        "impacted_services": sorted((_service(i) for i in p.get("impact") or []), key=lambda s: _lower(s["service"])),
        "recommended_action_message": plain(recommended.get("message")),
        "recommended_actions": actions,
        "event_tags": tags,
        "action_recommended": bool(actions) or any(_lower(t) == ACTION_RECOMMENDED_TAG for t in tags),
        "is_sensitive": bool(p.get("isEventSensitive")),
        "open": is_open(event_type, p.get("status"), p.get("impactMitigationTime"), now),
    }


def impacted_record(raw: dict) -> dict:
    p = raw.get("properties") or {}
    rid = p.get("targetResourceId")
    return {
        "resource_id": rid,
        "resource_type": _lower(p.get("targetResourceType")) or None,
        "resource_name": p.get("resourceName") or basename(rid),
        "resource_group": p.get("resourceGroup") or resource_group_from_id(rid),
        "region": p.get("targetRegion"),
        "status": p.get("status"),
        "maintenance_start_time": stamp(p.get("maintenanceStartTime")),
        "maintenance_end_time": stamp(p.get("maintenanceEndTime")),
        "info": {kv["key"]: plain(kv.get("value")) for kv in p.get("info") or [] if kv.get("key")},
    }


def read_status(exc: BaseException) -> str:
    """By HTTP status alone; message wording would let a 400 or 409 pass as an expected miss."""
    status = getattr(exc, "status", None)
    if status == 404:
        return NOT_FOUND
    if status in (401, 403):
        return NOT_AUTHORIZED
    return ERROR


def with_reads(event: dict, details_status: str, resources_status: str, resources) -> dict:
    """A 404 means no resource list for the event, so none; a refused or failed read leaves it unknown."""
    known = resources_status in (READ, NOT_FOUND)
    listed = sorted((resources or []), key=lambda r: arm_id_key(r["resource_id"])) if known else None
    return {**event, "details_status": details_status, "impacted_resources_status": resources_status,
            "impacted_resources": listed}


def apply_scope(scope: ResourceExclusions, events: list[dict]) -> tuple[list[dict], list[dict]]:
    """(in-scope events, excluded entries). An event whose every listed resource is excluded leaves with them."""
    kept, excluded = [], []
    for event in events:
        if not event["impacted_resources"]:
            kept.append({**event, "excluded_impacted_resources": 0})
            continue
        resources, out = scope.split(
            event["impacted_resources"], RESOURCE_KIND, resource_id=lambda r: r["resource_id"],
            location=lambda r: r["region"], resource_group=lambda r: r["resource_group"],
            name=lambda r: r["resource_name"],
        )
        excluded += [{**entry, "tracking_id": event["tracking_id"]} for entry in out]
        if out and not resources:
            excluded.append(excluded_item(EVENT_KIND, event["title"], None, "every_impacted_resource_excluded",
                                          tracking_id=event["tracking_id"], event_type=event["event_type"]))
            continue
        kept.append({**event, "impacted_resources": resources, "excluded_impacted_resources": len(out)})
    return kept, excluded


def summarize(events: list[dict], events_read: bool, billing_skipped, lookback_days: int,
              graph_read: bool = True, graph_not_found: int = 0) -> dict:
    open_events = [e for e in events if e["open"]]
    unread = [e for e in events if e["impacted_resources"] is None]
    resources: dict[str, dict] = {}
    for event in events:
        for r in event["impacted_resources"] or []:
            resources.setdefault(arm_id_key(r["resource_id"]) or _lower(r["resource_name"]), r)

    def open_of(event_type, sub_type=None):
        return sum(1 for e in open_events
                   if e["event_type"] == event_type and (sub_type is None or e["event_sub_type"] == sub_type))

    sensitive = [e for e in events if e["is_sensitive"]]
    summary = {
        "lookback_days": lookback_days,
        "events": len(events),
        "events_from_resource_graph": sum(1 for e in events if e.get("listed_by") == GRAPH) if graph_read else None,
        "events_in_resource_graph_not_found": graph_not_found if graph_read else None,
        "events_by_type": sorted_counts(Counter(e["event_type"] or "unknown" for e in events)),
        "events_by_status": sorted_counts(Counter(e["status"] or "unknown" for e in events)),
        "events_by_level": sorted_counts(Counter(e["event_level"] or "unknown" for e in events)),
        "retirement_advisories": sum(1 for e in events if e["event_sub_type"] == RETIREMENT),
        "billing_events_skipped": billing_skipped,
        "open_events": len(open_events),
        "open_events_by_type": sorted_counts(Counter(e["event_type"] or "unknown" for e in open_events)),
        "open_service_issues": open_of(SERVICE_ISSUE),
        "open_security_advisories": open_of(SECURITY_ADVISORY),
        "open_health_advisories": open_of(HEALTH_ADVISORY),
        "open_retirement_advisories": open_of(HEALTH_ADVISORY, RETIREMENT),
        "upcoming_planned_maintenance": open_of(PLANNED_MAINTENANCE),
        "open_events_action_recommended": sum(1 for e in open_events if e["action_recommended"]),
        "open_high_severity_advisories": sum(
            1 for e in open_events
            if e["event_type"] in ADVISORIES and _lower(e["event_level"]) in HIGH_SEVERITY_LEVELS),
        "sensitive_events": len(sensitive),
        "sensitive_event_details_read": sum(1 for e in sensitive if e["details_status"] == READ),
        "sensitive_event_details_not_authorized": sum(1 for e in sensitive if e["details_status"] == NOT_AUTHORIZED),
        "events_impacted_resources_unread": len(unread),
        "events_impacted_resources_not_authorized": sum(
            1 for e in events if e["impacted_resources_status"] == NOT_AUTHORIZED),
        "impacted_resources": len(resources),
        "impacted_resources_by_type": sorted_counts(Counter(r["resource_type"] or "unknown" for r in resources.values())),
        "events_with_impacted_resources": sum(1 for e in events if e["impacted_resources"]),
        "open_events_with_impacted_resources": sum(1 for e in open_events if e["impacted_resources"]),
    }
    unknown = (() if events_read else EVENT_COUNTS + RESOURCE_COUNTS) + (RESOURCE_COUNTS if unread else ())
    return {**summary, **dict.fromkeys(unknown, None)}


# --- collection ---

def graph_rows(cred, subscription_id: str, query: str) -> list[dict]:
    return query_all(resource_graph_client(cred), subscription_id, query)["rows"]


def tracking_id_of(resource_id) -> str:
    """The tracking id inside an event or impacted-resource id, as written."""
    text = str(resource_id or "")
    at = text.lower().find("/events/")
    return text[at + len("/events/"):].split("/")[0] if at >= 0 else ""


def impacted_by_event(rows: list[dict]) -> dict:
    out: dict[str, list] = {}
    for row in rows:
        out.setdefault(_lower(tracking_id_of(row.get("id"))), []).append(impacted_record(row))
    return out


def read_details(client, base: str, event: dict, raw: dict, collector: Collector) -> tuple:
    """(status, raw event): a sensitive event's summary and updates come only from fetchEventDetails."""
    if not event["is_sensitive"]:
        return NOT_NEEDED, raw
    try:
        return READ, client.post(f"{base}/{event['tracking_id']}/fetchEventDetails", API)
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        status = read_status(exc)
        if status == ERROR:
            collector.record(f"resourceHealth.events.fetchEventDetails ({event['tracking_id']})", exc)
        else:
            logger.warning("event details %s: %s (%s)", event["tracking_id"], status, exc)
        return status, raw


def read_impacted(client, base: str, event: dict, graph_impacted, collector: Collector) -> tuple:
    """(status, resources): Resource Graph for most events, a security advisory's own POST action for those."""
    if event["event_type"] != SECURITY_ADVISORY:
        if graph_impacted is None:
            return ERROR, None
        return READ, graph_impacted.get(_lower(event["tracking_id"]), [])
    try:
        raw = client.post_list(f"{base}/{event['tracking_id']}/listSecurityAdvisoryImpactedResources", API)
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        status = read_status(exc)
        if status == ERROR:
            collector.record(f"resourceHealth.events.listSecurityAdvisoryImpactedResources ({event['tracking_id']})",
                             exc)
        else:
            logger.warning("impacted resources %s: %s (%s)", event["tracking_id"], status, exc)
        return status, None
    return READ, [impacted_record(r) for r in raw]


def read_event(client, base: str, raw: dict, listed_by: str, now: datetime, graph_impacted,
               collector: Collector) -> dict:
    event = event_record(raw, now)
    details_status, source = read_details(client, base, event, raw, collector)
    if details_status == READ:
        event = event_record({**raw, **source, "name": event["tracking_id"]}, now)
    resources_status, resources = read_impacted(client, base, event, graph_impacted, collector)
    return {**with_reads(event, details_status, resources_status, resources), "listed_by": listed_by}


def read_by_id(client, base: str, tracking_id: str, since: datetime, collector: Collector) -> tuple:
    """(status, raw event) for an event Resource Graph holds but the windowed list left out."""
    try:
        # The GET filters on lastUpdateTime like the list (3 days by default), so start before the event's last update.
        params = {"queryStartTime": query_start(since - timedelta(days=BY_ID_MARGIN_DAYS))}
        return READ, {"name": tracking_id, **client.get(f"{base}/{tracking_id}", API, params)}
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        status = read_status(exc)
        if status == NOT_FOUND:
            logger.warning("event %s is in Resource Graph but the event API did not find it", tracking_id)
        else:
            collector.record(f"resourceHealth.events.get ({tracking_id})", exc)
        return status, None


def graph_events(rows: list[dict]) -> dict:
    """Tracking id -> last update time (None when Resource Graph has none)."""
    return {tid: parse_time(stamp(r.get("lastUpdateTime"))) for r in rows if (tid := tracking_id_of(r.get("id")))}


def collect(client, subscription_id: str, now: datetime, lookback_days: int, collector: Collector) -> tuple:
    """(events, whether the event list was read, billing events skipped, whether Resource Graph's events were read,
    how many events Resource Graph holds that the event API did not find)."""
    base = f"/subscriptions/{subscription_id}/providers/{NAMESPACE}/events"
    window_start = now - timedelta(days=lookback_days)
    start = query_start(window_start)
    raw = collector.guard("resourceHealth.events.list", lambda: client.list(base, API, {"queryStartTime": start}))
    if raw is None:
        return [], False, None, False, None
    graph = collector.guard(
        "resourcegraph.resources (Service Health events)",
        lambda: graph_events(graph_rows(client.cred, subscription_id, EVENTS_QUERY)))
    graph_impacted = collector.guard(
        "resourcegraph.resources (Service Health impacted resources)",
        lambda: impacted_by_event(graph_rows(client.cred, subscription_id, IMPACTED_QUERY)))
    listed = {_lower(r.get("name")) for r in raw}
    missing = sorted((t for t in graph or {} if _lower(t) not in listed), key=_lower)
    reads = [read_by_id(client, base, t, graph[t] or window_start, collector) for t in missing]
    older = [found for status, found in reads if found is not None]
    not_found = sum(1 for status, _ in reads if status == NOT_FOUND)
    sources = [(r, LISTED) for r in raw] + [(r, GRAPH) for r in older]
    billing = sum(1 for r, _ in sources if (r.get("properties") or {}).get("eventType") == BILLING)
    wanted = [(r, by) for r, by in sources if (r.get("properties") or {}).get("eventType") != BILLING]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        events = list(pool.map(
            lambda item: read_event(client, base, item[0], item[1], now, graph_impacted, collector), wanted))
    return events, True, billing, graph is not None, not_found if graph is not None else None


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    """(results, summary) for run_subscription."""
    scope = ResourceExclusions.from_env()
    scope.record_invalid(collector)
    requested = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    lookback_days = min(requested, MAX_LOOKBACK_DAYS)
    if requested > MAX_LOOKBACK_DAYS:
        logger.warning("%s=%d is past the %d days the event list serves; using %d",
                       LOOKBACK_ENV, requested, MAX_LOOKBACK_DAYS, MAX_LOOKBACK_DAYS)
    now = datetime.now(timezone.utc)
    registration = provider_registration_status(collector, subscription_id, client.cred, NAMESPACE)
    events, events_read, billing, graph_read, not_found = collect(client, subscription_id, now, lookback_days,
                                                                  collector)
    events, excluded = apply_scope(scope, events)
    scope.warn_unmatched(logger)
    events.sort(key=lambda e: (e["tracking_id"] or ""))
    if events_read:
        logger.info("%d Service Health events in the last %d days or still in Resource Graph", len(events),
                    lookback_days)
    results = {
        "evaluated_at": now.isoformat(),
        "lookback_days": lookback_days,
        "lookback_days_requested": requested,
        "query_start": query_start(now - timedelta(days=lookback_days)),
        "events": events,
        "excluded": excluded,
        "provider_registration_status": registration,
        "limitations": LIMITATIONS,
    }
    boundary = scope.summary(excluded, (EVENT_KIND, RESOURCE_KIND), {})
    # One entry per event that names the resource; the count is of distinct resources, like impacted_resources.
    boundary["excluded_impacted_resources"] = len({arm_id_key(x["id"]) or _lower(x["name"])
                                                   for x in excluded if x["kind"] == RESOURCE_KIND})
    if not events_read:
        boundary.update({"excluded_events": None, "excluded_impacted_resources": None})
    elif any(e["impacted_resources"] is None for e in events):
        boundary["excluded_impacted_resources"] = None
    summary = {
        **summarize(events, events_read, billing, lookback_days, graph_read, not_found),
        "provider_registration_status": registration,
        **boundary,
    }
    return results, summary


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
