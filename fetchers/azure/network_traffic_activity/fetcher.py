#!/usr/bin/env python3
"""Network flows from Traffic Analytics, Front Door requests and traffic reaching Front Door's App Service origins directly."""

import ipaddress
import json
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import basename, sorted_counts  # noqa: E402
from azure_rest import (  # noqa: E402
    DIAG_API,
    LAW_API,
    ArmError,
    dig,
    int_config,
    iso_duration_days,
    parse_time,
    run_subscription,
    table_missing,
)

NAME = "azure_network_traffic_activity"
NETWORK_API = "2024-05-01"
CDN_API = "2024-09-01"
WEB_API = "2023-12-01"
LOOKBACK_ENV = "NETWORK_TRAFFIC_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 7
MAX_LOOKBACK_DAYS = 30
PORTS_ENV = "NETWORK_TRAFFIC_EXPECTED_INBOUND_PORTS"
DEFAULT_EXPECTED_PORTS = "80,443"
SPIKE_ENV = "NETWORK_TRAFFIC_DENIED_SPIKE_FACTOR"
DEFAULT_SPIKE_FACTOR = 3
# A quiet baseline would flag a handful of denied flows as a spike.
DENIED_SPIKE_FLOOR = 100
SAMPLE_ENV = "NETWORK_TRAFFIC_SAMPLE_SIZE"
DEFAULT_SAMPLE_SIZE = 10
BASIC_ENV = "NETWORK_TRAFFIC_QUERY_BASIC_TABLES"
LIST_CAP = 100

NSG_TABLE = "AzureNetworkAnalytics_CL"
VNET_TABLE = "NTANetAnalytics"
FD_TABLE = "AzureDiagnostics"
HTTP_TABLE = "AppServiceHTTPLogs"
FD_CATEGORY = "FrontDoorAccessLog"
HTTP_CATEGORY = "AppServiceHTTPLogs"
LOG_GROUPS = frozenset({"alllogs"})
FRONT_DOOR_SKUS = frozenset({"standard_azurefrontdoor", "premium_azurefrontdoor"})
FRONT_DOOR_TAG = "AzureFrontDoor.Backend"
INTERNET_FLOW_TYPES = ("ExternalPublic", "MaliciousFlow")
MALICIOUS = "MaliciousFlow"
INTERNAL_V4 = ("127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16")
INTERNAL_V6 = ("::1/128", "fc00::/7", "fe80::/10")
SOURCES = ("front_door", "internal", "public", "unknown")

TARGET_TYPES = (
    ("/networksecuritygroups/", "network_security_group"),
    ("/subnets/", "subnet"),
    ("/virtualnetworks/", "virtual_network"),
    ("/networkinterfaces/", "network_interface"),
)

# Each Traffic Analytics table normalised to the same columns; a column a workspace lacks reads empty.
_NSG_FLOWS = (
    f"{NSG_TABLE} | where TimeGenerated > ago({{span}}d) | where tostring(column_ifexists('SubType_s', '')) == 'FlowLog' "
    "| extend Sub1 = tostring(column_ifexists('Subscription1_g', '')), Sub2 = tostring(column_ifexists('Subscription2_g', '')), "
    "Acl = tostring(column_ifexists('NSGList_s', '')) "
    "| where Sub1 =~ '{subscription_id}' or Sub2 =~ '{subscription_id}' or Acl startswith '{subscription_id}/' "
    "| extend FlowType = tostring(column_ifexists('FlowType_s', '')), "
    "Direction = toupper(substring(tostring(column_ifexists('FlowDirection_s', '')), 0, 1)), "
    "Status = toupper(substring(tostring(column_ifexists('FlowStatus_s', '')), 0, 1)), "
    "Protocol = toupper(substring(tostring(column_ifexists('L4Protocol_s', '')), 0, 1)), "
    "DestPort = toint(column_ifexists('DestPort_d', real(null))), "
    "SrcIp = tostring(column_ifexists('SrcIP_s', '')), DestIp = tostring(column_ifexists('DestIP_s', '')), "
    "SrcPublic = tostring(column_ifexists('SrcPublicIPs_s', '')), DestPublic = tostring(column_ifexists('DestPublicIPs_s', '')), "
    "RecordFlows = tolong(todouble(column_ifexists('AllowedInFlows_d', 0.0)) + todouble(column_ifexists('DeniedInFlows_d', 0.0)) "
    "+ todouble(column_ifexists('AllowedOutFlows_d', 0.0)) + todouble(column_ifexists('DeniedOutFlows_d', 0.0))) "
)
_VNET_FLOWS = (
    f"{VNET_TABLE} | where TimeGenerated > ago({{span}}d) | where tostring(column_ifexists('SubType', '')) == 'FlowLog' "
    "| extend Sub1 = tostring(column_ifexists('SrcSubscription', '')), Sub2 = tostring(column_ifexists('DestSubscription', '')), "
    "Acl = tostring(column_ifexists('AclGroup', '')) "
    "| where Sub1 =~ '{subscription_id}' or Sub2 =~ '{subscription_id}' or Acl startswith '{subscription_id}/' "
    "| extend FlowType = tostring(column_ifexists('FlowType', '')), "
    "Direction = toupper(substring(tostring(column_ifexists('FlowDirection', '')), 0, 1)), "
    "Status = toupper(substring(tostring(column_ifexists('FlowStatus', '')), 0, 1)), "
    "Protocol = toupper(substring(tostring(column_ifexists('L4Protocol', '')), 0, 1)), "
    "DestPort = toint(column_ifexists('DestPort', int(null))), "
    "SrcIp = tostring(column_ifexists('SrcIp', '')), DestIp = tostring(column_ifexists('DestIp', '')), "
    "SrcPublic = tostring(column_ifexists('SrcPublicIps', '')), DestPublic = tostring(column_ifexists('DestPublicIps', '')), "
    "RecordFlows = tolong(column_ifexists('AllowedInFlows', 0)) + tolong(column_ifexists('DeniedInFlows', 0)) "
    "+ tolong(column_ifexists('AllowedOutFlows', 0)) + tolong(column_ifexists('DeniedOutFlows', 0)) "
)
# Public peers arrive as space-separated "ip|flows started|..." entries; each becomes its own row with its own count.
_PEERS = (
    "| extend Period = iff(TimeGenerated > ago({days}d), 'current', 'prior'), "
    "PublicIps = trim(@'\\s+', iff(Direction == 'I', SrcPublic, DestPublic)) "
    "| extend Entries = iff(isempty(PublicIps), dynamic(['']), split(PublicIps, ' ')) "
    "| mv-expand Entry = Entries to typeof(string) "
    "| where isempty(PublicIps) or isnotempty(Entry) "
    "| extend Fields = split(Entry, '|') "
    "| extend PublicIp = tostring(Fields[0]) "
    "| extend Flows = iff(isempty(PublicIp), RecordFlows, coalesce(tolong(Fields[1]), 0)), "
    "Src = iff(Direction == 'I' and isnotempty(PublicIp), PublicIp, SrcIp), "
    "Dest = iff(Direction == 'O' and isnotempty(PublicIp), PublicIp, DestIp) "
    "| extend Allowed = iff(Status == 'A', Flows, 0), Denied = iff(Status == 'D', Flows, 0) "
)
_RANKED = "| extend Rank = row_number(1, prev(ResourceId) != ResourceId) | where Rank <= {sample}"
FLOW_QUERIES = {
    "flow_daily": "| summarize Flows = sum(Flows), Allowed = sum(Allowed), Denied = sum(Denied) "
                  "by Day = startofday(TimeGenerated), Period, Direction, FlowType",
    "flow_ports": "| where Allowed > 0 | summarize CurrentAllowed = sumif(Allowed, Period == 'current'), "
                  "PriorAllowed = sumif(Allowed, Period == 'prior'), Sources = dcountif(Src, Period == 'current') "
                  f"by Direction, Protocol, DestPort, Internet = FlowType in ('{INTERNET_FLOW_TYPES[0]}', '{INTERNET_FLOW_TYPES[1]}')",
    "flow_destinations": "| where Direction == 'O' and Allowed > 0 and isnotempty(Dest) "
                         "| summarize Current = sumif(Allowed, Period == 'current'), Prior = sumif(Allowed, Period == 'prior'), "
                         "FirstSeen = minif(TimeGenerated, Period == 'current') by Dest, FlowType "
                         "| where Current > 0 | extend New = Prior == 0 "
                         "| order by FlowType asc, New desc, Current desc, Dest asc "
                         "| extend Rank = row_number(1, prev(FlowType) != FlowType) "
                         "| summarize Destinations = count(), NewDestinations = countif(New), "
                         "NewTop = make_list_if(bag_pack('destination', Dest, 'flows', Current, 'first_seen', FirstSeen), "
                         "New and Rank <= {sample}) by FlowType",
    "flow_top": "| where Period == 'current' | summarize Flows = sum(Flows), Allowed = sum(Allowed), Denied = sum(Denied), "
                "LastSeen = max(TimeGenerated) by Direction, FlowType, Src, Dest, DestPort, Protocol | top {sample} by Flows desc",
}
FLOW_BASES = {NSG_TABLE: _NSG_FLOWS, VNET_TABLE: _VNET_FLOWS}

# Front Door logs each request at the edge and again at the origin shield; only the client-facing copy counts.
_FD = (
    f"{FD_TABLE} | where TimeGenerated > ago({{days}}d) | where Category == '{FD_CATEGORY}' "
    "| where _ResourceId startswith '/subscriptions/{subscription_id}/' "
    "| where tostring(column_ifexists('isReceivedFromClient_b', '')) !~ 'false' "
    "| extend ResourceId = tolower(_ResourceId), Host = tostring(column_ifexists('hostName_s', '')), "
    "Status = coalesce(toint(column_ifexists('httpStatusCode_s', '')), toint(column_ifexists('httpStatusCode_d', real(null)))), "
    "Origin = tostring(column_ifexists('originName_s', '')), ClientIp = tostring(column_ifexists('clientIp_s', '')) "
)
FD_QUERIES = {
    "fd_profiles": "| summarize Requests = count(), FirstRequest = min(TimeGenerated), LastRequest = max(TimeGenerated), "
                   "Status2xx = countif(Status between (200 .. 299)), Status3xx = countif(Status between (300 .. 399)), "
                   "Status4xx = countif(Status between (400 .. 499)), Status5xx = countif(Status >= 500), "
                   "ClientIps = dcount(ClientIp) by ResourceId",
    "fd_hosts": "| summarize Requests = count(), Status5xx = countif(Status >= 500) by ResourceId, Host "
                "| order by ResourceId asc, Requests desc " + _RANKED,
    "fd_origins": "| where isnotempty(Origin) | summarize Requests = count(), Status5xx = countif(Status >= 500) by ResourceId, Origin "
                  "| order by ResourceId asc, Requests desc " + _RANKED,
    "fd_clients": "| summarize Requests = count() by ResourceId, ClientIp | order by ResourceId asc, Requests desc " + _RANKED,
}

# CIp is the address that connected to the app: Front Door's back end when a request came through it.
_HTTP = (
    f"{HTTP_TABLE} | where TimeGenerated > ago({{days}}d) | where tolower(_ResourceId) in ({{app_ids}}) "
    "| extend ResourceId = tolower(_ResourceId), "
    "Ip = iff(CIp matches regex @'^[0-9.]+:[0-9]+$', tostring(split(CIp, ':')[0]), tostring(CIp)) "
    "| extend V6 = Ip contains ':' "
    "| extend Source = case(isempty(Ip), 'unknown', "
    "V6 and {fd_v6_test}, 'front_door', not(V6) and {fd_v4_test}, 'front_door', "
    f"not(V6) and (ipv4_is_private(Ip) or ipv4_is_in_any_range(Ip, dynamic({json.dumps(list(INTERNAL_V4))}))), 'internal', "
    f"V6 and ipv6_is_in_any_range(Ip, dynamic({json.dumps(list(INTERNAL_V6))})), 'internal', 'public') "
)
HTTP_QUERIES = {
    "origin_sources": "| summarize Requests = count(), Served = countif(ScStatus < 400), ClientIps = dcount(Ip), "
                      "LastRequest = max(TimeGenerated) by ResourceId, Source",
    "origin_public_clients": "| where Source == 'public' | summarize Requests = count(), Served = countif(ScStatus < 400) "
                             "by ResourceId, Ip | order by ResourceId asc, Requests desc " + _RANKED,
}

# Host and origin names reach the evidence verbatim; a probe's text there can make the upload refuse the file.
HOST_NAME = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]+)?$")
QUERY_CODE = re.compile(r"^\((\d{3})\)\s*(\S*)")

WS_QUERIED = "queried"
WS_NOT_AUTHORIZED = "not_authorized"
WS_NOT_FOUND = "not_found"
WS_ERROR = "error"
ANALYTICS = "analytics"
CURRENT = "current"
PRIOR = "prior"

logger = logging.getLogger(NAME)


# --- pure transforms ---

def id_key(resource_id) -> str:
    return (resource_id or "").lower().rstrip("/")


def lookback_days() -> int:
    days = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    if days > MAX_LOOKBACK_DAYS:
        logger.warning("%s=%d is over %d; using %d", LOOKBACK_ENV, days, MAX_LOOKBACK_DAYS, MAX_LOOKBACK_DAYS)
    return min(days, MAX_LOOKBACK_DAYS)


def expected_ports(raw) -> list[int]:
    ports = set()
    for part in re.split(r"[,\s]+", raw or ""):
        if part.isdigit() and 0 < int(part) < 65536:
            ports.add(int(part))
        elif part:
            logger.warning("%s: %r is not a port; ignored", PORTS_ENV, part)
    return sorted(ports)


def flag(env: str) -> bool:
    return os.environ.get(env, "").strip().lower() in {"1", "true", "yes", "on"}


def target_type(resource_id) -> str | None:
    rid = (resource_id or "").lower()
    return next((kind for marker, kind in TARGET_TYPES if marker in rid), None)


def flow_log_record(raw: dict) -> dict:
    props = raw.get("properties") or {}
    ta = dig(props, "flowAnalyticsConfiguration", "networkWatcherFlowAnalyticsConfiguration") or {}
    kind = target_type(props.get("targetResourceId"))
    enabled = props.get("enabled") is True
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "enabled": enabled,
        "target_type": kind,
        "target_id": props.get("targetResourceId"),
        "traffic_analytics_enabled": enabled and ta.get("enabled") is True,
        "traffic_analytics_workspace_id": ta.get("workspaceResourceId"),
        "traffic_analytics_interval_minutes": ta.get("trafficAnalyticsInterval"),
        "traffic_table": NSG_TABLE if kind == "network_security_group" else VNET_TABLE,
    }


def exporting_workspaces(settings, category: str) -> list[str]:
    """Workspaces of the settings that send `category` to Log Analytics, by name or through allLogs."""
    seen: dict = {}
    for setting in settings or []:
        props = setting.get("properties") or {}
        workspace = props.get("workspaceId")
        if not workspace:
            continue
        for log in props.get("logs") or []:
            named = (log.get("category") or "").lower() == category.lower()
            grouped = (log.get("categoryGroup") or "").lower() in LOG_GROUPS
            if log.get("enabled") is True and (named or grouped):
                seen.setdefault(id_key(workspace), workspace)
    return [seen[k] for k in sorted(seen)]


def host_name(value):
    return value if isinstance(value, str) and HOST_NAME.match(value) else None


def ip_text(value):
    try:
        return str(ipaddress.ip_address(str(value).strip("[]")))
    except ValueError:
        return None


def dynamic_list(value) -> list:
    """make_list columns arrive as JSON text from the query API."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return value if isinstance(value, list) else []


def range_test(function: str, prefixes: list[str]) -> str:
    """An empty range list reads false rather than asking KQL to match against nothing."""
    return f"{function}(Ip, dynamic({json.dumps(sorted(prefixes))}))" if prefixes else "false"


def split_prefixes(prefixes) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for prefix in prefixes or []:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6


def front_door_prefixes(tags: dict) -> list[str]:
    for tag in tags.get("values") or []:
        if tag.get("name") == FRONT_DOOR_TAG:
            return list(dig(tag, "properties", "addressPrefixes") or [])
    return []


def region_name(location) -> str:
    return (location or "").replace(" ", "").lower()


def _status_and_code(exc: BaseException) -> tuple:
    status, code = getattr(exc, "status", None), str(getattr(exc, "code", None) or "")
    match = QUERY_CODE.match(code)
    if match:
        status, code = int(match.group(1)), match.group(2)
    return status, code.lower()


def ws_status(exc: BaseException) -> str:
    """Classified on the status and error code only: messages can carry workspace names and query text."""
    status, code = _status_and_code(exc)
    if code == "subscriptionnotfound":
        return WS_NOT_AUTHORIZED
    if status == 404:
        return WS_NOT_FOUND
    if status in (401, 403):
        return WS_NOT_AUTHORIZED
    return WS_ERROR


def table_record(name: str, raw) -> dict:
    """raw None: the table does not exist in the workspace yet."""
    props = (raw or {}).get("properties") or {}
    return {
        "name": name,
        "exists": raw is not None,
        "plan": props.get("plan"),
        "retention_in_days": props.get("retentionInDays"),
    }


def analytics_plan(table: dict) -> bool:
    return (table.get("plan") or "Analytics").lower() == ANALYTICS


def _latest(times):
    parsed = [(parse_time(t), t) for t in times if t]
    parsed = [p for p in parsed if p[0] is not None]
    return max(parsed)[1] if parsed else None


def _earliest(times):
    parsed = [(parse_time(t), t) for t in times if t]
    parsed = [p for p in parsed if p[0] is not None]
    return min(parsed)[1] if parsed else None


def _day(value) -> str | None:
    parsed = parse_time(value)
    return parsed.date().isoformat() if parsed else None


def _num(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# --- traffic analytics ---

def traffic_record(flow_reads: list[dict], days: int, ports_expected: list[int], spike_factor: int, sample: int) -> dict:
    """flow_reads: one entry per workspace table read, each holding its query rows."""
    daily = [r for read in flow_reads for r in read.get("flow_daily") or []]
    totals: dict = defaultdict(Counter)
    flow_types: dict = defaultdict(Counter)
    denied_per_day: Counter = Counter()
    prior_days = set()
    for r in daily:
        period = r.get("Period")
        flows, allowed, denied = _num(r.get("Flows")), _num(r.get("Allowed")), _num(r.get("Denied"))
        totals[period].update({"flows": flows, "allowed": allowed, "denied": denied})
        if period == CURRENT:
            ftype = r.get("FlowType") or "Unknown"
            flow_types[ftype].update({"flows": flows, "allowed": allowed, "denied": denied})
            day = _day(r.get("Day"))
            if day:
                denied_per_day[day] += denied
            if r.get("Direction") == "I" and ftype in INTERNET_FLOW_TYPES:
                totals["internet_inbound"]["allowed"] += allowed
            if ftype == MALICIOUS:
                totals["malicious"]["allowed"] += allowed
        elif period == PRIOR and flows:
            day = _day(r.get("Day"))
            if day:
                prior_days.add(day)
    baseline = bool(prior_days)
    baseline_daily_denied = round(totals[PRIOR]["denied"] / days, 1) if baseline else None
    threshold = spike_factor * max(baseline_daily_denied or 0, DENIED_SPIKE_FLOOR) if baseline else None
    spikes = sorted(d for d, n in denied_per_day.items() if threshold is not None and n > threshold)

    ports: dict = defaultdict(Counter)
    for r in (r for read in flow_reads for r in read.get("flow_ports") or []):
        key = (r.get("Direction"), r.get("Protocol"), r.get("DestPort"), bool(r.get("Internet")))
        ports[key].update({"current": _num(r.get("CurrentAllowed")), "prior": _num(r.get("PriorAllowed")),
                           "sources": _num(r.get("Sources"))})
    port_records = sorted(
        ({"direction": d, "protocol": p, "port": port, "from_internet": internet, "allowed_flows": c["current"],
          "distinct_sources": c["sources"], "new": baseline and c["prior"] == 0}
         for (d, p, port, internet), c in ports.items() if c["current"] > 0),
        key=lambda x: (-x["allowed_flows"], x["direction"] or "", x["port"] if x["port"] is not None else -1),
    )
    new_ports = [p for p in port_records if p["new"]]
    unexpected = sorted({
        p["port"] for p in port_records
        if p["direction"] == "I" and p["from_internet"] and p["port"] is not None and p["port"] not in ports_expected
    })

    destinations: Counter = Counter()
    new_destinations: Counter = Counter()
    new_top = []
    for r in (r for read in flow_reads for r in read.get("flow_destinations") or []):
        ftype = r.get("FlowType") or "Unknown"
        destinations[ftype] += _num(r.get("Destinations"))
        new_destinations[ftype] += _num(r.get("NewDestinations"))
        for d in dynamic_list(r.get("NewTop")):
            ip = ip_text(d.get("destination")) if isinstance(d, dict) else None
            if ip:
                new_top.append({"destination": ip, "flow_type": ftype, "allowed_flows": _num(d.get("flows")),
                                "first_seen": d.get("first_seen")})
    new_top.sort(key=lambda d: (-d["allowed_flows"], d["destination"]))

    top = sorted(
        ({"direction": r.get("Direction"), "flow_type": r.get("FlowType"), "source": ip_text(r.get("Src")),
          "destination": ip_text(r.get("Dest")), "port": r.get("DestPort"), "protocol": r.get("Protocol"),
          "flows": _num(r.get("Flows")), "allowed": _num(r.get("Allowed")), "denied": _num(r.get("Denied")),
          "last_seen": r.get("LastSeen")}
         for read in flow_reads for r in read.get("flow_top") or []),
        key=lambda f: (-f["flows"], f["source"] or "", f["destination"] or "", f["port"] or 0),
    )[:sample]
    return {
        "baseline_available": baseline,
        "prior_window_days_with_records": len(prior_days),
        "flows": totals[CURRENT]["flows"],
        "allowed_flows": totals[CURRENT]["allowed"],
        "denied_flows": totals[CURRENT]["denied"],
        "prior_window_flows": totals[PRIOR]["flows"],
        "flow_types": {k: dict(sorted(v.items())) for k, v in sorted(flow_types.items())},
        "internet_inbound_allowed_flows": totals["internet_inbound"]["allowed"],
        "malicious_allowed_flows": totals["malicious"]["allowed"],
        "denied_flows_per_day": dict(sorted(denied_per_day.items())),
        "baseline_daily_denied_flows": baseline_daily_denied,
        "denied_spike_threshold": threshold,
        "denied_spike_days": spikes if baseline else None,
        "allowed_ports": len(port_records),
        "top_allowed_ports": port_records[:sample],
        "new_ports": new_ports[:LIST_CAP] if baseline else None,
        "new_ports_count": len(new_ports) if baseline else None,
        "unexpected_inbound_ports": unexpected[:LIST_CAP],
        "unexpected_inbound_ports_count": len(unexpected),
        "outbound_destinations": sum(destinations.values()),
        "outbound_destinations_by_flow_type": sorted_counts(destinations),
        "new_outbound_destinations": sum(new_destinations.values()) if baseline else None,
        "new_outbound_destinations_by_flow_type": sorted_counts(new_destinations) if baseline else None,
        "new_outbound_destinations_top": new_top[:sample] if baseline else None,
        "top_flows": top,
    }


# --- front door and origins ---

def _rows(workspaces: dict, wids: list[str], key: str, rid: str) -> list[dict]:
    rows: list[dict] = []
    for wid in wids:
        for r in (workspaces.get(id_key(wid)) or {}).get(key) or []:
            if (r.get("ResourceId") or "").lower() == rid:
                rows.append(r)
    return rows


def _fullest(rid: str, wids: list[str], workspaces: dict, key: str) -> list[str]:
    """Each destination keeps its own copy of the records, so counts come from the one holding the most, not a sum."""
    totals = {wid: sum(_num(r.get("Requests")) for r in _rows(workspaces, [wid], key, rid)) for wid in wids}
    return [max(totals, key=lambda wid: totals[wid])] if totals else []


def _answered(wids: list[str], workspaces: dict, table: str) -> bool:
    """Every workspace answered every query on the table, or no longer exists."""
    for wid in wids:
        ws = workspaces.get(id_key(wid)) or {}
        if ws.get("status") != WS_NOT_FOUND and table not in ws.get("read_tables", ()):
            return False
    return True


def _arriving(records: int, wids: list[str], workspaces: dict, table: str):
    if not wids:
        return None
    if records:
        return True
    return False if _answered(wids, workspaces, table) else None


def _ranked(rows: list[dict], field: str, clean, sample: int) -> list[dict]:
    out = [{"name": clean(r.get(field)), "requests": _num(r.get("Requests")), "status_5xx": _num(r.get("Status5xx"))}
           for r in rows]
    return sorted((o for o in out if o["name"]), key=lambda o: (-o["requests"], o["name"]))[:sample]


def profile_record(profile: dict, settings, origins: list[dict], workspaces: dict, sample: int) -> dict:
    rid = id_key(profile.get("id"))
    wids = exporting_workspaces(settings, FD_CATEGORY)
    counted = _fullest(rid, wids, workspaces, "fd_profiles")
    rows = _rows(workspaces, counted, "fd_profiles", rid)
    requests = sum(_num(r.get("Requests")) for r in rows)
    arriving = _arriving(requests, wids, workspaces, FD_TABLE)
    known = arriving is not None and _answered(counted, workspaces, FD_TABLE)
    clients = _rows(workspaces, counted, "fd_clients", rid)
    return {
        "id": profile.get("id"),
        "name": profile.get("name"),
        "sku": dig(profile, "sku", "name"),
        "origins": len(origins),
        "diagnostic_settings_read": settings is not None,
        "access_log_exported": bool(wids) if settings is not None else None,
        "access_log_workspaces": wids,
        "requests": requests if known else None,
        "first_request": _earliest(r.get("FirstRequest") for r in rows),
        "last_request": _latest(r.get("LastRequest") for r in rows),
        "status_classes": {k: sum(_num(r.get(f"Status{k}")) for r in rows) for k in ("2xx", "3xx", "4xx", "5xx")}
        if known else None,
        "distinct_client_ips": max((_num(r.get("ClientIps")) for r in rows), default=0) if known else None,
        "top_hosts": _ranked(_rows(workspaces, counted, "fd_hosts", rid), "Host", host_name, sample),
        "top_origins": _ranked(_rows(workspaces, counted, "fd_origins", rid), "Origin", host_name, sample),
        "top_clients": sorted(
            ({"client_ip": ip_text(c.get("ClientIp")), "requests": _num(c.get("Requests"))} for c in clients
             if ip_text(c.get("ClientIp"))),
            key=lambda c: (-c["requests"], c["client_ip"]),
        )[:sample],
        "access_logs_arriving": arriving,
    }


def match_origin_apps(origins: list[dict], sites: list[dict]) -> dict:
    """App Service apps (by id key) that a Front Door origin reaches, by the origin's Azure resource or its host name."""
    by_id = {id_key(s.get("id")): s for s in sites}
    by_host: dict = {}
    for s in sites:
        for host in dig(s, "properties", "enabledHostNames") or [dig(s, "properties", "defaultHostName")]:
            if host:
                by_host.setdefault(host.lower(), s)
    matched: dict = {}
    for origin in origins:
        site = by_id.get(id_key(origin.get("azure_origin_id"))) or by_host.get((origin.get("host_name") or "").lower())
        if site:
            entry = matched.setdefault(id_key(site.get("id")), {"site": site, "origins": [], "profiles": set()})
            entry["origins"].append(origin.get("host_name"))
            entry["profiles"].add(origin.get("profile"))
    return matched


def origin_app_record(entry: dict, settings, workspaces: dict, ranges_known: bool, sample: int) -> dict:
    site = entry["site"]
    rid = id_key(site.get("id"))
    wids = exporting_workspaces(settings, HTTP_CATEGORY)
    counted = _fullest(rid, wids, workspaces, "origin_sources")
    rows = _rows(workspaces, counted, "origin_sources", rid)
    requests = sum(_num(r.get("Requests")) for r in rows)
    arriving = _arriving(requests, wids, workspaces, HTTP_TABLE)
    known = ranges_known and arriving is not None and _answered(counted, workspaces, HTTP_TABLE)
    by_source = {s: 0 for s in SOURCES}
    served = {s: 0 for s in SOURCES}
    clients = {s: 0 for s in SOURCES}
    for r in rows:
        source = str(r.get("Source")) if r.get("Source") in by_source else "unknown"
        by_source[source] += _num(r.get("Requests"))
        served[source] += _num(r.get("Served"))
        clients[source] = max(clients[source], _num(r.get("ClientIps")))
    public_clients = _rows(workspaces, counted, "origin_public_clients", rid)
    return {
        "id": site.get("id"),
        "name": site.get("name"),
        "state": dig(site, "properties", "state"),
        "front_door_profiles": sorted(p for p in entry["profiles"] if p),
        "origin_host_names": sorted({h for h in entry["origins"] if host_name(h)}),
        "diagnostic_settings_read": settings is not None,
        "http_logs_exported": bool(wids) if settings is not None else None,
        "http_log_workspaces": wids,
        "requests_by_source": by_source if known else None,
        "requests_outside_front_door": by_source["public"] if known else None,
        "requests_outside_front_door_served": served["public"] if known else None,
        "client_ips_outside_front_door": clients["public"] if known else None,
        "top_clients_outside_front_door": sorted(
            ({"client_ip": ip_text(c.get("Ip")), "requests": _num(c.get("Requests")), "served": _num(c.get("Served"))}
             for c in public_clients if ip_text(c.get("Ip"))),
            key=lambda c: (-c["requests"], c["client_ip"]),
        )[:sample],
        "last_request": _latest(r.get("LastRequest") for r in rows),
        "http_logs_arriving": arriving,
    }


def _total(values):
    """None when any value is unknown."""
    values = list(values)
    return None if any(v is None for v in values) else sum(values)


def summarize(flow_logs: list[dict], traffic: dict, flow_tables: list[dict], profiles: list[dict], apps: list[dict],
              workspaces: list[dict], days: int, ports_expected: list[int]) -> dict:
    ta_logs = [f for f in flow_logs if f["traffic_analytics_enabled"]]
    status = Counter(w["status"] for w in workspaces)
    exporting_profiles = [p for p in profiles if p["access_log_exported"]]
    exporting_apps = [a for a in apps if a["http_logs_exported"]]
    flows_read = any(t["status"] == WS_QUERIED for t in flow_tables)
    flows_known = bool(flow_tables) and all(t["status"] == WS_QUERIED for t in flow_tables)
    t = traffic if flows_read else {}
    return {
        "lookback_days": days,
        "expected_inbound_ports": ports_expected,
        "flow_logs": len(flow_logs),
        "enabled_flow_logs": sum(1 for f in flow_logs if f["enabled"]),
        "flow_logs_with_traffic_analytics": len(ta_logs),
        "nsg_flow_logs_with_traffic_analytics": sum(1 for f in ta_logs if f["traffic_table"] == NSG_TABLE),
        "vnet_flow_logs_with_traffic_analytics": sum(1 for f in ta_logs if f["traffic_table"] == VNET_TABLE),
        "traffic_tables": len(flow_tables),
        "traffic_tables_read": sum(1 for x in flow_tables if x["status"] == WS_QUERIED),
        "traffic_tables_skipped_basic_plan": sum(1 for x in flow_tables if x["status"] == "skipped_basic_plan"),
        "traffic_tables_not_present": sum(1 for x in flow_tables if x["status"] == "not_present"),
        "traffic_read_in_full": flows_known,
        "traffic_baseline_available": t.get("baseline_available") if flows_read else None,
        "flows": t.get("flows"),
        "allowed_flows": t.get("allowed_flows"),
        "denied_flows": t.get("denied_flows"),
        "internet_inbound_allowed_flows": t.get("internet_inbound_allowed_flows"),
        "malicious_allowed_flows": t.get("malicious_allowed_flows"),
        "unexpected_inbound_ports": t.get("unexpected_inbound_ports"),
        "unexpected_inbound_ports_count": t.get("unexpected_inbound_ports_count"),
        "new_ports_count": t.get("new_ports_count"),
        "outbound_destinations": t.get("outbound_destinations"),
        "new_outbound_destinations": t.get("new_outbound_destinations"),
        "denied_spike_days": t.get("denied_spike_days"),
        "denied_spike_days_count": len(t["denied_spike_days"]) if t.get("denied_spike_days") is not None else None,
        "front_door_profiles": len(profiles),
        "front_door_profiles_exporting_access_log": len(exporting_profiles),
        "front_door_profiles_with_requests": sum(1 for p in profiles if p["access_logs_arriving"] is True),
        "front_door_profiles_without_access_log_records": sum(1 for p in exporting_profiles if p["access_logs_arriving"] is False),
        "front_door_profiles_access_log_unknown": sum(1 for p in exporting_profiles if p["access_logs_arriving"] is None),
        "front_door_requests": _total(p["requests"] for p in exporting_profiles),
        "front_door_5xx_responses": _total(p["status_classes"]["5xx"] if p["status_classes"] else None
                                           for p in exporting_profiles),
        "origin_apps": len(apps),
        "origin_apps_exporting_http_logs": len(exporting_apps),
        "origin_apps_without_http_log_export": sum(1 for a in apps if a["http_logs_exported"] is False),
        "origin_apps_bypass_unknown": sum(1 for a in exporting_apps if a["requests_by_source"] is None),
        "origin_apps_reached_outside_front_door": sum(1 for a in exporting_apps if (a["requests_outside_front_door"] or 0) > 0),
        "origin_apps_served_outside_front_door": sum(1 for a in exporting_apps
                                                     if (a["requests_outside_front_door_served"] or 0) > 0),
        "origin_requests_outside_front_door": _total(a["requests_outside_front_door"] for a in exporting_apps),
        "origin_requests_outside_front_door_served": _total(a["requests_outside_front_door_served"] for a in exporting_apps),
        "log_workspaces": len(workspaces),
        "log_workspaces_queried": status[WS_QUERIED],
        "log_workspaces_not_authorized": status[WS_NOT_AUTHORIZED],
        "log_workspaces_not_found": status[WS_NOT_FOUND],
    }


# --- collection ---

def _optional(client, path: str, api: str):
    try:
        return client.get(path, api)
    except ArmError as exc:
        if exc.status == 404:
            return None
        raise


def _error_text(exc: BaseException) -> str:
    return " ".join(str(exc).split())[:300]


def read_workspace(client, workspace_id: str, jobs: list[tuple], basic: bool, collector) -> dict:
    """jobs: (table, key, kql, timespan_days). A refusal leaves the workspace unread; another failure only that query."""
    tables = sorted({j[0] for j in jobs})
    out: dict = {"workspace_id": workspace_id, "name": basename(workspace_id), "status": WS_QUERIED, "error": None,
                 "tables": [], "read_tables": [], "skipped_tables": [], "failed_queries": []}
    try:
        customer_id = dig(client.get(workspace_id, LAW_API), "properties", "customerId")
        if not customer_id:
            raise LookupError(f"no customerId on workspace {workspace_id}")
        out["tables"] = [table_record(t, _optional(client, f"{workspace_id}/tables/{t}", LAW_API)) for t in tables]
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        return _unread(out, workspace_id, exc, collector)
    info = {t["name"]: t for t in out["tables"]}
    unread = set()
    for table, key, kql, span in jobs:
        meta = info[table]
        if not meta["exists"]:
            out[key] = []
            continue
        if not analytics_plan(meta) and not basic:
            continue
        runner = client.query if analytics_plan(meta) else client.search
        try:
            out[key] = runner(customer_id, kql, iso_duration_days(span))
        except Exception as exc:  # noqa: BLE001 — a refusal covers the workspace; anything else only this query
            if table_missing(exc, table):
                out[key] = []
                continue
            if ws_status(exc) != WS_ERROR:
                return _unread(out, workspace_id, exc, collector)
            unread.add(table)
            out["failed_queries"].append(key)
            collector.record(f"loganalytics.query({key}, {workspace_id})", exc)
            out["status"], out["error"] = WS_ERROR, out["error"] or _error_text(exc)
    out["skipped_tables"] = sorted(t["name"] for t in out["tables"] if t["exists"] and not analytics_plan(t) and not basic)
    out["read_tables"] = sorted(t["name"] for t in out["tables"]
                                if t["name"] not in unread and t["name"] not in out["skipped_tables"])
    return out


def _unread(out: dict, workspace_id: str, exc: BaseException, collector) -> dict:
    """A refused or deleted workspace is evidence; any other failure here fails the run."""
    status = ws_status(exc)
    if status == WS_ERROR:
        collector.record(f"loganalytics.read({workspace_id})", exc)
    else:
        logger.warning("Log Analytics workspace %s: %s (%s)", workspace_id, status, exc)
    return {**out, "status": status, "error": _error_text(exc), "read_tables": []}


def flow_table_status(ws: dict, table: str) -> str:
    if ws["status"] != WS_QUERIED and table not in ws.get("read_tables", ()):
        return ws["status"]
    meta = next((t for t in ws["tables"] if t["name"] == table), None)
    if meta is None or not meta["exists"]:
        return "not_present"
    if table in ws.get("skipped_tables", ()):
        return "skipped_basic_plan"
    return WS_QUERIED if table in ws.get("read_tables", ()) else WS_ERROR


def _provider_list(client, path: str, api: str, operation: str, collector) -> list:
    """A resource provider the subscription never registered has none of its resources."""
    def _list():
        try:
            return client.list(path, api)
        except ArmError as exc:
            if exc.code.lower() == "missingsubscriptionregistration":
                return []
            raise
    return collector.guard(operation, _list) or []


def _settings(client, resource_id: str, collector):
    return collector.guard(
        f"insights.diagnosticSettings.list({resource_id})",
        lambda: client.list(f"{resource_id}/providers/Microsoft.Insights/diagnosticSettings", DIAG_API),
    )


def collect_flow_logs(client, subscription_id: str, collector) -> list[dict]:
    base = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkWatchers"
    watchers = _provider_list(client, base, NETWORK_API, "network.networkWatchers.list", collector)
    out: list[dict] = []
    for w in watchers:
        logs = collector.guard(f"network.flowLogs.list({w.get('name')})",
                               lambda w=w: client.list(f"{w['id']}/flowLogs", NETWORK_API)) or []
        out.extend(flow_log_record(raw) for raw in logs)
    return sorted(out, key=lambda f: id_key(f["id"]))


def collect_front_door(client, subscription_id: str, collector) -> tuple:
    base = f"/subscriptions/{subscription_id}/providers/Microsoft.Cdn/profiles"
    listed = _provider_list(client, base, CDN_API, "cdn.profiles.list", collector)
    profiles = [p for p in listed if (dig(p, "sku", "name") or "").lower() in FRONT_DOOR_SKUS]
    origins: dict = {}
    for p in profiles:
        groups = collector.guard(f"cdn.originGroups.list({p.get('name')})",
                                 lambda p=p: client.list(f"{p['id']}/originGroups", CDN_API)) or []
        found = []
        for g in groups:
            for o in collector.guard(f"cdn.origins.list({g.get('name')})",
                                     lambda g=g: client.list(f"{g['id']}/origins", CDN_API)) or []:
                found.append({"profile": p.get("name"), "host_name": dig(o, "properties", "hostName"),
                              "azure_origin_id": dig(o, "properties", "azureOrigin", "id")})
        origins[id_key(p.get("id"))] = found
    return profiles, origins


def collect_sites(client, subscription_id: str, origins: list[dict], collector) -> list[dict]:
    sites = _provider_list(client, f"/subscriptions/{subscription_id}/providers/Microsoft.Web/sites", WEB_API,
                           "web.sites.list", collector)
    matched = match_origin_apps(origins, sites)
    hosts_left = {(o.get("host_name") or "").lower() for o in origins} - {
        (h or "").lower() for e in matched.values() for h in e["origins"]}
    # Slots are listed only when an origin names an App Service host no app claims.
    if any(h.endswith(".azurewebsites.net") for h in hosts_left):
        for site in list(sites):
            slots = collector.guard(f"web.sites.slots.list({site.get('name')})",
                                    lambda site=site: client.list(f"{site['id']}/slots", WEB_API))
            sites.extend(slots or [])
    return sites


def collect(client, subscription_id: str, collector) -> tuple:
    days = lookback_days()
    sample = int_config(SAMPLE_ENV, DEFAULT_SAMPLE_SIZE)
    spike_factor = int_config(SPIKE_ENV, DEFAULT_SPIKE_FACTOR)
    ports_expected = expected_ports(os.environ.get(PORTS_ENV) or DEFAULT_EXPECTED_PORTS)
    basic = flag(BASIC_ENV)
    fmt = {"days": days, "span": days * 2, "subscription_id": subscription_id, "sample": sample}

    flow_logs = collect_flow_logs(client, subscription_id, collector)
    profiles, origins_by_profile = collect_front_door(client, subscription_id, collector)
    origins = [o for found in origins_by_profile.values() for o in found]
    sites = collect_sites(client, subscription_id, origins, collector) if origins else []
    matched = match_origin_apps(origins, sites)
    profile_settings = {id_key(p["id"]): _settings(client, p["id"], collector) for p in profiles}
    app_settings = {k: _settings(client, e["site"]["id"], collector) for k, e in sorted(matched.items())}

    fd_v4: list[str] = []
    fd_v6: list[str] = []
    ranges_known = True
    http_apps = {k for k, s in app_settings.items() if exporting_workspaces(s, HTTP_CATEGORY)}
    if http_apps:
        location = region_name(dig(matched[sorted(http_apps)[0]], "site", "location"))
        tags = collector.guard(
            "network.serviceTags.list",
            lambda: client.get(f"/subscriptions/{subscription_id}/providers/Microsoft.Network/locations/{location}/serviceTags",
                               NETWORK_API),
        )
        fd_v4, fd_v6 = split_prefixes(front_door_prefixes(tags or {}))
        ranges_known = bool(fd_v4 or fd_v6)
        if tags is not None and not ranges_known:
            collector.record("network.serviceTags.list", LookupError(f"no {FRONT_DOOR_TAG} prefixes in the service tags"))

    jobs: dict = defaultdict(list)
    workspace_ids: dict = {}
    flow_tables = sorted({(id_key(f["traffic_analytics_workspace_id"]), f["traffic_table"])
                          for f in flow_logs if f["traffic_analytics_enabled"] and f["traffic_analytics_workspace_id"]})
    for f in flow_logs:
        if f["traffic_analytics_workspace_id"]:
            workspace_ids.setdefault(id_key(f["traffic_analytics_workspace_id"]), f["traffic_analytics_workspace_id"])
    for wkey, table in flow_tables:
        for key, tail in FLOW_QUERIES.items():
            jobs[wkey].append((table, f"{table}:{key}", (FLOW_BASES[table] + _PEERS + tail).format(**fmt), days * 2))
    for p in profiles:
        for wid in exporting_workspaces(profile_settings[id_key(p["id"])], FD_CATEGORY):
            workspace_ids.setdefault(id_key(wid), wid)
            if not any(j[1] == "fd_profiles" for j in jobs[id_key(wid)]):
                jobs[id_key(wid)].extend((FD_TABLE, key, (_FD + tail).format(**fmt), days) for key, tail in FD_QUERIES.items())
    if ranges_known:
        app_ids: dict = defaultdict(list)
        for k in sorted(http_apps):
            for wid in exporting_workspaces(app_settings[k], HTTP_CATEGORY):
                workspace_ids.setdefault(id_key(wid), wid)
                app_ids[id_key(wid)].append(k)
        for wkey, ids in app_ids.items():
            ids_kql = ", ".join(f"'{i}'" for i in ids)
            for key, tail in HTTP_QUERIES.items():
                kql = (_HTTP + tail).format(app_ids=ids_kql, fd_v4_test=range_test("ipv4_is_in_any_range", fd_v4),
                                            fd_v6_test=range_test("ipv6_is_in_any_range", fd_v6), **fmt)
                jobs[wkey].append((HTTP_TABLE, key, kql, days))

    workspaces = {k: read_workspace(client, workspace_ids[k], jobs[k], basic, collector) for k in sorted(jobs)}

    flow_reads, flow_table_records = [], []
    for wkey, table in flow_tables:
        ws = workspaces[wkey]
        status = flow_table_status(ws, table)
        meta: dict = next((t for t in ws["tables"] if t["name"] == table), {})
        flow_table_records.append({"workspace_id": ws["workspace_id"], "table": table, "status": status,
                                   "plan": meta.get("plan"), "retention_in_days": meta.get("retention_in_days")})
        if status == WS_QUERIED:
            flow_reads.append({key: ws.get(f"{table}:{key}") or [] for key in FLOW_QUERIES})
    traffic = traffic_record(flow_reads, days, ports_expected, spike_factor, sample)

    profile_records = sorted(
        (profile_record(p, profile_settings[id_key(p["id"])], origins_by_profile.get(id_key(p["id"]), []), workspaces, sample)
         for p in profiles),
        key=lambda p: id_key(p["id"]),
    )
    app_records = sorted(
        (origin_app_record(e, app_settings[k], workspaces, ranges_known, sample) for k, e in matched.items()),
        key=lambda a: id_key(a["id"]),
    )
    workspace_records = [
        {k: ws[k] for k in ("workspace_id", "name", "status", "error", "tables", "read_tables", "skipped_tables", "failed_queries")}
        for ws in workspaces.values()
    ]
    results = {
        "lookback_days": days,
        "baseline_days": days,
        "expected_inbound_ports": ports_expected,
        "denied_spike_factor": spike_factor,
        "denied_spike_floor": DENIED_SPIKE_FLOOR,
        "sample_size": sample,
        "query_basic_tables": basic,
        "flow_logs": flow_logs,
        "traffic_tables": flow_table_records,
        "traffic": traffic,
        "front_door_profiles": profile_records,
        "origin_apps": app_records,
        "front_door_backend_prefixes": len(fd_v4) + len(fd_v6),
        "workspaces": workspace_records,
        "queries": filled_queries(fmt),
    }
    return results, summarize(flow_logs, traffic, flow_table_records, profile_records, app_records, workspace_records,
                              days, ports_expected)


def filled_queries(fmt: dict) -> dict:
    """The KQL as run; the App Service query's id and Front Door range lists are left as placeholders."""
    out = {}
    for table, base in FLOW_BASES.items():
        for key, tail in FLOW_QUERIES.items():
            out[f"{table}:{key}"] = (base + _PEERS + tail).format(**fmt)
    out.update({key: (_FD + tail).format(**fmt) for key, tail in FD_QUERIES.items()})
    out.update({key: (_HTTP + tail).format(app_ids="{app_ids}", fd_v4_test="{fd_v4_test}", fd_v6_test="{fd_v6_test}", **fmt)
                for key, tail in HTTP_QUERIES.items()})
    return out


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
