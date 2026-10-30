#!/usr/bin/env python3
"""Whether WAF and DDoS protection are watched: WAF log activity, WAF and DDoS alerts, and DDoS mitigations in a window."""

import logging
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from alert_routing import (  # noqa: E402
    ACTION_GROUP_API,
    ACTION_GROUP_ID,
    PROCESSING_RULE_API,
    action_group_record,
    processing_rule_record,
    route,
)
from azure_common import basename  # noqa: E402
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

NAME = "azure_waf_ddos_activity"
NETWORK_API = "2024-05-01"
CDN_API = "2024-09-01"
FD_WAF_API = "2024-02-01"
METRIC_ALERT_API = "2018-03-01"
LOG_ALERT_API = "2023-12-01"
METRICS_API = "2023-10-01"
LOOKBACK_ENV = "WAF_DDOS_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 30
MAX_LOOKBACK_DAYS = 90
# Azure Monitor keeps platform metrics for 93 days.
MAX_METRIC_DAYS = 93
SAMPLE_ENV = "WAF_DDOS_SAMPLE_SIZE"
DEFAULT_SAMPLE_SIZE = 10
BASIC_ENV = "WAF_DDOS_QUERY_BASIC_TABLES"

DIAG_TABLE = "AzureDiagnostics"
AGW_DEDICATED_TABLE = "AGWFirewallLogs"
FD_WAF_CATEGORY = "FrontDoorWebApplicationFirewallLog"
AGW_WAF_CATEGORY = "ApplicationGatewayFirewallLog"
DDOS_CATEGORIES = ("DDoSProtectionNotifications", "DDoSMitigationFlowLogs", "DDoSMitigationReports")
LOG_GROUPS = frozenset({"alllogs"})
FRONT_DOOR_SKUS = frozenset({"standard_azurefrontdoor", "premium_azurefrontdoor"})
FRONT_DOOR = "front_door"
APP_GATEWAY = "application_gateway"
ATTACK_METRIC = "IfUnderDDoSAttack"
WAF_METRIC = re.compile(r"^(webapplicationfirewall|azwaf|blockedcount|blockedreqcount|matchedcount)", re.IGNORECASE)
WAF_TABLES = re.compile(r"\b(FrontDoorWebApplicationFirewallLog|ApplicationGatewayFirewallLog|AGWFirewallLogs)\b", re.IGNORECASE)
# Which WAF a metric or log belongs to: Front Door's start with WebApplicationFirewall, every other one is a gateway's.
FRONT_DOOR_WAF_SIGNAL = re.compile(r"^(webapplicationfirewall|frontdoorwebapplicationfirewalllog)", re.IGNORECASE)
DDOS_TABLES = re.compile(r"\b(DDoSProtectionNotifications|DDoSMitigationReports|DDoSMitigationFlowLogs)\b", re.IGNORECASE)
# Rule and policy names reach the evidence verbatim; anything else could carry a probe's text into the upload.
PLAIN_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
QUERY_CODE = re.compile(r"^\((\d{3})\)\s*(\S*)")

# Redirect sends the request elsewhere, so it never reaches the origin.
BLOCK_ACTIONS = ("block", "blocked", "jschallengeblock", "redirect")
LOG_ACTIONS = ("log", "anomalyscoring", "logandscore", "detected", "matched")
ALLOW_ACTIONS = ("allow", "allowed")

# Each WAF log normalised to Action, Policy, Mode, Rule and Ref (the request), whatever table it sits in.
_FD_WAF = (
    f"{DIAG_TABLE} | where TimeGenerated > ago({{days}}d) | where Category == '{FD_WAF_CATEGORY}' "
    "| where _ResourceId startswith '/subscriptions/{subscription_id}/' "
    "| extend ResourceId = tolower(_ResourceId), Action = tolower(tostring(column_ifexists('action_s', ''))), "
    "Policy = tostring(column_ifexists('policy_s', '')), Mode = tolower(tostring(column_ifexists('policyMode_s', ''))), "
    "Rule = tostring(column_ifexists('ruleName_s', '')), Ref = tostring(column_ifexists('trackingReference_s', '')) "
)
_AGW_WAF = (
    f"{DIAG_TABLE} | where TimeGenerated > ago({{days}}d) | where Category == '{AGW_WAF_CATEGORY}' "
    "| where _ResourceId startswith '/subscriptions/{subscription_id}/' "
    "| extend ResourceId = tolower(_ResourceId), Action = tolower(tostring(column_ifexists('action_s', ''))), "
    "Policy = tostring(column_ifexists('policyId_s', '')), "
    "Rule = trim('-', strcat_delim('-', tostring(column_ifexists('ruleSetType_s', '')), "
    "tostring(column_ifexists('ruleSetVersion_s', '')), tostring(column_ifexists('ruleId_s', '')))), "
    "Ref = tostring(column_ifexists('transactionId_g', '')) "
    "| extend Mode = iff(Action == 'detected', 'detection', '') "
)
_AGW_WAF_DEDICATED = (
    f"{AGW_DEDICATED_TABLE} | where TimeGenerated > ago({{days}}d) "
    "| where _ResourceId startswith '/subscriptions/{subscription_id}/' "
    "| extend ResourceId = tolower(_ResourceId), Action = tolower(tostring(column_ifexists('Action', ''))), "
    "Policy = tostring(column_ifexists('PolicyId', '')), "
    "Rule = trim('-', strcat_delim('-', tostring(column_ifexists('RuleSetType', '')), "
    "tostring(column_ifexists('RuleSetVersion', '')), tostring(column_ifexists('RuleId', '')))), "
    "Ref = tostring(column_ifexists('TransactionId', '')) "
    "| extend Mode = iff(Action == 'detected', 'detection', '') "
)
WAF_BASES = {
    "fd": (DIAG_TABLE, _FD_WAF),
    "agw": (DIAG_TABLE, _AGW_WAF),
    "agw_dedicated": (AGW_DEDICATED_TABLE, _AGW_WAF_DEDICATED),
}
_BLOCK = "Action in ({})".format(", ".join(f"'{a}'" for a in BLOCK_ACTIONS))
_LOG = "Action in ({})".format(", ".join(f"'{a}'" for a in LOG_ACTIONS))
_ALLOW = "Action in ({})".format(", ".join(f"'{a}'" for a in ALLOW_ACTIONS))
# A Detection-mode policy logs the action Prevention would take but never blocks.
_BLOCKED = f"{_BLOCK} and Mode != 'detection'"
_WOULD_BLOCK = f"{_BLOCK} and Mode == 'detection'"
# One request can match several rules, so each is folded to one row before it is counted.
WAF_QUERIES = {
    "requests": "| extend Ref = iff(isempty(Ref), tostring(new_guid()), Ref) "
                f"| summarize Events = count(), Blocked = countif({_BLOCKED}) > 0, WouldBlock = countif({_WOULD_BLOCK}) > 0, "
                f"Logged = countif({_LOG}) > 0, Allowed = countif({_ALLOW}) > 0, "
                f"Challenged = countif(Action has 'challenge' and not({_BLOCK})) > 0, "
                "First = min(TimeGenerated), Last = max(TimeGenerated) by ResourceId, Policy, Mode, Ref "
                "| summarize Events = sum(Events), Requests = count(), RequestsBlocked = countif(Blocked), "
                "RequestsWouldBlock = countif(WouldBlock and not(Blocked)), "
                "RequestsLoggedOnly = countif(Logged and not(Blocked) and not(WouldBlock) and not(Allowed)), "
                "RequestsAllowed = countif(Allowed and not(Blocked) and not(WouldBlock)), "
                "RequestsChallenged = countif(Challenged and not(Blocked)), FirstEvent = min(First), LastEvent = max(Last) "
                "by ResourceId, Policy, Mode",
    "rules": f"| where isnotempty(Rule) | summarize Events = count(), Blocked = countif({_BLOCKED}) by ResourceId, Rule "
             "| order by ResourceId asc, Events desc | extend Rank = row_number(1, prev(ResourceId) != ResourceId) "
             "| where Rank <= {sample}",
}
DDOS_QUERY = (
    f"{DIAG_TABLE} | where TimeGenerated > ago({{days}}d) "
    "| where Category in ('DDoSProtectionNotifications', 'DDoSMitigationFlowLogs', 'DDoSMitigationReports') "
    "| where _ResourceId startswith '/subscriptions/{subscription_id}/' "
    "| summarize Notifications = countif(Category == 'DDoSProtectionNotifications'), "
    "MitigationsStarted = countif(Category == 'DDoSProtectionNotifications' and tostring(column_ifexists('type_s', '')) =~ 'MitigationStarted'), "
    "Reports = countif(Category == 'DDoSMitigationReports'), FlowLogRecords = countif(Category == 'DDoSMitigationFlowLogs'), "
    "LastEvent = max(TimeGenerated) by ResourceId = tolower(_ResourceId)"
)

WS_QUERIED = "queried"
WS_NOT_AUTHORIZED = "not_authorized"
WS_NOT_FOUND = "not_found"
WS_ERROR = "error"
ANALYTICS = "analytics"
IP_PROTECTION = "ip_protection"
DISABLED = "disabled"
INHERITED = "virtual_network_inherited"

logger = logging.getLogger(NAME)


# --- pure transforms ---

def id_key(resource_id) -> str:
    return (resource_id or "").lower().rstrip("/")


def lookback_days() -> int:
    days = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    if days > MAX_LOOKBACK_DAYS:
        logger.warning("%s=%d is over %d; using %d", LOOKBACK_ENV, days, MAX_LOOKBACK_DAYS, MAX_LOOKBACK_DAYS)
    return min(days, MAX_LOOKBACK_DAYS)


def flag(env: str) -> bool:
    return os.environ.get(env, "").strip().lower() in {"1", "true", "yes", "on"}


def plain_name(value):
    return value if isinstance(value, str) and PLAIN_NAME.match(value) else None


def policy_name(value):
    """Front Door logs the policy's name, App Gateway its resource id."""
    return plain_name(basename(value) if isinstance(value, str) and "/" in value else value)


def exported_categories(settings, categories) -> dict:
    """{category: [workspace ids]} for the settings that send each category to Log Analytics, by name or through allLogs."""
    out: dict = {c: {} for c in categories}
    for setting in settings or []:
        props = setting.get("properties") or {}
        workspace = props.get("workspaceId")
        if not workspace:
            continue
        for log in props.get("logs") or []:
            if log.get("enabled") is not True:
                continue
            grouped = (log.get("categoryGroup") or "").lower() in LOG_GROUPS
            for c in categories:
                if grouped or (log.get("category") or "").lower() == c.lower():
                    out[c].setdefault(id_key(workspace), workspace)
    return {c: [ws[k] for k in sorted(ws)] for c, ws in out.items()}


def dedicated(settings, workspace) -> bool:
    """Whether the setting sending to `workspace` writes resource-specific tables instead of AzureDiagnostics."""
    for setting in settings or []:
        props = setting.get("properties") or {}
        if id_key(props.get("workspaceId")) == id_key(workspace):
            return (props.get("logAnalyticsDestinationType") or "").lower() == "dedicated"
    return False


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
    props = (raw or {}).get("properties") or {}
    return {"name": name, "exists": raw is not None, "plan": props.get("plan"), "retention_in_days": props.get("retentionInDays")}


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


def _num(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _covers(scope, resource_id) -> bool:
    scope, rid = id_key(scope), id_key(resource_id)
    return bool(scope) and (rid == scope or rid.startswith(scope + "/"))


def tri_any(values) -> bool | None:
    """True if any is True; False only when all are False."""
    values = list(values)
    if any(v is True for v in values):
        return True
    return False if values and all(v is False for v in values) else None


# --- alert rules ---

def alert_rule_record(rule_type: str, raw: dict) -> dict:
    """Only what decides whether the rule watches WAF or DDoS activity, and where it sends notifications."""
    props = raw.get("properties") or {}
    if rule_type == "metric":
        criteria = (props.get("criteria") or {}).get("allOf") or []
        metrics = sorted({c.get("metricName") for c in criteria if c.get("metricName")})
        groups = [a.get("actionGroupId") for a in props.get("actions") or [] if a.get("actionGroupId")]
        watches_waf = any(WAF_METRIC.match(m) for m in metrics)
        watches_ddos = any(m.lower() == ATTACK_METRIC.lower() for m in metrics)
        signal = metrics
        alerting = True
    else:
        queries = " ".join(c.get("query") or "" for c in (props.get("criteria") or {}).get("allOf") or [])
        groups = [g for g in (props.get("actions") or {}).get("actionGroups") or [] if g]
        watches_waf = bool(WAF_TABLES.search(queries))
        watches_ddos = bool(DDOS_TABLES.search(queries))
        signal = sorted({m.group(1) for m in list(WAF_TABLES.finditer(queries)) + list(DDOS_TABLES.finditer(queries))})
        # LogToMetric rules publish a metric and never notify.
        alerting = (raw.get("kind") or "LogAlert") != "LogToMetric"
    waf_signals = [s for s in signal if WAF_METRIC.match(s) or WAF_TABLES.fullmatch(s)]
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "rule_type": rule_type,
        "enabled": props.get("enabled") is True and alerting,
        "scopes": props.get("scopes") or [],
        "signals": signal,
        "watches_waf": watches_waf,
        "waf_resource_types": sorted({FRONT_DOOR if FRONT_DOOR_WAF_SIGNAL.match(s) else APP_GATEWAY for s in waf_signals}),
        "watches_ddos_attack": watches_ddos,
        "action_group_ids": groups,
    }


def routed(rule: dict, groups: dict, processing_rules: list[dict]) -> dict:
    r = route(rule["enabled"], rule["action_group_ids"], rule["scopes"], groups, processing_rules)
    return {
        **{k: rule[k] for k in ("id", "name", "rule_type", "enabled", "signals", "watches_waf", "waf_resource_types",
                                "watches_ddos_attack")},
        "scopes": len(rule["scopes"]),
        "routes_to_enabled_receiver": r["routes_to_enabled_receiver"],
        "routes_to_person": r["routes_to_person"],
        "suppressed": r["suppressed"],
        "reaches_human": r["reaches_human"],
        "unresolved_action_group_ids": r["unresolved_action_group_ids"],
    }


def covering_rules(rules: list[dict], resource_id: str, workspaces: list[str], key: str, waf_type: str | None = None) -> list[dict]:
    """Enabled rules on the signal scoped to the resource, a parent of it or (log rules) a workspace receiving its logs;
    a WAF rule covers only its own WAF kind."""
    wanted = {id_key(w) for w in workspaces}
    return [
        r for r in rules
        if r["enabled"] and r[key] and (waf_type is None or waf_type in r["waf_resource_types"])
        and any(_covers(s, resource_id) or (r["rule_type"] == "log_search" and id_key(s) in wanted) for s in r["_scopes"])
    ]


# --- WAF resources ---

def front_door_waf_resource(profile: dict, security_policies) -> dict:
    """Front Door attaches WAF policies through security policies; None when they could not be read."""
    policies = None if security_policies is None else sorted({
        dig(sp, "properties", "parameters", "wafPolicy", "id") for sp in security_policies
        if dig(sp, "properties", "parameters", "wafPolicy", "id")
    }, key=str.lower)
    return {"id": profile.get("id"), "name": profile.get("name"), "type": FRONT_DOOR, "sku": dig(profile, "sku", "name"),
            "waf_policy_ids": policies, "category": FD_WAF_CATEGORY}


def gateway_waf_resource(gateway: dict) -> dict | None:
    """A WAF-tier gateway with a WAF policy or the legacy in-gateway WAF configuration; None for any other gateway."""
    props = gateway.get("properties") or {}
    tier = (dig(props, "sku", "tier") or "").lower()
    policy = dig(props, "firewallPolicy", "id")
    legacy = props.get("webApplicationFirewallConfiguration") or {}
    if not tier.startswith("waf") or not (policy or legacy.get("enabled") is True):
        return None
    return {"id": gateway.get("id"), "name": gateway.get("name"), "type": APP_GATEWAY, "sku": dig(props, "sku", "name"),
            "waf_policy_ids": [policy] if policy else [], "legacy_waf_mode": legacy.get("firewallMode") if not policy else None,
            "category": AGW_WAF_CATEGORY}


def policy_record(raw: dict) -> dict:
    settings = dig(raw, "properties", "policySettings") or {}
    state = settings.get("enabledState") or settings.get("state")
    return {"id": raw.get("id"), "name": raw.get("name"), "mode": settings.get("mode"),
            "enabled": state.lower() == "enabled" if state else None}


def detection_mode(resource: dict, attached: list[dict]):
    """True if any policy is in Detection mode; None if a mode couldn't be read; otherwise False."""
    modes = [(p["mode"] or "").lower() for p in attached]
    if "detection" in modes:
        return True
    return None if resource["waf_policy_ids"] is None or "" in modes else False


def alert_fields(prefix: str, covering: list[dict] | None) -> dict:
    """A resource's covering alert rules and where they reach; null when the alert rules couldn't be listed."""
    if covering is None:
        return {f"{prefix}_rules": None, f"{prefix}_routes_to_receiver": None, f"{prefix}_reaches_person": None}
    return {
        f"{prefix}_rules": [r["name"] for r in covering],
        f"{prefix}_routes_to_receiver": tri_any(r["routes_to_enabled_receiver"] for r in covering) if covering else False,
        f"{prefix}_reaches_person": tri_any(r["reaches_human"] for r in covering) if covering else False,
    }


def _rows(ws: dict, key: str, rid: str) -> list[dict]:
    return [r for r in ws.get(key) or [] if (r.get("ResourceId") or "").lower() == rid]


def waf_activity(resource: dict, settings, workspaces: dict, policies: dict, alert_rules: list[dict] | None, sample: int) -> dict:
    rid = id_key(resource["id"])
    wids = exported_categories(settings, [resource["category"]])[resource["category"]]
    reads: list[dict] = []
    for wid in wids:
        ws = workspaces.get(id_key(wid)) or {}
        base = "agw_dedicated" if resource["type"] == APP_GATEWAY and dedicated(settings, wid) else (
            "fd" if resource["type"] == FRONT_DOOR else "agw")
        table = WAF_BASES[base][0]
        read = ws.get("status") == WS_NOT_FOUND or table in ws.get("read_tables", ())
        reads.append({"read": read, "requests": _rows(ws, f"{base}:requests", rid), "rules": _rows(ws, f"{base}:rules", rid)})
    # Each destination keeps its own copy, so figures come from the copy with the most events, not a sum.
    best = max(reads, key=lambda x: sum(_num(r.get("Events")) for r in x["requests"]), default=None)
    rows = best["requests"] if best else []
    events = sum(_num(r.get("Events")) for r in rows)
    if not wids:
        arriving = None
    elif events:
        arriving = True
    else:
        arriving = False if all(x["read"] for x in reads) else None
    known = arriving is not None
    per_policy: dict = defaultdict(Counter)
    modes: dict = defaultdict(set)
    for r in rows:
        name = policy_name(r.get("Policy")) or "unnamed"
        per_policy[name].update({k: _num(r.get(k)) for k in ("Events", "Requests", "RequestsBlocked", "RequestsWouldBlock",
                                                               "RequestsLoggedOnly", "RequestsAllowed", "RequestsChallenged")})
        if r.get("Mode"):
            modes[name].add(r["Mode"])
    attached = [policies.get(id_key(p)) or {"id": p, "name": basename(p), "mode": None, "enabled": None}
                for p in resource["waf_policy_ids"] or []]
    if resource.get("legacy_waf_mode"):
        attached.append({"id": None, "name": "gateway WAF configuration", "mode": resource["legacy_waf_mode"], "enabled": True})
    total: Counter = Counter()
    for c in per_policy.values():
        total.update(c)
    rules = sorted(
        ({"rule": plain_name(r.get("Rule")), "events": _num(r.get("Events")), "blocked_events": _num(r.get("Blocked"))}
         for r in (best["rules"] if best else []) if plain_name(r.get("Rule"))),
        key=lambda x: (-x["events"], x["rule"]),
    )[:sample]
    covering = None if alert_rules is None else covering_rules(alert_rules, resource["id"], wids, "watches_waf", resource["type"])
    return {
        "id": resource["id"],
        "name": resource["name"],
        "type": resource["type"],
        "sku": resource["sku"],
        "waf_policies": [{"name": p["name"], "mode": p["mode"], "enabled": p["enabled"]} for p in attached],
        "waf_policies_read": resource["waf_policy_ids"] is not None,
        "detection_mode": detection_mode(resource, attached),
        "diagnostic_settings_read": settings is not None,
        "waf_log_exported": bool(wids) if settings is not None else None,
        "waf_log_workspaces": wids,
        "waf_events": events if known else None,
        "requests_matched": total["Requests"] if known else None,
        "requests_blocked": total["RequestsBlocked"] if known else None,
        "requests_would_block": total["RequestsWouldBlock"] if known else None,
        "requests_logged_only": total["RequestsLoggedOnly"] if known else None,
        "requests_allowed": total["RequestsAllowed"] if known else None,
        "requests_challenged": total["RequestsChallenged"] if known else None,
        "activity_by_policy": [
            {"policy": name, "logged_modes": sorted(modes[name]), "events": c["Events"], "requests_matched": c["Requests"],
             "requests_blocked": c["RequestsBlocked"], "requests_would_block": c["RequestsWouldBlock"],
             "requests_logged_only": c["RequestsLoggedOnly"]}
            for name, c in sorted(per_policy.items())
        ] if known else None,
        "first_event": _earliest(r.get("FirstEvent") for r in rows) if known else None,
        "last_event": _latest(r.get("LastEvent") for r in rows) if known else None,
        "top_rules": rules if known else None,
        "waf_logs_arriving": arriving,
        **alert_fields("waf_alert", covering),
    }


# --- DDoS ---

def protection(ip: dict) -> str | None:
    mode = (dig(ip, "properties", "ddosSettings", "protectionMode") or "").lower()
    if mode == "enabled":
        return IP_PROTECTION
    if mode == "disabled":
        return DISABLED
    # Unset means inherited: protected only if the IP's virtual network has a DDoS plan (azure_ddos_protection resolves it).
    return INHERITED


def internet_facing(ip: dict) -> bool:
    props = ip.get("properties") or {}
    return bool(props.get("ipConfiguration") or props.get("natGateway"))


def attack_hours(metrics: list | None) -> int | None:
    """Hours in the window whose IfUnderDDoSAttack maximum was 1; None when the metric couldn't be read."""
    if metrics is None:
        return None
    return sum(1 for m in metrics for t in m.get("timeseries") or [] for d in t.get("data") or []
               if (d.get("maximum") or 0) >= 1)


def ddos_record(ip: dict, settings, workspaces: dict, alert_rules: list[dict] | None, metric, ddos_read: dict) -> dict:
    rid = id_key(ip.get("id"))
    mode = protection(ip)
    known_on = True if mode == IP_PROTECTION else None
    exports = exported_categories(settings, DDOS_CATEGORIES)
    wids = sorted({w for ws in exports.values() for w in ws}, key=id_key)
    rows = [r for w in wids for r in _rows(workspaces.get(id_key(w)) or {}, "ddos", rid)]
    read_all = bool(wids) and all(ddos_read.get(id_key(w)) for w in wids)
    records = max((_num(r.get("Notifications")) + _num(r.get("Reports")) + _num(r.get("FlowLogRecords")) for r in rows), default=0)
    best = max(rows, key=lambda r: _num(r.get("Notifications")) + _num(r.get("Reports")), default={})
    hours = attack_hours(metric)
    covering = None if alert_rules is None else covering_rules(alert_rules, ip.get("id") or "", wids, "watches_ddos_attack")
    alerts = alert_fields("attack_alert", covering)
    # Without DDoS Protection Azure records no mitigations and the attack metric stays 0, so a zero there proves nothing.
    zero_means_none = known_on is True
    return {
        "id": ip.get("id"),
        "name": ip.get("name"),
        "ip_address_present": bool(dig(ip, "properties", "ipAddress")),
        "attached": internet_facing(ip),
        "protection_mode": dig(ip, "properties", "ddosSettings", "protectionMode"),
        "protection": mode,
        "ddos_protection_known_on": known_on,
        "diagnostic_settings_read": settings is not None,
        "ddos_log_categories_exported": sorted(c for c, ws in exports.items() if ws) if settings is not None else None,
        "ddos_logs_exported": all(exports[c] for c in DDOS_CATEGORIES) if settings is not None else None,
        **alerts,
        "attack_alert_can_fire": alerts["attack_alert_routes_to_receiver"] if zero_means_none else None,
        "attack_hours": hours if hours or (zero_means_none and hours is not None) else None,
        "mitigations_started": _num(best.get("MitigationsStarted")) if records or (zero_means_none and read_all) else None,
        "mitigation_reports": _num(best.get("Reports")) if records or (zero_means_none and read_all) else None,
        "last_ddos_event": _latest(r.get("LastEvent") for r in rows),
    }


# --- summary ---

def _total(values):
    values = list(values)
    return None if any(v is None for v in values) else sum(values)


def _count(items, field, value) -> int:
    return sum(1 for i in items if i[field] is value)


def summarize(waf: list[dict], ips: list[dict], rules: list[dict] | None, workspaces: list[dict], days: int,
              fd_without_waf: int, total_ips: int) -> dict:
    exporting = [w for w in waf if w["waf_log_exported"]]
    status = Counter(w["status"] for w in workspaces)
    facing = [i for i in ips if i["attached"]]
    protected = [i for i in facing if i["ddos_protection_known_on"]]
    last = _latest(w["last_event"] for w in waf)

    def alerts(count):
        """An alert figure, or null when the alert rules couldn't be listed."""
        return None if rules is None else count()

    return {
        "lookback_days": days,
        "waf_resources": len(waf),
        "front_door_waf_resources": sum(1 for w in waf if w["type"] == FRONT_DOOR),
        "app_gateway_waf_resources": sum(1 for w in waf if w["type"] == APP_GATEWAY),
        "front_door_profiles_without_waf": fd_without_waf,
        "waf_resources_in_detection_mode": _count(waf, "detection_mode", True),
        "waf_resources_mode_unknown": _count(waf, "detection_mode", None),
        "waf_resources_exporting_waf_log": len(exporting),
        "waf_resources_without_waf_log_export": _count(waf, "waf_log_exported", False),
        "waf_resources_with_waf_events": _count(exporting, "waf_logs_arriving", True),
        "waf_resources_without_waf_events": _count(exporting, "waf_logs_arriving", False),
        "waf_resources_waf_log_unknown": _count(exporting, "waf_logs_arriving", None),
        "waf_events": _total(w["waf_events"] for w in exporting),
        "waf_requests_matched": _total(w["requests_matched"] for w in exporting),
        "waf_requests_blocked": _total(w["requests_blocked"] for w in exporting),
        "waf_requests_would_block": _total(w["requests_would_block"] for w in exporting),
        "waf_requests_logged_only": _total(w["requests_logged_only"] for w in exporting),
        "last_waf_event": last,
        "waf_alert_rules": alerts(lambda: sum(1 for r in rules or [] if r["watches_waf"])),
        "waf_alert_rules_enabled": alerts(lambda: sum(1 for r in rules or [] if r["watches_waf"] and r["enabled"])),
        "waf_alert_rules_reaching_person": alerts(lambda: sum(1 for r in rules or [] if r["watches_waf"] and r["reaches_human"] is True)),
        "waf_resources_with_alert_reaching_person": alerts(lambda: _count(waf, "waf_alert_reaches_person", True)),
        "waf_resources_without_waf_alert": alerts(lambda: sum(1 for w in waf if not w["waf_alert_rules"])),
        "public_ips": total_ips,
        "internet_facing_public_ips": len(facing),
        "public_ips_with_ip_protection": len(protected),
        "public_ips_protection_disabled": sum(1 for i in facing if i["protection"] == DISABLED),
        "public_ips_protection_inherited": sum(1 for i in facing if i["protection"] == INHERITED),
        "public_ips_exporting_ddos_logs": _count(facing, "ddos_logs_exported", True),
        "public_ips_with_attack_alert": alerts(lambda: sum(1 for i in facing if i["attack_alert_rules"])),
        "public_ips_with_attack_alert_reaching_person": alerts(lambda: _count(facing, "attack_alert_reaches_person", True)),
        "protected_ips_with_attack_alert_reaching_receiver":
            alerts(lambda: _count(protected, "attack_alert_can_fire", True)) if protected else None,
        "protected_ips_without_attack_alert":
            alerts(lambda: sum(1 for i in protected if not i["attack_alert_rules"])) if protected else None,
        "ddos_attack_alert_rules": alerts(lambda: sum(1 for r in rules or [] if r["watches_ddos_attack"])),
        "public_ips_attacked": sum(1 for i in facing if i["attack_hours"]) if protected or any(i["attack_hours"] for i in facing) else None,
        "ddos_mitigations_started": _total(i["mitigations_started"] for i in protected) if protected else None,
        "log_workspaces": len(workspaces),
        "log_workspaces_queried": status[WS_QUERIED],
        "log_workspaces_not_authorized": status[WS_NOT_AUTHORIZED],
        "log_workspaces_not_found": status[WS_NOT_FOUND],
    }


# --- collection ---

def _provider_read(client, path: str, api: str, operation: str, collector) -> list | None:
    """None when the list failed; a resource provider the subscription never registered has none of its resources."""
    def _list():
        try:
            return client.list(path, api)
        except ArmError as exc:
            if exc.code.lower() == "missingsubscriptionregistration":
                return []
            raise
    return collector.guard(operation, _list)


def _provider_list(client, path: str, api: str, operation: str, collector) -> list:
    return _provider_read(client, path, api, operation, collector) or []


def _settings(client, resource_id: str, collector):
    return collector.guard(
        f"insights.diagnosticSettings.list({resource_id})",
        lambda: client.list(f"{resource_id}/providers/Microsoft.Insights/diagnosticSettings", DIAG_API),
    )


def _optional(client, path: str, api: str):
    try:
        return client.get(path, api)
    except ArmError as exc:
        if exc.status == 404:
            return None
        raise


def _error_text(exc: BaseException) -> str:
    return " ".join(str(exc).split())[:300]


def _unread(out: dict, workspace_id: str, exc: BaseException, collector) -> dict:
    status = ws_status(exc)
    if status == WS_ERROR:
        collector.record(f"loganalytics.read({workspace_id})", exc)
    else:
        logger.warning("Log Analytics workspace %s: %s (%s)", workspace_id, status, exc)
    return {**out, "status": status, "error": _error_text(exc), "read_tables": []}


def read_workspace(client, workspace_id: str, jobs: list[tuple], basic: bool, days: int, collector) -> dict:
    """jobs: (table, key, kql). A refusal leaves the workspace unread; another failure only that query."""
    out: dict = {"workspace_id": workspace_id, "name": basename(workspace_id), "status": WS_QUERIED, "error": None,
                 "tables": [], "read_tables": [], "skipped_tables": [], "failed_queries": []}
    try:
        customer_id = dig(client.get(workspace_id, LAW_API), "properties", "customerId")
        if not customer_id:
            raise LookupError(f"no customerId on workspace {workspace_id}")
        out["tables"] = [table_record(t, _optional(client, f"{workspace_id}/tables/{t}", LAW_API))
                         for t in sorted({j[0] for j in jobs})]
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        return _unread(out, workspace_id, exc, collector)
    info = {t["name"]: t for t in out["tables"]}
    unread = set()
    for table, key, kql in jobs:
        meta = info[table]
        if not meta["exists"]:
            out[key] = []
            continue
        if not analytics_plan(meta) and not basic:
            continue
        runner = client.query if analytics_plan(meta) else client.search
        try:
            out[key] = runner(customer_id, kql, iso_duration_days(days))
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


def collect_alert_rules(client, subscription_id: str, collector) -> list[dict] | None:
    """The WAF and DDoS alert rules; None when either rule list couldn't be read."""
    base = f"/subscriptions/{subscription_id}/providers"
    metric = _provider_read(client, f"{base}/Microsoft.Insights/metricAlerts", METRIC_ALERT_API,
                            "insights.metricAlerts.list", collector)
    logs = _provider_read(client, f"{base}/Microsoft.Insights/scheduledQueryRules", LOG_ALERT_API,
                          "insights.scheduledQueryRules.list", collector)
    if metric is None or logs is None:
        return None
    rules = [alert_rule_record("metric", r) for r in metric] + [alert_rule_record("log_search", r) for r in logs]
    rules = [r for r in rules if r["watches_waf"] or r["watches_ddos_attack"]]
    if not rules:
        return []
    groups = {id_key(g["id"]): g for g in (action_group_record(g) for g in _provider_list(
        client, f"{base}/Microsoft.Insights/actionGroups", ACTION_GROUP_API, "insights.actionGroups.list", collector))}
    now = datetime.now(timezone.utc)
    processing = [processing_rule_record(r, now) for r in _provider_list(
        client, f"{base}/Microsoft.AlertsManagement/actionRules", PROCESSING_RULE_API, "alertsManagement.actionRules.list", collector)]
    for gid in sorted({g for r in rules for g in r["action_group_ids"]} | {g for p in processing for g in p["added_action_group_ids"]},
                      key=str.lower):
        if id_key(gid) in groups or not ACTION_GROUP_ID.match(gid):
            continue
        try:
            groups[id_key(gid)] = action_group_record(client.get(gid, ACTION_GROUP_API))
        except ArmError as exc:
            # A group in a subscription the credential can't read stays unresolved.
            if exc.status not in (403, 404):
                collector.record(f"insights.actionGroups.get({gid})", exc)
    return sorted(({**routed(r, groups, processing), "_scopes": r["scopes"]} for r in rules), key=lambda r: id_key(r["id"]))


def collect(client, subscription_id: str, collector) -> tuple:
    days = lookback_days()
    sample = int_config(SAMPLE_ENV, DEFAULT_SAMPLE_SIZE)
    basic = flag(BASIC_ENV)
    fmt = {"days": days, "subscription_id": subscription_id, "sample": sample}
    base = f"/subscriptions/{subscription_id}/providers"

    profiles = [p for p in _provider_list(client, f"{base}/Microsoft.Cdn/profiles", CDN_API, "cdn.profiles.list", collector)
                if (dig(p, "sku", "name") or "").lower() in FRONT_DOOR_SKUS]
    fd_resources = [
        front_door_waf_resource(p, collector.guard(f"cdn.securityPolicies.list({p.get('name')})",
                                                   lambda p=p: client.list(f"{p['id']}/securityPolicies", CDN_API)))
        for p in profiles
    ]
    gateways = _provider_list(client, f"{base}/Microsoft.Network/applicationGateways", NETWORK_API,
                              "network.applicationGateways.list", collector)
    agw_resources = [r for r in (gateway_waf_resource(g) for g in gateways) if r]
    waf_resources = [r for r in fd_resources if r["waf_policy_ids"] is None or r["waf_policy_ids"]] + agw_resources
    fd_without_waf = sum(1 for r in fd_resources if r["waf_policy_ids"] == [])
    policies = {}
    if any(r["type"] == FRONT_DOOR for r in waf_resources):
        policies.update({id_key(p["id"]): policy_record(p) for p in _provider_list(
            client, f"{base}/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies", FD_WAF_API,
            "network.frontDoorWebApplicationFirewallPolicies.list", collector)})
    if agw_resources:
        policies.update({id_key(p["id"]): policy_record(p) for p in _provider_list(
            client, f"{base}/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies", NETWORK_API,
            "network.applicationGatewayWebApplicationFirewallPolicies.list", collector)})

    ips = _provider_list(client, f"{base}/Microsoft.Network/publicIPAddresses", NETWORK_API, "network.publicIPAddresses.list",
                         collector)
    facing = [ip for ip in ips if internet_facing(ip)]
    waf_settings = {id_key(r["id"]): _settings(client, r["id"], collector) for r in waf_resources}
    ip_settings = {id_key(ip["id"]): _settings(client, ip["id"], collector) for ip in facing}
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    timespan = f"{(end - timedelta(days=min(days, MAX_METRIC_DAYS))).isoformat()}/{end.isoformat()}".replace("+00:00", "Z")
    metrics = {id_key(ip["id"]): _metric(client, ip["id"], timespan, collector) for ip in facing}
    alert_rules = collect_alert_rules(client, subscription_id, collector)

    jobs: dict = defaultdict(list)
    workspace_ids: dict = {}

    def add(wid, table, key, kql):
        workspace_ids.setdefault(id_key(wid), wid)
        if not any(j[1] == key for j in jobs[id_key(wid)]):
            jobs[id_key(wid)].append((table, key, kql))

    for r in waf_resources:
        settings = waf_settings[id_key(r["id"])]
        for wid in exported_categories(settings, [r["category"]])[r["category"]]:
            name = "fd" if r["type"] == FRONT_DOOR else ("agw_dedicated" if dedicated(settings, wid) else "agw")
            table, kql_base = WAF_BASES[name]
            for key, tail in WAF_QUERIES.items():
                add(wid, table, f"{name}:{key}", (kql_base + tail).format(**fmt))
    for ip in facing:
        exports = exported_categories(ip_settings[id_key(ip["id"])], DDOS_CATEGORIES)
        for wid in {w for ws in exports.values() for w in ws}:
            add(wid, DIAG_TABLE, "ddos", DDOS_QUERY.format(**fmt))

    workspaces = {k: read_workspace(client, workspace_ids[k], jobs[k], basic, days, collector) for k in sorted(jobs)}
    ddos_read = {k: ws["status"] == WS_NOT_FOUND or DIAG_TABLE in ws["read_tables"] for k, ws in workspaces.items()}

    waf_records = sorted(
        (waf_activity(r, waf_settings[id_key(r["id"])], workspaces, policies, alert_rules, sample) for r in waf_resources),
        key=lambda w: id_key(w["id"]),
    )
    ip_records = sorted(
        (ddos_record(ip, ip_settings.get(id_key(ip["id"])), workspaces, alert_rules, metrics.get(id_key(ip["id"])), ddos_read)
         for ip in facing),
        key=lambda i: id_key(i["id"]),
    )
    rule_records = None if alert_rules is None else [{k: v for k, v in r.items() if k != "_scopes"} for r in alert_rules]
    workspace_records = [
        {k: ws[k] for k in ("workspace_id", "name", "status", "error", "tables", "read_tables", "skipped_tables", "failed_queries")}
        for ws in workspaces.values()
    ]
    results = {
        "lookback_days": days,
        "sample_size": sample,
        "query_basic_tables": basic,
        "waf_resources": waf_records,
        "public_ips": ip_records,
        "public_ips_not_attached": len(ips) - len(facing),
        "alert_rules": rule_records,
        "workspaces": workspace_records,
        "queries": filled_queries(fmt),
        "metric_timespan": timespan,
    }
    return results, summarize(waf_records, ip_records, rule_records, workspace_records, days, fd_without_waf, len(ips))


def _metric(client, resource_id: str, timespan: str, collector):
    """The attack metric's hourly maximum; an IP the metric doesn't cover or the credential can't read stays unknown."""
    params = {"timespan": timespan, "interval": "PT1H", "metricnames": ATTACK_METRIC, "aggregation": "Maximum"}
    try:
        return client.list(f"{resource_id}/providers/Microsoft.Insights/metrics", METRICS_API, params=params)
    except ArmError as exc:
        if exc.status in (400, 403, 404):
            logger.warning("%s metric for %s: %s", ATTACK_METRIC, basename(resource_id), exc.code)
            return None
        collector.record(f"insights.metrics.list({basename(resource_id)})", exc)
    except Exception as exc:  # noqa: BLE001 — recorded, the run goes on
        collector.record(f"insights.metrics.list({basename(resource_id)})", exc)
    return None


def filled_queries(fmt: dict) -> dict:
    out = {f"{name}:{key}": (base + tail).format(**fmt) for name, (_, base) in WAF_BASES.items() for key, tail in WAF_QUERIES.items()}
    out["ddos"] = DDOS_QUERY.format(**fmt)
    return out


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
