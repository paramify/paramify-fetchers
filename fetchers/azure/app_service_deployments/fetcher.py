#!/usr/bin/env python3
"""Azure App Service deployments per web app and slot: Kudu history, Activity Log deployment events, source, slot drift."""

import logging
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_service import is_web_app, web_client  # noqa: E402
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_id_key,
    basename,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    get_optional,
    model_attr,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)

logger = logging.getLogger("azure_app_service_deployments")

# Kudu's DeployStatus enum; the API returns the integer.
DEPLOY_STATUS = {0: "Pending", 1: "Building", 2: "Deploying", 3: "Failed", 4: "Success"}
HISTORY_LIMIT = 50
ACTIVITY_LIMIT = 100
# Kudu's author and message are free text from the commit or client; a long one is cut, not copied whole.
MAX_TEXT = 500

# The Activity Log keeps 90 days; a read past this many events is cut and says so.
ACTIVITY_LOG_MAX_DAYS = 90
# The window starts this far inside retention, so its oldest edge is still served.
ACTIVITY_LOG_RETENTION_MARGIN = timedelta(minutes=5)
ACTIVITY_LOG_MAX_EVENTS = 200_000
# No $select: the documented list omits `caller`, so selecting could drop or reject the requester.

ACTIVITY_OPERATIONS = {
    "microsoft.web/sites/slotsswap/action": "slot_swaps",
    "microsoft.web/sites/slots/slotsswap/action": "slot_swaps",
    "microsoft.web/sites/publishxml/action": "publish_profile_downloads",
    "microsoft.web/sites/slots/publishxml/action": "publish_profile_downloads",
    "microsoft.web/sites/config/list/action": "publishing_credential_reads",
    "microsoft.web/sites/slots/config/list/action": "publishing_credential_reads",
    "microsoft.web/sites/extensions/write": "package_deployments",
    "microsoft.web/sites/slots/extensions/write": "package_deployments",
}
ACTIVITY_CATEGORIES = ("slot_swaps", "publish_profile_downloads", "publishing_credential_reads", "package_deployments")
PACKAGE_EXTENSIONS = ("msdeploy", "onedeploy", "zipdeploy")
# config/list also reads app settings and connection strings; only this resource is a credentials read.
PUBLISHING_CREDENTIALS_RESOURCE = "/config/publishingcredentials"
SITE_RESOURCE = re.compile(
    r"^(/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+)(?:/slots/([^/]+))?(/.*)?$"
)
# A swap logs the request (the caller's) and the platform's own events under one correlation id.
STATUS_PRECEDENCE = ("Failed", "Succeeded", "Accepted", "Started")
FINAL_STATUSES = {"Failed", "Succeeded"}

# config/web fields compared slot to production, plus the Site fields after them.
COMPARED_CONFIG_FIELDS = (
    "min_tls_version",
    "scm_min_tls_version",
    "min_tls_cipher_suite",
    "ftps_state",
    "http20_enabled",
    "remote_debugging_enabled",
    "linux_fx_version",
    "windows_fx_version",
    "net_framework_version",
    "java_version",
    "java_container",
    "java_container_version",
    "php_version",
    "python_version",
    "node_version",
    "ip_security_restrictions",
    "ip_security_restrictions_default_action",
    "scm_ip_security_restrictions",
    "scm_ip_security_restrictions_default_action",
    "scm_ip_security_restrictions_use_main",
)
BOOLEAN_FIELDS = ("http20_enabled", "remote_debugging_enabled", "scm_ip_security_restrictions_use_main",
                  "https_only", "client_cert_enabled")
COMPARED_SITE_FIELDS = ("https_only", "client_cert_enabled", "public_network_access")
RULE_FIELDS = ("action", "priority", "ip_address", "subnet_mask", "vnet_subnet_resource_id", "tag", "headers")

LIMITATIONS = [
    "Kudu deployment records (GET sites/{name}/deployments) exist for zip deploy, OneDeploy, local Git "
    "and source-control (GitHub, Azure Repos, Bitbucket) deployments. Web Deploy (MSDeploy, including "
    "Visual Studio publish), FTP/FTPS, a changed WEBSITE_RUN_FROM_PACKAGE URL and container image pulls "
    "create none, so an empty Kudu history does not mean no deployments.",
    "A Kudu record's author and message come from the commit or the deploying client; a push from a "
    "pipeline often names the tool, not a person. Kudu keeps a bounded history; the newest "
    f"{HISTORY_LIMIT} records per app or slot are kept, with the full count. An author or message longer than "
    f"{MAX_TEXT} characters is cut and marked as truncated.",
    "Activity Log events are control-plane requests, kept 90 days. A slot swap names who requested it, "
    "when and on which slot; the slot it swapped with is not logged. A publish-profile download (publishxml) "
    "or a publishing-credentials read (config/publishingcredentials/list) names who obtained the shared Web "
    "Deploy, FTP and Kudu credentials, not whether or when they were used. ListPublishingCredentials events, "
    "which the platform logs with no caller, identity type or app id, are not counted.",
    "Web Deploy, FTP and Kudu uploads made with those credentials go to the app's deployment endpoints, not "
    "Azure Resource Manager, so they leave no Activity Log entry: what content they shipped, which commit "
    "it was, and who uploaded it are not visible here. Whether basic-auth publishing is switched off, which "
    "removes those shared credentials, is reported by azure_app_service_configuration. Nothing older than "
    "the Activity Log window is seen.",
    "Microsoft lists runtime versions as swapped; HTTPS-only, TLS, client certificates and access restrictions "
    "stay with the slot. matches_production is posture parity between a slot and production, not what "
    "production runs after a swap.",
]


# --- projection: the only azure-mgmt model access ---

def project_site(site) -> dict:
    return {
        "id": model_attr(site, "id"),
        "name": model_attr(site, "name"),
        "kind": model_attr(site, "kind"),
        "location": model_attr(site, "location"),
        "state": model_attr(site, "state"),
        "https_only": model_attr(site, "https_only"),
        "client_cert_enabled": model_attr(site, "client_cert_enabled"),
        "public_network_access": model_attr(site, "public_network_access"),
    }


def project_deployment(deployment) -> dict:
    return {
        "id": model_attr(deployment, "id"),
        "name": model_attr(deployment, "name"),
        "status": model_attr(deployment, "status"),
        "active": model_attr(deployment, "active"),
        "author": model_attr(deployment, "author"),
        "deployer": model_attr(deployment, "deployer"),
        "message": model_attr(deployment, "message"),
        "start_time": model_attr(deployment, "start_time"),
        "end_time": model_attr(deployment, "end_time"),
    }


def project_source_control(source) -> dict:
    return {
        "repo_url": model_attr(source, "repo_url"),
        "branch": model_attr(source, "branch"),
        "is_manual_integration": model_attr(source, "is_manual_integration"),
        "is_git_hub_action": model_attr(source, "is_git_hub_action"),
        "deployment_rollback_enabled": model_attr(source, "deployment_rollback_enabled"),
    }


def project_rule(rule) -> dict:
    return {field: model_attr(rule, field) for field in RULE_FIELDS}


def project_site_config(config) -> dict:
    projected = {field: model_attr(config, field) for field in COMPARED_CONFIG_FIELDS}
    for field in ("ip_security_restrictions", "scm_ip_security_restrictions"):
        projected[field] = [project_rule(r) for r in (projected[field] or [])]
    return projected


def project_event(event) -> dict:
    """Read an Activity Log `EventData`; of its claims only the identity type is kept."""
    claims = model_attr(event, "claims") or {}
    return {
        "operation": model_attr(model_attr(event, "operation_name"), "value"),
        "status": model_attr(model_attr(event, "status"), "value"),
        "caller": model_attr(event, "caller"),
        "caller_type": claims.get("idtyp") if isinstance(claims, dict) else None,
        "resource_id": model_attr(event, "resource_id"),
        "correlation_id": model_attr(event, "correlation_id"),
        "event_id": model_attr(event, "event_data_id"),
        "time": _iso(model_attr(event, "event_timestamp")),
    }


# --- pure transforms ---

def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def capped(text):
    if not isinstance(text, str) or len(text) <= MAX_TEXT:
        return text
    return f"{text[:MAX_TEXT]}… [truncated from {len(text)} characters]"


def redact_url(url):
    """Drop any user:password a repository URL carries."""
    if not url:
        return url
    parts = urlsplit(str(url))
    if "@" not in parts.netloc:
        return url
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))


def deployment_record(deployment: dict) -> dict:
    status = deployment.get("status")
    return {
        "deployment_id": basename(deployment.get("name") or deployment.get("id")),
        "status": DEPLOY_STATUS.get(status, None if status is None else str(status)),
        "active": bool(deployment.get("active") or False),
        "author": capped(deployment.get("author")),
        "deployer": deployment.get("deployer"),
        "message": capped(deployment.get("message")),
        "start_time": _iso(deployment.get("start_time")),
        "end_time": _iso(deployment.get("end_time")),
    }


def deployment_history(deployments: list[dict]) -> dict:
    records = sorted(
        (deployment_record(d) for d in deployments),
        key=lambda r: r["start_time"] or r["end_time"] or "",
        reverse=True,
    )
    return {
        "count": len(records),
        "by_status": sorted_counts(Counter(r["status"] or "unknown" for r in records)),
        "by_deployer": sorted_counts(Counter(r["deployer"] or "unknown" for r in records)),
        "latest": records[0] if records else None,
        "active": next((r for r in records if r["active"]), None),
        "records": records[:HISTORY_LIMIT],
    }


def source_control_record(source, found) -> dict | None:
    """`found` is get_optional's: False on a 404 (none set up), None when the read failed."""
    if found is None:
        return None
    source = source or {}
    repo_url = redact_url(source.get("repo_url"))
    return {
        "configured": bool(repo_url),
        "repo_url": repo_url,
        "branch": source.get("branch"),
        "is_manual_integration": bool(source.get("is_manual_integration") or False),
        "is_git_hub_action": bool(source.get("is_git_hub_action") or False),
        "deployment_rollback_enabled": bool(source.get("deployment_rollback_enabled") or False),
    }


def _comparable(field, value):
    if field in BOOLEAN_FIELDS:
        return bool(value or False)
    if field.endswith("ip_security_restrictions"):
        return sorted(
            ({k: rule.get(k) for k in RULE_FIELDS} for rule in (value or [])),
            key=lambda r: (r["priority"] if isinstance(r["priority"], int) else 1 << 31, str(r)),
        )
    return value or None


def configuration_differences(prod_site: dict, prod_config, slot_site: dict, slot_config) -> list | None:
    """Fields where the slot differs from production; None when either config/web read failed."""
    if prod_config is None or slot_config is None:
        return None
    differences = []
    pairs = [(f, prod_config.get(f), slot_config.get(f)) for f in COMPARED_CONFIG_FIELDS]
    pairs += [(f, prod_site.get(f), slot_site.get(f)) for f in COMPARED_SITE_FIELDS]
    for field, production, slot in pairs:
        production, slot = _comparable(field, production), _comparable(field, slot)
        if production != slot:
            differences.append({"field": field, "production": production, "slot": slot})
    return differences


def site_of(resource_id):
    """(site id key, slot name or None, the path below the site) for a Microsoft.Web/sites resource id."""
    match = SITE_RESOURCE.match(arm_id_key(resource_id))
    return (match.group(1), match.group(2), match.group(3) or "") if match else (None, None, "")


def activity_category(event: dict):
    category = ACTIVITY_OPERATIONS.get(str(event.get("operation") or "").lower())
    _, _, below = site_of(event.get("resource_id"))
    if category == "package_deployments" and below.rsplit("/", 1)[-1] not in PACKAGE_EXTENSIONS:
        return None
    if category == "publishing_credential_reads" and below != PUBLISHING_CREDENTIALS_RESOURCE:
        return None
    return category


def _named(event: dict) -> bool:
    """The event names who made the request: an identity type, or a user name as the caller."""
    return bool(event.get("caller_type")) or "@" in str(event.get("caller") or "")


def _requester(events: list[dict]) -> tuple:
    """The request's own event and identity type: one with an identity type, else one whose caller is a user name."""
    for event in events:
        if event.get("caller_type"):
            return event, event["caller_type"]
    for event in events:
        if "@" in str(event.get("caller") or ""):
            return event, "user"
    return next((e for e in events if e.get("caller")), events[0]), "unknown"


def _requests(events: list[dict]) -> list[tuple]:
    """(category, every event, the events naming the requester) per request: one correlation id, any site."""
    grouped: dict = defaultdict(list)
    for event in events:
        category = activity_category(event)
        if category and site_of(event.get("resource_id"))[0]:
            grouped[(category, event.get("correlation_id") or event.get("event_id"))].append(event)
    requests = []
    for (category, _), group in grouped.items():
        group.sort(key=lambda e: e.get("time") or "")
        named = [e for e in group if _named(e)]
        if named:
            requests.append((category, group, named))
            continue
        # Unnamed platform rows reuse unrelated correlation ids, so on their own they stay with their site.
        by_site: dict = defaultdict(list)
        for event in group:
            by_site[site_of(event.get("resource_id"))[:2]].append(event)
        requests.extend((category, rows, rows) for rows in by_site.values())
    return requests


def activity_records(events: list[dict]) -> dict:
    """{(site key, slot): {category: [records]}}, one record per request, on the site of the event naming the requester."""
    by_site: dict = defaultdict(lambda: {c: [] for c in ACTIVITY_CATEGORIES})
    for category, group, named in _requests(events):
        requester, caller_type = _requester(named)
        own = {e.get("status") for e in named}
        # A request that finished keeps its own status; a platform row sharing its correlation id can't flip it.
        statuses = own if own & FINAL_STATUSES else {e.get("status") for e in group}
        site, slot, _ = site_of(requester.get("resource_id"))
        by_site[(site, slot)][category].append({
            "time": min((e["time"] for e in named if e.get("time")), default=None),
            "status": next((s for s in STATUS_PRECEDENCE if s in statuses), None),
            "caller": requester.get("caller"),
            "caller_type": caller_type,
            "correlation_id": requester.get("correlation_id"),
        })
    return by_site


def activity_summary(records_by_category: dict) -> dict:
    out = {}
    for category in ACTIVITY_CATEGORIES:
        records = sorted(records_by_category.get(category, []), key=lambda r: r["time"] or "", reverse=True)
        out[category] = {
            "count": len(records),
            "failed": sum(1 for r in records if r["status"] == "Failed"),
            "by_caller_type": sorted_counts(Counter(r["caller_type"] for r in records)),
            "latest": records[0] if records else None,
            "records": records[:ACTIVITY_LIMIT],
        }
    return out


def attach_activity(apps: list[dict], events: list[dict] | None) -> dict | None:
    """Fill each app's and slot's `activity` (None when the Activity Log could not be read).

    Returns the requests on sites not listed (deleted apps or slots, function apps), by category.
    """
    if events is None:
        return None
    by_site = activity_records(events)
    for app in apps:
        key = arm_id_key(app["id"])
        app["activity"] = activity_summary(by_site.pop((key, None), {}))
        for slot in app.get("slots") or []:
            slot["activity"] = activity_summary(by_site.pop((key, str(slot["name"]).lower()), {}))
    return {c: sum(len(records.get(c, [])) for records in by_site.values()) for c in ACTIVITY_CATEGORIES}


def slot_name(site: dict):
    return basename(site.get("name"))


def _sites(app: dict) -> list[dict]:
    return [app] + list(app.get("slots") or [])


def all_histories(app: dict) -> list[dict]:
    return [s["kudu_deployments"] for s in _sites(app) if s.get("kudu_deployments")]


def history_read(app: dict) -> bool:
    """Every Kudu history read for the app and its slots succeeded, the slot list included."""
    return app.get("slots") is not None and all(s.get("kudu_deployments") is not None for s in _sites(app))


def activity_count(app: dict, category: str) -> int:
    return sum(dig_count(s, category) for s in _sites(app))


def dig_count(site: dict, category: str) -> int:
    return ((site.get("activity") or {}).get(category) or {}).get("count", 0)


def activity_read(window: dict) -> bool:
    """Events were read: the whole window, or the newest events up to the cap."""
    return window.get("complete") is True or window.get("cut_reason") == "max_events"


def has_deployment_evidence(app: dict) -> bool:
    return any(h["count"] for h in all_histories(app)) or any(
        activity_count(app, c) for c in ACTIVITY_CATEGORIES
    )


def summarize(apps: list[dict], excluded_function_apps: int, window: dict) -> dict:
    slots = [s for a in apps for s in (a.get("slots") or [])]
    histories = [h for a in apps for h in all_histories(a)]
    deployers: Counter = Counter()
    for history in histories:
        deployers.update(history["by_deployer"])
    latest = [h["latest"] for h in histories if h["latest"]]
    caller_types: Counter = Counter()
    for site in (s for a in apps for s in _sites(a)):
        for category in ACTIVITY_CATEGORIES:
            caller_types.update(((site.get("activity") or {}).get(category) or {}).get("by_caller_type", {}))
    swaps = [s["activity"]["slot_swaps"]["latest"] for a in apps for s in _sites(a)
             if s.get("activity") and s["activity"]["slot_swaps"]["latest"]]
    complete = window.get("complete") is True
    read = activity_read(window)
    unlisted = window.get("requests_on_unlisted_sites")
    no_kudu = [a for a in apps if not any(h["count"] for h in all_histories(a))]

    def if_read(value):
        return value if read else None

    return {
        "total_web_apps": len(apps),
        "total_deployment_slots": len(slots),
        "excluded_function_apps": excluded_function_apps,
        "apps_with_slots": sum(1 for a in apps if a.get("slots")),
        # --- deployment source ---
        "apps_with_source_control": sum(1 for a in apps if (a.get("source_control") or {}).get("configured")),
        "apps_deploying_from_github_actions": sum(
            1 for a in apps if (a.get("source_control") or {}).get("is_git_hub_action")
        ),
        "slots_with_source_control": sum(1 for s in slots if (s.get("source_control") or {}).get("configured")),
        "apps_source_control_unknown": sum(1 for a in apps if a.get("source_control") is None),
        "slots_source_control_unknown": sum(1 for s in slots if s.get("source_control") is None),
        # --- Kudu deployment records ---
        "apps_with_kudu_deployment_records": len(apps) - len(no_kudu),
        "apps_without_kudu_deployment_records": sum(1 for a in no_kudu if history_read(a)),
        "apps_kudu_deployment_records_unknown": sum(1 for a in no_kudu if not history_read(a)),
        "kudu_deployment_records": sum(h["count"] for h in histories),
        "failed_kudu_deployment_records": sum(h["by_status"].get("Failed", 0) for h in histories),
        "kudu_deployments_by_deployer": sorted_counts(deployers),
        "latest_kudu_deployment_time": max(
            (r["end_time"] or r["start_time"] for r in latest if r["end_time"] or r["start_time"]), default=None
        ),
        # --- Activity Log ---
        "activity_log_days": window.get("days"),
        "activity_log_complete": complete,
        "slot_swaps": if_read(sum(activity_count(a, "slot_swaps") for a in apps)),
        "failed_slot_swaps": if_read(sum(
            ((s.get("activity") or {}).get("slot_swaps") or {}).get("failed", 0) for a in apps for s in _sites(a)
        )),
        "apps_with_slot_swaps": if_read(sum(1 for a in apps if activity_count(a, "slot_swaps"))),
        "latest_slot_swap_time": max((r["time"] for r in swaps if r["time"]), default=None),
        "publish_profile_downloads": if_read(sum(activity_count(a, "publish_profile_downloads") for a in apps)),
        "apps_with_publish_profile_downloads": if_read(sum(
            1 for a in apps if activity_count(a, "publish_profile_downloads")
        )),
        "publishing_credential_reads": if_read(sum(activity_count(a, "publishing_credential_reads") for a in apps)),
        "apps_with_publishing_credential_reads": if_read(sum(
            1 for a in apps if activity_count(a, "publishing_credential_reads")
        )),
        "package_deployments": if_read(sum(activity_count(a, "package_deployments") for a in apps)),
        "apps_with_package_deployments": if_read(sum(1 for a in apps if activity_count(a, "package_deployments"))),
        "deployment_activity_by_caller_type": if_read(sorted_counts(caller_types)),
        "deployment_activity_on_unlisted_sites": sum(unlisted.values()) if read and unlisted is not None else None,
        # --- any deployment evidence ---
        "apps_with_deployment_evidence": sum(1 for a in apps if has_deployment_evidence(a)),
        "apps_without_deployment_evidence": sum(
            1 for a in apps if not has_deployment_evidence(a) and history_read(a)
        ) if complete else None,
        # --- slots vs production ---
        "slots_matching_production": sum(1 for s in slots if s.get("matches_production") is True),
        "slots_differing_from_production": sum(1 for s in slots if s.get("matches_production") is False),
        "slots_comparison_unknown": sum(1 for s in slots if s.get("matches_production") is None),
    }


# --- collection ---

def _history(collector, operation, fn):
    deployments = collector.guard(operation, lambda: [project_deployment(d) for d in fn()])
    return None if deployments is None else deployment_history(deployments)


def _source_control(collector, operation, fn):
    source, found = get_optional(collector, operation, lambda: project_source_control(fn()))
    return source_control_record(source, found)


def collect_app(client, collector: Collector, app_site: dict) -> dict:
    group, name = resource_group_from_id(app_site["id"]), app_site["name"]
    web_apps = client.web_apps
    record = {
        "id": app_site["id"],
        "name": name,
        "resource_group": group,
        "kind": app_site.get("kind"),
        "location": app_site.get("location"),
        "state": app_site.get("state"),
        "source_control": _source_control(
            collector, f"web.web_apps.get_source_control ({name})",
            lambda: web_apps.get_source_control(resource_group_name=group, name=name),
        ),
        "kudu_deployments": _history(
            collector, f"web.web_apps.list_deployments ({name})",
            lambda: web_apps.list_deployments(resource_group_name=group, name=name),
        ),
        "activity": None,
        "slots": None,
    }
    slot_sites = collector.guard(
        f"web.web_apps.list_slots ({name})",
        lambda: [project_site(s) for s in web_apps.list_slots(resource_group_name=group, name=name)],
    )
    if slot_sites is None:
        return record
    prod_config = None
    if slot_sites:
        prod_config = collector.guard(
            f"web.web_apps.get_configuration ({name})",
            lambda: project_site_config(web_apps.get_configuration(resource_group_name=group, name=name)),
        )
    slots = []
    for slot_site in sorted(slot_sites, key=lambda s: s.get("name") or ""):
        slot = slot_name(slot_site)
        label = f"{name}/{slot}"
        slot_config = collector.guard(
            f"web.web_apps.get_configuration_slot ({label})",
            lambda slot=slot: project_site_config(
                web_apps.get_configuration_slot(resource_group_name=group, name=name, slot=slot)
            ),
        )
        differences = configuration_differences(app_site, prod_config, slot_site, slot_config)
        slots.append({
            "name": slot,
            "id": slot_site.get("id"),
            "state": slot_site.get("state"),
            "source_control": _source_control(
                collector, f"web.web_apps.get_source_control_slot ({label})",
                lambda slot=slot: web_apps.get_source_control_slot(resource_group_name=group, name=name, slot=slot),
            ),
            "kudu_deployments": _history(
                collector, f"web.web_apps.list_deployments_slot ({label})",
                lambda slot=slot: web_apps.list_deployments_slot(resource_group_name=group, name=name, slot=slot),
            ),
            "activity": None,
            "configuration_differences": differences,
            "matches_production": None if differences is None else not differences,
        })
    record["slots"] = slots
    return record


def collect_web_apps(subscription_id, cred, collector: Collector) -> tuple[list[dict], int]:
    client = web_client(subscription_id, cred, collector)
    if client is None:
        return [], 0
    sites = collector.guard("web.web_apps.list", lambda: [project_site(s) for s in client.web_apps.list()], default=[])
    web_apps = [s for s in sites if is_web_app(s.get("kind"))]
    apps = []
    for site in web_apps:
        if not resource_group_from_id(site.get("id")) or not site.get("name"):
            collector.record("web.web_apps.list", RuntimeError(f"web app {site.get('name')!r} has no resource group in its id"))
            continue
        apps.append(collect_app(client, collector, site))
    return sorted(apps, key=lambda a: a.get("id") or ""), len(sites) - len(web_apps)


def activity_log_days() -> int:
    raw = os.environ.get("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS") or str(ACTIVITY_LOG_MAX_DAYS)
    try:
        days = int(raw)
    except ValueError:
        logger.warning("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS=%r is not a whole number; using %d", raw, ACTIVITY_LOG_MAX_DAYS)
        return ACTIVITY_LOG_MAX_DAYS
    if not 1 <= days <= ACTIVITY_LOG_MAX_DAYS:
        logger.warning("activity_log_days %d is outside 1-%d; clamped", days, ACTIVITY_LOG_MAX_DAYS)
    return min(max(days, 1), ACTIVITY_LOG_MAX_DAYS)


def read_activity_log(subscription_id, cred, collector: Collector, days: int, now: datetime):
    """Microsoft.Web Activity Log events in [now - days, now], paged to the end; (events, window).

    events is None when any page fails: a partial read would count as fewer deployments, not unknown ones.
    """
    start = now - min(timedelta(days=days), timedelta(days=ACTIVITY_LOG_MAX_DAYS) - ACTIVITY_LOG_RETENTION_MARGIN)
    window = {
        "start_time": start.isoformat(),
        "end_time": now.isoformat(),
        "days": days,
        "complete": False,
        "cut_reason": None,
        "events_read": 0,
        "oldest_event_time": None,
        "requests_on_unlisted_sites": None,
    }
    monitor = collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
    if monitor is None:
        window["cut_reason"] = "read_failed"
        return None, window
    # An explicit end time: with only a start the Activity Log returns just a few hours.
    query = (
        f"eventTimestamp ge '{start:%Y-%m-%dT%H:%M:%SZ}' and eventTimestamp le '{now:%Y-%m-%dT%H:%M:%SZ}' "
        "and resourceProvider eq 'Microsoft.Web'"
    )
    events = []
    try:
        for event in monitor.activity_logs.list(filter=query):
            if window["events_read"] >= ACTIVITY_LOG_MAX_EVENTS:
                window["cut_reason"] = "max_events"
                break
            window["events_read"] += 1
            projected = project_event(event)
            if projected["time"] and (window["oldest_event_time"] is None or projected["time"] < window["oldest_event_time"]):
                window["oldest_event_time"] = projected["time"]
            if activity_category(projected):
                events.append(projected)
        else:
            window["complete"] = True
    except Exception as exc:  # noqa: BLE001 — record it; the counts are unknown, not zero
        collector.record("monitor.activity_logs.list", exc)
        window["cut_reason"] = "read_failed"
        return None, window
    return events, window


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    apps: list[dict] = []
    excluded = 0
    window: dict = {"days": activity_log_days(), "complete": False, "cut_reason": "not_read"}
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Web")
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Web is not registered on subscription %s — no App Service in use", subscription_id)
        apps, excluded = collect_web_apps(subscription_id, cred, collector)
        events, window = read_activity_log(subscription_id, cred, collector, window["days"], datetime.now(timezone.utc))
        window["requests_on_unlisted_sites"] = attach_activity(apps, events)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError("no subscription id (set AZURE_SUBSCRIPTION_ID or configure an ambient Azure "
                         "credential that can list subscriptions)"),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "web_apps": apps,
            "activity_log": window,
            "limitations": LIMITATIONS,
            "provider_registration_status": registration,
        },
        summary={**summarize(apps, excluded, window), "provider_registration_status": registration},
    )
    filename = f"azure_app_service_deployments_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s (%d web apps)", path, len(apps))

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
