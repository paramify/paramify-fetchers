#!/usr/bin/env python3
"""
Splunk Saved Search Alerts

Reads every saved search on one Splunk deployment and records which of them are
configured as ALERTS — their trigger condition, whether alerting is actually
enabled, their schedule, the actions that fire when they trigger, and the app
and owner that hold them — so a "we alert on audit events" claim can be
asserted against configuration rather than asserted in prose (KSI-MLA-RVL).

Four things this fetcher does that a naive read of the API does not:

1. **It reads the `-/-` namespace, not the default one.**
   `GET /services/saved/searches` resolves to the CALLER's current namespace.
   On this deployment that endpoint returns 8 saved searches, all from the
   `search` app, none scheduled and none with an action — from which the honest
   conclusion would be "there are no alerts here", and it would be wrong.
   `GET /servicesNS/-/-/saved/searches` returns 174 across 7 apps. Alerts live
   in whichever app defines them, so anything less than `-/-` silently hides
   most of the control's subject.

2. **An alert is identified from three signals, and the result deliberately
   over-counts.** A saved search is treated as an alert when it has a trigger
   condition (`alert_type` other than `"always"`, which is what Splunk writes
   on every plain report), OR tracks its triggers in the alert manager, OR
   carries an action that notifies something. That rule is inclusive on
   purpose: it will count Splunk's own scheduled telemetry jobs, which carry
   `alert_type: "number of events"` while notifying nobody. Over-counting is
   the safe direction for a fetcher whose roll-up asserts that alerts exist —
   it can never manufacture an alert the deployment does not have — and the
   app-scoping knob, not the classifier, is what removes the vendor's own jobs
   from the roll-up that speaks to the control. All three inputs are kept in
   the evidence next to the derived flag.

3. **Notification actions are identified by exclusion, not by allowlist.**
   Splunk's own non-notifying actions (`summary_index`, `populate_lookup`,
   `outputtelemetry`) write data back into Splunk and tell no one. Everything
   else — `email`, `webhook`, `script`, `rss`, and every app-installed custom
   action such as Slack, PagerDuty or ServiceNow — is counted as notifying. An
   allowlist would have missed precisely the actions a real SIEM deployment
   uses, since custom alert actions carry arbitrary names.

4. **It states the boundary of what it can prove.** The claim this serves says
   alerts are collated on a dashboard and "reviewed and resolved" by a named
   role. This evidence can show an alert is CONFIGURED and ENABLED and that it
   notifies something. It cannot show that a human read it. `review_evidence_
   boundary` says so in the payload, and the roll-ups are named for what they
   measure (`..._configured`, `..._enabled`) rather than for review.

Unlike retention and role access, the roll-up here asserts a POSITIVE — that
alerts exist and are enabled. A positive assertion over an empty set is
vacuously true: "every alert is enabled" holds when there are no alerts. That
is why `audit_scope.scope_is_assessable` exists and why every positive verdict
is AND-ed with it.
"""

import json
import logging
import os
import re
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("splunk_saved_search_alerts")

# Splunk's own alert actions that write data back into Splunk and notify nobody.
# Anything NOT in this set is treated as a notification action, because custom
# alert actions (Slack, PagerDuty, ServiceNow, a webhook to a SOAR platform)
# ship with app-defined names that no allowlist could enumerate in advance.
NON_NOTIFYING_ACTIONS = {"summary_index", "populate_lookup", "outputtelemetry"}

# `alert_type` on a saved search that has NO trigger condition. Splunk writes
# this on every plain report, so it is the absence of an alert condition rather
# than the presence of one.
ALERT_TYPE_NO_CONDITION = "always"

# Heuristic only — see `audit_index_reference_note` in the payload.
INDEX_IN_SPL = re.compile(r"""index\s*=\s*["']?([A-Za-z0-9_*\-]+)["']?""", re.IGNORECASE)


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("://", "_").replace("/", "_").replace(":", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in {"false", "0", "no", "off"}


def csv_env(name: str, default: str = "") -> List[str]:
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


def build_session(token: str, username: str, password: str, verify_ssl: bool) -> requests.Session:
    """Bearer token if we have one, HTTP basic otherwise.

    Splunk Cloud effectively requires the token; basic auth is the Enterprise
    and sandbox path. Callers guarantee one of the two is present.
    """
    session = requests.Session()
    session.verify = verify_ssl
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        session.auth = (username, password)
    return session


def get_json(session: requests.Session, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    merged = {"output_mode": "json", **params}
    response = session.get(url, params=merged, timeout=120)
    if response.status_code in (401, 403):
        raise PermissionError(f"{response.status_code} from {url}: {response.text[:300]}")
    if response.status_code != 200:
        raise RuntimeError(f"{response.status_code} from {url}: {response.text[:300]}")
    return response.json()


def to_int(value: Any) -> Any:
    """splunkd returns numbers as strings; keep non-numeric values visible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> List[str]:
    """splunkd omits empty multivalue fields and collapses single ones to a str."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def truthy(value: Any) -> bool:
    """splunkd mixes real JSON booleans with "0"/"1"/"true" strings.

    A MISSING key is false, and that distinction matters here: `action.webhook`
    does not appear at all on a deployment where no saved search uses it, while
    `action.webhook.enable_allowlist` does. An absent action key means "not
    configured" and must never be read as a present-and-false flag.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def split_actions(value: Any) -> List[str]:
    """`content.actions` is a comma-separated list of the ENABLED action names."""
    if not value:
        return []
    return [v.strip() for v in str(value).split(",") if v.strip()]


def enabled_action_keys(content: Dict[str, Any]) -> List[str]:
    """Action names whose `action.<name>` enable flag is truthy.

    Cross-checked against `content.actions`: the two normally agree, but the
    enable flag is the per-action source of truth and `actions` is the summary
    string, so both are recorded rather than one being trusted over the other.
    Only the bare `action.<name>` enable key counts — `action.<name>.<param>`
    is configuration for the action, not evidence that it is on.
    """
    names = []
    for key, value in content.items():
        if not key.startswith("action.") or key.count(".") != 1:
            continue
        if truthy(value):
            names.append(key.split(".", 1)[1])
    return sorted(names)


def indexes_referenced(search: str, audit_indexes: List[str]) -> List[str]:
    """Which of the named audit indexes this search's SPL appears to read.

    A text match over SPL, not a parse. See `audit_index_reference_note`.
    """
    if not search or not audit_indexes:
        return []
    found = {m.lower() for m in INDEX_IN_SPL.findall(search)}
    hits = [name for name in audit_indexes if name.lower() in found]
    # A search over `index=*` reaches every non-internal index, so it reaches
    # any named audit index that is not itself internal.
    if "*" in found:
        hits.extend(name for name in audit_indexes if not name.startswith("_"))
    return sorted(set(hits))


def describe_saved_search(
    entry: Dict[str, Any], audit_indexes: List[str], scope_apps: List[str]
) -> Dict[str, Any]:
    content = entry.get("content", {}) or {}
    # The ACL block sits at entry[].acl, NOT under entry[].content. content
    # carries an `eai:acl` duplicate; the top-level block is the one to read.
    acl = entry.get("acl", {}) or {}
    perms = acl.get("perms") or {}

    app = acl.get("app")
    actions = split_actions(content.get("actions"))
    action_keys = enabled_action_keys(content)
    all_actions = sorted(set(actions) | set(action_keys))
    notifying = sorted(a for a in all_actions if a not in NON_NOTIFYING_ACTIONS)

    alert_type = str(content.get("alert_type") or "")
    has_condition = bool(alert_type) and alert_type != ALERT_TYPE_NO_CONDITION
    tracks_alerts = truthy(content.get("alert.track"))
    is_scheduled = truthy(content.get("is_scheduled"))
    disabled = truthy(content.get("disabled"))

    # An alert is a saved search that has a trigger condition, OR tracks its
    # triggers in the alert manager, OR notifies something when it runs. All
    # three inputs stay in the evidence beside this flag.
    is_alert = has_condition or tracks_alerts or bool(notifying)

    search = str(content.get("search") or "")

    return {
        "name": entry.get("name"),
        "app": app,
        "owner": acl.get("owner"),
        "sharing": acl.get("sharing"),
        "read_roles": as_list(perms.get("read")),
        "write_roles": as_list(perms.get("write")),
        "in_scope_app": bool(scope_apps) and app in scope_apps,
        "description": content.get("description"),
        # --- is it an alert, and is alerting actually on? ---
        "is_alert": is_alert,
        "has_alert_condition": has_condition,
        "alert_type": alert_type,
        "alert_condition": content.get("alert_condition"),
        "alert_comparator": content.get("alert_comparator"),
        "alert_threshold": content.get("alert_threshold"),
        "alert_severity": to_int(content.get("alert.severity")),
        "alert_track": tracks_alerts,
        "alert_digest_mode": truthy(content.get("alert.digest_mode")),
        "alert_suppress": truthy(content.get("alert.suppress")),
        "alert_suppress_period": content.get("alert.suppress.period"),
        "alert_expires": content.get("alert.expires"),
        "is_scheduled": is_scheduled,
        "disabled": disabled,
        # The field that carries the control: configured is not the same as on.
        "alerting_enabled": is_alert and is_scheduled and not disabled,
        # --- schedule ---
        "cron_schedule": content.get("cron_schedule"),
        "has_schedule": bool(str(content.get("cron_schedule") or "").strip()),
        "dispatch_earliest_time": content.get("dispatch.earliest_time"),
        "dispatch_latest_time": content.get("dispatch.latest_time"),
        "next_scheduled_time": content.get("next_scheduled_time"),
        "realtime_schedule": truthy(content.get("realtime_schedule")),
        "schedule_window": content.get("schedule_window"),
        "schedule_priority": content.get("schedule_priority"),
        # --- actions ---
        "actions": actions,
        "actions_enabled_by_flag": action_keys,
        "actions_effective": all_actions,
        "notification_actions": notifying,
        "has_notification_action": bool(notifying),
        "non_notifying_actions": sorted(a for a in all_actions if a in NON_NOTIFYING_ACTIONS),
        "email_recipients": content.get("action.email.to"),
        # --- what it searches ---
        "search": search,
        "audit_indexes_referenced": indexes_referenced(search, audit_indexes),
        "references_audit_index": (
            bool(indexes_referenced(search, audit_indexes)) if audit_indexes else None
        ),
        "dispatch_as": content.get("dispatchAs"),
        "schedule_as": content.get("schedule_as"),
    }


def summarize(searches: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Alerting roll-up over whichever set of saved searches was handed in.

    Every verdict here is named for what it measures — `_configured`,
    `_enabled`, `_notifies` — and never for review, which this evidence cannot
    observe. See `review_evidence_boundary`.
    """
    alerts = [s for s in searches if s["is_alert"]]
    enabled = [s for s in alerts if s["alerting_enabled"]]
    notifying = [s for s in enabled if s["has_notification_action"]]
    return {
        "total_saved_searches": len(searches),
        "scheduled_saved_searches": sum(1 for s in searches if s["is_scheduled"]),
        "alerts_configured": len(alerts),
        "alerts_configured_names": sorted(str(s["name"]) for s in alerts),
        "any_alert_configured": bool(alerts),
        "alerts_enabled": len(enabled),
        "alerts_enabled_names": sorted(str(s["name"]) for s in enabled),
        "any_alert_enabled": bool(enabled),
        "alerts_disabled": len(alerts) - len(enabled),
        "alerts_disabled_names": sorted(
            str(s["name"]) for s in alerts if not s["alerting_enabled"]
        ),
        "every_configured_alert_is_enabled": bool(alerts) and len(enabled) == len(alerts),
        "alerts_with_notification_action": len(notifying),
        "alerts_with_notification_action_names": sorted(str(s["name"]) for s in notifying),
        "every_enabled_alert_notifies": bool(enabled) and len(notifying) == len(enabled),
        "enabled_alerts_without_notification_action_names": sorted(
            str(s["name"]) for s in enabled if not s["has_notification_action"]
        ),
        "notification_actions_in_use": sorted(
            {a for s in enabled for a in s["notification_actions"]}
        ),
        "apps_represented": sorted({str(s["app"]) for s in searches if s["app"]}),
    }


def collect(
    session: requests.Session,
    host: str,
    audit_indexes: List[str],
    scope_apps: List[str],
) -> Dict[str, Any]:
    base = host.rstrip("/")
    api_failures: List[Dict[str, str]] = []

    server = {}
    try:
        info = get_json(session, f"{base}/services/server/info", {})
        content = (info.get("entry") or [{}])[0].get("content", {})
        server = {
            "version": content.get("version"),
            "product_type": content.get("product_type"),
            "license_state": content.get("licenseState"),
            "server_name": content.get("serverName"),
            "mode": content.get("mode"),
        }
    except Exception as exc:  # server/info is context, not the evidence itself
        api_failures.append(
            {"operation": "GET /services/server/info", "type": type(exc).__name__, "message": str(exc)}
        )

    # splunkd filters knowledge objects by what the CALLER may read, so the
    # identity that read this is part of the evidence — the same reason
    # splunk_role_index_access records it.
    caller = {}
    try:
        ctx = get_json(session, f"{base}/services/authentication/current-context", {})
        content = (ctx.get("entry") or [{}])[0].get("content", {})
        caller = {
            "username": content.get("username"),
            "roles": as_list(content.get("roles")),
            "capability_count": len(as_list(content.get("capabilities"))),
        }
    except Exception as exc:
        api_failures.append(
            {
                "operation": "GET /services/authentication/current-context",
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )

    # Whether any alert has EVER fired. This is the closest splunkd gets to
    # "something happened that a person could review", and it is still not
    # review — see `review_evidence_boundary`. Recorded as context, not as a
    # verdict, and a failure here does not invalidate the configuration read.
    fired = {}
    try:
        data = get_json(session, f"{base}/servicesNS/-/-/alerts/fired_alerts", {"count": 0})
        entries = data.get("entry") or []
        # splunkd returns a synthetic `-` entry carrying the deployment-wide
        # total, alongside one entry per saved search that has fired.
        rollup = next((e for e in entries if e.get("name") == "-"), None)
        per_search = [e for e in entries if e.get("name") != "-"]
        fired = {
            "triggered_alert_count": to_int(
                ((rollup or {}).get("content") or {}).get("triggered_alert_count")
            ),
            "saved_searches_with_fired_alerts": sorted(
                str(e.get("name")) for e in per_search
            ),
            "any_alert_has_ever_fired": bool(per_search)
            or bool(
                to_int(((rollup or {}).get("content") or {}).get("triggered_alert_count"))
            ),
        }
    except Exception as exc:
        api_failures.append(
            {
                "operation": "GET /servicesNS/-/-/alerts/fired_alerts",
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )

    # `-/-` is load-bearing: /services/saved/searches resolves to the caller's
    # own namespace and returns only the saved searches of ONE app. count=0
    # returns everything in one call, splunkd's documented convention.
    data = get_json(session, f"{base}/servicesNS/-/-/saved/searches", {"count": 0})
    entries = data.get("entry") or []
    searches = [describe_saved_search(e, audit_indexes, scope_apps) for e in entries]
    reported_total = (data.get("paging") or {}).get("total")

    # Two roll-ups, mirroring splunk_index_retention and
    # splunk_role_index_access. `summary` covers every saved search on the
    # deployment and is the completeness view. `audit_scope` covers only the
    # apps the organization named as holding its audit alerting, and is the one
    # that speaks to the control: Splunk ships 174 saved searches across seven
    # of its own apps here, whose alerting configuration is Splunk's business
    # and not the customer's — the same trap splunk_index_retention hit with
    # _internal and splunk_role_index_access hit with the built-in roles.
    present_apps = {str(s["app"]) for s in searches if s["app"]}
    missing_apps = [a for a in scope_apps if a not in present_apps]
    scope: Dict[str, Any] = {
        "alert_apps_configured": bool(scope_apps),
        "alert_apps_named": sorted(scope_apps),
        "alert_apps_named_but_absent": sorted(missing_apps),
        "apps_available_on_deployment": sorted(present_apps),
    }
    in_scope = [s for s in searches if s["in_scope_app"]]
    scope["saved_searches_in_scope"] = len(in_scope)
    if scope_apps:
        scope.update(summarize(in_scope))
        # THE guard, and it matters more here than it did for the siblings.
        # Their roll-ups assert a negative ("no index below 90 days"), which an
        # empty set makes trivially true but also visibly empty. This one
        # asserts a POSITIVE — alerts exist and are enabled — and a positive
        # over an empty set is vacuously true in a way that reads as a pass.
        # A scope is assessable only when apps were named, the list came back
        # whole, every named app actually exists, and at least one alert was
        # found in it.
        scope["scope_is_assessable"] = bool(
            scope_apps
            and in_scope
            and (reported_total is None or reported_total == len(searches))
            and not missing_apps
            and scope["alerts_configured"] > 0
        )
        for verdict in (
            "any_alert_configured",
            "any_alert_enabled",
            "every_configured_alert_is_enabled",
            "every_enabled_alert_notifies",
        ):
            scope[verdict] = bool(scope[verdict]) and scope["scope_is_assessable"]
    else:
        scope["scope_is_assessable"] = False

    return {
        "authenticated_as": caller,
        "fired_alerts": fired,
        "namespace_note": (
            "Saved searches are read from /servicesNS/-/-/saved/searches, NOT "
            "/services/saved/searches. The latter resolves to the caller's own "
            "namespace and returns the saved searches of a single app: on this "
            "deployment it returns 8 of 174, none of them an alert. Alerts live "
            "in whichever app defines them, so any narrower namespace hides most "
            "of what this control is about."
        ),
        "alert_classification_note": (
            "A saved search is counted as an alert when it has a trigger "
            "condition (`alert_type` other than \"always\", which is what Splunk "
            "writes on every plain report), OR tracks its triggers in the alert "
            "manager (`alert.track`), OR carries an action that notifies "
            "something. That rule OVER-counts on purpose: Splunk's own scheduled "
            "telemetry jobs carry `alert_type: \"number of events\"` while "
            "notifying nobody, and they are counted as alerts here. Over-counting "
            "is the safe direction for a roll-up that asserts alerts EXIST, since "
            "it cannot manufacture an alert the deployment does not have; the "
            "`audit_scope` app filter, not this classifier, is what removes the "
            "vendor's own jobs from the verdict that speaks to the control. A "
            "notification action is any action NOT in "
            f"{sorted(NON_NOTIFYING_ACTIONS)}, which write results back into "
            "Splunk and tell no one; identifying them by exclusion rather than "
            "by allowlist is deliberate, because custom alert actions (Slack, "
            "PagerDuty, ServiceNow, a SOAR webhook) carry app-defined names."
        ),
        "audit_index_reference_note": (
            "`audit_indexes_referenced` is a TEXT MATCH for `index=<name>` over "
            "the saved search's SPL, not a parse of it. It will miss an index "
            "reached through a macro, an event type, a saved-search reference or "
            "a lookup, and it credits `index=*` with reaching every non-internal "
            "named index. It is reported per search as context and no roll-up "
            "verdict depends on it."
        ),
        "server": server,
        "saved_searches_reported_total": reported_total,
        "saved_searches_returned": len(searches),
        "saved_search_list_complete": reported_total is None or reported_total == len(searches),
        "saved_searches": sorted(searches, key=lambda s: (str(s["app"]), str(s["name"]))),
        "summary": summarize(searches),
        "audit_scope": scope,
        # The polarity warning, in the payload rather than only in this file.
        "review_evidence_boundary": {
            "proves": [
                "which saved searches are configured as alerts, and in which app and by which owner",
                "whether each alert's schedule and trigger condition are set",
                "whether alerting is ENABLED (scheduled and not disabled) on each",
                "which actions fire when an alert triggers, and whether any of them notifies anything",
                "whether any alert has ever fired, from the alert manager's own count",
            ],
            "does_not_prove": [
                "that any person read, triaged, reviewed or resolved an alert",
                "that the alerts are collated onto a dashboard, or onto WHICH dashboard",
                "that the notification recipients are the accountable role, or that anyone reads them",
                "that the configured alerts COVER the audit events the control cares about — this "
                "records the alerts that exist, not the ones that ought to",
                "that an enabled alert has ever run successfully, only that it is scheduled",
            ],
            "note": (
                "The capability narrative this serves claims alerts are collated, "
                "reviewed and resolved by a named role. Configuration evidence "
                "reaches the first half of that claim only. Review and resolution "
                "are a workflow record — alert manager triage state, a ticketing "
                "system, or a dashboard's own audit trail — and are not "
                "observable in the saved-search configuration this fetcher reads. "
                "No field in this payload should be read as review coverage."
            ),
        },
        "api_failures": api_failures,
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    host = os.environ.get("SPLUNK_HOST", "")
    token = os.environ.get("SPLUNK_TOKEN", "")
    username = os.environ.get("SPLUNK_USERNAME", "")
    password = os.environ.get("SPLUNK_PASSWORD", "")
    target_name = os.environ.get("SPLUNK_TARGET_NAME", "") or host
    verify_ssl = env_flag("SPLUNK_VERIFY_SSL", True)

    if not host:
        report_failure("Missing required env var: SPLUNK_HOST", "bad_config")
        return 1
    if not token and not (username and password):
        report_failure(
            "No Splunk credential: supply SPLUNK_TOKEN, or SPLUNK_USERNAME and SPLUNK_PASSWORD",
            "bad_config",
        )
        return 1

    audit_indexes = csv_env("SPLUNK_AUDIT_INDEXES")
    scope_apps = csv_env("SPLUNK_ALERT_APPS")

    if not verify_ssl:
        # Only reachable when the target explicitly opted out, which the schema
        # restricts to sandboxes. Suppressing the warning keeps it off stderr,
        # whose tail the runner reads as the failure reason. Filtered by message
        # rather than by class so this stays stdlib-only and urllib3 need not be
        # imported (or declared) just to name an exception type.
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    session = build_session(token, username, password, verify_ssl)
    auth_method = "bearer_token" if token else "basic_auth"

    failure: Dict[str, str] = {}
    try:
        result = collect(session, host, audit_indexes, scope_apps)
    except PermissionError as exc:
        result = {"api_failures": [{"operation": "collect", "type": "PermissionError", "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "not_authorized"}
    except requests.exceptions.RequestException as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "target_unreachable"}
    except Exception as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "internal_error"}

    api_failures = result.get("api_failures", [])
    evidence = {
        "target_name": target_name,
        "splunk_host": host,
        "auth_method": auth_method,
        "tls_verified": verify_ssl,
        "collected_at": current_timestamp(),
        "partial_failure": bool(api_failures) and not failure,
        **result,
    }

    output_path = output_dir / f"splunk_saved_search_alerts_{sanitize_for_filename(target_name)}.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    # Reported AFTER the success line above: the runner reads the TAIL of stderr
    # as the failure reason, so whichever line is logged last wins. report_failure
    # does the error-level logging itself — logging the reason here as well puts
    # it on stderr twice (tests/test_failure_reporting_contract.py enforces this).
    if failure:
        report_failure(failure["reason"], failure["code"])
        return 1
    if api_failures:
        report_failure(
            "; ".join(f"{f['operation']}: {f['message']}" for f in api_failures),
            "partial_failure",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
