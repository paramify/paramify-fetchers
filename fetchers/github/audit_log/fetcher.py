#!/usr/bin/env python3
"""The organization audit log for the window: event counts, and every access, protection or control change (Enterprise Cloud only)."""

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import iso, now_epoch, run  # noqa: E402

NAME = "github_audit_log"
CONFIG = {
    "days_back": ("GITHUB_AUDIT_DAYS_BACK", 7),
    "max_events": ("GITHUB_AUDIT_MAX_EVENTS", 50000),
}
MAX_DAYS_BACK = 180  # the API keeps web events for 180 days
# Action families that change access, protection or security controls; every event in them is kept in full.
SECURITY_FAMILIES = (
    "org", "repo", "team", "protected_branch", "repository_ruleset", "secret_scanning", "secret_scanning_alert",
    "secret_scanning_push_protection", "hook", "integration_installation", "oauth_application",
    "personal_access_token", "org_credential_authorization", "repository_vulnerability_alert", "dependabot_alerts",
    "code_scanning", "environment", "codespaces", "business", "ip_allow_list", "audit_log_streaming",
)
PLANS_WITHOUT_AUDIT_API = ("free", "team")


def when(value):
    """An event's time. The schema says Unix seconds; GitHub's own examples are milliseconds."""
    if not isinstance(value, (int, float)):
        return None
    return iso(value / 1000 if value > 10 ** 11 else value)


def event_row(e):
    return {
        "at": when(e.get("@timestamp") or e.get("created_at")),
        "action": e.get("action"),
        "actor": e.get("actor"),
        "country": (e.get("actor_location") or {}).get("country_name"),
        "user": e.get("user"),
        "repo": e.get("repo") or e.get("repository"),
        "team": e.get("team"),
        "visibility": e.get("visibility"),
        "previous_visibility": e.get("previous_visibility"),
        "operation_type": e.get("operation_type"),
        "document_id": e.get("_document_id"),
    }


def collect(client, org, repos, config):
    login = org["login"]
    days, cap = config["days_back"], config["max_events"]
    if not 1 <= days <= MAX_DAYS_BACK or cap < 1:
        client.fail("config", "BadConfig", f"GITHUB_AUDIT_DAYS_BACK must be 1..{MAX_DAYS_BACK} and "
                    "GITHUB_AUDIT_MAX_EVENTS at least 1", "bad_config")
        return None
    plan = (org.get("plan") or {}).get("name")
    if plan in PLANS_WITHOUT_AUDIT_API:
        client.fail(f"GET orgs/{login}/audit-log", "PlanUnavailable",
                    f"the organization audit log API needs GitHub Enterprise Cloud; this organization is on {plan}",
                    "bad_config")
        return None
    since = now_epoch() - days * 86400
    day = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%d")
    seen = []
    events = client.paginate_required(f"orgs/{login}/audit-log",
                                      {"phrase": f"created:>={day}", "include": "web", "order": "desc"},
                                      until=lambda e: seen.append(e) or len(seen) > cap)
    if events is None:
        return None
    if len(seen) > cap:
        client.fail(f"GET orgs/{login}/audit-log", "Truncated",
                    f"more than {cap} events since {day}; raise GITHUB_AUDIT_MAX_EVENTS or shorten the window",
                    "partial_failure")
        return None
    by_action = {}
    for e in events:
        by_action[e.get("action") or "unknown"] = by_action.get(e.get("action") or "unknown", 0) + 1
    security = [event_row(e) for e in events if str(e.get("action") or "").split(".")[0] in SECURITY_FAMILIES]
    return {
        "metadata": {"since": f"{day}T00:00:00Z", "include": "web"},
        "summary": {
            "events_total": len(events),
            "security_events": len(security),
            "actors": len({e.get("actor") for e in events if e.get("actor")}),
            "actor_countries": sorted({r["country"] for r in security if r["country"]}),
            "by_family": {f: sum(n for a, n in by_action.items() if a.split(".")[0] == f)
                          for f in sorted({a.split(".")[0] for a in by_action})},
            "by_action": dict(sorted(by_action.items())),
            "oldest_event": min((r["at"] for r in map(event_row, events) if r["at"]), default=None),
            "newest_event": max((r["at"] for r in map(event_row, events) if r["at"]), default=None),
        },
        "security_events": security,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
