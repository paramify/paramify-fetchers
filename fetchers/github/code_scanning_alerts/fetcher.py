#!/usr/bin/env python3
"""Code scanning per repository: whether the default branch is being analysed, by which tools and how recently, and every alert."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import days_between, iso, now_epoch, run, to_epoch  # noqa: E402

NAME = "github_code_scanning_alerts"
CONFIG = {
    "max_analysis_age_days": ("GITHUB_CODE_SCANNING_MAX_AGE_DAYS", 7),
}
SEVERITIES = ("critical", "high", "medium", "low")
AGE_BUCKETS = (7, 30, 90, 180)


def severity(rule):
    """security_severity_level for security queries; quality-only rules carry just `severity` (error/warning/note)."""
    return rule.get("security_severity_level") or None


def alert_record(alert, now):
    rule = alert.get("rule") or {}
    instance = alert.get("most_recent_instance") or {}
    created = to_epoch(alert.get("created_at"))
    closed = to_epoch(alert.get("fixed_at")) or to_epoch(alert.get("dismissed_at"))
    state = alert.get("state")
    return {
        "number": alert.get("number"),
        "state": state,
        "rule_id": rule.get("id"),
        "security_severity": severity(rule),
        "rule_severity": rule.get("severity"),
        "tool": (alert.get("tool") or {}).get("name"),
        "path": (instance.get("location") or {}).get("path"),
        "ref": instance.get("ref"),
        "created_at": alert.get("created_at"),
        "fixed_at": alert.get("fixed_at"),
        "dismissed_at": alert.get("dismissed_at"),
        "dismissed_reason": alert.get("dismissed_reason"),
        "age_days": days_between(created, now) if state == "open" else None,
        "days_to_close": days_between(created, closed),
    }


def repo_record(client, org, repo, now, max_age):
    name, branch = repo["name"], repo.get("default_branch")
    base = f"repos/{org}/{name}"
    record = {"repository": name, "visibility": repo.get("visibility"), "default_branch": branch}
    setup_state, setup = client.read(f"{base}/code-scanning/default-setup")
    analyses_state, analyses = client.paginate(f"{base}/code-scanning/analyses", {"ref": f"refs/heads/{branch}"},
                                               until=lambda a: (to_epoch(a.get("created_at")) or 0) < now - 90 * 86400)
    alerts_state, alerts = client.paginate(f"{base}/code-scanning/alerts")
    if "failed" in (setup_state, analyses_state, alerts_state):
        return {**record, "collected": False}
    if alerts_state is not None:
        alerts = []
    analyses = analyses or []
    latest = max((to_epoch(a.get("created_at")) or 0 for a in analyses), default=None) or None
    tools = sorted({(a.get("tool") or {}).get("name") for a in analyses if (a.get("tool") or {}).get("name")})
    alerts = [alert_record(a, now) for a in alerts]
    open_alerts = [a for a in alerts if a["state"] == "open"]
    record.update({
        "collected": True,
        "code_scanning_available": setup_state is None or analyses_state is None,
        "default_setup": (setup or {}).get("state") if setup_state is None else setup_state,
        "default_setup_languages": (setup or {}).get("languages"),
        "analysed": bool(analyses),
        "tools": tools,
        "last_analysis_at": iso(latest),
        "last_analysis_age_days": days_between(latest, now),
        "analysis_current": latest is not None and (now - latest) <= max_age * 86400,
        "open_by_security_severity": {s: len([a for a in open_alerts if a["security_severity"] == s])
                                      for s in SEVERITIES},
        "alerts": alerts,
    })
    return record


def summarize(records):
    done = [r for r in records if r["collected"]]
    open_alerts = [a for r in done for a in r["alerts"] if a["state"] == "open"]
    closed = [a for r in done for a in r["alerts"] if a["state"] == "fixed" and a["days_to_close"] is not None]
    return {
        "repositories_total": len(records),
        "not_collected": [r["repository"] for r in records if not r["collected"]],
        "repositories_not_analysed": [r["repository"] for r in done if not r["analysed"]],
        "repositories_analysis_stale": [r["repository"] for r in done if r["analysed"] and not r["analysis_current"]],
        "tools": sorted({t for r in done for t in r["tools"]}),
        "open_total": len(open_alerts),
        "open_by_security_severity": {s: len([a for a in open_alerts if a["security_severity"] == s])
                                      for s in SEVERITIES},
        "open_without_security_severity": len([a for a in open_alerts if a["security_severity"] is None]),
        "open_older_than_days": {str(d): {s: len([a for a in open_alerts if a["security_severity"] == s
                                                   and (a["age_days"] or 0) > d]) for s in SEVERITIES}
                                 for d in AGE_BUCKETS},
        "fixed_total": len(closed),
        "median_days_to_fix": sorted(a["days_to_close"] for a in closed)[len(closed) // 2] if closed else None,
        "dismissed_total": len([a for r in done for a in r["alerts"] if a["state"] == "dismissed"]),
        # GitHub's schema allows a null alert state; such an alert is in no count above, so count it here.
        "state_unknown_total": len([a for r in done for a in r["alerts"] if a["state"] is None]),
    }


def collect(client, org, repos, config):
    now = now_epoch()
    records = [repo_record(client, org["login"], repo, now, config["max_analysis_age_days"]) for repo in repos]
    return {"metadata": {"as_of": iso(now)}, "summary": summarize(records), "repositories": records}


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
