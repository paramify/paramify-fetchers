#!/usr/bin/env python3
"""Dependabot alerts per repository with their age and outcome, and whether each repository is being scanned at all."""

import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import (  # noqa: E402
    by_severity,
    days_between,
    iso,
    median_days,
    now_epoch,
    open_older_than,
    run,
    to_epoch,
)

NAME = "github_dependabot_alerts"
CONFIG = {
    "check_kev": ("GITHUB_CHECK_KEV", True),
}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def known_exploited(client):
    """CVE ids in CISA's Known Exploited Vulnerabilities catalog, or None when it cannot be read."""
    try:
        resp = requests.get(KEV_URL, timeout=60)
        resp.raise_for_status()
        return {v["cveID"] for v in resp.json().get("vulnerabilities", []) if v.get("cveID")}
    except (requests.exceptions.RequestException, ValueError, KeyError) as exc:
        client.fail(f"GET {KEV_URL}", type(exc).__name__,
                    f"{exc} (set check_kev false where cisa.gov is unreachable)", "target_unreachable")
        return None


def alert_record(alert, now, kev):
    advisory = alert.get("security_advisory") or {}
    vuln = alert.get("security_vulnerability") or {}
    dep = alert.get("dependency") or {}
    created, fixed = to_epoch(alert.get("created_at")), to_epoch(alert.get("fixed_at"))
    closed = fixed or to_epoch(alert.get("dismissed_at")) or to_epoch(alert.get("auto_dismissed_at"))
    cve = advisory.get("cve_id")
    return {
        "number": alert.get("number"),
        "state": alert.get("state"),
        "severity": vuln.get("severity") or advisory.get("severity"),
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": cve,
        "known_exploited": None if kev is None or not cve else cve in kev,
        "epss_percentage": (advisory.get("epss") or {}).get("percentage"),
        "package": (dep.get("package") or {}).get("name"),
        "ecosystem": (dep.get("package") or {}).get("ecosystem"),
        "manifest_path": dep.get("manifest_path"),
        "scope": dep.get("scope"),
        "first_patched_version": (vuln.get("first_patched_version") or {}).get("identifier"),
        "created_at": alert.get("created_at"),
        "fixed_at": alert.get("fixed_at"),
        "dismissed_at": alert.get("dismissed_at"),
        "dismissed_reason": alert.get("dismissed_reason"),
        "auto_dismissed_at": alert.get("auto_dismissed_at"),
        "age_days": days_between(created, now) if alert.get("state") == "open" else None,
        "days_to_close": days_between(created, closed),
    }


def repo_record(client, org, repo, now, kev):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    record = {"repository": name, "visibility": repo.get("visibility")}
    state, alerts = client.paginate(f"{base}/dependabot/alerts", {"state": "open,fixed,dismissed,auto_dismissed"})
    if state == "failed":
        return {**record, "collected": False}
    record["alerts_enabled"] = state is None  # disabled, or not on this plan
    found, sbom = client.lookup(f"{base}/dependency-graph/sbom")
    # The graph only parses manifests on a push; alerts can be on while it holds nothing but the repository itself.
    packages = [p for p in ((sbom or {}).get("sbom") or {}).get("packages") or []
                if not str(p.get("SPDXID", "")).endswith("-repository")
                and p.get("name") != f"com.github.{org}/{name}"] if found else None
    fixes = client.get(f"{base}/automated-security-fixes")  # 200 {enabled, paused} either way; a 404 is access
    alerts = [alert_record(a, now, kev) for a in alerts or []]
    open_alerts = [a for a in alerts if a["state"] == "open"]
    record.update({
        "collected": True,
        "dependency_graph_enabled": found,
        "dependency_graph_packages": None if packages is None else len(packages),
        "security_updates_enabled": None if fixes is None else bool(fixes.get("enabled")) and not fixes.get("paused"),
        "open_by_severity": by_severity(open_alerts, "severity"),
        "open_known_exploited": [a["number"] for a in open_alerts if a["known_exploited"]],
        "oldest_open_days": max((a["age_days"] for a in open_alerts if a["age_days"] is not None), default=None),
        "alerts": alerts,
    })
    return record


def summarize(records, kev):
    done = [r for r in records if r["collected"]]
    open_alerts = [a for r in done for a in r["alerts"] if a["state"] == "open"]
    fixed = [a for r in done for a in r["alerts"] if a["state"] == "fixed" and a["days_to_close"] is not None]
    dismissed = [a for r in done for a in r["alerts"] if a["state"] in ("dismissed", "auto_dismissed")]
    reasons = {}
    for a in dismissed:
        key = a["dismissed_reason"] or a["state"]
        reasons[key] = reasons.get(key, 0) + 1
    return {
        "repositories_total": len(records),
        "not_collected": [r["repository"] for r in records if not r["collected"]],
        "repositories_alerts_disabled": [r["repository"] for r in done if not r["alerts_enabled"]],
        "repositories_dependency_graph_disabled": [r["repository"] for r in done if r["dependency_graph_enabled"] is False],
        "repositories_dependency_graph_empty": [r["repository"] for r in done if r["dependency_graph_packages"] == 0],
        "repositories_without_security_updates": [r["repository"] for r in done if r["security_updates_enabled"] is False],
        "open_total": len(open_alerts),
        "open_by_severity": by_severity(open_alerts, "severity"),
        "open_older_than_days": open_older_than(open_alerts, "severity"),
        "open_known_exploited": len([a for a in open_alerts if a["known_exploited"]]),
        "known_exploited_checked": kev is not None,
        "fixed_total": len(fixed),
        "median_days_to_fix": median_days(fixed, "days_to_close"),
        "dismissed_total": len(dismissed),
        "dismissed_by_reason": reasons,
    }


def collect(client, org, repos, config):
    now = now_epoch()
    kev = known_exploited(client) if config["check_kev"] else None
    records = [repo_record(client, org["login"], repo, now, kev) for repo in repos]
    return {
        "metadata": {"kev_catalog": KEV_URL if config["check_kev"] else None, "kev_entries": len(kev) if kev else None,
                     "as_of": iso(now)},
        "summary": summarize(records, kev),
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
