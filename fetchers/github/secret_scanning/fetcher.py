#!/usr/bin/env python3
"""Secret scanning per repository: whether scanning and push protection are on, every alert, and every push-protection bypass."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import (  # noqa: E402
    days_between,
    iso,
    now_epoch,
    run,
    to_epoch,
)

NAME = "github_secret_scanning"
SETTINGS = ("secret_scanning", "secret_scanning_push_protection", "secret_scanning_non_provider_patterns",
            "secret_scanning_validity_checks")
GENERIC_TYPES = ",".join(("ec_private_key", "generic_private_key", "http_basic_authentication_header",
                          "http_bearer_authentication_header", "mongodb_connection_string", "mysql_connection_url",
                          "openssh_private_key", "pgp_private_key", "postgres_connection_string", "rsa_private_key",
                          "password"))


def alert_record(alert, now):
    """Never the secret itself: requested with hide_secret, and only these fields are copied."""
    created = to_epoch(alert.get("created_at"))
    state = alert.get("state")
    return {
        "number": alert.get("number"),
        "state": state,
        "resolution": alert.get("resolution"),
        "secret_type": alert.get("secret_type"),
        "secret_type_display_name": alert.get("secret_type_display_name"),
        "validity": alert.get("validity"),
        "publicly_leaked": alert.get("publicly_leaked"),
        "multi_repo": alert.get("multi_repo"),
        "push_protection_bypassed": bool(alert.get("push_protection_bypassed") or alert.get("push_protection_bypassed_by")),
        "push_protection_bypassed_by": (alert.get("push_protection_bypassed_by") or {}).get("login"),
        "push_protection_bypassed_at": alert.get("push_protection_bypassed_at"),
        "created_at": alert.get("created_at"),
        "resolved_at": alert.get("resolved_at"),
        "age_days": days_between(created, now) if state == "open" else None,
        "days_to_resolve": days_between(created, to_epoch(alert.get("resolved_at"))),
    }


def repo_record(client, org, repo, now):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    record = {"repository": name, "visibility": repo.get("visibility")}
    sa = repo.get("security_and_analysis")
    # Only an admin or security manager sees security_and_analysis; absent means unreadable, never "disabled".
    settings = None if sa is None else {k: (sa.get(k) or {}).get("status") for k in SETTINGS}
    state, alerts = client.paginate(f"{base}/secret-scanning/alerts", {"hide_secret": "true"})
    if state is None:
        # Without secret_type GitHub returns provider patterns only; non-provider and generic ones must be named.
        state, generic = client.paginate(f"{base}/secret-scanning/alerts",
                                         {"hide_secret": "true", "secret_type": GENERIC_TYPES})
        alerts = list({a.get("number"): a for a in (alerts or []) + (generic or [])}.values())
    if state == "failed":
        return {**record, "collected": False, "settings": settings}
    alerts = [alert_record(a, now) for a in alerts or []]
    open_alerts = [a for a in alerts if a["state"] == "open"]
    enabled = state is None  # disabled, or not on this plan: not scanning either way
    record.update({
        "collected": True,
        "settings": settings,
        "scanning_enabled": enabled,
        "push_protection_enabled": None if settings is None else settings["secret_scanning_push_protection"] == "enabled",
        "open_alerts": len(open_alerts),
        "open_active": [a["number"] for a in open_alerts if a["validity"] == "active"],
        "push_protection_bypasses": [a["number"] for a in alerts if a["push_protection_bypassed"]],
        "alerts": alerts,
    })
    return record


def summarize(records):
    done = [r for r in records if r["collected"]]
    open_alerts = [a for r in done for a in r["alerts"] if a["state"] == "open"]
    resolutions = {}
    for a in (a for r in done for a in r["alerts"] if a["state"] == "resolved"):
        resolutions[a["resolution"]] = resolutions.get(a["resolution"], 0) + 1
    return {
        "repositories_total": len(records),
        "not_collected": [r["repository"] for r in records if not r["collected"]],
        "settings_unreadable": [r["repository"] for r in records if r.get("settings") is None],
        "repositories_scanning_disabled": [r["repository"] for r in done if not r["scanning_enabled"]],
        "repositories_push_protection_disabled": [r["repository"] for r in done if r["push_protection_enabled"] is False],
        "open_total": len(open_alerts),
        "open_by_validity": {v: len([a for a in open_alerts if (a["validity"] or "unknown") == v])
                             for v in ("active", "inactive", "unknown")},
        "open_publicly_leaked": len([a for a in open_alerts if a["publicly_leaked"]]),
        "push_protection_bypasses": sum(len(r["push_protection_bypasses"]) for r in done),
        "oldest_open_days": max((a["age_days"] for a in open_alerts if a["age_days"] is not None), default=None),
        "resolved_by_resolution": resolutions,
    }


def collect(client, org, repos, config):
    now = now_epoch()
    records = [repo_record(client, org["login"], repo, now) for repo in repos]
    return {"metadata": {"as_of": iso(now)}, "summary": summarize(records), "repositories": records}


if __name__ == "__main__":
    sys.exit(run(NAME, collect))
