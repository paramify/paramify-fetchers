#!/usr/bin/env python3
"""Every open secret scanning alert in the organization as one CSV row, for a Paramify vulnerability assessment.

Never the secret: alerts are requested with hide_secret (github_client.secret_scanning_alerts, shared with
github_secret_scanning), and row() copies only the metadata fields it names, so a secret GitHub sent anyway is
never read. The columns are documented in README.md; the shared entry point is _shared/alert_report.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from alert_report import CONFIG, run_report  # noqa: E402,F401  (CONFIG: the settings the shape test checks)
from github_client import secret_scanning_alerts  # noqa: E402

NAME = "github_secret_scanning_report"
KIND = "secret-scanning/alerts"
COLUMNS = ["Title", "Secret Type", "Validity", "Publicly Leaked", "Multi Repo", "Push Protection Bypassed",
           "Location Path", "Location Line", "Has More Locations"]


def list_alerts(client, base):
    return secret_scanning_alerts(client, base, {"state": "open"})


def row(alert):
    """Metadata only. Never add a field that holds the secret or part of it (`secret`, or a location's text)."""
    location = alert.get("first_location_detected") or {}
    return {
        "Title": alert.get("secret_type_display_name") or alert.get("secret_type"),
        "Secret Type": alert.get("secret_type"),
        "Validity": alert.get("validity"),
        "Publicly Leaked": alert.get("publicly_leaked"),
        "Multi Repo": alert.get("multi_repo"),
        "Push Protection Bypassed": bool(alert.get("push_protection_bypassed")
                                         or alert.get("push_protection_bypassed_by")),
        "Location Path": location.get("path"),
        "Location Line": location.get("start_line"),
        "Has More Locations": alert.get("has_more_locations"),
    }


if __name__ == "__main__":
    sys.exit(run_report(NAME, KIND, list_alerts, row, COLUMNS))
