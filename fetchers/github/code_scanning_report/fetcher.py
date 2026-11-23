#!/usr/bin/env python3
"""Every open code scanning alert in the organization as one CSV row, for a Paramify vulnerability assessment.

Lists alerts per repository, as github_code_scanning_alerts does. GitHub lists the alerts of the default branch when
no ref is given. The columns are documented in README.md; the shared entry point is _shared/alert_report.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from alert_report import CONFIG, run_report  # noqa: E402,F401  (CONFIG: the settings the shape test checks)

NAME = "github_code_scanning_report"
KIND = "code-scanning/alerts"
COLUMNS = ["Title", "Severity", "Rule Severity", "Rule ID", "Rule Tags", "Tool", "Tool Version", "Message", "Path",
           "Start Line", "End Line", "Ref", "Commit SHA"]


def list_alerts(client, base):
    return client.paginate(f"{base}/code-scanning/alerts", {"state": "open"})


def row(alert):
    rule = alert.get("rule") or {}
    tool = alert.get("tool") or {}
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}
    return {
        "Title": rule.get("description") or rule.get("name") or rule.get("id"),
        # A security query has a security severity; a quality-only rule has its rule severity alone.
        "Severity": rule.get("security_severity_level") or rule.get("severity"),
        "Rule Severity": rule.get("severity"),
        "Rule ID": rule.get("id"),
        "Rule Tags": ", ".join(rule.get("tags") or []),
        "Tool": tool.get("name"),
        "Tool Version": tool.get("version"),
        "Message": (instance.get("message") or {}).get("text"),
        "Path": location.get("path"),
        "Start Line": location.get("start_line"),
        "End Line": location.get("end_line"),
        "Ref": instance.get("ref"),
        "Commit SHA": instance.get("commit_sha"),
    }


if __name__ == "__main__":
    sys.exit(run_report(NAME, KIND, list_alerts, row, COLUMNS))
