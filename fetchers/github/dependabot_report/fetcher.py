#!/usr/bin/env python3
"""Every open Dependabot alert in the organization as one CSV row, for a Paramify vulnerability assessment.

Lists alerts per repository, as github_dependabot_alerts does, because the organization list omits repositories with
alerts off. The columns are documented in README.md; the shared entry point is _shared/alert_report.py.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from alert_report import CONFIG, run_report  # noqa: E402,F401  (CONFIG: the settings the shape test checks)

NAME = "github_dependabot_report"
KIND = "dependabot/alerts"
COLUMNS = ["Title", "Severity", "GHSA ID", "CVE ID", "CVSS Score", "CVSS Vector", "EPSS Percentage", "CWE IDs",
           "Package", "Ecosystem", "Manifest Path", "Dependency Scope", "Vulnerable Versions",
           "First Patched Version", "Description"]


def list_alerts(client, base):
    return client.paginate(f"{base}/dependabot/alerts", {"state": "open"})


def cvss(advisory):
    """CVSS v4, then v3 (cvss_severities), then the older single cvss field: the first that has a score."""
    severities = advisory.get("cvss_severities") or {}
    for entry in (severities.get("cvss_v4"), severities.get("cvss_v3"), advisory.get("cvss")):
        if entry and entry.get("score"):
            return entry.get("score"), entry.get("vector_string")
    return None, None


def row(alert):
    advisory = alert.get("security_advisory") or {}
    vuln = alert.get("security_vulnerability") or {}
    dep = alert.get("dependency") or {}
    package = dep.get("package") or vuln.get("package") or {}
    score, vector = cvss(advisory)
    return {
        "Title": advisory.get("summary"),
        "Severity": vuln.get("severity") or advisory.get("severity"),
        "GHSA ID": advisory.get("ghsa_id"),
        "CVE ID": advisory.get("cve_id"),
        "CVSS Score": score,
        "CVSS Vector": vector,
        "EPSS Percentage": (advisory.get("epss") or {}).get("percentage"),
        "CWE IDs": ", ".join(c["cwe_id"] for c in advisory.get("cwes") or [] if c.get("cwe_id")),
        "Package": package.get("name"),
        "Ecosystem": package.get("ecosystem"),
        "Manifest Path": dep.get("manifest_path"),
        "Dependency Scope": dep.get("scope"),
        "Vulnerable Versions": vuln.get("vulnerable_version_range"),
        "First Patched Version": (vuln.get("first_patched_version") or {}).get("identifier"),
        "Description": advisory.get("description"),
    }


if __name__ == "__main__":
    sys.exit(run_report(NAME, KIND, list_alerts, row, COLUMNS))
