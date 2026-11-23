"""The shared entry point for the GitHub alert reports: every open alert of one kind, as a CSV issue report.

A report fetcher names its alert kind, how to list one repository's open alerts, and the columns it adds; `run_report`
reads the target and the repositories as every GitHub fetcher does (github_client) and writes the report only when
every repository was read in full. Paramify closes each issue the latest report leaves out, so a partial report
would read as fixed alerts: any failure writes no file and exits non-zero.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from github_client import GitHubClient, file_suffix, list_repos, report_failures, repository_asset_id, start

# github_client puts fetchers/_lib on sys.path.
from fetcher_status import report_failure  # noqa: E402
from report_csv import write_csv  # noqa: E402

logger = logging.getLogger("github")

CONFIG = {"allow_empty": ("GITHUB_REPORT_ALLOW_EMPTY", False)}

# Every alert report opens with these. ID is the row's stable identity; Asset ID is the inventory's
# unique_asset_identifier for the repository, the column a vulnerability preset maps to Inventory.
COMMON_COLUMNS = ["ID", "Asset ID", "Repository", "Alert Number", "State", "Created At", "Updated At", "Alert URL"]

# (client, "repos/{org}/{name}") -> (state, alerts), as GitHubClient.paginate returns them.
ListAlerts = Callable[[GitHubClient, str], Tuple[Optional[str], Optional[List[dict]]]]


def open_alert_rows(client: GitHubClient, org: str, repos: List[dict], kind: str, list_alerts: ListAlerts,
                    row: Callable[[dict], Dict[str, Any]]) -> Tuple[List[dict], List[str]]:
    """(one row per open alert, sorted by ID; the repositories where the feature is off or not on the plan).

    A failed read is recorded on the client and adds no rows. A feature that is off is what the evidence fetchers
    report as disabled: those repositories add no rows and are not a failure.
    """
    rows: Dict[str, dict] = {}
    off: List[str] = []
    for repo in repos:
        state, alerts = list_alerts(client, f"repos/{org}/{repo['name']}")
        if state == "failed":
            continue
        if state is not None:
            off.append(repo["name"])
            continue
        asset = repository_asset_id(client.api_url, repo.get("id"))
        for alert in alerts or []:
            if alert.get("state") != "open":
                continue  # asked for open alerts only; a closed one is never in the report
            number = alert["number"]
            rows[f"{asset}/{kind}/{number}"] = {
                "ID": f"{asset}/{kind}/{number}",
                "Asset ID": asset,
                "Repository": repo.get("full_name") or f"{org}/{repo['name']}",
                "Alert Number": number,
                "State": "open",
                "Created At": alert.get("created_at"),
                "Updated At": alert.get("updated_at"),
                "Alert URL": alert.get("html_url"),
                **row(alert),
            }
    return [rows[key] for key in sorted(rows)], off


def run_report(name: str, kind: str, list_alerts: ListAlerts, row: Callable[[dict], Dict[str, Any]],
               columns: List[str]) -> int:
    """Run one alert report against the organization in the environment. Returns the exit code.

    `kind` is the alert's REST path under a repository (`dependabot/alerts`), which makes the row ID a URL that is
    unique per host, alert kind, repository and alert. `row(alert)` gives the values of `columns`.
    """
    started = start(CONFIG)
    if started is None:
        return 1
    target, settings = started
    client = GitHubClient(target["api_url"], target["token"])
    rows: List[dict] = []
    off: List[str] = []
    repos: Optional[List[dict]] = None
    try:
        org = client.get(f"orgs/{target['org']}")
        repos = list_repos(client, org, target["repositories"], target["include_archived"],
                           target["exclude_repositories"]) if org else None
        if repos is not None:
            rows, off = open_alert_rows(client, org["login"], repos, kind, list_alerts, row)
    except Exception as exc:  # noqa: BLE001 - an unexpected response must still fail with a reason
        logger.exception("collection failed")
        client.fail("collect", type(exc).__name__, str(exc), "internal_error")
    if off:
        logger.warning("%d repositories add no rows because the feature is off or not on their plan: %s",
                       len(off), ", ".join(off))
    if client.failures:
        return report_failures(client, ", no report written")
    if not rows and not settings["allow_empty"]:
        report_failure(f"no open alerts in {len(repos or [])} repositories ({len(off)} with the feature off); "
                       "an empty report closes every open issue, so set allow_empty true only after you check the "
                       "scope", "bad_config")
        return 1
    dest = Path(os.environ.get("EVIDENCE_DIR", "./evidence")) / f"{name}_{file_suffix(target)}.csv"
    try:
        write_csv(dest, COMMON_COLUMNS + columns, rows)
    except (OSError, ValueError) as exc:  # ValueError: a row with a column outside `columns`
        report_failure(f"could not write the report: {exc}", "internal_error")
        return 1
    logger.info("Report saved to %s (%d open alerts in %d repositories)", dest, len(rows), len(repos or []))
    return 0
