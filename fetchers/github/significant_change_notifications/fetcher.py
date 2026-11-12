#!/usr/bin/env python3
"""FedRAMP significant change notifications from GitHub pull requests flagged as significant changes."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
import fedramp_scn as scn  # noqa: E402  (shared with gitlab_significant_change_notifications)
from github_client import iso, now_epoch, run, to_epoch  # noqa: E402

NAME = "github_significant_change_notifications"
CONFIG = {
    "days_back": ("GITHUB_SCN_DAYS_BACK", 30),
    "state": ("GITHUB_SCN_STATE", "merged"),
    "marker_label": ("GITHUB_SCN_MARKER_LABEL", ""),
    "section_heading": ("GITHUB_SCN_SECTION_HEADING", "Significant Change"),
    "strict": ("GITHUB_SCN_STRICT", True),
    "require_scn_cso_inf_complete": ("GITHUB_SCN_REQUIRE_COMPLETE", True),
    "fedramp_cert_package_uri": ("FEDRAMP_CERT_PACKAGE_URI", ""),
    "cert_package_uri": ("PARAMIFY_CERT_PACKAGE_URI", ""),
}
STATES = {"merged": "[MERGED]", "open": "[OPEN]", "closed": "[CLOSED]", "all": "[OPEN, CLOSED, MERGED]"}
MAX_DAYS_BACK = 366
PULL_REQUESTS = """
query($owner: String!, $name: String!, $first: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: %s, orderBy: {field: UPDATED_AT, direction: DESC}, first: $first, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number title body state url createdAt updatedAt mergedAt baseRefName headRefName
        author { login }
        mergedBy { login }
        mergeCommit { oid }
        labels(first: 50) { nodes { name } }
      }
    }
  }
}"""


def cert_uri(config):
    """(uri, source, warnings). FEDRAMP_CERT_PACKAGE_URI wins; the shared Paramify setting is the fallback."""
    fedramp = scn.clean_uri_value(config["fedramp_cert_package_uri"].strip())
    paramify = scn.clean_uri_value(config["cert_package_uri"].strip())
    warnings = []
    if fedramp and paramify and fedramp != paramify:
        # Not fatal (a run for another offering differs on purpose), never swallowed: the URI goes into every
        # notification FedRAMP keeps.
        warnings.append(f"Two different Certification Package Overview URIs are configured. Using "
                        f"FEDRAMP_CERT_PACKAGE_URI ({fedramp}); PARAMIFY_CERT_PACKAGE_URI says ({paramify}).")
    return (fedramp or paramify), ("FEDRAMP_CERT_PACKAGE_URI" if fedramp else "PARAMIFY_CERT_PACKAGE_URI"), warnings


def approvers(client, org, repo, number):
    """Each reviewer whose latest decisive review approved. None when unreadable."""
    reviews = client.paginate_required(f"repos/{org}/{repo}/pulls/{number}/reviews")
    if reviews is None:
        return None
    latest = {}
    for r in reviews:
        login = (r.get("user") or {}).get("login")
        if login and r.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[login] = r.get("state")
    return sorted(login for login, state in latest.items() if state == "APPROVED")


def notification(client, org, repo, pr, config, uri, validator):
    """One flagged pull request as a notification, in the GitLab fetcher's shape with GitHub's provenance."""
    description = scn.strip_comments(pr.get("body") or "")
    labels = [n.get("name") for n in (pr.get("labels") or {}).get("nodes") or [] if n.get("name")]
    approved = approvers(client, org, repo, pr["number"])
    provenance = {
        # Stable across runs: a weekly run over a 30-day window sees the same pull request four times.
        "notification_id": f"SCN-{scn.sanitize_for_filename(f'{org}/{repo}')}-{pr['number']}",
        "repository": repo,
        "number": pr["number"],
        "title": pr.get("title"),
        "state": pr.get("state"),
        "author": (pr.get("author") or {}).get("login"),
        "created_at": pr.get("createdAt"),
        "merged_at": pr.get("mergedAt"),
        "merged_by": (pr.get("mergedBy") or {}).get("login"),
        "merge_commit_sha": (pr.get("mergeCommit") or {}).get("oid"),
        "source_branch": pr.get("headRefName"),
        "target_branch": pr.get("baseRefName"),
        "url": pr.get("url"),
        "labels": labels,
        "marked_via": "label" if config["marker_label"] and config["marker_label"].lower() in
        [x.lower() for x in labels] else "checkbox",
        "approvers": approved,
        "change_request_form": scn.parse_change_request_form(description),
    }
    section = scn.extract_section(description, config["section_heading"])
    if section is None:
        return {"pull_request": provenance, "scn": None,
                "validation": {"valid": False,
                               "errors": [f"no '{config['section_heading']}' section found in the description"]},
                "completeness": {"complete": False, "missing": [{"field": f, "requirement": r}
                                                                for f, r in scn.SCN_CSO_INF_REQUIREMENTS]},
                "parse_notes": [f"marked as a significant change but has no '{config['section_heading']}' section"]}
    body, extras, notes = scn.build_scn(section, description, uri, pr.get("title") or "")
    errors = scn.validate_scn(validator, body)
    if provenance["change_request_form"].get("emergency_change"):
        notes.append("flagged as an Emergency Change — SCN-CSO-EMG applies, not the standard path")
    entry = {"pull_request": provenance, "scn": body, "validation": {"valid": not errors, "errors": errors},
             "completeness": scn.assess_completeness(body, extras), "parse_notes": notes}
    if extras.get("approver"):
        entry["approver"] = extras["approver"]
    return entry


def ref(n):
    return f"{n['pull_request']['repository']}#{n['pull_request']['number']}"


def collect(client, org, repos, config):
    login = org["login"]
    uri, source, warnings = cert_uri(config)
    state = config["state"].strip().lower()
    problems = ([] if uri else ["set FEDRAMP_CERT_PACKAGE_URI, or PARAMIFY_CERT_PACKAGE_URI to share one "
                                "Certification Package Overview URI across fetchers"]) + \
        ([] if state in STATES else [f"GITHUB_SCN_STATE must be one of {', '.join(STATES)}, got {state!r}"]) + \
        ([] if 1 <= config["days_back"] <= MAX_DAYS_BACK else [f"GITHUB_SCN_DAYS_BACK must be 1..{MAX_DAYS_BACK}"])
    if problems:
        for p in problems:
            client.fail("config", "BadConfig", p, "bad_config")
        return None
    validator = scn.load_validator()
    since = now_epoch() - config["days_back"] * 86400
    query = PULL_REQUESTS % STATES[state]
    notifications, skipped, scanned, unreadable = [], [], 0, []
    for repo in repos:
        name = repo["name"]
        nodes = client.graphql_nodes(f"GraphQL pullRequests repos/{login}/{name}", query,
                                     {"owner": login, "name": name},
                                     lambda d: (d.get("repository") or {}).get("pullRequests"),
                                     until=lambda n: (to_epoch(n.get("updatedAt")) or since) < since)
        if nodes is None:
            unreadable.append(name)
            continue
        scanned += len(nodes)
        for pr in nodes:
            description = scn.strip_comments(pr.get("body") or "")
            labels = [(n.get("name") or "").lower() for n in (pr.get("labels") or {}).get("nodes") or []]
            if not (config["marker_label"] and config["marker_label"].lower() in labels) \
                    and not scn.MARKER_RE.search(description):
                if scn.UNTICKED_MARKER_RE.search(description):
                    routine = bool(scn.ROUTINE_RECURRING_RE.search(description))
                    skipped.append({"repository": name, "number": pr.get("number"), "title": pr.get("title"),
                                    "url": pr.get("url"), "routine_recurring_declared": routine})
                continue
            notifications.append(notification(client, login, name, pr, config, uri, validator))
    valid = [n for n in notifications if n["validation"]["valid"]]
    incomplete = [n for n in notifications if not n["completeness"]["complete"]]
    if config["strict"] and len(valid) < len(notifications):
        client.fail("validate notifications", "SchemaInvalid",
                    "flagged as significant changes without a schema-valid FedRAMP SCN: "
                    + ", ".join(ref(n) for n in notifications if not n["validation"]["valid"]), "partial_failure")
    if config["require_scn_cso_inf_complete"] and incomplete:
        client.fail("check SCN-CSO-INF", "IncompleteNotification", "; ".join(
            f"{ref(n)}: missing {', '.join(m['field'] for m in n['completeness']['missing'])}" for n in incomplete),
            "partial_failure")
    by_type = {}
    for n in notifications:
        kind = (n.get("scn") or {}).get("changeType") or "unspecified"
        by_type[kind] = by_type.get(kind, 0) + 1
    return {
        "metadata": {"since": iso(since), "fedramp_schema_id": scn.SCHEMA_ID,
                     "fedramp_schema_version": json.loads(scn.SCHEMA_PATH.read_text()).get("$schemaVersion"),
                     "certification_package_overview_uri": uri,
                     "certification_package_overview_uri_source": source, "config_warnings": warnings},
        # The GitLab fetcher's summary keys, so one validator reads either platform.
        "summary": {
            "pull_requests_scanned": scanned,
            "flagged_count": len(notifications),
            "schema_valid_count": len(valid),
            "schema_invalid_count": len(notifications) - len(valid),
            "by_change_type": by_type,
            "unticked_marker_count": len(skipped),
            "routine_recurring_count": sum(1 for s in skipped if s["routine_recurring_declared"]),
            "emergency_change_count": sum(1 for n in notifications
                                          if n["pull_request"]["change_request_form"].get("emergency_change")),
            "notifications_with_parse_notes": sum(1 for n in notifications if n["parse_notes"]),
            "scn_cso_inf_complete_count": len(notifications) - len(incomplete),
            "scn_cso_inf_incomplete_count": len(incomplete),
            "approvers_unreadable": sorted(ref(n) for n in notifications if n["pull_request"]["approvers"] is None),
            "not_collected": unreadable,
        },
        "notifications": notifications,
        "skipped_unticked": skipped,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
