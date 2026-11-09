#!/usr/bin/env python3
"""
KSI-CMT-LMC / FedRAMP SCN: GitLab Significant Change Notifications

Finds merge requests that engineering flagged as a FedRAMP significant change,
parses the SCN section of the MR description, and emits one FedRAMP-schema-valid
Significant Change Notification per flagged MR.

Flow:
  1. List MRs for one project in the lookback window (paginated).
  2. Keep the ones whose description carries a TICKED marker checkbox
     (`- [x] Significant Change — SCN required`), or the configured GitLab label.
  3. Slice out the SCN section and parse it two ways, in priority order:
       a. SCHEMA MARKERS — Paramify's change-request template annotates each
          field with its schema key, e.g. "**Reason for Change** *(`reason`)*".
          That annotation is authoritative: it is impossible to misread and it
          survives anyone renaming the human-facing label.
       b. HEADINGS — for templates without those annotations, `### Reason for
          Change` and `**Key:** value` lines are mapped by name. Only fills
          fields (a) did not.
  4. Assemble an SCN per MR and validate it against the vendored FedRAMP schema
     (fetchers/_lib/schemas/fedramp_scn_2026-06-24.json, parsed by fetchers/_lib/fedramp_scn.py).
  5. Write ONE evidence file holding the array of SCNs plus per-MR provenance.

Single-target per invocation; fanout across projects happens at the runner layer
(see fetcher.yaml: supports_targets: true).

Note on shape: the runner discovers evidence by diffing EVIDENCE_DIR and wraps
every .json it finds in the standard envelope. So this fetcher writes exactly one
file — N separate SCN files would each get enveloped and stop being schema-valid
FedRAMP documents. Each element of payload.notifications[].scn is a verbatim,
schema-valid SCN object that a downstream step can lift out and submit as-is.

Unfilled template placeholders (`YYYY-MM-DD`, `KSI-XXX-XXX`, `N/A`, …) are dropped
rather than emitted, and each drop is recorded in parse_notes. A notification that
says nothing is better evidence than one that says "YYYY-MM-DD".
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from dotenv import load_dotenv
from jsonschema import Draft202012Validator

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

# The SCN parser and FedRAMP schema validator are shared with github_significant_change_notifications.
from fedramp_scn import (  # noqa: E402
    MARKER_RE,
    ROUTINE_RECURRING_RE,
    SCHEMA_ID,
    SCHEMA_PATH,
    SCN_CSO_INF_REQUIREMENTS,
    UNTICKED_MARKER_RE,
    assess_completeness,
    build_scn,
    clean_uri_value,
    current_timestamp,
    extract_section,
    get_env,
    load_validator,
    parse_change_request_form,
    sanitize_for_filename,
    strip_comments,
    validate_scn,
)
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("gitlab_significant_change_notifications")

# --- GitLab collection ----------------------------------------------------------


class GitLabClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.api = f"{base_url.rstrip('/')}/api/v4"
        self.headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}
        self.failures: List[Dict[str, Any]] = []

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
        url = f"{self.api}{path}"
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            self.failures.append({"path": path, "type": type(e).__name__, "message": str(e)})
            return None
        if resp.status_code != 200:
            self.failures.append(
                {"path": path, "type": "HTTPError", "message": f"{resp.status_code} {resp.text[:200]}"}
            )
            return None
        return resp

    def list_merge_requests(
        self, project: str, state: str, days_back: int, max_results: int, labels: str
    ) -> List[Dict[str, Any]]:
        encoded = quote(project, safe="")
        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat().replace("+00:00", "Z")
        params: Dict[str, Any] = {
            "state": state,
            "order_by": "updated_at",
            "sort": "desc",
            "per_page": 100,
            "page": 1,
            "updated_after": since,
        }
        if labels:
            params["labels"] = labels

        out: List[Dict[str, Any]] = []
        while len(out) < max_results:
            resp = self.get(f"/projects/{encoded}/merge_requests", params)
            if resp is None:
                break
            page = resp.json()
            out.extend(page)
            if len(page) < 100 or len(out) >= max_results:
                break
            next_page = resp.headers.get("x-next-page") or resp.headers.get("X-Next-Page")
            if not next_page:
                break
            params["page"] = int(next_page)
        return out[:max_results]

    def approvals(self, project: str, iid: int) -> Dict[str, Any]:
        encoded = quote(project, safe="")
        resp = self.get(f"/projects/{encoded}/merge_requests/{iid}/approvals")
        return resp.json() if resp is not None else {}


def is_marked(description: str, mr: Dict[str, Any], marker_label: str) -> Tuple[bool, Optional[str]]:
    """Marked = ticked checkbox, or the configured GitLab label is present."""
    if marker_label:
        labels = [l.lower() for l in (mr.get("labels") or [])]
        if marker_label.lower() in labels:
            return True, "label"
    if MARKER_RE.search(description or ""):
        return True, "checkbox"
    return False, None


def collect(
    client: GitLabClient,
    project: str,
    state: str,
    days_back: int,
    max_results: int,
    marker_label: str,
    section_heading: str,
    cert_uri: str,
    validator: Draft202012Validator,
) -> Dict[str, Any]:
    mrs = client.list_merge_requests(project, state, days_back, max_results, marker_label)

    notifications: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for mr in mrs:
        description = strip_comments(mr.get("description") or "")
        marked, via = is_marked(description, mr, marker_label)
        if not marked:
            if UNTICKED_MARKER_RE.search(description):
                routine = bool(ROUTINE_RECURRING_RE.search(description))
                skipped.append(
                    {
                        "iid": mr.get("iid"),
                        "title": mr.get("title"),
                        "web_url": mr.get("web_url"),
                        "routine_recurring_declared": routine,
                        "reason": (
                            "author declared the change Routine Recurring (SCN-RTR) — no notification required"
                            if routine
                            else "significant-change checkbox present but not ticked, and no routine-recurring declaration"
                        ),
                    }
                )
            continue

        section = extract_section(description, section_heading)
        iid = mr.get("iid")
        approvals = client.approvals(project, iid) if iid is not None else {}
        form = parse_change_request_form(description)

        provenance = {
            # Stable across runs: a weekly run with a 30-day window re-emits the
            # same MR four times, and whatever submits these needs to recognize
            # them as one notification rather than four.
            "notification_id": f"SCN-{sanitize_for_filename(project)}-{iid}",
            "iid": iid,
            "title": mr.get("title"),
            "state": mr.get("state"),
            "author": (mr.get("author") or {}).get("name"),
            "author_username": (mr.get("author") or {}).get("username"),
            "created_at": mr.get("created_at"),
            "merged_at": mr.get("merged_at"),
            "merged_by": (mr.get("merged_by") or {}).get("name") if mr.get("merged_by") else None,
            "merge_commit_sha": mr.get("merge_commit_sha") or mr.get("sha"),
            "source_branch": mr.get("source_branch"),
            "target_branch": mr.get("target_branch"),
            "web_url": mr.get("web_url"),
            "labels": mr.get("labels") or [],
            "marked_via": via,
            "approvers": [
                (a.get("user") or {}).get("name") for a in (approvals.get("approved_by") or [])
            ],
            "approvals_required": approvals.get("approvals_required", 0),
            "change_request_form": form,
        }

        if section is None:
            notifications.append(
                {
                    "merge_request": provenance,
                    "scn": None,
                    "validation": {
                        "valid": False,
                        "errors": [f"no '{section_heading}' section found in the MR description"],
                    },
                    "completeness": {
                        "complete": False,
                        "missing": [
                            {"field": f, "requirement": r} for f, r in SCN_CSO_INF_REQUIREMENTS
                        ],
                    },
                    "parse_notes": [
                        "MR is marked as a significant change but has no "
                        f"'{section_heading}' section to read"
                    ],
                }
            )
            continue

        scn, extras, notes = build_scn(section, description, cert_uri, mr.get("title") or "")
        errors = validate_scn(validator, scn)
        completeness = assess_completeness(scn, extras)
        if form.get("emergency_change"):
            notes.append("flagged as an Emergency Change — SCN-CSO-EMG applies, not the standard path")

        entry: Dict[str, Any] = {
            "merge_request": provenance,
            "scn": scn,
            "validation": {"valid": not errors, "errors": errors},
            "completeness": completeness,
            "parse_notes": notes,
        }
        if extras.get("approver"):
            entry["approver"] = extras["approver"]
        notifications.append(entry)

    valid_count = sum(1 for n in notifications if n["validation"]["valid"])
    by_type: Dict[str, int] = {}
    for n in notifications:
        change_type = (n.get("scn") or {}).get("changeType") or "unspecified"
        by_type[change_type] = by_type.get(change_type, 0) + 1

    return {
        "merge_requests_scanned": len(mrs),
        "notifications": notifications,
        "skipped_unticked": skipped,
        "summary": {
            "flagged_count": len(notifications),
            "schema_valid_count": valid_count,
            "schema_invalid_count": len(notifications) - valid_count,
            "by_change_type": by_type,
            "unticked_marker_count": len(skipped),
            "routine_recurring_count": sum(1 for s in skipped if s.get("routine_recurring_declared")),
            "emergency_change_count": sum(
                1
                for n in notifications
                if n["merge_request"]["change_request_form"].get("emergency_change")
            ),
            "notifications_with_parse_notes": sum(1 for n in notifications if n["parse_notes"]),
            "scn_cso_inf_complete_count": sum(1 for n in notifications if n["completeness"]["complete"]),
            "scn_cso_inf_incomplete_count": sum(1 for n in notifications if not n["completeness"]["complete"]),
        },
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

    config_warnings: List[str] = []
    try:
        gitlab_url = get_env("GITLAB_URL")
        api_token = get_env("GITLAB_API_TOKEN")
        project_id = get_env("GITLAB_PROJECT_ID")
        # One workspace publishes one Certification Package Overview, and the
        # paramify VER fetchers already read it from PARAMIFY_CERT_PACKAGE_URI
        # (see fetchers/_categories/paramify.yaml). Accept that as the shared
        # source so a single manifest line drives every artifact that carries
        # certificationPackageOverviewUri. FEDRAMP_CERT_PACKAGE_URI still wins
        # when set, for a run deliberately targeting a different offering.
        fedramp_uri = clean_uri_value(os.environ.get("FEDRAMP_CERT_PACKAGE_URI", "").strip())
        paramify_uri = clean_uri_value(os.environ.get("PARAMIFY_CERT_PACKAGE_URI", "").strip())

        cert_uri = fedramp_uri or paramify_uri
        cert_uri_source = "FEDRAMP_CERT_PACKAGE_URI" if fedramp_uri else "PARAMIFY_CERT_PACKAGE_URI"
        if not cert_uri:
            raise RuntimeError(
                "Missing required env var: set FEDRAMP_CERT_PACKAGE_URI, or "
                "PARAMIFY_CERT_PACKAGE_URI (platforms.paramify.config.cert_package_uri) "
                "to share one Certification Package Overview URI across every fetcher"
            )

        # Both set and disagreeing is ambiguous, and the quiet resolution is the
        # dangerous one: this URI goes into every notification FedRAMP keeps, so
        # silently picking the wrong document produces permanently wrong records.
        # It is NOT fatal — a run targeting a different service offering sets
        # them differently on purpose — but it is never something to swallow.
        # The usual cause is a stale FEDRAMP_CERT_PACKAGE_URI in a developer .env
        # overriding the manifest, since load_dotenv reads .env directly and
        # bypasses the environment the runner controls.
        if fedramp_uri and paramify_uri and fedramp_uri != paramify_uri:
            config_warnings.append(
                "Two different Certification Package Overview URIs are configured. "
                f"Using FEDRAMP_CERT_PACKAGE_URI ({fedramp_uri}); "
                f"PARAMIFY_CERT_PACKAGE_URI says ({paramify_uri}). "
                "Every notification in this run cites the first. If that is not "
                "deliberate, the usual cause is a stale FEDRAMP_CERT_PACKAGE_URI "
                "in a .env overriding the manifest."
            )
    except RuntimeError as e:
        report_failure(str(e), "bad_config")
        return 1

    state = os.environ.get("GITLAB_SCN_STATE", "merged")
    days_back = int(os.environ.get("GITLAB_SCN_DAYS_BACK", "30"))
    max_results = int(os.environ.get("GITLAB_SCN_MAX_RESULTS", "100"))
    marker_label = os.environ.get("GITLAB_SCN_MARKER_LABEL", "").strip()
    section_heading = os.environ.get("GITLAB_SCN_SECTION_HEADING", "Significant Change").strip()
    strict = os.environ.get("GITLAB_SCN_STRICT", "true").strip().lower() not in ("false", "0", "no")
    require_complete = os.environ.get(
        "GITLAB_SCN_REQUIRE_COMPLETE", "true"
    ).strip().lower() not in ("false", "0", "no")

    validator = load_validator()
    client = GitLabClient(gitlab_url, api_token)
    result = collect(
        client, project_id, state, days_back, max_results,
        marker_label, section_heading, cert_uri, validator,
    )

    evidence = {
        "metadata": {
            "project_id": project_id,
            "project_name": project_id.split("/")[-1] if "/" in project_id else project_id,
            "project_group": project_id.split("/")[0] if "/" in project_id else "unknown",
            "gitlab_url": gitlab_url,
            "fedramp_schema_id": SCHEMA_ID,
            "fedramp_schema_version": json.loads(SCHEMA_PATH.read_text()).get("$schemaVersion"),
            "certification_package_overview_uri": cert_uri,
            "certification_package_overview_uri_source": cert_uri_source,
            "section_heading": section_heading,
            "marker_label": marker_label or None,
            "state_filter": state,
            "days_back": days_back,
            "strict": strict,
            "require_scn_cso_inf_complete": require_complete,
            "scan_timestamp": current_timestamp(),
        },
        "status": "success" if not client.failures else "error",
        "config_warnings": config_warnings,
        **result,
        "api_failures": client.failures,
        "retrieved_at": current_timestamp(),
    }

    output_path = output_dir / f"gitlab_significant_change_notifications_{sanitize_for_filename(project_id)}.json"
    output_path.write_text(json.dumps(evidence, indent=2, default=str))
    for w in config_warnings:
        logger.warning("%s", w)
    logger.info("Evidence saved to %s", output_path)

    # Last line on stderr wins: the runner reads its tail into the envelope's
    # metadata.error. Everything below must log AFTER the "Evidence saved" line.
    if client.failures:
        reason = f"{len(client.failures)} GitLab API failures during collection"
        report_failure(reason, "partial_failure")
        return 1

    invalid = result["summary"]["schema_invalid_count"]
    if invalid and strict:
        iids = [n["merge_request"]["iid"] for n in result["notifications"] if not n["validation"]["valid"]]
        reason = (
            f"{invalid} merge request(s) marked as significant changes did not produce a "
            f"schema-valid FedRAMP SCN: MR {', '.join('!' + str(i) for i in iids)}"
        )
        report_failure(reason, "partial_failure")
        return 1

    # Schema-valid is a low bar: FedRAMP's schema requires three properties, while
    # SCN-CSO-INF asks for a dozen. A notification can validate cleanly and still
    # name no impacted controls, no dates, and no approver — which is the version
    # a reviewer rejects. Failing here is the difference between "well-formed" and
    # "worth sending".
    incomplete = [n for n in result["notifications"] if not n["completeness"]["complete"]]
    if incomplete and require_complete:
        detail = "; ".join(
            "MR !{}: missing {}".format(
                n["merge_request"]["iid"],
                ", ".join(m["field"] for m in n["completeness"]["missing"]),
            )
            for n in incomplete
        )
        reason = (
            f"{len(incomplete)} schema-valid notification(s) are incomplete under "
            f"SCN-CSO-INF — {detail}"
        )
        report_failure(reason, "partial_failure")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
