"""
Shared logic for the Paramify FedRAMP VER-* report fetchers.

One source of truth for the three reports (VER-RPT-AVI, VER-RPT-VDT,
VER-TFR-MRH): the "accepted vulnerability" definition, the Paramify /issues
fetch + coverage rule, the epoch/sentinel evaluation-date handling, the
VDT field mapping (disposition, overdue, rating), the acceptance rationale,
the VER-TFR-EVU backlog warning, and the per-report _summary builders.

Consolidating here means the AVI/VDT partition can never drift: all three
fetchers import the SAME is_accepted() and map_vulnerability_detail(), so a
change is made once and applies everywhere.

Env reads (interim v0.x: fetchers read env directly; the runner sets these):
    PARAMIFY_API_TOKEN         (falls back to PARAMIFY_UPLOAD_API_TOKEN)
    PARAMIFY_PROJECT_ID
    PARAMIFY_CERT_PACKAGE_URI
    PARAMIFY_REPORT_FROM
    PARAMIFY_REPORT_TO         (optional; defaults to run time)
    PARAMIFY_API_BASE_URL      (optional; defaults to app.paramify.com/api/v0)
    PARAMIFY_HTTP_TIMEOUT      (optional; default 300s)
"""

import logging
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("paramify_ver_common")

# --- Shared "accepted" definition (AVI and VDT must agree exactly) ----------
ACCEPTED_DEVIATION_TYPES = (
    "OPERATIONAL_REQUIREMENT",
    "VENDOR_DEPENDENCY",
    "RISK_ADJUSTMENT",
)
ACCEPTED_STATUS = "ACCEPTED"
ACCEPTANCE_DAYS = 192  # VER-TFR-MAV
OPEN_ISSUE_STATUSES = ("OPEN",)
CLOSED_ISSUE_STATUSES = ("CLOSED",)

# Potential Agency Impact N-rating. INTERIM positional mapping (confirmed with
# the FedRAMP package owner). Absent level => no rating emitted.
LEVEL_TO_NRATING = {"CHILL": 1, "LOW": 2, "MODERATE": 3, "HIGH": 4, "CRITICAL": 5}

# Not emitted. FedRAMP's "Fully Mitigated" means the vulnerability is still
# detected but its impact is negligible, and no mapping from Paramify data to
# that state has been decided. Closed issues are no longer detected, so they
# are Remediated.
DISPOSITION_FULLY = "Fully Mitigated"
DISPOSITION_REMEDIATED = "Remediated"
DISPOSITION_PARTIALLY = "Partially Mitigated"
DISPOSITION_FALSE_POSITIVE = "False Positive"

# Paramify records some issues with a Unix-epoch evaluationDate
# ("1970-01-01T00:00:00.000Z"). An epoch (or otherwise implausibly ancient)
# timestamp is a missing-data sentinel, not a real evaluation event. Any date
# before this floor is treated as "no evaluation recorded".
MIN_PLAUSIBLE_EVALUATION = datetime(2000, 1, 1, tzinfo=timezone.utc)

# HTTP timeout (seconds) for Paramify API calls; override with
# PARAMIFY_HTTP_TIMEOUT. The unfiltered /issues call is large (~1.9 MB /
# ~75-120 s on a ~2k-issue project), so the shipped default failsafe is 300s.
DEFAULT_HTTP_TIMEOUT = 300


def http_timeout() -> int:
    """Per-request timeout, resolved at call time.

    Read lazily (not as an import-time constant) so a malformed value degrades to
    the default with a warning instead of aborting the run with a bare int()
    ValueError before main() can log anything useful.
    """
    raw = os.environ.get("PARAMIFY_HTTP_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_HTTP_TIMEOUT
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "PARAMIFY_HTTP_TIMEOUT=%r is not an integer; using the %ds default",
            raw, DEFAULT_HTTP_TIMEOUT,
        )
        return DEFAULT_HTTP_TIMEOUT


# --- Environment / API ------------------------------------------------------
# The single timestamp format every value in these reports is emitted in:
# UTC, second precision, literal Z ("2026-07-30T09:00:00Z"). RFC 3339, and the
# same shape the runner stamps into envelope metadata.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def resolve_common_env() -> Dict[str, str]:
    """Resolve the env every VER fetcher needs. Token falls back to the upload
    token name. Raises RuntimeError naming the first missing required var."""
    token = os.environ.get("PARAMIFY_API_TOKEN") or os.environ.get("PARAMIFY_UPLOAD_API_TOKEN")
    if not token:
        raise RuntimeError("Missing required env var: PARAMIFY_API_TOKEN (or PARAMIFY_UPLOAD_API_TOKEN)")
    now = current_timestamp()
    return {
        "token": token,
        "base_url": os.environ.get("PARAMIFY_API_BASE_URL", "https://app.paramify.com/api/v0"),
        "project_id": get_env("PARAMIFY_PROJECT_ID"),
        "cert_package_uri": get_env("PARAMIFY_CERT_PACKAGE_URI"),
        "report_from": get_env("PARAMIFY_REPORT_FROM"),
        "report_to": os.environ.get("PARAMIFY_REPORT_TO") or now,
        "generated_at": now,
        # Optional readable label for this program; only used for the filename.
        "program_name": os.environ.get("PARAMIFY_PROGRAM_NAME", ""),
    }


def sanitize_for_filename(value: str) -> str:
    """Make a target identifier safe for a filename (mirrors the gitlab fetcher).

    Fanout writes one file per program; the runner discovers outputs by diffing
    the evidence dir, so each invocation MUST write a distinct name or the second
    program silently overwrites the first and its outputs list comes back empty.
    """
    return re.sub(r"[^a-zA-Z0-9_-]", "_", str(value))


def target_slug(env: Dict[str, str]) -> str:
    """Filename discriminator for this target: the readable program name when the
    manifest supplied one, else the project UUID.

    Program names are not guaranteed unique in a workspace, so two same-named
    programs would collide on one filename -- and the runner's dir-diff output
    discovery would report the second invocation as having produced nothing. The
    UUID tail keeps every name distinct while staying readable.
    """
    name = (env.get("program_name") or "").strip()
    if not name:
        return sanitize_for_filename(env["project_id"])
    return f"{sanitize_for_filename(name)}_{sanitize_for_filename(env['project_id'])[:8]}"


def paramify_get(base_url: str, token: str, path: str, params: Dict[str, Any]) -> Any:
    url = f"{base_url.rstrip('/')}{path}"
    resp = requests.get(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
        params=params,
        timeout=http_timeout(),
    )
    resp.raise_for_status()
    return resp.json()


def _window_bounds(status_start: str, status_end: str) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Half-open [start, end) report window from two ISO strings.

    A date-only upper bound ("2026-06-30") means "through the end of that day",
    so it is pushed to the following midnight. A timestamped bound is used as
    given -- callers must NOT pre-truncate to 10 chars, or a timestamped
    report_to silently over-includes up to a day past the declared period.
    """
    start = _parse_iso(status_start)
    end = _parse_iso(status_end)
    if end is not None and len(status_end.strip()) == 10:
        end = end + timedelta(days=1)
    return start, end


def fetch_all_issues(
    base_url: str,
    token: str,
    project_id: str,
    status_start: str,
    status_end: str,
    api_failures: List[Dict[str, Any]],
) -> List[Dict]:
    """Fetch every issue in the project, then keep those that are OPEN (an open,
    unresolved vulnerability is ongoing activity regardless of when its status
    last changed) OR whose statusDate falls in the report window (captures
    closures/changes in the period).

    The /issues API has no status filter, and filtering the query by statusDate
    silently excluded open issues whose statusDate is missing or an epoch
    sentinel. Fetching by projectId alone and filtering in code closes that gap.
    Pagination is not documented on this endpoint; extend here if large projects
    turn out to paginate."""
    try:
        payload = paramify_get(base_url, token, "/issues", {"projectId": project_id})
    except requests.exceptions.RequestException as e:
        api_failures.append({"query": "all_issues", "type": type(e).__name__, "message": str(e)})
        return []
    issues = payload.get("issues", []) if isinstance(payload, dict) else []

    start, end = _window_bounds(status_start, status_end)

    def in_window(issue: Dict) -> bool:
        sd = _parse_iso(issue.get("statusDate"))
        if sd is None or start is None or end is None:
            return False
        return start <= sd < end

    return [i for i in issues if i.get("status") in OPEN_ISSUE_STATUSES or in_window(i)]


# --- Date handling ----------------------------------------------------------
def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def to_utc_z(value: Optional[str]) -> Optional[str]:
    """Normalize a timestamp to the one format these reports emit: UTC, second
    precision, literal Z -- "2026-07-30T09:00:00Z".

    Every instant in a report goes through here. Paramify returns milliseconds
    ("2026-02-01T00:00:00.000Z") and config may supply a bare date, so passing
    values straight through produced a document mixing three notations. Offsets
    are converted to UTC rather than preserved, so "…T09:00:00+02:00" emits as
    "…T07:00:00Z".

    Unparseable input is returned unchanged: dropping or blanking a value the
    source gave us is worse than an off-format one, and schema verification is
    the right place for that to surface.
    """
    if not value:
        return value
    parsed = _parse_iso(value)
    if parsed is None:
        return value
    return parsed.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def report_period_bounds(report_from: str, report_to: str) -> Tuple[str, str]:
    """The reportPeriod as declared in a report: both ends in to_utc_z() form.

    A date-only bound is reported as that day's last second rather than its
    midnight, because a date-only end means "through the end of that day" to the
    coverage filter (see _window_bounds). Emitting "2026-06-30T00:00:00Z" for a
    window that collected all of June 30 would understate the period in a
    compliance artifact by a day.
    """
    end_day = _parse_iso(report_to) if report_to and len(report_to.strip()) == 10 else None
    end = (
        (end_day + timedelta(days=1, seconds=-1)).strftime(TIMESTAMP_FORMAT)
        if end_day is not None else (to_utc_z(report_to) or report_to)
    )
    return to_utc_z(report_from) or report_from, end


def effective_evaluation_date(issue: Dict) -> Optional[datetime]:
    """Real completed-evaluation date, or None when missing, unparseable, or a
    pre-2000 sentinel (e.g. Unix epoch)."""
    evaluated = _parse_iso(issue.get("evaluationDate"))
    if evaluated is None or evaluated < MIN_PLAUSIBLE_EVALUATION:
        return None
    return evaluated


# --- Accepted-vulnerability test (shared by AVI + VDT) ----------------------
def _accepted_deviations(issue: Dict, types: Tuple[str, ...]) -> List[Dict]:
    """Deviations of the given types that have actually been ACCEPTED. A pending
    or rejected deviation is a request, not a decision."""
    return [
        d for d in issue.get("deviations", [])
        if d.get("type") in types
        and (d.get("deviationMetadata") or {}).get("status") == ACCEPTED_STATUS
    ]


def accepted_deviation(issue: Dict) -> Optional[Dict]:
    """The most recently accepted qualifying deviation, or None."""
    return max(
        _accepted_deviations(issue, ACCEPTED_DEVIATION_TYPES),
        key=lambda d: (d.get("deviationMetadata") or {}).get("acceptanceStatusDate") or "",
        default=None,
    )


def is_192_day_accepted(issue: Dict, now: Optional[datetime] = None) -> bool:
    """VER-TFR-MAV: open AND evaluated 192+ days ago. Missing/sentinel evaluation
    dates mean no evaluation happened, so the clock has not started."""
    if issue.get("status") not in OPEN_ISSUE_STATUSES:
        return False
    evaluated = effective_evaluation_date(issue)
    if evaluated is None:
        return False
    now = now or datetime.now(timezone.utc)
    return (now - evaluated).days >= ACCEPTANCE_DAYS


def is_accepted(issue: Dict) -> bool:
    """Accepted deviation OR 192-day-open. The single partition test."""
    return accepted_deviation(issue) is not None or is_192_day_accepted(issue)


def acceptance_rationale(issue: Dict) -> str:
    """Rationale text from the qualifying accepted deviation, or a default.

    Shared by AVI and MRH: both wrap an accepted issue in the same
    {vulnerabilityDetail, acceptanceRationale} object, so the text must match.
    """
    dev = accepted_deviation(issue)
    if dev and dev.get("description"):
        return dev["description"]
    if is_192_day_accepted(issue):
        return "Open beyond the VER-TFR-MAV 192-day threshold without full mitigation."
    return "Accepted vulnerability."


# --- VDT field derivations --------------------------------------------------
def _final_disposition(issue: Dict) -> Optional[str]:
    """False Positive (accepted FP deviation) > Remediated (closed) >
    Partially Mitigated (open with accepted risk-adjustment or milestone) > omit.
    Milestones are read from the `milestones` array embedded in the /issues
    response -- no per-issue calls."""
    if _accepted_deviations(issue, ("FALSE_POSITIVE",)):
        return DISPOSITION_FALSE_POSITIVE
    if issue.get("status") in CLOSED_ISSUE_STATUSES:
        return DISPOSITION_REMEDIATED
    if issue.get("status") in OPEN_ISSUE_STATUSES and (
        _accepted_deviations(issue, ("RISK_ADJUSTMENT",)) or issue.get("milestones")
    ):
        return DISPOSITION_PARTIALLY
    return None


def _overdue_status(issue: Dict, now: Optional[datetime] = None) -> Dict:
    """INTERIM: open past dueDate => overdue (explanation required by schema)."""
    if issue.get("status") not in OPEN_ISSUE_STATUSES:
        return {"isOverdue": False}
    due = _parse_iso(issue.get("dueDate"))
    if due is None:
        return {"isOverdue": False}
    now = now or datetime.now(timezone.utc)
    if now > due:
        return {
            "isOverdue": True,
            "explanation": (
                f"Open past its remediation due date "
                f"({due.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)}); "
                "not yet fully mitigated or remediated."
            ),
        }
    return {"isOverdue": False}


def map_vulnerability_detail(issue: Dict) -> Dict:
    """Build one FedRAMP vulnerabilityDetail object (used by VDT + MRH active,
    and wrapped for AVI/MRH accepted)."""
    origin = issue.get("origin") or {}
    detail: Dict[str, Any] = {
        # An issue carrying neither identifier is a source-data defect; emit it
        # empty so schema verification flags the record, rather than raising a
        # KeyError that kills the whole report.
        "providerTrackingId": issue.get("poamId") or issue.get("id") or "",
        "detection": {
            # Normalized, not passed through: the API returns milliseconds.
            "detectedAt": to_utc_z(issue.get("createdAt")),
            "detectionSource": origin.get("name") or "Unspecified",
        },
        "vulnerabilityDescription": issue.get("description") or issue.get("title") or "",
    }
    if issue.get("internetReachableVulnerability") is not None:
        detail["isInternetReachable"] = issue["internetReachableVulnerability"]
    if issue.get("likelyExploitableVulnerability") is not None:
        detail["isLikelyExploitable"] = issue["likelyExploitableVulnerability"]
    evaluated = effective_evaluation_date(issue)
    if evaluated is not None:
        detail["evaluationCompletedAt"] = evaluated.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)
    rating = LEVEL_TO_NRATING.get(issue.get("level"))
    if rating is not None:
        detail["currentRating"] = rating
    detail["overdueStatus"] = _overdue_status(issue)
    disposition = _final_disposition(issue)
    if disposition is not None:
        detail["finalDisposition"] = disposition
    return detail


# --- Shared reporting helpers -----------------------------------------------
def warn_unevaluated_backlog(
    issues: List[Dict], log: logging.Logger, consequence: str
) -> List[Dict]:
    """Log the VER-TFR-EVU open-but-never-evaluated backlog; return it.

    Open, not deviation-accepted, and with no plausible evaluationDate: the
    VER-TFR-MAV 192-day clock never started for these, so each report states
    what it did with them via `consequence`.
    """
    unevaluated = [
        i for i in issues
        if i.get("status") in OPEN_ISSUE_STATUSES
        and effective_evaluation_date(i) is None
        and accepted_deviation(i) is None
    ]
    if unevaluated:
        log.warning(
            "%d open issue(s) have no real completed-evaluation date "
            "(missing or epoch sentinel); %s "
            "(VER-TFR-EVU: evaluate within 5 days of detection).",
            len(unevaluated), consequence,
        )
    return unevaluated


def build_collection_status(api_failures: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Collection outcome, carried inside the report's own _summary.

    House pattern (20+ fetchers): a failed collection still writes its evidence
    file with the failure ledger inside it. That matters twice over here -- a
    dropped /issues call yields EMPTY report arrays, and the uploader's
    skip_failed defaults to false, so without this block an empty failed report
    is indistinguishable from a genuinely clean one to anything reading the
    payload alone.
    """
    return {
        "status": "failed" if api_failures else "success",
        "apiFailures": api_failures,
    }


# --- _summary builders (vendor extension carried in the payload) ------------
DISPOSITION_IN_PROGRESS = "In Progress"


def _detail_counts(details: List[Dict]) -> Dict[str, Any]:
    """Disposition / overdue / unevaluated tallies over mapped vulnerabilityDetails.

    Shared by VDT and MRH, which count identically and differ only in the key
    names they file the result under. Keyed off the DISPOSITION_* constants the
    emitter uses, so renaming a label can't leave the summaries reporting zeros.
    """
    disp = Counter(v.get("finalDisposition", DISPOSITION_IN_PROGRESS) for v in details)
    return {
        "dispositions": {
            "fullyMitigated": disp[DISPOSITION_FULLY],
            "remediated": disp[DISPOSITION_REMEDIATED],
            "partiallyMitigated": disp[DISPOSITION_PARTIALLY],
            "falsePositive": disp[DISPOSITION_FALSE_POSITIVE],
            "inProgress": disp[DISPOSITION_IN_PROGRESS],
        },
        "overdue": sum(1 for v in details if (v.get("overdueStatus") or {}).get("isOverdue") is True),
        "withoutCompletedEvaluation": sum(1 for v in details if "evaluationCompletedAt" not in v),
    }


def build_vdt_summary(vulns: List[Dict], report_from: str, report_to: str) -> Dict:
    counts = _detail_counts(vulns)
    return {
        "report": "VER-RPT-VDT",
        "reportPeriod": {"from": report_from, "to": report_to},
        "nonAcceptedVulnerabilities": len(vulns),
        "dispositions": counts["dispositions"],
        "overdue": counts["overdue"],
        "notOverdue": len(vulns) - counts["overdue"],
        "withoutCompletedEvaluation": counts["withoutCompletedEvaluation"],
    }


def build_avi_summary(accepted: List[Dict], report_from: str, report_to: str) -> Dict:
    with_eval = sum(1 for a in accepted if a["vulnerabilityDetail"].get("evaluationCompletedAt"))
    return {
        "report": "VER-RPT-AVI",
        "reportPeriod": {"from": report_from, "to": report_to},
        "acceptedVulnerabilities": len(accepted),
        "withCompletedEvaluation": with_eval,
        "withoutCompletedEvaluation": len(accepted) - with_eval,
    }


def build_mrh_summary(active: List[Dict], accepted: List[Dict], generated_at: str) -> Dict:
    counts = _detail_counts(active)
    return {
        "report": "VER-TFR-MRH",
        "generatedAt": generated_at,
        "totalVulnerabilities": len(active) + len(accepted),
        "active": len(active),
        "accepted": len(accepted),
        "activeDispositions": counts["dispositions"],
        "activeOverdue": counts["overdue"],
        "activeWithoutCompletedEvaluation": counts["withoutCompletedEvaluation"],
    }
