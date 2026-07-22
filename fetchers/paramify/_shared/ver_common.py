"""
Shared logic for the Paramify FedRAMP VER-* report fetchers.

One source of truth for the three reports (VER-RPT-AVI, VER-RPT-VDT,
VER-TFR-MRH): the "accepted vulnerability" definition, the Paramify /issues
fetch + coverage rule, the epoch/sentinel evaluation-date handling, the
VDT field mapping (disposition, overdue, rating), and the per-report
_summary builders.

Consolidating here means the AVI/VDT partition can never drift: all three
fetchers import the SAME is_accepted() and map_issue(), so a change is made
once and applies everywhere.

Env reads (interim v0.x: fetchers read env directly; the runner sets these):
    PARAMIFY_API_TOKEN         (falls back to PARAMIFY_UPLOAD_API_TOKEN)
    PARAMIFY_PROJECT_ID
    PARAMIFY_CERT_PACKAGE_URI
    PARAMIFY_REPORT_FROM
    PARAMIFY_REPORT_TO         (optional; defaults to run time)
    PARAMIFY_API_BASE_URL      (optional; defaults to app.paramify.com/api/v0)
    PARAMIFY_HTTP_TIMEOUT      (optional; default 300s)
"""

import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

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

DISPOSITION_FULLY = "Fully Mitigated"
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
HTTP_TIMEOUT = int(os.environ.get("PARAMIFY_HTTP_TIMEOUT", "300"))


# --- Environment / API ------------------------------------------------------
def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    }


def paramify_get(base_url: str, token: str, path: str, params: Dict[str, Any]) -> Any:
    url = f"{base_url.rstrip('/')}{path}"
    resp = requests.get(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
        params=params,
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


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

    start = _parse_iso(status_start)
    end = _parse_iso(status_end)
    if end is not None and len(status_end) == 10:
        end = end + timedelta(days=1)  # date-only bound -> inclusive of that day

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


def _effective_evaluation_date(issue: Dict) -> Optional[datetime]:
    """Real completed-evaluation date, or None when missing, unparseable, or a
    pre-2000 sentinel (e.g. Unix epoch)."""
    evaluated = _parse_iso(issue.get("evaluationDate"))
    if evaluated is None or evaluated < MIN_PLAUSIBLE_EVALUATION:
        return None
    return evaluated


# --- Accepted-vulnerability test (shared by AVI + VDT) ----------------------
def _accepted_deviation(issue: Dict) -> Optional[Dict]:
    qualifying = [
        d for d in issue.get("deviations", [])
        if d.get("type") in ACCEPTED_DEVIATION_TYPES
        and (d.get("deviationMetadata") or {}).get("status") == ACCEPTED_STATUS
    ]
    if not qualifying:
        return None
    qualifying.sort(
        key=lambda d: (d.get("deviationMetadata") or {}).get("acceptanceStatusDate") or "",
        reverse=True,
    )
    return qualifying[0]


def _is_192_day_accepted(issue: Dict, now: Optional[datetime] = None) -> bool:
    """VER-TFR-MAV: open AND evaluated 192+ days ago. Missing/sentinel evaluation
    dates mean no evaluation happened, so the clock has not started."""
    if issue.get("status") not in OPEN_ISSUE_STATUSES:
        return False
    evaluated = _effective_evaluation_date(issue)
    if evaluated is None:
        return False
    now = now or datetime.now(timezone.utc)
    return (now - evaluated).days >= ACCEPTANCE_DAYS


def is_accepted(issue: Dict) -> bool:
    """Accepted deviation OR 192-day-open. The single partition test."""
    return _accepted_deviation(issue) is not None or _is_192_day_accepted(issue)


# --- VDT field derivations --------------------------------------------------
def _false_positive_deviation(issue: Dict) -> bool:
    return any(
        d.get("type") == "FALSE_POSITIVE"
        and (d.get("deviationMetadata") or {}).get("status") == ACCEPTED_STATUS
        for d in issue.get("deviations", [])
    )


def _has_risk_adjustment(issue: Dict) -> bool:
    return any(d.get("type") == "RISK_ADJUSTMENT" for d in issue.get("deviations", []))


def _final_disposition(issue: Dict) -> Optional[str]:
    """False Positive (accepted FP deviation) > Fully Mitigated (closed) >
    Partially Mitigated (open with risk-adjustment or milestone) > omit.
    Milestones are read from the `milestones` array embedded in the /issues
    response -- no per-issue calls."""
    if _false_positive_deviation(issue):
        return DISPOSITION_FALSE_POSITIVE
    if issue.get("status") in CLOSED_ISSUE_STATUSES:
        return DISPOSITION_FULLY
    if issue.get("status") in OPEN_ISSUE_STATUSES:
        if _has_risk_adjustment(issue) or issue.get("milestones"):
            return DISPOSITION_PARTIALLY
    return None


def _overdue_status(issue: Dict, now: Optional[datetime] = None) -> Optional[Dict]:
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
                f"Open past its remediation due date ({issue.get('dueDate')}); "
                "not yet fully mitigated or remediated."
            ),
        }
    return {"isOverdue": False}


def map_vulnerability_detail(issue: Dict) -> Dict:
    """Build one FedRAMP vulnerabilityDetail object (used by VDT + MRH active,
    and wrapped for AVI/MRH accepted)."""
    origin = issue.get("origin") or {}
    detail: Dict[str, Any] = {
        "providerTrackingId": issue.get("poamId") or issue["id"],
        "detection": {
            "detectedAt": issue.get("createdAt"),
            "detectionSource": origin.get("name") or "Unspecified",
        },
        "vulnerabilityDescription": issue.get("description") or issue.get("title") or "",
    }
    if issue.get("internetReachableVulnerability") is not None:
        detail["isInternetReachable"] = issue["internetReachableVulnerability"]
    if issue.get("likelyExploitableVulnerability") is not None:
        detail["isLikelyExploitable"] = issue["likelyExploitableVulnerability"]
    if _effective_evaluation_date(issue) is not None:
        detail["evaluationCompletedAt"] = issue["evaluationDate"]
    rating = LEVEL_TO_NRATING.get(issue.get("level"))
    if rating is not None:
        detail["currentRating"] = rating
    overdue = _overdue_status(issue)
    if overdue is not None:
        detail["overdueStatus"] = overdue
    disposition = _final_disposition(issue)
    if disposition is not None:
        detail["finalDisposition"] = disposition
    return detail


# --- _summary builders (vendor extension carried in the payload) ------------
def build_vdt_summary(vulns: List[Dict], report_from: str, report_to: str) -> Dict:
    disp = Counter(v.get("finalDisposition", "In Progress") for v in vulns)
    overdue = sum(1 for v in vulns if (v.get("overdueStatus") or {}).get("isOverdue") is True)
    no_eval = sum(1 for v in vulns if "evaluationCompletedAt" not in v)
    return {
        "report": "VER-RPT-VDT",
        "reportPeriod": {"from": report_from, "to": report_to},
        "nonAcceptedVulnerabilities": len(vulns),
        "dispositions": {
            "fullyMitigated": disp.get("Fully Mitigated", 0),
            "partiallyMitigated": disp.get("Partially Mitigated", 0),
            "falsePositive": disp.get("False Positive", 0),
            "inProgress": disp.get("In Progress", 0),
        },
        "overdue": overdue,
        "notOverdue": len(vulns) - overdue,
        "withoutCompletedEvaluation": no_eval,
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
    disp = Counter(v.get("finalDisposition", "In Progress") for v in active)
    overdue = sum(1 for v in active if (v.get("overdueStatus") or {}).get("isOverdue") is True)
    no_eval = sum(1 for v in active if "evaluationCompletedAt" not in v)
    return {
        "report": "VER-TFR-MRH",
        "generatedAt": generated_at,
        "totalVulnerabilities": len(active) + len(accepted),
        "active": len(active),
        "accepted": len(accepted),
        "activeDispositions": {
            "fullyMitigated": disp.get("Fully Mitigated", 0),
            "partiallyMitigated": disp.get("Partially Mitigated", 0),
            "falsePositive": disp.get("False Positive", 0),
            "inProgress": disp.get("In Progress", 0),
        },
        "activeOverdue": overdue,
        "activeWithoutCompletedEvaluation": no_eval,
    }
