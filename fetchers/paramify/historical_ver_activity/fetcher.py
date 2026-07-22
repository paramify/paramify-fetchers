#!/usr/bin/env python3
"""
VER-TFR-MRH: Paramify Historical VER Activity (snapshot)

Point-in-time snapshot containing BOTH partitions in one document:
    activeVulnerabilities    -- all non-accepted vulnerabilities (VER-RPT-VDT fields)
    acceptedVulnerabilities  -- all accepted vulnerabilities (VER-RPT-AVI fields)

Contains no acceptance logic of its own: it partitions a SINGLE issue fetch
using the shared accepted definition in _shared/ver_common.py, so the two arrays
are consistent by construction (same issue set, same instant) and can never
disagree with the individually generated AVI/VDT reports.

Output: $EVIDENCE_DIR/paramify_historical_ver_activity.json
Env: PARAMIFY_API_TOKEN (or PARAMIFY_UPLOAD_API_TOKEN), PARAMIFY_PROJECT_ID,
     PARAMIFY_CERT_PACKAGE_URI, PARAMIFY_REPORT_FROM, PARAMIFY_REPORT_TO (opt),
     PARAMIFY_API_BASE_URL (opt), PARAMIFY_HTTP_TIMEOUT (opt).
"""

import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
import ver_common as vc  # noqa: E402

logger = logging.getLogger("paramify_historical_ver_activity")


def _acceptance_rationale(issue):
    dev = vc._accepted_deviation(issue)
    if dev and dev.get("description"):
        return dev["description"]
    if vc._is_192_day_accepted(issue):
        return "Open beyond the VER-TFR-MAV 192-day threshold without full mitigation."
    return "Accepted vulnerability."


def build_report(issues, cert_package_uri, generated_at):
    active, accepted = [], []
    for issue in issues:
        if vc.is_accepted(issue):
            accepted.append({
                "vulnerabilityDetail": vc.map_vulnerability_detail(issue),
                "acceptanceRationale": _acceptance_rationale(issue),
            })
        else:
            active.append(vc.map_vulnerability_detail(issue))
    return {
        "certificationPackageOverviewUri": cert_package_uri,
        "generatedAt": generated_at,
        "activeVulnerabilities": active,
        "acceptedVulnerabilities": accepted,
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    env = vc.resolve_common_env()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    api_failures = []
    issues = vc.fetch_all_issues(
        env["base_url"], env["token"], env["project_id"],
        env["report_from"][:10], env["report_to"][:10], api_failures,
    )

    unevaluated = [
        i for i in issues
        if i.get("status") in vc.OPEN_ISSUE_STATUSES
        and vc._effective_evaluation_date(i) is None
        and vc._accepted_deviation(i) is None
    ]
    if unevaluated:
        logger.warning(
            "%d open issue(s) have no real completed-evaluation date "
            "(missing or epoch sentinel); reported as active without "
            "evaluationCompletedAt (VER-TFR-EVU: evaluate within 5 days).",
            len(unevaluated),
        )

    report = build_report(issues, env["cert_package_uri"], env["generated_at"])
    report["_summary"] = vc.build_mrh_summary(
        report["activeVulnerabilities"], report["acceptedVulnerabilities"],
        env["generated_at"],
    )

    output_path = output_dir / "paramify_historical_ver_activity.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    s = report["_summary"]
    logger.info(
        "Evidence saved to %s (%d total: %d active, %d accepted; "
        "active overdue=%d, without-eval=%d)",
        output_path, s["totalVulnerabilities"], s["active"], s["accepted"],
        s["activeOverdue"], s["activeWithoutCompletedEvaluation"],
    )

    if api_failures:
        logger.error("%d API failure(s) during collection", len(api_failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
