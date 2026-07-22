#!/usr/bin/env python3
"""
VER-RPT-AVI: Paramify Accepted Vulnerability Info

Generates the FedRAMP 20x Accepted Vulnerability Info report from Paramify
issues. An issue is an accepted vulnerability if it has an accepted deviation
(OPERATIONAL_REQUIREMENT / VENDOR_DEPENDENCY / RISK_ADJUSTMENT) or is open 192+
days past a real completed evaluation (VER-TFR-MAV). Issues with a missing or
epoch-sentinel evaluation date are NOT time-accepted (the 192-day clock never
started) and are surfaced as an unevaluated-backlog warning (VER-TFR-EVU).

Output: $EVIDENCE_DIR/paramify_accepted_vulnerabilities.json
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

logger = logging.getLogger("paramify_accepted_vulnerabilities")


def build_report(issues, cert_package_uri, report_from, report_to):
    accepted = [
        {"vulnerabilityDetail": vc.map_vulnerability_detail(i), "acceptanceRationale":
            _acceptance_rationale(i)}
        for i in issues if vc.is_accepted(i)
    ]
    return {
        "certificationPackageOverviewUri": cert_package_uri,
        "reportPeriod": {"from": report_from, "to": report_to},
        "acceptedVulnerabilities": accepted,
    }


def _acceptance_rationale(issue):
    """Rationale text from the qualifying accepted deviation, or a default."""
    dev = vc._accepted_deviation(issue)
    if dev and dev.get("description"):
        return dev["description"]
    if vc._is_192_day_accepted(issue):
        return "Open beyond the VER-TFR-MAV 192-day threshold without full mitigation."
    return "Accepted vulnerability."


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()  # interim v0.x: fetcher loads .env itself

    env = vc.resolve_common_env()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    api_failures = []
    issues = vc.fetch_all_issues(
        env["base_url"], env["token"], env["project_id"],
        env["report_from"][:10], env["report_to"][:10], api_failures,
    )

    # Visibility: open issues with no real completed evaluation (VER-TFR-EVU).
    unevaluated = [
        i for i in issues
        if i.get("status") in vc.OPEN_ISSUE_STATUSES
        and vc._effective_evaluation_date(i) is None
        and vc._accepted_deviation(i) is None
    ]
    if unevaluated:
        logger.warning(
            "%d open issue(s) have no real completed-evaluation date "
            "(missing or epoch sentinel); excluded from VER-TFR-MAV time-based "
            "acceptance (VER-TFR-EVU: evaluate within 5 days of detection).",
            len(unevaluated),
        )

    report = build_report(
        issues, env["cert_package_uri"], env["report_from"], env["report_to"]
    )
    report["_summary"] = vc.build_avi_summary(
        report["acceptedVulnerabilities"], env["report_from"], env["report_to"]
    )

    output_path = output_dir / "paramify_accepted_vulnerabilities.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    s = report["_summary"]
    logger.info(
        "Evidence saved to %s (%d accepted; %d with eval date, %d without)",
        output_path, s["acceptedVulnerabilities"],
        s["withCompletedEvaluation"], s["withoutCompletedEvaluation"],
    )

    # Exit non-zero if collection encountered API failures (repo convention).
    if api_failures:
        logger.error("%d API failure(s) during collection", len(api_failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
