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
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
import ver_common as vc  # noqa: E402
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("paramify_accepted_vulnerabilities")


def build_report(issues, cert_package_uri, report_from, report_to):
    accepted = [
        {
            "vulnerabilityDetail": vc.map_vulnerability_detail(i),
            "acceptanceRationale": vc.acceptance_rationale(i),
        }
        for i in issues if vc.is_accepted(i)
    ]
    return {
        "certificationPackageOverviewUri": cert_package_uri,
        "reportPeriod": {"from": report_from, "to": report_to},
        "acceptedVulnerabilities": accepted,
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()  # interim v0.x: fetcher loads .env itself

    try:
        env = vc.resolve_common_env()
    except RuntimeError as e:
        report_failure(str(e), "bad_config")
        return 1
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    api_failures = []
    issues = vc.fetch_all_issues(
        env["base_url"], env["token"], env["project_id"],
        env["report_from"], env["report_to"], api_failures,
    )

    # Visibility: open issues with no real completed evaluation (VER-TFR-EVU).
    vc.warn_unevaluated_backlog(
        issues, logger,
        "excluded from VER-TFR-MAV time-based acceptance",
    )

    # Declared period in the report's own timestamp format. The RAW env values
    # still drive fetch_all_issues above -- normalizing before the window is
    # computed would turn a date-only bound into a midnight instant and silently
    # drop that day's closures.
    period_from, period_to = vc.report_period_bounds(env["report_from"], env["report_to"])

    report = build_report(
        issues, env["cert_package_uri"], period_from, period_to
    )
    report["_summary"] = vc.build_avi_summary(
        report["acceptedVulnerabilities"], period_from, period_to
    )
    report["_summary"]["collection"] = vc.build_collection_status(api_failures)

    output_path = output_dir / f"paramify_accepted_vulnerabilities_{vc.target_slug(env)}.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    s = report["_summary"]
    logger.info(
        "Evidence saved to %s (%d accepted; %d with eval date, %d without)",
        output_path, s["acceptedVulnerabilities"],
        s["withCompletedEvaluation"], s["withoutCompletedEvaluation"],
    )

    # Exit non-zero if collection encountered API failures (repo convention).
    # /issues is the only call, so any failure means the report arrays above are
    # empty for want of data -- NOT because the program has no accepted
    # vulnerabilities. _summary.collection records that inside the payload.
    if api_failures:
        detail = "; ".join(
            f"{f.get('type')}: {f.get('message')}" for f in api_failures[:3]
        )
        report_failure(
            f"{len(api_failures)} Paramify API failure(s) reading issues for "
            f"project {env['project_id']}; the accepted-vulnerability report is "
            f"incomplete and its counts must not be read as a clean result: {detail}"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
