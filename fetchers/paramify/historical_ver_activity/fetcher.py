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
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
import ver_common as vc  # noqa: E402
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("paramify_historical_ver_activity")


def build_report(issues, cert_package_uri, generated_at):
    active, accepted = [], []
    for issue in issues:
        if vc.is_accepted(issue):
            accepted.append({
                "vulnerabilityDetail": vc.map_vulnerability_detail(issue),
                "acceptanceRationale": vc.acceptance_rationale(issue),
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

    vc.warn_unevaluated_backlog(
        issues, logger,
        "reported as active without evaluationCompletedAt",
    )

    report = build_report(issues, env["cert_package_uri"], env["generated_at"])
    report["_summary"] = vc.build_mrh_summary(
        report["activeVulnerabilities"], report["acceptedVulnerabilities"],
        env["generated_at"],
    )
    report["_summary"]["collection"] = vc.build_collection_status(api_failures)

    output_path = output_dir / f"paramify_historical_ver_activity_{vc.target_slug(env)}.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    s = report["_summary"]
    logger.info(
        "Evidence saved to %s (%d total: %d active, %d accepted; "
        "active overdue=%d, without-eval=%d)",
        output_path, s["totalVulnerabilities"], s["active"], s["accepted"],
        s["activeOverdue"], s["activeWithoutCompletedEvaluation"],
    )

    # /issues is the only call, so any failure means both arrays above are empty
    # for want of data -- NOT because the program has no vulnerabilities.
    # _summary.collection records that inside the payload.
    if api_failures:
        detail = "; ".join(
            f"{f.get('type')}: {f.get('message')}" for f in api_failures[:3]
        )
        report_failure(
            f"{len(api_failures)} Paramify API failure(s) reading issues for "
            f"project {env['project_id']}; the VER activity snapshot is incomplete "
            f"and its counts must not be read as a clean result: {detail}"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
