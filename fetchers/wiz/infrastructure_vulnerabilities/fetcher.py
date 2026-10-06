#!/usr/bin/env python3
"""
Wiz Infrastructure Vulnerabilities

Open Wiz vulnerability findings on infrastructure assets, summarized by severity, CISA
KEV exposure, fix availability, and age against the remediation window.

Wiz returns host, container and code findings from one query; the split into
this fetcher's bucket happens in _shared/vuln_summary.py on the asset type Wiz
reports. `scope.findings_by_bucket` in the evidence shows how every finding was
bucketed, so nothing is dropped silently.

Speaks to KSI-SVC-EIS. Read it together with wiz_scan_coverage: zero findings
only means something if the assets are being scanned.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import WizClient, collect_guarded, evidence, run_fetcher  # type: ignore  # noqa: E402
from vuln_summary import collect_bucket  # type: ignore  # noqa: E402

logger = logging.getLogger("wiz_infrastructure_vulnerabilities")


def body(client: WizClient) -> Dict[str, Any]:
    result = collect_bucket(client, "infrastructure")
    include = os.environ.get("WIZ_INCLUDE_RAW_FINDINGS", "true").strip().lower() not in {"false", "0", "no"}
    return evidence(
        client=client,
        operations=["vulnerabilityFindings"],
        records=result["rows"],
        analysis=result["analysis"],
        empty_message="No open infrastructure vulnerability findings. Check wiz_scan_coverage before "
                      "reading this as a clean result.",
        include_records=include,
        scope=result["scope"],
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_infrastructure_vulnerabilities.json", logger))
