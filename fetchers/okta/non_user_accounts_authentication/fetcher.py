#!/usr/bin/env python3
"""
Non-User Accounts Authentication

Thin wrapper around okta_iam_core.py that runs only this collector and outputs a dedicated JSON file.
"""

import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Import okta_iam_core from the category's _shared/ directory, and the shared
# failure-reporting helper from fetchers/_lib/ (same mechanism, one level up).
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402
from okta_iam_core import OktaIAMEvidenceFetcher  # type: ignore

logger = logging.getLogger("okta_non_user_accounts_authentication")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    skip_check = "--skip-check" in sys.argv

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    fetcher = OktaIAMEvidenceFetcher(skip_compatibility_check=skip_check)
    evidence = fetcher.collect_non_user_accounts_authentication()

    output_path = output_dir / "okta_non_user_accounts_authentication.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Evidence saved to %s", output_path)

    if fetcher.client.api_failures:
        failures = fetcher.client.api_failures
        summary = "; ".join(
            f"{f.get('endpoint', '?')}: {f.get('type', '')} {f.get('message', '')}".strip()
            for f in failures[:3]
        )
        report_failure(
            f"{len(failures)} Okta API call(s) failed during collection - {summary}",
            "partial_failure",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
