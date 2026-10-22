#!/usr/bin/env python3
"""
<KSI or control reference>: <short title>

<One paragraph: what this fetcher collects and why.>
"""

import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent

# The shared failure-reporting helper. Import it, never paste a copy: printing
# the nine-line version in this template is how 26 private copies under three
# different names happened. See docs/fetcher_contract_guide.md, step 6.
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

# If this fetcher relies on a category-shared module, uncomment:
# sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
# from <shared_module> import <EntryClass>

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("<category>_<short_name>")

# report_failure(reason, code) on every path that returns non-zero. It logs the
# reason AND writes $FETCHER_STATUS_FILE, so it is the whole failure path -- you
# do not also need a logger.error. Call it AFTER any "Evidence saved" line: the
# runner's fallback takes the tail of stderr, so a success message logged last
# becomes the failure reason an operator reads.
#
# `code` is optional and must be one of exactly these:
#     auth_failed, not_authorized, target_unreachable, rate_limited,
#     bad_config, partial_failure, internal_error
# Anything else is dropped with a warning. (There is no not_enabled: a service
# that is not in use is valid evidence and exits 0, so it reports no failure.)


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself and reads env directly.
    # Runner + secret resolver will replace this when the framework lands.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # Replace with the actual data-collection call.
    evidence: dict = {}

    output_path = output_dir / "<category>_<short_name>.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Evidence saved to %s", output_path)

    # Exit code is the ONLY failure signal the runner reads — it never looks inside
    # the payload. Non-zero for any failed call or precondition, and say why:
    #
    #     if api_failures:
    #         report_failure(f"{len(api_failures)} API calls failed", "partial_failure")
    #         return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
