#!/usr/bin/env python3
"""FedRAMP Marketplace certification status for a configured list of vendor packages."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from marketplace import (  # noqa: E402
    CollectionError,
    Marketplace,
    fail,
    output_mode_from_env,
    parse_pairs,
    write_outputs,
)

logger = logging.getLogger("fedramp_marketplace_vendor_certification_status")

FILE_STEM = "fedramp_marketplace_vendor_certification_status"


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))

    try:
        output_mode = output_mode_from_env()
        vendors = parse_pairs(os.environ.get("FEDRAMP_VENDORS", ""), "FEDRAMP_VENDORS")
        if not vendors:
            raise CollectionError(
                "FEDRAMP_VENDORS is empty: list vendors as 'Vendor Name=PACKAGE_ID, ...'", "bad_config"
            )
        market = Marketplace.load()
        records = [market.record(name, package_id, source="config") for name, package_id in vendors]
        paths = write_outputs(output_dir, FILE_STEM, records, market, output_mode, vendor_source="config")
    except CollectionError as exc:
        return fail(output_dir, FILE_STEM, str(exc), exc.code, "load FedRAMP marketplace data")
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still reportable
        return fail(
            output_dir, FILE_STEM, f"Unexpected error: {type(exc).__name__}: {exc}", "internal_error",
            "build vendor certification evidence",
        )

    for path in paths:
        logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
