#!/usr/bin/env python3
"""Collect all evaluated STIG postures for one policy, including errors and exceptions."""

import logging
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from qualys_client import QualysError, build_client, env_bool, report_failure
from reports import STIG_COLUMNS, collect_stig, write_report


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    client = None
    try:
        policy_id = os.environ.get("QUALYS_POLICY_ID", "").strip()
        if not re.fullmatch(r"[1-9]\d*", policy_id):
            raise QualysError(
                "QUALYS_POLICY_ID must be a positive integer", "bad_config"
            )
        allow_empty = env_bool("QUALYS_ALLOW_EMPTY")
        client = build_client()
        rows = collect_stig(client, policy_id)
        dest = (
            Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
            / f"qualys_stig_compliance_report_{policy_id}.csv"
        )
        write_report(dest, STIG_COLUMNS, rows, allow_empty)
        logging.info("Wrote %d STIG rows to %s", len(rows), dest)
        return 0
    except QualysError as exc:
        report_failure(str(exc), exc.code)
        return 1
    except Exception:
        report_failure(
            "Unexpected STIG collection or file-write failure", "internal_error"
        )
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
