#!/usr/bin/env python3
"""
<KSI or control reference>: <short title>

<One paragraph: which claim needs both inputs, and how a record in one is
matched to a record in the other.>
"""

import json
import logging
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))  # comparators/_lib
sys.path.insert(0, str(SCRIPT_DIR.parents[2] / "fetchers" / "_lib"))  # report_failure

from comparator_inputs import build_payload, load_inputs  # noqa: E402
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("<category>_<short_name>")

LEFT = "<input_fetcher_a>"
RIGHT = "<input_fetcher_b>"
# Every key the summary has when inputs are present; all of them are null when one is missing.
SUMMARY_KEYS = ("records", "matched", "unmatched", "percent_matched")


def compare(left_payloads, right_payloads):
    """Verdicts only: each result names what it matched, never a copy of an input record."""
    right_ids = {r["id"] for p in right_payloads for r in p.get("results", [])}
    results = [
        {"id": r["id"], "verdict": "matched" if r["id"] in right_ids else "unmatched"}
        for p in left_payloads
        for r in p.get("results", [])
    ]
    matched = sum(1 for r in results if r["verdict"] == "matched")
    summary = {
        "records": len(results),
        "matched": matched,
        "unmatched": len(results) - matched,
        "percent_matched": matched * 100 // len(results) if results else 0,
    }
    return results, summary


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        inputs = load_inputs()
    except (RuntimeError, OSError, ValueError) as exc:
        report_failure(f"cannot read the comparator input index: {exc}", "internal_error")
        return 1

    results, summary, error = [], dict.fromkeys(SUMMARY_KEYS), None
    if not inputs.missing:
        try:
            results, summary = compare(inputs[LEFT].payloads, inputs[RIGHT].payloads)
        except Exception as exc:  # a failed input can hold a shape compare() never expected; still write the file
            error = f"cannot compare the inputs: {exc.__class__.__name__}: {exc}"

    output_path = output_dir / "<category>_<short_name>.json"
    with open(output_path, "w") as f:
        json.dump(build_payload(inputs, results, summary, error), f, indent=2, sort_keys=True)
    logger.info("Evidence saved to %s", output_path)

    # After the "saved" line, so the reason is the last thing on stderr.
    if error:
        report_failure(error, "internal_error")
        return 1
    if not inputs.complete:
        report_failure(inputs.reason(), "input_failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
