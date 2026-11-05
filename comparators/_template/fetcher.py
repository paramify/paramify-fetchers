#!/usr/bin/env python3
"""
<KSI or control reference>: <short title>

<One paragraph: which claim needs both inputs, and how a record in one is
matched to a record in the other.>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))  # comparators/_lib

from comparator_inputs import run  # noqa: E402

LEFT = "<input_fetcher_a>"
RIGHT = "<input_fetcher_b>"
# Every key the summary has when the inputs are compared; all of them are null when one is missing.
SUMMARY_KEYS = ("records", "matched", "unmatched", "percent_matched")


def check(inputs):
    """Verdicts only: each result names what it matched, never a copy of an input record."""
    right_ids = {r["id"] for p in inputs[RIGHT].payloads for r in p.get("results", [])}
    results = [
        {"id": r["id"], "verdict": "matched" if r["id"] in right_ids else "unmatched"}
        for p in inputs[LEFT].payloads
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


if __name__ == "__main__":
    raise SystemExit(run(check, output="<category>_<short_name>.json", summary_keys=SUMMARY_KEYS))
