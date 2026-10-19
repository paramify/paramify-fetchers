#!/usr/bin/env python3
"""
Demo comparator: a verdict per policy in demo_hello's synthetic evidence.

Shows the comparator mechanics with no credentials: the runner runs this after
demo_hello, hands it that file through $COMPARATOR_INPUTS, and wraps what it
writes like any other evidence. See `examples/demo_comparator.yaml`.
"""

import json
import logging
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
sys.path.insert(0, str(SCRIPT_DIR.parents[2] / "fetchers" / "_lib"))

from comparator_inputs import build_payload, load_inputs  # noqa: E402
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("demo_policy_check")

INPUT = "demo_hello"
SUMMARY_KEYS = ("policies", "policies_enforced", "policies_not_enforced", "percent_enforced")


def check(payloads):
    results = [
        {
            "policy": p.get("policy"),
            "verdict": "enforced" if p.get("enabled") and p.get("applies_to") == "all-users"
            else "not_enforced",
        }
        for payload in payloads
        for p in payload.get("results", [])
    ]
    enforced = sum(1 for r in results if r["verdict"] == "enforced")
    summary = {
        "policies": len(results),
        "policies_enforced": enforced,
        "policies_not_enforced": len(results) - enforced,
        "percent_enforced": enforced * 100 // len(results) if results else 0,
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
            results, summary = check(inputs[INPUT].payloads)
        except Exception as exc:  # a failed input can hold a shape check() never expected; still write the file
            error = f"cannot check the input: {exc.__class__.__name__}: {exc}"

    output_path = output_dir / "demo_policy_check.json"
    with open(output_path, "w") as f:
        json.dump(build_payload(inputs, results, summary, error), f, indent=2, sort_keys=True)
    logger.info("Evidence saved to %s", output_path)

    if error:
        report_failure(error, "internal_error")
        return 1
    if not inputs.complete:
        report_failure(inputs.reason(), "input_failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
