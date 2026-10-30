#!/usr/bin/env python3
"""
Demo comparator: a verdict per policy in demo_hello's synthetic evidence.

Shows the comparator mechanics with no credentials: the runner runs this after
demo_hello, hands it that file through $COMPARATOR_INPUTS, and wraps what it
writes like any other evidence. See `examples/demo_comparator.yaml`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))  # comparators/_lib

from comparator_inputs import run  # noqa: E402

INPUT = "demo_hello"
SUMMARY_KEYS = ("policies", "policies_enforced", "policies_not_enforced", "percent_enforced")


def check(inputs):
    results = [
        {
            "policy": p.get("policy"),
            "verdict": "enforced" if p.get("enabled") and p.get("applies_to") == "all-users"
            else "not_enforced",
        }
        for payload in inputs[INPUT].payloads
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


if __name__ == "__main__":
    raise SystemExit(run(check, output="demo_policy_check.json", summary_keys=SUMMARY_KEYS))
