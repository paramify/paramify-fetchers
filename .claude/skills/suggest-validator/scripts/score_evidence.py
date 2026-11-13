#!/usr/bin/env python3
"""Run registry validators against a real evidence file.

`paramify validators check` runs the synthetic case files. This runs the same
ECMAScript engine against actual evidence — the step that says whether the
tenant meets the claim, once the cases prove the validator can fail.

    python .claude/skills/suggest-validator/scripts/score_evidence.py \
        evidence/run-.../aws_s3_encryption_status.json --select s3_buckets_all_encrypted
    python .claude/skills/suggest-validator/scripts/score_evidence.py <file> --select EVD-S3-ENC

`--select` takes a validator key or an evidence-set reference id; omit it and
every validator whose `evidence_sets` matches the file's own
`metadata.evidence_set.reference_id` is run, which is the set Paramify would
apply. Reports each validator's verdict with a per-rule trace, then the
combined set verdict (worst wins, the way Paramify combines them).

Defaults to --mode api-today: `disposition` is discarded by the REST API, so
every rule is a pass-requirement on a live tenant regardless of how it was
authored. Pass --mode as-designed to see what it would do if that were fixed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from framework.validator_eval import (  # noqa: E402
    NodeUnavailable,
    evaluate,
    node_available,
)
from framework.validators import discover_validators  # noqa: E402

_RANK = {"PASS": 0, "FAIL": 1, "ERROR": 2, "COMPILE_ERROR": 3}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("evidence", help="Path to a real evidence JSON file")
    ap.add_argument("-s", "--select", help="Validator key or evidence-set reference id")
    ap.add_argument("--mode", default="api-today", choices=("api-today", "as-designed"))
    ap.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON")
    args = ap.parse_args()

    if not node_available():
        print("`node` is not on PATH. Paramify evaluates these with ECMAScript, "
              "so they cannot be checked with Python re.", file=sys.stderr)
        return 2

    path = Path(args.evidence)
    try:
        artifact = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        return 2

    registry = discover_validators(REPO_ROOT)

    if args.select:
        chosen = [v for v in registry.values()
                  if v.key == args.select or args.select in (v.evidence_sets or [])]
        scope = args.select
    else:
        # Fall back to the set the evidence itself names, which is what Paramify
        # would apply to this artifact.
        try:
            meta = json.loads(artifact).get("metadata", {})
            ref = (meta.get("evidence_set") or {}).get("reference_id", "")
        except (ValueError, AttributeError):
            ref = ""
        if not ref:
            print("No --select given and the file names no evidence set in "
                  "metadata.evidence_set.reference_id — pass --select.", file=sys.stderr)
            return 2
        chosen = [v for v in registry.values() if ref in (v.evidence_sets or [])]
        scope = ref

    chosen = [v for v in chosen if v.type == "AUTOMATED"]
    if not chosen:
        print(f"No AUTOMATED validators in the registry match {scope!r}.", file=sys.stderr)
        return 1
    chosen.sort(key=lambda v: (v.role or "", v.key))

    results = []
    for v in chosen:
        try:
            out = evaluate(
                {"key": v.key, "regex": v.regex, "validation_rules": v.validation_rules},
                artifact, mode=args.mode,
            )
        except (NodeUnavailable, RuntimeError) as e:
            out = {"verdict": "ERROR", "error": str(e), "rules": []}
        results.append({"key": v.key, "role": v.role or "", "name": v.name, **out})

    combined = max((r["verdict"] for r in results), key=lambda x: _RANK.get(x, 9))

    if args.json_out:
        print(json.dumps(
            {"ok": True, "evidence": str(path), "scope": scope, "mode": args.mode,
             "combined": combined, "validators": results}, indent=2))
        return 0 if combined == "PASS" else 1

    print(f"{path.name} — {scope} — mode {args.mode}\n")
    for r in results:
        head = f"  {r['verdict']:<6} {r['key']}"
        print(f"{head}  ({r['role']})" if r["role"] else head)
        if r.get("error"):
            print(f"         {r['error']}")
        for rule in r.get("rules", []):
            held = "held" if rule.get("held") else "did NOT hold"
            # A rule that read nothing is the setup for the silent false pass:
            # nothing compared to nothing holds. Flag it either way, because a
            # rule that held without reading anything proved nothing.
            note = "  (READ NOTHING)" if rule.get("readNothing") else ""
            print(f"         {rule.get('operation', '?')} {rule.get('criteria', '')}"
                  f" {rule.get('rhs')!r} <- got {rule.get('lhs')!r}  {held}{note}")
        if r.get("compiles") is False:
            print(f"         regex did not compile: {r.get('compileError')}")
        if r.get("vacuous"):
            print("         every rule read nothing — this verdict means nothing")
    print(f"\n  set verdict: {combined}")
    if combined != "PASS":
        print("\n  A FAIL here is only readable as 'the tenant is non-compliant' when the")
        print("  synthetic compliant case passes. If it does not, the validator is broken:")
        print("  paramify validators check --select <key>")
    return 0 if combined == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
