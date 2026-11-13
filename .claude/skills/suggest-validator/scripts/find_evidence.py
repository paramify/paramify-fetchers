#!/usr/bin/env python3
"""Find the local evidence a validator could be authored against.

Lists evidence files newest first with two facts that decide whether authoring
can start: whether the run succeeded, and whether the payload carries any
measured value at all.

    python .claude/skills/suggest-validator/scripts/find_evidence.py
    python .claude/skills/suggest-validator/scripts/find_evidence.py aws_s3_encryption_status
    python .claude/skills/suggest-validator/scripts/find_evidence.py --json

The `populated` verdict is triage, not proof, and it is wrong in both
directions — read the caveats in SKILL.md Phase 1 before acting on it. A
findings-style fetcher reads as hollow precisely when the control is working,
and a payload full of static descriptive strings reads as populated when every
measured value is zero.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

# Envelope metadata is present on every run regardless of posture, so it must
# not count toward "this payload has data".
_ENVELOPE_KEYS = {"schema_version", "metadata"}


def has_signal(obj) -> bool:
    """Does anything in here carry a non-empty, non-zero value?"""
    if isinstance(obj, dict):
        return any(has_signal(v) for v in obj.values())
    if isinstance(obj, list):
        return len(obj) > 0 and any(has_signal(x) for x in obj)
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj != 0
    if isinstance(obj, str):
        return bool(obj.strip())
    return False


def describe(path: str) -> dict:
    try:
        doc = json.load(open(path))
    except (OSError, ValueError) as e:
        return {"path": path, "readable": False, "error": str(e)}
    meta = doc.get("metadata", {}) if isinstance(doc, dict) else {}
    payload = doc.get("payload", doc) if isinstance(doc, dict) else doc
    return {
        "path": path,
        "readable": True,
        "status": meta.get("status", "?"),
        "exit_code": meta.get("exit_code"),
        "fetcher": meta.get("fetcher_name", ""),
        "evidence_set": (meta.get("evidence_set") or {}).get("reference_id", "")
                        if isinstance(meta.get("evidence_set"), dict) else "",
        "collected_at": meta.get("collected_at", ""),
        "bytes": os.path.getsize(path),
        "populated": has_signal(payload),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("fetcher", nargs="?", help="Fetcher name; omit for every fetcher")
    ap.add_argument("-o", "--output-dir", default="evidence", help="Run output dir (default: evidence)")
    ap.add_argument("-n", "--limit", type=int, default=20,
                    help="Rows to show (default 20; 0 for all). JSON always returns all.")
    ap.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON")
    args = ap.parse_args()

    pattern = f"{args.output_dir}/run-*/{args.fetcher or ''}*.json"
    paths = [p for p in sorted(glob.glob(pattern), reverse=True)
             if not os.path.basename(p).startswith("_")]
    rows = [describe(p) for p in paths]

    if args.json_out:
        print(json.dumps({"ok": True, "candidates": rows}, indent=2))
        return 0

    if not rows:
        where = f" for {args.fetcher}" if args.fetcher else ""
        print(f"No evidence{where} under {args.output_dir}/run-*/.")
        print("Nothing to author against — run the fetcher against a real tenant first")
        print("(wire-manifest -> paramify run), or pull an artifact from the workspace:")
        print("  paramify artifacts list")
        return 1

    usable = [r for r in rows if r.get("status") == "success" and r.get("populated")]
    shown = rows if args.limit <= 0 else rows[: args.limit]
    print(f"{len(rows)} evidence file(s), newest first"
          f" — {len(usable)} look(s) populated and successful:\n")
    for r in shown:
        if not r["readable"]:
            print(f"  unreadable  {r['path']}  ({r['error']})")
            continue
        flag = "populated" if r["populated"] else "HOLLOW"
        size = f"{max(1, r['bytes'] // 1024)}KB"
        print(f"  {r['status']:<8} {flag:<10} {size:>7}  {r['path']}")
        if r["evidence_set"]:
            print(f"           {r['evidence_set']}")
    if len(shown) < len(rows):
        print(f"\n  … and {len(rows) - len(shown)} older file(s)."
              f" Name a fetcher to narrow, or -n 0 for all.")
    if not usable:
        print("\nNothing here is both successful and populated. Before asking for another")
        print("run, check the polarity: a findings-style fetcher (guard duty, access")
        print("analyzer, vulnerability scans) reads as HOLLOW exactly when the control")
        print("is working. See SKILL.md Phase 1.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
