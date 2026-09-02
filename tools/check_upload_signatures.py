#!/usr/bin/env python3
"""Flag evidence files that the production WAF will reject on upload.

Uploads to app.paramify.com pass through AWS WAF managed rules that inspect the
whole request body — the evidence file AND the artifact metadata. A match is
rejected at the load balancer with a bare HTML 403 carrying no requestId, so the
uploader can only report "HTTP 403" with nothing to act on.

The signatures below were confirmed empirically against production on
2026-09-02. Note that a single "../" is enough: an ordinary relative path in a
CodeBuild buildspec is what first surfaced this.

Usage:
    python tools/check_upload_signatures.py                    # latest run
    python tools/check_upload_signatures.py evidence/run-...   # a specific run
    python tools/check_upload_signatures.py --json

Exits 1 if any file would be blocked, so it can gate an upload in CI.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Confirmed blocked, with the AWS managed rule group each maps to.
SIGNATURES = [
    ("../", "GenericLFI_BODY (path traversal)"),
    ("/etc/passwd", "GenericLFI_BODY (sensitive file)"),
    ("/bin/sh", "LinuxRuleSet (shell path)"),
    ("/bin/bash", "LinuxRuleSet (shell path)"),
    ("<script", "CrossSiteScripting_BODY"),
]

# Confirmed NOT blocked as of 2026-09-02 — kept so nobody re-adds them on a hunch.
KNOWN_SAFE = ["$(", "&&", "rm -rf", "' OR 1=1", "<b>"]


def find_latest_run(evidence_dir: Path) -> Path | None:
    runs = sorted((p for p in evidence_dir.glob("run-*") if p.is_dir()), reverse=True)
    return runs[0] if runs else None


def iter_evidence_files(run_dir: Path):
    for p in sorted(run_dir.glob("*.json")):
        if p.name in ("_run_metadata.json", "upload_log.json"):
            continue
        yield p


def scan_text(text: str) -> list[tuple[str, str, int, str]]:
    """Return (signature, rule, line_no, context) for every match."""
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for sig, rule in SIGNATURES:
            if sig in line:
                idx = line.index(sig)
                start, end = max(0, idx - 30), min(len(line), idx + len(sig) + 30)
                hits.append((sig, rule, lineno, line[start:end].strip()))
    return hits


def build_note(metadata: dict) -> str:
    """Mirror the note paramify_evidence builds, so metadata is scanned too."""
    parts = [
        f"fetcher={metadata.get('fetcher_name')}",
        f"version={metadata.get('fetcher_version')}",
        f"run_id={metadata.get('run_id')}",
        f"status={metadata.get('status')}",
    ]
    if metadata.get("target"):
        parts.append(f"target={json.dumps(metadata['target'], separators=(',', ':'))}")
    return "; ".join(parts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", nargs="?", help="run directory (default: latest under ./evidence)")
    ap.add_argument("--evidence-dir", default="evidence")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir) if args.run_dir else find_latest_run(Path(args.evidence_dir))
    if not run_dir or not run_dir.is_dir():
        print(f"no run directory found (looked in {args.evidence_dir}/)", file=sys.stderr)
        return 2

    findings = []
    scanned = 0
    for path in iter_evidence_files(run_dir):
        scanned += 1
        raw = path.read_text(errors="replace")
        for sig, rule, lineno, ctx in scan_text(raw):
            findings.append({"file": path.name, "part": "file", "signature": sig,
                             "rule": rule, "line": lineno, "context": ctx})
        # The artifact metadata travels in the same request body.
        try:
            meta = json.loads(raw).get("metadata", {})
        except (json.JSONDecodeError, AttributeError):
            continue
        for field, value in (("note", build_note(meta)),
                             ("title", str((meta.get("evidence_set") or {}).get("name", "")))):
            for sig, rule, _, ctx in scan_text(value):
                findings.append({"file": path.name, "part": field, "signature": sig,
                                 "rule": rule, "line": 0, "context": ctx})

    if args.as_json:
        print(json.dumps({"run_dir": str(run_dir), "scanned": scanned,
                          "blocked_files": sorted({f["file"] for f in findings}),
                          "findings": findings}, indent=2))
        return 1 if findings else 0

    print(f"scanned {scanned} evidence file(s) in {run_dir}")
    if not findings:
        print("no WAF signatures found - safe to upload")
        return 0

    blocked = sorted({f["file"] for f in findings})
    print(f"\n{len(blocked)} file(s) will be rejected with HTTP 403:\n")
    for name in blocked:
        print(f"  {name}")
        for f in (x for x in findings if x["file"] == name):
            loc = f"line {f['line']}" if f["line"] else f"{f['part']} metadata"
            print(f"      {f['signature']!r} - {f['rule']}  ({loc})")
            print(f"        ...{f['context']}...")
    print(f"\n{len(findings)} match(es). These uploads fail at the load balancer "
          f"with a bare HTML 403 and no requestId.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
