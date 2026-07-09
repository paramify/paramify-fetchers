#!/usr/bin/env python3
"""Regenerate the KSI-coverage block in README.md from live data.

The FedRAMP 20x KSI coverage numbers rot as fetchers and mappings change, so we
generate them rather than hand-maintain them (the SEC-27 "generate the rot-prone
parts" pattern). This reads `framework.api.ksi_coverage()` — the same model
`paramify ksi` renders — and rewrites the README between the markers:

    <!-- BEGIN:ksi-coverage --> ... <!-- END:ksi-coverage -->

Run it after changing fetcher `ksis` or the KSI reference:

    python tools/gen_ksi_coverage.py

CI can run it and fail on any diff to guarantee the badge never lies.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from framework import api  # noqa: E402

BEGIN = "<!-- BEGIN:ksi-coverage -->"
END = "<!-- END:ksi-coverage -->"
BRAND = "1467ff"


def build_block(cov: dict) -> str:
    s = cov["summary"]
    pct = s["coverage_pct"]
    badge = (
        f"![FedRAMP 20x KSI coverage]"
        f"(https://img.shields.io/badge/FedRAMP_20x_KSI_coverage-{pct}%25-{BRAND})"
    )

    evidenceable_fams = [f for f in cov["families"] if f["evidenceable"] > 0]
    organizational_fams = [f for f in cov["families"] if f["evidenceable"] == 0]

    rows = ["| Family | Covered | Gaps |", "|---|---|---|"]
    for f in evidenceable_fams:
        gaps = ", ".join(f"`{g}`" for g in f["gaps"]) if f["gaps"] else "—"
        rows.append(f"| {f['name']} ({f['family']}) | {f['covered']} / {f['evidenceable']} | {gaps} |")

    lines = [
        badge,
        "",
        f"**{s['covered']} of {s['evidenceable']}** config-evidenceable KSIs covered — "
        f"**{pct}%** — plus {s['organizational']} organizational KSIs (evidenced by "
        f"HR / training / process, not cloud config). Straight from `paramify ksi`; "
        f"regenerate with `python tools/gen_ksi_coverage.py`.",
        "",
        *rows,
    ]
    if organizational_fams:
        names = ", ".join(f"{f['name']} ({f['family']})" for f in organizational_fams)
        lines += ["", f"Organizational-only families (no cloud-config evidence): {names}."]
    return "\n".join(lines)


def main() -> int:
    readme = REPO_ROOT / "README.md"
    text = readme.read_text()
    if BEGIN not in text or END not in text:
        # Coverage publishing is currently parked — the README has no
        # ksi-coverage block. We're not yet confident enough in the KSI mapping
        # to publish it; `paramify ksi` still shows live numbers. Re-add the
        # BEGIN/END markers to the README to resume publishing, then rerun this.
        print("ksi-coverage markers not in README.md — coverage publishing is parked; nothing to do.")
        return 0

    cov = api.ksi_coverage(REPO_ROOT)
    block = build_block(cov)

    pre, rest = text.split(BEGIN, 1)
    _, post = rest.split(END, 1)
    new = f"{pre}{BEGIN}\n{block}\n{END}{post}"

    if new == text:
        print(f"README.md already up to date ({cov['summary']['coverage_pct']}%).")
        return 0
    readme.write_text(new)
    print(f"README.md KSI-coverage block updated ({cov['summary']['coverage_pct']}%).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
