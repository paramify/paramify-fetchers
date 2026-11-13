#!/usr/bin/env python3
"""Generate docs/ksi_mapping.md — the full fetcher <-> KSI mapping.

The mapping is live data: it changes every time a fetcher's `ksis` changes or the
KSI reference is re-keyed. Hand-maintaining a doc this size guarantees it goes
stale, so we generate it (the same "generate the rot-prone parts" pattern as
tools/gen_ksi_coverage.py).

Reads framework/reference/ksis.yaml for indicator names/statements/controls and
framework.api.ksi_coverage() for the fetcher join, then writes the doc:

    python tools/gen_ksi_mapping.py

CI can run it and fail on any diff, which keeps the committed doc honest.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from framework import api  # noqa: E402

OUT = REPO_ROOT / "docs" / "ksi_mapping.md"
SOURCE_URL = "https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json"


def fetcher_link(name: str) -> str:
    """`name` -> a repo-relative link to its directory, when we can infer one."""
    cat, _, rest = name.partition("_")
    for tree in ("fetchers", "comparators"):
        if (REPO_ROOT / tree / cat / rest).is_dir():
            return f"[`{name}`](../{tree}/{cat}/{rest})"
    return f"`{name}`"


def main() -> int:
    ref = yaml.safe_load((REPO_ROOT / "framework" / "reference" / "ksis.yaml").read_text())
    cov = api.ksi_coverage(REPO_ROOT)
    s = cov["summary"]

    meta = {k["id"]: k for k in ref["ksis"]}
    fams = ref["families"]
    by_id = {k["id"]: k for k in cov["ksis"]}

    # reverse index: fetcher -> [ksi ids]
    rev: dict[str, list[str]] = defaultdict(list)
    for k in cov["ksis"]:
        for f in k["fetchers"]:
            rev[f].append(k["id"])

    all_fetchers = api.discover_fetchers(REPO_ROOT)
    unmapped = sorted(n for n in all_fetchers if n not in rev)

    L: list[str] = []
    w = L.append

    # ---- header -------------------------------------------------------------
    w("# Fetcher ↔ KSI mapping")
    w("")
    w(f"**{ref['release']}**")
    w("")
    w(f"Source of truth for the indicators: [`fedramp-consolidated-rules.json`]({SOURCE_URL}). "
      "Statements below are verbatim from it.")
    w("")
    w("> [!IMPORTANT]")
    w("> These are **suggested / related** mappings. A `ksis` entry says *this evidence "
      "speaks to this indicator* — not that the fetcher alone satisfies it. Treat the "
      "mapping as the starting point for an assessor conversation, not a substitute for "
      "one. Where a claim would need a generous reading of the statement, the indicator "
      "is left uncovered on purpose: an honest gap is more useful than a mapping that has "
      "to be defended.")
    w("")
    w("Generated — do not hand-edit. Change a fetcher's `ksis:` (or the reference) and "
      "regenerate:")
    w("")
    w("```")
    w("python tools/gen_ksi_mapping.py")
    w("```")
    w("")

    # ---- summary ------------------------------------------------------------
    w("## Coverage")
    w("")
    w(f"**{s['covered']} of {s['evidenceable']}** config-evidenceable indicators covered "
      f"— **{s['coverage_pct']}%**. Plus {s['organizational']} organizational indicators "
      f"(evidenced by HR, training or process, not cloud config), for {s['total']} total.")
    w("")
    w("| Family | | Covered | Gaps |")
    w("|---|---|---|---|")
    for f in cov["families"]:
        evi = f["evidenceable"]
        if evi == 0:
            w(f"| `{f['family']}` | {f['name']} | — *organizational ({f['total']})* | — |")
            continue
        filled = round(10 * f["covered"] / evi)
        bar = "█" * filled + "░" * (10 - filled)
        gaps = ", ".join(f"`{g}`" for g in f["gaps"]) or "—"
        w(f"| `{f['family']}` | {f['name']} | `{bar}` {f['covered']}/{evi} | {gaps} |")
    w("")

    # ---- per-indicator ------------------------------------------------------
    w("## Indicators, and what covers them")
    w("")
    for fam, fam_name in fams.items():
        members = [k for k in cov["ksis"] if k["family"] == fam]
        evi = [k for k in members if k["evidenceable"]]
        cvd = [k for k in evi if k["fetchers"]]
        head = f"### {fam} — {fam_name}"
        head += f"  ({len(cvd)}/{len(evi)})" if evi else "  *(organizational)*"
        w(head)
        w("")
        for k in members:
            m = meta[k["id"]]
            # Covered indicators carry no mark; only gaps and organizational ones do.
            mark = {"covered": "", "gap": "⏳ ", "organizational": "⬜ "}[k["status"]]
            opt = " *(optional at Low)*" if m.get("optional_for_class_b") else ""
            w(f"#### {mark}`{k['id']}` — {m['name']}{opt}")
            w("")
            w(f"> {k['statement']}")
            w("")
            if m.get("controls"):
                w(f"*Controls:* {', '.join('`'+c+'`' for c in m['controls'])}")
                w("")
            if k["fetchers"]:
                w(f"*{len(k['fetchers'])} fetcher{'s' if len(k['fetchers']) != 1 else ''}:* "
                  + ", ".join(fetcher_link(f) for f in k["fetchers"]))
            elif k["evidenceable"]:
                w("*No fetcher covers this yet — a capability gap, not a mapping gap.*")
            else:
                w("*Organizational — evidenced by HR, training or process, not cloud config.*")
            w("")
    # ---- gaps ---------------------------------------------------------------
    gaps = [k for k in cov["ksis"] if k["status"] == "gap"]
    if gaps:
        w("## Open gaps")
        w("")
        w(f"{len(gaps)} config-evidenceable indicator"
          f"{'s' if len(gaps) != 1 else ''} that nothing covers. Each is a **fetcher "
          "backlog item** — the evidence does not exist yet, rather than existing and "
          "being unmapped.")
        w("")
        w("| Indicator | | What would be needed |")
        w("|---|---|---|")
        for k in gaps:
            w(f"| `{k['id']}` | {meta[k['id']]['name']} | {k['statement']} |")
        w("")

    # ---- reverse index ------------------------------------------------------
    w("## By fetcher")
    w("")
    w(f"{len(rev)} of {len(all_fetchers)} fetchers carry a mapping.")
    w("")
    for cat in sorted({n.split("_")[0] for n in rev}):
        rows = sorted(n for n in rev if n.split("_")[0] == cat)
        w(f"### {cat}  ({len(rows)})")
        w("")
        w("| Fetcher | Indicators |")
        w("|---|---|")
        for n in rows:
            w(f"| {fetcher_link(n)} | " + ", ".join(f"`{i}`" for i in sorted(rev[n])) + " |")
        w("")

    if unmapped:
        w("### Unmapped")
        w("")
        w(", ".join(fetcher_link(n) for n in unmapped)
          + " — deliberately carry no mapping.")
        w("")

    OUT.write_text("\n".join(L).rstrip() + "\n")
    print(f"{OUT.relative_to(REPO_ROOT)}: {s['covered']}/{s['evidenceable']} covered "
          f"({s['coverage_pct']}%), {len(rev)} fetchers mapped, {len(gaps)} gaps, "
          f"{len(unmapped)} unmapped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
