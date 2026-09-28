"""The run report: what changed, what did not, and why.

Every skip carries its reason. A row this tool declined to touch is the most
important thing in the output — it is where a human has to look — so the report
is organised around skips rather than successes.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mapping import RowPlan
from matching import MatchResult


def build(
    *,
    plans: list[RowPlan],
    matches: MatchResult,
    mode: str,
    timezone_name: str,
    workbook_in: str,
    workbook_out: str | None,
    audit_status: dict[str, Any],
    capability_count: int,
    dry_run: bool,
    rows_with_activity: list[str] | None = None,
    strict_test_status: bool = False,
    fallback_solcap: bool = False,
) -> dict[str, Any]:
    writes = [u for p in plans for u in p.updates if u.written]
    holds = [u for p in plans for u in p.updates if not u.written]
    skip_reasons = Counter(
        reason.split(":", 1)[0].strip() for p in plans for reason in p.skipped
    )
    by_kind: dict[str, list[str]] = {}
    for plan in plans:
        for advisory in plan.advisories:
            by_kind.setdefault(advisory["kind"], []).append(plan.action_name)
    no_activity = [
        p for p in plans
        if any("Activity feed" in reason for reason in p.skipped)
    ]
    return {
        "tool": "purview_action_update",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dry_run": dry_run,
        "mode": mode,
        "strict_test_status": strict_test_status,
        "sources": {
            "implementation_status": "audit_log_activity"
            + (" (with solution-capability fallback)" if fallback_solcap else ""),
            "implementation_date": "audit_log_activity",
            "implementation_notes": "solution_capability_function_narrative",
        },
        "implementation_date_timezone": timezone_name,
        "workbook_in": workbook_in,
        "workbook_out": workbook_out,
        "audit_log": audit_status,
        "totals": {
            "solution_capabilities": capability_count,
            "action_rows": len(plans),
            "rows_with_writes": sum(1 for p in plans if p.wrote_anything),
            "cells_written": len(writes),
            "cells_held_back": len(holds),
            "cells_by_column": dict(Counter(u.column for u in writes)),
        },
        "join": {
            "exact_matches": len(matches.exact),
            "near_matches_detected": len(matches.near),
            "unmatched_action_rows": matches.unmatched_actions,
            "unmatched_solution_capabilities": matches.unmatched_capabilities,
            "ambiguous_names": matches.ambiguous,
            "duplicate_action_names": matches.duplicate_action_names,
            "duplicate_capability_names": matches.duplicate_capability_names,
        },
        "skips_by_field": dict(skip_reasons),
        "status_change_activity": {
            "rows": len(rows_with_activity or []),
            "action_names": list(rows_with_activity or [])[:50],
        },
        "no_status_change_activity": {
            "rows": len(no_activity),
            "meaning": (
                "the audit log holds no implementation-status change for this "
                "capability, so neither Implementation Status nor Implementation Date "
                "could be derived. Its status may predate audit retention or never "
                "have changed. --status-fallback-solcap writes the capability's "
                "current status instead, without a date."
            ),
            "action_names": [p.action_name for p in no_activity][:50],
        },
        "advisories": {
            kind: {"rows": len(names), "action_names": names[:50]}
            for kind, names in sorted(by_kind.items())
        },
        "advisory_meanings": {
            "blank_test_status": (
                "Implementation Status written onto a row whose Test Status is blank, "
                "where the rules tab does not list \"None\" among that status's permitted "
                "values. Written on the reading that a blank cell is an absence rather "
                "than a value; --strict-test-status excludes these."
            ),
            "status_from_capability_fallback": (
                "no status-change activity existed, so the capability's current status "
                "was used and no Implementation Date could be derived."
            ),
            "audit_disagrees_with_capability": (
                "the latest audit activity and the capability's current status differ; "
                "the written values describe that earlier transition."
            ),
            "test_date_advanced": (
                "Test Date moved to the new Implementation Date so Purview accepts the "
                "row. The recorded result stands but its date no longer reflects when "
                "the test was performed."
            ),
            "test_result_cleared": (
                "Test Status and Test Date cleared because the implementation date "
                "moved past them. These controls need retesting."
            ),
        },
        "rows": [
            {
                "row": p.row,
                "action_id": p.action_id,
                "action_name": p.action_name,
                "updates": [
                    {
                        "column": u.column,
                        "old": _trim(u.old),
                        "new": _trim(u.new),
                        "written": u.written,
                        "reason": u.reason,
                    }
                    for u in p.updates
                ],
                "skipped": p.skipped,
                "notes": p.notes,
                "advisories": p.advisories,
            }
            for p in plans
            if p.updates or p.skipped
        ],
    }


def _trim(value: Any, limit: int = 300) -> Any:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit] + " …"


def write(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    return path


def summarize(report: dict[str, Any]) -> str:
    """The human-readable summary printed at the end of a run."""
    totals, join = report["totals"], report["join"]
    audit = report["audit_log"]
    lines = [
        "",
        f"  mode                 {report['mode']}"
        + ("   (DRY RUN — nothing written)" if report["dry_run"] else ""),
        f"  solution capabilities{totals['solution_capabilities']:>6}",
        f"  action rows          {totals['action_rows']:>6}",
        f"  exact name matches   {join['exact_matches']:>6}",
        f"  cells written        {totals['cells_written']:>6}  {totals['cells_by_column']}",
        f"  cells held back      {totals['cells_held_back']:>6}",
        f"  status + date source audit log Activity feed",
        f"  audit log            {audit.get('state')}"
        + (f" ({audit.get('events')} events)" if audit.get("events") is not None else ""),
    ]
    if join["near_matches_detected"]:
        lines.append(
            f"  ! {join['near_matches_detected']} near name match(es) detected and NOT "
            "applied — use --accept-near-matches after reviewing them"
        )
    if join["unmatched_action_rows"]:
        lines.append(f"  ! {len(join['unmatched_action_rows'])} action row(s) matched no capability")
    if join["unmatched_solution_capabilities"]:
        lines.append(
            f"  ! {len(join['unmatched_solution_capabilities'])} capability(ies) matched no action row"
        )
    found = report.get("status_change_activity", {})
    if found.get("rows"):
        names = ", ".join(n[:38] for n in found["action_names"][:4])
        more = f" +{found['rows'] - 4} more" if found["rows"] > 4 else ""
        lines.append(f"  audit activity found  {found['rows']:>4}  {names}{more}")
    quiet = report["no_status_change_activity"]["rows"]
    if quiet:
        lines.append(
            f"  ! {quiet} row(s) had no status-change activity in the audit log — no "
            "status or date written (--status-fallback-solcap uses the capability's current status)"
        )
    for kind, bucket in sorted(report.get("advisories", {}).items()):
        lines.append(f"  ! {bucket['rows']} row(s) — {kind.replace('_', ' ')}")
    if report["skips_by_field"]:
        lines.append(f"  skips by field       {report['skips_by_field']}")
    return "\n".join(lines)


def changes_table(report: dict[str, Any], skip_columns: tuple[str, ...] = ()) -> str:
    """Every written cell, one per line: what changed, from what, to what.

    Exists so inspecting a run needs no shell one-liner. Quoting a Python
    snippet through zsh is a trap — `!=` triggers history expansion even inside
    double quotes — and a mangled command is a worse answer than a flag.
    """
    rows = [
        (x["action_name"], u["column"], u["old"], u["new"])
        for x in report["rows"]
        for u in x["updates"]
        if u["written"] and u["column"] not in skip_columns
    ]
    if not rows:
        return "\n  (no cells written)"
    width = min(max(len(a) for a, _, _, _ in rows), 44)
    out = [f"\n  {len(rows)} cell(s) written:"]
    for action, column, old, new in rows:
        out.append(
            f"    {action[:width]:<{width}}  {column:<22} "
            f"{_short(old)} -> {_short(new)}"
        )
    return "\n".join(out)


def _short(value: Any, limit: int = 30) -> str:
    """One-line preview of a cell value.

    Paragraph breaks render as a visible marker rather than collapsing to a
    space: an appended note reads "client text ⏎⏎ narrative", and silently
    flattening that made the preview look like the two had been concatenated
    without separation when the cell was in fact correct.
    """
    if value is None:
        return "(blank)"
    text = " ".join(str(value).replace("\n\n", " ⏎⏎ ").replace("\n", " ⏎ ").split())
    return repr(text if len(text) <= limit else text[:limit] + "…")
