"""Per-row decisions: given a workbook row and its solution capability, what
should change and what must not.

Kept free of openpyxl so the rules are unit-testable against plain dicts.

The governing principle is that this tool is preparing a file a human will
upload into a live compliance assessment. Two failure modes are unacceptable and
both are guarded here rather than left to reviewer diligence:

  * Producing a workbook Purview rejects, by writing a status that invalidates
    the row's existing Test Status or a date later than its Test Date.
  * Destroying the client's own work, by overwriting hand-entered notes or
    blanking a cell because Paramify had nothing to say.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from audit import DateResolution
from config import (
    COL_IMPL_DATE,
    COL_IMPL_NOTES,
    COL_IMPL_STATUS,
    COL_TEST_DATE,
    COL_TEST_STATUS,
)
from mapping import (
    CellUpdate,
    RowPlan,
    format_purview_datetime,
    map_status,
    render_notes,
    check_test_date,
    check_test_status,
    to_local,
)

#: Advisory kinds. Each names one reason a written cell deserves a second look.
ADVISORY_BLANK_TEST_STATUS = "blank_test_status"
ADVISORY_CAPABILITY_FALLBACK = "status_from_capability_fallback"
ADVISORY_AUDIT_DISAGREES = "audit_disagrees_with_capability"
ADVISORY_TEST_DATE_ADVANCED = "test_date_advanced"
ADVISORY_TEST_CLEARED = "test_result_cleared"

#: `fill-empty` writes only where the cell is blank — the safe default, because
#: 156 of this export's rows already carry values a person typed.
#: `sync` additionally replaces a cell whose value disagrees with Paramify.
#: What to do when the derived Implementation Date is later than the row's
#: existing Test Date — a combination Purview rejects outright.
#:
#: Neither resolution is free, which is why `skip` remains the default:
#:   advance-test  keeps the recorded result but moves its date, asserting the
#:                 test happened on the implementation date. It did not.
#:   clear-test    is truthful — the implementation changed, so the earlier test
#:                 is stale — but it discards the client's recorded pass.
CONFLICT_SKIP = "skip"
CONFLICT_ADVANCE_TEST = "advance-test"
CONFLICT_CLEAR_TEST = "clear-test"
DATE_CONFLICT_CHOICES = (CONFLICT_SKIP, CONFLICT_ADVANCE_TEST, CONFLICT_CLEAR_TEST)

#: How a Paramify narrative interacts with a note the client already wrote.
#: `follow-mode` defers to --mode (fill gaps, or replace under sync). `append`
#: keeps both: the client's wording stays and the narrative is added beneath it,
#: so a production sync never destroys someone's own sentence.
NOTES_FOLLOW_MODE = "follow-mode"
NOTES_APPEND = "append"
#: Always write the narrative over whatever the cell holds, whatever --mode
#: says. Paramify is the source of truth for this column and the client's
#: earlier text is discarded. Explicit rather than implied by --mode sync, so
#: the intent is visible in the command that ran.
NOTES_REPLACE = "replace"
NOTES_POLICIES = (NOTES_FOLLOW_MODE, NOTES_APPEND, NOTES_REPLACE)

#: Separates the client's note from the appended narrative. Also the marker
#: that makes appending idempotent -- re-running must not stack duplicates.
NOTES_JOINER = "\n\n"

MODE_FILL_EMPTY = "fill-empty"
MODE_SYNC = "sync"
MODES = (MODE_FILL_EMPTY, MODE_SYNC)


def _is_blank(value: Any) -> bool:
    return value is None or str(value).strip() == ""


def _should_write(existing: Any, new: Any, mode: str) -> tuple[bool, Optional[str]]:
    """Whether to write, under the chosen mode. Returns (write, reason_if_not)."""
    if _is_blank(new):
        return False, "nothing to write"
    if _is_blank(existing):
        return True, None
    if str(existing).strip() == str(new).strip():
        return False, "already matches Paramify"
    if mode == MODE_SYNC:
        return True, None
    return False, (
        f"cell already holds {str(existing).strip()[:60]!r}; "
        f"--mode {MODE_SYNC} would replace it"
    )


def _append_note(existing: str, narrative: str) -> tuple[Optional[str], Optional[str]]:
    """Client note first, Paramify narrative beneath. Returns (text, reason).

    `None` means nothing to do. Appending must be idempotent: a second run
    would otherwise stack the same narrative again, and by the fifth run the
    cell is unreadable. The narrative's own text is the marker -- if it is
    already in the cell, the row is left alone.
    """
    kept = existing.strip()
    if narrative.strip() in kept:
        return None, "the Paramify narrative is already present in this note"
    return kept + NOTES_JOINER + narrative.strip(), None


def plan_row(
    *,
    row_number: int,
    values: dict[str, Any],
    solcap: Optional[dict[str, Any]],
    resolution: Optional[DateResolution],
    tzinfo,
    mode: str = MODE_FILL_EMPTY,
    strict_test_status: bool = False,
    fallback_solcap: bool = False,
    on_date_conflict: str = CONFLICT_SKIP,
    notes_policy: str = NOTES_FOLLOW_MODE,
    skip_unassessed_notes: bool = False,
) -> RowPlan:
    plan = RowPlan(
        row=row_number,
        action_id=str(values.get("Action Id") or ""),
        action_name=str(values.get("Improvement Action Name") or ""),
    )

    if solcap is None:
        plan.skipped.append("no solution capability matches this action name")
        return plan

    # --- Implementation Status and Date -------------------------------- #
    # Both are read from the audit log's Activity feed: the most recent
    # implementation-status change event supplies the status (its `new` value)
    # and the date (its timestamp), so the two always describe the same
    # transition rather than pairing a current status with an unrelated date.
    #
    # The cost of that consistency is that a capability with no status-change
    # activity yields neither field — its status may predate audit retention, or
    # never have changed. Those rows are counted in the run report, and
    # --status-fallback-solcap opts into the capability's current status (with
    # no date) instead.
    audit_status = (resolution.status_from_audit if resolution else None) or None
    have_activity = bool(resolution and resolution.timestamp and audit_status)

    purview_status: Optional[str] = None
    status_source = None

    if have_activity:
        purview_status, unmapped_reason = map_status(audit_status)
        status_source = "audit_log"
        if purview_status is None:
            plan.skipped.append(
                f"Implementation Status: audit activity reports {audit_status!r} — {unmapped_reason}"
            )
    elif fallback_solcap:
        purview_status, unmapped_reason = map_status(solcap.get("implementationStatus"))
        status_source = "solution_capability_fallback"
        if purview_status is None:
            plan.skipped.append(f"Implementation Status: {unmapped_reason}")
        else:
            plan.advise(
                ADVISORY_CAPABILITY_FALLBACK,
                "Implementation Status taken from the capability's current value because "
                "the audit log holds no status-change activity for it; no Implementation "
                "Date can be derived"
            )
    else:
        plan.skipped.append(
            "Implementation Status: no implementation-status change found in the audit "
            "log Activity feed for this capability"
        )
        plan.skipped.append(
            "Implementation Date: no implementation-status change found in the audit "
            "log Activity feed for this capability"
        )

    status_written = False
    if purview_status is not None:
        blocking, advisory = check_test_status(
            purview_status, values.get("Test Status"), strict=strict_test_status
        )
        if blocking:
            # Clearing the Test Status to make room would erase a recorded test
            # result, so this row is left for a human instead.
            plan.skipped.append(f"Implementation Status: {blocking}")
        else:
            if advisory:
                plan.advise(ADVISORY_BLANK_TEST_STATUS, advisory)
            write, reason = _should_write(
                values.get(COL_IMPL_STATUS), purview_status, mode
            )
            plan.updates.append(
                CellUpdate(COL_IMPL_STATUS, values.get(COL_IMPL_STATUS),
                           purview_status, write, reason)
            )
            status_written = write
            if write:
                plan.notes.append(f"Implementation Status from {status_source}")

    # The date only accompanies a status the row actually accepted: a date on its
    # own asserts an implementation the workbook does not claim.
    if have_activity and purview_status is not None:
        local = to_local(resolution.timestamp, tzinfo)
        rendered = format_purview_datetime(local)
        date_conflict = check_test_date(local, values.get("Test Date"))

        if date_conflict and on_date_conflict == CONFLICT_SKIP:
            plan.skipped.append(
                f"Implementation Date: {date_conflict}. "
                f"--on-date-conflict {CONFLICT_ADVANCE_TEST}|{CONFLICT_CLEAR_TEST} "
                "can resolve it"
            )
        else:
            write, reason = _should_write(values.get(COL_IMPL_DATE), rendered, mode)
            if not write and status_written and reason and "already holds" in reason:
                write, reason = True, None
            plan.updates.append(
                CellUpdate(COL_IMPL_DATE, values.get(COL_IMPL_DATE), rendered,
                           write, reason)
            )
            if write:
                plan.notes.append(
                    f"Implementation Date from audit activity, resolved by the "
                    f"{resolution.method} strategy"
                )
            # Only touch the test columns if the date they are blocking is
            # actually being written; otherwise the row is left incoherent —
            # a cleared test beside an unchanged implementation date.
            if date_conflict and write:
                if on_date_conflict == CONFLICT_ADVANCE_TEST:
                    plan.updates.append(CellUpdate(
                        COL_TEST_DATE, values.get(COL_TEST_DATE), rendered, True,
                        "advanced to the new Implementation Date "
                        f"(--on-date-conflict {CONFLICT_ADVANCE_TEST})"))
                    plan.advise(
                        ADVISORY_TEST_DATE_ADVANCED,
                        f"Test Date moved from {values.get(COL_TEST_DATE)!r} to "
                        f"{rendered!r} so Purview accepts the new Implementation Date. "
                        "The recorded test result is unchanged, but its date no longer "
                        "reflects when the test was performed."
                    )
                elif on_date_conflict == CONFLICT_CLEAR_TEST:
                    plan.updates.append(CellUpdate(
                        COL_TEST_DATE, values.get(COL_TEST_DATE), None, True,
                        "cleared: the implementation moved past this test"))
                    plan.updates.append(CellUpdate(
                        COL_TEST_STATUS, values.get(COL_TEST_STATUS), None, True,
                        "cleared: the implementation moved past this test"))
                    plan.advise(
                        ADVISORY_TEST_CLEARED,
                        f"Test Status {values.get(COL_TEST_STATUS)!r} and Test Date "
                        f"{values.get(COL_TEST_DATE)!r} cleared: the implementation "
                        f"date moved to {rendered}, so the earlier test no longer "
                        "covers what is implemented. This control needs retesting."
                    )

        # The capability's own field is no longer the source, but a disagreement
        # still means the latest activity is not the transition that produced the
        # current state — worth surfacing rather than silently preferring one.
        current = str(solcap.get("implementationStatus") or "").strip().upper()
        normalized_audit = re.sub(r"[\s-]+", "_", str(audit_status).strip().upper())
        if current and normalized_audit != current:
            plan.advise(
                ADVISORY_AUDIT_DISAGREES,
                f"audit activity's latest status change was to {audit_status!r} but the "
                f"capability currently reports {solcap.get('implementationStatus')!r}; "
                "the written status and date describe that earlier transition"
            )

    # --- Implementation Notes --------------------------------------------- #
    # Narratives publish regardless of the capability's implementation status.
    #
    # An earlier version suppressed them for NOT_SET capabilities, reasoning that
    # unassessed prose should not enter a live assessment. That conflated two
    # different things: a narrative DESCRIBES what the system does, while the
    # Implementation Status column carries the claim about whether it is in
    # place. Suppressing the description because the status is unset silently
    # emptied the Notes column for 456 of 463 rows in a real program -- the
    # opposite of what this tool is for.
    #
    # --skip-unassessed-notes restores the cautious behaviour for anyone who
    # wants it.
    if skip_unassessed_notes and (
        str(solcap.get("implementationStatus") or "").strip().upper() == "NOT_SET"
    ):
        plan.skipped.append(
            "Implementation Notes: --skip-unassessed-notes and the capability is "
            "NOT_SET, so its narrative was not published"
        )
        return plan

    notes_text, contributors = render_notes(solcap.get("functions") or [])
    if notes_text is None:
        # Deliberately no CellUpdate: writing "" would overwrite, and the rules
        # tab is explicit that a written value replaces what is there.
        plan.skipped.append(
            "Implementation Notes: the capability has no function narrative"
        )
    else:
        existing = values.get(COL_IMPL_NOTES)
        if notes_policy == NOTES_APPEND and not _is_blank(existing):
            combined, reason = _append_note(str(existing), notes_text)
            plan.updates.append(
                CellUpdate(COL_IMPL_NOTES, existing, combined,
                           combined is not None, reason)
            )
            write = combined is not None
        else:
            # `replace` decides this column on its own, so --mode fill-empty
            # can still protect status and dates while notes are overwritten.
            effective = MODE_SYNC if notes_policy == NOTES_REPLACE else mode
            write, reason = _should_write(existing, notes_text, effective)
            plan.updates.append(
                CellUpdate(COL_IMPL_NOTES, existing, notes_text, write, reason)
            )
        if write and contributors:
            plan.notes.append(f"Notes from function narrative(s): {', '.join(contributors)}")

    return plan
