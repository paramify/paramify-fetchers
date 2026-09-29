#!/usr/bin/env python3
"""Update a Purview "Action Update" workbook from Paramify, for manual re-upload.

Semi-automated by design: Compliance Manager has no write API for improvement
actions, so the supported path is export -> edit the Action Update tab ->
re-upload. This fills three columns of that tab from Paramify and stops. A human
uploads the result.

    Implementation Status  <- Audit Log Activity, the last status change's new value
    Implementation Date    <- Audit Log Activity, that same change's timestamp
    Implementation Notes   <- Solution Capability function narrative

Read-only against Paramify. The input workbook is never modified; an updated
copy and a run report are written to the output directory.

    python tools/purview_action_update/run.py --dry-run
    python tools/purview_action_update/run.py --workbook ~/Desktop/ExportActions.xlsx
    python tools/purview_action_update/run.py --probe-audit
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit  # noqa: E402
import upload as upload_mod  # noqa: E402
import verify as verify_mod  # noqa: E402
import report as report_mod  # noqa: E402
import workbook as wb_mod  # noqa: E402
from config import (  # noqa: E402
    COL_ACTION_NAME,
    US_TIMEZONES,
    ConfigError,
    resolve_timezone,
    WRITABLE_COLUMNS,
    WRITABLE_WITH_TEST_RESOLUTION,
)
from matching import build as build_matches  # noqa: E402
from paramify_api import AuditLogUnavailable, ParamifyClient, ParamifyError  # noqa: E402
from planner import (  # noqa: E402
    CONFLICT_SKIP,
    NOTES_FOLLOW_MODE,
    NOTES_POLICIES,
    DATE_CONFLICT_CHOICES,
    MODE_FILL_EMPTY,
    MODES,
    plan_row,
)

logger = logging.getLogger("purview_action_update")

#: Where the Purview export tends to live. Searched in order when --workbook is
#: not given; the resolved path is always logged so the choice is never silent.
WORKBOOK_CANDIDATES = (
    Path("ExportActions.xlsx"),
    Path.home() / "Downloads" / "ExportActions.xlsx",
    Path.home() / "Desktop" / "ExportActions.xlsx",
)


def default_workbook() -> Path:
    for candidate in WORKBOOK_CANDIDATES:
        if candidate.exists():
            return candidate
    return WORKBOOK_CANDIDATES[0]
DEFAULT_OUT = Path("out") / "purview_action_update"


def _load_offline(directory: Path) -> tuple[list, list]:
    """Fixture-driven input, so a run can be reviewed with no token and no network."""
    caps = json.loads((directory / "solution_capabilities.json").read_text())
    events_path = directory / "audit_logs.json"
    events = json.loads(events_path.read_text()) if events_path.exists() else []
    if isinstance(caps, dict):
        caps = caps.get("solutionCapabilities", [])
    if isinstance(events, dict):
        events = events.get("data", [])
    return caps, events


def _fetch(args) -> tuple[list, list, dict]:
    """Pull capabilities and audit events from Paramify."""
    with ParamifyClient() as client:
        capabilities = client.solution_capabilities()
        logger.info("fetched %d solution capabilities", len(capabilities))
        try:
            events = list(
                client.audit_log_events(
                    activity_types=tuple(
                        t.strip().upper() for t in args.activity_types.split(",") if t.strip()
                    ),
                    start_date=args.audit_start,
                )
            )
            status = {"state": "available", "events": len(events)}
            logger.info("fetched %d HISTORY audit events", len(events))
        except AuditLogUnavailable as exc:
            # Not fatal: statuses and notes are still derivable, only the date
            # is lost. The report says so rather than leaving a silent blank.
            logger.warning("%s", exc)
            events, status = [], {"state": "unavailable", "detail": str(exc)}
    return capabilities, events, status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="purview_action_update", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workbook", type=Path, default=None,
        help="the Purview Action Update export. Defaults to the first of "
             + ", ".join(str(c) for c in WORKBOOK_CANDIDATES) + " that exists",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--no-run-dir", action="store_true",
        help="write straight into --out instead of a timestamped run-<ISO> "
             "subdirectory. The subdirectory is the default so each cycle's "
             "uploaded workbook and report are retained rather than overwritten.",
    )
    parser.add_argument(
        "--allow-chained-input", action="store_true",
        help="proceed even when the input workbook was produced by a previous run "
             "of this tool. Refused by default: each cycle must start from a FRESH "
             "Purview export, or changes made in Purview since the last run are "
             "silently overwritten.",
    )
    parser.add_argument(
        "--mode", choices=MODES, default=MODE_FILL_EMPTY,
        help="fill-empty (default) writes only blank cells; sync also replaces "
             "cells that disagree with Paramify",
    )
    parser.add_argument(
        "--timezone", default=None, metavar="ZONE",
        help="IANA zone for rendering audit timestamps as Purview dates. Defaults to "
             "this machine's own zone, so the date matches what Paramify shows you; "
             "UTC would put events after ~5pm US-Pacific on the following day. "
             "US zones: " + ", ".join(US_TIMEZONES),
    )
    parser.add_argument(
        "--accept-near-matches", action="store_true",
        help="also join actions whose name matches a capability only after case and "
             "whitespace normalization (reported but not applied by default)",
    )
    parser.add_argument(
        "--notes-policy", choices=NOTES_POLICIES, default=NOTES_FOLLOW_MODE,
        help="how a Paramify narrative meets a note the client already wrote. "
             "'follow-mode' (default) defers to --mode: fill gaps, or replace under "
             "sync. 'append' keeps the client's wording and adds the narrative "
             "beneath it, idempotently. 'replace' always overwrites the cell with "
             "the narrative, whatever --mode says.",
    )
    parser.add_argument(
        "--skip-unassessed-notes", action="store_true",
        help="do not publish the narrative of a capability whose implementation "
             "status is NOT_SET. Off by default: a narrative describes what the "
             "system does, which is independent of whether the status has been set.",
    )
    parser.add_argument(
        "--on-date-conflict", choices=DATE_CONFLICT_CHOICES, default=CONFLICT_SKIP,
        help="Purview requires Test Date >= Implementation Date. When a derived "
             "Implementation Date is later than the row's Test Date: 'skip' (default) "
             "leaves the row alone; 'advance-test' moves Test Date to match, keeping "
             "the recorded result but not its real date; 'clear-test' clears Test Date "
             "and Test Status, which is truthful but discards a recorded pass. The "
             "last two make those two columns writable.",
    )
    parser.add_argument(
        "--strict-test-status", action="store_true",
        help="refuse rows whose Test Status is blank when the new Implementation "
             "Status does not list \"None\" among its permitted values (see README)",
    )
    parser.add_argument(
        "--status-fallback-solcap", action="store_true",
        help="when the audit log holds no status-change activity for a capability, "
             "fall back to its current implementationStatus (no date is derivable). "
             "Off by default: Implementation Status is sourced from the Activity feed.",
    )
    parser.add_argument(
        "--activity-types", default="HISTORY",
        help="comma-separated audit activityTypes to scan (default HISTORY, the type "
             "that carries field changes)",
    )
    parser.add_argument("--audit-start", default=None, metavar="YYYY-MM-DD")
    parser.add_argument("--offline", type=Path, default=None, metavar="DIR",
                        help="read capabilities and audit events from JSON fixtures")
    parser.add_argument(
        "--print-changes", action="store_true",
        help="list every written cell after the summary (old -> new)",
    )
    parser.add_argument(
        "--print-changes-brief", action="store_true",
        help="like --print-changes but omits the long Implementation Notes rows",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="plan and report, but write no workbook")
    parser.add_argument("--probe-audit", action="store_true",
                        help="dump the audit-log record shape and distributions (no values)")
    parser.add_argument("--probe-values", action="store_true",
                        help="with --probe-audit, also histogram SHORT change values on "
                             "solution-capability events, to see what a status change "
                             "looks like on the wire")
    parser.add_argument(
        "--allow-no-changes", action="store_true",
        help="upload even when the run changed no cells. Off by default: an "
             "unchanged workbook in an evidence set is noise, not evidence.",
    )
    parser.add_argument(
        "--min-match-rate", type=float, default=0.5, metavar="0..1",
        help="refuse to upload when fewer than this fraction of action rows match a "
             "solution capability by name (default 0.5). A very low rate almost always "
             "means the token points at the wrong workspace. 0 disables the check.",
    )
    parser.add_argument(
        "--base-url", default=None,
        help="Paramify API base URL. Defaults to PARAMIFY_API_BASE_URL, else "
             "production. Staging is https://stage.paramify.com/api/v0",
    )
    clean = parser.add_argument_group("cleanup (destructive; all require --confirm)")
    clean.add_argument("--list-artifacts", metavar="EVIDENCE_ID", default=None,
                       help="list an Evidence Set's artifacts, marking no-op ones")
    clean.add_argument("--prune-no-op-artifacts", metavar="EVIDENCE_ID", default=None,
                       help="delete artifacts whose note records a run that changed nothing")
    clean.add_argument("--delete-evidence-set", metavar="EVIDENCE_ID", default=None,
                       help="delete an entire Evidence Set and everything attached to it")
    clean.add_argument("--confirm", action="store_true",
                       help="actually perform a cleanup action; without it they only report")
    parser.add_argument("--check-auth", action="store_true",
                        help="validate the token with one cheap read and report which "
                             "auth scheme worked")
    upload_group = parser.add_argument_group("upload to Paramify (opt-in; the only writes)")
    upload_group.add_argument(
        "--upload", action="store_true",
        help="attach the updated workbook AND the run report to a Paramify Evidence Set",
    )
    upload_group.add_argument("--evidence-reference-id",
                              default=upload_mod.DEFAULT_REFERENCE_ID,
                              help="idempotency key: found first, created only if absent")
    upload_group.add_argument("--evidence-name", default=upload_mod.DEFAULT_NAME)
    upload_group.add_argument("--evidence-id", default=None,
                              help="attach to this Evidence Set directly, skipping lookup")
    args = parser.parse_args(argv)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="%(levelname)s %(message)s")

    # Repo convention: credentials live in the repo-root .env, so running from
    # the Terminal needs no exported variables.
    try:
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    except ImportError:
        pass

    run_id = datetime.now(timezone.utc).strftime("run-%Y-%m-%dT%H-%M-%SZ")

    if args.workbook is None:
        args.workbook = default_workbook()
        logger.info("using workbook %s", args.workbook)

    if not args.no_run_dir:
        args.out = args.out / run_id

    if args.base_url:
        os.environ["PARAMIFY_API_BASE_URL"] = args.base_url

    if args.upload and args.dry_run:
        logger.error("--upload cannot be combined with --dry-run: there is no workbook to attach")
        return 2

    try:
        tzinfo, tz_name, tz_how = resolve_timezone(args.timezone)
    except ConfigError as exc:
        logger.error("%s", exc)
        return 2
    logger.info("rendering dates in %s (%s)", tz_name, tz_how)

    try:
        if args.list_artifacts:
            print(upload_mod.describe(upload_mod.list_artifacts(args.list_artifacts)))
            return 0

        if args.prune_no_op_artifacts:
            result = upload_mod.prune_no_op_artifacts(
                args.prune_no_op_artifacts, confirm=args.confirm)
            if not args.confirm:
                logger.warning("DRY RUN — would delete %d artifact(s); "
                               "re-run with --confirm", len(result["would_delete"]))
            json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0

        if args.delete_evidence_set:
            if not args.confirm:
                with ParamifyClient() as client:
                    existing = client.artifacts(args.delete_evidence_set)
                logger.warning(
                    "DRY RUN — would delete evidence set %s and its %d artifact(s); "
                    "re-run with --confirm", args.delete_evidence_set, len(existing))
                print(upload_mod.describe(existing))
                return 0
            result = upload_mod.delete_evidence_set(
                args.delete_evidence_set, confirm=True)
            json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0

        if args.check_auth:
            with ParamifyClient() as client:
                json.dump(client.check_auth(), sys.stdout, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            return 0

        if args.probe_audit:
            with ParamifyClient() as client:
                events = list(client.audit_log_events(
                    activity_types=tuple(
                        t.strip().upper() for t in args.activity_types.split(",") if t.strip()
                    ),
                    start_date=args.audit_start,
                ))
            json.dump(
                audit.probe_shape(events, include_values=args.probe_values),
                sys.stdout, indent=2, sort_keys=True,
            )
            sys.stdout.write("\n")
            return 0

        if args.offline:
            capabilities, events = _load_offline(args.offline)
            audit_status = {"state": "offline-fixture", "events": len(events)}
        else:
            capabilities, events, audit_status = _fetch(args)

        resolutions = audit.index_by_capability(events)
        logger.info("audit log yielded status changes for %d capabilities", len(resolutions))
        if events and not resolutions:
            # Distinguish "nothing changed" from "this log cannot express changes".
            shape = audit.probe_shape(events)
            logger.warning("no status changes recoverable: %s", shape["diagnosis"])
            audit_status = dict(audit_status, diagnosis=shape["diagnosis"],
                                events_carrying_changes=shape["events_carrying_changes"])

        stamp = wb_mod.provenance_of(args.workbook)
        if stamp and not args.allow_chained_input:
            logger.error(
                "refusing to run: %s was produced by this tool (%s), not exported "
                "from Purview.\n"
                "  Each cycle must start from a FRESH export. Re-using the last "
                "run's output means any change made in Purview since then -- a new "
                "improvement action, an edited note, a recorded test -- is invisible "
                "here and gets overwritten on re-upload.\n"
                "  Export again from Compliance Manager -> Assessments, or pass "
                "--allow-chained-input if you are certain.",
                args.workbook.name, stamp.get(wb_mod.PROP_RUN, "unknown run"),
            )
            return 6

        book = wb_mod.load(args.workbook)
        sheet = wb_mod.action_sheet(book)
        headers = wb_mod.header_index(sheet)
        rows = list(wb_mod.iter_rows(sheet, headers))

        matches = build_matches(
            [str(values.get(COL_ACTION_NAME) or "") for _, values in rows], capabilities
        )

        plans = []
        rows_with_activity: list[str] = []
        for row_number, values in rows:
            capability = matches.lookup(
                str(values.get(COL_ACTION_NAME) or ""),
                accept_near=args.accept_near_matches,
            )
            resolution = resolutions.get(str((capability or {}).get("id") or ""))
            if resolution is not None and resolution.timestamp is not None:
                rows_with_activity.append(str(values.get(COL_ACTION_NAME) or ""))
            plans.append(
                plan_row(
                    row_number=row_number,
                    values=values,
                    solcap=capability,
                    resolution=resolution,
                    tzinfo=tzinfo,
                    mode=args.mode,
                    strict_test_status=args.strict_test_status,
                    fallback_solcap=args.status_fallback_solcap,
                    on_date_conflict=args.on_date_conflict,
                    notes_policy=args.notes_policy,
                    skip_unassessed_notes=args.skip_unassessed_notes,
                )
            )

        match_rate = (len(matches.exact) / len(rows)) if rows else 0.0

        out_path = None
        violations: list = []
        if not args.dry_run:
            writable = (
                WRITABLE_COLUMNS if args.on_date_conflict == CONFLICT_SKIP
                else WRITABLE_WITH_TEST_RESOLUTION
            )
            wb_mod.apply(sheet, headers, plans, writable=writable)
            wb_mod.stamp_provenance(book, run_id=run_id, source=str(args.workbook))
            out_path = wb_mod.save(book, args.out / f"{args.workbook.stem}.updated.xlsx")
            logger.info("workbook written to %s", out_path)
            # Independent of the planner: check the FILE, not the decisions.
            violations = verify_mod.verify(args.workbook, out_path, writable=writable)
            if violations:
                logger.error("the produced workbook violates %d Purview rule(s)",
                             len(violations))

        run_report = report_mod.build(
            plans=plans, matches=matches, mode=args.mode,
            timezone_name=f"{tz_name} ({tz_how})", workbook_in=str(args.workbook),
            workbook_out=str(out_path) if out_path else None,
            audit_status=audit_status, capability_count=len(capabilities),
            dry_run=args.dry_run, rows_with_activity=rows_with_activity,
            strict_test_status=args.strict_test_status,
            fallback_solcap=args.status_fallback_solcap,
        )
        run_report["verification"] = {
            "ran": out_path is not None,
            "violations": violations,
        }
        report_path = report_mod.write(run_report, args.out / "run_report.json")
        logger.info("report written to %s", report_path)

        if args.upload and violations:
            logger.error(
                "refusing to upload: the produced workbook violates %d of Purview's "
                "own rules and would be rejected on re-upload. See "
                "run_report.json -> verification.", len(violations))
            print(report_mod.summarize(run_report))
            print(verify_mod.summarize(violations))
            return 5

        if args.upload and not run_report["totals"]["cells_written"] \
                and not args.allow_no_changes:
            logger.error(
                "refusing to upload: the run changed no cells, so the workbook is "
                "byte-identical in content to the one you exported.\n"
                "  %d cell(s) were proposed and held back — see run_report.json for "
                "the reason on each.\n"
                "  Pass --allow-no-changes to upload anyway (e.g. to record a dated "
                "no-op check).",
                run_report["totals"]["cells_held_back"],
            )
            print(report_mod.summarize(run_report))
            return 4

        if args.upload and match_rate < args.min_match_rate:
            # An implausible match rate means the token is pointed at a workspace
            # that does not hold this assessment's capabilities. Uploading here
            # would put a workbook of near-zero changes into the wrong program.
            logger.error(
                "refusing to upload: only %d of %d action rows (%.1f%%) matched a "
                "solution capability by name, below the --min-match-rate of %.0f%%.\n"
                "  This usually means the token points at the wrong Paramify "
                "workspace. %d capabilities in this workspace matched no action row.\n"
                "  The workbook and report were still written to %s for diagnosis.\n"
                "  Pass --min-match-rate 0 to upload anyway.",
                len(matches.exact), len(rows), match_rate * 100,
                args.min_match_rate * 100,
                len(matches.unmatched_capabilities), args.out,
            )
            print(report_mod.summarize(run_report))
            return 3

        if args.upload:
            if out_path is None:
                logger.error("nothing to upload: no workbook was written")
                return 1
            if args.offline:
                # Guard against quietly seeding a real program with fixture data.
                run_report["fixture_sourced"] = True
                report_mod.write(run_report, report_path)
                logger.warning(
                    "uploading a workbook built from OFFLINE FIXTURES, not live "
                    "Paramify data — the artifact note will say so"
                )
            run_report["upload"] = upload_mod.push(
                workbook_path=out_path,
                report_path=report_path,
                report=run_report,
                reference_id=args.evidence_reference_id,
                evidence_name=args.evidence_name,
                evidence_id=args.evidence_id,
            )
            report_mod.write(run_report, report_path)

        print(report_mod.summarize(run_report))
        if out_path is not None:
            print(verify_mod.summarize(violations))
        if args.print_changes or args.print_changes_brief:
            print(report_mod.changes_table(
                run_report,
                skip_columns=("Implementation Notes",) if args.print_changes_brief else (),
            ))
        return 0

    except (ParamifyError, wb_mod.WorkbookError) as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
