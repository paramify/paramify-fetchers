"""Paramify fetcher framework — the unified CLI (`paramify`).

A single Typer command surface over ``framework.api`` (the shared facade). Every
command — human or AI — goes through the facade; nothing here re-implements
discovery, validation, manifest editing, or execution. The TUI is launched as a
subcommand (``paramify tui``) so one CLI steers every front-end, and the
headless CLI is a strict superset of what the TUI can do (see
``tests/test_cli.py``, which enforces that invariant).

Read / discover:
  paramify list [--json]                       # discovered fetchers (flat)
  paramify catalog [--json]                    # categories -> fetchers -> fields
  paramify describe <fetcher> [--json]
  paramify ksi [--json]                        # FedRAMP KSI coverage
  paramify doctor [manifest] [--probe] [--json]  # preflight: deps, manifest, upload
  paramify manifests [--json]                  # discovered run manifests
  paramify runs [--output-dir DIR] [--json]    # past runs under an output dir
    paramify evidence <path> [--json]            # read one evidence file (or issue-report sidecar)
  paramify upload [run-dir] [--dry-run] [--json]

Paramify workspace (live lookups; needs PARAMIFY_API_TOKEN with read scope):
  paramify programs list [--json]              # programs in the workspace: name + id
  paramify programs target [fetcher ...] [--program NAME|ID ...] [--all]
                           [--cert-uri URI] [--report-from DATE] [-f FILE] [--json]
                           # -f takes a bare name (resolved under manifests/) or a
                           # path; omit it to pick from the discovered manifests
  paramify assessments list [--type VULNERABILITY|CONFIGURATION] [--json]
  paramify assessments select [fetcher ...] [--assessment NAME|ID] [-f FILE] [--json]
                           # points issue-report fetchers at an assessment

Manifest editing (writes the manifest file; -f/--file, default ./manifest.yaml;
every subcommand accepts --json, emitting {"ok", "path", "errors"}):
  paramify manifest init [--output-dir DIR]
  paramify manifest new <name> [--output-dir DIR]      # creates manifests/<name>.yaml
  paramify manifest add <fetcher>
  paramify manifest remove <fetcher>
  paramify manifest set-config <fetcher> key=value
  paramify manifest set-secret <fetcher> <secret_name> <ENV_VAR>
  paramify manifest add-target <fetcher> k=v ... [--secret name=ENV_VAR ...]
  paramify manifest remove-target <fetcher> <index>
  paramify manifest set-platform-config <category> key=value
  paramify manifest set-passthrough <category> ENV_VAR ...
  paramify manifest set-output-dir <dir>
  paramify manifest show [--json]

Validate / run / launch:
  paramify validate <manifest> [--json]
  paramify run <manifest> [--json]
  paramify upload [run-dir] [--output-dir DIR] [--config PATH] [--dry-run] [--json]
  paramify issues upload [run-dir] [--output-dir DIR] [--config PATH] [--dry-run] [--json]
  paramify tui [--manifest PATH] [--at ROOT]   # interactive terminal UI

Secrets are referenced as ${env:VAR} — set-secret / add-target take the ENV VAR
NAME, never the secret value. The runner resolves refs from its own environment.
Outputs land in <output_dir>/run-<timestamp>/ with a _run_metadata.json.

Two collection kinds, two upload commands: evidence fetchers write enveloped JSON
that `paramify upload` attaches to evidence sets, while `kind: issue_report`
fetchers write raw scan files to <run>/issue-reports/ that `paramify issues
upload` posts to assessment intake. A run of both needs both commands. See
docs/issue_report_fetchers.md.
"""

from __future__ import annotations

import json
import os
import re
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import List, NoReturn, Optional

import typer

from framework import api, paramify_auth
from framework import cli_style as style
from framework.issue_reports import ISSUE_REPORTS_DIR

_DEFAULT_MANIFEST = "manifest.yaml"

# context_settings registers `-h` as an alias for `--help` at every level
# (top-level, each command, the manifest group, and its subcommands), matching
# the old argparse CLI — argparse gave `-h` for free; Typer/Click does not.
_HELP_OPTS = {"help_option_names": ["-h", "--help"]}

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    context_settings=_HELP_OPTS,
    help="Paramify fetcher framework — discover, build, run, and inspect evidence fetchers.",
)
manifest_app = typer.Typer(
    no_args_is_help=True,
    context_settings=_HELP_OPTS,
    help="Create/edit a manifest file (-f/--file, default ./manifest.yaml).",
)
app.add_typer(manifest_app, name="manifest")

scripts_app = typer.Typer(
    no_args_is_help=True,
    context_settings=_HELP_OPTS,
    help="Sync fetcher entry scripts to Paramify and associate them to evidence sets.",
)
app.add_typer(scripts_app, name="scripts")

programs_app = typer.Typer(
    no_args_is_help=True,
    context_settings=_HELP_OPTS,
    help="List the workspace's programs and turn them into manifest targets.",
)
app.add_typer(programs_app, name="programs")

assessments_app = typer.Typer(
    no_args_is_help=True,
    context_settings=_HELP_OPTS,
    help="List the workspace's assessments and point issue-report fetchers at one.",
)
app.add_typer(assessments_app, name="assessments")

issues_app = typer.Typer(
    no_args_is_help=True,
    context_settings=_HELP_OPTS,
    help="Upload issue reports (scan results) into Paramify assessment intake.",
)
app.add_typer(issues_app, name="issues")


@app.callback()
def _root(ctx: typer.Context) -> None:
    """Resolve color once for every subcommand.

    typer.echo already strips ANSI when stdout is not a tty, which is the right
    default: it keeps `--json` machine-readable and CI logs free of escapes. These
    two env vars override it in both directions, per the NO_COLOR / FORCE_COLOR
    conventions — FORCE_COLOR is what lets `paramify evidence … | head` keep its
    highlighting, which is how the README demos are recorded.
    """
    if os.environ.get("NO_COLOR"):
        ctx.color = False
    elif os.environ.get("FORCE_COLOR"):
        ctx.color = True


# --------------------------------------------------------------------------- #
# Small shared helpers (ported verbatim from the previous argparse CLI)
# --------------------------------------------------------------------------- #

def _err(msg: str) -> None:
    typer.echo(msg, err=True)


def _coerce(raw: str, typ: str):
    """Coerce a CLI string value to a config/target field's declared type."""
    if typ == "boolean":
        return str(raw).strip().lower() in ("true", "1", "yes", "on")
    if typ == "integer":
        return int(raw)
    return raw


def _fail(path, msg: str, json_out: bool) -> NoReturn:
    """Report a command-level argument error honoring --json, then exit 1.

    Keeps the {ok, path, errors} contract on mutator argument-error paths (a
    missing '=' or an un-coercible integer) instead of letting Click emit a
    usage panel (exit 2) or a raw traceback (exit 1) that leaves a --json
    consumer with empty stdout.
    """
    if json_out:
        typer.echo(json.dumps({"ok": False, "path": str(path) if path else None, "errors": [msg]}, indent=2))
    else:
        _err(msg)
    raise typer.Exit(1)


def _parse_kv(arg: str, path, json_out: bool):
    if "=" not in arg:
        _fail(path, f"expected key=value, got: {arg!r}", json_out)
    return arg.split("=", 1)


def _coerce_or_fail(value: str, typ: str, key: str, path, json_out: bool):
    try:
        return _coerce(value, typ)
    except ValueError:
        _fail(path, f"{key}: expected {typ}, got: {value!r}", json_out)


def _find_fetcher(cat: dict, name: str):
    for c in cat["categories"]:
        for f in c["fetchers"]:
            if f["name"] == name:
                return f
    return None


def _config_type(root: Path, fetcher_name: str, key: str) -> str:
    """Look up a config field's declared type (fetcher then platform), else string."""
    cat = api.catalog(root)
    f = _find_fetcher(cat, fetcher_name)
    if f:
        for fld in f["config"]:
            if fld["name"] == key:
                return fld["type"]
        cat_name = f["category"]
        for c in cat["categories"]:
            if c["name"] == cat_name and c.get("platform"):
                for fld in c["platform"]["config"]:
                    if fld["name"] == key:
                        return fld["type"]
    return "string"


def _platform_config_type(root: Path, category: str, key: str) -> str:
    cat = api.catalog(root)
    for c in cat["categories"]:
        if c["name"] == category and c.get("platform"):
            for fld in c["platform"]["config"]:
                if fld["name"] == key:
                    return fld["type"]
    return "string"


def _target_field_type(root: Path, fetcher_name: str, key: str) -> str:
    cat = api.catalog(root)
    f = _find_fetcher(cat, fetcher_name)
    if f:
        for fld in f["target_schema"]:
            if fld["name"] == key:
                return fld["type"]
    return "string"


def _human_run_printer():
    """Return an on_event callback that reproduces the original CLI run output."""
    def on_event(ev: dict) -> None:
        kind = ev["event"]
        if kind == "run_start":
            typer.echo(f"Run {style.head(ev['run_id'])} → {style.path(ev['run_dir'])}\n")
        elif kind == "fetcher_skip":
            _err(f"  {style.mark('SKIP')}  {style.name(ev['fetcher'])} {style.dim('(' + ev['reason'] + ')')}")
        elif kind == "fetcher_start":
            targets = style.dim(f"  ({ev['targets']} targets)") if ev["fanout"] else ""
            typer.echo(f"  {style.dim('RUN')}   {style.name(ev['fetcher'])}{targets}")
        elif kind == "fetcher_error":
            _err(f"        {style.fail('runner error')}: {ev['error']}")
        elif kind == "fetcher_result":
            m = "OK" if ev["exit_code"] == 0 else "FAIL"
            detail = f"exit={ev['exit_code']} duration={ev['duration_sec']}s"
            target = f"  target={ev['target']}" if ev["target"] else ""
            typer.echo(
                f"        [{style.mark(m)}] {style.dim(detail)}{style.env(target)}"
            )
        elif kind == "run_complete":
            typer.echo(f"\n_run_metadata.json → {style.path(ev['metadata_path'])}")
        # log_line is intentionally not printed (matches prior non-streaming CLI)
    return on_event


def _human_upload_printer(noun: str = "file", log_name: str = "upload_log.json"):
    """Return an on_event callback for Paramify upload progress.

    Shared by the evidence and issue-report stages: both emit the same
    upload_start / upload_file / upload_complete events, and differ only in what
    they call the thing being sent and where each item landed.
    """
    def on_event(ev: dict) -> None:
        kind = ev["event"]
        if kind == "upload_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            typer.echo(
                f"Upload {ev['files']} {noun}(s) from {ev['run_dir']} → {ev['base_url']}{mode}\n"
            )
        elif kind == "upload_file":
            outcome = ev.get("outcome")
            if outcome == "uploaded":
                mark = "OK"
            elif outcome in ("skipped_duplicate", "skipped_failed"):
                mark = "SKIP"
            elif outcome == "would_upload":
                mark = "DRY"
            else:
                mark = "FAIL"
            if ev.get("reference_id"):
                ref = f"  set={ev['reference_id']}"
            elif ev.get("assessment_id"):
                ref = f"  assessment={ev['assessment_id']}"
            else:
                ref = ""
            reason = ev.get("reason") or ev.get("error")
            suffix = f"  {reason}" if reason else ""
            typer.echo(
                f"        [{style.mark(mark)}] {ev.get('file', '?')}"
                f"{style.env(ref)}{style.dim(suffix)}"
            )
        elif kind == "upload_complete":
            typer.echo(
                "\nDone: "
                f"uploaded={ev['uploaded']} "
                f"skipped_duplicate={ev['skipped_duplicate']} "
                f"skipped_failed={ev['skipped_failed']} "
                f"errors={ev['errors']}"
            )
            if ev.get("halted"):
                typer.echo(f"\nStopped early: {ev['halted']}")
            if ev.get("log_path"):
                typer.echo(f"{log_name} → {ev['log_path']}")
    return on_event


def _upload_stage(
    *,
    run_dir: Optional[str],
    output_dir: str,
    config: Optional[str],
    dry_run: bool,
    json_out: bool,
    preflight_fn,
    upload_fn,
    noun: str,
    log_name: str,
    upload_kwargs: Optional[dict] = None,
) -> NoReturn:
    """Resolve a run directory, preflight it, and upload — the whole flow for one
    upload stage.

    Both stages (evidence artifacts, issue-report intake) do exactly this against
    different endpoints. Parameterizing it keeps the token prompt, the JSON error
    shape, and the exit codes identical between them, which is what a caller
    scripting either one depends on.
    """
    root = api.find_repo_root()
    if run_dir:
        resolved_run_dir = Path(run_dir).resolve()
    else:
        runs = api.list_runs(output_dir)
        if not runs:
            msg = f"No runs found under {output_dir}."
            if json_out:
                typer.echo(json.dumps({"ok": False, "errors": [msg]}, indent=2))
            else:
                _err(msg)
            raise typer.Exit(1)
        resolved_run_dir = Path(runs[0]["dir"]).resolve()

    config_path = Path(config).resolve() if config else None
    try:
        preflight = preflight_fn(resolved_run_dir, root, config_path, dry_run=dry_run)
    except Exception as e:  # noqa: BLE001 — surface setup errors to CLI users
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Upload setup failed: {e}")
        raise typer.Exit(1)
    # A missing token is the one preflight failure a person can fix on the spot,
    # and by here they have already paid for a full collection. Ask, rather than
    # making them quit, export, and re-run. --json and CI never reach this: a
    # prompt there hangs the job instead of failing it.
    if not preflight["ok"] and not preflight["token_present"] and not json_out:
        if paramify_auth.prompt_for_token(preflight["base_url"]) is not None:
            preflight = preflight_fn(resolved_run_dir, root, config_path, dry_run=dry_run)

    if not preflight["ok"]:
        if json_out:
            typer.echo(json.dumps(preflight, indent=2, default=str))
        else:
            for err in preflight["errors"]:
                _err(f"  ERROR  {err}")
        raise typer.Exit(1)

    if not json_out:
        typer.echo(f"Uploading to {preflight['base_url_label']}: {preflight['base_url']}")

    try:
        summary = upload_fn(
            resolved_run_dir,
            root,
            config_path,
            dry_run=dry_run,
            on_event=None if json_out else _human_upload_printer(noun, log_name),
            **(upload_kwargs or {}),
        )
    except Exception as e:  # noqa: BLE001
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Upload failed: {e}")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(summary, indent=2, default=str))
    raise typer.Exit(0 if summary["ok"] else 1)


# --------------------------------------------------------------------------- #
# Discover / describe
# --------------------------------------------------------------------------- #

@app.command("list")
def list_cmd(json_out: bool = typer.Option(False, "--json", help="Emit JSON")):
    """List discovered fetchers (flat)."""
    root = api.find_repo_root()
    cat = api.catalog(root)
    fetchers = sorted(
        (f for c in cat["categories"] for f in c["fetchers"]),
        key=lambda f: f["name"],
    )
    if json_out:
        typer.echo(json.dumps(fetchers, indent=2))
        return
    if not fetchers:
        typer.echo("No fetchers discovered.")
        return
    typer.echo(f"Discovered {len(fetchers)} fetchers:\n")
    for f in fetchers:
        tag = "fanout" if f["supports_targets"] else "single"
        # Pad before styling: ANSI codes count as characters to str.format, so a
        # styled value formatted to a width lands short by the length of its escape.
        col = "{:50s}".format(f["name"])
        ver = "v{:8s}".format(f["version"])
        typer.echo(
            f"  {style.name(col)} {style.dim(ver)} [{style.dim('{:6s}'.format(tag))}]"
            f" {style.dim('category=')}{style.env(f['category'] or '-')}"
        )


@app.command("catalog")
def catalog_cmd(json_out: bool = typer.Option(False, "--json", help="Emit JSON")):
    """Show categories -> fetchers -> editable fields."""
    root = api.find_repo_root()
    cat = api.catalog(root)
    if json_out:
        typer.echo(json.dumps(cat, indent=2))
        return
    for c in cat["categories"]:
        desc = style.dim(f" — {c['description'].strip()}") if c.get("description") else ""
        typer.echo(f"\n{style.head(style.name(c['name']))}{desc}")
        if c.get("platform") and c["platform"]["config"]:
            keys = ", ".join(style.env(f["name"]) for f in c["platform"]["config"])
            typer.echo(f"  {style.dim('platform config:')} {keys}")
        for f in c["fetchers"]:
            tag = "fanout" if f["supports_targets"] else "single"
            # Pad before styling — see the note in list_cmd.
            typer.echo(f"    {'{:48s}'.format(f['name'])} [{style.dim(tag)}]")


@app.command("describe")
def describe_cmd(
    fetcher: str = typer.Argument(..., help="Fetcher name (globally unique)"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Describe one fetcher's config / secrets / target fields."""
    root = api.find_repo_root()
    cat = api.catalog(root)
    f = _find_fetcher(cat, fetcher)
    if f is None:
        _err(f"Unknown fetcher: {fetcher}")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(f, indent=2))
        return
    typer.echo(
        f"{style.head(style.name(f['name']))}  {style.dim('v' + f['version'])}"
        f"  {style.dim('(category=')}{style.env(f['category'] or '-')}{style.dim(')')}"
    )
    typer.echo(f"  {f['description']}")
    typer.echo(f"  {style.dim('supports_targets:')} {f['supports_targets']}")
    for label, fields in (("config", f["config"]), ("secrets", f["secrets"]),
                          ("target_schema", f["target_schema"])):
        if fields:
            typer.echo(f"  {style.head(label)}:")
            for fld in fields:
                req = style.warn("required") if fld.get("required") else style.dim("optional")
                extra = (
                    style.dim(f" default={fld['default']}")
                    if fld.get("default") is not None else ""
                )
                var = f"  {style.dim('env=')}{style.env(fld['env'])}" if fld.get("env") else ""
                typer.echo(
                    f"    - {style.env(fld['name'])} {style.dim('(' + fld['type'] + ',')} "
                    f"{req}{style.dim(')')}{extra}{var}"
                )
                # The env var and the description are what someone needs to wire
                # this field into a manifest, and the schemas say describe shows
                # them. Wrapped rather than truncated: a secret's description is
                # where "optional" is explained, and half of that is no use.
                if fld.get("description"):
                    for line in textwrap.wrap(
                        " ".join(fld["description"].split()), width=76,
                        initial_indent=" " * 8, subsequent_indent=" " * 8,
                        # Identifiers -- env vars, account names, fetcher names --
                        # are most of what these descriptions name; splitting them
                        # at a hyphen or a width boundary makes them unsearchable.
                        break_on_hyphens=False, break_long_words=False,
                    ):
                        typer.echo(line)


@app.command("ksi")
def ksi_cmd(json_out: bool = typer.Option(False, "--json", help="Emit JSON")):
    """Show FedRAMP KSI coverage across discovered fetchers."""
    root = api.find_repo_root()
    cov = api.ksi_coverage(root)
    if json_out:
        typer.echo(json.dumps(cov, indent=2))
        return
    s = cov["summary"]
    release = cov["release"].split("—", 1)[-1].strip() if "—" in cov["release"] else cov["release"]
    typer.echo("FedRAMP KSI coverage")
    typer.echo(f"{release}\n")

    bar_w = 10
    for fam in cov["families"]:
        evi = fam["evidenceable"]
        if evi == 0:
            typer.echo(f"  {fam['family']:4s} {fam['name']:33s} {'·' * bar_w}  organizational ({fam['total']})")
            continue
        filled = round(bar_w * fam["covered"] / evi)
        bar = "█" * filled + "░" * (bar_w - filled)
        note = ""
        if fam["gaps"]:
            note = f"   gap{'s' if len(fam['gaps']) > 1 else ''}: " + ", ".join(fam["gaps"])
        typer.echo(f"  {fam['family']:4s} {fam['name']:33s} {bar}  {fam['covered']}/{evi}{note}")

    typer.echo(
        f"\n  {s['covered']}/{s['evidenceable']} config-evidenceable KSIs covered  ·  "
        f"{s['coverage_pct']}%  ·  {s['gaps']} gaps  ·  {s['organizational']} organizational"
    )
    if cov["unknown_ksis"]:
        typer.echo("\n  ⚠ KSIs used by fetchers but absent from the reference:")
        for u in cov["unknown_ksis"]:
            typer.echo(f"    {u['id']:14s} {', '.join(u['fetchers'])}")


@app.command("doctor")
def doctor_cmd(
    manifest: Optional[str] = typer.Argument(
        None, help="Manifest to check secret env vars for (optional)"
    ),
    upload_config: Optional[str] = typer.Option(
        None, "--upload-config", help="Uploader config YAML, to resolve its base_url"
    ),
    require_upload: bool = typer.Option(
        False, "--require-upload", help="Fail if the run could not be uploaded"
    ),
    probe: bool = typer.Option(
        False, "--probe", help="Authenticate to each cloud category and report the identity"
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Preflight: Python, CLIs and packages, and (with a manifest) validity + secrets.

    Passing a manifest narrows every check to the categories it actually uses, so
    a GitLab-only run is never told to install the aws CLI, and validates it the
    way the runner does — an unknown fetcher name or a missing required config key
    fails here rather than at run time. Upload readiness (API token and
    destination URL) is always reported; --require-upload makes it count toward
    the exit code.
    """
    root = api.find_repo_root()
    rep = api.doctor(
        root,
        Path(manifest) if manifest else None,
        upload_config=Path(upload_config) if upload_config else None,
        require_upload=require_upload,
        probe=probe,
    )
    if json_out:
        typer.echo(json.dumps(rep, indent=2))
        raise typer.Exit(0 if rep["ok"] else 1)

    ok_mark, bad_mark = "✅", "❌"
    p = rep["python"]
    typer.echo(
        f"{ok_mark if p['ok'] else bad_mark} Python {p['version']} "
        f"{style.dim('(need ≥ ' + p['required'] + ')')}"
    )

    if rep["tools"]:
        heading = "Required CLIs" if rep["tools_required"] else "CLIs for discovered categories"
        typer.echo(f"\n{style.head(heading)}:")
        for t in rep["tools"]:
            mark = ok_mark if t["present"] else bad_mark
            where = style.path(t["path"]) if t["path"] else style.fail("not found on PATH")
            cats = style.dim(f"  ({', '.join(t['categories'])})")
            typer.echo(f"  {mark} {style.env('{:8s}'.format(t['name']))} {where}{cats}")
        if not rep["tools_required"]:
            typer.echo("  (informational — you only need the CLIs for categories you run)")

    for grp in rep.get("packages") or []:
        # Only the problems are listed by name: a healthy category is a one-line
        # count, since 23 green azure packages is noise, not information.
        bad = [p for p in grp["packages"] if not p["ok"]]
        if not bad:
            typer.echo(
                f"\n{ok_mark} {grp['category']} packages: "
                f"{len(grp['packages'])} installed and within pins"
            )
            continue
        typer.echo(f"\n{bad_mark} {grp['category']} packages:")
        for pkg in bad:
            if pkg["status"] == "missing":
                typer.echo(f"  {bad_mark} {pkg['name']:42s} not installed")
            else:
                typer.echo(
                    f"  {bad_mark} {pkg['name']:42s} {pkg['installed']} "
                    f"installed, needs {pkg['required']}"
                )
        typer.echo("  fix: pip install -r requirements.txt")

    if rep.get("probes"):
        typer.echo(f"\n{style.head('Credentials (live)')}:")
        for pr in rep["probes"]:
            if pr["ok"]:
                typer.echo(f"  {ok_mark} {pr['category']:6s} {pr['identity']}")
                # The detail line is the point of the probe: credentials that
                # authenticate against the wrong account produce a clean run
                # full of empty evidence.
                bits = [f"{k}={v}" for k, v in (pr["detail"] or {}).items() if v]
                if bits:
                    typer.echo(f"           {'  '.join(bits)}")
            else:
                typer.echo(f"  {bad_mark} {pr['category']:6s} {pr['error']}")

    up = rep.get("upload")
    if up:
        typer.echo(f"\n{style.head('Upload')}:")
        src = f" (from {up['token_source']})" if up["token_source"] else ""
        if up["token_present"]:
            typer.echo(f"  {ok_mark} API token set{src}")
        else:
            typer.echo(
                f"  {bad_mark} API token not set — "
                f"{style.env(api.UPLOAD_TOKEN_ENV)} {style.dim('(or')} "
                f"{style.env(api.READ_TOKEN_ENV)}{style.dim(')')}"
            )
        # Shown whether or not the token resolved: the destination is the other
        # half of "am I about to do the right thing", and stage-vs-production is
        # invisible in the run output once it succeeds.
        origin = (
            "default" if up["base_url_source"] == "default"
            else f"from {up['base_url_source']}"
        )
        typer.echo(
            f"  → {up['base_url_label']}: {style.path(up['base_url'])}  {style.dim('(' + origin + ')')}"
        )
        if not rep.get("upload_required") and not up["ok"]:
            typer.echo(style.dim("  (informational — collecting without uploading is fine)"))

    if rep["manifest"]:
        m = rep["manifest"]
        # Validity before secrets: an unknown fetcher name or an unset required
        # config key is what makes the run fail, and no amount of secret listing
        # shows it.
        if m["errors"]:
            typer.echo(f"\n{style.head('Manifest')} {style.path('(' + str(m['path']) + ')')}:")
            for err in m["errors"]:
                typer.echo(f"  {bad_mark} {err}")
        else:
            n = len(m["fetchers"])
            typer.echo(
                f"\n{ok_mark} Manifest valid {style.path('(' + str(m['path']) + ')')}: "
                f"{style.dim(str(n) + ' entr' + ('y' if n == 1 else 'ies'))}"
            )

        if m["fetchers"]:
            typer.echo(
                f"\n{style.head('Manifest secrets')} {style.path('(' + str(m['path']) + ')')}:"
            )
        for fr in m["fetchers"]:
            use = style.name(fr["use"])
            if not fr["known"]:
                typer.echo(f"  {bad_mark} {use}  {style.fail('unknown fetcher — see above')}")
            elif not fr["env_refs"]:
                typer.echo(f"  {ok_mark} {use}  {style.dim('(no secrets)')}")
            elif fr["ok"]:
                refs = style.dim("(") + style.env(", ".join(fr["env_refs"])) + style.dim(")")
                typer.echo(f"  {ok_mark} {use}  {refs}")
            else:
                typer.echo(
                    f"  {bad_mark} {use}  {style.fail('missing:')} "
                    f"{style.env(', '.join(fr['missing']))}"
                )
            # Advisory: set, but shaped like a value that will fail at the API.
            for warn in fr["warnings"]:
                typer.echo(f"  ⚠️  {style.warn(warn)}")

    if not rep["ok"]:
        typer.echo("\n" + style.verdict(False, "Issues found — see above."))
    elif any(not pr["ok"] for pr in rep.get("probes") or []):
        # The checks that gate the exit code passed, but a live credential did
        # not answer. Saying "All good" over the top of that is how a preflight
        # teaches people to stop reading it.
        typer.echo("\n" + style.warn(
            "Checks passed, but a live credential check failed — see above."
        ))
    else:
        typer.echo("\n" + style.verdict(True, "All good."))
    raise typer.Exit(0 if rep["ok"] else 1)


@app.command("manifests")
def manifests_cmd(json_out: bool = typer.Option(False, "--json", help="Emit JSON")):
    """List discovered run manifests (manifests/*.yaml + legacy manifest.yaml)."""
    root = api.find_repo_root()
    items = api.list_manifests(root)
    if json_out:
        typer.echo(json.dumps(items, indent=2))
        return
    if not items:
        typer.echo("No manifests found (looked in ./manifests/*.yaml and ./manifest.yaml).")
        return
    typer.echo(f"Discovered {len(items)} manifest(s):\n")
    for m in items:
        if not m["readable"]:
            typer.echo(f"  {m['name']:32s} (unreadable)")
            continue
        if m["runnable"]:
            state = "runnable"
        elif m["issues"] is not None:
            state = f"{m['issues']} issue(s)"
        else:
            state = "unvalidated"
        last = f"  last={m['last_result']}" if m.get("last_result") else ""
        typer.echo(f"  {m['name']:32s} {m['fetcher_count']:2d} fetchers  [{state}]{last}")


@app.command("runs")
def runs_cmd(
    output_dir: str = typer.Option("./evidence", "-o", "--output-dir", help="Run output dir to scan"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """List past runs under an output dir (newest first)."""
    runs = api.list_runs(output_dir)
    if json_out:
        typer.echo(json.dumps(runs, indent=2, default=str))
        return
    if not runs:
        typer.echo(f"No runs found under {output_dir}.")
        return
    typer.echo(f"{len(runs)} run(s) under {output_dir} (newest first):\n")
    for r in runs:
        total = r["ok"] + r["fail"]
        if not r["complete"]:
            status = "incomplete"
        elif r["fail"]:
            status = "has failures"
        else:
            status = "ok"
        when = r.get("started_at") or "?"
        tone = style.ok if status == "ok" else style.warn if status == "incomplete" else style.fail
        typer.echo(
            f"  {style.name('{:26s}'.format(r['run_id']))} {style.dim(when)}  "
            f"{r['ok']}/{total} ok  {style.dim(str(len(r['files'])) + ' files')}  [{tone(status)}]"
        )


@app.command("evidence")
def evidence_cmd(
    path: str = typer.Argument(..., help="Path to an evidence JSON file, or an issue-report file"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Read & display one evidence file (or the sidecar record of an issue report)."""
    p = Path(path)
    if p.parent.name == ISSUE_REPORTS_DIR:
        try:
            rec = api.read_issue_report(p)
        except ValueError as e:
            if json_out:
                typer.echo(json.dumps({"error": str(e)}, indent=2))
            else:
                _err(str(e))
            raise typer.Exit(1)
        if json_out:
            typer.echo(json.dumps(rec, indent=2, default=str))
            return
        typer.echo(api.preview_issue_report(p))
        return
    try:
        ev = api.read_evidence(path)
    except ValueError as e:
        if json_out:
            typer.echo(json.dumps({"error": str(e)}, indent=2))
        else:
            _err(str(e))
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(ev, indent=2, default=str))
        return
    # ensure_ascii=False: this view is for a person reading their own evidence, and
    # \u00e9 / \u2014 in place of the characters a tenant actually uses makes names
    # unreadable and unsearchable. The file on disk is untouched either way.
    typer.echo(f"{style.dim('enveloped:')} {ev['enveloped']}")
    if ev["schema_version"]:
        typer.echo(f"{style.dim('schema_version:')} {ev['schema_version']}")
    if ev["metadata"]:
        typer.echo(style.head("metadata:"))
        rendered = json.dumps(ev["metadata"], indent=2, default=str, ensure_ascii=False)
        typer.echo("  " + style.highlight_json(rendered).replace("\n", "\n  "))
    typer.echo(style.head("payload:"))
    typer.echo(style.highlight_json(
        json.dumps(ev["payload"], indent=2, default=str, ensure_ascii=False)
    ))


# --------------------------------------------------------------------------- #
# Validate / run
# --------------------------------------------------------------------------- #

@app.command("validate")
def validate_cmd(
    manifest: str = typer.Argument(..., help="Path to manifest yaml"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Validate a manifest against the schema + discovered fetchers."""
    root = api.find_repo_root()
    mpath = Path(manifest).resolve()
    if not mpath.is_file():
        msg = f"no such manifest: {manifest}"
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [msg]}, indent=2))
        else:
            _err(f"Validation failed: {msg}")
        raise typer.Exit(1)
    try:
        m = api.read_manifest(mpath)
    except Exception as e:  # noqa: BLE001 — surface any load error to the user
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Validation failed: {e}")
        raise typer.Exit(1)
    errors = api.validate(m, root)
    if json_out:
        typer.echo(json.dumps({"ok": not errors, "errors": errors}, indent=2))
        raise typer.Exit(0 if not errors else 1)
    if errors:
        for err in errors:
            _err(f"  {style.fail('ERROR')}  {err}")
        raise typer.Exit(1)
    n = len(m.get("run", {}).get("fetchers", []))
    typer.echo(
        f"{style.verdict(True, 'OK')}  manifest valid; {style.dim(str(n) + ' fetcher entries')}"
    )


@app.command("run")
def run_cmd(
    manifest: str = typer.Argument(..., help="Path to manifest yaml"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON summary"),
):
    """Run a manifest; streams per-fetcher results (or a JSON summary with --json)."""
    root = api.find_repo_root()
    mpath = Path(manifest).resolve()
    if not mpath.is_file():
        msg = f"no such manifest: {manifest}"
        if json_out:
            typer.echo(json.dumps({"ok": False, "error": msg}, indent=2))
        else:
            _err(f"Setup failed: {msg}")
        raise typer.Exit(1)
    try:
        m = api.read_manifest(mpath)
    except Exception as e:  # noqa: BLE001
        if json_out:
            typer.echo(json.dumps({"ok": False, "error": str(e)}, indent=2))
        else:
            _err(f"Setup failed: {e}")
        raise typer.Exit(1)
    # Said before the run, not after: collection can take a long time, and
    # discovering the upload token is missing at the end of it is the complaint
    # this answers. Advisory only — collecting without uploading is legitimate.
    if not json_out:
        readiness = api.upload_readiness(root)
        if not readiness["token_present"]:
            typer.echo(
                f"Note: no Paramify API token set, so `paramify upload` will need one "
                f"({api.UPLOAD_TOKEN_ENV}). Collecting anyway.\n"
            )

    try:
        summary = api.run(
            m, root,
            on_event=None if json_out else _human_run_printer(),
            manifest_path=Path(manifest).resolve(),
        )
    except (ValueError, RuntimeError) as e:
        if json_out:
            typer.echo(json.dumps({"ok": False, "error": str(e)}, indent=2))
        else:
            _err(f"Run failed: {e}")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(summary, indent=2, default=str))
    raise typer.Exit(0 if summary["ok"] else 1)


@app.command("upload")
def upload_cmd(
    run_dir: Optional[str] = typer.Argument(None, help="Run directory to upload (default: latest under --output-dir)"),
    output_dir: str = typer.Option("./evidence", "-o", "--output-dir", help="Base dir to find latest run"),
    config: Optional[str] = typer.Option(None, "--config", help="Uploader config YAML"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Resolve and report what would upload; no API calls"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON summary"),
):
    """Upload one evidence run to Paramify.

    Evidence only. Issue reports collected by the same run go to a different
    endpoint — see `paramify issues upload`.
    """
    _upload_stage(
        run_dir=run_dir,
        output_dir=output_dir,
        config=config,
        dry_run=dry_run,
        json_out=json_out,
        preflight_fn=api.upload_preflight,
        upload_fn=api.upload_run,
        noun="file",
        log_name="upload_log.json",
    )


# --------------------------------------------------------------------------- #
# Scripts — sync fetcher entry scripts to Paramify + associate to evidence sets
# --------------------------------------------------------------------------- #

def _human_scripts_printer():
    """Return an on_event callback for Paramify scripts-sync progress."""
    _marks = {
        "create": "NEW", "update": "UPD", "noop": "OK", "drift_skipped": "DRIFT",
        "would_create": "DRY+", "would_update": "DRY~", "would_noop": "DRY=",
        "would_drift": "DRY!", "error": "FAIL",
    }

    def on_event(ev: dict) -> None:
        kind = ev["event"]
        if kind == "sync_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            typer.echo(f"Sync {ev['fetchers']} fetcher script(s) → {ev['base_url']}{mode}\n")
        elif kind == "sync_item":
            mark = _marks.get(ev.get("outcome"), "?")
            assoc = " +assoc" if ev.get("associated") else ""
            reason = ev.get("reason") or ev.get("error")
            suffix = f"  {reason}" if reason else ""
            typer.echo(f"        [{mark}] {ev.get('fetcher', '?')}  set={ev.get('reference_id')}{assoc}{suffix}")
        elif kind == "sync_complete":
            typer.echo(
                "\nDone: "
                f"created={ev['created']} updated={ev['updated']} drift={ev['drift']} "
                f"noop={ev['noop']} associated={ev['associated']} errors={ev['errors']}"
            )
    return on_event


@scripts_app.command("sync")
def scripts_sync_cmd(
    manifest: Optional[str] = typer.Argument(None, help=f"Sync only the fetchers this manifest uses (default: {_DEFAULT_MANIFEST}). Ignored with --all."),
    config: Optional[str] = typer.Option(None, "--config", help="Uploader config YAML (base_url, overrides)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report the plan; read-only (no writes)"),
    force: bool = typer.Option(False, "--force", help="Push scripts whose code drifted without a version bump"),
    reassociate: bool = typer.Option(False, "--reassociate", help="Ensure the association for every fetcher, not just changed ones"),
    all_fetchers: bool = typer.Option(False, "--all", help="Sync every fetcher in the repo, not just the manifest's"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON summary"),
):
    """Sync fetcher entry scripts to Paramify and associate them to evidence sets.

    Scoped to a manifest by default — it provisions scripts for the fetchers you
    actually collect, mirroring how `upload` is run-scoped. Use --all to push the
    whole catalog.
    """
    root = api.find_repo_root()
    config_path = Path(config).resolve() if config else None
    include = None
    if not all_fetchers:
        mpath = Path(manifest).resolve() if manifest else (root / _DEFAULT_MANIFEST)
        m = api.read_manifest(mpath)
        entries = (m.get("run") or {}).get("fetchers") or []
        include = {e.get("use") for e in entries if e.get("use")}
    try:
        preflight = api.scripts_sync_preflight(root, config_path, dry_run=dry_run, include=include)
    except Exception as e:  # noqa: BLE001 — surface setup errors to CLI users
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Scripts sync setup failed: {e}")
        raise typer.Exit(1)
    if not preflight["ok"]:
        if json_out:
            typer.echo(json.dumps(preflight, indent=2, default=str))
        else:
            for err in preflight["errors"]:
                _err(f"  ERROR  {err}")
        raise typer.Exit(1)

    try:
        summary = api.scripts_sync(
            root,
            config_path,
            dry_run=dry_run,
            force=force,
            reassociate=reassociate,
            include=include,
            on_event=None if json_out else _human_scripts_printer(),
        )
    except Exception as e:  # noqa: BLE001
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Scripts sync failed: {e}")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(summary, indent=2, default=str))
    raise typer.Exit(0 if summary["ok"] else 1)


# --------------------------------------------------------------------------- #
# Manifest editing — every mutator emits {"ok", "path", "errors"} under --json
# --------------------------------------------------------------------------- #

def _read_for_edit(path: Path, json_out: bool) -> dict:
    try:
        return api.read_manifest(path)
    except Exception as e:  # noqa: BLE001
        if json_out:
            typer.echo(json.dumps({"ok": False, "path": str(path), "errors": [f"could not read {path}: {e}"]}, indent=2))
        else:
            _err(f"Could not read {path}: {e}")
        raise typer.Exit(1)


def _save_and_report(manifest: dict, path: Path, root: Path, json_out: bool, *, verb: str = "Wrote") -> None:
    """Dump + validate, then report. Exit 0 even when not-yet-runnable (errors are
    surfaced) so a manifest can be built incrementally; exit 1 only if the dump is
    rejected as structurally invalid."""
    try:
        api.dump_manifest(manifest, path, root)
    except ValueError as e:
        if json_out:
            typer.echo(json.dumps({"ok": False, "path": str(path), "errors": [str(e)]}, indent=2))
        else:
            _err(f"Not written: {e}")
        raise typer.Exit(1)
    errors = api.validate(manifest, root)
    if json_out:
        typer.echo(json.dumps({"ok": not errors, "path": str(path), "errors": errors}, indent=2))
        return
    typer.echo(f"{style.dim(verb)} {style.path(str(path))}")
    if errors:
        _err(style.warn("  (manifest saved but not yet runnable):"))
        for err in errors:
            _err(style.dim(f"    {err}"))


@manifest_app.command("init")
def manifest_init(
    output_dir: str = typer.Option("./evidence", "--output-dir", help="Default run output dir"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Create a new empty manifest file."""
    root = api.find_repo_root()
    m = api.init_manifest(output_dir)
    _save_and_report(m, Path(file).resolve(), root, json_out)


@manifest_app.command("new")
def manifest_new(
    name: str = typer.Argument(..., help="Manifest name (created under manifests/<name>.yaml)"),
    output_dir: str = typer.Option("./evidence", "--output-dir", help="Default run output dir"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Create a fresh manifest at manifests/<name>.yaml (the picker convention)."""
    root = api.find_repo_root()
    try:
        path = api.new_manifest_path(root, name, output_dir)
    except (FileExistsError, ValueError) as e:
        if json_out:
            typer.echo(json.dumps({"ok": False, "path": None, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Not created: {e}")
        raise typer.Exit(1)
    errors = api.validate(api.read_manifest(path), root)
    if json_out:
        typer.echo(json.dumps({"ok": not errors, "path": str(path), "errors": errors}, indent=2))
        return
    typer.echo(f"Created {path}")
    if errors:
        _err("  (empty manifest — add fetchers before it can run)")


@manifest_app.command("add")
def manifest_add(
    fetcher: str = typer.Argument(..., help="Fetcher name to add"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Add a fetcher entry to the manifest."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    api.add_entry(m, fetcher)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("remove")
def manifest_remove(
    fetcher: str = typer.Argument(..., help="Fetcher name to remove"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Remove a fetcher entry from the manifest."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    api.remove_entry(m, fetcher)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("set-config")
def manifest_set_config(
    fetcher: str = typer.Argument(..., help="Fetcher name"),
    kv: str = typer.Argument(..., help="key=value"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Set a config key on a fetcher entry."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    key, raw = _parse_kv(kv, path, json_out)
    value = _coerce_or_fail(raw, _config_type(root, fetcher, key), key, path, json_out)
    api.set_fetcher_config(m, fetcher, key, value)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("set-secret")
def manifest_set_secret(
    fetcher: str = typer.Argument(..., help="Fetcher name"),
    secret_name: str = typer.Argument(..., help="Secret declared in the fetcher's contract"),
    env_var: str = typer.Argument(..., help="ENV VAR NAME holding the secret (not the value)"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Set a secret reference (${env:VAR}) on a fetcher entry."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    api.set_secret(m, fetcher, secret_name, env_var)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("add-target")
def manifest_add_target(
    fetcher: str = typer.Argument(..., help="Fanout fetcher name"),
    values: Optional[List[str]] = typer.Argument(None, help="target field key=value pairs"),
    secret: Optional[List[str]] = typer.Option(None, "--secret", help="per_target secret name=ENV_VAR (repeatable)"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Append a fanout target (with optional per-target secrets) to a fetcher."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    vals = {}
    for kv in (values or []):
        k, raw = _parse_kv(kv, path, json_out)
        vals[k] = _coerce_or_fail(raw, _target_field_type(root, fetcher, k), k, path, json_out)
    secret_env = {}
    for s in (secret or []):
        k, v = _parse_kv(s, path, json_out)
        secret_env[k] = v
    api.add_target(m, fetcher, vals, secret_env or None)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("remove-target")
def manifest_remove_target(
    fetcher: str = typer.Argument(..., help="Fanout fetcher name"),
    index: int = typer.Argument(..., help="Zero-based index of the target to remove"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Remove the fanout target at the given index from a fetcher entry."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    api.remove_target(m, fetcher, index)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("set-platform-config")
def manifest_set_platform_config(
    category: str = typer.Argument(..., help="Platform category name"),
    kv: str = typer.Argument(..., help="key=value"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Set a platform-wide config key for a category."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    key, raw = _parse_kv(kv, path, json_out)
    value = _coerce_or_fail(raw, _platform_config_type(root, category, key), key, path, json_out)
    api.set_platform_config(m, category, key, value)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("set-passthrough")
def manifest_set_passthrough(
    category: str = typer.Argument(..., help="Platform category name"),
    env_vars: List[str] = typer.Argument(..., help="Ambient ENV VAR names to pass through"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Set the ambient passthrough env vars for a platform category."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    api.set_passthrough_env(m, category, env_vars)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("set-output-dir")
def manifest_set_output_dir(
    output_dir: str = typer.Argument(..., help="Output directory for run artifacts"),
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Set the manifest's run output directory."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    api.set_output_dir(m, output_dir)
    _save_and_report(m, path, root, json_out)


@manifest_app.command("show")
def manifest_show(
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Print the current manifest (YAML, or JSON with --json). No write, no validation."""
    path = Path(file).resolve()
    try:
        m = api.read_manifest(path)
    except Exception as e:  # noqa: BLE001
        _err(f"Could not read {path}: {e}")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(m, indent=2))
    else:
        import yaml
        typer.echo(yaml.safe_dump(m, sort_keys=False))


# --------------------------------------------------------------------------- #
# Launch the other front-ends — one CLI steers everything
# --------------------------------------------------------------------------- #

@app.command("tui")
def tui_cmd(
    manifest: Optional[str] = typer.Option(None, "--manifest", help="Manifest to open directly, skipping the welcome screen"),
    at: Optional[str] = typer.Option(None, "--at", help="Repo root override (default: discovered by walking up)"),
):
    """Launch the interactive terminal UI."""
    try:
        from framework.tui.__main__ import launch
    except ImportError as e:
        _err(
            "The TUI requires the 'tui' extra (textual). Install it from the repo "
            "root:  pip install -e '.[tui]'\n"
            "  (do NOT run `pip install 'paramify[tui]'` — this project isn't on "
            "PyPI, and that name resolves to an unrelated package.)\n"
            f"  ({e})"
        )
        raise typer.Exit(1)
    launch(manifest, at)

# --------------------------------------------------------------------------- #
# Paramify workspace — pick programs by name, target them by UUID
#
# The API only accepts project UUIDs; people know their programs by name. These
# commands close that gap: list what's in the workspace, let the operator choose,
# then reuse the manifest mutators to write the targets. Selection is interactive
# by default and fully flag-driven under --json, so an AI caller never hits a
# prompt it can't answer.
# --------------------------------------------------------------------------- #

def _is_iso_datish(value: str) -> bool:
    """Accept what the fetchers' date parser accepts: an ISO date or timestamp,
    with a trailing Z allowed. Mirrors ver_common._parse_iso — fetchers aren't an
    importable package, so the rule is restated rather than shared."""
    try:
        datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _can_prompt(json_out: bool) -> bool:
    """--json has no way to answer a prompt, and neither does a piped stdin."""
    return not json_out and sys.stdin.isatty()


def _config_origin(state: dict) -> str:
    """Where a shared config field's value comes from, for the line above its
    prompt. The value itself is the prompt's default, so this says only what the
    bracketed default can't: whether it's already stored, and where — an entry's
    own config outranks the category value this command writes."""
    labels = ", ".join(
        "this entry's own config" if s == "entry" else
        "the fetcher default" if s == "default" else s
        for s in state["sources"]
    )
    if state["conflict"]:
        return f"differs across entries ({labels}) — one value replaces them all"
    return f"set in {labels}" if labels else "not set yet"


def _programs_or_exit(json_out: bool) -> List[dict]:
    try:
        return api.list_programs()
    except RuntimeError as e:
        _fail(None, str(e), json_out)


def _manifest_label(path, root: Path) -> str:
    """How a manifest is named in output. Manifest names are arbitrary, so the
    label is the path relative to the repo root, never a stem."""
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return str(path)


def _manifest_choices(root: Path, fetchers: dict) -> List[dict]:
    """The discovered manifests, each annotated with how many of its entries take
    a program — the one fact that decides whether this command has anything to do
    with a given file."""
    choices: List[dict] = []
    for item in api.list_manifests(root):
        path = Path(item["path"])
        entries: Optional[int] = None
        if item["readable"]:
            try:
                entries = len(api.program_target_fetchers(api.read_manifest(path), root, fetchers))
            except Exception:  # noqa: BLE001
                entries = None  # unparseable: still offer it, just unannotated
        choices.append({**item, "label": _manifest_label(path, root), "program_entries": entries})
    return choices


def _manifest_choice_note(choice: dict) -> str:
    if not choice["readable"]:
        return "unreadable"
    n = choice["program_entries"]
    if n is None:
        return ""  # readable, but its entries couldn't be counted
    if not n:
        return "no program entries"
    return f"{n} program {'entry' if n == 1 else 'entries'}"


def _resolve_manifest_arg(root: Path, file: str, json_out: bool) -> Path:
    """Resolve an explicit -f value: as typed, then against <root>/manifests/ and
    the repo root, so a bare name works from anywhere in the tree.

    A value that resolves to nothing is an error here. read_manifest() reads a
    missing file as an *empty* manifest, which this command then reports as "no
    entry takes a program" — blaming the contents for a path that isn't there —
    and whose write would fork a brand-new manifest at the wrong location.
    """
    given = Path(file)
    candidates = [given]
    if not given.is_absolute():
        if len(given.parts) == 1:
            candidates += [root / "manifests" / file, root / "manifests" / f"{file}.yaml"]
        candidates.append(root / file)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    known = ", ".join(_manifest_label(i["path"], root) for i in api.list_manifests(root))
    _fail(
        given.resolve(),
        f"no such manifest: {file}"
        + (f" (discovered: {known})" if known else " (no manifests discovered)"),
        json_out,
    )


def _manifest_for_edit(root: Path, file: Optional[str], json_out: bool, fetchers: dict) -> Path:
    """The manifest to edit: the -f path if given, else chosen from the discovered
    set. One manifest is used outright (named, so the write is never a surprise);
    several are offered as a numbered pick list, because the file names carry no
    convention this command could guess from."""
    if file:
        return _resolve_manifest_arg(root, file, json_out)

    choices = _manifest_choices(root, fetchers)
    if not choices:
        _fail(
            None,
            f"No manifests found (looked in {root}/manifests/*.yaml and "
            f"{root}/manifest.yaml). Create one with: paramify manifest new <name>",
            json_out,
        )
    if len(choices) == 1:
        if not json_out:
            typer.echo(f"{style.dim('Manifest:')} {style.path(choices[0]['label'])}")
        return Path(choices[0]["path"]).resolve()
    labels = ", ".join(c["label"] for c in choices)
    if not _can_prompt(json_out):
        _fail(
            None,
            f"{len(choices)} manifests found and no terminal to choose on: "
            f"pass -f <path>. Discovered: {labels}",
            json_out,
        )

    typer.echo("Manifests in this workspace\n")
    width = max(len(c["label"]) for c in choices)
    for i, c in enumerate(choices, 1):
        label = style.name(c["label"].ljust(width))
        count = style.dim(f"{c['fetcher_count']:2d} fetchers")
        note = _manifest_choice_note(c)
        line = f"  {i:>3}. {label}  {count}"
        typer.echo(f"{line}  {style.dim(note)}" if note else line)
    typer.echo("")
    choice = typer.prompt("Select a manifest", type=int)
    if not 1 <= choice <= len(choices):
        _fail(None, f"Invalid selection: {choice} is outside 1-{len(choices)}", json_out)
    return Path(choices[choice - 1]["path"]).resolve()


def _parse_selection(raw: str, count: int) -> List[int]:
    """Parse "1,3,5", "1-3", "2 4", or "all" into zero-based indices.

    Raises ValueError on anything out of range so a typo can't silently target
    the wrong program.
    """
    text = raw.strip().lower()
    if text in ("all", "*"):
        return list(range(count))
    picked: List[int] = []
    for token in re.split(r"[,\s]+", text):
        if not token:
            continue
        lo_s, _, hi_s = token.partition("-")
        lo, hi = int(lo_s), int(hi_s or lo_s)
        if not 1 <= lo <= hi <= count:
            raise ValueError(f"{token!r} is outside 1-{count}")
        picked.extend(range(lo - 1, hi))
    ordered = list(dict.fromkeys(picked))  # de-dupe, keep the order typed
    if not ordered:
        raise ValueError("no programs selected")
    return ordered


@programs_app.command("list")
def programs_list(json_out: bool = typer.Option(False, "--json", help="Emit JSON")):
    """List the programs in the Paramify workspace (name + id)."""
    programs = _programs_or_exit(json_out)
    if json_out:
        typer.echo(json.dumps({"ok": True, "programs": programs}, indent=2))
        return
    if not programs:
        typer.echo("No programs found in this workspace.")
        return
    width = max(len(api.program_display_name(p)) for p in programs)
    typer.echo(f"{len(programs)} program(s):\n")
    for p in programs:
        short = f"  [{p['short_name']}]" if p["short_name"] else ""
        typer.echo(f"  {api.program_display_name(p):<{width}}  {p['id']}{short}")


@programs_app.command("target")
def programs_target(
    fetchers: Optional[List[str]] = typer.Argument(
        None, help="Fanout fetcher(s) to add targets to. Default: every manifest entry that takes a program."
    ),
    program: Optional[List[str]] = typer.Option(
        None, "--program", "-p", help="Program name or id (repeatable). Omit to choose interactively."
    ),
    all_programs: bool = typer.Option(False, "--all", help="Target every program in the workspace"),
    cert_uri: Optional[str] = typer.Option(
        None, "--cert-uri",
        help="Certification Package Overview URI for the workspace. Set once as category "
             "config; shown for confirmation on every interactive run.",
    ),
    report_from: Optional[str] = typer.Option(
        None, "--report-from",
        help="Report period start (ISO date, e.g. 2026-01-01). Set once as category "
             "config; shown for confirmation on every interactive run.",
    ),
    file: Optional[str] = typer.Option(
        None, "-f", "--file",
        help="Manifest to edit. A bare name resolves under manifests/. Omit to "
             "choose from the discovered manifests.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Select programs from the workspace and add them as manifest targets."""
    root = api.find_repo_root()
    # Discovered once and threaded through every api call below. Each of these
    # walks + schema-validates all ~125 fetcher.yaml files; the tree is immutable
    # for the life of the command, so one pass is enough.
    discovered = api.discover(root)
    path = _manifest_for_edit(root, file, json_out, discovered["fetchers"])
    m = _read_for_edit(path, json_out)

    uses = list(fetchers or [])
    if not uses:
        uses = api.program_target_fetchers(m, root, discovered["fetchers"])
        if not uses:
            _fail(
                path,
                "No manifest entry takes a program as a target. Add one first "
                "(e.g. paramify manifest add paramify_accepted_vulnerabilities), "
                "or name the fetcher explicitly.",
                json_out,
            )

    programs = _programs_or_exit(json_out)
    if not programs:
        _fail(path, "No programs found in this workspace.", json_out)

    # --- selection ---------------------------------------------------------- #
    selected: List[dict] = []
    if all_programs:
        selected = programs
    elif program:
        for selector in program:
            try:
                selected.append(api.resolve_program(programs, selector))
            except (LookupError, ValueError) as e:
                _fail(path, str(e), json_out)
        selected = list({p["id"]: p for p in selected}.values())
    else:
        if not _can_prompt(json_out):
            _fail(
                path,
                "No programs chosen and no terminal to prompt on: pass --program "
                "NAME|ID (repeatable) or --all.",
                json_out,
            )
        typer.echo(f"Programs in this workspace (targeting: {', '.join(uses)})\n")
        for i, p in enumerate(programs, 1):
            short = f"  [{p['short_name']}]" if p["short_name"] else ""
            typer.echo(f"  {i:>3}. {api.program_display_name(p)}{short}")
        typer.echo("")
        try:
            indices = _parse_selection(
                typer.prompt("Select programs (e.g. 1,3 or 1-3 or all)"), len(programs)
            )
        except ValueError as e:
            _fail(path, f"Invalid selection: {e}", json_out)
        selected = [programs[i] for i in indices]

    # --- shared config ------------------------------------------------------- #
    # Values that don't vary per program are written once to
    # platforms.<category>.config, where every fetcher in the category picks them
    # up. Interactively each one is shown on every run with the value in force as
    # the prompt default, because a re-run is also how you fix a wrong URI or roll
    # the report window forward — enter keeps what's there and writes nothing.
    # Nothing is asked when the flag supplied it (that's an override) or when
    # there's no terminal, where only a genuinely missing value is an error.
    fields = [
        (name, flag, prompt_text, is_date, supplied,
         api.shared_config_state(m, uses, name, root, **discovered))
        for name, flag, prompt_text, is_date, supplied in (
            ("cert_package_uri", "--cert-uri",
             "Certification Package Overview URI (used for every program)", False, cert_uri),
            ("report_from", "--report-from",
             "Report period start — ISO date, e.g. 2026-01-01 (used for every program)", True, report_from),
        )
    ]
    # The header promises "enter keeps it" only when something is actually stored
    # to keep — on a first run there is nothing to show and every prompt is bare.
    header = "\nShared config — one value for every program." + (
        " Enter keeps what's shown." if any(s["value"] for *_, s in fields) else ""
    )
    announced = False
    for field_name, flag, prompt_text, is_date, supplied, state in fields:
        if not state["categories"]:
            continue
        current = "" if state["conflict"] else str(state["value"] or "")
        value = (supplied or "").strip()
        if not value:
            if not _can_prompt(json_out):
                if state["missing"]:
                    _fail(
                        path,
                        f"{field_name} is not set for "
                        + ", ".join(f"platforms.{c}.config" for c in state["missing"])
                        + f". Pass {flag} <value>.",
                        json_out,
                    )
                continue
            if not announced:
                typer.echo(header)
                announced = True
            typer.echo(f"\n  {field_name}: {_config_origin(state)}")
            value = typer.prompt(prompt_text, default=current or None).strip()
            if not value:
                _fail(path, f"No {field_name} given; nothing written.", json_out)
        if is_date and not _is_iso_datish(value):
            # A date the fetcher can't parse yields an empty report window, which
            # silently drops every closed issue rather than failing — so reject it
            # here, where it's still a typo instead of a wrong report.
            _fail(
                path,
                f"{field_name}: {value!r} is not an ISO date or timestamp "
                "(e.g. 2026-01-01 or 2026-01-01T00:00:00Z).",
                json_out,
            )
        if value == current and not state["missing"] and not supplied:
            continue  # enter on a value already in force everywhere: leave it be
        for category in state["categories"]:
            api.set_platform_config(m, category, field_name, value)

    report = api.add_program_targets(m, uses, selected, fetchers=discovered["fetchers"])
    if not json_out:
        for rec in report["added"]:
            typer.echo(f"  + {rec['use']}  ->  {rec['program_name']} ({rec['program_id']})")
        for rec in report["skipped"]:
            typer.echo(f"  = {rec['use']}  ->  {rec['program_name']} ({rec['reason']})")
    _save_and_report(m, path, root, json_out, verb="Updated")


# --------------------------------------------------------------------------- #
# Assessments — pick an assessment by name, store its UUID
#
# The same gap the programs commands close, for issue reports: the intake
# endpoint takes an assessment UUID, and operators know their assessments by
# name. `select` writes the UUID into the manifest so nobody copies one by hand.
# --------------------------------------------------------------------------- #

def _assessments_or_exit(json_out: bool, assessment_type: Optional[str] = None) -> List[dict]:
    try:
        return api.list_assessments(assessment_type)
    except (RuntimeError, ValueError) as e:
        _fail(None, str(e), json_out)


def _assessment_line(a: dict) -> str:
    """One assessment as a single readable line. Two assessments often differ
    only by mechanism or frequency, so both are shown."""
    bits = [b for b in (a.get("type"), a.get("frequency"), a.get("mechanism_name")) if b]
    return f"{api.assessment_display_name(a)}" + (f"  ({', '.join(bits)})" if bits else "")


@assessments_app.command("list")
def assessments_list(
    assessment_type: Optional[str] = typer.Option(
        None, "--type", "-t",
        help="Only VULNERABILITY or only CONFIGURATION assessments.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """List the assessments in the Paramify workspace (name + id)."""
    normalized = assessment_type.upper() if assessment_type else None
    assessments = _assessments_or_exit(json_out, normalized)
    if json_out:
        typer.echo(json.dumps({"ok": True, "assessments": assessments}, indent=2))
        return
    if not assessments:
        scope = f" of type {normalized}" if normalized else ""
        typer.echo(f"No assessments{scope} found in this workspace.")
        return
    width = max(len(api.assessment_display_name(a)) for a in assessments)
    typer.echo(f"{len(assessments)} assessment(s):\n")
    for a in assessments:
        bits = [b for b in (a.get("type"), a.get("frequency"), a.get("mechanism_name")) if b]
        note = f"  [{', '.join(bits)}]" if bits else ""
        typer.echo(
            f"  {api.assessment_display_name(a):<{width}}  {a['id']}{style.dim(note)}"
        )


@assessments_app.command("select")
def assessments_select(
    fetchers: Optional[List[str]] = typer.Argument(
        None,
        help="Issue-report fetcher(s) to point at an assessment. "
             "Default: every issue-report entry in the manifest.",
    ),
    assessment: Optional[str] = typer.Option(
        None, "--assessment", "-a",
        help="Assessment name or id. Omit to choose interactively.",
    ),
    file: Optional[str] = typer.Option(
        None, "-f", "--file",
        help="Manifest to edit. A bare name resolves under manifests/. Omit to "
             "choose from the discovered manifests.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Point issue-report fetchers at a Paramify assessment."""
    root = api.find_repo_root()
    discovered = api.discover(root)
    path = _manifest_for_edit(root, file, json_out, discovered["fetchers"])
    m = _read_for_edit(path, json_out)

    uses = list(fetchers or [])
    if not uses:
        uses = api.issue_report_fetchers(m, root, discovered["fetchers"])
        if not uses:
            _fail(
                path,
                "No issue-report fetcher in this manifest. Add one first "
                "(paramify manifest add <fetcher>), or name it explicitly.",
                json_out,
            )

    # Every named entry must be an issue report, or the assessment_id written
    # would sit in the manifest doing nothing — a silent no-op is worse than a
    # refusal here.
    not_issue_reports = [
        u for u in uses
        if (f := discovered["fetchers"].get(u)) is not None and not f.is_issue_report
    ]
    if not_issue_reports:
        _fail(
            path,
            f"not issue-report fetchers, so an assessment means nothing to them: "
            f"{', '.join(not_issue_reports)}",
            json_out,
        )
    unknown = [u for u in uses if u not in discovered["fetchers"]]
    if unknown:
        _fail(path, f"unknown fetcher(s): {', '.join(unknown)}", json_out)

    # Filter the list by what these fetchers can actually feed, so a CSPM report
    # is never offered a vulnerability assessment. Mixed kinds in one invocation
    # means no single filter applies, so nothing is filtered.
    types = {
        discovered["fetchers"][u].issue_report.assessment_type
        for u in uses if discovered["fetchers"][u].issue_report
    }
    type_filter = types.pop() if len(types) == 1 else None

    assessments = _assessments_or_exit(json_out, type_filter)
    if not assessments:
        scope = f" of type {type_filter}" if type_filter else ""
        _fail(path, f"No assessments{scope} found in this workspace.", json_out)

    if assessment:
        try:
            chosen = api.resolve_assessment(assessments, assessment)
        except (LookupError, ValueError) as e:
            _fail(path, str(e), json_out)
    elif len(assessments) == 1:
        chosen = assessments[0]
        if not json_out:
            typer.echo(f"{style.dim('Assessment:')} {_assessment_line(chosen)}")
    else:
        if not _can_prompt(json_out):
            _fail(
                path,
                "No assessment chosen and no terminal to prompt on: pass "
                "--assessment NAME|ID.",
                json_out,
            )
        scope = f" ({type_filter})" if type_filter else ""
        typer.echo(f"Assessments in this workspace{scope} (for: {', '.join(uses)})\n")
        for i, a in enumerate(assessments, 1):
            typer.echo(f"  {i:>3}. {_assessment_line(a)}")
        typer.echo("")
        choice = typer.prompt("Select an assessment", type=int)
        if not 1 <= choice <= len(assessments):
            _fail(
                path,
                f"Invalid selection: {choice} is outside 1-{len(assessments)}",
                json_out,
            )
        chosen = assessments[choice - 1]

    for use in uses:
        api.set_assessment(m, use, chosen)
        if not json_out:
            typer.echo(
                f"  + {use}  ->  {api.assessment_display_name(chosen)} ({chosen['id']})"
            )
    _save_and_report(m, path, root, json_out, verb="Updated")


# --------------------------------------------------------------------------- #
# Issues — upload raw issue reports into assessment intake
# --------------------------------------------------------------------------- #

@issues_app.command("upload")
def issues_upload_cmd(
    run_dir: Optional[str] = typer.Argument(
        None, help="Run directory to upload (default: latest under --output-dir)"
    ),
    output_dir: str = typer.Option("./evidence", "-o", "--output-dir", help="Base dir to find latest run"),
    config: Optional[str] = typer.Option(None, "--config", help="Uploader config YAML"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Resolve and report what would upload; no API calls"),
    force: bool = typer.Option(
        False, "--force",
        help="Re-intake reports already in this run's _intake_log.json (duplicates issues)",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON summary"),
):
    """Upload a run's issue reports into Paramify assessment intake.

    The counterpart to `paramify upload`, which handles evidence. A run
    containing both kinds needs both commands.
    """
    _upload_stage(
        run_dir=run_dir,
        output_dir=output_dir,
        config=config,
        dry_run=dry_run,
        json_out=json_out,
        preflight_fn=api.issues_upload_preflight,
        upload_fn=api.issues_upload_run,
        noun="report",
        log_name="_intake_log.json",
        upload_kwargs={"force": force},
    )


if __name__ == "__main__":
    app()
