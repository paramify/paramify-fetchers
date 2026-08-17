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
  paramify ksi [--json]                        # FedRAMP 20x KSI coverage
  paramify doctor [manifest] [--json]          # preflight: python, CLIs, secrets
  paramify manifests [--json]                  # discovered run manifests
  paramify runs [--output-dir DIR] [--json]    # past runs under an output dir
  paramify evidence <path> [--json]            # read one evidence file
  paramify upload [run-dir] [--dry-run] [--json]

Paramify workspace (live lookups; needs PARAMIFY_API_TOKEN with read scope):
  paramify programs list [--json]              # programs in the workspace: name + id
  paramify programs target [fetcher ...] [--program NAME|ID ...] [--all]
                           [--cert-uri URI] [--report-from DATE] [-f FILE] [--json]

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
  paramify tui [--manifest PATH] [--at ROOT]   # interactive terminal UI

Secrets are referenced as ${env:VAR} — set-secret / add-target take the ENV VAR
NAME, never the secret value. The runner resolves refs from its own environment.
Outputs land in <output_dir>/run-<timestamp>/ with a _run_metadata.json.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, NoReturn, Optional

import typer

from framework import api

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
validators_app = typer.Typer(
    no_args_is_help=True,
    context_settings=_HELP_OPTS,
    help="Sync registry validators to Paramify and associate them to evidence sets.",
)
app.add_typer(validators_app, name="validators")

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
            typer.echo(f"Run {ev['run_id']} → {ev['run_dir']}\n")
        elif kind == "fetcher_skip":
            _err(f"  SKIP  {ev['fetcher']} ({ev['reason']})")
        elif kind == "fetcher_start":
            if ev["fanout"]:
                typer.echo(f"  RUN   {ev['fetcher']}  ({ev['targets']} targets)")
            else:
                typer.echo(f"  RUN   {ev['fetcher']}")
        elif kind == "fetcher_error":
            _err(f"        runner error: {ev['error']}")
        elif kind == "fetcher_result":
            mark = "OK" if ev["exit_code"] == 0 else "FAIL"
            target = f"  target={ev['target']}" if ev["target"] else ""
            typer.echo(f"        [{mark}] exit={ev['exit_code']} duration={ev['duration_sec']}s{target}")
        elif kind == "run_complete":
            typer.echo(f"\n_run_metadata.json → {ev['metadata_path']}")
        # log_line is intentionally not printed (matches prior non-streaming CLI)
    return on_event


def _human_upload_printer():
    """Return an on_event callback for Paramify upload progress."""
    def on_event(ev: dict) -> None:
        kind = ev["event"]
        if kind == "upload_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            typer.echo(f"Upload {ev['files']} file(s) from {ev['run_dir']} → {ev['base_url']}{mode}\n")
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
            ref = f"  set={ev['reference_id']}" if ev.get("reference_id") else ""
            reason = ev.get("reason") or ev.get("error")
            suffix = f"  {reason}" if reason else ""
            typer.echo(f"        [{mark}] {ev.get('file', '?')}{ref}{suffix}")
        elif kind == "upload_complete":
            typer.echo(
                "\nDone: "
                f"uploaded={ev['uploaded']} "
                f"skipped_duplicate={ev['skipped_duplicate']} "
                f"skipped_failed={ev['skipped_failed']} "
                f"errors={ev['errors']}"
            )
            if ev.get("log_path"):
                typer.echo(f"upload_log.json → {ev['log_path']}")
    return on_event


def _human_validator_printer():
    """Return an on_event callback for Paramify validator-sync progress."""
    def on_event(ev: dict) -> None:
        kind = ev["event"]
        if kind == "sync_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            upd = " (update)" if ev.get("update") else ""
            typer.echo(f"Sync {ev['validators']} validator(s) → {ev['base_url']}{mode}{upd}\n")
        elif kind == "sync_validator":
            outcome = ev.get("outcome") or ""
            mark = {
                "created": "OK", "updated": "OK",
                "skipped_exists": "SKIP",
                "would_create": "DRY", "would_update": "DRY", "would_skip_exists": "DRY",
            }.get(outcome, "FAIL" if outcome == "error" else "..")
            extra = ""
            if ev.get("associated"):
                extra += f"  associated={','.join(ev['associated'])}"
            if ev.get("set_not_found"):
                extra += f"  set_not_found={','.join(ev['set_not_found'])}"
            if ev.get("error"):
                extra += f"  {ev['error']}"
            typer.echo(f"        [{mark}] {ev.get('key', '?')}  {outcome}{extra}")
        elif kind == "sync_complete":
            typer.echo(
                "\nDone: "
                f"created={ev['created']} updated={ev['updated']} skipped={ev['skipped']} "
                f"associated={ev['associated']} set_not_found={ev['set_not_found']} "
                f"errors={ev['errors']}"
            )
            if not ev.get("dry_run"):
                typer.echo(f"lock → {ev['lock_path']}")
    return on_event


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
        st = "fanout" if f["supports_targets"] else "single"
        typer.echo(f"  {f['name']:50s} v{f['version']:8s} [{st:6s}] category={f['category'] or '-'}")


@app.command("catalog")
def catalog_cmd(json_out: bool = typer.Option(False, "--json", help="Emit JSON")):
    """Show categories -> fetchers -> editable fields."""
    root = api.find_repo_root()
    cat = api.catalog(root)
    if json_out:
        typer.echo(json.dumps(cat, indent=2))
        return
    for c in cat["categories"]:
        desc = f" — {c['description'].strip()}" if c.get("description") else ""
        typer.echo(f"\n{c['name']}{desc}")
        if c.get("platform") and c["platform"]["config"]:
            keys = ", ".join(f["name"] for f in c["platform"]["config"])
            typer.echo(f"  platform config: {keys}")
        for f in c["fetchers"]:
            tag = "fanout" if f["supports_targets"] else "single"
            typer.echo(f"    {f['name']:48s} [{tag}]")


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
    typer.echo(f"{f['name']}  v{f['version']}  (category={f['category'] or '-'})")
    typer.echo(f"  {f['description']}")
    typer.echo(f"  supports_targets: {f['supports_targets']}")
    for label, fields in (("config", f["config"]), ("secrets", f["secrets"]),
                          ("target_schema", f["target_schema"])):
        if fields:
            typer.echo(f"  {label}:")
            for fld in fields:
                req = "required" if fld.get("required") else "optional"
                extra = f" default={fld['default']}" if fld.get("default") is not None else ""
                typer.echo(f"    - {fld['name']} ({fld['type']}, {req}){extra}")


@app.command("ksi")
def ksi_cmd(json_out: bool = typer.Option(False, "--json", help="Emit JSON")):
    """Show FedRAMP 20x KSI coverage across discovered fetchers."""
    root = api.find_repo_root()
    cov = api.ksi_coverage(root)
    if json_out:
        typer.echo(json.dumps(cov, indent=2))
        return
    s = cov["summary"]
    release = cov["release"].split("—", 1)[-1].strip() if "—" in cov["release"] else cov["release"]
    typer.echo("FedRAMP 20x KSI coverage")
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
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Preflight: Python version, required CLIs on PATH, and (with a manifest) secrets."""
    root = api.find_repo_root()
    rep = api.doctor(root, Path(manifest) if manifest else None)
    if json_out:
        typer.echo(json.dumps(rep, indent=2))
        raise typer.Exit(0 if rep["ok"] else 1)

    ok_mark, bad_mark = "✅", "❌"
    p = rep["python"]
    typer.echo(f"{ok_mark if p['ok'] else bad_mark} Python {p['version']} (need ≥ {p['required']})")

    if rep["tools"]:
        heading = "Required CLIs" if rep["tools_required"] else "CLIs for discovered categories"
        typer.echo(f"\n{heading}:")
        for t in rep["tools"]:
            mark = ok_mark if t["present"] else bad_mark
            where = t["path"] or "not found on PATH"
            typer.echo(f"  {mark} {t['name']:8s} {where}  ({', '.join(t['categories'])})")
        if not rep["tools_required"]:
            typer.echo("  (informational — you only need the CLIs for categories you run)")

    if rep["manifest"]:
        m = rep["manifest"]
        typer.echo(f"\nManifest secrets ({m['path']}):")
        for fr in m["fetchers"]:
            if not fr["env_refs"]:
                typer.echo(f"  {ok_mark} {fr['use']}  (no secrets)")
            elif fr["ok"]:
                typer.echo(f"  {ok_mark} {fr['use']}  ({', '.join(fr['env_refs'])})")
            else:
                typer.echo(f"  {bad_mark} {fr['use']}  missing: {', '.join(fr['missing'])}")

    typer.echo(f"\n{'All good.' if rep['ok'] else 'Issues found — see above.'}")
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
        typer.echo(f"  {r['run_id']:26s} {when}  {r['ok']}/{total} ok  {len(r['files'])} files  [{status}]")


@app.command("evidence")
def evidence_cmd(
    path: str = typer.Argument(..., help="Path to an evidence JSON file"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Read & display one evidence file (normalizing the standard envelope)."""
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
    typer.echo(f"enveloped: {ev['enveloped']}")
    if ev["schema_version"]:
        typer.echo(f"schema_version: {ev['schema_version']}")
    if ev["metadata"]:
        typer.echo("metadata:")
        typer.echo("  " + json.dumps(ev["metadata"], indent=2, default=str).replace("\n", "\n  "))
    typer.echo("payload:")
    typer.echo(json.dumps(ev["payload"], indent=2, default=str))


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
            _err(f"  ERROR  {err}")
        raise typer.Exit(1)
    n = len(m.get("run", {}).get("fetchers", []))
    typer.echo(f"OK  manifest valid; {n} fetcher entries")


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
    with_validators: bool = typer.Option(False, "--with-validators", help="After upload, sync validators for the sets this run produced (create-or-skip)"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON summary"),
):
    """Upload one evidence run to Paramify."""
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
        preflight = api.upload_preflight(resolved_run_dir, root, config_path, dry_run=dry_run)
    except Exception as e:  # noqa: BLE001 — surface setup errors to CLI users
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Upload setup failed: {e}")
        raise typer.Exit(1)
    if not preflight["ok"]:
        if json_out:
            typer.echo(json.dumps(preflight, indent=2, default=str))
        else:
            for err in preflight["errors"]:
                _err(f"  ERROR  {err}")
        raise typer.Exit(1)

    try:
        summary = api.upload_run(
            resolved_run_dir,
            root,
            config_path,
            dry_run=dry_run,
            on_event=None if json_out else _human_upload_printer(),
        )
    except Exception as e:  # noqa: BLE001
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Upload failed: {e}")
        raise typer.Exit(1)

    vsummary = None
    if with_validators:
        try:
            refs = list(api.reference_ids_from_run(resolved_run_dir))
            vsummary = api.sync_validators(
                root,
                reference_ids=refs,
                config_path=config_path,
                dry_run=dry_run,
                on_event=None if json_out else _human_validator_printer(),
            )
        except Exception as e:  # noqa: BLE001
            if json_out:
                typer.echo(json.dumps(
                    {**summary, "ok": False, "validators": {"ok": False, "error": str(e)}},
                    indent=2, default=str,
                ))
            else:
                _err(f"Validator sync failed: {e}")
            raise typer.Exit(1)

    # Combined success — top-level `ok` reflects BOTH stages, matching the exit code
    # (a consumer reading .ok must not see true when the validator sync failed).
    ok = summary["ok"] and (vsummary is None or vsummary["ok"])
    if json_out:
        out = dict(summary) if vsummary is None else {**summary, "validators": vsummary}
        out["ok"] = ok
        typer.echo(json.dumps(out, indent=2, default=str))
    raise typer.Exit(0 if ok else 1)


@validators_app.command("sync")
def validators_sync_cmd(
    manifest: Optional[str] = typer.Option(None, "-m", "--manifest", help="Scope to validators for this manifest's fetchers (default: whole registry)"),
    config: Optional[str] = typer.Option(None, "--config", help="Syncer config YAML (base_url, lock_path)"),
    lock: Optional[str] = typer.Option(None, "--lock", help="Lock file path (default ./.paramify/validators-sync.lock.json)"),
    update: bool = typer.Option(False, "--update", help="Also PATCH existing validators (overwrites customer tuning)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report planned actions; make no writes"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON summary"),
):
    """Create/associate registry validators in Paramify. Create-or-skip by default."""
    root = api.find_repo_root()
    try:
        summary = api.sync_validators(
            root,
            Path(manifest).resolve() if manifest else None,
            Path(config).resolve() if config else None,
            dry_run=dry_run,
            update=update,
            lock_path=lock,
            on_event=None if json_out else _human_validator_printer(),
        )
    except Exception as e:  # noqa: BLE001 — surface setup errors to CLI users
        if json_out:
            typer.echo(json.dumps({"ok": False, "errors": [str(e)]}, indent=2))
        else:
            _err(f"Validator sync failed: {e}")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(summary, indent=2, default=str))
    raise typer.Exit(0 if summary["ok"] else 1)


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
    typer.echo(f"{verb} {path}")
    if errors:
        _err("  (manifest saved but not yet runnable):")
        for err in errors:
            _err(f"    {err}")


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
    file: str = typer.Option(_DEFAULT_MANIFEST, "-f", "--file", help="Manifest path"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Select programs from the workspace and add them as manifest targets."""
    root = api.find_repo_root()
    path = Path(file).resolve()
    m = _read_for_edit(path, json_out)
    # Discovered once and threaded through every api call below. Each of these
    # walks + schema-validates all ~125 fetcher.yaml files; the tree is immutable
    # for the life of the command, so one pass is enough.
    discovered = api.discover(root)

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


if __name__ == "__main__":
    app()
