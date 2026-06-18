"""Tests for the unified `paramify` CLI (framework.cli).

The central guarantee these tests protect is the parity invariant:

    Everything a human can do in the TUI, the CLI can do.

Because every front-end talks only to ``framework.api``, that reduces to: every
``api`` capability the TUI uses has a corresponding CLI command. The
``test_parity_*`` tests enforce that by reading the TUI source directly (AST
walk) — not a hand-maintained literal — so a future TUI capability backed by a
new ``api`` function turns the suite red until a CLI command is added for it.

The rest smoke the commands end-to-end against the real repo, covering both the
``--json`` contract (the AI/skill surface) and the human render (what users see,
including the ``run`` streaming printer).

Run: ``pytest tests/test_cli.py`` (needs an editable install: ``pip install -e .``).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from framework import api
from framework.cli import app

REPO_ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


# --------------------------------------------------------------------------- #
# Command registry introspection
# --------------------------------------------------------------------------- #

def _registered():
    """Return (top_level_command_names, manifest_subcommand_names)."""
    cmd = get_command(app)
    top = set(cmd.commands.keys())
    manifest = set(cmd.commands["manifest"].commands.keys())
    return top, manifest


EXPECTED_TOP = {
    "list", "catalog", "describe", "manifests", "runs", "evidence",
    "validate", "run", "upload", "manifest", "tui",
}
EXPECTED_MANIFEST = {
    "init", "new", "add", "remove", "set-config", "set-secret",
    "add-target", "remove-target", "set-platform-config",
    "set-passthrough", "set-output-dir", "show",
}


def test_all_expected_commands_registered():
    top, manifest = _registered()
    assert EXPECTED_TOP <= top, f"missing top-level commands: {EXPECTED_TOP - top}"
    assert EXPECTED_MANIFEST <= manifest, f"missing manifest subcommands: {EXPECTED_MANIFEST - manifest}"


# --------------------------------------------------------------------------- #
# Parity invariant: every api function the TUI calls maps to a CLI command.
# Derived from the TUI SOURCE so it can't drift into a tautology.
# --------------------------------------------------------------------------- #

def _tui_api_calls() -> set[str]:
    """Every ``api.<name>`` attribute accessed anywhere under framework/tui/."""
    tui_dir = REPO_ROOT / "framework" / "tui"
    names: set[str] = set()
    for pyf in tui_dir.rglob("*.py"):
        if "__pycache__" in pyf.parts:
            continue
        tree = ast.parse(pyf.read_text(), filename=str(pyf))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "api"):
                names.add(node.attr)
    return names


# Where each api function the TUI uses surfaces in the CLI. "<implicit>" = used
# by every command (repo discovery / manifest read+write plumbing) rather than
# its own command. Keep this in sync with the TUI; the test below enforces it.
API_TO_CLI = {
    "find_repo_root": "<implicit: every command>",
    "catalog": "list / catalog / describe",
    "list_manifests": "manifests",
    "read_manifest": "manifest show",
    "init_manifest": "manifest init",
    "new_manifest_path": "manifest new",
    "add_entry": "manifest add",
    "set_secret": "manifest set-secret",
    "set_fetcher_config": "manifest set-config",
    "set_output_dir": "manifest set-output-dir",
    "remove_entry": "manifest remove",
    "add_target": "manifest add-target",
    "remove_target": "manifest remove-target",
    "dump_manifest": "<implicit: every mutator>",
    "validate": "validate",
    "run": "run",
    "upload_preflight": "upload",
    "upload_run": "upload",
    "list_runs": "runs",
    "read_evidence": "evidence",
}


def test_parity_walker_finds_tui_api_calls():
    """Guard the AST walker itself — if it finds nothing, every parity test
    below would pass vacuously."""
    used = _tui_api_calls()
    assert len(used) >= 15, f"AST walk found only {used} — walker likely broken"


def test_parity_every_tui_api_call_has_a_cli_home():
    """The real invariant, source-derived: if the TUI starts calling a new api
    function, this fails until API_TO_CLI (and a CLI command) covers it."""
    used = _tui_api_calls()
    uncovered = used - set(API_TO_CLI)
    assert not uncovered, (
        f"TUI calls api functions with no CLI mapping: {uncovered}. "
        "Add a CLI command for each (or an <implicit> note in API_TO_CLI)."
    )


def test_parity_mapped_commands_actually_exist():
    """Every concrete command named in API_TO_CLI is really registered."""
    top, manifest = _registered()
    for api_fn, where in API_TO_CLI.items():
        if where.startswith("<implicit"):
            continue
        for token in (t.strip() for t in where.split(" / ")):
            if token.startswith("manifest "):
                sub = token.split(" ", 1)[1]
                assert sub in manifest, f"{api_fn}: manifest subcommand '{sub}' not registered"
            else:
                assert token in top, f"{api_fn}: command '{token}' not registered"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def in_repo(monkeypatch):
    """Run with cwd = repo root, so api.find_repo_root() resolves correctly."""
    monkeypatch.chdir(REPO_ROOT)
    return REPO_ROOT


@pytest.fixture(scope="module")
def fetchers():
    """A few representative fetchers pulled from the live catalog."""
    cat = api.catalog(api.find_repo_root(REPO_ROOT))
    allf = [f for c in cat["categories"] for f in c["fetchers"]]
    assert allf, "no fetchers discovered — cannot run parity smoke tests"
    with_secret = next((f for f in allf if f["secrets"] and not f["supports_targets"]), None)
    fanout = next((f for f in allf if f["supports_targets"]), None)
    return {"any": allf[0], "with_secret": with_secret, "fanout": fanout}


def _json(result):
    """Parse the JSON a --json command printed to stdout (no stderr in json mode)."""
    assert result.exit_code == 0, f"exit={result.exit_code}\n{result.output}"
    return json.loads(result.output)


def _json_err(result):
    """Parse the JSON an error path printed (--json still emits a JSON body on exit 1)."""
    assert result.exit_code == 1, f"exit={result.exit_code}\n{result.output}"
    return json.loads(result.output)


def _entry(manifest_dict, use):
    for e in manifest_dict["run"]["fetchers"]:
        if e["use"] == use:
            return e
    return None


# --------------------------------------------------------------------------- #
# Help (-h parity with the old argparse CLI)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("argv", [["-h"], ["list", "-h"], ["manifest", "-h"], ["manifest", "add", "-h"]])
def test_dash_h_shows_help_and_exits_0(argv):
    result = runner.invoke(app, argv)
    assert result.exit_code == 0, f"{argv}: exit {result.exit_code}\n{result.output}"
    assert "Usage" in result.output


# --------------------------------------------------------------------------- #
# Read / discover commands — JSON
# --------------------------------------------------------------------------- #

def test_list_json(in_repo):
    data = _json(runner.invoke(app, ["list", "--json"]))
    assert isinstance(data, list) and data
    assert {"name", "version", "supports_targets", "category"} <= set(data[0])


def test_catalog_json(in_repo):
    data = _json(runner.invoke(app, ["catalog", "--json"]))
    assert "categories" in data


def test_describe_json(in_repo, fetchers):
    name = fetchers["any"]["name"]
    data = _json(runner.invoke(app, ["describe", name, "--json"]))
    assert data["name"] == name


def test_describe_unknown_exits_1(in_repo):
    result = runner.invoke(app, ["describe", "definitely_not_a_fetcher"])
    assert result.exit_code == 1


def test_manifests_json(in_repo):
    data = _json(runner.invoke(app, ["manifests", "--json"]))
    assert isinstance(data, list)  # repo ships some, but [] is also valid


def test_runs_json_empty(tmp_path):
    data = _json(runner.invoke(app, ["runs", "--output-dir", str(tmp_path), "--json"]))
    assert data == []


def test_evidence_json_raw(tmp_path):
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"hello": "world"}))
    data = _json(runner.invoke(app, ["evidence", str(f), "--json"]))
    assert data["enveloped"] is False
    assert data["payload"] == {"hello": "world"}


def test_evidence_json_enveloped(tmp_path):
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({
        "schema_version": "1.0",
        "metadata": {"fetcher": "x"},
        "payload": {"k": "v"},
    }))
    data = _json(runner.invoke(app, ["evidence", str(f), "--json"]))
    assert data["enveloped"] is True
    assert data["schema_version"] == "1.0"
    assert data["payload"] == {"k": "v"}


def test_upload_dry_run_json(tmp_path, in_repo):
    run_dir = tmp_path / "run-2026-01-01T00-00-00Z"
    run_dir.mkdir()
    (run_dir / "example.json").write_text(json.dumps({
        "schema_version": "1.0",
        "metadata": {
            "fetcher_name": "example_fetcher",
            "fetcher_version": "0.1.0",
            "run_id": "2026-01-01T00-00-00Z",
            "status": "ok",
            "collected_at": "2026-01-01T00:00:00Z",
            "evidence_set": {
                "reference_id": "TEST-001",
                "name": "Example Evidence",
                "instructions": "Upload test evidence.",
            },
        },
        "payload": {"ok": True},
    }))
    data = _json(runner.invoke(app, ["upload", str(run_dir), "--dry-run", "--json"]))
    assert data["ok"] is True
    assert data["dry_run"] is True
    assert data["files"] == 1
    assert data["results"][0]["outcome"] == "would_upload"


def test_evidence_missing_exits_1(tmp_path):
    result = runner.invoke(app, ["evidence", str(tmp_path / "nope.json")])
    assert result.exit_code == 1


def test_run_missing_manifest_errors_not_noop(tmp_path):
    # Regression: a missing manifest path used to load as an empty manifest and
    # silently produce a zero-fetcher run (exit 0, "invocations": []). It must error.
    missing = tmp_path / "does-not-exist.yaml"
    result = runner.invoke(app, ["run", str(missing)])
    assert result.exit_code == 1
    data = _json_err(runner.invoke(app, ["run", str(missing), "--json"]))
    assert data["ok"] is False and "no such manifest" in data["error"]


def test_validate_missing_manifest_exits_1(tmp_path):
    missing = tmp_path / "does-not-exist.yaml"
    assert runner.invoke(app, ["validate", str(missing)]).exit_code == 1
    data = _json_err(runner.invoke(app, ["validate", str(missing), "--json"]))
    assert data["ok"] is False and any("no such manifest" in e for e in data["errors"])


# --------------------------------------------------------------------------- #
# Read / discover commands — human render (preserved user-facing contract)
# --------------------------------------------------------------------------- #

def test_list_human(in_repo):
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "Discovered" in result.output and "fetchers" in result.output


def test_describe_human(in_repo, fetchers):
    name = fetchers["any"]["name"]
    result = runner.invoke(app, ["describe", name])
    assert result.exit_code == 0
    assert name in result.output and "supports_targets:" in result.output


def test_evidence_human_raw(tmp_path):
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"hello": "world"}))
    result = runner.invoke(app, ["evidence", str(f)])
    assert result.exit_code == 0
    assert "enveloped: False" in result.output and "payload:" in result.output


# --------------------------------------------------------------------------- #
# validate — exit codes (superset parity vs the old CLI)
# --------------------------------------------------------------------------- #

def test_validate_valid_manifest(in_repo, fetchers, tmp_path):
    """A fetcher with all secrets wired validates clean: exit 0, ok True."""
    m = str(tmp_path / "m.yaml")
    sec = fetchers["with_secret"]
    if not sec:
        pytest.skip("no single-target secret-bearing fetcher to build a valid manifest")
    runner.invoke(app, ["manifest", "init", "-f", m])
    runner.invoke(app, ["manifest", "add", sec["name"], "-f", m])
    for s in sec["secrets"]:
        runner.invoke(app, ["manifest", "set-secret", sec["name"], s["name"], f"{s['name'].upper()}_ENV", "-f", m])

    r = runner.invoke(app, ["validate", m, "--json"])
    assert r.exit_code == 0
    assert json.loads(r.output)["ok"] is True

    human = runner.invoke(app, ["validate", m])
    assert human.exit_code == 0 and human.output.startswith("OK")


def test_validate_invalid_manifest(in_repo, fetchers, tmp_path):
    """A fetcher with unmet secrets fails: exit 1, ok False, non-empty errors."""
    m = str(tmp_path / "m.yaml")
    sec = fetchers["with_secret"]
    if not sec:
        pytest.skip("no secret-bearing fetcher available")
    runner.invoke(app, ["manifest", "init", "-f", m])
    runner.invoke(app, ["manifest", "add", sec["name"], "-f", m])  # secrets left unset

    r = runner.invoke(app, ["validate", m, "--json"])
    assert r.exit_code == 1
    out = json.loads(r.output)
    assert out["ok"] is False and out["errors"]

    assert runner.invoke(app, ["validate", m]).exit_code == 1


# --------------------------------------------------------------------------- #
# run — streaming human printer (the documented per-fetcher render)
# --------------------------------------------------------------------------- #

def test_human_run_printer_emits_contract(capsys):
    """Feed _human_run_printer a synthetic event stream and assert the exact
    lines docs/users depend on. Avoids actually executing fetchers."""
    from framework.cli import _human_run_printer
    cb = _human_run_printer()
    cb({"event": "run_start", "run_id": "R1", "run_dir": "/tmp/run"})
    cb({"event": "fetcher_start", "fetcher": "f1", "fanout": False})
    cb({"event": "fetcher_result", "fetcher": "f1", "exit_code": 0, "duration_sec": 1.2, "target": None})
    cb({"event": "fetcher_start", "fetcher": "f2", "fanout": True, "targets": 3})
    cb({"event": "fetcher_result", "fetcher": "f2", "exit_code": 1, "duration_sec": 0.4, "target": "t1"})
    cb({"event": "fetcher_skip", "fetcher": "f3", "reason": "missing secret"})
    cb({"event": "run_complete", "metadata_path": "/tmp/run/_run_metadata.json"})
    captured = capsys.readouterr()
    out, err = captured.out, captured.err
    assert "Run R1 → /tmp/run" in out
    assert "RUN   f1" in out
    assert "[OK] exit=0" in out
    assert "RUN   f2  (3 targets)" in out
    assert "[FAIL] exit=1" in out and "target=t1" in out
    assert "_run_metadata.json → /tmp/run/_run_metadata.json" in out
    assert "SKIP  f3 (missing secret)" in err  # skips/errors go to stderr


# --------------------------------------------------------------------------- #
# Manifest mutators — JSON contract + actual effects
# --------------------------------------------------------------------------- #

def test_manifest_mutator_json_shape(in_repo, tmp_path):
    """Every mutator's --json output is the stable {ok, path, errors} contract."""
    m = str(tmp_path / "m.yaml")
    out = _json(runner.invoke(app, ["manifest", "init", "-f", m, "--json"]))
    assert set(out) == {"ok", "path", "errors"}
    assert isinstance(out["ok"], bool)
    assert isinstance(out["errors"], list)


def test_manifest_set_secret_writes_ref(in_repo, fetchers, tmp_path):
    """set-secret actually writes the ${env:VAR} ref (not just a valid shape)."""
    sec = fetchers["with_secret"]
    if not sec:
        pytest.skip("no secret-bearing fetcher available")
    m = str(tmp_path / "m.yaml")
    runner.invoke(app, ["manifest", "init", "-f", m])
    runner.invoke(app, ["manifest", "add", sec["name"], "-f", m])
    secret_name = sec["secrets"][0]["name"]
    out = _json(runner.invoke(app, ["manifest", "set-secret", sec["name"], secret_name, "MY_ENV", "-f", m, "--json"]))
    assert isinstance(out["ok"], bool)

    shown = _json(runner.invoke(app, ["manifest", "show", "-f", m, "--json"]))
    entry = _entry(shown, sec["name"])
    assert entry is not None
    assert entry["secrets"][secret_name] == "${env:MY_ENV}"
    # the just-set secret no longer appears among the missing-secret errors
    assert not any(secret_name in e and "missing secret" in e for e in out["errors"])


def test_manifest_remove_target_actually_removes(in_repo, fetchers, tmp_path):
    """remove-target drops the target (count 1 -> 0); an out-of-range index is a
    documented no-op that leaves the target in place."""
    fanout = fetchers["fanout"]
    if not fanout:
        pytest.skip("no fanout fetcher in catalog")
    m = str(tmp_path / "m.yaml")
    runner.invoke(app, ["manifest", "init", "-f", m])
    runner.invoke(app, ["manifest", "add", fanout["name"], "-f", m])
    target_kv = [f"{fld['name']}=x" for fld in fanout["target_schema"]] or ["dummy=x"]
    runner.invoke(app, ["manifest", "add-target", fanout["name"], *target_kv, "-f", m])

    before = _entry(_json(runner.invoke(app, ["manifest", "show", "-f", m, "--json"])), fanout["name"])
    assert len(before.get("targets", [])) == 1

    # out-of-range index: no-op, target still present
    _json(runner.invoke(app, ["manifest", "remove-target", fanout["name"], "99", "-f", m, "--json"]))
    still = _entry(_json(runner.invoke(app, ["manifest", "show", "-f", m, "--json"])), fanout["name"])
    assert len(still.get("targets", [])) == 1

    # valid index: removed
    _json(runner.invoke(app, ["manifest", "remove-target", fanout["name"], "0", "-f", m, "--json"]))
    after = _entry(_json(runner.invoke(app, ["manifest", "show", "-f", m, "--json"])), fanout["name"])
    assert len(after.get("targets", [])) == 0


def test_manifest_set_output_dir_persists(in_repo, tmp_path):
    m = str(tmp_path / "m.yaml")
    runner.invoke(app, ["manifest", "init", "-f", m])
    _json(runner.invoke(app, ["manifest", "set-output-dir", "./custom-out", "-f", m, "--json"]))
    shown = _json(runner.invoke(app, ["manifest", "show", "-f", m, "--json"]))
    assert shown["run"]["output_dir"] == "./custom-out"


# --------------------------------------------------------------------------- #
# Mutator argument-error paths still honor the --json {ok, path, errors} contract
# --------------------------------------------------------------------------- #

def test_set_config_bad_kv_json(in_repo, fetchers, tmp_path):
    m = str(tmp_path / "m.yaml")
    name = fetchers["any"]["name"]
    runner.invoke(app, ["manifest", "init", "-f", m])
    runner.invoke(app, ["manifest", "add", name, "-f", m])
    r = runner.invoke(app, ["manifest", "set-config", name, "noequalshere", "-f", m, "--json"])
    assert r.exit_code == 1
    out = json.loads(r.output)
    assert out["ok"] is False and out["errors"]
    assert "key=value" in out["errors"][0]


def test_set_platform_config_bad_int_json(in_repo, tmp_path):
    """An un-coercible integer must still produce {ok,path,errors}, not a traceback."""
    m = str(tmp_path / "m.yaml")
    runner.invoke(app, ["manifest", "init", "-f", m])
    # rippling.page_size is an integer-typed platform config field in the repo.
    r = runner.invoke(app, ["manifest", "set-platform-config", "rippling", "page_size=notanint", "-f", m, "--json"])
    assert r.exit_code == 1
    out = json.loads(r.output)
    assert out["ok"] is False and out["errors"]
    assert "integer" in out["errors"][0]


# --------------------------------------------------------------------------- #
# `manifest new` — the manifests/<name>.yaml picker convention
# --------------------------------------------------------------------------- #

def test_manifest_new_creates_under_manifests_dir(in_repo):
    name = "_parity_smoke_test"
    target = REPO_ROOT / "manifests" / f"{name}.yaml"
    if target.exists():
        target.unlink()
    try:
        out = _json(runner.invoke(app, ["manifest", "new", name, "--json"]))
        assert out["path"] == str(target)
        assert target.exists()
        listed = _json(runner.invoke(app, ["manifests", "--json"]))
        assert any(item["name"] == f"{name}.yaml" for item in listed)
    finally:
        if target.exists():
            target.unlink()
