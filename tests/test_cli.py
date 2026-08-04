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

from framework import api, cli
from framework.cli import app

REPO_ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


# --------------------------------------------------------------------------- #
# Command registry introspection
# --------------------------------------------------------------------------- #

def _registered():
    """Return (top_level, manifest_subcommand, scripts_subcommand) names."""
    cmd = get_command(app)
    top = set(cmd.commands.keys())
    manifest = set(cmd.commands["manifest"].commands.keys())
    scripts = set(cmd.commands["scripts"].commands.keys())
    return top, manifest, scripts


EXPECTED_TOP = {
    "list", "catalog", "describe", "ksi", "doctor", "manifests", "runs",
    "evidence", "validate", "run", "upload", "manifest", "scripts", "programs", "tui",
}
EXPECTED_PROGRAMS = {"list", "target"}
EXPECTED_MANIFEST = {
    "init", "new", "add", "remove", "set-config", "set-secret",
    "add-target", "remove-target", "set-platform-config",
    "set-passthrough", "set-output-dir", "show",
}
EXPECTED_SCRIPTS = {"sync"}


def test_all_expected_commands_registered():
    top, manifest, scripts = _registered()
    assert EXPECTED_TOP <= top, f"missing top-level commands: {EXPECTED_TOP - top}"
    assert EXPECTED_MANIFEST <= manifest, f"missing manifest subcommands: {EXPECTED_MANIFEST - manifest}"
    assert EXPECTED_SCRIPTS <= scripts, f"missing scripts subcommands: {EXPECTED_SCRIPTS - scripts}"


def test_programs_subcommands_registered():
    """Assert the subcommands are actually attached to the sub-app.

    Worth its own test: a @programs_app.command decorator placed after the
    module's `if __name__ == "__main__": app()` line never runs before dispatch,
    so the group loads but reports "No such command" at runtime.
    """
    programs = set(get_command(app).commands["programs"].commands.keys())
    assert EXPECTED_PROGRAMS <= programs, f"missing programs subcommands: {EXPECTED_PROGRAMS - programs}"


def test_doctor_json_ok_without_manifest():
    """Without a manifest, doctor is a Python-version gate; tools are advisory."""
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, result.output
    rep = json.loads(result.output)
    assert rep["python"]["ok"] is True
    assert rep["ok"] is True
    assert rep["tools_required"] is False
    assert rep["manifest"] is None


def test_doctor_with_credential_free_demo_manifest():
    """The demo manifest has no secrets, so doctor passes with a manifest too."""
    result = runner.invoke(app, ["doctor", "examples/demo.yaml", "--json"])
    assert result.exit_code == 0, result.output
    rep = json.loads(result.output)
    assert rep["tools_required"] is True
    assert rep["manifest"]["ok"] is True


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
    "discover": "<implicit: one fetcher-tree scan shared across a redraw>",
    "catalog": "list / catalog / describe",
    "list_manifests": "manifests",
    "read_manifest": "manifest show",
    # Entry-point env bootstrap, not a command: the CLI runs it in the top-level
    # @app.callback() (so it covers every command) and the TUI in FetcherApp
    # .__init__. Both front-ends populate the environment once, before any other
    # facade call, which is what keeps facade functions order-independent.
    "load_environment": "<implicit: entry-point bootstrap, every command>",
    # Read-only render helper: the runner's merged config view (platform <- entry)
    # behind what the manifest screen displays. No command of its own — the CLI
    # surfaces the same facts through `manifest show` + `validate`.
    "effective_config": "<implicit: manifest render>",
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
    "scripts_sync_preflight": "scripts sync",
    "scripts_sync": "scripts sync",
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
    top, manifest, scripts = _registered()
    groups = {"manifest": manifest, "scripts": scripts}
    for api_fn, where in API_TO_CLI.items():
        if where.startswith("<implicit"):
            continue
        for token in (t.strip() for t in where.split(" / ")):
            group, _, sub = token.partition(" ")
            if sub and group in groups:
                assert sub in groups[group], f"{api_fn}: {group} subcommand '{sub}' not registered"
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


# --------------------------------------------------------------------------- #
# programs — pick a program by name, target it by UUID
#
# GET /projects is stubbed at the api boundary (never over the wire), so these
# assert the selection/resolution/manifest-wiring logic, not the HTTP client.
# --------------------------------------------------------------------------- #

_PROGRAMS = [
    {"id": "aaaa1111-0000-0000-0000-000000000000", "name": "Alpha Cloud Services",
     "system_name": "Alpha Cloud Services", "short_name": "ACS"},
    {"id": "bbbb2222-0000-0000-0000-000000000000", "name": "Beta Platform",
     "system_name": "Beta Platform", "short_name": "BETA"},
    {"id": "cccc3333-0000-0000-0000-000000000000", "name": "Gamma Analytics",
     "system_name": "Gamma Analytics", "short_name": "GAM"},
]

_VER_FETCHER = "paramify_accepted_vulnerabilities"


@pytest.fixture
def stub_programs(monkeypatch):
    """Stub the workspace lookup so no test touches the network."""
    monkeypatch.setattr(api, "list_programs", lambda *a, **k: list(_PROGRAMS))
    return _PROGRAMS


@pytest.fixture
def ver_manifest(tmp_path, in_repo):
    """A manifest at the point `programs target` is normally reached: the entry
    added and its secret wired, but no targets and no shared config yet — those
    are exactly what the command fills in.
    """
    path = tmp_path / "m.yaml"
    m = api.init_manifest(str(tmp_path / "out"))
    api.add_entry(m, _VER_FETCHER)
    api.set_secret(m, _VER_FETCHER, "api_token", "PARAMIFY_API_TOKEN")
    api.dump_manifest(m, path, in_repo)
    return path


def test_programs_list_json(stub_programs):
    rep = _json(runner.invoke(app, ["programs", "list", "--json"]))
    assert rep["ok"] is True
    assert [p["name"] for p in rep["programs"]] == [p["name"] for p in _PROGRAMS]


def test_programs_list_human_shows_name_and_id(stub_programs):
    result = runner.invoke(app, ["programs", "list"])
    assert result.exit_code == 0, result.output
    assert "Alpha Cloud Services" in result.output
    assert "aaaa1111-0000-0000-0000-000000000000" in result.output


def test_programs_list_reports_missing_token_as_json_error(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("No Paramify API token: set PARAMIFY_API_TOKEN")
    monkeypatch.setattr(api, "list_programs", boom)
    rep = _json_err(runner.invoke(app, ["programs", "list", "--json"]))
    assert rep["ok"] is False
    assert "PARAMIFY_API_TOKEN" in rep["errors"][0]


@pytest.mark.parametrize("selector", [
    "Alpha Cloud Services",              # exact name
    "alpha cloud services",              # case-insensitive
    "Alpha",                             # unique substring
    "aaaa1111-0000-0000-0000-000000000000",  # id
])
def test_resolve_program_accepts_name_or_id(selector):
    assert api.resolve_program(_PROGRAMS, selector)["short_name"] == "ACS"


def test_resolve_program_rejects_ambiguous_substring():
    """'a' hits all three — resolving it silently would target the wrong program."""
    with pytest.raises(ValueError, match="ambiguous"):
        api.resolve_program(_PROGRAMS, "a")


def test_resolve_program_rejects_unknown():
    with pytest.raises(LookupError):
        api.resolve_program(_PROGRAMS, "Nope")


@pytest.mark.parametrize("raw,expected", [
    ("1,3", [0, 2]),
    ("1-3", [0, 1, 2]),
    ("2 3", [1, 2]),
    ("all", [0, 1, 2]),
    ("3,1,3", [2, 0]),  # de-duped, in the order typed
])
def test_parse_selection(raw, expected):
    from framework.cli import _parse_selection
    assert _parse_selection(raw, 3) == expected


@pytest.mark.parametrize("raw", ["0", "4", "2-9", "", "nope"])
def test_parse_selection_rejects_out_of_range(raw):
    from framework.cli import _parse_selection
    with pytest.raises(ValueError):
        _parse_selection(raw, 3)


def _platform_cfg(manifest_dict, category="paramify"):
    return (manifest_dict["run"].get("platforms") or {}).get(category, {}).get("config", {})


# The shared config `programs target` needs; supplied by default so each test's
# argv shows only what that test is actually varying.
_SHARED_ARGS = ["--cert-uri", "https://example.gov/cpo", "--report-from", "2026-01-01"]


def _target(manifest, *args, shared=True):
    return runner.invoke(app, [
        "programs", "target", *args, *(_SHARED_ARGS if shared else []),
        "-f", str(manifest), "--json",
    ])


def test_programs_target_writes_targets_by_name(stub_programs, ver_manifest):
    rep = _json(_target(ver_manifest, _VER_FETCHER,
                        "--program", "Alpha Cloud Services", "--program", "Gamma"))
    assert rep["ok"] is True, rep["errors"]
    m = api.read_manifest(ver_manifest)
    targets = _entry(m, _VER_FETCHER)["targets"]
    assert [t["project_id"] for t in targets] == [_PROGRAMS[0]["id"], _PROGRAMS[2]["id"]]
    assert [t["program_name"] for t in targets] == ["Alpha Cloud Services", "Gamma Analytics"]
    # A target carries ONLY what varies per program.
    assert all("cert_package_uri" not in t for t in targets)


def test_programs_target_writes_cert_uri_as_category_config(stub_programs, ver_manifest):
    """One workspace, one URI: it lands once under platforms.paramify.config."""
    uri = "https://example.gov/cpo?package=abc&v=2"  # '=' in the query must survive
    # shared=False: _SHARED_ARGS is appended after *args, so its --cert-uri would
    # win over this one.
    _json(_target(ver_manifest, _VER_FETCHER, "--all", "--cert-uri", uri,
                  "--report-from", "2026-01-01", shared=False))
    m = api.read_manifest(ver_manifest)
    assert _platform_cfg(m)["cert_package_uri"] == uri
    assert len(_entry(m, _VER_FETCHER)["targets"]) == len(_PROGRAMS)


def test_programs_target_under_json_reuses_existing_cert_uri(stub_programs, ver_manifest):
    """Second run with the URI already in the manifest must not need --cert-uri.

    Under --json there is no prompt to fall back on, so if the command still
    considered it missing this would fail instead of succeeding.
    """
    _json(_target(ver_manifest, _VER_FETCHER, "--program", "Alpha"))
    rep = _json(_target(ver_manifest, _VER_FETCHER, "--program", "Beta", shared=False))
    assert rep["ok"] is True, rep["errors"]
    m = api.read_manifest(ver_manifest)
    assert _platform_cfg(m)["cert_package_uri"] == "https://example.gov/cpo"
    assert len(_entry(m, _VER_FETCHER)["targets"]) == 2


def test_programs_target_all_covers_every_program(stub_programs, ver_manifest):
    rep = _json(_target(ver_manifest, _VER_FETCHER, "--all"))
    assert rep["ok"] is True, rep["errors"]
    targets = _entry(api.read_manifest(ver_manifest), _VER_FETCHER)["targets"]
    assert [t["project_id"] for t in targets] == [p["id"] for p in _PROGRAMS]


def test_programs_target_is_idempotent(stub_programs, ver_manifest):
    _json(_target(ver_manifest, _VER_FETCHER, "--program", "Beta"))
    _json(_target(ver_manifest, _VER_FETCHER, "--program", "Beta"))  # same command again
    targets = _entry(api.read_manifest(ver_manifest), _VER_FETCHER)["targets"]
    assert len(targets) == 1, "re-targeting the same program must not duplicate it"


def test_programs_target_defaults_to_program_taking_entries(stub_programs, ver_manifest):
    """No fetcher argument: every manifest entry that takes a program gets it."""
    rep = _json(_target(ver_manifest, "--program", "Beta"))
    assert rep["ok"] is True, rep["errors"]
    assert _entry(api.read_manifest(ver_manifest), _VER_FETCHER)["targets"]


def test_programs_target_requires_cert_uri_under_json(stub_programs, ver_manifest):
    """--json can't prompt, so a missing URI must fail loudly and say where it goes."""
    rep = _json_err(_target(ver_manifest, _VER_FETCHER, "--program", "Beta", shared=False))
    assert "cert_package_uri" in rep["errors"][0]
    assert "platforms.paramify.config" in rep["errors"][0]
    assert "--cert-uri" in rep["errors"][0]


def test_programs_target_writes_report_from_as_category_config(stub_programs, ver_manifest):
    """report_from is declared per-fetcher but set once at the platform level —
    the runner merges platform config over any field a fetcher declares."""
    _json(_target(ver_manifest, _VER_FETCHER, "--all"))
    m = api.read_manifest(ver_manifest)
    assert _platform_cfg(m)["report_from"] == "2026-01-01"
    assert "report_from" not in (_entry(m, _VER_FETCHER).get("config") or {})


@pytest.mark.parametrize("bad", ["Jan 1 2026", "2026-13-45", "01/01/2026", "soon"])
def test_programs_target_rejects_non_iso_report_from(stub_programs, ver_manifest, bad):
    """An unparseable date yields an empty report window, which silently drops
    every closed issue — so it has to fail here, not at run time."""
    rep = _json_err(_target(ver_manifest, _VER_FETCHER, "--all",
                            "--cert-uri", "https://example.gov/cpo",
                            "--report-from", bad, shared=False))
    assert "report_from" in rep["errors"][0]
    assert "ISO" in rep["errors"][0]


@pytest.mark.parametrize("good", ["2026-01-01", "2026-01-01T00:00:00Z", "2026-06-30T12:00:00+00:00"])
def test_programs_target_accepts_iso_report_from(stub_programs, ver_manifest, good):
    rep = _json(_target(ver_manifest, _VER_FETCHER, "--all",
                        "--cert-uri", "https://example.gov/cpo",
                        "--report-from", good, shared=False))
    assert rep["ok"] is True, rep["errors"]
    assert _platform_cfg(api.read_manifest(ver_manifest))["report_from"] == good


def test_programs_target_requires_report_from_under_json(stub_programs, ver_manifest):
    rep = _json_err(_target(ver_manifest, _VER_FETCHER, "--all",
                            "--cert-uri", "https://example.gov/cpo", shared=False))
    assert "report_from" in rep["errors"][0]
    assert "--report-from" in rep["errors"][0]


def test_programs_target_flag_overrides_existing_shared_config(stub_programs, ver_manifest):
    """Passing a flag is an override — it applies even when a value is already set."""
    _json(_target(ver_manifest, _VER_FETCHER, "--all", "--cert-uri",
                  "https://old.example.gov/cpo", "--report-from", "2026-01-01", shared=False))
    _json(_target(ver_manifest, _VER_FETCHER, "--all", "--cert-uri",
                  "https://new.example.gov/cpo", "--report-from", "2026-04-01", shared=False))
    cfg = _platform_cfg(api.read_manifest(ver_manifest))
    assert cfg["cert_package_uri"] == "https://new.example.gov/cpo"
    assert cfg["report_from"] == "2026-04-01"


def test_programs_target_requires_a_selection_under_json(stub_programs, ver_manifest):
    rep = _json_err(_target(ver_manifest, _VER_FETCHER, shared=False))
    assert "--program" in rep["errors"][0]


# --------------------------------------------------------------------------- #
# Shared config is shown and editable on every interactive run — the manifest is
# never a black box you have to open to see what a re-run will carry forward.
# --------------------------------------------------------------------------- #

@pytest.fixture
def tty(monkeypatch):
    """Let the command prompt. CliRunner's stdin isn't a tty, so `_can_prompt`
    is patched rather than sys.stdin: click reads the runner's piped `input=`
    either way, and this keeps the seam to one function."""
    monkeypatch.setattr(cli, "_can_prompt", lambda json_out: not json_out)


def _target_tty(manifest, *args, keys=""):
    """Invoke without --json, answering the shared-config prompts with `keys`."""
    return runner.invoke(
        app, ["programs", "target", *args, "-f", str(manifest)], input=keys
    )


def _seeded(manifest):
    """A manifest that already carries both shared values, as a second run finds it."""
    _json(_target(manifest, _VER_FETCHER, "--program", "Alpha"))
    return manifest


def test_programs_target_shows_shared_config_on_every_run(stub_programs, ver_manifest, tty):
    """Values already in the manifest are still displayed — a re-run shows what
    it's about to carry forward instead of silently reusing it."""
    result = _target_tty(_seeded(ver_manifest), _VER_FETCHER, "--program", "Beta", keys="\n\n")
    assert result.exit_code == 0, result.output
    assert "https://example.gov/cpo" in result.output   # the URI, as the prompt default
    assert "2026-01-01" in result.output                # the report start, likewise
    assert "set in platforms.paramify" in result.output  # ...and where it lives


def test_programs_target_enter_keeps_shared_config(stub_programs, ver_manifest, tty):
    """Enter at both prompts leaves the platform block byte-identical."""
    before = _platform_cfg(api.read_manifest(_seeded(ver_manifest)))
    result = _target_tty(ver_manifest, _VER_FETCHER, "--program", "Beta", keys="\n\n")
    assert result.exit_code == 0, result.output
    m = api.read_manifest(ver_manifest)
    assert _platform_cfg(m) == before
    assert len(_entry(m, _VER_FETCHER)["targets"]) == 2, "the run still added its target"


def test_programs_target_prompt_updates_shared_config(stub_programs, ver_manifest, tty):
    """Typing over the default is how you fix a wrong URI or roll the window."""
    result = _target_tty(_seeded(ver_manifest), _VER_FETCHER, "--program", "Beta",
                         keys="https://new.example.gov/cpo\n2026-04-01\n")
    assert result.exit_code == 0, result.output
    cfg = _platform_cfg(api.read_manifest(ver_manifest))
    assert cfg["cert_package_uri"] == "https://new.example.gov/cpo"
    assert cfg["report_from"] == "2026-04-01"


def test_programs_target_rejects_a_bad_date_typed_at_the_prompt(stub_programs, ver_manifest, tty):
    """The ISO check guards the prompt too, and failing writes nothing at all."""
    result = _target_tty(_seeded(ver_manifest), _VER_FETCHER, "--program", "Beta",
                         keys="\nsoon\n")
    assert result.exit_code == 1
    assert "ISO" in result.output
    m = api.read_manifest(ver_manifest)
    assert _platform_cfg(m)["report_from"] == "2026-01-01"
    assert len(_entry(m, _VER_FETCHER)["targets"]) == 1, "no target written on a failed run"


def test_programs_target_offers_no_default_when_entries_disagree(stub_programs, ver_manifest, tty):
    """Two entries, two different report starts — either one shown as *the*
    default would misreport the other, so it says so and asks outright: with no
    default, enter re-asks instead of quietly picking a side."""
    other = "paramify_vulnerability_detail_report"
    m = api.read_manifest(_seeded(ver_manifest))
    api.add_entry(m, other)
    api.set_secret(m, other, "api_token", "PARAMIFY_API_TOKEN")
    api.set_fetcher_config(m, other, "report_from", "2025-06-01")  # diverges from the platform value
    api.dump_manifest(m, ver_manifest, REPO_ROOT)
    result = _target_tty(ver_manifest, "--program", "Beta", keys="\n\n2026-05-05\n")
    assert result.exit_code == 0, result.output
    assert "differs across entries" in result.output
    for value in ("[2026-01-01]", "[2025-06-01]"):
        assert value not in result.output, "a disputed value must not be offered as the default"
    assert _platform_cfg(api.read_manifest(ver_manifest))["report_from"] == "2026-05-05"


def test_programs_target_errors_when_no_entry_takes_a_program(stub_programs, tmp_path, in_repo):
    path = tmp_path / "empty.yaml"
    api.dump_manifest(api.init_manifest(str(tmp_path / "out")), path, in_repo)
    rep = _json_err(runner.invoke(app, [
        "programs", "target", "--program", "Beta", "-f", str(path), "--json",
    ]))
    assert "No manifest entry takes a program" in rep["errors"][0]
