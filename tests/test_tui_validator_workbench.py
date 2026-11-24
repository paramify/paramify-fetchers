"""TUI: the validator window as a workbench.

Open a validator on the Validators tab (4) and it shows its latest result in
Paramify and a test on your latest run (validator_eval under Node). When the
test fails, Ask Claude explains why and proposes a regex, which is tested on the
same run before it is shown and is written to the registry only on w.

Paramify is stubbed (api.validator_results) and so is Claude (ask_claude.ask):
nothing here reaches the network or a real `claude`. The local test runs the
real ECMAScript evaluator, so these tests need `node`.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.widgets import Label, Static  # noqa: E402

from framework import api, ask_claude  # noqa: E402
from framework.contract import Validator  # noqa: E402
from framework.tui.components.table import DataTable  # noqa: E402
from framework.tui.modals import ConfirmModal, ReportModal  # noqa: E402
from framework.tui.screens import validators as page_mod  # noqa: E402
from framework.tui.screens.validators import (  # noqa: E402
    ValidatorModal,
    ValidatorsPage,
)
from framework.validator_eval import node_available  # noqa: E402
from framework.validators import write_regex  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
REF = "EVD-DEMO-HELLO"
needs_node = pytest.mark.skipif(not node_available(), reason="validator_eval needs node")

# What demo_hello writes, as an envelope on disk.
EVIDENCE = {
    "schema_version": "1.0",
    "metadata": {"fetcher_name": "demo_hello", "run_id": "2026-11-20T10-31-00Z-a1b2", "status": "success",
                 "exit_code": 0, "evidence_set": {"reference_id": REF}},
    "payload": {"results": [
        {"policy": "require-phishing-resistant-mfa", "enabled": True, "applies_to": "all-users",
         "enrolled_users": 42, "total_users": 42},
    ]},
}
# The fetcher renamed mfa_enabled to enabled; this regex still looks for the old key.
STALE = '"mfa_enabled":\\s*(?<mfa_enabled>true|false)'
FIXED = '"enabled":\\s*(?<mfa_enabled>true|false)'
ANSWER = ("Why: The evidence now says `\"enabled\": true`, not `mfa_enabled`, so the regex finds "
          "nothing and the match-count rule fails. The policy itself is on.\n"
          f"Regex: `{FIXED}`")

YAML = f"""key: mfa_enforced
name: MFA Enforced For All Users
type: AUTOMATED
role: configuration
statement: Phishing-resistant MFA is required for every user.
# The policy flag, not the enrolment count.
regex: '{STALE}'
validation_rules:
  - regexOperation: {{ type: MATCH_COUNT }}
    criteria: NOT_EQUALS
    value: {{ type: CUSTOM_TEXT, customText: "0" }}
  - regexOperation: {{ type: MATCH_GROUP, groupNumber: 1 }}
    criteria: EQUALS
    value: {{ type: CUSTOM_TEXT, customText: "true" }}
evidence_sets:
  - {REF}
"""


def make_workspace(tmp_path: Path, *, evidence: bool = True) -> tuple:
    """A manifest with demo_hello, a run holding its evidence, and a two-validator
    registry on its set (one file on disk, so w has something to write)."""
    out = tmp_path / "evidence"
    if evidence:
        run = out / "run-2026-11-20T10-31-00Z-a1b2"
        run.mkdir(parents=True)
        (run / "demo_hello.json").write_text(json.dumps(EVIDENCE, indent=2))
        (run / "_run_metadata.json").write_text(json.dumps({
            "run_id": "2026-11-20T10-31-00Z-a1b2", "started_at": "2026-11-20T10:31:00Z",
            "completed_at": "2026-11-20T10:31:02Z",
            "invocations": [{"fetcher_name": "demo_hello", "exit_code": 0, "target": None,
                             "outputs": ["demo_hello.json"]}]}))
    m = api.init_manifest()
    api.set_output_dir(m, str(out))
    api.add_entry(m, "demo_hello")
    manifest = tmp_path / "wb.yaml"
    api.dump_manifest(m, manifest, REPO_ROOT)

    vfile = tmp_path / "validators" / "demo" / "mfa_enforced.yaml"
    vfile.parent.mkdir(parents=True)
    vfile.write_text(YAML)
    registry = {
        "mfa_enforced": Validator(
            key="mfa_enforced", name="MFA Enforced For All Users", type="AUTOMATED",
            statement="Phishing-resistant MFA is required for every user.", evidence_sets=[REF],
            role="configuration", regex=STALE, path=vfile, validation_rules=[
                {"regexOperation": {"type": "MATCH_COUNT"}, "criteria": "NOT_EQUALS",
                 "value": {"type": "CUSTOM_TEXT", "customText": "0"}},
                {"regexOperation": {"type": "MATCH_GROUP", "groupNumber": 1}, "criteria": "EQUALS",
                 "value": {"type": "CUSTOM_TEXT", "customText": "true"}}]),
        "all_users_enrolled": Validator(
            key="all_users_enrolled", name="Every User Enrolled In MFA", type="AUTOMATED",
            statement="Every user has enrolled an MFA factor.", evidence_sets=[REF], role="completeness",
            regex='"enrolled_users":\\s*(?<enrolled>\\d+),\\s*"total_users":\\s*(?<total>\\d+)',
            validation_rules=[
                {"regexOperation": {"type": "MATCH_COUNT"}, "criteria": "NOT_EQUALS",
                 "value": {"type": "CUSTOM_TEXT", "customText": "0"}},
                {"regexOperation": {"type": "MATCH_GROUP", "groupNumber": 1}, "criteria": "EQUALS",
                 "value": {"type": "MATCH_GROUP", "groupNumber": 2}}]),
    }
    return manifest, registry


PARAMIFY = {"state": "ok", "results": {
    "mfa_enforced": {"id": "v-1", "name": "MFA Enforced For All Users", "result": "FAIL",
                     "at": "2026-11-19 14:02", "artifact": "demo_hello.json"},
    "all_users_enrolled": {"id": "v-2", "name": "Every User Enrolled In MFA", "result": "PASS",
                           "at": "2026-11-19 14:02", "artifact": "demo_hello.json"},
}}


def fake_claude(answer: str = ANSWER):
    """A stand-in for ask_claude.ask: streams `answer` word by word, never runs claude."""
    calls = []

    def ask(prompt, *, on_event, **kw):
        calls.append(prompt)
        on_event(ask_claude.Event("turn"))
        for word in answer.split(" "):
            on_event(ask_claude.Event("text", word + " "))
        on_event(ask_claude.Event("final", answer))
        return ask_claude.Outcome(answer=answer)

    return ask, calls


def stub(monkeypatch, registry, paramify=PARAMIFY, answer: str = ANSWER) -> list:
    monkeypatch.setattr(page_mod, "discover_validators", lambda root: registry)
    monkeypatch.setattr(api, "validator_results", lambda root, ref, vs: paramify)
    monkeypatch.setattr(ask_claude, "find_claude", lambda: "/fake/claude")
    ask, calls = fake_claude(answer)
    monkeypatch.setattr(ask_claude, "ask", ask)
    return calls


def _text(renderable) -> str:
    console = Console(file=io.StringIO(), width=220, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


async def _settle(app, pilot) -> None:
    for _ in range(3):
        await app.workers.wait_for_complete()
        await pilot.pause()


async def open_validator(app, pilot, row: int) -> ValidatorModal:
    """Tab 4, into the validators, onto `row` (1 = the first under PARAMIFY), enter."""
    await pilot.press("4")
    await _settle(app, pilot)
    await pilot.press("right")
    page = app.screen.query_one(ValidatorsPage)
    page.query_one("#vs-validators", DataTable).move_cursor(row=row)
    await pilot.pause()
    await pilot.press("enter")
    await _settle(app, pilot)
    return app.screen


def _foot(modal) -> str:
    return _text(modal.query_one("#vm-foot", Label).content)


# -- the list ------------------------------------------------------------------ #


def test_the_list_shows_each_validators_latest_result_in_paramify(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry)

    async def body(app, pilot):
        await pilot.press("4")
        await _settle(app, pilot)
        page = app.screen.query_one(ValidatorsPage)
        table = page.query_one("#vs-validators", DataTable)
        rows = [" ".join(_text(c).strip() for c in table.get_row_at(i)).strip() for i in range(table.row_count)]
        await pilot.press("right")
        await pilot.pause()
        return rows, _text(page.query_one("#vs-detail", Static).content)

    rows, detail = run_tui(body, manifest)
    assert rows[1].endswith("PASS") and "Every User Enrolled" in rows[1]
    assert rows[2].endswith("FAIL") and "MFA Enforced" in rows[2]
    assert "in Paramify   PASS   on the newest upload, 2026-11-19 14:02" in detail


def test_no_token_shows_no_marks(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry, paramify={"state": "no_token", "results": {}})

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 1)
        table = app.screen_stack[-2].query_one(ValidatorsPage).query_one("#vs-validators", DataTable)
        return [_text(c).strip() for c in table.get_row_at(1)], _text(modal._top())

    cells, top = run_tui(body, manifest)
    assert cells[-1] == ""
    assert "Not read: no Paramify API token." in top


# -- the window: Paramify's result and the local test --------------------------- #


@needs_node
def test_a_passing_validator(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry)

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 1)
        return modal.local, _text(modal._top()), _foot(modal)

    local, top, foot = run_tui(body, manifest)
    assert local["verdict"] == "PASS"
    assert "in Paramify        PASS   on the newest upload, 2026-11-19 14:02" in top
    assert "on your last run   PASS   demo_hello.json" in top
    assert "✓  group 1 (enrolled) equals group 2 (total)   read 42 and 42" in top
    assert "ask Claude" not in foot


@needs_node
def test_a_failing_validator_says_why_and_offers_claude(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry)

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 2)
        return modal.local, _text(modal._top()), _foot(modal)

    local, top, foot = run_tui(body, manifest)
    assert local["verdict"] == "FAIL"
    assert "The regex found nothing in this file." in top
    assert "✗  number of matches not equals 0   read 0" in top
    assert "a ask Claude why" in foot


@needs_node
def test_no_evidence_says_to_run_the_fetcher(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path, evidence=False)
    stub(monkeypatch, registry)

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 2)
        return _text(modal._top())

    assert "No evidence from demo_hello yet. Run it on the Run tab (2), then press t." in run_tui(body, manifest)


def test_without_node_it_says_how_to_get_it(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry)
    monkeypatch.setattr(page_mod, "node_available", lambda: False)

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 2)
        return _text(modal._top()), _foot(modal)

    top, foot = run_tui(body, manifest)
    assert "Node isn't installed" in top and "brew install node" in top
    assert "ask Claude" not in foot


# -- Ask Claude ------------------------------------------------------------------ #


@needs_node
def test_ask_claude_shows_what_it_sends_then_a_tested_fix_and_w_writes_it(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    calls = stub(monkeypatch, registry)
    seen = {}

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 2)
        await pilot.press("a")
        await pilot.pause()
        seen["confirm"] = isinstance(app.screen, ReportModal)
        seen["sent"] = _text(app.screen.query_one("#preview-text", Static).content)
        await pilot.press("y")
        await _settle(app, pilot)
        seen["proposal"] = modal.proposal
        seen["claude"] = _text(modal.query_one("#vm-claude", Static).content)
        seen["foot"] = _foot(modal)
        await pilot.press("w")
        await pilot.pause()
        seen["write_confirm"] = isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        await _settle(app, pilot)
        seen["after"] = modal.local["verdict"]
        seen["again"] = app.ask_claude_confirmed

    run_tui(body, manifest)
    assert seen["confirm"] and len(calls) == 1
    # What is sent: the validator, its trace, and the evidence itself.
    assert STALE in seen["sent"] and "FAILS (read nothing)" in seen["sent"] and '"enrolled_users": 42' in seen["sent"]
    assert seen["proposal"]["regex"] == FIXED and seen["proposal"]["test"]["verdict"] == "PASS"
    assert "proposed regex   PASS   on demo_hello.json" in seen["claude"]
    assert "w writes it to" in seen["claude"] and "validators/demo/mfa_enforced.yaml" in seen["claude"]
    assert "w write the fix" in seen["foot"]
    assert seen["write_confirm"]
    text = (tmp_path / "validators" / "demo" / "mfa_enforced.yaml").read_text()
    assert f"regex: '{FIXED}'" in text and "# The policy flag" in text  # comments kept
    assert seen["after"] == "PASS"
    assert seen["again"] is True


@needs_node
@pytest.mark.parametrize("tracked", [True, False])
def test_after_w_it_points_at_the_paramify_tabs_sync(tmp_path, monkeypatch, run_tui, tracked):
    """The Paramify tab's sync (5, v) updates a validator whose file changed, so
    the window and the notice after w send the fix there, not to a command, and
    say to track the validator first when the manifest doesn't."""
    manifest, registry = make_workspace(tmp_path)
    if not tracked:
        m = api.read_manifest(manifest)
        m["run"]["fetchers"][0]["validators"] = ["all_users_enrolled"]
        api.dump_manifest(m, manifest, REPO_ROOT)
    stub(monkeypatch, registry)
    seen = {}

    async def body(app, pilot):
        app.ask_claude_confirmed = True
        modal = await open_validator(app, pilot, 2)
        await pilot.press("a")
        await _settle(app, pilot)
        seen["claude"] = " ".join(_text(modal.query_one("#vm-claude", Static).content).split())
        await pilot.press("w")
        await pilot.pause()
        await pilot.press("y")
        await _settle(app, pilot)
        seen["notices"] = [str(n.message) for n in app._notifications]

    run_tui(body, manifest)
    saved = next(n for n in seen["notices"] if n.startswith("Saved "))
    assert "paramify validators sync" not in seen["claude"] and "paramify validators sync" not in saved
    if tracked:
        hint = "To send it, press v on the Paramify tab (5): it shows what changed and updates it on a yes."
        assert hint in seen["claude"] and saved.endswith(hint)
    else:
        assert "This manifest doesn't track it, so press space to track it." in saved


@needs_node
def test_a_proposal_that_still_fails_is_not_offered(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry, answer='Why: guess.\nRegex: `"nope":\\s*(?<x>true)`')

    async def body(app, pilot):
        app.ask_claude_confirmed = True
        modal = await open_validator(app, pilot, 2)
        await pilot.press("a")
        await _settle(app, pilot)
        await pilot.press("w")
        await pilot.pause()
        return modal.proposal, _text(modal.query_one("#vm-claude", Static).content), app.screen is modal

    proposal, claude, still = run_tui(body, manifest)
    assert proposal["test"]["verdict"] == "FAIL"
    assert "Not offered" in claude
    assert still  # w did nothing
    assert STALE in (tmp_path / "validators" / "demo" / "mfa_enforced.yaml").read_text()


@needs_node
def test_ask_claude_can_be_turned_off(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    calls = stub(monkeypatch, registry)
    monkeypatch.setenv(ask_claude.ENV_SWITCH, "0")

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 2)
        await pilot.press("a")
        await _settle(app, pilot)
        return _foot(modal), app.screen is modal

    foot, still = run_tui(body, manifest)
    assert "ask Claude" not in foot and still and calls == []


@needs_node
def test_without_claude_code_the_key_says_so_and_c_copies_the_report(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    calls = stub(monkeypatch, registry)
    monkeypatch.setattr(ask_claude, "find_claude", lambda: None)
    copied = []

    async def body(app, pilot):
        monkeypatch.setattr(app, "copy_to_clipboard", copied.append)
        modal = await open_validator(app, pilot, 2)
        foot = _foot(modal)
        await pilot.press("a")
        await _settle(app, pilot)
        await pilot.press("c")
        await _settle(app, pilot)
        return foot, _text(modal.query_one("#vm-claude").render()) if modal.query("#vm-claude") else ""

    foot, claude = run_tui(body, manifest)
    assert "a ask Claude (not installed)" in foot and "c copy report" in foot
    assert calls == []  # nothing was sent
    assert len(copied) == 1 and "MFA Enforced For All Users" in copied[0]


@needs_node
def test_copy_report_works_with_ask_claude_turned_off(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry)
    monkeypatch.setenv(ask_claude.ENV_SWITCH, "0")
    copied = []

    async def body(app, pilot):
        monkeypatch.setattr(app, "copy_to_clipboard", copied.append)
        modal = await open_validator(app, pilot, 2)
        await pilot.press("c")
        await _settle(app, pilot)
        return _foot(modal)

    foot = run_tui(body, manifest)
    assert "c copy report" in foot and "ask Claude" not in foot
    assert len(copied) == 1


# -- the pieces -------------------------------------------------------------------- #


def test_latest_result_is_the_newest_artifact_that_has_one():
    artifacts = [  # newest first, as list_artifacts returns them
        {"created_at": "2026-11-20T09:00:00Z", "title": "c", "validators": [{"id": "v-2", "name": "B", "result": "FAIL"}]},
        {"created_at": "2026-11-19T09:00:00Z", "title": "b", "validators": [{"id": "v-1", "name": "A", "result": "PASS"},
                                                                          {"id": "v-2", "name": "B", "result": "PASS"}]},
    ]
    latest = api.latest_validator_results(artifacts)
    assert latest["v-2"]["result"] == "FAIL" and latest["v-2"]["at"] == "2026-11-20 09:00"
    assert api.result_for(latest, "v-1", "A")["result"] == "PASS"
    assert api.result_for(latest, None, "B")["result"] == "FAIL"  # by name without a lock id
    assert api.result_for(latest, None, "C") is None


def test_proposed_regex_reads_the_regex_line():
    assert ask_claude.proposed_regex(ANSWER) == FIXED
    assert ask_claude.proposed_regex("Why: the control is off.\nRegex: none") is None
    assert ask_claude.proposed_regex("Why: no regex line at all") is None


def test_write_regex_keeps_the_file_and_refuses_a_block_regex(tmp_path):
    path = tmp_path / "v.yaml"
    path.write_text(YAML)
    write_regex(path, "it's \\d+")
    assert "regex: 'it''s \\d+'" in path.read_text() and "# The policy flag" in path.read_text()
    path.write_text("key: x\nregex: >-\n  abc\n")
    with pytest.raises(ValueError):
        write_regex(path, "x")


def test_proposed_regex_takes_the_first_backtick_span_after_regex():
    assert ask_claude.proposed_regex(f"Why: renamed.\nRegex: `{FIXED}` (matches the new key)") == FIXED
    assert ask_claude.proposed_regex("Why: x.\n**Regex:** `a+` then `b+`") == "a+"
    # The answer drops the whole Regex: line, trailing words included.
    assert ask_claude.REGEX_LINE.sub("", "Why: x.\nRegex: `a+` (tested)").strip() == "Why: x."


def test_write_regex_refuses_a_quoted_regex_continued_on_the_next_line(tmp_path):
    path = tmp_path / "v.yaml"
    for text in ("key: x\nregex: 'abc\n  def'\nname: n\n",
                 'key: x\nregex: "abc\n  def"\nname: n\n',
                 "key: x\nregex: abc\n  def\nname: n\n"):
        path.write_text(text)
        with pytest.raises(ValueError, match="spans several lines"):
            write_regex(path, "x")
        assert path.read_text() == text  # untouched


def test_write_regex_turns_a_yaml_error_into_a_value_error(tmp_path):
    path = tmp_path / "v.yaml"
    path.write_text("key: [unclosed\nregex: 'abc'\n")
    with pytest.raises(ValueError):
        write_regex(path, "x")


# -- the local test across several files ---------------------------------------- #

PAIRED = Validator(
    key="enrolled_matches_total", name="Enrolled Matches Total", type="AUTOMATED",
    statement="Every user has enrolled.", evidence_sets=[REF], role="completeness",
    regex='"enrolled_users":\\s*(?<enrolled>\\d+),\\s*"total_users":\\s*(?<total>\\d+)',
    # No match-count rule: with no match, nothing equals nothing and it passes vacuously.
    validation_rules=[{"regexOperation": {"type": "MATCH_GROUP", "groupNumber": 1}, "criteria": "EQUALS",
                       "value": {"type": "MATCH_GROUP", "groupNumber": 2}}])


@needs_node
def test_a_vacuous_pass_on_a_later_file_is_shown_and_counted(tmp_path):
    clean, empty = tmp_path / "a_clean.json", tmp_path / "b_empty.json"
    clean.write_text(json.dumps(EVIDENCE))
    empty.write_text(json.dumps({"payload": {"results": []}}))
    local = page_mod.run_local_test(PAIRED, [clean, empty])
    assert local["verdict"] == "PASS"
    assert local["shown"][0] == empty and local["shown"][1]["vacuous"]
    assert local["failing"] == 1 and local["vacuous"] == 1
    # A FAIL still outranks a vacuous pass.
    assert page_mod._rank({"verdict": "FAIL"}) > page_mod._rank({"verdict": "PASS", "vacuous": True}) \
        > page_mod._rank({"verdict": "PASS", "vacuous": False})

    modal = ValidatorModal(PAIRED, True, REF, tmp_path)
    modal.proposal = {"regex": PAIRED.regex, "test": local}
    assert not modal._can_write()  # vacuous on one of the files
    modal.proposal = {"regex": PAIRED.regex, "test": page_mod.run_local_test(PAIRED, [clean, clean])}
    assert modal._can_write()


@needs_node
def test_paramify_results_reach_the_window_under_the_send_confirmation(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry)

    async def body(app, pilot):
        modal = await open_validator(app, pilot, 2)
        page = app.screen_stack[-2].query_one(ValidatorsPage)
        modal.paramify = None  # still reading
        await pilot.press("a")
        await pilot.pause()
        on_top = isinstance(app.screen, ReportModal)
        page.post_message(page_mod.ResultsReady(REF, PARAMIFY))
        await _settle(app, pilot)
        return on_top, modal.paramify, _text(modal._top())

    on_top, paramify, top = run_tui(body, manifest)
    assert on_top and paramify == PARAMIFY
    assert "reading the workspace" not in top and "FAIL   on the newest upload" in top


@needs_node
def test_the_window_sends_claude_no_secrets(tmp_path, monkeypatch, run_tui):
    manifest, registry = make_workspace(tmp_path)
    stub(monkeypatch, registry)
    seen = {}

    def ask(prompt, *, on_event, **kw):
        seen.update(kw)
        return ask_claude.Outcome(answer="Why: x.\nRegex: none")

    monkeypatch.setattr(ask_claude, "ask", ask)

    async def body(app, pilot):
        app.ask_claude_confirmed = True
        await open_validator(app, pilot, 2)
        await pilot.press("a")
        await _settle(app, pilot)
        return ask_claude.secret_names(app.root_path, app.manifest)

    expected = run_tui(body, manifest)
    assert "cwd" not in seen  # ask() makes its own empty folder
    assert set(seen["drop"]) == expected and "PARAMIFY_API_TOKEN" in expected


# -- what claude runs with ----------------------------------------------------- #


class FakeProc:
    def __init__(self, answer: str) -> None:
        self.stdin = io.StringIO()
        self.stdout = io.StringIO(json.dumps({"type": "result", "result": answer}) + "\n")
        self.stderr = io.StringIO("")
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self):
        self.returncode = 0
        return 0

    def kill(self):
        self.returncode = -9


def test_claude_runs_in_an_empty_folder_with_no_tools_and_no_secrets(tmp_path, monkeypatch):
    import os
    import tempfile

    (tmp_path / ".env").write_text("FROM_DOTENV_TOKEN=s3cret\nEMPTY_ONE=\n")
    monkeypatch.setenv("FROM_DOTENV_TOKEN", "s3cret")  # as load_dotenv leaves it
    monkeypatch.setenv("OKTA_API_TOKEN", "t0ken")
    monkeypatch.setenv("CLAUDECODE", "1")
    manifest = {"run": {"fetchers": [{"use": "okta_mfa", "secrets": {"token": "${env:OKTA_API_TOKEN}"}}]}}
    seen = {}

    def popen(cmd, *, cwd, env, **kw):
        seen.update(cmd=cmd, cwd=cwd, env=env, listing=os.listdir(cwd))
        return FakeProc("Why: x.\nRegex: none")

    outcome = ask_claude.ask("the report", exe="/fake/claude", on_event=lambda ev: None,
                             drop=ask_claude.secret_names(tmp_path, manifest), popen=popen)
    assert outcome.ok
    # A fresh, empty temp folder, not the repo, removed afterwards.
    assert seen["listing"] == []
    assert os.path.realpath(seen["cwd"]).startswith(os.path.realpath(tempfile.gettempdir()))
    assert not Path(seen["cwd"]).exists()
    # No tools at all, so nothing to approve either.
    cmd = seen["cmd"]
    assert cmd[cmd.index("--tools") + 1] == ""
    assert "--allowedTools" not in cmd and not any("Read" in part for part in cmd)
    # Neither .env's variables nor the manifest's secrets; what claude needs to start stays.
    env = seen["env"]
    assert "FROM_DOTENV_TOKEN" not in env and "OKTA_API_TOKEN" not in env and "CLAUDECODE" not in env
    assert env.get("PATH") == os.environ["PATH"] and env.get("HOME") == os.environ["HOME"]


def test_an_empty_or_not_set_result_does_not_hide_an_older_verdict():
    artifacts = [  # newest first
        {"created_at": "2026-11-20T09:00:00Z", "title": "c", "validators": [
            {"id": "v-1", "name": "A", "result": "NOT_SET"}, {"id": "v-2", "name": "B", "result": ""},
            {"id": "v-3", "name": "C", "result": "NOT_SET"}]},
        {"created_at": "2026-11-19T09:00:00Z", "title": "b", "validators": [
            {"id": "v-1", "name": "A", "result": "FAIL"}, {"id": "v-2", "name": "B", "result": "PASS"}]},
    ]
    latest = api.latest_validator_results(artifacts)
    assert latest["v-1"]["result"] == "FAIL" and latest["v-1"]["at"] == "2026-11-19 09:00"
    assert latest["v-2"]["result"] == "PASS"
    # No artifact has a real verdict for C: it reads as not run.
    assert api.result_for(latest, "v-3", "C") is None
