"""TUI: the Validators tab, which picks the validators each manifest fetcher tracks.

The registry is stubbed with a few Paramify-made and community-made validators
for demo_hello's evidence set; the manifest is a real file the tab saves to.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.widgets import Static  # noqa: E402

from framework import api  # noqa: E402
from framework.config_loader import discover_fetchers  # noqa: E402
from framework.contract import Validator  # noqa: E402
from framework.tui.components.table import DataTable  # noqa: E402
from framework.tui.screens import validators as page_mod  # noqa: E402
from framework.tui.screens.validators import ValidatorModal, ValidatorsPage, describe_rule  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
REF = discover_fetchers(REPO_ROOT)["demo_hello"].evidence_set.reference_id


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """The tab reads Paramify's results for the highlighted fetcher: no token here."""
    monkeypatch.setattr(api, "validator_results", lambda root, ref, vs: {"state": "no_token", "results": {}})


def _registry(monkeypatch):
    def v(key, source="paramify", role="configuration"):
        return Validator(key=key, name=key.replace("_", " ").title(), type="AUTOMATED",
                         statement=f"{key} holds.", evidence_sets=[REF], source=source, role=role,
                         regex=r'"count":\s*(?<count>\d+)',
                         validation_rules=[{"regexOperation": {"type": "MATCH_GROUP", "groupNumber": 1},
                                            "criteria": "EQUALS", "value": {"type": "CUSTOM_TEXT", "customText": "0"}}])
    reg = {x.key: x for x in [v("p_complete", role="completeness"), v("p_config"),
                              v("c_extra", source="community")]}
    monkeypatch.setattr(page_mod, "discover_validators", lambda root: reg)
    return reg


def _manifest(tmp_path: Path) -> Path:
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, "demo_hello")
    path = tmp_path / "vs.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path


def _text(renderable) -> str:
    console = Console(file=io.StringIO(), width=220, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


def _rows(table: DataTable) -> list:
    return [" ".join(_text(c).strip() for c in table.get_row_at(i)).strip() for i in range(table.row_count)]


async def _open(pilot) -> ValidatorsPage:
    await pilot.press("4")
    await pilot.pause()
    return pilot.app.screen.query_one(ValidatorsPage)


def _entry(path: Path) -> dict:
    return api.read_manifest(path)["run"]["fetchers"][0]


def test_lists_paramify_then_community_with_defaults_ticked(tmp_path, monkeypatch, run_tui):
    _registry(monkeypatch)

    async def body(app, pilot):
        page = await _open(pilot)
        return (_rows(page.query_one("#vs-fetchers", DataTable)),
                _rows(page.query_one("#vs-validators", DataTable)))

    fetchers, validators = run_tui(body, _manifest(tmp_path))
    assert fetchers[0].split()[:3] == ["2/2", "0/1", "demo_hello"]
    assert validators == [
        "PARAMIFY   2 of 2 tracked",
        "▌ [x] P Complete",
        "▌ [x] P Config",
        "",
        "COMMUNITY   0 of 1 tracked",
        "▌ [ ] C Extra",
    ]


def test_space_writes_the_exact_list_and_a_goes_back_to_defaults(tmp_path, monkeypatch, run_tui):
    _registry(monkeypatch)
    path = _manifest(tmp_path)
    seen = {}

    async def body(app, pilot):
        page = await _open(pilot)
        await pilot.press("right")          # into the validators, on the first one
        await pilot.press("down", "space")  # untrack p_config
        seen["untracked"] = _entry(path).get("validators")
        await pilot.press("down", "down", "down", "space")  # track c_extra (skips the blank row and header)
        seen["community"] = _entry(path).get("validators")
        seen["counts"] = _rows(page.query_one("#vs-fetchers", DataTable))[0].split()[:3]
        await pilot.press("a")
        seen["defaults"] = "validators" in _entry(path)

    run_tui(body, path)
    assert seen["untracked"] == ["p_complete"]
    assert seen["community"] == ["p_complete", "c_extra"]
    assert seen["counts"] == ["1/2", "1/1", "demo_hello"]
    assert seen["defaults"] is False


def test_space_on_a_section_header_changes_nothing(tmp_path, monkeypatch, run_tui):
    _registry(monkeypatch)
    path = _manifest(tmp_path)

    async def body(app, pilot):
        page = await _open(pilot)
        await pilot.press("right")
        page.query_one("#vs-validators", DataTable).move_cursor(row=0)  # the PARAMIFY header
        await pilot.pause()
        await pilot.press("space")
        await pilot.pause()
        return _text(page.query_one("#vs-detail", Static).content)

    detail = run_tui(body, path)
    assert "validators" not in _entry(path)
    assert "Tracked by default" in detail


def test_enter_opens_the_full_validator_and_space_there_toggles(tmp_path, monkeypatch, run_tui):
    _registry(monkeypatch)
    path = _manifest(tmp_path)
    seen = {}

    async def body(app, pilot):
        await _open(pilot)
        await pilot.press("right", "enter")
        await pilot.pause()
        modal = app.screen
        seen["modal"] = isinstance(modal, ValidatorModal)
        seen["body"] = _text(modal._top())
        await pilot.press("space")
        await pilot.pause()
        seen["closed"] = not isinstance(app.screen, ValidatorModal)

    run_tui(body, path)
    assert seen["modal"] and seen["closed"]
    assert '"count":\\s*(?<count>\\d+)' in seen["body"]
    assert "group 1 (count) equals 0" in seen["body"]
    assert _entry(path)["validators"] == ["p_config"]


def test_describe_rule_in_plain_words():
    count = {"regexOperation": {"type": "MATCH_COUNT"}, "criteria": "NOT_EQUALS",
             "value": {"type": "CUSTOM_TEXT", "customText": "0"}}
    text = {"regexOperation": {"type": "MATCH_GROUP", "groupNumber": 2}, "criteria": "EQUALS",
            "value": {"type": "CUSTOM_TEXT", "customText": "true"}}
    assert describe_rule(count, []) == "number of matches not equals 0"
    assert describe_rule(text, ["a", "enabled"]) == 'group 2 (enabled) equals "true"'
