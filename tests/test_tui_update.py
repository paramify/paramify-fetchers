"""TUI: the "update waiting" notice, and the update screen that applies or rolls back.

framework.api is stubbed at its boundary: no git, no subprocess, no network. The
app, the screen and its modals run for real.
"""

from __future__ import annotations

import asyncio
import copy
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Button, DataTable  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.components.chrome import UpdateNotice  # noqa: E402
from framework.tui.modals import ConfirmModal  # noqa: E402
from framework.tui.screens.update import UpdateScreen  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

# The shape `paramify update --json` prints (trimmed: two fetchers, three breaking).
PLAN = {
    "ok": True, "errors": [],
    "current": {"label": "main @ fc74f19", "short": "fc74f19", "branch": "main"},
    "fetched": True, "channel": "branch",
    "target": {"channel": "branch", "ref": "origin/main", "sha": "3a97b70bdfae3a403b38f704f571591d595f8a37",
               "label": "main", "branch": "main"},
    "span": {"commits": 281, "days": 4}, "direction": "forward",
    "manifests": ["manifests/prod.yaml"],
    "check": {"ok": True, "python_required": None, "python": "3.12.14", "linked_local_fetchers": [],
              "has_local_fetchers": True, "fetchers": {},
              "manifests": [{"manifest": "manifests/prod.yaml", "status": "ok", "errors": [], "reason": None}]},
    "fetchers": {
        "yours": [
            {"name": "azure_alert_rules", "change": "changed", "manifests": ["manifests/prod.yaml"],
             "from": "0.3.0", "to": "0.3.1", "reason": None, "more": 2},
            {"name": "azure_entra_privileged_roles", "change": "changed", "manifests": ["manifests/prod.yaml"],
             "from": "0.2.0", "to": "0.3.0", "reason": "administrative-unit holders are not checked", "more": 4},
        ],
        "others": ["aws_discovery_beta", "azure_ddos_protection"],
        "added": ["wiz_inventory"], "removed": [],
    },
    "breaking": [
        {"title": "An inventory fetcher needs a pipeline block in fetcher.yaml",
         "fix": "Add pipeline: {type: inventory, id_scheme: <scheme>}", "release": "unreleased",
         "touches": True, "why": "custom", "manifests": []},
        {"title": "Inventory records must carry asset_type", "fix": "Set asset_type",
         "release": "unreleased", "touches": True, "why": "custom", "manifests": []},
        {"title": "Something that does not touch this clone", "fix": "n/a", "release": "unreleased",
         "touches": False, "why": "everyone", "manifests": []},
    ],
    "highlights": [
        {"tag": "cli", "title": "paramify status shows what each fetcher has in Paramify",
         "detail": "Evidence set, artifact count and validators", "try": "paramify status <manifest>",
         "release": "unreleased"},
    ],
    "hidden_highlights": 0,
    "tries": ["paramify status <manifest>"],
    "used": 2,
    "changelog": "https://github.com/paramify/paramify-fetchers/blob/3a97b70bdf/CHANGELOG.md",
    "stops": {"breaks": [], "python_required": None,
              "touching": ["An inventory fetcher needs a pipeline block in fetcher.yaml",
                           "Inventory records must carry asset_type"]},
    "state": "ready",
    "needs_allow_breaking": True,
    "can_roll_back": False,
}
SHA = PLAN["target"]["sha"]


def _plan(**over) -> dict:
    plan = copy.deepcopy(PLAN)
    plan.update(over)
    return plan


def _text(widget) -> str:
    content = widget.render()
    if hasattr(content, "plain"):
        return content.plain
    # A Group (the breaking rows): render it the way the widget would.
    from rich.console import Console

    console = Console(width=200, file=io.StringIO(), record=True)
    console.print(getattr(content, "_renderable", None) or widget.content)
    return console.export_text()


def _run(body, *, size=(120, 40)):
    async def main():
        app = FetcherApp(root_override=str(REPO_ROOT))
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.pause()
            return await body(app, pilot)

    return asyncio.run(main())


# --------------------------------------------------------------------------- #
# The notice
# --------------------------------------------------------------------------- #

def test_notice_shows_when_update_waiting(monkeypatch):
    monkeypatch.setattr(api, "update_notice", lambda root: "12 new commits on main")

    async def body(app, pilot):
        await pilot.pause()
        notice = app.screen.query_one(UpdateNotice)
        assert notice.display
        assert "12 new commits on main" in _text(notice)
        assert "press U" in _text(notice)

    _run(body)


def test_no_notice_when_none(monkeypatch):
    monkeypatch.setattr(api, "update_notice", lambda root: None)

    async def body(app, pilot):
        await pilot.pause()
        notice = app.screen.query_one(UpdateNotice)
        assert not notice.display

    _run(body)


def test_a_failing_notice_check_is_silent(monkeypatch):
    def boom(root):
        raise RuntimeError("git exploded")

    monkeypatch.setattr(api, "update_notice", boom)

    async def body(app, pilot):
        await pilot.pause()
        assert not app.screen.query_one(UpdateNotice).display

    _run(body)


# --------------------------------------------------------------------------- #
# The screen
# --------------------------------------------------------------------------- #

def test_screen_lists_breaking_that_touch():
    async def body(app, pilot):
        await app.push_screen(UpdateScreen(_plan()))
        await pilot.pause()
        screen = app.screen
        breaking = _text(screen.query_one("#update-breaking"))
        assert "2 touch you" in breaking
        assert "An inventory fetcher needs a pipeline block" in breaking
        assert "Inventory records must carry asset_type" in breaking
        assert "does not touch this clone" not in breaking
        assert "fix:" in breaking
        table = screen.query_one("#update-fetchers", DataTable)
        assert table.row_count == 2
        assert "main" in _text(screen.query_one("#update-header"))
        assert "passes" in _text(screen.query_one("#update-check"))
        assert "paramify status shows" in _text(screen.query_one("#update-new"))
        assert not screen.query("#update-rollback")

    _run(body)


def test_screen_shows_the_newest_fetcher_note():
    plan = _plan()
    plan["fetchers"]["yours"][0]["notes"] = [
        {"release": "0.8.0-beta", "version": "0.3.1", "note": "alerts fire sooner"},
        {"release": "0.7.0-beta", "version": "0.3.0", "note": "older note"}]

    async def body(app, pilot):
        await app.push_screen(UpdateScreen(plan))
        await pilot.pause()
        table = app.screen.query_one("#update-fetchers", DataTable)
        cell = table.get_row_at(0)[2].plain
        assert cell.startswith("0.8.0-beta  alerts fire sooner") and cell.endswith("+1 earlier")

    _run(body)


def test_rollback_button_only_when_there_is_something_to_roll_back_to():
    async def body(app, pilot):
        await app.push_screen(UpdateScreen(_plan(can_roll_back=True)))
        await pilot.pause()
        assert app.screen.query_one("#update-rollback", Button)

    _run(body)


def test_apply_with_breaking_needs_second_confirm(monkeypatch):
    calls = []
    monkeypatch.setattr(api, "apply_update",
                        lambda root, expect, allow_breaking: calls.append((expect, allow_breaking)) or {"ok": True, "errors": []})

    async def body(app, pilot):
        await app.push_screen(UpdateScreen(_plan()))
        await pilot.pause()
        await pilot.click("#update-apply")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        await pilot.pause()
        # first yes is not enough: a second dialog names how many breaking changes touch this clone
        assert isinstance(app.screen, ConfirmModal)
        assert "2 breaking changes" in app.screen._message
        assert calls == []
        await pilot.press("n")
        await pilot.pause()
        assert calls == []
        # and yes to both applies, allowing breaking
        await pilot.click("#update-apply")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert calls == [(SHA, True)]  # the commit this screen showed, nothing newer
        assert "Restart the TUI to load the new code." in _text(app.screen.query_one("#update-result"))

    _run(body)


def test_apply_without_breaking_asks_once(monkeypatch):
    calls = []
    monkeypatch.setattr(api, "apply_update",
                        lambda root, expect, allow_breaking: calls.append((expect, allow_breaking)) or {"ok": True, "errors": []})
    plan = _plan(breaking=[], stops={"breaks": [], "touching": [], "python_required": None}, needs_allow_breaking=False)

    async def body(app, pilot):
        await app.push_screen(UpdateScreen(plan))
        await pilot.pause()
        await pilot.click("#update-apply")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert calls == [(SHA, False)]

    _run(body)


def test_failed_apply_shows_the_error_and_keeps_the_screen(monkeypatch):
    monkeypatch.setattr(api, "apply_update",
                        lambda root, expect, allow_breaking: {"ok": False, "errors": ["local files are in the way"]})

    async def body(app, pilot):
        await app.push_screen(UpdateScreen(_plan(breaking=[], stops={"breaks": [], "touching": [],
                                                                     "python_required": None},
                                                               needs_allow_breaking=False)))
        await pilot.pause()
        await pilot.click("#update-apply")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        result = _text(app.screen.query_one("#update-result"))
        assert "local files are in the way" in result
        assert "Restart" not in result

    _run(body)


def test_an_apply_that_moved_then_failed_is_treated_as_moved(monkeypatch):
    monkeypatch.setattr(api, "apply_update", lambda root, expect, allow_breaking: {
        "ok": False, "switched": True,
        "errors": ["you're on main, but 1 manifest fails on the new code. Fix what validate names, "
                   "or go back with paramify update --rollback"]})
    plan = _plan(breaking=[], stops={"breaks": [], "touching": [], "python_required": None}, needs_allow_breaking=False)

    async def body(app, pilot):
        app.show_update_notice("281 new commits on main")
        await app.push_screen(UpdateScreen(plan))
        await pilot.pause()
        await pilot.click("#update-apply")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        screen = app.screen
        text = _text(screen.query_one("#update-result"))
        assert "1 manifest fails" in text and "Restart the TUI" in text
        assert screen.query_one("#update-apply", Button).disabled
        assert not screen.query_one("#update-rollback", Button).disabled
        assert app.update_waiting is None

    _run(body)


def test_an_offline_plan_says_it_may_be_stale():
    async def body(app, pilot):
        await app.push_screen(UpdateScreen(_plan(fetched=False)))
        await pilot.pause()
        assert "couldn't reach origin" in _text(app.screen.query_one("#update-header"))

    _run(body)


def test_rollback_confirms_then_runs(monkeypatch):
    calls = []
    monkeypatch.setattr(api, "rollback_update", lambda root: calls.append(1) or {"ok": True, "errors": []})

    async def body(app, pilot):
        await app.push_screen(UpdateScreen(_plan(can_roll_back=True)))
        await pilot.pause()
        await pilot.click("#update-rollback")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert calls == [1]
        assert "Restart the TUI" in _text(app.screen.query_one("#update-result"))

    _run(body)


def test_a_blocked_plan_names_the_files_and_offers_no_apply():
    plan = {k: v for k, v in PLAN.items() if k not in ("check", "fetchers", "breaking", "highlights", "stops")}
    plan.update(state="blocked", blocking={"tracked": ["fetchers/demo/alpha/fetch.py"], "untracked": []})

    async def body(app, pilot):
        await app.push_screen(UpdateScreen(plan))
        await pilot.pause()
        screen = app.screen
        assert "fetchers/demo/alpha/fetch.py" in _text(screen.query_one("#update-blocked"))
        assert not screen.query("#update-apply")

    _run(body)


def test_a_python_too_old_for_the_target_is_shown_not_offered():
    plan = _plan(stops={**PLAN["stops"], "python_required": ">=3.13"}, state="unrunnable",
                 check={**PLAN["check"], "python_required": ">=3.13"})

    async def body(app, pilot):
        await app.push_screen(UpdateScreen(plan))
        await pilot.pause()
        assert "needs Python >=3.13" in _text(app.screen.query_one("#update-check"))
        assert not app.screen.query("#update-apply")

    _run(body)


def test_an_up_to_date_clone_has_nothing_to_apply():
    async def body(app, pilot):
        await app.push_screen(UpdateScreen({"ok": True, "errors": [], "up_to_date": True,
                                            "current": {"label": "main @ fc74f19"}, "can_roll_back": False}))
        await pilot.pause()
        assert "up to date" in _text(app.screen.query_one("#update-header")).lower()
        assert not app.screen.query("#update-apply")

    _run(body)


def test_a_plan_with_errors_shows_them_and_cannot_be_applied():
    async def body(app, pilot):
        await app.push_screen(UpdateScreen({"ok": False, "errors": ["couldn't read the clone"]}))
        await pilot.pause()
        assert "couldn't read the clone" in _text(app.screen.query_one("#update-header"))
        assert not app.screen.query("#update-apply")

    _run(body)


@pytest.mark.parametrize("key", ["U", "u"])
def test_u_key_opens_the_screen_with_the_plan(monkeypatch, key):
    monkeypatch.setattr(api, "update_plan", lambda root: _plan())

    async def body(app, pilot):
        await pilot.press(key)
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert isinstance(app.screen, UpdateScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, UpdateScreen)

    _run(body)


# --------------------------------------------------------------------------- #
# The api: a subprocess, so the TUI never imports half-updated code
# --------------------------------------------------------------------------- #

def _fake_run(monkeypatch, *, stdout="", stderr="", code=0):
    seen = {}

    def run(cmd, **kw):
        seen.update(cmd=cmd, **kw)
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)

    monkeypatch.setattr(subprocess, "run", run)
    return seen


def test_non_json_output_is_an_error_line(monkeypatch, tmp_path):
    seen = _fake_run(monkeypatch, stdout="Traceback...\n", stderr="warn\nModuleNotFoundError: no module x\n", code=1)
    out = api.apply_update(tmp_path, SHA, allow_breaking=False)
    assert out == {"ok": False, "errors": ["ModuleNotFoundError: no module x"]}
    assert seen["cwd"] == tmp_path


def test_apply_asks_the_cli_for_exactly_the_planned_commit(monkeypatch, tmp_path):
    reply = {"ok": True, "errors": [], "version": "main"}
    seen = _fake_run(monkeypatch, stdout=json.dumps(reply))
    assert api.apply_update(tmp_path, SHA, allow_breaking=True) == reply
    assert seen["cmd"][seen["cmd"].index("--expect") + 1] == SHA
    assert api.rollback_update(tmp_path) == reply


def test_update_plan_reads_the_plan_in_this_process(monkeypatch, tmp_path):
    from framework import update

    located = {"current": {"label": "main @ fc74f19"}, "target": PLAN["target"], "up_to_date": False,
               "manifests": [{"label": "manifests/prod.yaml", "path": "/x"}], "rows": [{"tag": "new"}]}
    monkeypatch.setattr(update, "plan", lambda root: located)
    monkeypatch.setattr(update, "rollback_refusal", lambda root: None)
    plan = api.update_plan(tmp_path)
    assert plan["ok"] and plan["errors"] == [] and plan["can_roll_back"]
    assert plan["manifests"] == ["manifests/prod.yaml"] and "rows" not in plan

    def refuse(root):
        raise update.UpdateError("main has 2 commits that origin/main does not")

    monkeypatch.setattr(update, "plan", refuse)
    monkeypatch.setattr(update, "rollback_refusal", lambda root: "nothing to roll back to")
    assert api.update_plan(tmp_path) == {"ok": False, "errors": ["main has 2 commits that origin/main does not"],
                                         "can_roll_back": False}


# --------------------------------------------------------------------------- #
# The header at 80 columns with the notice showing
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("width", "shown"), [(80, "↑ update · U"), (140, "↑ 12 new commits on main · press U")])
def test_the_header_picks_the_wording_that_fits(monkeypatch, width, shown):
    monkeypatch.setattr(api, "update_notice", lambda root: "12 new commits on main")
    got = _header_probe(width)
    assert got.notice and got.text == shown


def test_alone_on_the_welcome_screen_the_notice_says_it_in_full(monkeypatch):
    async def body(app, pilot):
        app.show_update_notice("12 new commits on main")
        await pilot.pause()
        assert _text(app.screen.query_one("#welcome-update")) == "↑ 12 new commits on main · press U"

    _run(body, size=(80, 30))


@pytest.mark.parametrize("notice", ["12 new commits on main", None])
def test_header_fits_at_80_columns(monkeypatch, notice):
    """Title, clock and (some of) the crumb always fit on the one header row; the notice gives way first."""
    monkeypatch.setattr(api, "update_notice", lambda root: notice)
    from framework.tui.components.chrome import AppHeader
    from framework.tui.screens.workspace import WorkspaceScreen

    async def main():
        app = FetcherApp(root_override=str(REPO_ROOT))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await app.push_screen(WorkspaceScreen())
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            header = app.screen.query_one(AppHeader)
            header.set_crumb("manifests › prod › paramify")
            await pilot.pause()
            clock = app.screen.query_one("#app-header-clock")
            crumb = app.screen.query_one("#app-header-crumb")
            left = app.screen.query_one("#app-header-left")
            assert clock.region.right <= header.region.right
            assert left.region.y == crumb.region.y == clock.region.y
            assert crumb.region.width >= 6 and crumb.region.right <= clock.region.x
            assert header.size.height <= 2  # one row of content and the rule

    asyncio.run(main())


def test_a_failed_plan_read_does_not_leave_u_dead(monkeypatch):
    monkeypatch.setattr(api, "update_plan", lambda root: _plan())

    async def body(app, pilot):
        def boom(plan):
            raise RuntimeError("no screen for you")

        monkeypatch.setattr(app, "_show_update_screen", boom)
        await pilot.press("U")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app._opening_update is False

    _run(body)


def _header_probe(first, then=None):
    """Boot at `first` columns x 24, resize to `then`, and report the header's geometry."""
    from framework.tui.components.chrome import AppHeader
    from framework.tui.screens.workspace import WorkspaceScreen

    async def main():
        app = FetcherApp(root_override=str(REPO_ROOT))
        async with app.run_test(size=(first, 24)) as pilot:
            await pilot.pause()
            await app.push_screen(WorkspaceScreen())
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            if then:
                await pilot.resize_terminal(then, 24)
                for _ in range(4):
                    await pilot.pause()
            header = app.screen.query_one(AppHeader)
            header.set_crumb("manifests › prod › paramify")
            await pilot.pause()
            q = app.screen.query_one
            return SimpleNamespace(header=header, clock=q("#app-header-clock").region,
                                   crumb=q("#app-header-crumb").region, notice=q(UpdateNotice).display,
                                   text=_text(q(UpdateNotice)), right=header.region.right)

    return asyncio.run(main())


def test_resizing_a_wide_header_down_to_80_keeps_the_clock(monkeypatch):
    monkeypatch.setattr(api, "update_notice", lambda root: "12 new commits on main")
    got = _header_probe(120, 80)
    assert got.clock.right <= got.right
    assert got.crumb.width >= 6 and got.crumb.right <= got.clock.x


def test_the_notice_gives_way_when_the_row_is_too_short(monkeypatch):
    monkeypatch.setattr(api, "update_notice", lambda root: "12 new commits on main")
    got = _header_probe(42)
    assert not got.notice
    assert got.clock.right <= got.right
    assert got.crumb.width >= 6
    wide = _header_probe(120)
    assert wide.notice  # and it is back when there is room


def _late_notice_probe(width):
    """Boot with no update waiting, then let the check land: the header must re-fit for the new text."""
    from framework.tui.components.chrome import AppHeader
    from framework.tui.screens.workspace import WorkspaceScreen

    async def main():
        app = FetcherApp(root_override=str(REPO_ROOT))
        async with app.run_test(size=(width, 24)) as pilot:
            await pilot.pause()
            await app.push_screen(WorkspaceScreen())
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()
            header = app.screen.query_one(AppHeader)
            header.set_crumb("manifests › prod › paramify")
            await pilot.pause()
            assert not app.screen.query_one(UpdateNotice).display  # nothing waiting yet
            app.show_update_notice("12 new commits on main")
            for _ in range(3):
                await pilot.pause()
            q = app.screen.query_one
            return SimpleNamespace(clock=q("#app-header-clock").region, crumb=q("#app-header-crumb").region,
                                   notice=q(UpdateNotice).display, right=header.region.right,
                                   height=header.size.height)

    return asyncio.run(main())


def test_a_late_notice_on_a_short_row_stays_hidden(monkeypatch):
    monkeypatch.setattr(api, "update_notice", lambda root: None)
    got = _late_notice_probe(42)
    assert not got.notice
    assert got.clock.right <= got.right
    assert got.crumb.width >= 6 and got.crumb.right <= got.clock.x
    assert got.height <= 2


def test_a_late_notice_shows_when_there_is_room(monkeypatch):
    monkeypatch.setattr(api, "update_notice", lambda root: None)
    got = _late_notice_probe(120)
    assert got.notice
    assert got.clock.right <= got.right
