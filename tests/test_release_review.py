"""tools/release_review.py: the release notes editor and its preview."""

from __future__ import annotations

import asyncio
import importlib.util
import io
from pathlib import Path

import pytest
import yaml

pytest.importorskip("textual", reason="the editor needs the 'tui' extra")

from framework import release_notes  # noqa: E402
from framework import update_view as view  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("release_review", REPO_ROOT / "tools" / "release_review.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)

DOC = {
    "version": "0.7.0-beta",
    "date": "2026-11-24",
    "highlights": [
        {"tag": "cli", "title": "Shell tab completion", "try": "paramify --install-completion", "draft": True},
        {"tag": "breaking", "title": "Inventory records must carry asset_type",
         "fix": "Set asset_type on every record", "custom_fetchers": True, "draft": True},
    ],
    "fetchers": [
        {"name": "aws_config_inventory", "version": "0.1.0", "note": release_notes.TODO_NOTE, "draft": True},
        {"name": "aws_ecr_image_scanning", "version": "0.5.0", "note": "Counts every image in scope…", "draft": True},
    ],
}


def _write(tmp_path: Path) -> Path:
    p = tmp_path / "0.7.0-beta.yaml"
    p.write_text(release_notes.dump_release(yaml.safe_load(yaml.safe_dump(DOC))))
    return p


def _text(renderable) -> str:
    console = view.make_console(record=True, width=100, file=io.StringIO())
    console.print(renderable)
    return console.export_text()


def test_rows_put_breaking_first_then_new_then_fetchers():
    assert [k for k, _r in rr.rows(DOC)] == ["breaking", "new", "fetcher", "fetcher"]


def test_flags_name_what_still_needs_a_person():
    breaking, new, todo, cut = (r for _k, r in rr.rows(DOC))
    assert rr.flags("fetcher", todo) == ["draft", "todo"]
    assert rr.flags("fetcher", cut) == ["draft", "cut"]
    assert rr.flags("fetcher", {"name": "x", "note": "y" * 111}) == ["long"]
    assert rr.flags("new", {"tag": "cli", "title": "fine"}) == []


def test_preview_draws_rows_the_way_update_does():
    k, breaking = rr.rows(DOC)[0]
    out = _text(rr.preview(k, breaking, "0.7.0-beta", "2026-11-24", {}))
    assert "Breaking" in out and "Inventory records must carry asset_type" in out
    assert "fix: Set asset_type on every record" in out and "your own fetchers · 0.7.0-beta" in out

    k, new = rr.rows(DOC)[1]
    out = _text(rr.preview(k, new, "0.7.0-beta", "2026-11-24", {}))
    assert "0.7.0-beta · Nov 24" in out and "+ Shell tab completion" in out and "paramify --install-completion" in out

    k, line = rr.rows(DOC)[3]
    out = _text(rr.preview(k, line, "0.7.0-beta", None, {"aws_ecr_image_scanning": "0.4.0"}))
    assert "aws_ecr_image_scanning" in out and "0.4.0 → 0.5.0" in out
    assert "0.7.0-beta  Counts every image in scope…" in out and "TUI table:" in out


def test_problems_list_marks_todos_and_schema_errors():
    doc = yaml.safe_load(yaml.safe_dump(DOC))
    left = rr.problems(doc, None)
    assert "4 rows still have draft: true" in left and "1 notes still start with TODO" in left
    for _k, r in rr.rows(doc):
        r.pop("draft")
    doc["fetchers"][0]["note"] = "Records each config item"
    assert rr.problems(doc, None) == []
    doc["highlights"][0]["title"] = "x" * 80
    assert any(p.startswith("schema: highlights/0/title") for p in rr.problems(doc, None))


def test_default_file_is_the_one_release_file_with_draft_marks(tmp_path):
    (tmp_path / "releases").mkdir()
    (tmp_path / "releases" / "unreleased.yaml").write_text("version: unreleased\nhighlights: []\n")
    (tmp_path / "releases" / "0.6.0-beta.yaml").write_text("version: 0.6.0-beta\nhighlights: []\n")
    assert rr.default_file(tmp_path) is None
    _write(tmp_path / "releases")
    assert rr.default_file(tmp_path).name == "0.7.0-beta.yaml"


def test_edit_review_delete_and_save(tmp_path):
    path = _write(tmp_path)

    async def run():
        app = rr.ReleaseReview(path, facts=None)
        async with app.run_test(size=(160, 50)) as pilot:
            assert app.current[0] == "breaking"          # opens on the first row that needs you
            await pilot.press("ctrl+r")                    # breaking row reviewed, moves on
            assert app.current[1]["title"] == "Shell tab completion"
            await pilot.press("ctrl+d")                    # highlight rows can be deleted
            assert all(r.get("title") != "Shell tab completion" for r in app.doc["highlights"])
            assert app.current[0] == "fetcher"
            await pilot.press("ctrl+d")                    # fetcher lines can't
            assert len(app.doc["fetchers"]) == 2
            app.query_one("#field0").value = "Records each AWS Config item"
            await pilot.pause()
            assert "Records each AWS Config item" in _text(app.query_one("#preview").content)
            await pilot.press("ctrl+r")
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert not app.unsaved
            status = _text(app.query_one("#status").content)
            assert "1 rows still have draft: true" in status

    asyncio.run(run())
    saved = yaml.safe_load(path.read_text())
    assert [r["title"] for r in saved["highlights"]] == ["Inventory records must carry asset_type"]
    assert "draft" not in saved["highlights"][0]
    first, second = saved["fetchers"]
    assert first == {"name": "aws_config_inventory", "version": "0.1.0", "note": "Records each AWS Config item"}
    assert second.get("draft") is True
    assert path.read_text().startswith("# What `paramify update` shows")


def test_quit_with_unsaved_changes_asks_once(tmp_path):
    path = _write(tmp_path)
    before = path.read_text()

    async def run():
        app = rr.ReleaseReview(path, facts=None)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.press("ctrl+r")
            await pilot.press("escape")
            app.query_one("#rows").focus()
            await pilot.press("q")
            assert app.is_running
            await pilot.press("q")
            await pilot.pause()

    asyncio.run(run())
    assert path.read_text() == before


def test_checks_use_the_repo_that_holds_the_file(tmp_path, monkeypatch):
    import subprocess
    repo = tmp_path / "other"
    (repo / "releases").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    path = _write(repo / "releases")
    assert rr.repo_of(path) == repo.resolve()
    assert rr.repo_of(tmp_path / "nowhere.yaml") == rr.REPO_ROOT
