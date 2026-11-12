"""TUI: pipeline fetchers on the Manifest tab (sends-to cell, entry form, preset sheet)
and the upload log's "waiting for approval" line."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402

from framework import api  # noqa: E402
from framework.tui import palette  # noqa: E402
from framework.tui.modals import FormModal, PreviewModal  # noqa: E402
from framework.tui.render import destination_cell  # noqa: E402
from framework.tui.screens.upload import pipeline_wait_lines  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
PIPELINE = "sophos_endpoint_inventory"


def _text(widget) -> str:
    rendered = widget.render()
    return getattr(rendered, "plain", str(rendered)).strip()


def _manifest(tmp_path: Path, name: str) -> Path:
    manifest = api.init_manifest()
    api.set_output_dir(manifest, str(tmp_path / "evidence"))
    api.add_entry(manifest, name)
    path = tmp_path / "pipeline-entries.yaml"
    api.dump_manifest(manifest, path, REPO_ROOT)
    return path


def _plain_evidence_name() -> str:
    d = api.catalog(REPO_ROOT)
    return next(f["name"] for c in d["categories"] for f in c["fetchers"]
                if not f.get("pipeline") and (f.get("kind") or "evidence") == "evidence" and f.get("evidence_set"))


def test_destination_cell_marks_a_pipeline_set():
    d = {"kind": "inventory", "evidence_set": {"reference_id": "EVD-X"},
         "pipeline": {"type": "inventory", "id_scheme": "x"}}
    assert destination_cell(d, None).plain.endswith(" · pipeline")
    assert destination_cell({"evidence_set": {"reference_id": "EVD-X"}}, None).plain == "EVD-X"


def test_entry_form_hides_direct_settings_for_a_pipeline_entry(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        return {s["key"]: s for s in app.screen._groups["paramify"]}

    specs = run_tui(body, _manifest(tmp_path, PIPELINE))
    assert set(specs) == {"stack", "approval"}
    assert specs["approval"]["help"] == "pipeline files always go in a batch; MANUAL waits for a person"


def test_entry_form_keeps_direct_settings_for_ordinary_evidence(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        return {s["key"] for s in app.screen._groups["paramify"]}

    keys = run_tui(body, _manifest(tmp_path, _plain_evidence_name()))
    assert keys == {"stack", "approval", "no_request", "delivery"}


def test_detail_pane_names_the_pipeline(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        console = Console(file=io.StringIO(), width=160, color_system=None)
        console.print(app.screen.query_one("#manifest-detail").content)
        return console.file.getvalue()

    assert "pipeline: inventory · " in run_tui(body, _manifest(tmp_path, PIPELINE))


def test_P_opens_the_preset_sheet(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("P")
        await pilot.pause()
        assert isinstance(app.screen, PreviewModal)
        title = _text(app.screen.query_one("#modal-title"))
        shown = _text(app.screen.query_one("#preview-text"))
        await pilot.press("P")
        await pilot.pause()
        return title, shown, isinstance(app.screen, PreviewModal)

    title, shown, still_open = run_tui(body, _manifest(tmp_path, PIPELINE))
    assert title == f"preset: {PIPELINE}"
    assert "payload.data" in shown
    assert not still_open


def test_P_on_an_evidence_row_notifies_instead(tmp_path, run_tui):
    name = _plain_evidence_name()

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("P")
        await pilot.pause()
        return isinstance(app.screen, PreviewModal), [str(n.message) for n in app._notifications]

    modal, messages = run_tui(body, _manifest(tmp_path, name))
    assert not modal
    assert f"{name} is not a pipeline fetcher" in messages


def test_only_an_unapproved_pipeline_entry_gets_a_warning_line():
    entries = {
        "a": {"pipeline": {"type": "inventory", "approved": False}, "batch_reference": "B-1"},
        "b": {"pipeline": {"type": "inventory", "approved": None}},  # direct: not a warning
        "c": {"pipeline": {"type": "inventory", "approved": True}},
        "d": {},
    }
    [line] = pipeline_wait_lines(entries)
    assert "waiting for approval" in line.plain and "a" in line.plain and "B-1" in line.plain
    assert line.style == palette.WARN
