"""Community-made fetchers: `source: community` in fetcher.yaml, and the COMMUNITY
label the TUI puts on such a fetcher wherever it is named.

The registry has no community fetcher yet, so the TUI tests mark demo_hello as
one by wrapping fetcher discovery.
"""

from __future__ import annotations

import dataclasses
import io
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.widgets import Input, Static, Tree  # noqa: E402

from framework import api  # noqa: E402
from framework.config_loader import _parse_fetcher, discover_fetchers  # noqa: E402
from framework.tui import palette  # noqa: E402
from framework.tui.components.table import DataTable  # noqa: E402
from framework.tui.screens import validators as validators_page  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((REPO_ROOT / "framework/schemas/fetcher_schema.json").read_text())


def _yaml(**extra) -> dict:
    return {"name": "x_demo", "version": "0.1.0", "description": "d", "category": "demo",
            "runtime": {"type": "python", "entry": "fetcher.py"},
            "output": {"type": "json", "path": "x.json"}, "secrets": [],
            "evidence_set": {"reference_id": "EVD-X", "name": "X"}, **extra}


def test_source_defaults_to_paramify_and_reads_community():
    here = REPO_ROOT / "fetchers" / "demo" / "x"
    assert _parse_fetcher(_yaml(), here).source == "paramify"
    assert _parse_fetcher(_yaml(source="community"), here).source == "community"


def test_schema_takes_paramify_or_community_only():
    v = Draft202012Validator(SCHEMA)
    assert not list(v.iter_errors(_yaml(source="community")))
    assert list(v.iter_errors(_yaml(source="vendor")))


def test_catalog_carries_the_source():
    cat = api.catalog(REPO_ROOT)
    sources = {f["source"] for c in cat["categories"] for f in c["fetchers"]}
    assert "paramify" in sources
    assert sources <= {"paramify", "community"}


# --- the TUI ------------------------------------------------------------------


@pytest.fixture
def demo_hello_is_community(monkeypatch):
    def discover(root):
        found = discover_fetchers(root)
        found["demo_hello"] = dataclasses.replace(found["demo_hello"], source="community")
        return found

    monkeypatch.setattr(api, "discover_fetchers", discover)
    monkeypatch.setattr(validators_page, "discover_fetchers", discover)


def _manifest(tmp_path: Path) -> Path:
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, "demo_hello")
    path = tmp_path / "community.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path


def _text(renderable) -> str:
    console = Console(file=io.StringIO(), width=220, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


def _detail(app) -> str:
    return _text(app.screen.query_one("#fetchers-detail", Static).content)


async def _catalog_cursor_on(app, pilot, name: str) -> str:
    """Filter the catalog to one fetcher, put the cursor on it, return its label."""
    await pilot.press("1")
    await pilot.pause()
    app.screen.query_one("#catalog-search", Input).value = name
    await pilot.pause()
    tree = app.screen.query_one("#catalog-tree", Tree)
    tree.focus()
    await pilot.pause()
    for _ in range(12):
        node = tree.cursor_node
        if node is not None and isinstance(node.data, dict) and node.data["name"] == name:
            return str(node.label)
        await pilot.press("down")
        await pilot.pause()
    raise AssertionError(f"{name} is not reachable in the filtered catalog")


def test_fetchers_tab_labels_a_community_fetcher(tmp_path, demo_hello_is_community, run_tui):
    seen = {}

    async def body(app, pilot):
        seen["leaf"] = await _catalog_cursor_on(app, pilot, "demo_hello")
        await pilot.pause()
        seen["catalog_detail"] = _detail(app)
        table = app.screen.query_one("#manifest-entries", DataTable)
        seen["row"] = _text(table.get_row_at(0)[0])
        table.focus()
        await pilot.pause()
        seen["entry_detail"] = _detail(app)

    run_tui(body, _manifest(tmp_path))
    assert seen["leaf"].split() == ["[x]", "demo_hello", "COMMUNITY"]
    assert "COMMUNITY" in seen["catalog_detail"] and palette.COMMUNITY_NOTE in seen["catalog_detail"]
    assert "COMMUNITY" in seen["row"]
    assert "COMMUNITY" in seen["entry_detail"] and palette.COMMUNITY_NOTE in seen["entry_detail"]


def test_a_paramify_fetcher_has_no_label(tmp_path, run_tui):
    seen = {}

    async def body(app, pilot):
        seen["leaf"] = await _catalog_cursor_on(app, pilot, "demo_hello")
        await pilot.pause()
        seen["detail"] = _detail(app)

    run_tui(body, _manifest(tmp_path))
    assert "COMMUNITY" not in seen["leaf"] + seen["detail"]
    assert palette.COMMUNITY_NOTE not in seen["detail"]


def test_validators_tab_labels_a_community_fetcher(tmp_path, demo_hello_is_community, run_tui):
    async def body(app, pilot):
        await pilot.press("4")
        await pilot.pause()
        row = app.screen.query_one("#vs-fetchers", DataTable).get_row_at(0)
        return _text(row[-1]), str(app.screen.query_one("#vs-right").border_title)

    name, title = run_tui(body, _manifest(tmp_path))
    assert "demo_hello" in name and "COMMUNITY" in name
    assert "community fetcher" in title
