"""Beta fetchers: `status: beta` in fetcher.yaml, and the BETA label that
`paramify describe` and the TUI put on such a fetcher wherever it is named.

The registry has no beta fetcher on main yet, so these tests mark demo_hello as
one by wrapping fetcher discovery, the same way the community tests do.
"""

from __future__ import annotations

import dataclasses

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from framework import api
from framework.cli import app
from framework.config_loader import _parse_fetcher, discover_fetchers

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from framework.tui import palette  # noqa: E402
from framework.tui.components.table import DataTable  # noqa: E402
from tests.test_tui_community_fetchers import (  # noqa: E402
    REPO_ROOT,
    SCHEMA,
    _catalog_cursor_on,
    _detail,
    _manifest,
    _text,
    _yaml,
)


def test_status_defaults_to_stable_and_reads_beta():
    here = REPO_ROOT / "fetchers" / "demo" / "x"
    assert _parse_fetcher(_yaml(), here).status == "stable"
    assert _parse_fetcher(_yaml(status="beta"), here).status == "beta"


def test_schema_takes_stable_or_beta_only():
    v = Draft202012Validator(SCHEMA)
    assert not list(v.iter_errors(_yaml(status="beta")))
    assert not list(v.iter_errors(_yaml(status="stable")))
    assert list(v.iter_errors(_yaml(status="alpha")))


def test_catalog_carries_the_status():
    cat = api.catalog(REPO_ROOT)
    statuses = {f["status"] for c in cat["categories"] for f in c["fetchers"]}
    assert "stable" in statuses
    assert statuses <= {"stable", "beta"}


@pytest.fixture
def demo_hello_as(monkeypatch):
    """Rewrite demo_hello's descriptor fields (status, source) as discovery returns it."""
    def mark(**fields):
        def discover(root):
            found = discover_fetchers(root)
            found["demo_hello"] = dataclasses.replace(found["demo_hello"], **fields)
            return found
        monkeypatch.setattr(api, "discover_fetchers", discover)
    return mark


def test_describe_marks_a_beta_fetcher(demo_hello_as, monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    runner = CliRunner()
    assert "[beta]" not in runner.invoke(app, ["describe", "demo_hello"]).output
    demo_hello_as(status="beta")
    out = runner.invoke(app, ["describe", "demo_hello"])
    assert out.exit_code == 0, out.output
    assert "[beta]" in out.output.splitlines()[0]


def test_tags_follow_the_name_community_then_beta():
    assert palette.fetcher_tags(None).plain == ""
    assert palette.fetcher_tags({"status": "stable"}).plain == ""
    assert palette.fetcher_tags({"status": "beta"}).plain == "   BETA "
    both = palette.fetcher_tags({"source": "community", "status": "beta"}).plain
    assert both.split() == ["COMMUNITY", "BETA"]


def test_fetchers_tab_labels_a_beta_fetcher(tmp_path, demo_hello_as, run_tui):
    demo_hello_as(status="beta")
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
    assert seen["leaf"].split() == ["[x]", "demo_hello", "BETA"]
    assert "BETA" in seen["catalog_detail"] and palette.BETA_NOTE in seen["catalog_detail"]
    assert "BETA" in seen["row"]
    assert "BETA" in seen["entry_detail"] and palette.BETA_NOTE in seen["entry_detail"]
    assert palette.COMMUNITY_NOTE not in seen["catalog_detail"] + seen["entry_detail"]


def test_a_stable_fetcher_has_no_beta_label(tmp_path, run_tui):
    seen = {}

    async def body(app, pilot):
        seen["leaf"] = await _catalog_cursor_on(app, pilot, "demo_hello")
        await pilot.pause()
        seen["detail"] = _detail(app)

    run_tui(body, _manifest(tmp_path))
    assert "BETA" not in seen["leaf"] + seen["detail"]
    assert palette.BETA_NOTE not in seen["detail"]
