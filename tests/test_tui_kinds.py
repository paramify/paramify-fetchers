"""The console keeps evidence and scan reports apart wherever it lists fetchers.

A platform can ship both kinds (wiz does), and the kind — not the platform —
decides where a fetcher's output goes. These tests stage a temp repo root with
one platform holding one of each, because the repo itself has no scan-report
fetcher on main to test against, and lock in that:

  * the catalog and the add picker group by kind first, platform second
  * every view of a fetcher says its kind and where its output goes
  * the manifest table says where each entry sends, and flags a scan report
    that has no assessment yet
  * the console calls the second kind "scan reports"

Written sync (asyncio.run per test) so the suite needs no async pytest plugin.
"""

from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.widgets import DataTable, Static, Tree  # noqa: E402

from framework import api  # noqa: E402
from framework.issue_reports import (  # noqa: E402
    ASSESSMENT_ID_FIELD,
    ASSESSMENT_NAME_FIELD,
    CLOSE_CYCLE_FIELD,
)
from framework.tui import kinds  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import MultiPickerModal  # noqa: E402
from framework.tui.screens.manifest import ManifestPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SIZE = (200, 50)

EVIDENCE = "acme_settings"
SCAN = "acme_findings"
OTHER = "zeta_policy"


def _stage_root(root: Path) -> Path:
    """A repo root whose `acme` platform ships one fetcher of each kind, plus a
    second platform with evidence only."""
    schemas = root / "framework" / "schemas"
    schemas.mkdir(parents=True)
    for src in (REPO_ROOT / "framework" / "schemas").glob("*.json"):
        (schemas / src.name).write_bytes(src.read_bytes())

    def fetcher(category: str, short: str, body: str) -> None:
        fdir = root / "fetchers" / category / short
        fdir.mkdir(parents=True)
        (fdir / "fetcher.yaml").write_text(body)
        (fdir / "fetcher.py").write_text("")

    common = "version: 0.1.0\nruntime:\n  type: python\n  entry: fetcher.py\nsecrets: []\n"
    fetcher("acme", "settings", (
        f"name: {EVIDENCE}\ndescription: acme tenant settings\ncategory: acme\n{common}"
        "output:\n  type: json\n  path: settings.json\n"
        "evidence_set:\n  reference_id: EVD-ACME-SETTINGS\n  name: Acme settings\n"
    ))
    fetcher("acme", "findings", (
        f"name: {SCAN}\ndescription: acme vulnerability export\ncategory: acme\n{common}"
        "kind: issue_report\n"
        "output:\n  type: csv\n  path: findings.csv\n"
        "issue_report:\n  assessment_type: VULNERABILITY\n  title: Acme findings\n"
    ))
    fetcher("zeta", "policy", (
        f"name: {OTHER}\ndescription: zeta policy\ncategory: zeta\n{common}"
        "output:\n  type: json\n  path: policy.json\n"
        "evidence_set:\n  reference_id: EVD-ZETA-POLICY\n  name: Zeta policy\n"
    ))
    return root


def _manifest(root: Path, entries: list, config: dict | None = None) -> Path:
    manifest = api.init_manifest()
    api.set_output_dir(manifest, str(root / "evidence"))
    for name in entries:
        api.add_entry(manifest, name)
    for field, value in (config or {}).items():
        api.set_fetcher_config(manifest, SCAN, field, value)
    path = root / "kinds-test.yaml"
    api.dump_manifest(manifest, path, root)
    return path


def _run(coro_fn, root: Path, manifest: Path):
    async def main():
        app = FetcherApp(manifest_path=str(manifest), root_override=str(root))
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            return await coro_fn(app, pilot)

    return asyncio.run(main())


def _plain(renderable) -> str:
    console = Console(file=io.StringIO(), width=160, color_system=None)
    console.print(renderable)
    return console.file.getvalue()


def _label(node) -> str:
    return getattr(node.label, "plain", str(node.label))


def _cell(value) -> str:
    return getattr(value, "plain", str(value))


# --------------------------------------------------------------------------- #
# grouping
# --------------------------------------------------------------------------- #

def test_sections_put_a_two_kind_platform_under_both_headings(tmp_path):
    root = _stage_root(tmp_path)
    got = [
        (kind, [(cat, [f["name"] for f in fs]) for cat, fs in groups])
        for kind, groups in kinds.sections(api.catalog(root))
    ]
    assert got == [
        (kinds.EVIDENCE, [("acme", [EVIDENCE]), ("zeta", [OTHER])]),
        (kinds.SCAN_REPORT, [("acme", [SCAN])]),
    ]


def test_sections_drop_what_the_filter_empties(tmp_path):
    root = _stage_root(tmp_path)
    only_zeta = kinds.sections(api.catalog(root), keep=lambda f: f["category"] == "zeta")
    assert [k for k, _ in only_zeta] == [kinds.EVIDENCE], "an empty kind was kept"
    assert [c for c, _ in only_zeta[0][1]] == ["zeta"], "an empty category was kept"


def test_descriptors_say_where_the_output_goes(tmp_path):
    root = _stage_root(tmp_path)
    by_name = {f["name"]: f for c in api.catalog(root)["categories"] for f in c["fetchers"]}
    assert by_name[EVIDENCE]["evidence_set"]["reference_id"] == "EVD-ACME-SETTINGS"
    assert "issue_report" not in by_name[EVIDENCE]
    assert by_name[SCAN]["issue_report"]["format"] == "csv"
    assert "evidence_set" not in by_name[SCAN]


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #

def test_catalog_tree_is_kind_then_platform(tmp_path):
    root = _stage_root(tmp_path)

    async def body(app, pilot):
        tree = app.screen.query_one("#catalog-tree", Tree)
        return [
            (_label(k), [(_label(c), [_label(f) for f in c.children]) for c in k.children])
            for k in tree.root.children
        ]

    assert _run(body, root, _manifest(root, [EVIDENCE])) == [
        ("Evidence  (2)", [("acme  (1)", [EVIDENCE]), ("zeta  (1)", [OTHER])]),
        ("Scan reports  (1)", [("acme  (1)", [SCAN])]),
    ]


def test_catalog_detail_says_kind_and_destination(tmp_path):
    root = _stage_root(tmp_path)

    async def body(app, pilot):
        page = app.screen.query_one("#catalog-left").parent
        tree = page.query_one("#catalog-tree", Tree)
        detail = page.query_one("#catalog-detail", Static)
        shown = {}
        for kind_node in tree.root.children:
            page._show(kind_node.data)
            shown[_label(kind_node)] = _plain(detail.content)
            for cat in kind_node.children:
                for leaf in cat.children:
                    page._show(leaf.data)
                    shown[_label(leaf)] = _plain(detail.content)
        return shown

    shown = _run(body, root, _manifest(root, [EVIDENCE]))
    assert "kind: scan report" in shown[SCAN]
    assert "a vulnerability assessment, chosen per manifest" in shown[SCAN]
    assert "csv" in shown[SCAN] and "never enveloped" in shown[SCAN]
    assert "kind: evidence" in shown[EVIDENCE]
    assert "EVD-ACME-SETTINGS — Acme settings" in shown[EVIDENCE]
    assert "assessment's pipeline" in shown["Scan reports  (1)"]
    assert "evidence set" in shown["Evidence  (2)"]


# --------------------------------------------------------------------------- #
# add picker
# --------------------------------------------------------------------------- #

def test_add_picker_groups_by_kind_and_lists_picks_under_their_kind(tmp_path):
    root = _stage_root(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, MultiPickerModal)
        tree = app.screen.query_one("#multi-pick-tree", Tree)
        headings = [_label(n) for n in tree.root.children]
        # EVIDENCE is already in the manifest, so acme's evidence is "all added".
        under_scan = [_label(c) for c in tree.root.children[1].children]
        await pilot.press(*"findings", "enter")
        await pilot.pause()
        chosen = _plain(app.screen.query_one("#multi-pick-chosen", Static).content)
        return headings, under_scan, sorted(app.screen._chosen), chosen

    headings, under_scan, picked, chosen = _run(body, root, _manifest(root, [EVIDENCE]))
    assert headings == ["Evidence  (1)", "Scan reports  (1)"]
    assert under_scan == ["acme  (1)"]
    assert picked == [SCAN], "enter in the filter did not pick the lone match"
    assert chosen.splitlines()[0] == "Scan reports"


# --------------------------------------------------------------------------- #
# manifest table
# --------------------------------------------------------------------------- #

def _rows(app) -> dict:
    dt = app.screen.query_one("#manifest-entries", DataTable)
    cols = [_cell(c.label) for c in dt.columns.values()]
    return {
        key.value: dict(zip(cols, (_cell(v) for v in dt.get_row(key))))
        for key in dt.rows
    }


def test_manifest_table_says_kind_and_flags_a_scan_report_with_no_assessment(tmp_path):
    root = _stage_root(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        return _rows(app)

    rows = _run(body, root, _manifest(root, [EVIDENCE, SCAN]))
    assert rows[EVIDENCE]["kind"] == "evidence"
    assert rows[EVIDENCE]["sends to"] == "EVD-ACME-SETTINGS"
    assert rows[SCAN]["kind"] == "scan report"
    assert rows[SCAN]["sends to"] == "no assessment — press A"
    assert "mode" not in rows[SCAN]


def test_manifest_table_shows_the_assessment_and_close_policy(tmp_path):
    root = _stage_root(tmp_path)
    config = {
        ASSESSMENT_ID_FIELD: "11111111-1111-1111-1111-111111111111",
        ASSESSMENT_NAME_FIELD: "Acme Vulns",
        CLOSE_CYCLE_FIELD: "after_run",
    }

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        page = app.screen.query_one(ManifestPage)
        page._selected = SCAN
        page._refresh_detail()
        detail = _plain(app.screen.query_one("#manifest-detail", Static).content)
        return _rows(app), detail

    rows, detail = _run(body, root, _manifest(root, [SCAN], config))
    assert rows[SCAN]["sends to"] == "Acme Vulns · after_run"
    assert any("assessment" in line and "Acme Vulns" in line for line in detail.splitlines())
    assert "after each complete run" in detail


def test_a_on_evidence_explains_where_evidence_goes(tmp_path):
    root = _stage_root(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("A")
        await pilot.pause()
        return [str(n.message) for n in app._notifications]

    messages = _run(body, root, _manifest(root, [EVIDENCE]))
    assert any("Only scan reports go to an assessment" in m for m in messages), messages
