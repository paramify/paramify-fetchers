"""The fanout target editor: api.set_target plus the TUI table that drives it.

A fanout fetcher runs once per target, so its targets are the run plan. Adding
and removing them existed; changing one did not, which made a typo'd account id
cost a full retype. These cover the mutator's replace semantics (including the
one thing a replace must not destroy — per-target secrets it never showed) and
the wiring that opens the editor's three row actions.

Everything runs in tmp_path; the manifest under test is built with the api, not
read from the working tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework import api

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import DataTable  # noqa: E402

from framework.tui.modals import ConfirmModal, FormModal, TargetsModal  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# api.set_target — replace, don't merge; never silently drop a secret
# --------------------------------------------------------------------------- #

def _manifest_with_targets():
    m = api.init_manifest()
    api.add_entry(m, "f")
    api.add_target(m, "f", {"account_id": "1111", "region": "us-east-1"})
    api.add_target(m, "f", {"account_id": "2222", "region": "us-west-2"},
                   secret_env={"api_token": "TOKEN_B"})
    return m


def test_set_target_replaces_the_target_at_the_index():
    m = _manifest_with_targets()
    api.set_target(m, "f", 0, {"account_id": "9999", "region": "eu-west-1"})
    targets = m["run"]["fetchers"][0]["targets"]
    assert targets[0] == {"account_id": "9999", "region": "eu-west-1"}
    assert targets[1]["account_id"] == "2222"      # its neighbour is untouched


def test_a_cleared_field_is_actually_cleared():
    """Replace, not merge: a field the user emptied in the form has to go, or the
    editor could never unset an optional field."""
    m = _manifest_with_targets()
    api.set_target(m, "f", 0, {"account_id": "1111"})
    assert m["run"]["fetchers"][0]["targets"][0] == {"account_id": "1111"}


def test_secrets_survive_an_edit_that_did_not_touch_them():
    """The editor can show a target's values without showing its credentials, so
    a replace with no secret_env must preserve what was there — otherwise editing
    a region would silently unwire the target's token."""
    m = _manifest_with_targets()
    api.set_target(m, "f", 1, {"account_id": "2222", "region": "eu-central-1"})
    assert m["run"]["fetchers"][0]["targets"][1]["secrets"] == {"api_token": "${env:TOKEN_B}"}


def test_secrets_are_replaced_when_given():
    m = _manifest_with_targets()
    api.set_target(m, "f", 1, {"account_id": "2222"}, secret_env={"api_token": "TOKEN_C"})
    assert m["run"]["fetchers"][0]["targets"][1]["secrets"] == {"api_token": "${env:TOKEN_C}"}


def test_out_of_range_index_raises():
    m = _manifest_with_targets()
    with pytest.raises(IndexError):
        api.set_target(m, "f", 7, {"account_id": "x"})


def test_unknown_fetcher_raises_rather_than_creating_an_entry():
    """add_target creates the entry it appends to; set_target must not — an index
    into a fetcher that isn't in the manifest is a mistake, not a new entry."""
    m = api.init_manifest()
    with pytest.raises(IndexError):
        api.set_target(m, "nope", 0, {"account_id": "x"})


# --------------------------------------------------------------------------- #
# The TUI editor — one key opens the table, and each row action opens its screen
# --------------------------------------------------------------------------- #

def _fanout_manifest(tmp_path: Path):
    """A manifest holding one real fanout fetcher with two targets."""
    catalog = api.catalog(REPO_ROOT)
    fetcher = next(
        f
        for c in catalog["categories"] for f in c["fetchers"]
        if f.get("supports_targets") and f.get("target_schema")
    )
    name = fetcher["name"]
    fields = [t["name"] for t in fetcher["target_schema"]]

    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, name)
    api.add_target(m, name, {fields[0]: "first-value"})
    api.add_target(m, name, {fields[0]: "second-value"})
    path = tmp_path / "targets-test.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path, name, fields



async def _open_targets(app, pilot):
    await pilot.press("1")          # Fetchers tab
    await pilot.pause()
    await pilot.press("tab")  # from the catalog to the manifest list
    await pilot.pause()
    await pilot.press("t")
    await pilot.pause()


def test_t_opens_the_targets_table_with_a_row_per_target(tmp_path, run_tui):
    manifest, name, fields = _fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _open_targets(app, pilot)
        assert isinstance(app.screen, TargetsModal)
        table = app.screen.query_one("#targets-table", DataTable)
        rows = [table.get_row_at(i) for i in range(table.row_count)]
        return rows

    rows = run_tui(body, manifest)
    assert len(rows) == 2
    assert rows[0][0] == "0" and "first-value" in rows[0]
    assert rows[1][0] == "1" and "second-value" in rows[1]


def test_unset_fields_render_as_a_dash_not_an_empty_cell(tmp_path, run_tui):
    manifest, name, fields = _fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _open_targets(app, pilot)
        table = app.screen.query_one("#targets-table", DataTable)
        return list(table.get_row_at(0))

    row = run_tui(body, manifest)
    # every column is populated text; the columns this fetcher leaves unset show —
    assert "" not in row


def test_e_opens_the_edit_form_prefilled_for_the_highlighted_row(tmp_path, run_tui):
    manifest, name, fields = _fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _open_targets(app, pilot)
        await pilot.press("down")       # highlight target 1
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        inputs = [i.value for i in app.screen.query("Input")]
        return app.screen._title, inputs

    title, values = run_tui(body, manifest)
    assert "Edit target 1" in title
    assert "second-value" in values      # the row's own values, not the first row's


def test_x_asks_before_removing_and_names_the_target(tmp_path, run_tui):
    manifest, name, fields = _fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _open_targets(app, pilot)
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        return app.screen._message

    question = run_tui(body, manifest)
    assert "first-value" in question and "target 0" in question


def test_a_opens_the_add_form(tmp_path, run_tui):
    manifest, name, fields = _fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _open_targets(app, pilot)
        await pilot.press("a")
        await pilot.pause()
        return type(app.screen).__name__, app.screen._title

    kind, title = run_tui(body, manifest)
    assert kind == "FormModal" and "Add target" in title


def test_escape_closes_the_editor_back_to_the_page(tmp_path, run_tui):
    manifest, name, fields = _fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _open_targets(app, pilot)
        await pilot.press("escape")
        await pilot.pause()
        return type(app.screen).__name__

    # back to the workspace, with no modal left on the stack
    assert run_tui(body, manifest) == "WorkspaceScreen"


def test_the_entry_editor_says_where_targets_are_edited(tmp_path, run_tui):
    """`e` on the page edits the ENTRY, not a target. 104 of the 138 fanout
    fetchers declare no entry config, so that form is nothing but secrets —
    indistinguishable from the target editor failing to open unless the form
    itself says where targets live."""
    manifest, name, fields = _fanout_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        await pilot.press("tab")  # from the catalog to the manifest list
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        return app.screen._title, app.screen._subtitle

    title, subtitle = run_tui(body, manifest)
    assert "entry config and secrets" in title
    assert "'t'" in subtitle
    # short enough to survive the card width — a clipped subtitle takes the
    # pointer with it, which is the half that matters here
    assert len(subtitle) <= 66


# --------------------------------------------------------------------------- #
# Two entries that use the same fetcher: each action acts on the selected one
# --------------------------------------------------------------------------- #

def test_api_target_and_remove_helpers_take_an_entry_key():
    m = api.init_manifest()
    m["run"]["fetchers"] = [{"use": "f", "targets": [{"id": "a"}]}, {"use": "f", "targets": [{"id": "b"}]}]
    api.set_target(m, "f", 0, {"id": "b2"}, entry_key="f#1")
    api.add_target(m, "f", {"id": "c"}, entry_key="f#1")
    api.remove_target(m, "f", 0, entry_key="f#1")
    assert m["run"]["fetchers"] == [{"use": "f", "targets": [{"id": "a"}]}, {"use": "f", "targets": [{"id": "c"}]}]
    api.remove_entry(m, "f", entry_key="f#1")
    assert m["run"]["fetchers"] == [{"use": "f", "targets": [{"id": "a"}]}]
    api.remove_entry(m, "f")  # no key: every entry of the fetcher, as before
    assert m["run"]["fetchers"] == []


def _duplicate_fanout_manifest(tmp_path: Path):
    path, name, fields = _fanout_manifest(tmp_path)
    import yaml

    m = yaml.safe_load(path.read_text())
    m["run"]["fetchers"].append({"use": name, "targets": [{fields[0]: "other-entry"}]})
    path.write_text(yaml.safe_dump(m))
    return path, name, fields


async def _select_second_entry(app, pilot):
    await pilot.press("1")
    await pilot.pause()
    await pilot.press("tab")  # from the catalog to the manifest list
    await pilot.pause()
    await pilot.press("down")
    await pilot.pause()


def test_t_on_the_second_of_two_entries_edits_only_its_targets(tmp_path, run_tui):
    import yaml

    manifest, name, fields = _duplicate_fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _select_second_entry(app, pilot)
        await pilot.press("t")
        await pilot.pause()
        assert isinstance(app.screen, TargetsModal)
        table = app.screen.query_one("#targets-table", DataTable)
        rows = [list(table.get_row_at(i)) for i in range(table.row_count)]
        assert len(rows) == 1 and "other-entry" in rows[0]
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        for r in app.screen.query("FieldRow"):
            if r.spec["key"] == fields[0]:
                r.query_one("Input").value = "other-edited"
        await pilot.pause()
        await pilot.press("ctrl+s")
        await pilot.pause()

    run_tui(body, manifest)
    first, second = yaml.safe_load(manifest.read_text())["run"]["fetchers"]
    assert [t[fields[0]] for t in first["targets"]] == ["first-value", "second-value"]
    assert [t[fields[0]] for t in second["targets"]] == ["other-edited"]


def test_x_on_the_second_of_two_entries_removes_only_it(tmp_path, run_tui):
    import yaml

    manifest, name, fields = _duplicate_fanout_manifest(tmp_path)

    async def body(app, pilot):
        await _select_second_entry(app, pilot)
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        await pilot.pause()

    run_tui(body, manifest)
    [left] = yaml.safe_load(manifest.read_text())["run"]["fetchers"]
    assert [t[fields[0]] for t in left["targets"]] == ["first-value", "second-value"]
