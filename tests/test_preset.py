"""`paramify preset <fetcher>`: the settings to enter when building a pipeline's preset."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from framework import api
from framework.cli import app

REPO_ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()
NAME = "sophos_endpoint_inventory"


def _env(by_type=None, fetcher=NAME) -> dict:
    return {"schema_version": "1.0",
            "metadata": {"fetcher_name": fetcher, "inventory": {"by_asset_type": by_type or {}}},
            "payload": {"data": []}}


def _run(out: Path, stamp: str, files=None, *, metadata=True, fetcher=NAME) -> Path:
    """A run dir with `files` ({name: by_asset_type, or a str written as is}) and, by default,
    a _run_metadata.json whose invocation of `fetcher` names them as its outputs."""
    run = out / f"run-{stamp}"
    run.mkdir(parents=True)
    files = files or {}
    for name, body in files.items():
        (run / name).write_text(body if isinstance(body, str) else json.dumps(_env(body, fetcher)))
    if metadata:
        meta = {"run_id": stamp, "invocations": [
            {"fetcher_name": fetcher, "exit_code": 0, "outputs": sorted(files), "entry_key": fetcher}]}
        (run / "_run_metadata.json").write_text(json.dumps(meta))
    return run


def test_sheet_for_an_inventory_with_a_run(tmp_path):
    run = _run(tmp_path, "2026-11-12T00-00-00Z", {f"{NAME}_acme.json": {"endpoint": 412, "server": 37}})
    s = api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)
    assert s["data_path"] == "payload.data" and s["unique_id"] == "unique_asset_identifier"
    assert s["id_scheme"] == "sophos-endpoint-id" and s["asset_types"] == {"endpoint": 412, "server": 37}
    assert s["sample"] == str(run / f"{NAME}_acme.json") and s["problem"] is None
    text = api.render_preset_sheet(s)
    assert "attach it to this set, not a new one" in text and "endpoint 412 · server 37" in text
    assert "none in the catalog use sophos-endpoint-id" in text


def test_two_tenants_merge_their_counts_and_the_first_file_is_the_sample(tmp_path):
    run = _run(tmp_path, "2026-11-12T00-00-00Z", {
        f"{NAME}_beta.json": {"server": 40, "endpoint": 8},
        f"{NAME}_acme.json": {"endpoint": 32, "mobile": 40},
    })
    s = api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)
    assert s["sample"] == str(run / f"{NAME}_acme.json")
    # merged: endpoint 8 + 32; a tie in count orders by name
    assert list(s["asset_types"].items()) == [("endpoint", 40), ("mobile", 40), ("server", 40)]


def test_merged_counts_order_by_count_then_name(tmp_path):
    _run(tmp_path, "2026-11-12T00-00-00Z", {
        f"{NAME}_acme.json": {"server": 3, "endpoint": 10},
        f"{NAME}_beta.json": {"mobile": 3, "endpoint": 2},
    })
    s = api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)
    assert list(s["asset_types"].items()) == [("endpoint", 12), ("mobile", 3), ("server", 3)]


def test_a_run_without_metadata_is_found_by_file_name_and_envelope(tmp_path):
    run = _run(tmp_path, "2026-11-12T00-00-00Z", {f"{NAME}_acme.json": {"endpoint": 1}}, metadata=False)
    (run / f"{NAME}_other.json").write_text(json.dumps(_env({"x": 9}, fetcher="someone_else")))
    s = api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)
    assert s["sample"] == str(run / f"{NAME}_acme.json") and s["asset_types"] == {"endpoint": 1}


def test_runs_of_other_fetchers_are_skipped(tmp_path):
    older = _run(tmp_path, "2026-11-11T00-00-00Z", {f"{NAME}_acme.json": {"endpoint": 1}})
    _run(tmp_path, "2026-11-12T00-00-00Z", {"aws_x.json": {}}, fetcher="aws_x")
    assert api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)["sample"] == str(older / f"{NAME}_acme.json")


def test_a_ghost_run_is_skipped(tmp_path):
    older = _run(tmp_path, "2026-11-11T00-00-00Z", {f"{NAME}_acme.json": {"endpoint": 1}})
    (tmp_path / "run-2026-11-12T00-00-00Z").mkdir()  # an aborted run that wrote nothing
    assert api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)["sample"] == str(older / f"{NAME}_acme.json")


def test_an_unreadable_newest_file_says_so(tmp_path):
    _run(tmp_path, "2026-11-11T00-00-00Z", {f"{NAME}_acme.json": {"endpoint": 1}})
    run = _run(tmp_path, "2026-11-12T00-00-00Z", {f"{NAME}_acme.json": "{not json"})
    s = api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)
    path = run / f"{NAME}_acme.json"
    assert s["sample"] == str(path) and s["asset_types"] is None
    assert s["problem"] == f"could not read {path}"
    text = api.render_preset_sheet(s)
    assert f"could not read {path}" in text and "run the fetcher first" not in text


def test_sheet_without_a_run_says_what_needs_one(tmp_path):
    s = api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path)
    assert s["sample"] is None and s["asset_types"] is None
    assert "run the fetcher first" in api.render_preset_sheet(s)
    assert api.preset_sheet(REPO_ROOT, NAME, output_dir=tmp_path / "missing")["sample"] is None


def test_github_inventory_is_found_by_its_per_org_name(tmp_path):
    name = "github_repository_inventory"
    run = _run(tmp_path, "2026-11-12T00-00-00Z", {f"{name}_acme-org.json": {"repository": 5}}, fetcher=name)
    s = api.preset_sheet(REPO_ROOT, name, output_dir=tmp_path)
    assert s["sample"] == str(run / f"{name}_acme-org.json") and s["asset_types"] == {"repository": 5}


def test_non_pipeline_fetcher_is_refused():
    with pytest.raises(ValueError, match="not a pipeline fetcher"):
        api.preset_sheet(REPO_ROOT, "aws_acm_certificate_status")


def test_unknown_fetcher_is_a_key_error():
    with pytest.raises(KeyError):
        api.preset_sheet(REPO_ROOT, "no_such_fetcher")


def test_cli_preset_json(tmp_path):
    r = runner.invoke(app, ["preset", "sophos_endpoint_inventory", "--json", "--output-dir", str(tmp_path)])
    assert r.exit_code == 0 and json.loads(r.stdout)["id_scheme"] == "sophos-endpoint-id"


def test_cli_preset_text(tmp_path):
    r = runner.invoke(app, ["preset", "sophos_endpoint_inventory", "--output-dir", str(tmp_path)])
    assert r.exit_code == 0 and "payload.data" in r.stdout


def test_cli_unknown_fetcher_suggests_close_names(tmp_path):
    r = runner.invoke(app, ["preset", "sophos_endpoint_inventry", "--output-dir", str(tmp_path)])
    assert r.exit_code == 2 and "sophos_endpoint_inventory" in r.output


def test_cli_non_pipeline_fetcher_exits_1():
    r = runner.invoke(app, ["preset", "aws_acm_certificate_status"])
    assert r.exit_code == 1 and "not a pipeline fetcher" in r.output
