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
FILE = "sophos_endpoint_inventory.json"


def _run(out: Path, stamp: str, by_type=None, *, with_file=True) -> Path:
    run = out / f"run-{stamp}"
    run.mkdir(parents=True)
    if with_file:
        env = {"schema_version": "1.0", "metadata": {"inventory": {"by_asset_type": by_type or {}}}, "payload": {"data": []}}
        (run / FILE).write_text(json.dumps(env))
    return run


def test_sheet_for_an_inventory_with_a_run(tmp_path):
    _run(tmp_path, "2026-11-12T00-00-00Z", {"endpoint": 412, "server": 37})
    s = api.preset_sheet(REPO_ROOT, "sophos_endpoint_inventory", output_dir=tmp_path)
    assert s["data_path"] == "payload.data" and s["unique_id"] == "unique_asset_identifier"
    assert s["id_scheme"] == "sophos-endpoint-id" and s["asset_types"] == {"endpoint": 412, "server": 37}
    assert s["sample"].endswith("sophos_endpoint_inventory.json")
    text = api.render_preset_sheet(s)
    assert "attach it to this set, not a new one" in text and "endpoint 412 · server 37" in text
    assert "none in the catalog use sophos-endpoint-id" in text


def test_sheet_without_a_run_says_what_needs_one(tmp_path):
    s = api.preset_sheet(REPO_ROOT, "sophos_endpoint_inventory", output_dir=tmp_path)
    assert s["sample"] is None and s["asset_types"] is None
    assert "run the fetcher first" in api.render_preset_sheet(s)


def test_newest_run_with_skips_runs_without_the_file(tmp_path):
    older = _run(tmp_path, "2026-11-11T00-00-00Z")
    _run(tmp_path, "2026-11-12T00-00-00Z", with_file=False)
    assert api.newest_run_with(tmp_path, FILE) == older
    assert api.newest_run_with(tmp_path / "missing", FILE) is None


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
