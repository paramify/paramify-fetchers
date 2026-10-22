"""`kind: inventory`: the contract, the runner's verdict, and the uploader's refusal.

An inventory pipeline reads the uploaded file as the whole estate, so the
property that matters is end to end: a run that did not collect every asset
must never be sent. These tests stage a real fetcher, run it through the
runner, and hand the run directory to the real uploader in dry-run mode.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from framework import api, inventory
from framework.config_loader import discover_fetchers

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = REPO_ROOT / "framework" / "schemas"

_spec = importlib.util.spec_from_file_location(
    "inventory_uploader_under_test", REPO_ROOT / "uploaders" / "paramify_evidence" / "uploader.py"
)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)


def _records(n: int) -> list:
    return [{"unique_asset_identifier": f"arn:aws:ec2:us-east-2:1:instance/i-{i}", "name": f"vm{i}"}
            for i in range(n)]


def _payload(records=None, included=True, **extra) -> dict:
    records = _records(2) if records is None else records
    return {"data": records if included else [], "records_included": included,
            "record_count": len(records), **extra}


# --------------------------------------------------------------------------- #
# fetcher.yaml schema
# --------------------------------------------------------------------------- #

def _doc(**overrides) -> dict:
    doc = {
        "name": "x_inventory", "version": "0.1.0", "description": "d", "kind": "inventory",
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "json", "path": "x.json"},
        "secrets": [],
        "evidence_set": {"reference_id": "EVD-X-INVENTORY", "name": "X"},
    }
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not None}


def _schema_errors(doc: dict) -> list:
    return list(Draft202012Validator(json.loads((SCHEMAS / "fetcher_schema.json").read_text()))
                .iter_errors(doc))


def test_schema_accepts_an_inventory():
    assert not _schema_errors(_doc())


def test_schema_requires_an_evidence_set_on_an_inventory():
    """Without one there is nowhere for an inventory pipeline to read it from."""
    assert _schema_errors(_doc(evidence_set=None))


def test_schema_requires_json_output_on_an_inventory():
    assert _schema_errors(_doc(output={"type": "csv", "path": "x.csv"}))


def test_schema_refuses_an_issue_report_block_on_an_inventory():
    assert _schema_errors(_doc(issue_report={"assessment_type": "VULNERABILITY"}))


# --------------------------------------------------------------------------- #
# The payload verdict
# --------------------------------------------------------------------------- #

def test_a_clean_run_is_complete():
    block = inventory.check(_payload(), 0)
    assert block == {"records": 2, "records_included": True, "complete": True}


def test_a_failed_run_is_never_complete_even_with_records():
    """A fetcher that exits non-zero but forgot to withhold its records still
    has a partial estate in the file; the exit code alone rules it out."""
    block = inventory.check(_payload(), 1)
    assert block["complete"] is False
    assert block["incomplete_because"] == ["the fetcher exited 1"]


def test_withheld_records_are_not_complete():
    block = inventory.check(_payload(included=False), 0)
    assert block["complete"] is False
    assert "withheld" in block["incomplete_because"][0]


def test_an_empty_inventory_is_not_complete():
    block = inventory.check(_payload(records=[]), 0)
    assert block["complete"] is False
    assert block["incomplete_because"] == ["it holds no records"]


@pytest.mark.parametrize("payload, needle", [
    ({"records_included": True}, "'data' is a required property"),
    ({"data": [], "records_included": "yes"}, "is not of type 'boolean'"),
    (_payload(records=[{"name": "no id"}]), "'unique_asset_identifier' is a required property"),
    (_payload(records=[{"unique_asset_identifier": ""}]), "payload.data[0].unique_asset_identifier"),
    ({"data": _records(1), "records_included": False}, "payload.data"),
    (_payload(records=_records(1) * 2), "repeat a unique_asset_identifier"),
])
def test_contract_breaks_are_named(payload, needle):
    block = inventory.check(payload, 0)
    assert block["complete"] is False
    assert block["incomplete_because"] == ["the payload breaks the inventory contract"]
    assert any(needle in p for p in block["problems"]), block["problems"]


def test_a_systematic_break_is_summarised_not_listed_per_record():
    block = inventory.check(_payload(records=[{"name": str(i)} for i in range(500)]), 0)
    assert len(block["problems"]) == 6
    assert block["problems"][-1] == "... and 495 more"


def test_a_failed_runs_error_body_is_not_a_second_finding():
    """A fault usually leaves an error body without the inventory shape. The
    reason is the exit code; the shape problems are recorded but not repeated
    as a reason."""
    block = inventory.check({"status": "error", "message": "boom"}, 1)
    assert block["incomplete_because"] == ["the fetcher exited 1"]
    assert block["problems"]


# --------------------------------------------------------------------------- #
# Runner → envelope → uploader
# --------------------------------------------------------------------------- #

def _stage(root: Path, payload: dict, exit_code: int = 0, kind: str = "inventory") -> None:
    fdir = root / "fetchers" / "testcat" / "inventory"
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "fetcher.yaml").write_text(
        "name: t_inventory\nversion: 0.1.0\ndescription: d\ncategory: testcat\n"
        f"kind: {kind}\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        "output:\n  type: json\n  path: t_inventory.json\n"
        "secrets: []\n"
        "evidence_set:\n  reference_id: EVD-T-INVENTORY\n  name: T Inventory\n"
    )
    (fdir / "fetcher.py").write_text(
        "import json, os\nfrom pathlib import Path\n"
        f"Path(os.environ['EVIDENCE_DIR'], 't_inventory.json').write_text(json.dumps({payload!r}))\n"
        f"raise SystemExit({exit_code})\n"
    )
    schemas = root / "framework" / "schemas"
    if not schemas.exists():
        schemas.mkdir(parents=True)
        for src in SCHEMAS.glob("*.json"):
            (schemas / src.name).write_bytes(src.read_bytes())


def _run(root: Path) -> Path:
    summary = api.run({"run": {"output_dir": str(root / "out"),
                               "fetchers": [{"use": "t_inventory"}]}}, root)
    return Path(summary["run_dir"])


def _envelope(run_dir: Path) -> dict:
    return json.loads((run_dir / "t_inventory.json").read_text())


def _dry_upload(run_dir: Path) -> dict:
    summary = uploader.upload_run(run_dir, token="tok",
                                  base_url="https://app.example.com/api/v0", dry_run=True)
    (result,) = summary["results"]
    return result


def test_discovery_marks_an_inventory(tmp_path):
    _stage(tmp_path, _payload())
    f = discover_fetchers(tmp_path)["t_inventory"]
    assert f.is_inventory and not f.is_issue_report


def test_a_complete_inventory_is_enveloped_with_its_verdict_and_sent(tmp_path):
    _stage(tmp_path, _payload())
    run_dir = _run(tmp_path)
    env = _envelope(run_dir)
    assert env["metadata"]["inventory"]["complete"] is True
    assert env["payload"]["data"][0]["unique_asset_identifier"].startswith("arn:")
    assert _dry_upload(run_dir)["outcome"] == "would_upload"


@pytest.mark.parametrize("payload, exit_code, why", [
    (_payload(), 1, "the fetcher exited 1"),
    (_payload(included=False), 1, "the fetcher exited 1"),
    (_payload(records=[]), 0, "it holds no records"),
    (_payload(records=_records(1) * 2), 0, "breaks the inventory contract"),
])
def test_an_incomplete_inventory_is_not_sent(tmp_path, payload, exit_code, why):
    """Not optional the way skip_failed is: a partial estate reads as assets
    that are gone, so even the default uploader config refuses it."""
    _stage(tmp_path, payload, exit_code)
    result = _dry_upload(_run(tmp_path))
    assert result["outcome"] == "skipped_failed"
    assert why in result["reason"]


def test_payload_is_left_as_the_fetcher_wrote_it(tmp_path):
    payload = _payload(scope={"accounts": "ALL"})
    _stage(tmp_path, payload)
    assert _envelope(_run(tmp_path))["payload"] == payload


def test_plain_evidence_gets_no_inventory_verdict(tmp_path):
    """The check is keyed on kind: an evidence fetcher whose payload happens to
    have a `data` list is not judged as an inventory, and is sent as before."""
    _stage(tmp_path, _payload(records=[]), kind="evidence")
    run_dir = _run(tmp_path)
    assert "inventory" not in _envelope(run_dir)["metadata"]
    assert _dry_upload(run_dir)["outcome"] == "would_upload"
