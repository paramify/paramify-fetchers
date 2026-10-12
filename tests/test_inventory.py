"""`kind: inventory`: the source's own file, sent to an evidence set untouched.

Two properties are defended here, end to end through the real runner and the
real uploader:

  - **the bytes Paramify receives are the bytes the source wrote.** The
    inventory pipeline parses the CSV, JSON or XML itself and dedupes the
    assets; anything the framework reshapes is a place to lose one.
  - **a file that cannot be the whole estate is never sent.** The pipeline reads
    the file as every asset there is, so a failed run, an empty file or a CSV
    with only a header would read as assets that are gone. That is judged from
    the file alone, never by parsing the data.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from framework import api, inventory
from framework.config_loader import discover_fetchers
from framework.contract import InvocationResult
from framework.envelope import is_enveloped

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = REPO_ROOT / "framework" / "schemas"

_spec = importlib.util.spec_from_file_location(
    "inventory_uploader_under_test", REPO_ROOT / "uploaders" / "paramify_evidence" / "uploader.py"
)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)

# A Wiz-style export whose bytes are deliberately awkward: a BOM, CRLF line
# endings, a quoted comma and a trailing space. Each survives a byte copy and
# dies in a parse-and-rewrite. Two rows share an id: deduping is the
# pipeline's job, so both must arrive.
RAW_CSV = (
    b"\xef\xbb\xbfID,Name,Type,External ID\r\n"
    b"r-1,\"web, primary\",VIRTUAL_MACHINE,i-0abc \r\n"
    b"r-1,\"web, primary\",VIRTUAL_MACHINE,i-0abc \r\n"
)


# --------------------------------------------------------------------------- #
# fetcher.yaml schema
# --------------------------------------------------------------------------- #

def _doc(**overrides) -> dict:
    doc = {
        "name": "x_inventory", "version": "0.1.0", "description": "d", "kind": "inventory",
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "csv", "path": "x.csv"},
        "secrets": [],
        "evidence_set": {"reference_id": "EVD-X-INVENTORY", "name": "X"},
    }
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not None}


def _schema_errors(doc: dict) -> list:
    return list(Draft202012Validator(json.loads((SCHEMAS / "fetcher_schema.json").read_text()))
                .iter_errors(doc))


@pytest.mark.parametrize("fmt", ["csv", "json", "xml"])
def test_schema_accepts_the_formats_an_inventory_pipeline_ingests(fmt):
    assert not _schema_errors(_doc(output={"type": fmt, "path": f"x.{fmt}"}))


@pytest.mark.parametrize("fmt", ["html", "nessus"])
def test_schema_refuses_formats_the_pipeline_cannot_read(fmt):
    assert _schema_errors(_doc(output={"type": fmt, "path": f"x.{fmt}"}))


def test_schema_requires_an_evidence_set_on_an_inventory():
    """Without one there is nowhere for an inventory pipeline to read it from."""
    assert _schema_errors(_doc(evidence_set=None))


def test_schema_refuses_an_issue_report_block_on_an_inventory():
    assert _schema_errors(_doc(issue_report={"assessment_type": "VULNERABILITY"}))


# --------------------------------------------------------------------------- #
# The file-level verdict
# --------------------------------------------------------------------------- #

def _file(tmp_path: Path, data: bytes, name: str = "x.csv") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_a_clean_csv_is_complete(tmp_path):
    assert inventory.incomplete_because(_file(tmp_path, RAW_CSV), "csv", 0) == []


def test_a_failed_run_is_never_complete_even_with_rows(tmp_path):
    """A fetcher that exits non-zero may have written half an estate."""
    assert inventory.incomplete_because(_file(tmp_path, RAW_CSV), "csv", 1) == [
        "the fetcher exited 1"]


def test_a_missing_file_is_not_complete(tmp_path):
    assert inventory.incomplete_because(tmp_path / "absent.csv", "csv", 0) == [
        "the file is missing"]


@pytest.mark.parametrize("fmt", ["csv", "json", "xml"])
def test_an_empty_file_is_not_complete(tmp_path, fmt):
    assert inventory.incomplete_because(_file(tmp_path, b"", f"x.{fmt}"), fmt, 0) == [
        "the file is empty"]


@pytest.mark.parametrize("data", [
    b"ID,Name\r\n",
    b"\xef\xbb\xbfID,Name\n",
    b"ID,Name\n\n , \n",
])
def test_a_csv_with_only_a_header_is_not_complete(tmp_path, data):
    """The shape a report run against an empty project, or a broken filter,
    produces: well-formed, and every asset missing."""
    assert inventory.incomplete_because(_file(tmp_path, data), "csv", 0) == [
        "the CSV has no rows under its header"]


def test_a_csv_that_is_not_text_is_not_complete(tmp_path):
    (reason,) = inventory.incomplete_because(_file(tmp_path, b"\xff\xfe\x00bin"), "csv", 0)
    assert reason.startswith("the CSV could not be read")


@pytest.mark.parametrize("fmt, data", [
    ("json", b"[]"),
    ("json", b"not json at all"),
    ("xml", b"<assets/>"),
])
def test_json_and_xml_are_never_parsed(tmp_path, fmt, data):
    """Only a CSV's row count is looked at. Whether a JSON or XML file holds
    assets is the pipeline's question, not the framework's."""
    assert inventory.incomplete_because(_file(tmp_path, data, f"x.{fmt}"), fmt, 0) == []


# --------------------------------------------------------------------------- #
# Runner → sidecar
# --------------------------------------------------------------------------- #

def _stage(root: Path, data: bytes, exit_code: int = 0, kind: str = "inventory",
           fmt: str = "csv") -> None:
    fdir = root / "fetchers" / "testcat" / "inventory"
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "fetcher.yaml").write_text(
        "name: t_inventory\nversion: 0.1.0\ndescription: d\ncategory: testcat\n"
        f"kind: {kind}\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        f"output:\n  type: {fmt}\n  path: t_inventory.{fmt}\n"
        "secrets: []\n"
        "evidence_set:\n  reference_id: EVD-T-INVENTORY\n  name: T Inventory\n"
    )
    (fdir / "fetcher.py").write_text(
        "import os\nfrom pathlib import Path\n"
        f"Path(os.environ['EVIDENCE_DIR'], 't_inventory.{fmt}').write_bytes({data!r})\n"
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


def _index(run_dir: Path) -> dict:
    return json.loads(inventory.sidecar_path(run_dir).read_text())


def _result(**overrides) -> InvocationResult:
    defaults = dict(
        fetcher_name="t_inventory", fetcher_version="0.1.0", target=None,
        started_at="2026-10-09T00:00:00Z", completed_at="2026-10-09T00:00:01Z",
        duration_sec=1.0, exit_code=0, stdout="", stderr="",
        outputs=["inventory/t_inventory.csv"],
    )
    defaults.update(overrides)
    return InvocationResult(**defaults)


def test_discovery_marks_an_inventory(tmp_path):
    _stage(tmp_path, RAW_CSV)
    f = discover_fetchers(tmp_path)["t_inventory"]
    assert f.is_inventory and not f.is_issue_report


def test_the_file_lands_in_inventory_byte_for_byte(tmp_path):
    _stage(tmp_path, RAW_CSV)
    run_dir = _run(tmp_path)
    assert (run_dir / "inventory" / "t_inventory.csv").read_bytes() == RAW_CSV
    assert not (run_dir / "t_inventory.csv").exists()


def test_a_json_inventory_is_not_enveloped(tmp_path):
    """The case an extension-based guard would get wrong: a .json file the
    envelope stage would otherwise wrap."""
    data = b'[{"id": "r-1"}, {"id": "r-1"}]'
    _stage(tmp_path, data, fmt="json")
    run_dir = _run(tmp_path)
    assert (run_dir / "inventory" / "t_inventory.json").read_bytes() == data


def test_the_sidecar_carries_identity_and_the_verdict(tmp_path):
    _stage(tmp_path, RAW_CSV)
    index = _index(_run(tmp_path))
    assert index["schema_version"] == inventory.SIDECAR_SCHEMA_VERSION
    (rec,) = index["files"]
    assert rec["file"] == "t_inventory.csv"
    assert rec["fetcher_name"] == "t_inventory"
    assert rec["evidence_set"]["reference_id"] == "EVD-T-INVENTORY"
    assert rec["evidence_set"]["name"] == "T Inventory"
    assert rec["format"] == "csv"
    assert rec["bytes"] == len(RAW_CSV)
    assert rec["complete"] is True and "incomplete_because" not in rec


def test_a_header_only_run_is_indexed_as_incomplete(tmp_path):
    _stage(tmp_path, b"ID,Name\r\n")
    (rec,) = _index(_run(tmp_path))["files"]
    assert rec["complete"] is False
    assert rec["incomplete_because"] == ["the CSV has no rows under its header"]


def test_an_invocation_that_wrote_nothing_adds_nothing(tmp_path):
    _stage(tmp_path, RAW_CSV)
    f = discover_fetchers(tmp_path)["t_inventory"]
    assert inventory.record_outputs(_result(outputs=[], exit_code=1), f, "RID", tmp_path) == []
    assert not inventory.sidecar_path(tmp_path).exists()


def test_a_corrupt_sidecar_is_kept_and_a_new_one_started(tmp_path):
    _stage(tmp_path, RAW_CSV)
    run_dir = _run(tmp_path)
    side = inventory.sidecar_path(run_dir)
    side.write_text("{not json")
    f = discover_fetchers(tmp_path)["t_inventory"]
    inventory.record_outputs(_result(), f, "RID", run_dir)
    assert side.with_name(side.name + ".corrupt").read_text() == "{not json"
    assert [rec["file"] for rec in _index(run_dir)["files"]] == ["t_inventory.csv"]


def test_an_evidence_fetcher_is_unaffected(tmp_path):
    """The kind, not the file, decides: an evidence fetcher still writes an
    envelope at the run root and leaves no inventory sidecar."""
    _stage(tmp_path, b'{"data": []}', kind="evidence", fmt="json")
    run_dir = _run(tmp_path)
    assert is_enveloped(json.loads((run_dir / "t_inventory.json").read_text()))
    assert not inventory.sidecar_path(run_dir).exists()


# --------------------------------------------------------------------------- #
# Runner → uploader
# --------------------------------------------------------------------------- #

def _dry_upload(run_dir: Path) -> dict:
    summary = uploader.upload_run(run_dir, token="tok",
                                  base_url="https://app.example.com/api/v0", dry_run=True)
    (result,) = summary["results"]
    return result


class _TagSession:
    """What the Tagger posts default custom tags through; records each POST."""

    def __init__(self):
        self.posts = []

    def post(self, url, json=None, timeout=None, **_):
        self.posts.append((url, json))
        return type("R", (), {"status_code": 200, "text": ""})()


class RecordingClient:
    """Just enough of ParamifyClient to see what goes over the wire."""

    def __init__(self):
        self.sent = []
        self.session = _TagSession()

    def get_or_create_evidence_set(self, es):
        return {"id": "ev-" + es["reference_id"], "referenceId": es["reference_id"], "channels": []}

    def artifact_exists(self, evidence_id, filename, run_id):
        return False

    def upload_artifact(self, evidence_id, filename, content, meta, content_type="application/json"):
        self.sent.append({"evidence_id": evidence_id, "filename": filename,
                          "content": content, "content_type": content_type})
        return {"id": "art-" + filename}


def test_a_complete_inventory_would_be_sent_to_its_set(tmp_path):
    _stage(tmp_path, RAW_CSV)
    result = _dry_upload(_run(tmp_path))
    assert result["outcome"] == "would_upload"
    assert result["reference_id"] == "EVD-T-INVENTORY"


@pytest.mark.parametrize("fmt, data, content_type", [
    ("csv", RAW_CSV, "text/csv"),
    ("json", b'[{"id": "r-1"}]', "application/json"),
    ("xml", b"<a><r id='1'/></a>", "application/xml"),
])
def test_the_uploader_sends_the_source_bytes_unchanged(tmp_path, monkeypatch, fmt, data, content_type):
    monkeypatch.delenv("PARAMIFY_CUSTOM_TAGS", raising=False)
    _stage(tmp_path, data, fmt=fmt)
    fake = RecordingClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)
    summary = uploader.upload_run(_run(tmp_path), token="tok",
                                  base_url="https://app.example.com/api/v0")
    assert summary["uploaded"] == 1
    assert fake.sent == [{"evidence_id": "ev-EVD-T-INVENTORY", "filename": f"t_inventory.{fmt}",
                          "content": data, "content_type": content_type}]
    # The inventory's set is tagged like any other evidence set.
    assert [url.rsplit("/custom-tags/", 1)[1] for url, _ in fake.session.posts] == ["evidence/ev-EVD-T-INVENTORY"]


@pytest.mark.parametrize("data, exit_code, why", [
    (RAW_CSV, 1, "the fetcher exited 1"),
    (b"", 0, "the file is empty"),
    (b"ID,Name\r\n", 0, "the CSV has no rows under its header"),
])
def test_an_incomplete_inventory_is_not_sent(tmp_path, data, exit_code, why):
    """Not optional the way skip_failed is: a partial estate reads as assets
    that are gone, so even the default uploader config refuses it."""
    _stage(tmp_path, data, exit_code)
    result = _dry_upload(_run(tmp_path))
    assert result["outcome"] == "skipped_failed"
    assert why in result["reason"]


def test_an_edited_sidecar_cannot_send_another_file(tmp_path):
    """The index is a plain file in the run dir; pointing it outside
    inventory/ must not send that file to Paramify."""
    _stage(tmp_path, RAW_CSV)
    run_dir = _run(tmp_path)
    index = _index(run_dir)
    index["files"][0]["file"] = "../_run_metadata.json"
    inventory.sidecar_path(run_dir).write_text(json.dumps(index))
    result = _dry_upload(run_dir)
    assert result["outcome"] == "error"
    assert result["reason"].startswith("refused:")


def test_an_unreadable_sidecar_is_reported_not_skipped(tmp_path):
    _stage(tmp_path, RAW_CSV)
    run_dir = _run(tmp_path)
    inventory.sidecar_path(run_dir).write_text("{not json")
    result = _dry_upload(run_dir)
    assert result["outcome"] == "error" and result["file"] == "inventory"


# --------------------------------------------------------------------------- #
# resolve_file
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [
    None, "", "../x.csv", "sub/x.csv", "_inventory.json", "/etc/passwd",
])
def test_resolve_file_refuses_names_outside_the_inventory_dir(tmp_path, name):
    (tmp_path / "inventory").mkdir()
    with pytest.raises(ValueError):
        inventory.resolve_file(tmp_path, name)


def test_resolve_file_refuses_a_symlink(tmp_path):
    inv = tmp_path / "inventory"
    inv.mkdir()
    (tmp_path / "elsewhere.csv").write_bytes(RAW_CSV)
    (inv / "x.csv").symlink_to(tmp_path / "elsewhere.csv")
    with pytest.raises(ValueError, match="symlink"):
        inventory.resolve_file(tmp_path, "x.csv")


def test_resolve_file_returns_a_listed_file(tmp_path):
    inv = tmp_path / "inventory"
    inv.mkdir()
    (inv / "x.csv").write_bytes(RAW_CSV)
    assert inventory.resolve_file(tmp_path, "x.csv").read_bytes() == RAW_CSV


# --------------------------------------------------------------------------- #
# Front-ends
# --------------------------------------------------------------------------- #

def test_the_run_summary_labels_and_counts_inventory_files(tmp_path):
    _stage(tmp_path, RAW_CSV)
    _run(tmp_path)
    (run,) = api.list_runs(tmp_path / "out")
    assert run["inventory"] == 1 and run["issue_reports"] == 0
    (f,) = run["files"]
    assert f["name"] == "inventory/t_inventory.csv" and f["kind"] == "inventory"


def test_preview_shows_why_an_inventory_is_held_back(tmp_path):
    _stage(tmp_path, b"ID,Name\r\n")
    run_dir = _run(tmp_path)
    text = api.preview_inventory_file(run_dir / "inventory" / "t_inventory.csv")
    assert "EVD-T-INVENTORY" in text
    assert "not sent: the CSV has no rows under its header" in text


def test_read_inventory_file_refuses_an_unlisted_file(tmp_path):
    _stage(tmp_path, RAW_CSV)
    run_dir = _run(tmp_path)
    stray = run_dir / "inventory" / "stray.csv"
    stray.write_bytes(RAW_CSV)
    with pytest.raises(ValueError, match="not listed"):
        api.read_inventory_file(stray)
