"""One rule for which files in a run directory are evidence."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from framework import api
from framework.run_files import is_evidence_file

_UPLOADER_PATH = (
    Path(__file__).resolve().parent.parent / "uploaders" / "paramify_evidence" / "uploader.py"
)
_spec = importlib.util.spec_from_file_location("uploader_run_files_test", _UPLOADER_PATH)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)


def test_reserved_and_underscore_files_are_not_evidence(tmp_path):
    for name in ["_run_metadata.json", "upload_log.json", "_upload_state.json",
                 "_anything.json", "a.txt"]:
        (tmp_path / name).write_text("{}")
    (tmp_path / "aws_iam.json").write_text("{}")
    assert [p.name for p in sorted(tmp_path.iterdir()) if is_evidence_file(p)] == ["aws_iam.json"]


def test_uploader_and_api_readers_skip_state_file(tmp_path):
    envelope = {"metadata": {"evidence_set": {"reference_id": "EVD-X"}}, "data": {}}
    (tmp_path / "x.json").write_text(json.dumps(envelope))
    (tmp_path / "_upload_state.json").write_text(json.dumps(envelope))
    assert [p.name for p in uploader.iter_evidence_files(tmp_path)] == ["x.json"]
    assert api.reference_ids_from_run(tmp_path) == {"EVD-X"}
    (tmp_path / "_upload_state.json").write_text(
        json.dumps({"metadata": {"evidence_set": {"reference_id": "EVD-STATE"}}})
    )
    assert api.reference_ids_from_run(tmp_path) == {"EVD-X"}
