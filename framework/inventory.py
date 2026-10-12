"""Inventory files: the source system's own export, sent to an evidence set.

An inventory fetcher hands over the asset list a source system already produces
(a Wiz inventory report, a CMDB export), byte for byte. Paramify's inventory
pipeline, attached to the fetcher's evidence set, parses the CSV, JSON or XML
itself and matches and dedupes the assets. Nothing in between reshapes the
data: every transformation is a place to lose or corrupt an asset.

So, as with issue reports, the file is never enveloped, and its identity moves
out of band. Inventory files go to `<run>/inventory/`, and this module writes
`_inventory.json` beside them: one record per file, carrying the envelope's
metadata (fetcher, run, target, evidence set) plus a completeness verdict.
`paramify upload` reads that index and sends each complete file to its set.

The verdict exists because the pipeline reads the file as the whole estate: a
partial or empty file reads as assets that are gone. It is judged from the file
alone, never by parsing the data: the fetcher exited 0, the file is not empty,
and a CSV has at least one row under its header.

See docs/inventory_fetchers.md.
"""

import csv
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from framework.contract import Fetcher, InvocationResult
from framework.envelope import build_metadata
from framework.issue_reports import _atomic_write_json, _sha256

logger = logging.getLogger("framework.inventory")

# Subdirectory of the run dir that inventory files land in. The runner points
# EVIDENCE_DIR here for an inventory fetcher, so fetchers never name it.
INVENTORY_DIR = "inventory"
SIDECAR_NAME = "_inventory.json"
SIDECAR_SCHEMA_VERSION = "1.0"

# The formats an inventory pipeline ingests, and the MIME type each is sent as.
CONTENT_TYPES = {"csv": "text/csv", "json": "application/json", "xml": "application/xml"}


def inventory_dir(run_dir: Path) -> Path:
    return Path(run_dir) / INVENTORY_DIR


def sidecar_path(run_dir: Path) -> Path:
    return inventory_dir(run_dir) / SIDECAR_NAME


def _csv_rows(path: Path) -> int:
    """Data rows under the header. Raises ValueError on a file that is not text."""
    rows = 0
    try:
        # utf-8-sig: exports from Windows-minded tools start with a BOM.
        with path.open(newline="", encoding="utf-8-sig") as fh:
            reader = csv.reader(fh)
            next(reader, None)
            for row in reader:
                if any(cell.strip() for cell in row):
                    rows += 1
    except (UnicodeDecodeError, csv.Error) as e:
        raise ValueError(str(e)) from e
    return rows


def incomplete_because(path: Path, fmt: str, exit_code: int) -> List[str]:
    """Why this file must not be sent; empty when it may be.

    Only the file's existence, size and (for a CSV) row count are looked at. The
    contents are the source system's and are never interpreted here.
    """
    reasons: List[str] = []
    if exit_code != 0:
        reasons.append(f"the fetcher exited {exit_code}")
    try:
        size = path.stat().st_size
    except OSError:
        return reasons + ["the file is missing"]
    if size == 0:
        return reasons + ["the file is empty"]
    if fmt == "csv":
        try:
            if _csv_rows(path) == 0:
                reasons.append("the CSV has no rows under its header")
        except (OSError, ValueError) as e:
            reasons.append(f"the CSV could not be read ({e})")
    return reasons


def build_record(
    filename: str, result: InvocationResult, fetcher: Fetcher, run_id: str, run_dir: Path
) -> dict:
    """One sidecar record: the envelope's metadata, field for field, plus the
    file's format, hash, size and completeness verdict."""
    path = inventory_dir(run_dir) / filename
    reasons = incomplete_because(path, fetcher.output_type, result.exit_code)
    record = {
        "file": filename,
        **build_metadata(result, fetcher, run_id),
        "format": fetcher.output_type,
        "sha256": _sha256(path) if path.exists() else None,
        "bytes": path.stat().st_size if path.exists() else None,
        "complete": not reasons,
    }
    if reasons:
        record["incomplete_because"] = reasons
    return record


def record_outputs(
    result: InvocationResult, fetcher: Fetcher, run_id: str, run_dir: Path
) -> List[dict]:
    """Add the inventory files this invocation wrote to the run's sidecar.

    Read-modify-write after every invocation, so a run killed halfway still
    leaves an index for what it did collect. An invocation that wrote nothing
    adds nothing: there is no file to send, and so nothing to hold back.
    """
    prefix = f"{INVENTORY_DIR}/"
    names = [
        name[len(prefix):]
        for name in result.outputs
        if name.startswith(prefix) and Path(name).name != SIDECAR_NAME
    ]
    if not names:
        return []
    added = [build_record(name, result, fetcher, run_id, run_dir) for name in names]

    path = sidecar_path(run_dir)
    index: Dict[str, Any] = {"schema_version": SIDECAR_SCHEMA_VERSION, "run_id": run_id, "files": []}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
            if not (isinstance(existing, dict) and isinstance(existing.get("files"), list)):
                raise ValueError("not an inventory index (no files list)")
            index = existing
        except (OSError, ValueError) as e:
            # Keep the unreadable one for whoever investigates; the files it
            # listed can no longer be sent from this run, but this invocation's can.
            backup = path.with_name(path.name + ".corrupt")
            try:
                os.replace(path, backup)
            except OSError:
                pass
            logger.error("inventory: %s was unreadable (%s); starting a new index", path.name, e)
    index["files"] = list(index["files"]) + added
    try:
        _atomic_write_json(path, index)
    except OSError as e:
        logger.error("inventory: could not write %s (%s); these files cannot be uploaded", path, e)
        return []
    return added


def read_index(run_dir: Path) -> Optional[dict]:
    """A run's inventory index, or None when the run collected no inventory."""
    path = sidecar_path(run_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read inventory index {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        raise ValueError(f"{path} is not an inventory index (no files list)")
    return data


def resolve_file(run_dir: Path, name: Any) -> Path:
    """The inventory file an index record names, refusing anything outside the
    run's inventory directory.

    The index is a plain file in the run dir; an edited one must not be able to
    send some other file to Paramify. A symlink is refused for the same reason.
    """
    base = inventory_dir(run_dir).resolve()
    if not isinstance(name, str) or not name or Path(name).name != name or name.startswith("_"):
        raise ValueError(f"not an inventory file name: {name!r}")
    path = base / name
    if path.is_symlink():
        raise ValueError(f"{name} is a symlink")
    if path.resolve().parent != base:
        raise ValueError(f"{name} is outside {INVENTORY_DIR}/")
    return path
