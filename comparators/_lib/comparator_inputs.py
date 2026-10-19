"""Read a comparator's inputs in place and apply one policy to them (docs/comparators.md).

Stdlib-only, like fetchers/_lib: the runner execs a comparator with no PYTHONPATH.

    complete  every invocation succeeded, no file records partial_failure, and the
              runner marked every inventory file complete
    partial   succeeded, but a file records partial_failure or is an incomplete inventory
    failed    an invocation failed but still wrote its file
    missing   not in the manifest, not run, no file, not a complete envelope from this
              run, a payload that is not a JSON object, or an inventory that
              withholds its records (records_included: false)

All but missing are compared; anything but complete makes the result partial
(exit 1). A missing input, or a comparison that raised, makes every summary
value null, never 0.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

__all__ = [
    "COMPLETE", "PARTIAL", "FAILED", "MISSING", "INPUTS_ENV",
    "Input", "InputFile", "Inputs", "build_payload", "load_inputs",
]

INPUTS_ENV = "COMPARATOR_INPUTS"
COMPLETE, PARTIAL, FAILED, MISSING = "complete", "partial", "failed", "missing"
_ENVELOPE_KEYS = {"schema_version", "metadata", "payload"}


@dataclass
class InputFile:
    path: Path
    target: Optional[dict]
    metadata: dict  # the runner's envelope metadata
    payload: Any  # what the input fetcher wrote


@dataclass
class Input:
    name: str
    state: str
    reason: Optional[str] = None
    files: List[InputFile] = field(default_factory=list)

    @property
    def payloads(self) -> List[Any]:
        return [f.payload for f in self.files]


class Inputs:
    """Every input a comparator declared, by fetcher name."""

    def __init__(self, inputs: Dict[str, Input], run_id: Optional[str] = None):
        self._inputs = inputs
        self.run_id = run_id

    def __getitem__(self, name: str) -> Input:
        return self._inputs[name]

    def __iter__(self) -> Iterator[Input]:
        return iter(self._inputs.values())

    @property
    def complete(self) -> bool:
        return all(i.state == COMPLETE for i in self)

    @property
    def missing(self) -> List[str]:
        return [i.name for i in self if i.state == MISSING]

    @property
    def failures(self) -> List[dict]:
        """The payload's `api_failures` entries, one per input that is not complete."""
        return [
            {"operation": f"read input {i.name}", "type": f"input_{i.state}", "message": i.reason}
            for i in self if i.state != COMPLETE
        ]

    @property
    def exit_code(self) -> int:
        return 0 if self.complete else 1

    def reason(self) -> str:
        """One line for report_failure, naming each input to look at."""
        return "; ".join(f"input {i.name} {i.state}: {i.reason}" for i in self if i.state != COMPLETE)


def load_inputs(path: Optional[Union[str, Path]] = None) -> Inputs:
    """Read the index at `path` (default $COMPARATOR_INPUTS) and every file it names."""
    index_path = path or os.environ.get(INPUTS_ENV)
    if not index_path:
        raise RuntimeError(f"{INPUTS_ENV} is not set; comparators run under `paramify run`")
    index = json.loads(Path(index_path).read_text())
    run_id = index.get("run_id")
    return Inputs(
        {name: _classify(name, entry or {}, run_id) for name, entry in (index.get("inputs") or {}).items()},
        run_id,
    )


def build_payload(
    inputs: Inputs, results: List[Any], summary: Dict[str, Any], error: Optional[str] = None,
) -> Dict[str, Any]:
    """The comparator's evidence, `{metadata, results, summary}`, with the policy applied.

    `error` is why the comparison itself failed; the file is still written, with null counts.
    """
    if inputs.missing or error:
        results, summary = [], dict.fromkeys(summary)
    failures = inputs.failures
    if error:
        failures.append({"operation": "compare inputs", "type": "internal_error", "message": error})
    return {
        "metadata": {
            "datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "partial_failure": bool(failures),
            "api_failures": failures,
        },
        "results": results,
        "summary": {**summary, "inputs_complete": inputs.complete},
    }


def _classify(name: str, entry: dict, run_id: Optional[str]) -> Input:
    if not entry.get("in_manifest"):
        return Input(name, MISSING, "not in the manifest")
    invocations = entry.get("invocations") or []
    if not invocations:
        return Input(name, MISSING, "did not run")

    files: List[InputFile] = []
    failed: List[str] = []
    for inv in invocations:
        where = _where(inv.get("target"))
        error = inv.get("error") or "no reason given"
        if not inv.get("files"):
            detail = f": {error}" if inv.get("status") != "success" else ""
            return Input(name, MISSING, f"wrote no file{where}{detail}")
        for p in inv["files"]:
            read = _read(Path(p), name, run_id, inv.get("target"))
            if isinstance(read, str):
                return Input(name, MISSING, f"{Path(p).name}{where} {read}")
            if _inventory(read).get("records_included") is False:
                return Input(name, MISSING, f"{read.path.name}{where} withholds its records (records_included: false)")
            files.append(read)
        if inv.get("status") != "success":
            failed.append(f"collection failed{where}: {error}")

    if failed:
        return Input(name, FAILED, "; ".join(failed), files)
    partial = [f"{f.path.name} records partial_failure" for f in files if _partial(f.payload)]
    for f in files:
        inventory = _inventory(f)
        if inventory and inventory.get("complete") is not True:
            why = "; ".join(inventory.get("incomplete_because") or ["not marked complete"])
            partial.append(f"{f.path.name} is an incomplete inventory: {why}")
    if partial:
        return Input(name, PARTIAL, "; ".join(partial), files)
    return Input(name, COMPLETE, None, files)


def _read(path: Path, name: str, run_id: Optional[str], target: Optional[dict]) -> Union[InputFile, str]:
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        return f"cannot be read as JSON ({exc.__class__.__name__})"
    if not (isinstance(raw, dict) and _ENVELOPE_KEYS <= raw.keys() and isinstance(raw["metadata"], dict)):
        return "is not a complete evidence envelope"
    meta = raw["metadata"]
    if meta.get("fetcher_name") != name or (run_id and meta.get("run_id") != run_id):
        return f"is not {name}'s evidence from this run"
    if not isinstance(raw["payload"], dict):
        return "holds a payload that is not a JSON object"
    return InputFile(path, target, meta, raw["payload"])


def _inventory(f: InputFile) -> dict:
    block = f.metadata.get("inventory")
    return block if isinstance(block, dict) else {}


def _partial(payload: Any) -> bool:
    meta = payload.get("metadata") if isinstance(payload, dict) else None
    return isinstance(meta, dict) and meta.get("partial_failure") is True


def _where(target: Optional[dict]) -> str:
    return f" (target {json.dumps(target, sort_keys=True, default=str)})" if target else ""
