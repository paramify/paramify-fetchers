"""The `kind: inventory` contract: what makes an inventory complete enough to send.

An inventory fetcher is an evidence fetcher whose payload is one record per
asset under `data`, for a Paramify inventory pipeline attached to the evidence
set to turn into Inventory items. The pipeline reads the file as the whole
estate, so a partial or empty file is worse than none: it would read as assets
that no longer exist. The framework therefore checks every inventory output
when it envelopes it, records the verdict in `metadata.inventory`, and the
evidence uploader sends only one marked complete.

Only the outer shape is fixed (framework/schemas/inventory_schema.json). Each
fetcher chooses its own record fields. See docs/inventory_fetchers.md.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "inventory_schema.json"

# An inventory can hold tens of thousands of records, and one systematic bug
# (no id on any record) would otherwise produce a problem line for each.
_MAX_PROBLEMS = 5


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(_SCHEMA_PATH.read_text()))


def _where(error) -> str:
    path = "payload" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.absolute_path)
    return f"{path}: {error.message}"


def payload_problems(payload: Any) -> List[str]:
    """Why `payload` breaks the inventory contract; empty when it holds.

    The schema covers the shape. Duplicate IDs are checked here because JSON
    Schema cannot express uniqueness of one field across objects, and the
    pipeline matches Inventory items on that ID.
    """
    errors = sorted(_validator().iter_errors(payload), key=lambda e: list(e.absolute_path))
    problems = [_where(e) for e in errors[:_MAX_PROBLEMS]]
    if len(errors) > _MAX_PROBLEMS:
        problems.append(f"... and {len(errors) - _MAX_PROBLEMS} more")
    if errors:
        return problems

    ids = [r["unique_asset_identifier"] for r in payload["data"]]
    repeated = len(ids) - len(set(ids))
    if repeated:
        problems.append(f"{repeated} record(s) repeat a unique_asset_identifier")
    return problems


def check(payload: Any, exit_code: int) -> Dict[str, Any]:
    """The `metadata.inventory` block for one inventory output.

    `complete` is the only field the uploader acts on. It is true when the
    fetcher exited 0, the payload holds the contract, the fetcher did not
    withhold its records, and there is at least one record. An empty inventory
    is not sent: an empty estate is far likelier to be a filter or permission
    mistake than a real one, and the pipeline cannot tell the difference.
    """
    data = payload.get("data") if isinstance(payload, dict) else None
    included = payload.get("records_included") if isinstance(payload, dict) else None
    block: Dict[str, Any] = {
        "records": len(data) if isinstance(data, list) else None,
        "records_included": included if isinstance(included, bool) else None,
    }

    reasons: List[str] = []
    if exit_code != 0:
        reasons.append(f"the fetcher exited {exit_code}")
    problems = payload_problems(payload)
    if problems:
        block["problems"] = problems
        # A failed run's error body rarely has the inventory shape; that is a
        # symptom of the failure, not a second finding.
        if exit_code == 0:
            reasons.append("the payload breaks the inventory contract")
    elif not included:
        reasons.append("the fetcher withheld its records (records_included: false)")
    elif not data:
        reasons.append("it holds no records")

    block["complete"] = not reasons
    if reasons:
        block["incomplete_because"] = reasons
    return block
