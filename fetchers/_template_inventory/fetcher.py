#!/usr/bin/env python3
"""
<short title>: list every <asset> in <tool>, one record per asset.

<One paragraph: which assets, over what scope, and what each record holds.>

THE ONE RULE: all or nothing. A Paramify inventory pipeline reads this file as
the whole estate, so a record missing from it reads as an asset that is gone.
If any page, call or record fails, write no records (`data: []`,
`records_included: false`) and exit non-zero. The framework checks the shape
when it envelopes the file, and the uploader sends only a complete inventory,
but the fetcher is the only one that knows a page went missing.
See docs/inventory_fetchers.md.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent

# The shared failure-reporting helper. Import it, never paste a copy.
# See docs/fetcher_contract.md § Output.
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("<category>_<short_name>")

OUTPUT_FILE = "<category>_<short_name>.json"
_TIMEOUT = 60


class _Incomplete(Exception):
    """Collection cannot vouch for the whole estate. Carries the failure code."""

    def __init__(self, message: str, code: str = "partial_failure") -> None:
        super().__init__(message)
        self.code = code


def fetch_assets(session: requests.Session) -> list:
    """Every asset, across every page. Raises _Incomplete on any gap."""
    assets: list = []
    url = "https://<tool-host>/api/<assets-path>"
    while url:
        try:
            resp = session.get(url, timeout=_TIMEOUT)
        except requests.RequestException as e:
            raise _Incomplete(f"could not reach <tool>: {e}", "target_unreachable") from e
        if resp.status_code in (401, 403):
            raise _Incomplete(f"<tool> rejected the credential (HTTP {resp.status_code})", "auth_failed")
        if resp.status_code != 200:
            raise _Incomplete(f"<tool> returned HTTP {resp.status_code}: {resp.text[:300]}")
        page = resp.json()
        assets.extend(page.get("items") or [])
        url = page.get("next")  # replace with the tool's own pagination
    return assets


def record(asset: dict) -> dict:
    """One inventory record. The fields are yours to choose, except one.

    `unique_asset_identifier` is required, must be non-empty, and must be unique
    in the file: it is what the pipeline matches Inventory items on, so use the
    asset's own stable ID (an ARN, a resource ID), never a display name. Keep
    every record's keys the same, with None for a missing value, so a pipeline
    mapping built from one sample holds for every run.
    """
    asset_id = asset.get("id")
    if not asset_id:
        raise _Incomplete(f"an asset came back without an id: {asset.get('name')!r}")
    return {
        "unique_asset_identifier": asset_id,
        "name": asset.get("name"),
        "asset_type": asset.get("type"),
        # ... the fields an inventory pipeline should map
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    token = os.environ.get("<UPPER_SNAKE_ENV_VAR>")
    if not token:
        report_failure("<UPPER_SNAKE_ENV_VAR> is not set", "bad_config")
        return 1

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"

    failure = None
    records: list = []
    try:
        records = [record(a) for a in fetch_assets(session)]
    except _Incomplete as e:
        failure = e

    payload = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        # Withhold every record on failure. The count stays, so an operator can
        # see how far collection got.
        "records_included": failure is None,
        "data": records if failure is None else [],
    }
    if failure is not None:
        payload["error"] = str(failure)

    try:
        (output_dir / OUTPUT_FILE).write_text(json.dumps(payload, indent=2))
    except OSError as e:
        report_failure(f"could not write the inventory: {e}", "internal_error")
        return 1

    if failure is not None:
        report_failure(f"inventory incomplete, records withheld: {failure}", failure.code)
        return 1
    logger.info("Inventory saved to %s (%d records)", output_dir / OUTPUT_FILE, len(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
