#!/usr/bin/env python3
"""Qualys VMDR host inventory: every host the API user sees, one record each.

Each record is keyed by the Qualys host ID. qualys_vmdr_vulnerability_findings
puts the same ID in its `Host ID` column, so Paramify can link each finding to
its Inventory item.

All or nothing: if any page or host fails, the file holds no records
(`records_included: false`) and the fetcher exits non-zero.
See docs/inventory_fetchers_guide.md.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from qualys_client import QualysClient, QualysError, text  # noqa: E402
from qualys_evidence import host_identity, list_hosts  # noqa: E402
from qualys_report_client import report_failure  # noqa: E402
from reports import hostname  # noqa: E402

logger = logging.getLogger("qualys_host_inventory")
OUTPUT_FILE = "qualys_host_inventory.json"


def record(host) -> dict:
    """One inventory record. Every record has the same keys, None for a missing value."""
    ident = host_identity(host)
    host_id = ident.pop("host_id")
    if not host_id:
        raise QualysError("a host came back without an ID", "partial_failure", "list_hosts")
    return {
        "unique_asset_identifier": host_id,
        "asset_type": "host",
        # The same value as the report's Host Name column.
        "name": hostname(host),
        **ident,  # ip, dns, netbios, os, tracking_method
        "ipv6": text(host, "IPV6"),
        "asset_id": text(host, "ASSET_ID"),
        "last_vuln_scan_datetime": text(host, "LAST_VULN_SCAN_DATETIME"),
        "last_vm_scanned_date": text(host, "LAST_VM_SCANNED_DATE"),
        "last_vm_auth_scanned_date": text(host, "LAST_VM_AUTH_SCANNED_DATE"),
    }


def collect(client: QualysClient, records: dict) -> None:
    """Every host, across every page, into `records` by host ID. Raises QualysError on any gap."""
    for host in list_hosts(client, show_asset_id="1"):
        rec = record(host)
        if rec["unique_asset_identifier"] in records:
            raise QualysError(f"Qualys returned host {rec['unique_asset_identifier']} twice; paging overlapped",
                              "partial_failure", "list_hosts")
        records[rec["unique_asset_identifier"]] = rec


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    client: Optional[QualysClient] = None
    failure: Optional[QualysError] = None
    records: dict = {}
    try:
        client = QualysClient.from_env()
        collect(client, records)
    except QualysError as e:
        failure = e
    except Exception as e:  # noqa: BLE001 - the inventory must still say why it was withheld
        failure = QualysError(f"unexpected error: {type(e).__name__}: {e}", "internal_error", "collect")

    payload = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "api_url": client.base_url if client else None,
        "platform": client.platform if client else None,
        "pages": client.pages if client else 0,
        # On failure the count stays, so an operator can see how far collection got.
        "record_count": len(records),
        "records_included": failure is None,
        "data": list(records.values()) if failure is None else [],
    }
    if failure is not None:
        payload["error"] = str(failure)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / OUTPUT_FILE
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    except OSError as e:
        report_failure(f"could not write the inventory: {e}", "internal_error")
        return 1

    if failure is not None:
        report_failure(f"inventory incomplete, records withheld: {failure}", failure.code)
        return 1
    logger.info("Inventory saved to %s (%d records)", path, len(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
