#!/usr/bin/env python3
"""Sophos Central endpoint inventory: every computer and server, one record each."""

import copy
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from sophos_client import SophosClient, SophosError  # noqa: E402
from sophos_evidence import endpoint_identity, output_name, report_failure  # noqa: E402

logger = logging.getLogger("sophos_endpoint_inventory")
OUTPUT_FILE = "sophos_endpoint_inventory.json"


def record(ep: dict) -> dict:
    if not ep.get("id"):
        raise SophosError(f"an endpoint came back without an id: {ep.get('hostname')!r}", "partial_failure", "list_endpoints")
    attributes = copy.deepcopy(ep)
    # Personal-data rule is undecided: keep the login, leave the display name out.
    if isinstance(attributes.get("associatedPerson"), dict):
        attributes["associatedPerson"].pop("name", None)
    ident = endpoint_identity(ep)
    os_info = ep.get("os") or {}
    ipv4 = ep.get("ipv4Addresses") or []
    macs = ep.get("macAddresses") or []
    return {
        "unique_asset_identifier": ep["id"],
        "hostname": ident["hostname"],
        "serial_number": ident["serial_number"],
        "asset_type": ident["type"],
        "os_platform": os_info.get("platform"),
        "os_name": os_info.get("name"),
        "os_is_server": os_info.get("isServer"),
        "primary_ip_address": ipv4[0] if ipv4 else None,
        "primary_mac_address": macs[0] if macs else None,
        "group_name": (ep.get("group") or {}).get("name"),
        "associated_person_login": (ep.get("associatedPerson") or {}).get("viaLogin"),
        "last_seen_at": ep.get("lastSeenAt"),
        "attributes": attributes,
    }


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    client = None
    failure = None
    records: list = []
    reported_total = None
    try:
        client = SophosClient.from_env()
        client.connect()
        endpoints, reported_total = client.list_endpoints()
        records = [record(ep) for ep in endpoints]
        if reported_total is not None and len(records) != reported_total:
            raise SophosError(f"collected {len(records)} endpoints but Sophos reports {reported_total}",
                              "partial_failure", "count_check")
    except SophosError as e:
        failure = e
    except Exception as e:  # noqa: BLE001 - the inventory must still say why it was withheld
        failure = SophosError(f"unexpected error: {type(e).__name__}: {e}", "internal_error", "collect")

    payload = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": client.tenant_id if client else None,
        "record_count": len(records),
        "reported_total": reported_total,
        "records_included": failure is None,
        "data": records if failure is None else [],
    }
    if failure is not None:
        payload["error"] = str(failure)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / output_name(OUTPUT_FILE, client)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
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
