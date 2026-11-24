#!/usr/bin/env python3
"""
CrowdStrike Falcon host inventory: every managed host, one record each.

Feeds a Paramify inventory pipeline. Each record is keyed by the host's Falcon
agent ID (`device_id`), which is the same ID Spotlight writes as `aid` on every
finding, so crowdstrike_spotlight_vulnerability_report can link each finding to
the host's Inventory item.

THE ONE RULE: all or nothing. The pipeline reads this file as the whole estate,
so a host missing from it reads as a host that is gone. If any page, batch or
record fails, write no records (`data: []`, `records_included: false`) and exit
non-zero. See docs/inventory_fetchers_guide.md.

Auth, cloud selection, retry and the two paginators are the category's shared
client (_shared/falcon_client.py), the same calls crowdstrike_hosts makes.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from falcon_client import (  # type: ignore  # noqa: E402
    FalconAuthError,
    FalconClient,
    build_client,
    cloud_provenance,
    failure_code,
    failure_summary,
    host_id,
    report_failure,
)

logger = logging.getLogger("crowdstrike_host_inventory")

OUTPUT_FILE = "crowdstrike_host_inventory.json"
QUERY_PATH = "/devices/queries/devices-scroll/v1"
ENTITY_PATH = "/devices/entities/devices/v2"

# Every record is one managed endpoint. The Falcon product type (Workstation,
# Server, Domain Controller) stays a field of its own, so the parent component
# does not move when a host's product type changes.
ASSET_TYPE = "endpoint"


class Incomplete(Exception):
    """Collection cannot vouch for the whole estate. Carries the failure code."""

    def __init__(self, message: str, code: str = "partial_failure") -> None:
        super().__init__(message)
        self.code = code


def record(device: Dict[str, Any]) -> Dict[str, Any]:
    """One inventory record: the same keys on every record, None for a missing value."""
    uid = host_id(device.get("device_id"))
    if uid is None:
        raise Incomplete(f"a host came back without a device_id: {device.get('hostname')!r}")
    tags = [t for t in device.get("tags") or [] if isinstance(t, str) and t]
    return {
        "unique_asset_identifier": uid,
        "asset_type": ASSET_TYPE,
        "hostname": device.get("hostname"),
        "primary_ip_address": device.get("local_ip"),
        "external_ip_address": device.get("external_ip"),
        "mac_address": device.get("mac_address"),
        "os_platform": device.get("platform_name"),
        "os_version": device.get("os_version"),
        "os_build": device.get("os_build"),
        "os_product_name": device.get("os_product_name"),
        "product_type": device.get("product_type_desc"),
        "machine_domain": device.get("machine_domain"),
        "serial_number": device.get("serial_number"),
        "system_manufacturer": device.get("system_manufacturer"),
        "system_product_name": device.get("system_product_name"),
        "sensor_version": device.get("agent_version"),
        "reduced_functionality_mode": device.get("reduced_functionality_mode"),
        "containment_status": device.get("status"),
        "first_seen_at": device.get("first_seen"),
        "last_seen_at": device.get("last_seen"),
        "cloud_provider": device.get("service_provider"),
        "cloud_account_id": device.get("service_provider_account_id"),
        "cloud_instance_id": device.get("instance_id"),
        "falcon_customer_id": device.get("cid"),
        "tags": "; ".join(tags) or None,
    }


def collect(client: FalconClient) -> Tuple[List[Dict[str, Any]], int]:
    """Every host record, sorted by ID, and the query's ID count. Raises Incomplete on any gap."""
    device_ids = client.paginate_scroll(QUERY_PATH)
    devices = client.get_entities(ENTITY_PATH, device_ids) if device_ids else []
    # The client records a failed page or batch and carries on; for an
    # inventory any one of them means the file cannot stand for the estate.
    if client.api_failures:
        raise Incomplete(failure_summary(client.api_failures), failure_code(client.api_failures))

    by_id: Dict[str, Dict[str, Any]] = {}
    for device in devices:
        rec = record(device)
        by_id.setdefault(rec["unique_asset_identifier"], rec)

    queried = {i for i in (host_id(d) for d in device_ids) if i}
    unresolved = sorted(queried - by_id.keys())
    if unresolved:
        raise Incomplete(
            f"{len(unresolved)} of {len(queried)} host ID(s) from the query came back with no host "
            f"record (first: {unresolved[0]})"
        )
    return [by_id[k] for k in sorted(by_id)], len(device_ids)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))

    client: Optional[FalconClient] = None
    failure: Optional[Incomplete] = None
    records: List[Dict[str, Any]] = []
    queried = 0
    try:
        client = build_client()
        records, queried = collect(client)
    except Incomplete as e:
        failure = e
    except FalconAuthError as e:
        failure = Incomplete(str(e), "auth_failed")
    except RuntimeError as e:  # a missing secret or an unknown cloud region
        failure = Incomplete(str(e), "bad_config")
    except Exception as e:  # noqa: BLE001 - the inventory must still say why it was withheld
        failure = Incomplete(f"unexpected error: {type(e).__name__}: {e}", "internal_error")

    payload: Dict[str, Any] = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "cloud": cloud_provenance(client) if client else None,
        "queried_id_count": queried,
        "record_count": len(records),
        # Withhold every record on failure; `error` and `api_failures` say why.
        "records_included": failure is None,
        "data": records if failure is None else [],
    }
    if failure is not None:
        payload["error"] = str(failure)
        payload["api_failures"] = client.api_failures if client else []

    path = output_dir / OUTPUT_FILE
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, default=str))
    except OSError as e:
        report_failure(f"could not write the inventory: {e}", "internal_error")
        return 1
    logger.info("Inventory saved to %s (%d records)", path, len(payload["data"]))

    if failure is not None:
        report_failure(f"inventory incomplete, records withheld: {failure}", failure.code)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
