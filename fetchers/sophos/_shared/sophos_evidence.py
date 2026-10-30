"""Evidence shape shared by the sophos fetchers: identity, ages, tallies and the run loop."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402
from sophos_client import SophosClient, SophosError  # noqa: E402

ABSENT = "absent_from_response"
NOT_RETURNED = "not_returned"
PROTECTION_PRODUCTS = ("interceptX", "endpointProtection")


class Ledger:
    """Calls that failed while the rest of the collection carried on."""

    def __init__(self) -> None:
        self.failures: list[dict] = []

    def add(self, err: Exception, operation: str = "") -> None:
        self.failures.append({
            "operation": getattr(err, "operation", "") or operation,
            "type": getattr(err, "code", type(err).__name__),
            "message": str(err),
        })


def endpoint_identity(ep: dict) -> dict:
    hostname = ep.get("hostname")
    return {
        "endpoint_id": ep.get("id"),
        "hostname": hostname.lower() if isinstance(hostname, str) and hostname else None,
        "serial_number": ep.get("serialNumber") or None,
        "type": ep.get("type"),
    }


def parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def age(value: Any, now: datetime, unit_seconds: int) -> Optional[float]:
    """Time from `value` to `now` in the given unit, to one decimal; None if unreadable."""
    then = parse_time(value)
    if then is None:
        return None
    return round(max((now - then).total_seconds(), 0) / unit_seconds, 1)


def tally(items: list[dict], field: str) -> tuple[int, int, int]:
    """(true, false, null) counts of a boolean item field."""
    values = [item.get(field) for item in items]
    return values.count(True), values.count(False), sum(1 for v in values if v is None)


def count_by(items: list[dict], field: str) -> dict[str, int]:
    counts = Counter(item.get(field) if item.get(field) is not None else NOT_RETURNED for item in items)
    return {key: counts[key] for key in sorted(counts)}


def largest(items: list[dict], field: str) -> Optional[float]:
    values = [item[field] for item in items if isinstance(item.get(field), (int, float))]
    return max(values) if values else None


def output_name(output_file: str, client: Optional[SophosClient]) -> str:
    """<stem>_<tenant>.json, so fanned-out tenants never overwrite each other."""
    tenant = (client.tenant_id or client.requested_tenant_id) if client else None
    if not tenant:
        seed = os.environ.get("SOPHOS_CLIENT_ID", "")
        tenant = "credential-" + hashlib.sha256(seed.encode()).hexdigest()[:8] if seed else "unconfigured"
    stem = output_file.removesuffix(".json")
    return f"{stem}_{tenant}.json"


Collect = Callable[[SophosClient, Ledger, datetime], tuple[list[dict], dict, dict]]


def run(logger_name: str, output_file: str, collect: Collect) -> int:
    """Connect, collect, check completeness, write the evidence, and report any failure."""
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger = logging.getLogger(logger_name)
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    now = datetime.now(timezone.utc)
    ledger = Ledger()
    client: Optional[SophosClient] = None
    items: list[dict] = []
    summary: Optional[dict] = None
    population: dict = {"collected": 0, "reported_total": None}
    fatal: Optional[SophosError] = None

    try:
        client = SophosClient.from_env()
        client.connect()
        items, summary, population = collect(client, ledger, now)
    except SophosError as e:
        fatal = e
        ledger.add(e)
    except Exception as e:  # noqa: BLE001 - the evidence must still say why the run failed
        fatal = SophosError(f"unexpected error: {type(e).__name__}: {e}", "internal_error", "collect")
        ledger.add(fatal)

    unread = [item for item in items if item.get("unread_facts")]
    mismatch = (population.get("reported_total") is not None
                and population["collected"] != population["reported_total"])
    if mismatch:
        ledger.add(SophosError(
            f"collected {population['collected']} but Sophos reports {population['reported_total']}",
            "partial_failure", "count_check"))
    if fatal is not None:
        complete: Optional[bool] = False
    elif mismatch or unread or ledger.failures:
        complete = False
    elif population.get("reported_total") is None:
        complete = None
    else:
        complete = True

    payload = {
        "metadata": {
            "tenant_id": client.tenant_id if client else None,
            "credential_type": client.id_type if client else None,
            "api_host": client.api_host if client else None,
            "datetime": now.isoformat(),
            "partial_failure": bool(ledger.failures or unread),
            "api_failures": ledger.failures,
            "population": {**population, "complete": complete,
                           "items_with_unread_facts": len(unread)},
        },
        "items": items,
        "summary": summary if fatal is None else None,
    }
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / output_name(output_file, client)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
    except OSError as e:
        report_failure(f"could not write the evidence: {e}", "internal_error")
        return 1
    logger.info("Evidence saved to %s (%d items)", path, len(items))

    if fatal is not None:
        report_failure(str(fatal), fatal.code)
        return 1
    if ledger.failures:
        first = ledger.failures[0]
        report_failure(f"{len(ledger.failures)} Sophos read(s) failed; first: {first['message']}", first["type"])
        return 1
    if unread:
        fields = sorted({key for item in unread for key in item["unread_facts"]})
        report_failure(f"{len(unread)} item(s) have facts Sophos did not return: {', '.join(fields)}",
                       "partial_failure")
        return 1
    return 0
