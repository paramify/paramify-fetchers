"""Evidence shape shared by the qualys fetchers: scope, dates, timeframes, detections and the run loop."""

from __future__ import annotations

import json
import logging
import os
import statistics
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, Optional

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402
from qualys_client import QualysClient, QualysError, text  # noqa: E402

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

SEVERITIES = ("5", "4", "3", "2", "1")
NOT_RETURNED = "not_returned"
DEFAULT_REMEDIATION_DAYS = "5:30,4:30,3:90,2:180,1:180"
ASSET_GROUP_PATH = "/api/2.0/fo/asset/group/"
DETECTION_PATH = "/api/5.0/fo/asset/host/vm/detection/"
PAGE_SIZE = "1000"


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


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def days_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    if start is None or end is None:
        return None
    return round(max((end - start).total_seconds(), 0) / 86400, 1)


def qualys_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def int_config(env: str, default: int, minimum: int = 1, maximum: int = 3650) -> int:
    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = minimum - 1
    if not minimum <= value <= maximum:
        raise QualysError(f"{env} must be a whole number from {minimum} to {maximum}, got {raw!r}",
                          "bad_config", "configuration")
    return value


def bool_config(env: str, default: bool) -> bool:
    raw = os.environ.get(env, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise QualysError(f"{env} must be true or false, got {raw!r}", "bad_config", "configuration")


def remediation_days() -> dict[str, int]:
    """Days allowed per Qualys severity, from QUALYS_REMEDIATION_DAYS ('5:30,4:30,3:90,2:180,1:180')."""
    raw = os.environ.get("QUALYS_REMEDIATION_DAYS", "").strip() or DEFAULT_REMEDIATION_DAYS
    days: dict[str, int] = {}
    try:
        for part in raw.split(","):
            severity, value = (p.strip() for p in part.split(":"))
            if severity not in SEVERITIES or int(value) < 1:
                raise ValueError
            days[severity] = int(value)
    except ValueError:
        days = {}
    if set(days) != set(SEVERITIES):
        raise QualysError(f"QUALYS_REMEDIATION_DAYS must give days for severities 5 to 1, like "
                          f"{DEFAULT_REMEDIATION_DAYS!r}; got {raw!r}", "bad_config", "configuration")
    return {s: days[s] for s in SEVERITIES}


def read_scope(client: QualysClient, ledger: Ledger) -> dict:
    """Asset groups the API user can see; the built-in 'All' group among them means it sees every asset."""
    try:
        titles = [text(g, "TITLE") or "" for g in client.records(
            ASSET_GROUP_PATH, {"action": "list", "show_attributes": "ID,TITLE", "truncation_limit": PAGE_SIZE},
            "ASSET_GROUP", "list_asset_groups")]
    except QualysError as e:
        ledger.add(e)
        return {"scope_all": None, "visible_asset_groups": None, "asset_group_titles": None}
    return {"scope_all": "All" in titles, "visible_asset_groups": len(titles),
            "asset_group_titles": sorted(titles)}


def host_identity(host: Element) -> dict:
    return {
        "host_id": text(host, "ID"),
        "ip": text(host, "IP") or text(host, "IPV6"),
        "dns": text(host, "DNS_DATA/FQDN") or text(host, "DNS") or text(host, "DNS_DATA/HOSTNAME"),
        "netbios": text(host, "NETBIOS"),
        "os": text(host, "OS"),
        "tracking_method": text(host, "TRACKING_METHOD"),
    }


def detection_params(**extra: str) -> dict:
    params = {"action": "list", "show_results": "0", "show_reopened_info": "1", "show_igs": "0",
              "include_ignored": "1", "include_disabled": "1", "truncation_limit": PAGE_SIZE}
    params.update(extra)
    return params


def detections(client: QualysClient, params: dict, operation: str) -> Iterable[tuple[dict, Element]]:
    """(host identity, DETECTION element) for every detection, across every page."""
    for host in client.records(DETECTION_PATH, params, "HOST", operation):
        identity = host_identity(host)
        for det in host.iter("DETECTION"):
            yield identity, det


def detection_record(identity: dict, det: Element, now: datetime, timeframes: dict[str, int]) -> dict:
    """One detection with its age against its severity's timeframe; the clock restarts at its last reopening."""
    severity = text(det, "SEVERITY")
    first_found = text(det, "FIRST_FOUND_DATETIME")
    last_fixed = text(det, "LAST_FIXED_DATETIME")
    last_reopened = text(det, "LAST_REOPENED_DATETIME")
    status = text(det, "STATUS")
    started = parse_time(last_reopened or first_found)
    ended = parse_time(last_fixed) if status == "Fixed" else now
    age = days_between(started, ended)
    timeframe = timeframes.get(severity or "")
    within, over = None, None
    if age is not None and timeframe is not None:
        within, over = age <= timeframe, round(max(age - timeframe, 0), 1)
    return {
        "host_id": identity["host_id"],
        "ip": identity["ip"],
        "dns": identity["dns"],
        "qid": text(det, "QID"),
        "unique_vuln_id": text(det, "UNIQUE_VULN_ID"),
        "type": text(det, "TYPE"),
        "severity": severity,
        "status": status,
        "first_found": first_found,
        "last_found": text(det, "LAST_FOUND_DATETIME"),
        "last_fixed": last_fixed,
        "last_reopened": last_reopened,
        "times_reopened": _int(text(det, "TIMES_REOPENED")),
        "is_ignored": _flag(text(det, "IS_IGNORED")),
        "is_disabled": _flag(text(det, "IS_DISABLED")),
        "age_from": "last_reopened" if last_reopened else "first_found",
        "age_days": age,
        "timeframe_days": timeframe,
        "within_timeframe": within,
        "days_over_timeframe": over,
    }


def _flag(value: Optional[str]) -> Optional[bool]:
    return {"1": True, "0": False}.get(value or "")


def _int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def by_severity(records: Iterable[dict], keep: Callable[[dict], bool] = lambda r: True) -> dict[str, int]:
    counts = Counter(r["severity"] if r["severity"] in SEVERITIES else NOT_RETURNED for r in records if keep(r))
    return {s: counts.get(s, 0) for s in (*SEVERITIES, NOT_RETURNED)}


def median(values: Iterable[Optional[float]]) -> Optional[float]:
    present = [v for v in values if v is not None]
    return round(statistics.median(present), 1) if present else None


def cutoff(now: datetime, days: int) -> datetime:
    return now - timedelta(days=days)


Collect = Callable[[QualysClient, Ledger, datetime], tuple[dict, dict, int]]


def run(logger_name: str, output_file: str, collect: Collect) -> int:
    """Read scope, collect, write the evidence, and report any failure."""
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger = logging.getLogger(logger_name)
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    now = datetime.now(timezone.utc)
    ledger = Ledger()
    client: Optional[QualysClient] = None
    body: dict = {}
    summary: Optional[dict] = None
    scope: dict = {"scope_all": None, "visible_asset_groups": None, "asset_group_titles": None}
    collected = 0
    fatal: Optional[QualysError] = None

    try:
        client = QualysClient.from_env()
        scope = read_scope(client, ledger)
        body, summary, collected = collect(client, ledger, now)
    except QualysError as e:
        fatal = e
        ledger.add(e)
    except Exception as e:  # noqa: BLE001 - the evidence must still say why the run failed
        fatal = QualysError(f"unexpected error: {type(e).__name__}: {e}", "internal_error", "collect")
        ledger.add(fatal)

    if summary is not None:
        summary["scope_all"] = scope["scope_all"]
        summary["visible_asset_groups"] = scope["visible_asset_groups"]
    payload = {
        "metadata": {
            "api_url": client.base_url if client else None,
            "platform": client.platform if client else None,
            "datetime": now.isoformat(),
            "partial_failure": bool(ledger.failures),
            "api_failures": ledger.failures,
            "api_user_scope": scope,
            "population": {"collected": collected, "pages": client.pages if client else 0,
                           "complete": fatal is None and not ledger.failures},
        },
        **body,
        "summary": summary if fatal is None else None,
    }
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / output_file
        path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str))
    except OSError as e:
        report_failure(f"could not write the evidence: {e}", "internal_error")
        return 1
    logger.info("Evidence saved to %s (%d records)", path, collected)

    if fatal is not None:
        report_failure(str(fatal), fatal.code)
        return 1
    if ledger.failures:
        first = ledger.failures[0]
        report_failure(f"{len(ledger.failures)} Qualys read(s) failed; first: {first['message']}", first["type"])
        return 1
    return 0
