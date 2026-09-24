#!/usr/bin/env python3
"""KSI-CNA-OFA: Better Stack public status page.

One unauthenticated GET against <status_page_url>/index.json — the JSON:API
document a hosted Better Stack status page renders itself from — recorded
verbatim, plus one additive per-component availability block.

Generic by design: nothing here knows about any particular status page. The
page URL and a label come from the target, and every component the page
publishes is read out of the response.

Single-target per invocation; fanout across pages happens at the runner layer
(see fetcher.yaml: supports_targets: true).
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("betterstack_public_status_page")

REQUEST_TIMEOUT = 30
SECONDS_PER_DAY = 86400
# Better Stack reports `availability` to six decimal places; the derived figure
# is rounded the same way so the two are read on the same scale.
AVAILABILITY_PRECISION = 6


class CollectionError(Exception):
    """A failure that must end the invocation, carrying its contract `code`."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise CollectionError(f"Missing required env var: {name}", "bad_config")
    return value


def env_bool(name: str, default: bool) -> bool:
    """Read a boolean target field. The runner hands booleans over as strings."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def resolve_index_url(status_page_url: str) -> str:
    """Append /index.json unless the URL already names it.

    A malformed URL is `bad_config`, not `target_unreachable`: nothing was
    unreachable, the manifest is wrong.
    """
    cleaned = status_page_url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise CollectionError(
            f"BETTERSTACK_STATUS_PAGE_URL is not an http(s) URL: {status_page_url!r}",
            "bad_config",
        )
    path = parsed.path.rstrip("/")
    if path.endswith("/index.json") or path == "/index.json":
        return cleaned.rstrip("/")
    return f"{cleaned.rstrip('/')}/index.json"


def sanitize_for_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", value.replace("/", "_").replace(" ", "_"))


def fetch_index(url: str, verify_ssl: bool) -> Tuple[Dict[str, Any], int]:
    """GET the document. Every failure mode here is fatal — see the contract.

    An empty payload from a status page that did not answer, or answered with
    something else, would read downstream as "nothing to report" rather than
    "we did not find out", so none of these degrade to a partial success.
    """
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            verify=verify_ssl,
            headers={"Accept": "application/json"},
        )
    except requests.exceptions.RequestException as exc:
        raise CollectionError(
            f"GET {url} failed at the network layer: {type(exc).__name__}: {exc}",
            "target_unreachable",
        ) from exc

    if response.status_code != 200:
        raise CollectionError(
            f"GET {url} returned HTTP {response.status_code} "
            f"(expected 200); body starts: {response.text[:200]!r}",
            "target_unreachable",
        )

    try:
        document = response.json()
    except ValueError as exc:
        raise CollectionError(
            f"GET {url} returned a body that is not JSON "
            f"(content-type {response.headers.get('Content-Type')!r}); "
            f"body starts: {response.text[:200]!r}",
            "target_unreachable",
        ) from exc

    if not isinstance(document, dict):
        raise CollectionError(
            f"GET {url} returned JSON that is not an object (got {type(document).__name__})",
            "target_unreachable",
        )
    return document, response.status_code


def assert_is_status_page(document: Dict[str, Any], url: str) -> None:
    """Fail loudly when the body is JSON but not a Better Stack status page."""
    data = document.get("data")
    if not isinstance(data, dict) or data.get("type") != "status_page":
        found = data.get("type") if isinstance(data, dict) else type(data).__name__
        raise CollectionError(
            f"GET {url} did not return a Better Stack status page document: "
            f'expected data.type == "status_page", found {found!r}',
            "target_unreachable",
        )
    if not isinstance(data.get("attributes"), dict):
        raise CollectionError(
            f"GET {url} returned a status_page document with no attributes object",
            "target_unreachable",
        )
    if not isinstance(document.get("included"), list):
        raise CollectionError(
            f"GET {url} returned a status_page document with no `included` array, "
            "so no component could be read from it",
            "target_unreachable",
        )


def _relationship_ids(container: Any, relationship: str) -> List[str]:
    """The ids a JSON:API relationship names, as strings."""
    relationships = (container or {}).get("relationships")
    if not isinstance(relationships, dict):
        return []
    entry = relationships.get(relationship)
    if not isinstance(entry, dict):
        return []
    rows = entry.get("data")
    if not isinstance(rows, list):
        return []
    return [str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id") is not None]


def assert_included_is_complete(document: Dict[str, Any], url: str) -> None:
    """Every referenced object must actually be in `included`.

    A payload holding 30 of 133 objects is populated too, and it is the more
    dangerous failure: it reads as evidence while quietly omitting whatever was
    dropped. So a shortfall ends the collection instead of being recorded as a
    caveat nobody reads.
    """
    included = document.get("included") or []
    present = {
        (item.get("type"), str(item.get("id")))
        for item in included
        if isinstance(item, dict)
    }

    expected: List[Tuple[str, str]] = []
    for relationship, item_type in (
        ("sections", "status_page_section"),
        ("resources", "status_page_resource"),
        ("status_reports", "status_report"),
    ):
        expected += [
            (item_type, ident)
            for ident in _relationship_ids(document.get("data"), relationship)
        ]

    # Reports name their own updates, so the check has to walk one level down.
    for item in included:
        if isinstance(item, dict) and item.get("type") == "status_report":
            expected += [
                ("status_update", ident)
                for ident in _relationship_ids(item, "status_updates")
            ]

    missing = sorted({ref for ref in expected if ref not in present})
    if missing:
        shown = ", ".join(f"{t}:{i}" for t, i in missing[:10])
        more = "" if len(missing) <= 10 else f" (+{len(missing) - 10} more)"
        raise CollectionError(
            f"GET {url} referenced {len(missing)} object(s) that are absent from "
            f"`included`, so the collected page is incomplete: {shown}{more}",
            "internal_error",
        )


def derive_availability(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The one additive block: what each component's own history adds up to.

    Better Stack's reported `availability` counts only days whose status is
    "downtime". Degraded days carry a downtime_duration in the same rows and are
    excluded from it, as is maintenance time — so the reported figure and the
    history can disagree without either being wrong. This recomputes the number
    with degraded time counted as unavailable, and reports the three totals it
    is built from so a reader can redo the arithmetic or draw the line
    elsewhere.

    Ordered worst-first (ascending effective_availability), which is what lets a
    validator reading the FIRST match assert a threshold for every component:
    Paramify's validator engine reads capture groups from the first match only.
    """
    derived: List[Dict[str, Any]] = []
    for item in document.get("included") or []:
        if not isinstance(item, dict) or item.get("type") != "status_page_resource":
            continue
        attributes = item.get("attributes")
        if not isinstance(attributes, dict):
            continue
        history = attributes.get("status_history")
        history = history if isinstance(history, list) else []

        downtime_seconds = 0.0
        degraded_seconds = 0.0
        maintenance_seconds = 0.0
        for row in history:
            if not isinstance(row, dict):
                continue
            status = row.get("status")
            down = float(row.get("downtime_duration") or 0)
            maintenance = float(row.get("maintenance_duration") or 0)
            maintenance_seconds += maintenance
            if status == "downtime":
                downtime_seconds += down
            elif status == "degraded":
                degraded_seconds += down

        history_days = len(history)
        window = history_days * SECONDS_PER_DAY
        unavailable = downtime_seconds + degraded_seconds
        effective = round(1 - unavailable / window, AVAILABILITY_PRECISION) if window else None

        derived.append(
            {
                "status_page_resource_id": str(item.get("id")),
                "public_name": attributes.get("public_name"),
                "history_days": history_days,
                "downtime_seconds": round(downtime_seconds, 6),
                "degraded_seconds": round(degraded_seconds, 6),
                "maintenance_seconds": round(maintenance_seconds, 6),
                "effective_availability": effective,
            }
        )

    # Worst first; `position` breaks ties so the order is deterministic across
    # runs of an unchanged page. A component with no history sorts last — there
    # is nothing to fail a threshold with.
    derived.sort(
        key=lambda row: (
            row["effective_availability"] is None,
            row["effective_availability"] if row["effective_availability"] is not None else 0,
            row["status_page_resource_id"],
        )
    )
    return derived


def build_evidence(
    document: Dict[str, Any],
    *,
    target_name: str,
    status_page_url: str,
    source_url: str,
    http_status: int,
) -> Dict[str, Any]:
    """The evidence dict: the page's own document, plus provenance and derivation.

    `data` and `included` are the response verbatim — same keys, same nesting,
    nothing removed or renamed — so an assessor is reading what the status page
    publishes rather than this fetcher's opinion of it.
    """
    return {
        "collected_at": current_timestamp(),
        "target_name": target_name,
        "status_page_url": status_page_url,
        "source_url": source_url,
        "http_status": http_status,
        "availability_derived": derive_availability(document),
        "data": document.get("data"),
        "included": document.get("included"),
    }


def write_evidence(output_dir: Path, target_name: str, evidence: Dict[str, Any]) -> Path:
    path = output_dir / f"betterstack_public_status_page_{sanitize_for_filename(target_name)}.json"
    with open(path, "w") as handle:
        json.dump(evidence, handle, indent=2, default=str)
    return path


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    target_name = os.environ.get("BETTERSTACK_TARGET_NAME", "").strip() or "status_page"
    status_page_url = os.environ.get("BETTERSTACK_STATUS_PAGE_URL", "").strip()
    source_url = status_page_url
    http_status = 0

    try:
        target_name = get_env("BETTERSTACK_TARGET_NAME")
        status_page_url = get_env("BETTERSTACK_STATUS_PAGE_URL")
        verify_ssl = env_bool("BETTERSTACK_VERIFY_SSL", True)

        source_url = resolve_index_url(status_page_url)
        document, http_status = fetch_index(source_url, verify_ssl)
        assert_is_status_page(document, source_url)
        assert_included_is_complete(document, source_url)
    except CollectionError as exc:
        # Still write a valid evidence file: the contract's payload ledger is
        # what a reader of the file sees, and an unreadable file would hide the
        # failure from everyone who is not looking at the envelope.
        failed = {
            "collected_at": current_timestamp(),
            "target_name": target_name,
            "status_page_url": status_page_url,
            "source_url": source_url,
            "http_status": http_status,
            "availability_derived": [],
            "data": None,
            "included": [],
            "metadata": {
                "partial_failure": True,
                "api_failures": [
                    {
                        "operation": f"GET {source_url or status_page_url}",
                        "type": exc.code,
                        "message": str(exc),
                    }
                ],
            },
        }
        path = write_evidence(output_dir, target_name, failed)
        logger.info("Evidence saved to %s", path)
        # report_failure logs too, and logging LAST is what makes the reason —
        # not the line above — the tail of stderr the runner falls back to.
        report_failure(str(exc), exc.code)
        return 1
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still reportable
        report_failure(f"Unexpected error collecting {source_url or status_page_url}: {exc}", "internal_error")
        return 1

    evidence = build_evidence(
        document,
        target_name=target_name,
        status_page_url=status_page_url,
        source_url=source_url,
        http_status=http_status,
    )
    path = write_evidence(output_dir, target_name, evidence)
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
