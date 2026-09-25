#!/usr/bin/env python3
"""Better Stack public status page.

One unauthenticated GET against <status_page_url>/index.json — the JSON:API
document a hosted Better Stack status page renders itself from — recorded
verbatim, plus one selected component so a validator has a single field to
compare.

Generic by design: nothing here knows about any particular status page. The
page URL and a label come from the target, and every component the page
publishes is read out of the response.

Single-target per invocation; fanout across pages happens at the runner layer
(see fetcher.yaml: supports_targets: true).

Speaks to KSI-CNA-OFA (Optimizing for Availability); the mapping itself lives
in fetcher.yaml's `ksis:` field, which is what the framework reads.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("betterstack_public_status_page")

REQUEST_TIMEOUT = 30


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
    # Rebuild from the parsed parts rather than string-appending: a page URL
    # carrying a query or fragment (https://status.example.com?preview=1) would
    # otherwise become ".../?preview=1/index.json", which is a different and
    # non-existent path.
    path = parsed.path.rstrip("/")
    if not path.endswith("/index.json"):
        path = f"{path}/index.json"
    return urlunparse(parsed._replace(path=path))


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


def _resource_id_sort_key(resource_id: str) -> Tuple[int, int, str]:
    """Order ids numerically where they are numeric, and never raise.

    Better Stack ids are numeric strings, so "451733" must sort below "8655373"
    rather than above it the way a plain string comparison would. A
    non-numeric id sorts after every numeric one, deterministically.

    `isascii()` is not redundant beside `isdigit()`: `isdigit()` is true for
    characters like "\u00b2" that `int()` then refuses, and this function must
    never be the thing that raises.
    """
    if resource_id.isascii() and resource_id.isdigit():
        return (0, int(resource_id), resource_id)
    return (1, 0, resource_id)


def lowest_reported_availability(document: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The component with the lowest availability Better Stack itself reports.

    A SELECTION, not a calculation. The `availability` value is copied out of
    the response byte for byte — it is the same number the status page UI
    renders (0.999915 shows as "99.991% uptime"), and nothing here recomputes,
    rescales or rounds it.

    It exists because a Paramify `MATCH_GROUP` rule reads one capture group
    from the first match, while the number of components varies per page.
    Naming the weakest component in one top-level field gives such a rule a
    single field to compare that still speaks for the whole page: if the lowest
    reported availability clears a threshold, every component does.

    Ties go to the lowest resource id, so an unchanged page selects the same
    component on every run. Returns None when no component reports a numeric
    availability — better no field than an invented one, and the validators'
    presence guard turns the absence into a FAIL rather than a silent pass.
    """
    candidates: List[Tuple[Any, Tuple[int, int, str], Dict[str, Any]]] = []
    for item in document.get("included") or []:
        if not isinstance(item, dict) or item.get("type") != "status_page_resource":
            continue
        attributes = item.get("attributes")
        if not isinstance(attributes, dict):
            continue
        availability = attributes.get("availability")
        # bool is an int subclass, and a JSON true here would be meaningless.
        if isinstance(availability, bool) or not isinstance(availability, (int, float)):
            continue
        resource_id = str(item.get("id"))
        candidates.append(
            (
                availability,
                _resource_id_sort_key(resource_id),
                {
                    "public_name": attributes.get("public_name"),
                    "status_page_resource_id": resource_id,
                    # Verbatim from the response: the figure the page displays.
                    "availability": availability,
                },
            )
        )

    if not candidates:
        return None
    return min(candidates, key=lambda row: (row[0], row[1]))[2]


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
    publishes rather than this fetcher's opinion of it. The one added field,
    `lowest_reported_availability`, is a selection out of that same document
    and carries no arithmetic.
    """
    evidence: Dict[str, Any] = {
        "collected_at": current_timestamp(),
        "target_name": target_name,
        "status_page_url": status_page_url,
        "source_url": source_url,
        "http_status": http_status,
    }
    lowest = lowest_reported_availability(document)
    if lowest is not None:
        # Placed ahead of the verbatim document on purpose: a validator's
        # MATCH_GROUP reads the FIRST match, and this block must be what it
        # finds rather than whichever component happens to come first in
        # `included`.
        evidence["lowest_reported_availability"] = lowest
    evidence["data"] = document.get("data")
    evidence["included"] = document.get("included")
    return evidence


def write_evidence(output_dir: Path, target_name: str, evidence: Dict[str, Any]) -> Path:
    path = output_dir / f"betterstack_public_status_page_{sanitize_for_filename(target_name)}.json"
    with open(path, "w") as handle:
        json.dump(evidence, handle, indent=2, default=str)
    return path


def _failure_evidence(
    *,
    target_name: str,
    status_page_url: str,
    source_url: str,
    http_status: int,
    reason: str,
    code: str,
) -> Dict[str, Any]:
    """An honest evidence file for a run that collected nothing.

    Written on every failure path, so the file on disk says why rather than
    being absent or — worse — present and empty. Shape per the contract's
    payload ledger (docs/fetcher_contract.md § Output).
    """
    return {
        "collected_at": current_timestamp(),
        "target_name": target_name,
        "status_page_url": status_page_url,
        "source_url": source_url,
        "http_status": http_status,
        "data": None,
        "included": [],
        "metadata": {
            "partial_failure": True,
            "api_failures": [
                {
                    "operation": f"GET {source_url or status_page_url}",
                    "type": code,
                    "message": reason,
                }
            ],
        },
    }


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

    # Everything that can fail is inside one try, the write included. Anything
    # escaping it would exit non-zero with no $FETCHER_STATUS_FILE and no
    # evidence file, leaving the runner to report a traceback's last line as the
    # reason — which is the failure mode report_failure exists to prevent.
    try:
        target_name = get_env("BETTERSTACK_TARGET_NAME")
        status_page_url = get_env("BETTERSTACK_STATUS_PAGE_URL")
        verify_ssl = env_bool("BETTERSTACK_VERIFY_SSL", True)

        source_url = resolve_index_url(status_page_url)
        document, http_status = fetch_index(source_url, verify_ssl)
        assert_is_status_page(document, source_url)
        assert_included_is_complete(document, source_url)

        evidence = build_evidence(
            document,
            target_name=target_name,
            status_page_url=status_page_url,
            source_url=source_url,
            http_status=http_status,
        )
        path = write_evidence(output_dir, target_name, evidence)
    except CollectionError as exc:
        reason, code = str(exc), exc.code
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still reportable
        # A malformed history row (a duration that is not a number), an
        # unwritable EVIDENCE_DIR, anything unforeseen. It is still a failed
        # collection and still has to be reported through the contract's
        # channels rather than as a stack trace.
        reason = (
            f"Unexpected error collecting {source_url or status_page_url}: "
            f"{type(exc).__name__}: {exc}"
        )
        code = "internal_error"
    else:
        logger.info("Evidence saved to %s", path)
        return 0

    try:
        path = write_evidence(
            output_dir,
            target_name,
            _failure_evidence(
                target_name=target_name,
                status_page_url=status_page_url,
                source_url=source_url,
                http_status=http_status,
                reason=reason,
                code=code,
            ),
        )
        logger.info("Evidence saved to %s", path)
    except OSError as exc:
        # The exit code and the status file are the authoritative signals; not
        # being able to write the file must not replace the real reason.
        logger.info("Could not write the failure evidence file: %s", exc)
    # report_failure logs too, and logging LAST is what makes the reason — not
    # the "Evidence saved" line above — the tail of stderr the runner falls
    # back to when no status file was written.
    report_failure(reason, code)
    return 1


if __name__ == "__main__":
    sys.exit(main())
