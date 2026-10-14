#!/usr/bin/env python3
"""FedRAMP Marketplace certification status for the FedRAMP systems recorded as elements in a Paramify workspace."""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from marketplace import (  # noqa: E402
    MARKETPLACE_PRODUCT_URL,
    NOT_LISTED,
    PACKAGE_ID_PATTERN,
    CollectionError,
    Marketplace,
    fail,
    output_mode_from_env,
    parse_pairs,
    write_outputs,
)

logger = logging.getLogger("fedramp_marketplace_workspace_vendor_certification_status")

FILE_STEM = "fedramp_marketplace_workspace_vendor_certification_status"
DEFAULT_API_BASE_URL = "https://app.paramify.com/api/v0"
DEFAULT_SUBTYPES = "COM_FEDRAMP_SYSTEM"


def fetch_elements(base_url: str, token: str, timeout: int) -> List[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/elements"
    try:
        response = requests.get(
            url, timeout=timeout, headers={"Accept": "application/json", "Authorization": f"Bearer {token}"}
        )
    except requests.exceptions.RequestException as exc:
        raise CollectionError(f"GET {url} failed: {type(exc).__name__}: {exc}", "target_unreachable") from exc
    if response.status_code == 401:
        raise CollectionError(f"GET {url} returned HTTP 401: the Paramify API token was rejected", "auth_failed")
    if response.status_code == 403:
        raise CollectionError(f"GET {url} returned HTTP 403: the token cannot read elements", "not_authorized")
    if response.status_code != 200:
        raise CollectionError(
            f"GET {url} returned HTTP {response.status_code}; body starts: {response.text[:200]!r}",
            "target_unreachable",
        )
    try:
        elements = response.json().get("elements")
    except (ValueError, AttributeError) as exc:
        raise CollectionError(f"GET {url} returned a body with no `elements` object", "target_unreachable") from exc
    if not isinstance(elements, list):
        raise CollectionError(f"GET {url} returned a body with no `elements` list", "target_unreachable")
    return elements


def build_records(
    market: Marketplace, elements: List[Dict[str, Any]], subtypes: List[str], overrides: Dict[str, str]
) -> List[Dict[str, Any]]:
    # One vendor per distinct element name: a system recorded twice is still one vendor.
    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for element in elements:
        if isinstance(element, dict) and element.get("subtype") in subtypes and (element.get("name") or "").strip():
            by_name.setdefault(element["name"].strip(), []).append(element)

    records = []
    for name in sorted(by_name, key=str.lower):
        group = by_name[name]
        extra = {
            "source": "paramify_element",
            "element_subtype": group[0].get("subtype"),
            "paramify_element_ids": sorted(e.get("id") for e in group if e.get("id")),
        }
        named_id = PACKAGE_ID_PATTERN.search(name)
        if name.lower() in overrides:
            package_id, how, candidates = overrides[name.lower()], "config_override", []
        elif named_id:
            package_id, how, candidates = named_id.group(1), "id_in_name", []
        else:
            package_id, how, candidates = market.match_name(name)

        if package_id:
            records.append(market.record(name, package_id, match_method=how, match_candidates=candidates, **extra))
            continue
        records.append(
            {
                "vendor_name": name,
                "package_id": None,
                "marketplace_url": None,
                "listed_name": None,
                "certification_state": NOT_LISTED,
                "package_id_resolves": False,
                "suggested_package_ids": candidates,
                "suggested_marketplace_urls": [MARKETPLACE_PRODUCT_URL.format(package_id=c) for c in candidates],
                "match_method": how,
                "match_candidates": candidates,
                **extra,
            }
        )
    return records


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))

    try:
        output_mode = output_mode_from_env()
        token = (os.environ.get("PARAMIFY_API_TOKEN") or os.environ.get("PARAMIFY_UPLOAD_API_TOKEN") or "").strip()
        if not token:
            raise CollectionError("Missing required env var: PARAMIFY_API_TOKEN", "bad_config")
        base_url = os.environ.get("PARAMIFY_API_BASE_URL") or DEFAULT_API_BASE_URL
        timeout = int(os.environ.get("PARAMIFY_HTTP_TIMEOUT") or 120)
        subtypes = [
            s.strip().upper()
            for s in (os.environ.get("FEDRAMP_ELEMENT_SUBTYPES") or DEFAULT_SUBTYPES).split(",")
            if s.strip()
        ]
        overrides = {
            name.lower(): package_id
            for name, package_id in parse_pairs(
                os.environ.get("FEDRAMP_PACKAGE_ID_OVERRIDES", ""), "FEDRAMP_PACKAGE_ID_OVERRIDES"
            )
        }

        elements = fetch_elements(base_url, token, timeout)
        market = Marketplace.load()
        records = build_records(market, elements, subtypes, overrides)
        if not records:
            raise CollectionError(
                f"The workspace has no elements of subtype {', '.join(subtypes)}, so there is no vendor to check",
                "bad_config",
            )
        paths = write_outputs(
            output_dir, FILE_STEM, records, market, output_mode,
            vendor_source="paramify_workspace", element_subtypes=subtypes,
        )
    except CollectionError as exc:
        return fail(output_dir, FILE_STEM, str(exc), exc.code, "collect workspace FedRAMP vendors")
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still reportable
        return fail(
            output_dir, FILE_STEM, f"Unexpected error: {type(exc).__name__}: {exc}", "internal_error",
            "build workspace vendor certification evidence",
        )

    for path in paths:
        logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
