"""Every list a fetcher reads must be read to the last page.

The recorded tenancy is small: nearly every list fits on one page, so a call
that read only the first page would pass every other test here and silently
drop everything past it on a real estate. So each cassette is replayed a second
time with every multi-item list re-served one item per page — `opc-next-page`
tokens for OCI's own APIs, `startIndex`/`totalResults` for SCIM — and the
evidence must come out identical.

Proven to bite: making `list_all` return the first page only changes eleven of
the seventeen fetchers' evidence here, and the other six through
`compartments_scanned`; cutting the SCIM loop in `iam_password_policy` to one
page changes its findings.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("oci", reason="the OCI SDK deserializes the recorded responses")

_spec = importlib.util.spec_from_file_location(
    "oci_fetcher_subprocess_helpers", Path(__file__).parent / "test_oci_fetchers.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)

signing_key = _helpers.signing_key  # re-exported so the fixture resolves here


def _with_param(key: str, name: str, value) -> str:
    """The cassette key with one query parameter set, in request_key's sorted order."""
    head, _, query = key.partition("?")
    pairs = [p for p in query.split("&") if p and not p.startswith(f"{name}=")] + [f"{name}={value}"]
    return head + "?" + "&".join(sorted(pairs, key=lambda p: p.split("=")[0]))


def _one_item_per_page(interaction: dict) -> list[dict]:
    try:
        body = json.loads(interaction["body"])
    except ValueError:
        return [interaction]
    scim = isinstance(body, dict) and isinstance(body.get("Resources"), list)
    if scim:
        items = body["Resources"]
    elif isinstance(body, list):
        items = body
    elif isinstance(body, dict) and isinstance(body.get("items"), list):
        items = body["items"]
    else:
        return [interaction]
    if interaction["status"] != 200 or len(items) < 2 or (scim and "startIndex=1" not in interaction["key"]):
        return [interaction]

    tag = hashlib.sha1(interaction["key"].encode()).hexdigest()[:8]
    carried = {k: v for k, v in interaction["headers"].items() if k.lower() == "opc-next-page"}
    pages = []
    for n, item in enumerate(items, 1):
        if scim:
            key = interaction["key"] if n == 1 else _with_param(interaction["key"], "startIndex", n)
            page = dict(body, Resources=[item], totalResults=len(items), startIndex=n, itemsPerPage=1)
            headers = dict(interaction["headers"])
        else:
            key = interaction["key"] if n == 1 else _with_param(interaction["key"], "page", f"split{tag}p{n}")
            page = [item] if isinstance(body, list) else dict(body, items=[item])
            headers = {k: v for k, v in interaction["headers"].items() if k.lower() != "opc-next-page"}
            # The last split page hands on to whatever came after the original.
            headers.update({"opc-next-page": f"split{tag}p{n + 1}"} if n < len(items) else carried)
        pages.append({"key": key, "status": 200, "headers": headers, "body": json.dumps(page)})
    return pages


def _evidence(name, cassette, signing_key, out):
    out.mkdir()
    result = _helpers.run_fetcher(name, signing_key, out, OCI_CASSETTE=str(cassette))
    assert result.returncode == 0, f"{name} exited {result.returncode}\n{result.stderr[-1500:]}"
    return _helpers.evidence_of(out)


@pytest.mark.parametrize("name", _helpers.FETCHERS)
def test_evidence_is_identical_when_every_list_is_paginated(name, signing_key, tmp_path):
    original = _helpers.CASSETTE_DIR / f"{name}.json"
    data = json.loads(original.read_text())
    before = len(data["interactions"])
    data["interactions"] = [page for i in data["interactions"] for page in _one_item_per_page(i)]
    assert len(data["interactions"]) > before, f"{name}'s cassette has no multi-item list to paginate"
    paged = tmp_path / f"{name}-paged.json"
    paged.write_text(json.dumps(data))

    whole = _evidence(name, original, signing_key, tmp_path / "whole")
    split = _evidence(name, paged, signing_key, tmp_path / "split")

    assert split["metadata"]["api_failures"] == []
    assert split["summary"] == whole["summary"]
    assert split["results"] == whole["results"]
    assert split["metadata"].get("compartments_scanned") == whole["metadata"].get("compartments_scanned")
