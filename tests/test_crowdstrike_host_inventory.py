"""Offline tests for crowdstrike_host_inventory.

The clean run must give a complete inventory. Every failure (a failed page, a
failed batch, a partial 200, a host without an ID, an ID that resolves to
nothing, a rejected credential) must write `data: []` with
`records_included: false` and exit non-zero. framework.inventory.check() is the
verdict the uploader acts on.

The fake Falcon API is the `falcon_fake` fixture (tests/conftest.py, tests/falcon_fake.py).
The fixtures are synthetic and live in fetchers/crowdstrike/host_inventory/tests/fixtures/.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from framework import inventory

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_DIR = REPO_ROOT / "fetchers" / "crowdstrike" / "host_inventory"

SCROLL = "/devices/queries/devices-scroll/v1"
ENTITIES = "/devices/entities/devices/v2"


def _serve(falcon_fake, devices: List[Dict[str, Any]], page_size: int = 3) -> None:
    """Scroll in pages of `page_size` IDs, then resolve IDs to the given devices."""
    ids = [d["device_id"] for d in devices]

    def scroll(params, _body):
        start = int(params.get("offset") or 0)
        nxt = start + page_size
        token = str(nxt) if nxt < len(ids) else ""
        return 200, falcon_fake.envelope(ids[start:nxt], {"offset": token, "total": len(ids)})

    def entities(_params, body):
        wanted = set(body["ids"])
        return 200, falcon_fake.envelope([d for d in devices if d["device_id"] in wanted])

    falcon_fake.route(SCROLL, scroll)
    falcon_fake.route(ENTITIES, entities)


def _run(falcon_fake) -> tuple[int, Dict[str, Any]]:
    mod = falcon_fake.load_fetcher("host_inventory")
    code = mod.main()
    payload = json.loads((falcon_fake.output_dir / mod.OUTPUT_FILE).read_text())
    return code, payload


def _assert_withheld(code: int, payload: Dict[str, Any]) -> None:
    assert code == 1
    assert payload["records_included"] is False
    assert payload["data"] == []
    assert payload["error"]
    assert inventory.check(payload, code)["complete"] is False


@pytest.fixture
def devices(falcon_fake) -> List[Dict[str, Any]]:
    return falcon_fake.load_fixture("host_inventory", "devices.json")


def test_clean_run_is_a_complete_inventory(falcon_fake, devices) -> None:
    _serve(falcon_fake, devices)
    code, payload = _run(falcon_fake)

    assert code == 0, falcon_fake.status()
    assert payload["records_included"] is True
    assert inventory.payload_problems(payload) == []
    assert inventory.check(payload, code)["complete"] is True

    records = payload["data"]
    assert len(records) == payload["record_count"] == payload["queried_id_count"] == len(devices)
    assert [r["unique_asset_identifier"] for r in records] == sorted(d["device_id"] for d in devices)
    assert {r["asset_type"] for r in records} == {"endpoint"}
    # The same keys on every record, so a preset built from one sample holds for every run.
    assert len({tuple(sorted(r)) for r in records}) == 1
    # Every value a preset maps is a flat scalar.
    assert all(not isinstance(v, (dict, list)) for r in records for v in r.values())

    web = next(r for r in records if r["hostname"] == "web-prod-01")
    assert web["unique_asset_identifier"] == "3f1c9a7e5b2d4c6e8a0b1c2d3e4f5a61"
    assert web["primary_ip_address"] == "10.0.1.20"
    assert web["os_platform"] == "Linux"
    assert web["last_seen_at"] == "2026-11-22T21:15:04Z"
    assert web["cloud_instance_id"] == "i-0000000000000001"
    assert web["tags"] == "SensorGroupingTags/web; FalconGroupingTags/prod"
    laptop = next(r for r in records if r["hostname"] == "laptop-17")
    assert laptop["cloud_instance_id"] is None and laptop["tags"] is None

    # Both pages were read, and IDs were resolved in one batch of five.
    scroll_calls = [c for c in falcon_fake.calls if c[1] == SCROLL]
    assert [c[2].get("offset") for c in scroll_calls] == [None, "3"]
    entity_calls = [c for c in falcon_fake.calls if c[1] == ENTITIES]
    assert len(entity_calls) == 1 and len(entity_calls[0][3]["ids"]) == 5


def test_a_failed_second_page_withholds_every_record(falcon_fake, devices) -> None:
    _serve(falcon_fake, devices)
    serve_page = falcon_fake.routes[SCROLL]

    def scroll(params, body):
        if params.get("offset"):
            return 400, falcon_fake.envelope([], errors=[{"code": 400, "message": "invalid offset"}])
        return serve_page(params, body)

    falcon_fake.route(SCROLL, scroll)
    code, payload = _run(falcon_fake)

    _assert_withheld(code, payload)
    assert falcon_fake.status()["code"] == "partial_failure"
    assert payload["api_failures"][0]["status_code"] == 400


def test_a_failed_entity_batch_withholds_every_record(falcon_fake, devices) -> None:
    _serve(falcon_fake, devices)
    falcon_fake.route(ENTITIES, lambda _p, _b: (500, falcon_fake.envelope([], errors=[{"code": 500, "message": "boom"}])))
    code, payload = _run(falcon_fake)
    _assert_withheld(code, payload)


def test_a_partial_200_withholds_every_record(falcon_fake, devices) -> None:
    """Falcon reports some IDs not found as HTTP 200 with errors[]."""
    _serve(falcon_fake, devices)

    def entities(_params, body):
        found = [d for d in devices if d["device_id"] in set(body["ids"])][:-1]
        return 200, falcon_fake.envelope(found, errors=[{"code": 404, "message": "device not found"}])

    falcon_fake.route(ENTITIES, entities)
    code, payload = _run(falcon_fake)
    _assert_withheld(code, payload)


def test_an_id_that_resolves_to_nothing_withholds_every_record(falcon_fake, devices) -> None:
    """A host dropped between the query and the lookup, with no error in the body."""
    _serve(falcon_fake, devices)
    falcon_fake.route(ENTITIES, lambda _p, body: (200, falcon_fake.envelope(
        [d for d in devices if d["device_id"] in set(body["ids"])][1:])))
    code, payload = _run(falcon_fake)
    _assert_withheld(code, payload)
    assert "came back with no host record" in payload["error"]


def test_a_host_without_a_device_id_withholds_every_record(falcon_fake, devices) -> None:
    _serve(falcon_fake, devices)
    broken = [dict(d) for d in devices]
    broken[2]["device_id"] = ""
    falcon_fake.route(ENTITIES, lambda _p, _b: (200, falcon_fake.envelope(broken)))
    code, payload = _run(falcon_fake)
    _assert_withheld(code, payload)
    assert "without a device_id" in payload["error"]


def test_a_rejected_credential_withholds_every_record(falcon_fake, devices) -> None:
    _serve(falcon_fake, devices)
    falcon_fake.token_status = 401
    code, payload = _run(falcon_fake)
    _assert_withheld(code, payload)
    assert falcon_fake.status()["code"] == "auth_failed"


def test_a_forbidden_scope_is_reported_as_not_authorized(falcon_fake, devices) -> None:
    _serve(falcon_fake, devices)
    falcon_fake.route(SCROLL, lambda _p, _b: (403, falcon_fake.envelope([], errors=[{"code": 403, "message": "access denied"}])))
    code, payload = _run(falcon_fake)
    _assert_withheld(code, payload)
    assert falcon_fake.status()["code"] == "not_authorized"


def test_an_empty_estate_is_not_sent(falcon_fake) -> None:
    _serve(falcon_fake, [])
    code, payload = _run(falcon_fake)
    assert code == 0
    assert payload["data"] == [] and payload["records_included"] is True
    assert inventory.check(payload, code)["complete"] is False


def test_the_id_is_written_in_lowercase(falcon_fake, devices) -> None:
    """The Spotlight report writes aid through the same host_id(), so the two always match."""
    mod = falcon_fake.load_fetcher("host_inventory")
    device = dict(devices[0], device_id="  3F1C9A7E5B2D4C6E8A0B1C2D3E4F5A61 ")
    assert mod.record(device)["unique_asset_identifier"] == devices[0]["device_id"]


# --- vendor schema -----------------------------------------------------------
#
# The fixture and the fetcher were written together, so they can be wrong
# together. These check both against CrowdStrike's own models
# (tools/crowdstrike_models.json, generated from gofalcon).


def _models() -> Dict[str, Any]:
    return json.loads((REPO_ROOT / "tools" / "crowdstrike_models.json").read_text())["models"]


def test_every_device_field_read_is_in_the_vendor_model() -> None:
    source = (FETCHER_DIR / "fetcher.py").read_text()
    read = {
        node.args[0].value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "get"
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "device"
        and node.args and isinstance(node.args[0], ast.Constant)
    }
    assert len(read) > 20
    unknown = sorted(read - set(_models()["DeviceapiDeviceSwagger"]))
    assert not unknown, f"fields absent from DeviceapiDeviceSwagger: {unknown}"


def test_fixture_conforms_to_the_vendor_model(falcon_fake, devices) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("cs_schema_for_inventory", REPO_ROOT / "tools" / "crowdstrike_schema.py")
    schema = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(schema)
    models = schema.load_models()
    problems = [p for i, d in enumerate(devices) for p in schema.validate(d, "DeviceapiDeviceSwagger", models, f"[{i}]")]
    assert problems == []
