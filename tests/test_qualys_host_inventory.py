"""qualys_host_inventory against recorded-shape XML pages, with no network.

The fixtures (fetchers/qualys/host_inventory/tests/fixtures) follow the Qualys
host list v5 and VM detection v6 output DTDs; the values are synthetic.

What this proves: every record is keyed by the Qualys host ID, which is the
`Host ID` column of qualys_vmdr_vulnerability_findings for the same host; every
record has the same keys and a non-empty asset_type; and a run that misses any
page or host writes no records and exits non-zero.
Run: ``pytest tests/test_qualys_host_inventory.py``
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from framework import inventory
from framework.config_loader import discover_fetchers

REPO_ROOT = Path(__file__).resolve().parent.parent
QUALYS = REPO_ROOT / "fetchers" / "qualys"
FIXTURES = QUALYS / "host_inventory" / "tests" / "fixtures"
sys.path.insert(0, str(QUALYS / "_shared"))

import qualys_report_client as qrc  # noqa: E402
import reports  # noqa: E402
from qualys_client import QualysClient  # noqa: E402

API = "https://qualysapi.qualys.com"
HOST_PATH = "/api/5.0/fo/asset/host/"
USER, PASSWORD = "acme_ro1", "pw"


def _load():
    spec = importlib.util.spec_from_file_location("qualys_host_inventory_test", QUALYS / "host_inventory" / "fetcher.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inv = _load()


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status_code = status
        self.content = body
        self.headers: dict = {}


class FakeQualys:
    """Serves the host list: page 1 without id_min, page 2 with id_min=103."""

    def __init__(self) -> None:
        self.pages = {None: (200, fixture("hosts_page1.xml")), "103": (200, fixture("hosts_page2.xml"))}
        self.calls: list = []

    def get(self, url, params=None, auth=None, headers=None, timeout=None, allow_redirects=True):
        assert allow_redirects is False and headers["X-Requested-With"]
        assert url == API + HOST_PATH
        self.calls.append(dict(params))
        if auth != (USER, PASSWORD):
            return FakeResponse(401, b"<SIMPLE_RETURN><RESPONSE><CODE>2000</CODE>"
                                     b"<TEXT>Bad Login/Password</TEXT></RESPONSE></SIMPLE_RETURN>")
        return FakeResponse(*self.pages[params.get("id_min")])


@pytest.fixture()
def qualys(monkeypatch, tmp_path):
    fake = FakeQualys()
    monkeypatch.setenv("QUALYS_API_URL", API)
    monkeypatch.setenv("QUALYS_USERNAME", USER)
    monkeypatch.setenv("QUALYS_PASSWORD", PASSWORD)
    monkeypatch.delenv("QUALYS_PRIVATE_CLOUD_HOST", raising=False)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    real = QualysClient.from_env.__func__

    def from_env(cls):
        client = real(cls)
        client.session, client.sleep = fake, lambda _s: None
        return client

    monkeypatch.setattr(QualysClient, "from_env", classmethod(from_env))
    return fake


def run(tmp_path: Path) -> tuple[int, dict, dict]:
    code = inv.main()
    payload = json.loads((tmp_path / "evidence" / "qualys_host_inventory.json").read_text())
    status_file = tmp_path / "status.json"
    status = json.loads(status_file.read_text()) if status_file.exists() else {}
    return code, payload, status


def assert_withheld(code: int, payload: dict) -> None:
    assert code == 1
    assert payload["records_included"] is False and payload["data"] == []
    assert inventory.check(payload, code)["complete"] is False


def test_declares_the_qualys_host_id_scheme():
    f = discover_fetchers(REPO_ROOT)["qualys_host_inventory"]
    assert f.is_inventory and f.is_pipeline
    assert (f.pipeline.type, f.pipeline.id_scheme) == ("inventory", "qualys-host-id")


def test_every_host_is_one_record_keyed_by_host_id(qualys, tmp_path):
    code, payload, status = run(tmp_path)
    assert code == 0, status
    data = payload["data"]
    assert [r["unique_asset_identifier"] for r in data] == ["101", "102", "103"]
    assert {r["asset_type"] for r in data} == {"host"}
    assert len({tuple(sorted(r)) for r in data}) == 1, "every record has the same keys"
    assert all(not isinstance(v, (list, dict)) for r in data for v in r.values()), "flat for a preset"
    web = data[0]
    assert web == {
        "unique_asset_identifier": "101", "asset_type": "host", "name": "web1.example.test",
        "ip": "192.0.2.10", "ipv6": None, "dns": "web1.example.test", "netbios": "WEB1",
        "os": "Ubuntu Linux 22.04", "tracking_method": "IP", "asset_id": "9001",
        "last_vuln_scan_datetime": "2026-11-18T02:10:00Z", "last_vm_scanned_date": "2026-11-18T02:30:00Z",
        "last_vm_auth_scanned_date": "2026-11-18T02:30:00Z",
    }
    agent = data[2]
    assert (agent["ip"], agent["ipv6"], agent["dns"], agent["name"]) == ("2001:db8::3", "2001:db8::3", None, "103")
    assert (payload["record_count"], payload["pages"], payload["records_included"]) == (3, 2, True)
    assert inventory.check(payload, code)["complete"] is True
    # Page 2 re-sends every filter with the cursor from page 1's WARNING/URL.
    assert qualys.calls[0]["details"] == "All" and qualys.calls[0]["show_asset_id"] == "1"
    assert qualys.calls[1] == {**qualys.calls[0], "id_min": "103"}


def test_inventory_id_is_the_report_host_id():
    """The same host, read by the inventory and by qualys_vmdr_vulnerability_findings."""

    class ReportClient:
        base_url, page_size, max_records = API, 1000, 1000

        def pages(self, path, params, root):
            assert path == qrc.DETECTIONS
            yield qrc.parse_xml(fixture("vmdr_detections.xml")).find("RESPONSE")

        def xml(self, path, params, root):
            assert path == qrc.KNOWLEDGE_BASE
            return qrc.parse_xml(fixture("knowledge_base.xml")).find("RESPONSE")

    [row] = reports.collect_vm(ReportClient())
    host = qrc.parse_xml(fixture("hosts_page1.xml")).find("RESPONSE/HOST_LIST/HOST")
    rec = inv.record(host)
    assert rec["unique_asset_identifier"] == row["Host ID"] == "101"
    assert (rec["name"], rec["ip"], rec["asset_id"]) == (row["Host Name"], row["IP"], row["Asset ID"])


def test_failed_second_page_withholds_every_record(qualys, tmp_path):
    qualys.pages["103"] = (503, b"Service Unavailable")
    code, payload, status = run(tmp_path)
    assert_withheld(code, payload)
    assert payload["record_count"] == 2, "the count shows how far collection got"
    assert status["code"] == "target_unreachable"
    assert "records withheld" in status["error"]


def test_truncated_page_without_next_url_withholds_records(qualys, tmp_path):
    body = fixture("hosts_page1.xml")
    start, end = body.index(b"<URL>"), body.index(b"</URL>") + len(b"</URL>")
    qualys.pages[None] = (200, body[:start] + body[end:])
    code, payload, status = run(tmp_path)
    assert_withheld(code, payload)
    assert status["code"] == "partial_failure"


def test_host_without_an_id_withholds_records(qualys, tmp_path):
    qualys.pages["103"] = (200, fixture("host_without_id.xml"))
    code, payload, status = run(tmp_path)
    assert_withheld(code, payload)
    assert status["code"] == "partial_failure" and "without an ID" in status["error"]


def test_repeated_host_withholds_records(qualys, tmp_path):
    qualys.pages["103"] = qualys.pages[None]
    code, payload, status = run(tmp_path)
    assert_withheld(code, payload)
    assert status["code"] == "partial_failure" and "twice" in status["error"]


def test_rejected_login_withholds_records(qualys, tmp_path, monkeypatch):
    monkeypatch.setenv("QUALYS_PASSWORD", "wrong")
    code, payload, status = run(tmp_path)
    assert_withheld(code, payload)
    assert status["code"] == "auth_failed"
    assert "wrong" not in json.dumps(payload)


def test_missing_api_url_is_bad_config(qualys, tmp_path, monkeypatch):
    monkeypatch.setenv("QUALYS_API_URL", "")
    code, payload, status = run(tmp_path)
    assert_withheld(code, payload)
    assert status["code"] == "bad_config" and payload["api_url"] is None
    assert qualys.calls == []
