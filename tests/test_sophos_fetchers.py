"""The sophos fetchers end to end against a local Sophos Central double.

Response shapes follow Sophos's OpenAPI specs (endpoint-v1 1.85.0, whoami-v1).
This proves the fetchers parse what the spec says Sophos sends; field-level
fidelity still needs a run against a real tenant.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SOPHOS = REPO_ROOT / "fetchers" / "sophos"
sys.path.insert(0, str(SOPHOS / "_shared"))

from sophos_client import SophosClient, SophosError  # noqa: E402

NOW = datetime.now(timezone.utc)
ON_ACCESS_KEY = "endpoint.threat-protection.on-access-scanning.enabled"  # fixture name; the real key is measured live


def _iso(delta: timedelta) -> str:
    return (NOW - delta).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _endpoint(i: int, **over: Any) -> dict:
    ep = {
        "id": f"ep-{i}",
        "type": "computer",
        "tenant": {"id": "tenant-1"},
        "hostname": f"HOST-{i}",
        "serialNumber": f"SN{i}",
        "os": {"isServer": False, "platform": "windows", "name": "Windows 11 Pro"},
        "health": {
            "overall": "good",
            "threats": {"status": "good"},
            "services": {"status": "good", "serviceDetails": [
                {"name": "Sophos MCS Agent", "status": "running"},
                {"name": "Sophos File Scanner", "status": "running"},
            ]},
        },
        "tamperProtectionSupported": True,
        "tamperProtectionEnabled": True,
        "assignedProducts": [
            {"code": "coreAgent", "version": "2024.3.1", "status": "installed"},
            {"code": "interceptX", "version": "2024.3.2", "status": "installed"},
        ],
        "packages": {"protection": {"assignedId": "p1", "name": "Recommended", "status": "assigned"}},
        "lastSeenAt": _iso(timedelta(hours=2)),
        "lastAgentUpdateAt": _iso(timedelta(days=1)),
        "online": True,
        "ipv4Addresses": [f"10.0.0.{i}"],
        "macAddresses": [f"00:00:00:00:00:0{i}"],
        "associatedPerson": {"id": "u1", "name": "Pat Example", "viaLogin": "CORP\\pat"},
        "isolation": {"status": "notIsolated"},
    }
    ep.update(over)
    return ep


def _endpoints() -> list[dict]:
    bad_server = _endpoint(
        2, type="server",
        os={"isServer": True, "platform": "linux", "name": "Ubuntu 22.04"},
        health={"overall": "bad", "threats": {"status": "suspicious"},
                "services": {"status": "bad", "serviceDetails": [
                    {"name": "Sophos MCS Agent", "status": "running"},
                    {"name": "Sophos Anti-Virus", "status": "stopped"}]}},
        tamperProtectionEnabled=False,
        assignedProducts=[{"code": "coreAgent", "version": "2023.1", "status": "installed"},
                          {"code": "interceptX", "version": "2023.1", "status": "notInstalled"}],
        packages={"protection": {"name": "Recommended", "status": "upgradable"}},
        lastSeenAt=_iso(timedelta(days=10)),
        lastAgentUpdateAt=_iso(timedelta(days=40)),
        online=False,
    )
    return [_endpoint(1), bad_server, _endpoint(3)]


def _policies() -> list[dict]:
    def policy(pid, ptype, *, enabled=True, days=("monday",), on_access=True, priority=1):
        settings = {
            "endpoint.scans.scheduled.days": {"value": list(days), "format": "string"},
            "endpoint.scans.scheduled.hour": {"value": "21:00"},
            ON_ACCESS_KEY: {"value": on_access, "recommendedValue": True},
        }
        return {"id": pid, "name": pid, "type": ptype, "enabled": enabled, "priority": priority,
                "settings": settings, "appliesTo": {"endpoints": [], "endpointGroups": []}}
    return [
        policy("tp-custom", "threat-protection", days=(), on_access=False),
        policy("tp-base", "threat-protection", priority=0),
        policy("stp-base", "server-threat-protection", priority=0),
    ]


STATE: dict = {}


def _reset() -> None:
    STATE.clear()
    STATE.update(endpoints=_endpoints(), policies=_policies(), id_type="tenant", log=[],
                 total_override=None, tamper_403=False, throttle=0)


class SophosDouble(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, status: int, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _base(self) -> str:
        return f"http://{self.headers['Host']}"

    def do_POST(self) -> None:  # noqa: N802
        body = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        if body.get("client_id") == ["bad"]:
            self._send(401, {"error": "invalid_client"})
            return
        self._send(200, {"access_token": "tok", "token_type": "bearer", "expires_in": 3600})

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        STATE["log"].append({"path": url.path, "query": q, "tenant": self.headers.get("X-Tenant-ID")})
        path = url.path
        if path == "/whoami/v1":
            if STATE["id_type"] == "tenant":
                self._send(200, {"id": "tenant-1", "idType": "tenant",
                                 "apiHosts": {"global": self._base(), "dataRegion": self._base()}})
            else:
                self._send(200, {"id": "partner-1", "idType": "partner", "apiHosts": {"global": self._base()}})
        elif path.startswith("/partner/v1/tenants/"):
            self._send(200, {"id": path.rsplit("/", 1)[1], "apiHost": self._base(), "dataRegion": "us01"})
        elif path == "/endpoint/v1/endpoints":
            if STATE["throttle"] > 0:
                STATE["throttle"] -= 1
                self._send(429, {"error": "TooManyRequests"})
                return
            eps = STATE["endpoints"]
            start = int(q.get("pageFromKey", 0))
            page = eps[start:start + 2]
            pages = {"fromKey": str(start), "size": len(page), "maxSize": 2}
            if start + 2 < len(eps):
                pages["nextKey"] = str(start + 2)
            if q.get("pageTotal") == "true":
                pages["items"] = STATE["total_override"] or len(eps)
                pages["total"] = (len(eps) + 1) // 2
            self._send(200, {"items": page, "pages": pages})
        elif path.startswith("/endpoint/v1/endpoints/") and path.endswith("/tamper-protection"):
            self._send(200, {"enabled": True, "password": "secret", "previousPasswords": []})
        elif path == "/endpoint/v1/settings/tamper-protection":
            self._send(403, {"error": "forbidden"}) if STATE["tamper_403"] else self._send(200, {"enabled": True})
        elif path == "/endpoint/v1/policies/settings":
            self._send(200, {"items": [{"type": q.get("policyType"), "items": [
                {"name": "endpoint.scans.scheduled.days", "description": "Scheduled scan days", "type": "array", "defaultValue": []},
                {"name": ON_ACCESS_KEY, "description": "Real-time scanning of files", "type": "boolean", "defaultValue": True},
            ]}]})
        elif path.endswith("/base"):
            ptype = path.split("/")[-2]
            base = next(p for p in STATE["policies"] if p["type"] == ptype and p["id"].endswith("base"))
            self._send(200, base)
        elif path == "/endpoint/v1/policies":
            matching = [p for p in STATE["policies"] if p["type"] == q.get("policyType")]
            page_no = int(q.get("page", 1))
            page = matching[page_no - 1:page_no]
            pages = {"current": page_no, "size": 1, "maxSize": 100}
            if q.get("pageTotal") == "true":
                pages.update(total=max(len(matching), 1), items=len(matching))
            self._send(200, {"items": page, "pages": pages})
        else:
            self._send(404, {"error": "not found", "path": path})


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    srv = HTTPServer(("127.0.0.1", 0), SophosDouble)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def fresh_state() -> None:
    _reset()


def _run(fetcher: str, server: str, tmp_path: Path, **env: str) -> tuple[int, dict, dict]:
    status_file = tmp_path / "status.json"
    full_env = {
        "PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path),
        "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(status_file),
        "SOPHOS_CLIENT_ID": "id", "SOPHOS_CLIENT_SECRET": "secret",
        "SOPHOS_AUTH_URL": f"{server}/oauth2/token", "SOPHOS_GLOBAL_URL": server, **env,
    }
    proc = subprocess.run([sys.executable, str(SOPHOS / fetcher / "fetcher.py")], env=full_env,
                          cwd=SOPHOS / fetcher, capture_output=True, text=True, timeout=120)
    outputs = list(tmp_path.glob(f"sophos_{fetcher}_*.json"))
    assert len(outputs) == 1, (proc.stderr, outputs)
    status = json.loads(status_file.read_text()) if status_file.exists() else {}
    return proc.returncode, json.loads(outputs[0].read_text()), status


def test_protection_counts_every_endpoint_across_pages(server: str, tmp_path: Path) -> None:
    code, ev, _ = _run("endpoint_protection", server, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["total_endpoints"] == 3
    assert ev["metadata"]["population"] == {"collected": 3, "reported_total": 3, "complete": True,
                                            "items_with_unread_facts": 0}
    assert (s["endpoints_all_services_running"], s["endpoints_service_not_running"]) == (2, 1)
    assert (s["endpoints_tamper_protection_enabled"], s["endpoints_tamper_protection_disabled"]) == (2, 1)
    assert (s["endpoints_protection_product_installed"], s["endpoints_protection_product_not_installed"]) == (2, 1)
    assert (s["endpoints_threats_status_good"], s["endpoints_threats_status_not_good"]) == (2, 1)
    assert s["endpoints_by_health_overall"] == {"bad": 1, "good": 2}
    assert s["tenant_tamper_protection_enabled"] is True
    bad = next(i for i in ev["items"] if i["endpoint_id"] == "ep-2")
    assert bad["stopped_or_missing_services"] == ["Sophos Anti-Virus: stopped"]
    assert bad["hostname"] == "host-2"


def test_every_endpoints_call_asks_for_the_full_view(server: str, tmp_path: Path) -> None:
    _run("endpoint_protection", server, tmp_path)
    calls = [c for c in STATE["log"] if c["path"] == "/endpoint/v1/endpoints"]
    assert len(calls) == 2
    assert all(c["query"].get("view") == "full" and c["tenant"] == "tenant-1" for c in calls)


def test_no_fetcher_reads_tamper_protection_passwords(server: str, tmp_path: Path) -> None:
    for fetcher in ("endpoint_protection", "endpoint_check_in", "agent_updates", "endpoint_inventory"):
        out = tmp_path / fetcher
        out.mkdir()
        _run(fetcher, server, out)
    assert not [c for c in STATE["log"] if c["path"].endswith("/tamper-protection") and "/endpoints/" in c["path"]]


def test_count_mismatch_fails_the_run(server: str, tmp_path: Path) -> None:
    STATE["total_override"] = 4
    code, ev, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1
    assert ev["metadata"]["population"]["complete"] is False
    assert status["code"] == "partial_failure"
    assert "Sophos reports 4" in status["error"]


def test_missing_fact_is_null_and_named_not_false(server: str, tmp_path: Path) -> None:
    del STATE["endpoints"][0]["health"]["services"]["serviceDetails"]
    del STATE["endpoints"][0]["tamperProtectionEnabled"]
    code, ev, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1
    item = next(i for i in ev["items"] if i["endpoint_id"] == "ep-1")
    assert item["services_all_running"] is None and item["tamper_protection_enabled"] is None
    assert set(item["unread_facts"]) == {"services_all_running", "tamper_protection_enabled"}
    assert ev["summary"]["endpoints_services_unread"] == 1
    assert ev["summary"]["endpoints_tamper_protection_disabled"] == 1
    assert ev["metadata"]["population"]["complete"] is False
    assert "services_all_running" in status["error"]


def test_failed_side_read_keeps_the_endpoints(server: str, tmp_path: Path) -> None:
    STATE["tamper_403"] = True
    code, ev, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1
    assert ev["summary"]["total_endpoints"] == 3
    assert ev["summary"]["tenant_tamper_protection_enabled"] is None
    assert ev["metadata"]["api_failures"][0]["operation"] == "tenant_tamper_protection"
    assert status["code"] == "not_authorized"


def test_rejected_credential_reports_auth_failed(server: str, tmp_path: Path) -> None:
    code, ev, status = _run("endpoint_protection", server, tmp_path, SOPHOS_CLIENT_ID="bad")
    assert code == 1
    assert status["code"] == "auth_failed"
    assert "expired" in status["error"]
    assert ev["summary"] is None and ev["items"] == []


def test_partner_credential_needs_a_tenant(server: str, tmp_path: Path) -> None:
    STATE["id_type"] = "partner"
    code, _, status = _run("endpoint_check_in", server, tmp_path)
    assert code == 1 and status["code"] == "bad_config"


def test_partner_credential_with_tenant_resolves_its_host(server: str, tmp_path: Path) -> None:
    STATE["id_type"] = "partner"
    code, ev, _ = _run("endpoint_check_in", server, tmp_path, SOPHOS_TENANT_ID="tenant-9")
    assert code == 0
    assert ev["metadata"]["tenant_id"] == "tenant-9"
    assert (tmp_path / "sophos_endpoint_check_in_tenant-9.json").exists()


def test_check_in_keeps_stale_endpoints_and_reports_age(server: str, tmp_path: Path) -> None:
    code, ev, _ = _run("endpoint_check_in", server, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["total_endpoints"] == 3
    assert (s["endpoints_online"], s["endpoints_offline"]) == (2, 1)
    assert 239 <= s["max_hours_since_last_seen"] <= 241


def test_check_in_missing_online_is_unread(server: str, tmp_path: Path) -> None:
    del STATE["endpoints"][2]["online"]
    code, ev, _ = _run("endpoint_check_in", server, tmp_path)
    assert code == 1
    assert ev["summary"]["endpoints_online_unread"] == 1


def test_agent_updates(server: str, tmp_path: Path) -> None:
    code, ev, _ = _run("agent_updates", server, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["endpoints_by_protection_package_status"] == {"assigned": 2, "upgradable": 1}
    assert (s["endpoints_package_not_upgradable"], s["endpoints_package_upgradable"]) == (2, 1)
    assert 39.9 <= s["max_days_since_agent_update"] <= 40.1
    item = next(i for i in ev["items"] if i["endpoint_id"] == "ep-1")
    assert item["assigned_product_versions"] == {"coreAgent": "2024.3.1", "interceptX": "2024.3.2"}


def test_threat_protection_policies(server: str, tmp_path: Path) -> None:
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 0, ev["metadata"]
    s = ev["summary"]
    assert s["total_policies"] == 3 and s["base_policies"] == 2
    assert s["policies_by_type"] == {"server-threat-protection": 1, "threat-protection": 2}
    assert (s["policies_scheduled_scan_configured"], s["policies_no_scheduled_scan"]) == (2, 1)
    assert (s["policies_on_access_scanning_on"], s["policies_on_access_scanning_off"]) == (2, 1)
    custom = next(i for i in ev["items"] if i["policy_id"] == "tp-custom")
    assert custom["settings_off_vendor_baseline_keys"] == [ON_ACCESS_KEY]
    assert custom["settings"][ON_ACCESS_KEY] == {"value": False, "recommendedValue": True}
    assert ev["metadata"]["population"]["complete"] is True


def test_policy_without_schedule_setting_is_unread(server: str, tmp_path: Path) -> None:
    del STATE["policies"][1]["settings"]["endpoint.scans.scheduled.days"]
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 1
    assert ev["summary"]["policies_scheduled_scan_unread"] == 1
    assert ev["summary"]["policies_no_scheduled_scan"] == 1


def test_inventory_records(server: str, tmp_path: Path) -> None:
    code, ev, _ = _run("endpoint_inventory", server, tmp_path)
    assert code == 0
    assert ev["records_included"] is True and ev["record_count"] == 3
    rec = ev["data"][0]
    assert rec["unique_asset_identifier"] == "ep-1"
    assert rec["primary_ip_address"] == "10.0.0.1"
    assert rec["associated_person_login"] == "CORP\\pat"
    assert "name" not in rec["attributes"]["associatedPerson"]


def test_inventory_withholds_records_when_incomplete(server: str, tmp_path: Path) -> None:
    STATE["total_override"] = 5
    code, ev, status = _run("endpoint_inventory", server, tmp_path)
    assert code == 1
    assert ev["records_included"] is False and ev["data"] == []
    assert status["code"] == "partial_failure"


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self) -> Any:
        return self._body


class _Session:
    def __init__(self, responses: list[_Resp]) -> None:
        self.responses = responses
        self.calls = 0

    def request(self, *args: Any, **kwargs: Any) -> _Resp:
        self.calls += 1
        return self.responses.pop(0)


def _client(responses: list[_Resp]) -> SophosClient:
    client = SophosClient("id", "secret", session=_Session(responses), sleep=lambda s: None)
    client.token, client.api_host, client.tenant_id = "tok", "http://x", "t"
    return client


def test_retries_429_then_succeeds() -> None:
    client = _client([_Resp(429, {}), _Resp(503, {}), _Resp(200, {"ok": True})])
    assert client.get("/p", "op") == {"ok": True}


def test_persistent_429_is_rate_limited() -> None:
    client = _client([_Resp(429, {}) for _ in range(5)])
    with pytest.raises(SophosError) as err:
        client.get("/p", "op")
    assert err.value.code == "rate_limited"
