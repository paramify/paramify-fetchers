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
from typing import Any, Iterator, Optional
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SOPHOS = REPO_ROOT / "fetchers" / "sophos"
sys.path.insert(0, str(SOPHOS / "_shared"))

import sophos_client  # noqa: E402
from sophos_client import SophosClient, SophosError  # noqa: E402

NOW = datetime.now(timezone.utc)
TENANT = "11111111-2222-4333-8444-555555555555"
OTHER_TENANT = "99999999-8888-4777-8666-555555555555"
# Documented names: https://developer.sophos.com/endpoint-policy-settings-all/
MALWARE = "endpoint.threat-protection.malware-protection."
SCHED_ENABLED = MALWARE + "scheduled-scan.enabled"
SCHED_DAYS = MALWARE + "scheduled-scan.days"
SCHED_TIME = MALWARE + "scheduled-scan.time"
ON_ACCESS_KEY = MALWARE + "on-access.enabled"


def _iso(delta: timedelta) -> str:
    return (NOW - delta).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _endpoint(i: int, **over: Any) -> dict:
    ep = {
        "id": f"ep-{i}",
        "type": "computer",
        "tenant": {"id": TENANT},
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
    # One endpoint for each documented breakdown value: securityVm, no type, and each package status.
    security_vm = _endpoint(4, type="securityVm", packages={"protection": {"name": "Recommended", "status": "unassigned"}})
    no_type = _endpoint(5, packages={"protection": {"name": "Recommended", "status": "unlicensed"}})
    del no_type["type"]
    unsupported = _endpoint(6, packages={"protection": {"name": "Recommended", "status": "unsupported"}})
    return [_endpoint(1), bad_server, _endpoint(3), security_vm, no_type, unsupported]


def _policy(pid: str, ptype: str, *, enabled: bool = True, sched: Any = True, days: Any = (1, 3),
            on_access: bool = True, priority: int = 1) -> dict:
    settings = {
        SCHED_ENABLED: {"value": sched, "recommendedValue": True},
        SCHED_DAYS: {"value": list(days)},
        SCHED_TIME: {"value": "00:00"},
        ON_ACCESS_KEY: {"value": on_access, "recommendedValue": True},
    }
    return {"id": pid, "name": pid, "type": ptype, "enabled": enabled, "priority": priority,
            "settings": settings, "appliesTo": {"endpoints": [], "endpointGroups": []}}


def _policies() -> list[dict]:
    return [
        # Sophos's defaults: scheduled scans off, days [6]. Not a scheduled scan.
        _policy("tp-custom", "threat-protection", sched=False, days=(6,), on_access=False),
        _policy("tp-base", "threat-protection", priority=0),
        _policy("stp-base", "server-threat-protection", priority=0),
    ]


STATE: dict = {}


def _reset() -> None:
    STATE.clear()
    STATE.update(endpoints=_endpoints(), policies=_policies(), id_type="tenant", log=[],
                 total_override=None, tamper_403=False, tamper_body={"enabled": True}, base_fail=False,
                 data_region=None, policy_no_total=False, throttle=0)


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
                self._send(200, {"id": TENANT, "idType": "tenant",
                                 "apiHosts": {"global": self._base(),
                                              "dataRegion": STATE["data_region"] or self._base()}})
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
            self._send(403, {"error": "forbidden"}) if STATE["tamper_403"] else self._send(200, STATE["tamper_body"])
        elif path.endswith("/base"):
            if STATE["base_fail"]:
                self._send(400, {"error": "bad request"})
                return
            ptype = path.split("/")[-2]
            base = next(p for p in STATE["policies"] if p["type"] == ptype and p["id"].endswith("base"))
            self._send(200, base)
        elif path == "/endpoint/v1/policies":
            matching = [p for p in STATE["policies"] if p["type"] == q.get("policyType")]
            page_no = int(q.get("page", 1))
            page = matching[page_no - 1:page_no]
            pages = {"current": page_no, "size": 1, "maxSize": 100}
            if STATE["policy_no_total"]:
                pages["maxSize"] = 1  # full pages until an empty one, and no total to stop on
            elif q.get("pageTotal") == "true":
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
    STATE["stderr"] = proc.stderr
    outputs = list(tmp_path.glob(f"sophos_{fetcher}_*.json"))
    assert len(outputs) == 1, (proc.stderr, outputs)
    status = json.loads(status_file.read_text()) if status_file.exists() else {}
    return proc.returncode, json.loads(outputs[0].read_text()), status


def test_protection_counts_every_endpoint_across_pages(server: str, tmp_path: Path,
                                                       assert_summary_documented: Any) -> None:
    code, ev, _ = _run("endpoint_protection", server, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert_summary_documented("sophos/endpoint_protection", s)
    assert s["total_endpoints"] == 6
    assert s["endpoints_by_type"] == {"computer": 3, "not_returned": 1, "securityVm": 1, "server": 1}
    assert ev["metadata"]["population"] == {"collected": 6, "reported_total": 6, "complete": True,
                                            "items_with_unread_facts": 0}
    assert ev["metadata"]["partial_failure"] is False and ev["metadata"]["api_failures"] == []
    assert (s["endpoints_all_services_running"], s["endpoints_service_not_running"]) == (5, 1)
    assert (s["endpoints_tamper_protection_enabled"], s["endpoints_tamper_protection_disabled"]) == (5, 1)
    assert s["endpoints_tamper_protection_not_supported"] == 0
    assert (s["endpoints_protection_product_installed"], s["endpoints_protection_product_not_installed"]) == (5, 1)
    assert (s["endpoints_threats_status_good"], s["endpoints_threats_status_not_good"]) == (5, 1)
    assert s["endpoints_by_health_overall"] == {"bad": 1, "good": 5}
    assert s["tenant_tamper_protection_enabled"] is True
    bad = next(i for i in ev["items"] if i["endpoint_id"] == "ep-2")
    assert bad["stopped_or_missing_services"] == ["Sophos Anti-Virus: stopped"]
    assert bad["hostname"] == "host-2"


def test_every_endpoints_call_asks_for_the_full_view(server: str, tmp_path: Path) -> None:
    _run("endpoint_protection", server, tmp_path)
    calls = [c for c in STATE["log"] if c["path"] == "/endpoint/v1/endpoints"]
    assert len(calls) == 3
    assert all(c["query"].get("view") == "full" and c["tenant"] == TENANT for c in calls)


def test_no_fetcher_reads_tamper_protection_passwords(server: str, tmp_path: Path) -> None:
    for fetcher in ("endpoint_protection", "endpoint_check_in", "agent_updates", "endpoint_inventory",
                    "threat_protection_policies"):
        out = tmp_path / fetcher
        out.mkdir()
        _run(fetcher, server, out)
    assert not [c for c in STATE["log"] if c["path"].endswith("/tamper-protection") and "/endpoints/" in c["path"]]


def test_count_mismatch_fails_the_run(server: str, tmp_path: Path) -> None:
    STATE["total_override"] = 7
    code, ev, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1
    assert ev["metadata"]["population"]["complete"] is False
    assert status["code"] == "partial_failure"
    assert "Sophos reports 7" in status["error"]


def test_missing_fact_is_null_and_named_not_false(server: str, tmp_path: Path) -> None:
    del STATE["endpoints"][0]["health"]["services"]["serviceDetails"]
    del STATE["endpoints"][0]["tamperProtectionEnabled"]
    code, ev, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1
    item = next(i for i in ev["items"] if i["endpoint_id"] == "ep-1")
    assert item["services_all_running"] is None and item["tamper_protection_enabled"] is None
    assert set(item["unread_facts"]) == {"services_all_running", "tamper_protection_enabled"}
    assert ev["summary"]["endpoints_services_unread"] == 1
    assert ev["summary"]["endpoints_tamper_protection_unread"] == 1
    assert ev["summary"]["endpoints_tamper_protection_disabled"] == 1
    assert ev["metadata"]["population"]["complete"] is False
    assert "services_all_running" in status["error"]
    # A partial run names its reason in api_failures, not only in the items.
    assert ev["metadata"]["partial_failure"] is True
    assert ev["metadata"]["api_failures"] == [{
        "operation": "unread_facts", "type": "partial_failure",
        "message": "1 item(s) have facts Sophos did not return: services_all_running, tamper_protection_enabled",
    }]


def test_tamper_protection_not_supported_is_neither_on_off_nor_unread(server: str, tmp_path: Path) -> None:
    STATE["endpoints"][2].update(tamperProtectionSupported=False, tamperProtectionEnabled=False)
    STATE["endpoints"][3]["tamperProtectionSupported"] = False
    del STATE["endpoints"][3]["tamperProtectionEnabled"]
    code, ev, _ = _run("endpoint_protection", server, tmp_path)
    assert code == 0, ev["metadata"]
    s = ev["summary"]
    assert s["endpoints_tamper_protection_not_supported"] == 2
    assert (s["endpoints_tamper_protection_enabled"], s["endpoints_tamper_protection_disabled"]) == (3, 1)
    assert s["endpoints_tamper_protection_unread"] == 0
    for ep_id in ("ep-3", "ep-4"):
        item = next(i for i in ev["items"] if i["endpoint_id"] == ep_id)
        assert item["tamper_protection_enabled"] is None and item["tamper_protection_supported"] is False
        assert "unread_facts" not in item


def test_tenant_tamper_without_enabled_is_a_failure(server: str, tmp_path: Path) -> None:
    STATE["tamper_body"] = {}
    code, ev, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1
    assert ev["summary"]["tenant_tamper_protection_enabled"] is None
    assert [f["operation"] for f in ev["metadata"]["api_failures"]] == ["tenant_tamper_protection"]
    assert status["code"] == "partial_failure"


def test_failed_side_read_keeps_the_endpoints(server: str, tmp_path: Path) -> None:
    STATE["tamper_403"] = True
    code, ev, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1
    assert ev["summary"]["total_endpoints"] == 6
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
    code, ev, _ = _run("endpoint_check_in", server, tmp_path, SOPHOS_TENANT_ID=OTHER_TENANT)
    assert code == 0
    assert ev["metadata"]["tenant_id"] == OTHER_TENANT
    assert (tmp_path / f"sophos_endpoint_check_in_{OTHER_TENANT}.json").exists()


def test_tenant_id_that_is_not_a_uuid_is_bad_config(server: str, tmp_path: Path) -> None:
    code, ev, status = _run("endpoint_check_in", server, tmp_path, SOPHOS_TENANT_ID="../../../tmp/x")
    assert code == 1 and status["code"] == "bad_config"
    assert "UUID" in status["error"]
    assert not STATE["log"]  # refused before any call
    assert not list(tmp_path.glob("*tmp*"))


def test_data_region_host_outside_sophos_is_refused(server: str, tmp_path: Path) -> None:
    STATE["data_region"] = "https://evil.example"
    code, _, status = _run("endpoint_protection", server, tmp_path)
    assert code == 1 and status["code"] == "bad_config"
    assert "evil.example" in status["error"]
    assert [c["path"] for c in STATE["log"]] == ["/whoami/v1"]


def test_check_in_keeps_stale_endpoints_and_reports_age(server: str, tmp_path: Path,
                                                        assert_summary_documented: Any) -> None:
    code, ev, _ = _run("endpoint_check_in", server, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert_summary_documented("sophos/endpoint_check_in", s)
    assert s["total_endpoints"] == 6
    assert s["endpoints_by_type"] == {"computer": 3, "not_returned": 1, "securityVm": 1, "server": 1}
    assert (s["endpoints_online"], s["endpoints_offline"]) == (5, 1)
    assert 239 <= s["max_hours_since_last_seen"] <= 241


def test_check_in_missing_online_does_not_fail_the_run(server: str, tmp_path: Path) -> None:
    del STATE["endpoints"][2]["online"]
    code, ev, _ = _run("endpoint_check_in", server, tmp_path)
    assert code == 0
    assert ev["summary"]["endpoints_online_unread"] == 1
    item = next(i for i in ev["items"] if i["endpoint_id"] == "ep-3")
    assert item["online"] is None and "unread_facts" not in item
    assert ev["metadata"]["partial_failure"] is False


def test_check_in_missing_last_seen_fails_the_run(server: str, tmp_path: Path) -> None:
    del STATE["endpoints"][2]["lastSeenAt"]
    code, ev, status = _run("endpoint_check_in", server, tmp_path)
    assert code == 1 and status["code"] == "partial_failure"
    assert ev["summary"]["endpoints_last_seen_unread"] == 1


def test_agent_updates_counts_every_package_status(server: str, tmp_path: Path,
                                                   assert_summary_documented: Any) -> None:
    # ep-3 has no package status, so every documented status occurs. That one fact is unread, so the run exits 1.
    del STATE["endpoints"][2]["packages"]["protection"]["status"]
    code, ev, status = _run("agent_updates", server, tmp_path)
    assert code == 1
    assert status["error"] == "1 item(s) have facts Sophos did not return: protection_package_current"
    s = ev["summary"]
    assert_summary_documented("sophos/agent_updates", s)
    assert s["endpoints_by_protection_package_status"] == {
        "assigned": 1, "not_returned": 1, "unassigned": 1, "unlicensed": 1, "unsupported": 1, "upgradable": 1}
    # Only "assigned" is current: unassigned, unlicensed and unsupported do not pass as current.
    assert (s["endpoints_package_current"], s["endpoints_package_not_current"], s["endpoints_package_unread"]) \
        == (1, 4, 1)
    assert 39.9 <= s["max_days_since_agent_update"] <= 40.1
    item = next(i for i in ev["items"] if i["endpoint_id"] == "ep-1")
    assert item["protection_package_current"] is True
    assert item["assigned_product_versions"] == {"coreAgent": "2024.3.1", "interceptX": "2024.3.2"}


def test_threat_protection_policies(server: str, tmp_path: Path, assert_summary_documented: Any) -> None:
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 0, ev["metadata"]
    s = ev["summary"]
    assert_summary_documented("sophos/threat_protection_policies", s)
    assert s["total_policies"] == 3 and s["base_policies"] == 2
    assert s["policies_by_type"] == {"server-threat-protection": 1, "threat-protection": 2}
    assert (s["policies_scheduled_scan_configured"], s["policies_no_scheduled_scan"]) == (2, 1)
    assert (s["policies_on_access_scanning_on"], s["policies_on_access_scanning_off"]) == (2, 1)
    assert s["policies_with_settings_off_vendor_baseline"] == 1
    assert s["policies_without_recommended_values"] == 0
    custom = next(i for i in ev["items"] if i["policy_id"] == "tp-custom")
    # Sophos's defaults (enabled: false, days: [6]) are not a scheduled scan.
    assert custom["scheduled_scan_configured"] is False
    assert custom["scheduled_scan_enabled"] is False and custom["scheduled_scan_days"] == [6]
    assert custom["settings_off_vendor_baseline_keys"] == sorted([ON_ACCESS_KEY, SCHED_ENABLED])
    assert custom["settings"][ON_ACCESS_KEY] == {"value": False, "recommendedValue": True}
    base = next(i for i in ev["items"] if i["policy_id"] == "tp-base")
    assert base["scheduled_scan_configured"] is True
    assert (base["scheduled_scan_days"], base["scheduled_scan_time"]) == ([1, 3], "00:00")
    assert ev["metadata"]["population"]["complete"] is True
    assert not [c for c in STATE["log"] if c["path"] == "/endpoint/v1/policies/settings"]


def test_policy_without_scheduled_scan_enabled_is_unread(server: str, tmp_path: Path) -> None:
    del STATE["policies"][1]["settings"][SCHED_ENABLED]
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 1
    assert ev["summary"]["policies_scheduled_scan_unread"] == 1
    assert ev["summary"]["policies_no_scheduled_scan"] == 1
    base = next(i for i in ev["items"] if i["policy_id"] == "tp-base")
    assert base["scheduled_scan_configured"] is None and "scheduled_scan_configured" in base["unread_facts"]


def test_enabled_schedule_with_no_days_is_not_a_scheduled_scan(server: str, tmp_path: Path) -> None:
    STATE["policies"][1]["settings"][SCHED_DAYS]["value"] = []
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 0
    base = next(i for i in ev["items"] if i["policy_id"] == "tp-base")
    assert base["scheduled_scan_configured"] is False


def test_policy_without_recommended_values_has_no_baseline_count(server: str, tmp_path: Path) -> None:
    for entry in STATE["policies"][0]["settings"].values():
        entry.pop("recommendedValue", None)
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 0
    custom = next(i for i in ev["items"] if i["policy_id"] == "tp-custom")
    assert custom["settings_off_vendor_baseline"] is None and custom["settings_with_recommended_value"] == 0
    assert ev["summary"]["policies_without_recommended_values"] == 1
    assert ev["summary"]["policies_with_settings_off_vendor_baseline"] == 0


def test_failed_base_read_does_not_mark_a_policy_without_id_as_base(server: str, tmp_path: Path) -> None:
    STATE["base_fail"] = True
    no_id = _policy("no-id", "threat-protection")
    del no_id["id"]
    STATE["policies"].append(no_id)
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 1
    assert ev["summary"]["base_policies"] == 0
    assert not [i for i in ev["items"] if i["is_base_policy"]]


def test_policies_without_a_page_total_read_until_an_empty_page(server: str, tmp_path: Path) -> None:
    STATE["policy_no_total"] = True
    code, ev, _ = _run("threat_protection_policies", server, tmp_path)
    assert code == 0, ev["metadata"]
    assert ev["summary"]["total_policies"] == 3
    pages = [c["query"]["page"] for c in STATE["log"]
             if c["path"] == "/endpoint/v1/policies" and c["query"]["policyType"] == "threat-protection"]
    assert pages == ["1", "2", "3"]


def test_inventory_records(server: str, tmp_path: Path) -> None:
    code, ev, _ = _run("endpoint_inventory", server, tmp_path)
    assert code == 0
    assert ev["records_included"] is True and ev["record_count"] == 6
    rec = ev["data"][0]
    assert rec["unique_asset_identifier"] == "ep-1"
    assert rec["primary_ip_address"] == "10.0.0.1"
    assert rec["associated_person_login"] == "CORP\\pat"
    assert "name" not in rec["attributes"]["associatedPerson"]


def test_inventory_withholds_records_when_incomplete(server: str, tmp_path: Path) -> None:
    STATE["total_override"] = 8
    code, ev, status = _run("endpoint_inventory", server, tmp_path)
    assert code == 1
    assert ev["records_included"] is False and ev["data"] == []
    assert status["code"] == "partial_failure"
    # The saved line comes before the failure, so the log shows the file exists.
    saved = STATE["stderr"].find("Inventory saved to")
    assert 0 <= saved < STATE["stderr"].find("inventory incomplete")


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self) -> Any:
        return self._body


class _Session:
    def __init__(self, responses: list[_Resp]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _Resp:
        self.calls.append((method, url))
        return self.responses.pop(0)


def _client(responses: list[_Resp], sleeps: Optional[list] = None) -> SophosClient:
    client = SophosClient("id", "secret", session=_Session(responses),  # type: ignore[arg-type]
                          sleep=(sleeps.append if sleeps is not None else lambda s: None))
    client.token, client.api_host, client.tenant_id = "tok", "http://127.0.0.1", TENANT
    return client


def test_retries_429_then_succeeds() -> None:
    client = _client([_Resp(429, {}), _Resp(503, {}), _Resp(200, {"ok": True})])
    assert client.get("/p", "op") == {"ok": True}


def test_persistent_429_is_rate_limited_after_more_than_a_minute() -> None:
    sleeps: list = []
    client = _client([_Resp(429, {}) for _ in range(sophos_client.MAX_ATTEMPTS)], sleeps)
    with pytest.raises(SophosError) as err:
        client.get("/p", "op")
    assert err.value.code == "rate_limited"
    assert sum(sleeps) > 60  # Sophos's limit is per minute


def test_token_request_retries_5xx() -> None:
    client = _client([_Resp(503, {}), _Resp(429, {}), _Resp(200, {"access_token": "new"})])
    client._authenticate()
    assert client.token == "new"
    assert [m for m, _ in client.session.calls] == ["POST", "POST", "POST"]  # type: ignore[attr-defined]


def test_token_service_outage_is_not_auth_failed() -> None:
    client = _client([_Resp(503, {}) for _ in range(sophos_client.MAX_ATTEMPTS)])
    with pytest.raises(SophosError) as err:
        client._authenticate()
    assert err.value.code == "target_unreachable"


@pytest.mark.parametrize("status", [400, 401])
def test_token_rejection_is_auth_failed(status: int) -> None:
    client = _client([_Resp(status, {"error": "invalid_client"})])
    with pytest.raises(SophosError) as err:
        client._authenticate()
    assert err.value.code == "auth_failed" and "expired" in str(err.value)


def test_repeated_next_key_stops_paging() -> None:
    page: dict[str, Any] = {"items": [{"id": "a"}], "pages": {"nextKey": "k1", "maxSize": 1}}
    client = _client([_Resp(200, page), _Resp(200, page), _Resp(200, page)])
    with pytest.raises(SophosError) as err:
        client.list_endpoints()
    assert err.value.code == "partial_failure" and "k1" in str(err.value)
    assert len(client.session.calls) == 2  # type: ignore[attr-defined]


def test_page_limit_stops_paging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sophos_client, "MAX_PAGES", 3)
    client = _client([_Resp(200, {"items": [{"id": n}], "pages": {"nextKey": f"k{n}"}}) for n in range(5)])
    with pytest.raises(SophosError) as err:
        client.list_endpoints()
    assert err.value.code == "partial_failure" and "more than 3 pages" in str(err.value)


REFUSED_URLS = [
    "http://evil.example/token",           # plain http, not loopback
    "https://evil.example/token",          # not a Sophos host
    "https://sophos.com.evil.example/x",   # Sophos name as a prefix only
    "https://evilsophos.com/x",            # ends with sophos.com, not .sophos.com
    "http://id.sophos.com/token",          # Sophos host, but plain http
    "https://user:pw@id.sophos.com/token", # credentials in the URL
    "not a url",
]


@pytest.mark.parametrize("url", REFUSED_URLS)
@pytest.mark.parametrize("var", ["SOPHOS_AUTH_URL", "SOPHOS_GLOBAL_URL"])
def test_hosts_outside_sophos_are_refused_before_the_token_request(
        monkeypatch: pytest.MonkeyPatch, var: str, url: str) -> None:
    monkeypatch.setenv("SOPHOS_CLIENT_ID", "id")
    monkeypatch.setenv("SOPHOS_CLIENT_SECRET", "secret")
    monkeypatch.delenv("SOPHOS_TENANT_ID", raising=False)
    monkeypatch.delenv("SOPHOS_AUTH_URL", raising=False)
    monkeypatch.delenv("SOPHOS_GLOBAL_URL", raising=False)
    monkeypatch.setenv(var, url)
    with pytest.raises(SophosError) as err:
        SophosClient.from_env()
    assert err.value.code == "bad_config"


@pytest.mark.parametrize("url", ["https://id.sophos.com/api/v2/oauth2/token", "https://api.central.sophos.com",
                                 "https://api-us01.central.sophos.com", "http://127.0.0.1:8080", "http://localhost:1"])
def test_sophos_and_loopback_hosts_are_accepted(url: str) -> None:
    assert sophos_client.sophos_url(url, "X") == url


@pytest.mark.parametrize("data_region", ["https://evil.example", "http://api-us01.central.sophos.com"])
def test_data_region_host_is_checked_before_the_token_goes_to_it(data_region: str) -> None:
    session = _Session([_Resp(200, {"access_token": "tok"}),
                        _Resp(200, {"id": TENANT, "idType": "tenant", "apiHosts": {"dataRegion": data_region}})])
    client = SophosClient("id", "secret", session=session)  # type: ignore[arg-type]
    with pytest.raises(SophosError) as err:
        client.connect()
    assert err.value.code == "bad_config"
    assert len(session.calls) == 2  # the token request and whoami only
