"""The qualys fetchers end to end against a local Qualys API double.

Response shapes follow the Qualys VM/PC API user guide and its published DTDs
(host list and detection list v5, schedules v5, scan list v3, option profiles,
IP lists, SIMPLE_RETURN errors). Field-level fidelity still needs a real run.
"""

from __future__ import annotations

import base64
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
from xml.sax.saxutils import escape

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
QUALYS = REPO_ROOT / "fetchers" / "qualys"
sys.path.insert(0, str(QUALYS / "_shared"))

from qualys_client import QualysClient, QualysError, normalize_api_url  # noqa: E402

NOW = datetime.now(timezone.utc)
USER, PASSWORD = "acme_ro1", "pw"
LOCAL = "127.0.0.1"  # the double, named as the private cloud host


def _iso(days: float) -> str:
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _doc(root: str, inner: str, warning: str = "") -> str:
    return (f'<?xml version="1.0" encoding="UTF-8" ?>\n'
            f'<!DOCTYPE {root} SYSTEM "https://qualysapi.qualys.com/api/5.0/dtd/output.dtd">\n'
            f"<{root}><RESPONSE><DATETIME>{_iso(0)}</DATETIME>{inner}<!-- keep-alive -->{warning}</RESPONSE></{root}>")


def _simple_return(code: str, message: str, wait: str | None = None) -> str:
    items = (f"<ITEM_LIST><ITEM><KEY>SECONDS_TO_WAIT</KEY><VALUE>{wait}</VALUE></ITEM></ITEM_LIST>"
             if wait is not None else "")
    return _doc("SIMPLE_RETURN", f"<CODE>{code}</CODE><TEXT>{escape(message)}</TEXT>{items}")


def _el(tag: str, value: Any) -> str:
    return "" if value is None else f"<{tag}><![CDATA[{value}]]></{tag}>"


def _hosts() -> list[dict]:
    return [
        {"ID": "101", "IP": "10.0.0.1", "TRACKING_METHOD": "IP", "DNS": "web1.example.test", "OS": "Linux",
         "LAST_VULN_SCAN_DATETIME": _iso(3), "LAST_VM_SCANNED_DATE": _iso(3), "LAST_VM_AUTH_SCANNED_DATE": _iso(3)},
        {"ID": "102", "IP": "10.0.0.2", "TRACKING_METHOD": "IP", "DNS": "web2.example.test", "OS": "Linux",
         "LAST_VULN_SCAN_DATETIME": _iso(45), "LAST_VM_SCANNED_DATE": _iso(45)},
        {"ID": "103", "IP": "10.0.0.9", "TRACKING_METHOD": "Cloud Agent", "OS": "Windows Server 2022",
         "LAST_VULN_SCAN_DATETIME": _iso(1), "LAST_VM_SCANNED_DATE": _iso(1), "LAST_VM_AUTH_SCANNED_DATE": _iso(40)},
        {"ID": "104", "IP": "10.0.1.5", "TRACKING_METHOD": "EC2", "OS": "Amazon Linux"},
        {"ID": "105", "IP": "10.0.1.6", "TRACKING_METHOD": "DNS", "DNS": "db.example.test",
         "LAST_VM_SCANNED_DATE": "not-a-date"},
    ]


def _detections() -> dict[str, list[dict]]:
    def det(qid, sev, status, first, typ="Confirmed", **over):
        d = {"UNIQUE_VULN_ID": f"{qid}{sev}", "QID": qid, "TYPE": typ, "SEVERITY": sev, "STATUS": status,
             "FIRST_FOUND_DATETIME": _iso(first), "LAST_FOUND_DATETIME": _iso(1), "TIMES_FOUND": "4",
             "IS_IGNORED": "0", "IS_DISABLED": "0", "RESULTS": "User Name root Authentication Record 10.0.0.1"}
        d.update(over)
        return d
    return {
        "101": [det("38739", "5", "Active", 45), det("38740", "4", "New", 5), det("90001", "3", "Re-Opened", 100,
                LAST_REOPENED_DATETIME=_iso(10), TIMES_REOPENED="1", LAST_FIXED_DATETIME=_iso(20))],
        "102": [det("38741", "2", "Active", 200, typ="Potential"), det("38742", "5", "Active", 90, IS_IGNORED="1"),
                det("38743", "1", "Fixed", 50, LAST_FIXED_DATETIME=_iso(5)),
                det("38744", "5", "Fixed", 70, LAST_FIXED_DATETIME=_iso(10)),
                det("38745", "3", "Fixed", 400, LAST_FIXED_DATETIME=_iso(300))],
        "103": [det("38746", "4", "Active", 10, IS_DISABLED="1"),
                det("38747", "3", "Fixed", 100, LAST_FIXED_DATETIME=_iso(2), LAST_REOPENED_DATETIME=_iso(60),
                    TIMES_REOPENED="1")],
    }


def _schedules() -> list[dict]:
    return [
        {"ID": "1", "ACTIVE": "1", "TITLE": "Weekly internal", "OPTION_PROFILE": "Authenticated Scan",
         "SCHEDULE": '<WEEKLY frequency_weeks="1" weekdays="0"/>', "LAUNCH_TYPE": "recurring",
         "ASSET_GROUPS": ["All"], "NEXTLAUNCH_UTC": _iso(-2)},
        {"ID": "2", "ACTIVE": "1", "TITLE": "Quarterly external", "OPTION_PROFILE": "Initial Options",
         "SCHEDULE": '<MONTHLY frequency_months="3" day_of_month="1"/>', "LAUNCH_TYPE": "recurring",
         "ASSET_GROUPS": ["DMZ"], "NEXTLAUNCH_UTC": _iso(-20)},
        {"ID": "3", "ACTIVE": "0", "TITLE": "Old daily", "OPTION_PROFILE": "Authenticated Scan",
         "SCHEDULE": '<DAILY frequency_days="1"/>', "LAUNCH_TYPE": "recurring", "ASSET_GROUPS": ["Lab"]},
        {"ID": "4", "ACTIVE": "1", "TITLE": "Mystery profile", "OPTION_PROFILE": "Not In List",
         "SCHEDULE": '<DAILY frequency_days="7"/>', "LAUNCH_TYPE": "recurring", "ASSET_GROUPS": ["All"]},
    ]


def _option_profiles() -> list[dict]:
    return [{"ID": "11", "GROUP_NAME": "Authenticated Scan", "AUTHENTICATION": "Windows,Unix"},
            {"ID": "12", "GROUP_NAME": "Initial Options", "AUTHENTICATION": None}]


def _scans() -> list[dict]:
    return [
        {"REF": "scan/1.1", "TYPE": "Scheduled", "TITLE": "Weekly internal", "LAUNCH": _iso(6), "STATE": "Finished"},
        {"REF": "scan/1.2", "TYPE": "Scheduled", "TITLE": "Weekly internal", "LAUNCH": _iso(13), "STATE": "Error"},
        {"REF": "scan/1.3", "TYPE": "On-Demand", "TITLE": "Ad hoc", "LAUNCH": _iso(2), "STATE": "Running"},
        {"REF": "scan/1.4", "TYPE": "API", "TITLE": "Pipeline", "LAUNCH": _iso(1), "STATE": "Loading"},
    ]


STATE: dict = {}


def _reset() -> None:
    STATE.clear()
    STATE.update(hosts=_hosts(), detections=_detections(), groups=["All", "DMZ", "Lab"], page_size=2,
                 ips=["10.0.0.1-10.0.0.10", "10.0.1.5", "10.0.2.0-10.0.2.3"], excluded=["10.0.0.10"],
                 schedules=_schedules(), profiles=_option_profiles(), scans=_scans(),
                 fail={}, throttle={}, wait="0", log=[], bad_next=False, drop_id_min=False, entity=False,
                 extra_warning=False)


class QualysDouble(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, status: int, body: str, headers: dict | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _base(self) -> str:
        return f"http://{self.headers['Host']}"

    def _page(self, path: str, q: dict, items: list, key: str) -> tuple[list, str]:
        start = int(q.get("id_min", "0"))
        rest = [i for i in items if int(i[key]) >= start]
        page, more = rest[:STATE["page_size"]], rest[STATE["page_size"]:]
        extra = ("<WARNING><CODE>1001</CODE><TEXT>This API version is deprecated.</TEXT></WARNING>"
                 if STATE["extra_warning"] else "")
        if not more:
            return page, extra
        base = "https://evil.example" if STATE["bad_next"] else self._base()
        id_min = "" if STATE["drop_id_min"] else f"&id_min={more[0][key]}"
        url = f"{base}{path}?action=list&truncation_limit={STATE['page_size']}{id_min}"
        return page, (f"<WARNING><CODE>1980</CODE><TEXT>{STATE['page_size']} record limit exceeded.</TEXT>"
                      f"<URL><![CDATA[{url}]]></URL></WARNING>{extra}")

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        path = url.path
        STATE["log"].append({"path": path, "query": q})
        auth = self.headers.get("Authorization", "")
        if auth != "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode():
            self._send(401, _simple_return("2000", "Bad Login/Password"))
            return
        if not self.headers.get("X-Requested-With"):
            self._send(400, _simple_return("1907", "X-Requested-With header is required"))
            return
        if path in STATE["fail"]:
            status, code, message = STATE["fail"][path]
            self._send(status, _simple_return(code, message))
            return
        if STATE["throttle"].get(path, 0) > 0:
            STATE["throttle"][path] -= 1
            self._send(409, _simple_return("1965", "Rate limit exceeded", wait=STATE["wait"]),
                       {"X-RateLimit-ToWait-Sec": STATE["wait"]})
            return
        handler = ROUTES.get(path)
        if handler is None:
            self._send(404, _simple_return("1904", "not found"))
            return
        self._send(200, handler(self, path, q))


def _groups(h: QualysDouble, path: str, q: dict) -> str:
    rows = "".join(f"<ASSET_GROUP><ID>{i}</ID>{_el('TITLE', t)}</ASSET_GROUP>" for i, t in enumerate(STATE["groups"]))
    return _doc("ASSET_GROUP_LIST_OUTPUT", f"<ASSET_GROUP_LIST>{rows}</ASSET_GROUP_LIST>")


def _host_xml(host: dict, inner: str = "") -> str:
    fields = "".join(_el(k, v) for k, v in host.items() if k != "ID")
    return f"<HOST><ID>{host['ID']}</ID>{fields}{inner}</HOST>"


def _host_list(h: QualysDouble, path: str, q: dict) -> str:
    page, warning = h._page(path, q, STATE["hosts"], "ID")
    return _doc("HOST_LIST_OUTPUT", f"<HOST_LIST>{''.join(_host_xml(x) for x in page)}</HOST_LIST>", warning)


def _ip_set(values: list[str]) -> str:
    rows = "".join(f"<IP_RANGE>{v}</IP_RANGE>" if "-" in v else f"<IP>{v}</IP>" for v in values)
    return f"<IP_SET>{rows}</IP_SET>" if values else ""


def _ip_list(h: QualysDouble, path: str, q: dict) -> str:
    return _doc("IP_LIST_OUTPUT", _ip_set(STATE["ips"]))


def _excluded(h: QualysDouble, path: str, q: dict) -> str:
    return _doc("IP_LIST_OUTPUT", _ip_set(STATE["excluded"]))


def _detection_list(h: QualysDouble, path: str, q: dict) -> str:
    wanted = set((q.get("status") or "New,Active,Re-Opened").split(","))
    since = q.get("detection_updated_since")
    hosts = []
    for host in STATE["hosts"]:
        dets = [d for d in STATE["detections"].get(host["ID"], []) if d["STATUS"] in wanted
                and (q.get("include_ignored") == "1" or d["IS_IGNORED"] == "0")
                and (q.get("include_disabled") == "1" or d["IS_DISABLED"] == "0")
                and (since is None or max(d["FIRST_FOUND_DATETIME"], d.get("LAST_FIXED_DATETIME", ""),
                                          d.get("LAST_REOPENED_DATETIME", "")) >= since)]
        if dets:
            hosts.append((host, dets))
    page, warning = h._page(path, q, [x[0] for x in hosts], "ID")
    ids = {x["ID"] for x in page}
    body = []
    for host, dets in hosts:
        if host["ID"] not in ids:
            continue
        rows = "".join("<DETECTION>" + "".join(
            _el(k, v) for k, v in d.items() if not (k == "RESULTS" and q.get("show_results") == "0")
        ) + "</DETECTION>" for d in dets)
        ident = {k: host[k] for k in ("ID", "IP", "TRACKING_METHOD", "DNS") if k in host}
        body.append(_host_xml(ident, f"<DETECTION_LIST>{rows}</DETECTION_LIST>"))
    if STATE["entity"]:
        return ('<?xml version="1.0"?>\n<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT [<!ENTITY a "aaaa">]>'
                "<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>&a;</ID></HOST></HOST_LIST>"
                "</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>")
    return _doc("HOST_LIST_VM_DETECTION_OUTPUT", f"<HOST_LIST>{''.join(body)}</HOST_LIST>", warning)


def _schedule_list(h: QualysDouble, path: str, q: dict) -> str:
    rows = []
    for s in STATE["schedules"]:
        groups = "".join(_el("ASSET_GROUP_TITLE", g) for g in s["ASSET_GROUPS"])
        rows.append(
            f"<SCAN><ID>{s['ID']}</ID><ACTIVE>{s['ACTIVE']}</ACTIVE>{_el('TITLE', s['TITLE'])}"
            f"{_el('USER_LOGIN', 'acme_mgr')}<TARGET><![CDATA[{', '.join(s['ASSET_GROUPS'])}]]></TARGET>"
            f"<ASSET_GROUP_TITLE_LIST>{groups}</ASSET_GROUP_TITLE_LIST>"
            f"<OPTION_PROFILE>{_el('TITLE', s['OPTION_PROFILE'])}<DEFAULT_FLAG>0</DEFAULT_FLAG></OPTION_PROFILE>"
            f"<SCHEDULE>{s['SCHEDULE']}<START_DATE_UTC>{_iso(400)}</START_DATE_UTC><START_HOUR>2</START_HOUR>"
            f"{_el('NEXTLAUNCH_UTC', s.get('NEXTLAUNCH_UTC'))}<LAUNCH_TYPE>{s['LAUNCH_TYPE']}</LAUNCH_TYPE></SCHEDULE>"
            f"</SCAN>")
    return _doc("SCHEDULE_SCAN_LIST_OUTPUT", f"<SCHEDULE_SCAN_LIST>{''.join(rows)}</SCHEDULE_SCAN_LIST>")


def _profiles(h: QualysDouble, path: str, q: dict) -> str:
    rows = "".join(
        f"<OPTION_PROFILE><BASIC_INFO><ID>{p['ID']}</ID>{_el('GROUP_NAME', p['GROUP_NAME'])}</BASIC_INFO>"
        f"<SCAN>{_el('AUTHENTICATION', p['AUTHENTICATION'])}"
        f"<LOGIN_PASSWORD><![CDATA[L:Guest,P:temp]]></LOGIN_PASSWORD></SCAN></OPTION_PROFILE>"
        for p in STATE["profiles"])
    return f'<?xml version="1.0" encoding="UTF-8" ?>\n<OPTION_PROFILES>{rows}</OPTION_PROFILES>'


def _scan_list(h: QualysDouble, path: str, q: dict) -> str:
    since = q.get("launched_after_datetime", "")
    rows = "".join(
        f"<SCAN>{_el('REF', s['REF'])}<TYPE>{s['TYPE']}</TYPE>{_el('TITLE', s['TITLE'])}"
        f"<LAUNCH_DATETIME>{s['LAUNCH']}</LAUNCH_DATETIME><STATUS><STATE>{s['STATE']}</STATE></STATUS>"
        f"<OPTION_PROFILE>{_el('TITLE', 'Authenticated Scan')}</OPTION_PROFILE></SCAN>"
        for s in STATE["scans"] if s["LAUNCH"] >= since)
    return _doc("SCAN_LIST_OUTPUT", f"<SCAN_LIST>{rows}</SCAN_LIST>")


ROUTES = {
    "/api/2.0/fo/asset/group/": _groups,
    "/api/5.0/fo/asset/host/": _host_list,
    "/api/2.0/fo/asset/ip/": _ip_list,
    "/api/2.0/fo/asset/excluded_ip/": _excluded,
    "/api/5.0/fo/asset/host/vm/detection/": _detection_list,
    "/api/5.0/fo/schedule/scan/": _schedule_list,
    "/api/4.0/fo/subscription/option_profile/vm/": _profiles,
    "/api/3.0/fo/scan/": _scan_list,
}


@pytest.fixture()
def qualys() -> Iterator[str]:
    _reset()
    server = HTTPServer(("127.0.0.1", 0), QualysDouble)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def run_fetcher(short: str, base: str, tmp_path: Path, **env: str) -> tuple[int, dict, dict]:
    out = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    full_env = {
        "PATH": os.environ.get("PATH", ""), "QUALYS_API_URL": base, "QUALYS_USERNAME": USER,
        "QUALYS_PASSWORD": PASSWORD, "QUALYS_PRIVATE_CLOUD_HOST": LOCAL, "EVIDENCE_DIR": str(out), "FETCHER_STATUS_FILE": str(status_file),
        **env,
    }
    proc = subprocess.run([sys.executable, str(QUALYS / short / "fetcher.py")], env=full_env,
                          cwd=QUALYS / short, capture_output=True, text=True, timeout=60)
    evidence = json.loads((out / f"qualys_{short}.json").read_text())
    status = json.loads(status_file.read_text()) if status_file.exists() else {}
    return proc.returncode, evidence, status


# --------------------------------------------------------------------------- #
# client
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(("raw", "expected"), [
    ("https://qualysapi.qualys.com", "https://qualysapi.qualys.com"),
    ("https://QualysAPI.gov1.qualys.us/api/2.0/", "https://qualysapi.gov1.qualys.us"),
    ("https://qualysapi.qg1.apps.qualys.co.uk", "https://qualysapi.qg1.apps.qualys.co.uk"),
    ("https://qualysapi.qg9.apps.qualys.com", "https://qualysapi.qg9.apps.qualys.com"),
])
def test_qualys_platform_urls_are_accepted(raw: str, expected: str) -> None:
    assert normalize_api_url(raw) == expected


@pytest.mark.parametrize("raw", [
    "http://qualysapi.qualys.com", "https://qualysguard.qualys.com", "https://u:p@qualysapi.qualys.com", "not a url",
    "https://qualysapi.qualys.co", "https://qualysapi.qualys.com.example.test", "https://qualysapi.notqualys.com",
    "https://api.qualys.com", "https://qualysapi.example.test", "http://127.0.0.1:8080",
])
def test_other_api_urls_are_refused(raw: str) -> None:
    with pytest.raises(QualysError) as e:
        normalize_api_url(raw)
    assert e.value.code == "bad_config"


def test_private_cloud_host_must_be_named() -> None:
    assert normalize_api_url("https://qualysapi.qualys.example.test", " QualysAPI.qualys.example.test ") == \
        "https://qualysapi.qualys.example.test"
    assert normalize_api_url("http://127.0.0.1:8080", LOCAL) == "http://127.0.0.1:8080"
    with pytest.raises(QualysError, match="QUALYS_PRIVATE_CLOUD_HOST") as e:
        normalize_api_url("https://qualysapi.qualys.example.test", "qualysapi.other.example.test")
    assert e.value.code == "bad_config"


def test_client_knows_the_platform() -> None:
    assert QualysClient("https://qualysapi.gov1.qualys.us", "u", "p").platform == "GOV1"
    assert QualysClient("https://qualysapi.example.test", "u", "p", "qualysapi.example.test").platform == \
        "private_or_unlisted"


def test_unnamed_host_fails_before_credentials_are_sent(qualys: str, tmp_path: Path) -> None:
    code, ev, status = run_fetcher("scan_coverage", qualys, tmp_path, QUALYS_PRIVATE_CLOUD_HOST="")
    assert code == 1 and status["code"] == "bad_config"
    assert "QUALYS_PRIVATE_CLOUD_HOST" in status["error"]
    assert STATE["log"] == [] and ev["summary"] is None


def test_paging_follows_the_warning_url_to_the_end(qualys: str) -> None:
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: None)
    ids = [h.findtext("ID") for h in client.records("/api/5.0/fo/asset/host/", {"action": "list"}, "HOST", "op")]
    assert ids == ["101", "102", "103", "104", "105"]
    assert client.pages == 3
    assert [entry["query"].get("id_min") for entry in STATE["log"]] == [None, "103", "105"]


def test_next_pages_keep_the_original_filters(qualys: str) -> None:
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: None)
    params = {"action": "list", "status": "Fixed", "include_ignored": "1"}
    list(client.records("/api/5.0/fo/asset/host/", params, "HOST", "op"))
    assert all(e["query"]["status"] == "Fixed" and e["query"]["include_ignored"] == "1" for e in STATE["log"])
    assert "truncation_limit" not in STATE["log"][1]["query"]


def test_a_later_warning_does_not_drop_the_next_page(qualys: str) -> None:
    STATE["extra_warning"] = True
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: None)
    ids = [h.findtext("ID") for h in client.records("/api/5.0/fo/asset/host/", {"action": "list"}, "HOST", "op")]
    assert ids == ["101", "102", "103", "104", "105"]
    assert client.pages == 3


def test_next_page_without_id_min_stops_as_partial(qualys: str) -> None:
    STATE["drop_id_min"] = True
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: None)
    with pytest.raises(QualysError) as e:
        list(client.records("/api/5.0/fo/asset/host/", {"action": "list"}, "HOST", "op"))
    assert e.value.code == "partial_failure"


def test_next_page_on_another_host_is_not_followed(qualys: str) -> None:
    STATE["bad_next"] = True
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: None)
    with pytest.raises(QualysError, match="outside"):
        list(client.records("/api/5.0/fo/asset/host/", {"action": "list"}, "HOST", "op"))
    assert len(STATE["log"]) == 1


def test_entities_are_refused_not_expanded(qualys: str) -> None:
    STATE["entity"] = True
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: None)
    with pytest.raises(QualysError, match="parsed safely") as e:
        list(client.records("/api/5.0/fo/asset/host/vm/detection/", {"action": "list"}, "HOST", "op"))
    assert e.value.code == "internal_error"
    assert type(e.value.__cause__).__name__ == "EntitiesForbidden"


def test_rate_limit_is_retried(qualys: str) -> None:
    STATE["throttle"]["/api/2.0/fo/asset/group/"] = 2
    waits: list[float] = []
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=waits.append)
    groups = list(client.records("/api/2.0/fo/asset/group/", {"action": "list"}, "ASSET_GROUP", "op"))
    assert len(groups) == 3 and waits == [0.0, 0.0]


def test_rate_limit_wait_over_the_cap_fails_as_rate_limited(qualys: str) -> None:
    STATE["throttle"]["/api/2.0/fo/asset/group/"] = 1
    STATE["wait"] = "3600"
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: pytest.fail("must not wait an hour"))
    with pytest.raises(QualysError) as e:
        list(client.records("/api/2.0/fo/asset/group/", {"action": "list"}, "ASSET_GROUP", "op"))
    assert e.value.code == "rate_limited"


@pytest.mark.parametrize(("status", "code", "expected"), [
    (401, "2000", "auth_failed"), (409, "2003", "bad_config"), (403, "2012", "not_authorized"),
    (409, "2011", "auth_failed"), (400, "1905", "bad_config"),
])
def test_errors_are_classified_without_retry(qualys: str, status: int, code: str, expected: str) -> None:
    STATE["fail"]["/api/2.0/fo/asset/group/"] = (status, code, "denied")
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=lambda s: pytest.fail("must not retry"))
    with pytest.raises(QualysError) as e:
        list(client.records("/api/2.0/fo/asset/group/", {"action": "list"}, "ASSET_GROUP", "op"))
    assert (e.value.code, e.value.qualys_code) == (expected, code)
    assert len(STATE["log"]) == 1


def test_server_errors_are_retried_then_reported(qualys: str) -> None:
    STATE["fail"]["/api/2.0/fo/asset/group/"] = (503, "1999", "maintenance")
    waits: list[float] = []
    client = QualysClient(qualys, USER, PASSWORD, LOCAL, sleep=waits.append)
    with pytest.raises(QualysError) as e:
        list(client.records("/api/2.0/fo/asset/group/", {"action": "list"}, "ASSET_GROUP", "op"))
    assert e.value.code == "target_unreachable" and len(waits) == 4


# --------------------------------------------------------------------------- #
# qualys_scan_coverage
# --------------------------------------------------------------------------- #

def test_scan_coverage_happy_path(qualys: str, tmp_path: Path, assert_summary_documented) -> None:
    code, ev, status = run_fetcher("scan_coverage", qualys, tmp_path)
    assert code == 0, status
    s = ev["summary"]
    assert_summary_documented("qualys/scan_coverage", s)
    assert (s["total_hosts"], s["scan_window_days"]) == (5, 31)
    assert s["hosts_by_tracking_method"] == {"ip": 2, "dns": 1, "netbios": 0, "cloud_agent": 1,
                                             "cloud_instance": 1, "other": 0, "not_returned": 0}
    assert (s["hosts_scanned_within_window"], s["hosts_not_scanned_within_window"]) == (2, 2)
    assert (s["hosts_without_vm_scan_date"], s["hosts_scan_date_unreadable"]) == (1, 1)
    assert s["max_days_since_vm_scan"] == 45.0
    assert (s["hosts_auth_scanned_within_window"], s["hosts_auth_scan_older_than_window"],
            s["hosts_never_auth_scanned"]) == (1, 1, 3)
    assert (s["subscription_ips"], s["subscription_ips_without_host_record"], s["excluded_ips"]) == (15, 11, 1)
    assert ev["ips_without_host_record"] == ["10.0.0.3-10.0.0.8", "10.0.0.10", "10.0.2.0-10.0.2.3"]
    assert (s["scope_all"], s["visible_asset_groups"]) == (True, 3)
    assert ev["metadata"]["population"] == {"collected": 5, "pages": 6, "complete": True}
    assert ev["metadata"]["platform"] == "private_or_unlisted"
    host_calls = [e for e in STATE["log"] if e["path"] == "/api/5.0/fo/asset/host/"]
    assert host_calls[0]["query"]["details"] == "All"


def test_scan_coverage_window_is_configurable(qualys: str, tmp_path: Path) -> None:
    code, ev, _ = run_fetcher("scan_coverage", qualys, tmp_path, QUALYS_SCAN_WINDOW_DAYS="60")
    assert code == 0
    assert ev["summary"]["hosts_scanned_within_window"] == 3
    assert ev["summary"]["hosts_auth_scanned_within_window"] == 2


def test_scan_coverage_partial_scope_reads_false(qualys: str, tmp_path: Path) -> None:
    STATE["groups"] = ["DMZ"]
    code, ev, _ = run_fetcher("scan_coverage", qualys, tmp_path)
    assert code == 0
    assert ev["summary"]["scope_all"] is False


def test_scan_coverage_forbidden_ip_list_is_null_not_zero(qualys: str, tmp_path: Path) -> None:
    STATE["fail"]["/api/2.0/fo/asset/ip/"] = (403, "2012", "not licensed")
    code, ev, status = run_fetcher("scan_coverage", qualys, tmp_path)
    assert code == 1
    assert status["code"] == "not_authorized"
    s = ev["summary"]
    assert s["subscription_ips"] is None and s["subscription_ips_without_host_record"] is None
    assert s["total_hosts"] == 5 and s["excluded_ips"] == 1
    assert ev["metadata"]["partial_failure"] is True
    assert ev["metadata"]["population"]["complete"] is False
    assert ev["metadata"]["api_failures"][0]["operation"] == "list_ips"


def test_scan_coverage_failed_scope_read_is_null(qualys: str, tmp_path: Path) -> None:
    STATE["fail"]["/api/2.0/fo/asset/group/"] = (403, "2012", "no")
    code, ev, _ = run_fetcher("scan_coverage", qualys, tmp_path)
    assert code == 1
    assert ev["summary"]["scope_all"] is None and ev["summary"]["visible_asset_groups"] is None


def test_scan_coverage_failed_host_page_publishes_no_summary(qualys: str, tmp_path: Path) -> None:
    STATE["bad_next"] = True
    code, ev, status = run_fetcher("scan_coverage", qualys, tmp_path)
    assert code == 1
    assert ev["summary"] is None
    assert ev["metadata"]["population"]["complete"] is False
    assert status["code"] == "internal_error"


def test_scan_coverage_bad_login(qualys: str, tmp_path: Path) -> None:
    code, ev, status = run_fetcher("scan_coverage", qualys, tmp_path, QUALYS_PASSWORD="wrong")
    assert code == 1
    assert status["code"] == "auth_failed"
    assert ev["summary"] is None


def test_scan_coverage_missing_url(qualys: str, tmp_path: Path) -> None:
    code, ev, status = run_fetcher("scan_coverage", qualys, tmp_path, QUALYS_API_URL="")
    assert code == 1
    assert status["code"] == "bad_config"
    assert "QUALYS_API_URL" in status["error"]


def test_scan_coverage_rate_limit_recovers(qualys: str, tmp_path: Path) -> None:
    STATE["throttle"]["/api/5.0/fo/asset/host/"] = 2
    code, ev, _ = run_fetcher("scan_coverage", qualys, tmp_path)
    assert code == 0
    assert ev["summary"]["total_hosts"] == 5


# --------------------------------------------------------------------------- #
# qualys_scan_schedules
# --------------------------------------------------------------------------- #

def test_scan_schedules_happy_path(qualys: str, tmp_path: Path, assert_summary_documented) -> None:
    code, ev, status = run_fetcher("scan_schedules", qualys, tmp_path)
    assert code == 0, status
    s = ev["summary"]
    assert_summary_documented("qualys/scan_schedules", s)
    assert (s["total_schedules"], s["active_schedules"], s["inactive_schedules"]) == (4, 3, 1)
    assert s["active_schedules_by_recurrence"] == {"daily": 1, "weekly": 1, "monthly": 1, "once": 0,
                                                   "not_returned": 0}
    assert (s["active_schedules_within_window"], s["active_schedules_over_window"],
            s["active_schedules_interval_unread"]) == (2, 1, 0)
    assert (s["active_schedules_with_authentication"], s["active_schedules_without_authentication"],
            s["active_schedules_authentication_unread"]) == (1, 1, 1)
    assert (s["option_profiles"], s["option_profiles_with_authentication"]) == (2, 1)
    assert s["scans_in_window"] == 4
    assert s["scans_by_state"] == {"finished": 1, "running": 1, "queued": 0, "loading": 1, "paused": 0,
                                   "canceled": 0, "error": 1, "other": 0, "not_returned": 0}
    assert s["scans_by_type"] == {"scheduled": 2, "on_demand": 1, "api": 1, "other": 0, "not_returned": 0}
    assert s["scheduled_scans_finished_in_window"] == 1
    weekly = next(x for x in ev["schedules"] if x["schedule_id"] == "1")
    assert (weekly["interval_days"], weekly["asset_groups"], weekly["authentication_types"]) == (
        7, ["All"], ["Unix", "Windows"])
    assert "L:Guest" not in json.dumps(ev) and "acme_mgr" not in json.dumps(ev)
    scan_call = next(e for e in STATE["log"] if e["path"] == "/api/3.0/fo/scan/")
    assert scan_call["query"]["launched_after_datetime"].endswith("Z")


def test_scan_schedules_monthly_fits_the_default_window(qualys: str, tmp_path: Path) -> None:
    STATE["schedules"][1]["SCHEDULE"] = '<MONTHLY frequency_months="1" day_of_month="1"/>'
    code, ev, _ = run_fetcher("scan_schedules", qualys, tmp_path)
    s = ev["summary"]
    assert code == 0 and s["scan_window_days"] == 31
    assert (s["active_schedules_within_window"], s["active_schedules_over_window"]) == (3, 0)
    code, ev, _ = run_fetcher("scan_schedules", qualys, tmp_path, QUALYS_SCAN_WINDOW_DAYS="30")
    assert code == 0 and ev["summary"]["active_schedules_over_window"] == 1


def test_scan_schedules_profiles_without_auth_setting_read_null(qualys: str, tmp_path: Path) -> None:
    for p in STATE["profiles"]:
        p["AUTHENTICATION"] = None
    code, ev, _ = run_fetcher("scan_schedules", qualys, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["active_schedules_authentication_unread"] == 3
    assert s["active_schedules_without_authentication"] == 0
    assert s["option_profiles_with_authentication"] is None


def test_scan_schedules_failed_scan_list_is_null(qualys: str, tmp_path: Path) -> None:
    STATE["fail"]["/api/3.0/fo/scan/"] = (403, "2012", "no")
    code, ev, status = run_fetcher("scan_schedules", qualys, tmp_path)
    assert code == 1 and status["code"] == "not_authorized"
    s = ev["summary"]
    assert s["scans_in_window"] is None and s["scans_by_state"] is None
    assert s["total_schedules"] == 4


def test_scan_schedules_failed_profiles_leave_auth_unread(qualys: str, tmp_path: Path) -> None:
    STATE["fail"]["/api/4.0/fo/subscription/option_profile/vm/"] = (400, "1905", "bad parameter")
    code, ev, _ = run_fetcher("scan_schedules", qualys, tmp_path)
    assert code == 1
    s = ev["summary"]
    assert s["option_profiles"] is None and s["active_schedules_authentication_unread"] == 3


def test_scan_schedules_rate_limit_recovers(qualys: str, tmp_path: Path) -> None:
    STATE["throttle"]["/api/5.0/fo/schedule/scan/"] = 1
    code, ev, _ = run_fetcher("scan_schedules", qualys, tmp_path)
    assert code == 0 and ev["summary"]["total_schedules"] == 4


# --------------------------------------------------------------------------- #
# qualys_vulnerability_findings
# --------------------------------------------------------------------------- #

def _sev(**counts: int) -> dict:
    return {k: counts.get(f"s{k}" if k != "not_returned" else k, 0) for k in ("5", "4", "3", "2", "1", "not_returned")}


def test_vulnerability_findings_happy_path(qualys: str, tmp_path: Path, assert_summary_documented) -> None:
    code, ev, status = run_fetcher("vulnerability_findings", qualys, tmp_path)
    assert code == 0, status
    s = ev["summary"]
    assert_summary_documented("qualys/vulnerability_findings", s)
    assert s["open_detections"] == 6
    assert s["open_by_severity"] == _sev(s5=2, s4=2, s3=1, s2=1)
    assert s["open_by_type"] == {"confirmed": 5, "potential": 1, "other": 0, "not_returned": 0}
    assert s["hosts_with_open_detections"] == 3
    assert s["remediation_days"] == {"5": 30, "4": 30, "3": 90, "2": 180, "1": 180}
    assert s["past_due_detections"] == 2
    assert s["past_due_by_severity"] == _sev(s5=1, s2=1)
    assert s["past_due_confirmed"] == 1
    assert (s["open_age_unread"], s["oldest_open_days"]) == (0, 200.0)
    assert (s["ignored_detections"], s["disabled_detections"], s["ignored_or_disabled_past_due"]) == (1, 1, 1)
    assert ev["detection_records"] == "all" and len(ev["detections"]) == 6
    assert "Authentication Record" not in json.dumps(ev)
    q = next(e for e in STATE["log"] if e["path"] == "/api/5.0/fo/asset/host/vm/detection/")["query"]
    assert (q["status"], q["include_ignored"], q["include_disabled"], q["show_results"]) == (
        "New,Active,Re-Opened", "1", "1", "0")
    assert ev["metadata"]["population"]["pages"] == 3
    det_calls = [e for e in STATE["log"] if e["path"] == "/api/5.0/fo/asset/host/vm/detection/"]
    assert len(det_calls) == 2 and all(e["query"]["status"] == "New,Active,Re-Opened" for e in det_calls)


def test_vulnerability_findings_custom_timeframes(qualys: str, tmp_path: Path) -> None:
    code, ev, _ = run_fetcher("vulnerability_findings", qualys, tmp_path,
                              QUALYS_REMEDIATION_DAYS="5:60,4:60,3:120,2:365,1:365")
    assert code == 0
    assert ev["summary"]["past_due_detections"] == 0


@pytest.mark.parametrize("bad", ["5:30,4:30", "5:x,4:30,3:90,2:180,1:180", "6:1,4:30,3:90,2:180,1:180"])
def test_vulnerability_findings_bad_timeframes_are_bad_config(qualys: str, tmp_path: Path, bad: str) -> None:
    code, ev, status = run_fetcher("vulnerability_findings", qualys, tmp_path, QUALYS_REMEDIATION_DAYS=bad)
    assert code == 1 and status["code"] == "bad_config"
    assert ev["summary"] is None


def test_vulnerability_findings_past_due_only(qualys: str, tmp_path: Path) -> None:
    code, ev, _ = run_fetcher("vulnerability_findings", qualys, tmp_path, QUALYS_INCLUDE_DETECTION_RECORDS="false")
    assert code == 0
    assert ev["detection_records"] == "past_due_only"
    assert {d["qid"] for d in ev["detections"]} == {"38739", "38741", "38742"}
    assert ev["summary"]["open_detections"] == 6


def test_vulnerability_findings_age_restarts_at_reopening(qualys: str, tmp_path: Path) -> None:
    code, ev, _ = run_fetcher("vulnerability_findings", qualys, tmp_path)
    assert code == 0
    reopened = next(d for d in ev["detections"] if d["qid"] == "90001")
    assert (reopened["age_from"], reopened["age_days"], reopened["within_timeframe"]) == ("last_reopened", 10.0, True)
    assert reopened["first_found"] == _iso(100)
    never = next(d for d in ev["detections"] if d["qid"] == "38739")
    assert (never["age_from"], never["age_days"]) == ("first_found", 45.0)


def test_vulnerability_findings_forbidden_is_null_not_zero(qualys: str, tmp_path: Path) -> None:
    STATE["fail"]["/api/5.0/fo/asset/host/vm/detection/"] = (403, "2012", "not licensed")
    code, ev, status = run_fetcher("vulnerability_findings", qualys, tmp_path)
    assert code == 1 and status["code"] == "not_authorized"
    assert ev["summary"] is None
    assert ev["metadata"]["population"]["complete"] is False


def test_vulnerability_findings_failed_second_page_publishes_no_summary(qualys: str, tmp_path: Path) -> None:
    STATE["bad_next"] = True
    code, ev, status = run_fetcher("vulnerability_findings", qualys, tmp_path)
    assert code == 1 and ev["summary"] is None
    assert status["code"] == "internal_error"


def test_vulnerability_findings_rate_limit_recovers(qualys: str, tmp_path: Path) -> None:
    STATE["throttle"]["/api/5.0/fo/asset/host/vm/detection/"] = 2
    code, ev, _ = run_fetcher("vulnerability_findings", qualys, tmp_path)
    assert code == 0 and ev["summary"]["open_detections"] == 6


# --------------------------------------------------------------------------- #
# qualys_vulnerability_remediation
# --------------------------------------------------------------------------- #

def test_vulnerability_remediation_happy_path(qualys: str, tmp_path: Path, assert_summary_documented) -> None:
    code, ev, status = run_fetcher("vulnerability_remediation", qualys, tmp_path)
    assert code == 0, status
    s = ev["summary"]
    assert_summary_documented("qualys/vulnerability_remediation", s)
    assert (s["lookback_days"], s["fixed_detections"], s["fixed_date_unread"]) == (90, 3, 0)
    assert s["fixed_by_severity"] == _sev(s5=1, s3=1, s1=1)
    assert (s["fixed_within_timeframe"], s["fixed_after_timeframe"], s["fixed_timeframe_unread"]) == (2, 1, 0)
    assert s["fixed_after_timeframe_by_severity"] == _sev(s5=1)
    assert (s["median_days_to_fix"], s["max_days_to_fix"]) == (58.0, 60.0)
    assert (s["reopened_in_lookback"], s["fixed_after_reopening"]) == (2, 1)
    refixed = next(r for r in ev["fixed"] if r["qid"] == "38747")
    assert (refixed["age_from"], refixed["age_days"], refixed["first_found"]) == ("last_reopened", 58.0, _iso(100))
    q = next(e for e in STATE["log"] if e["path"] == "/api/5.0/fo/asset/host/vm/detection/")["query"]
    assert q["status"] == "Fixed,Re-Opened,Active" and q["detection_updated_since"].endswith("Z")


def test_vulnerability_remediation_counts_a_reopened_detection_now_active(qualys: str, tmp_path: Path) -> None:
    STATE["detections"]["103"].append({
        "UNIQUE_VULN_ID": "y", "QID": "38748", "TYPE": "Confirmed", "SEVERITY": "4", "STATUS": "Active",
        "FIRST_FOUND_DATETIME": _iso(300), "LAST_FOUND_DATETIME": _iso(1), "LAST_FIXED_DATETIME": _iso(40),
        "LAST_REOPENED_DATETIME": _iso(15), "TIMES_REOPENED": "1", "IS_IGNORED": "0", "IS_DISABLED": "0"})
    code, ev, _ = run_fetcher("vulnerability_remediation", qualys, tmp_path)
    assert code == 0
    assert ev["summary"]["reopened_in_lookback"] == 3 and ev["summary"]["fixed_detections"] == 3
    assert {(r["qid"], r["status"]) for r in ev["reopened"]} == {
        ("90001", "Re-Opened"), ("38747", "Fixed"), ("38748", "Active")}
    assert ev["metadata"]["population"]["collected"] == 5


def test_vulnerability_remediation_lookback_is_configurable(qualys: str, tmp_path: Path) -> None:
    code, ev, _ = run_fetcher("vulnerability_remediation", qualys, tmp_path, QUALYS_REMEDIATION_LOOKBACK_DAYS="7")
    assert code == 0
    assert ev["summary"]["fixed_detections"] == 2


def test_vulnerability_remediation_missing_fixed_date_is_unread(qualys: str, tmp_path: Path) -> None:
    STATE["detections"]["101"].append({"UNIQUE_VULN_ID": "x", "QID": "1", "TYPE": "Confirmed", "SEVERITY": "4",
                                       "STATUS": "Fixed", "FIRST_FOUND_DATETIME": _iso(3), "IS_IGNORED": "0",
                                       "IS_DISABLED": "0"})
    code, ev, _ = run_fetcher("vulnerability_remediation", qualys, tmp_path)
    assert code == 0
    assert ev["summary"]["fixed_date_unread"] == 1 and ev["summary"]["fixed_detections"] == 3


def test_vulnerability_remediation_bad_lookback(qualys: str, tmp_path: Path) -> None:
    code, ev, status = run_fetcher("vulnerability_remediation", qualys, tmp_path,
                                   QUALYS_REMEDIATION_LOOKBACK_DAYS="soon")
    assert code == 1 and status["code"] == "bad_config"


def test_vulnerability_remediation_server_error_fails(qualys: str, tmp_path: Path) -> None:
    STATE["fail"]["/api/5.0/fo/asset/host/vm/detection/"] = (400, "1905", "parameter detection_updated_since")
    code, ev, status = run_fetcher("vulnerability_remediation", qualys, tmp_path)
    assert code == 1 and status["code"] == "bad_config"
    assert ev["summary"] is None
