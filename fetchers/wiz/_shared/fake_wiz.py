"""In-process Wiz test double for the wiz fetchers' unit tests.

Not fetcher code: nothing under fetchers/wiz/*/fetcher.py imports it. It lives in
_shared/ so both fetchers' tests/ directories can use one copy. Serves on
127.0.0.1 only (wiz_client allows http for localhost, for exactly this).

Knobs (set before or during a test):
    report_fail_runs  next N report runs end FAILED
    stale_polls       first N status polls return a COMPLETED run whose runAt is
                      older than the fetch started (a leftover from a previous run)
    issues_rows       data rows in the issues CSV (0 = header only)
    vuln_count        number of vulnerability findings
    vuln_break_page   that page returns hasNextPage=true with no endCursor
Records: log, creates, vuln_filters, downloads, download_auth_headers.
"""

from __future__ import annotations

import importlib.util
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

CLIENT_ID, CLIENT_SECRET, TOKEN = "wiz-id", "wiz-secret", "wiz-bearer-xyz"
ISSUE_HEADER = ("Created At,Title,Severity,Status,Resource Type,Resource external ID,"
                "Subscription ID,Issue ID,Resource Name,Status Changed At\n")
STALE_RUN_AT = "2000-01-01T00:00:00.000000Z"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def vuln_node(i: int) -> dict:
    return {
        "id": f"vf-{i:05d}", "name": f"CVE-2024-{1000 + i}", "CVEDescription": "d",
        "CVSSSeverity": "HIGH", "score": 7.5, "severity": "HIGH", "nvdSeverity": "HIGH",
        "status": "OPEN", "hasExploit": False, "hasFix": True, "hasCisaKevExploit": False,
        "firstDetectedAt": "2026-08-01T00:00:00Z", "lastDetectedAt": "2026-09-30T00:00:00Z",
        "resolvedAt": None, "description": "d", "remediation": "upgrade",
        "detailedName": "openssl", "version": "1.1.1", "fixedVersion": "3.0.0",
        "detectionMethod": "PACKAGE", "link": "https://nvd", "portalUrl": "https://app.wiz.io/x",
        "epssSeverity": "LOW", "epssPercentile": 0.5, "epssProbability": 0.01,
        "relatedIssueAnalytics": {"issueCount": 1, "criticalSeverityCount": 0,
                                  "highSeverityCount": 1, "mediumSeverityCount": 0,
                                  "lowSeverityCount": 0},
        "vulnerableAsset": {"id": f"asset-{i % 7}", "type": "VIRTUAL_MACHINE", "name": f"vm-{i % 7}",
                            "region": "us-east-1", "providerUniqueId": f"i-{i % 7}",
                            "cloudPlatform": "AWS", "status": "Active", "subscriptionName": "prod",
                            "subscriptionExternalId": "1", "tags": {"env": "prod"},
                            "hasWideInternetExposure": False, "operatingSystem": "Linux",
                            "ipAddresses": ["10.0.0.1"]},
    }


class FakeWiz:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reports: dict = {}
        self.log: list = []              # (method, path)
        self.creates: list = []          # CreateReport inputs
        self.vuln_filters: list = []     # filterBy seen on each vuln page
        self.downloads = 0
        self.download_auth_headers: list = []
        self.polls = 0
        self.report_fail_runs = 0
        self.stale_polls = 0
        self.issues_rows = 3
        self.vuln_count = 250
        self.vuln_break_page = 0
        self._server: ThreadingHTTPServer | None = None

    # -- lifecycle -------------------------------------------------------- #
    def start(self) -> "FakeWiz":
        fake = self

        class Handler(_Handler):
            owner = fake

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"  # type: ignore[union-attr]

    def env(self) -> dict:
        return {"WIZ_CLIENT_ID": CLIENT_ID, "WIZ_CLIENT_SECRET": CLIENT_SECRET,
                "WIZ_AUTH_URL": f"{self.base}/oauth/token",
                "WIZ_API_ENDPOINT": f"{self.base}/graphql",
                "WIZ_REPORT_POLL_SECONDS": "0.01"}

    # -- helpers ---------------------------------------------------------- #
    def issues_csv(self) -> str:
        rows = [ISSUE_HEADER]
        for i in range(self.issues_rows):
            rows.append(f'2026-09-01T00:00:00Z,"Public bucket, {i}",HIGH,OPEN,bucket,'
                        f'arn:aws:s3:::b{i},123,issue-{i:04d},b{i},2026-09-02T00:00:00Z\n')
        return "".join(rows)

    def graphql(self, q: str, v: dict) -> dict:
        if "FindReports" in q:
            return {"reports": {"nodes": [
                {"id": r["id"], "name": r["name"], "type": {"id": "ISSUES"}}
                for r in self.reports.values() if v.get("search", "") in r["name"]]}}
        if "CreateReport" in q:
            rid = "rep-" + uuid.uuid4().hex[:6]
            self.creates.append(v["input"])
            self.reports[rid] = {"id": rid, "name": v["input"]["name"], "project_id":
                                 v["input"].get("projectId"), "status": "IN_PROGRESS",
                                 "runAt": _now(), "polls": 0}
            return {"createReport": {"report": {"id": rid}}}
        if "UpdateReport" in q:
            return {"updateReport": {"report": {"id": v["input"]["id"]}}}
        if "RerunReport" in q:
            r = self.reports[v["reportId"]]
            r.update(status="IN_PROGRESS", runAt=_now(), polls=0)
            return {"rerunReport": {"report": {"id": r["id"]}}}
        if "ReportDownloadUrl" in q:
            r = self.reports[v["reportId"]]
            url = f"{self.base}/download/{r['id']}.csv"
            self.polls += 1
            if self.stale_polls > 0:
                self.stale_polls -= 1
                return {"report": {"lastRun": {"status": "COMPLETED", "url": url,
                                               "runAt": STALE_RUN_AT}}}
            r["polls"] += 1
            if r["status"] == "IN_PROGRESS" and r["polls"] >= 2:
                if self.report_fail_runs > 0:
                    self.report_fail_runs -= 1
                    r["status"] = "FAILED"
                else:
                    r["status"] = "COMPLETED"
            done = r["status"] == "COMPLETED"
            return {"report": {"lastRun": {"status": r["status"], "url": url if done else None,
                                           "runAt": r["runAt"]}}}
        if "VulnerabilityFindingsPage" in q:
            self.vuln_filters.append(v.get("filterBy"))
            start = int(v.get("after") or 0)
            page_no = start // v["first"] + 1
            end = min(start + v["first"], self.vuln_count)
            more = end < self.vuln_count
            cursor = str(end) if more else None
            if self.vuln_break_page == page_no:
                cursor = None
            return {"vulnerabilityFindings": {
                "nodes": [vuln_node(i) for i in range(start, end)],
                "pageInfo": {"hasNextPage": more, "endCursor": cursor}}}
        return {}


class _Handler(BaseHTTPRequestHandler):
    owner: FakeWiz

    def log_message(self, *a):  # silence
        pass

    def _send(self, code: int, body, ctype: str = "application/json") -> None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        o = self.owner
        with o.lock:
            o.log.append(("GET", self.path))
            if self.path.startswith("/download/"):
                o.downloads += 1
                o.download_auth_headers.append(self.headers.get("Authorization"))
                return self._send(200, o.issues_csv().encode(), "text/csv")
            self._send(404, {"error": "no route"})

    def do_POST(self):
        o = self.owner
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with o.lock:
            o.log.append(("POST", self.path))
            if self.path == "/oauth/token":
                f = parse_qs(raw.decode())
                if f.get("client_id") == [CLIENT_ID] and f.get("client_secret") == [CLIENT_SECRET]:
                    return self._send(200, {"access_token": TOKEN})
                return self._send(401, {"error": "invalid_client"})
            if self.path == "/graphql":
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._send(401, {"error": "unauthorized"})
                body = json.loads(raw)
                return self._send(200, {"data": o.graphql(body["query"], body.get("variables") or {})})
            self._send(404, {"error": "no route"})


# -- running a fetcher in-process ----------------------------------------- #
def load_fetcher(fetcher_py: Path, name: str):
    """Import fetcher.py fresh, so module-level env reads (poll seconds) see the
    test's environment."""
    spec = importlib.util.spec_from_file_location(name, fetcher_py)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def run_main(mod, monkeypatch, tmp_path: Path, env: dict) -> dict:
    """Run mod.main() with `env` (plus a status file and evidence dir) and report
    what happened: exit code, files written, and the failure status the fetcher
    reported."""
    import wiz_client

    monkeypatch.setattr(wiz_client, "MAX_RETRIES", 0)
    # Module-level constants are read at import, before this test's env is set.
    if hasattr(mod, "POLL_SECONDS"):
        monkeypatch.setattr(mod, "POLL_SECONDS", float(env.get("WIZ_REPORT_POLL_SECONDS", "0.01")))
    out, status = tmp_path / "issue-reports", tmp_path / "status.json"
    for k in [k for k in os.environ if k.startswith("WIZ_")]:
        monkeypatch.delenv(k)
    for k, v in {**env, "EVIDENCE_DIR": str(out), "FETCHER_STATUS_FILE": str(status)}.items():
        monkeypatch.setenv(k, v)
    rc = mod.main()
    return {"rc": rc,
            "files": sorted(p.name for p in out.iterdir()) if out.exists() else [],
            "out": out,
            "status": json.loads(status.read_text()) if status.exists() else None}
