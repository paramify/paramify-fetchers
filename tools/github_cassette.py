#!/usr/bin/env python3
"""Record GitHub API responses from a real run, and replay them through the real fetcher code.

Only the socket is faked: replay hands recorded `requests.Response` objects to
the shared client, so paging, state classification and every fetcher's logic
run exactly as they do live.

    python tools/github_cassette.py record <fetcher> <cassette.json>   # env: GITHUB_ORG, GITHUB_TOKEN, ...

Recording redacts the sandbox owner's login. Replay and the fault sweep are used
by tests/test_github_cassettes.py and tools/github_fault_sweep.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlparse

import requests
from requests.structures import CaseInsensitiveDict

ROOT = Path(__file__).resolve().parent.parent
GITHUB = ROOT / "fetchers" / "github"
KEPT_HEADERS = ("Link", "X-Accepted-GitHub-Permissions", "Content-Type")
REDACT = {"StewartClaw": "sandbox-owner", "stewartclaw": "sandbox-owner"}


def key(url: str, params: Optional[dict] = None) -> str:
    """Path plus sorted query, host dropped, so a recording replays against any api_url."""
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query.update({k: str(v) for k, v in (params or {}).items()})
    query.pop("since", None)  # derived from the clock; one recording must replay on any day
    path = parsed.path.removeprefix("/api/v3")
    return f"{path}?{urlencode(sorted(query.items()))}" if query else path


def graphql_key(body: dict) -> str:
    """The query's hash plus its variables, minus the clock-derived `since`."""
    variables = {k: v for k, v in (body.get("variables") or {}).items() if k != "since"}
    digest = hashlib.sha256(body["query"].encode()).hexdigest()[:12]
    return f"POST /graphql {digest} {json.dumps(variables, sort_keys=True)}"


EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Hypermedia and long text no fetcher reads (tests/test_github_schema.py knows every field that is read).
DROPPED = {"node_id", "_links", "gravatar_id", "description", "body", "references", "identifiers", "cvss",
           "cvss_severities", "cwes", "vulnerabilities", "license", "topics", "repo", "base",
           "copyrightText"}


def redact(text: str) -> str:
    for old, new in REDACT.items():
        text = text.replace(old, new)
    return EMAIL.sub(lambda m: "redacted@" + m.group(0).split("@")[1] if m.group(0).endswith(".invalid")
                     else "redacted@example.com", text)


def compact(value: Any) -> Any:
    """Drop GitHub's hypermedia (links back into the API, node ids); no fetcher reads them."""
    if isinstance(value, dict):
        # "repo" is an embedded repository object in most answers but the repository's name in an audit log event.
        return {k: compact(v) for k, v in value.items()
                if not (k in DROPPED and (k != "repo" or isinstance(v, dict))) and not ((k == "url" or k.endswith("_url")) and isinstance(v, str)
                                             and v.startswith(("https://api.github.com", "https://github.com",
                                                               "https://avatars.githubusercontent.com")))}
    if isinstance(value, list):
        return [compact(v) for v in value]
    return value


def to_response(entry: dict, url: str) -> requests.Response:
    resp = requests.Response()
    resp.status_code = entry["status"]
    resp._content = json.dumps(entry["body"]).encode() if entry["body"] is not None else b""
    resp.headers = CaseInsensitiveDict(entry.get("headers") or {})
    resp.url = url
    resp.reason = entry.get("reason", "")
    return resp


class Recorder:
    def __init__(self, session: requests.Session):
        self.session = session
        self.entries: Dict[str, dict] = {}
        self.headers = session.headers

    def get(self, url: str, params: Optional[dict] = None, timeout: Any = None) -> requests.Response:
        resp = self.session.get(url, params=params, timeout=timeout)
        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = None
        headers = {h: resp.headers[h] for h in KEPT_HEADERS if h in resp.headers}
        if "Link" in headers:
            headers["Link"] = headers["Link"].replace(urlparse(url)._replace(path="", query="").geturl(), "")
        self._keep(key(url, params), resp, body, headers)
        return resp

    def post(self, url: str, json: Optional[dict] = None, timeout: Any = None) -> requests.Response:
        resp = self.session.post(url, json=json, timeout=timeout)
        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = None
        self._keep(graphql_key(json or {}), resp, body,
                   {h: resp.headers[h] for h in KEPT_HEADERS + ("X-RateLimit-Resource",) if h in resp.headers})
        return resp

    def _keep(self, k: str, resp: requests.Response, body: Any, headers: dict) -> None:
        # A GraphQL answer holds only the fields the fetcher asked for, pull request bodies among them.
        self.entries[k] = json.loads(redact(json.dumps(
            {"status": resp.status_code, "reason": resp.reason, "headers": headers,
             "body": body if k.startswith("POST ") else compact(body)})))


class Replay:
    """A requests.Session stand-in serving a cassette. `fault` replaces one key's answer."""

    def __init__(self, cassette: Dict[str, dict], fault: Optional[tuple] = None):
        self.cassette = cassette
        self.fault = fault
        self.headers: dict = {}
        self.calls: list = []
        self.missing: list = []

    def get(self, url: str, params: Optional[dict] = None, timeout: Any = None) -> requests.Response:
        return self._serve(key(url, params), url)

    def post(self, url: str, json: Optional[dict] = None, timeout: Any = None) -> requests.Response:
        return self._serve(graphql_key(json or {}), url)

    def _serve(self, k: str, url: str) -> requests.Response:
        self.calls.append(k)
        if self.fault and self.fault[0] == k:
            return self.fault[1](url)
        entry = self.cassette.get(k)
        if entry is None:
            self.missing.append(k)
            return to_response({"status": 599, "body": {"message": f"not in cassette: {k}"}}, url)
        return to_response(entry, url)


def record(fetcher: str, out: Path) -> int:
    recorders = []
    real_session = requests.Session

    def recording_session():
        r = Recorder(real_session())
        recorders.append(r)
        return r

    requests.Session = recording_session  # type: ignore[misc]
    sys.argv = [str(GITHUB / fetcher / "fetcher.py")]
    code = 0
    try:
        runpy.run_path(str(GITHUB / fetcher / "fetcher.py"), run_name="__main__")
    except SystemExit as exc:
        code = int(exc.code or 0)
    finally:
        requests.Session = real_session  # type: ignore[misc]
    entries = {k: v for r in recorders for k, v in r.entries.items()}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"fetcher": fetcher, "org": redact(os.environ.get("GITHUB_ORG", "")),
                               "env": {k: v for k, v in os.environ.items()
                                       if k.startswith(("GITHUB_", "PARAMIFY_", "FEDRAMP_")) and k != "GITHUB_TOKEN"},
                               "exit_code": code, "entries": entries}, indent=1, sort_keys=True))
    print(f"{fetcher}: {len(entries)} responses -> {out} (exit {code})")
    return code


def recompact(path: Path) -> None:
    data = json.loads(redact(path.read_text()))
    data["entries"] = {(k if k.startswith("POST ") else key(k)): {**e, "body": e["body"] if k.startswith("POST ") else compact(e["body"])}
                       for k, e in data["entries"].items()}
    path.write_text(json.dumps(data, indent=1, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "compact":
        for p in sys.argv[2:]:
            recompact(Path(p))
        sys.exit(0)
    if len(sys.argv) != 4 or sys.argv[1] != "record":
        sys.exit(__doc__)
    sys.exit(record(sys.argv[2], Path(sys.argv[3])))
