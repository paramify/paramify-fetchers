"""web_page_text, driven against a local HTTP server serving synthetic pages.

The server is real (http.server on 127.0.0.1), so redirects, streaming, the
redirect cap and Content-Length handling go through requests itself. Only the
TLS failure is simulated. The pages under tests/fixtures/web/ are synthetic.
"""

from __future__ import annotations

import importlib.util
import json
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple

import pytest
import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_DIR = REPO_ROOT / "fetchers" / "web" / "page_text"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "web"

_spec = importlib.util.spec_from_file_location("web_page_text_under_test", FETCHER_DIR / "fetcher.py")
wpt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wpt)
wp = sys.modules["web_page"]  # fetchers/web/_shared/web_page.py, put on sys.path by the fetcher


def run_fetcher() -> int:
    return wp.run(wpt.NAME, wpt.collect, wpt.FAILURE_FIELDS)

ASA = (FIXTURES / "synthetic_access_and_services_agreement.html").read_bytes()
DPA = (FIXTURES / "synthetic_data_processing_agreement.html").read_bytes()
TRUST = (FIXTURES / "synthetic_trust_center.json").read_bytes()
JS_SHELL = (FIXTURES / "synthetic_js_shell.html").read_bytes()

SLA = (
    "Paramify shall use commercially reasonable efforts to ensure that Customer may access and use the "
    "Product at least ninety-nine and nine tenths percent (99.9%) of the time each calendar month except "
    "in the case of scheduled maintenance for which Paramify will provide advance notification to Customer."
)
SUPPORT = (
    "Support. Paramify shall provide email support to Customer from 9AM to 5PM Mountain Standard Time, "
    "Monday through to Friday, business days. Paramify shall use commercially reasonable efforts to "
    "respond to support requests within one business day and shall address (internally and externally) "
    "such support requests in a commercially reasonable manner"
)
DPA_CLAUSE = (
    "Paramify shall not Sell Customer Personal Data, nor use, retain, disclose, or otherwise Process "
    "Customer Personal Data outside of its business relationship with the Customer or for any other "
    "purpose except as required by law."
)

FIXED_FIELDS = [
    "collected_at", "target_name", "url", "final_url", "redirects", "http_status",
    "content_type", "title", "last_updated", "text_length", "sha256", "text_sha256",
]

# path -> (status, headers, body). Built per test by the `site` fixture.
Routes = Dict[str, Tuple[int, Dict[str, str], bytes]]


class _Handler(BaseHTTPRequestHandler):
    routes: Routes = {}
    seen_headers: Dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        _Handler.seen_headers = dict(self.headers)
        if self.path.startswith("/hop/"):
            remaining = int(self.path.rsplit("/", 1)[1])
            target = f"/hop/{remaining - 1}" if remaining > 1 else "/asa"
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, headers, body = self.routes.get(self.path, (404, {"Content-Type": "text/html"}, b"<p>Not Found</p>"))
        self.send_response(status)
        for key, value in headers.items():
            if not key.startswith("_"):
                self.send_header(key, value)
        if "Content-Length" not in headers and not headers.get("_no_length"):
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address) -> None:
        pass  # the fetcher hanging up on an oversized body is expected


@pytest.fixture(scope="module")
def server():
    httpd = _QuietServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture
def site(server, monkeypatch, tmp_path):
    html = {"Content-Type": "text/html; charset=utf-8"}
    _Handler.routes = {
        "/asa": (200, html, ASA),
        "/dpa": (200, {"Content-Type": "text/html"}, DPA),
        "/trust.json": (200, {"Content-Type": "application/json"}, TRUST),
        "/trust.vnd": (200, {"Content-Type": "application/vnd.api+json; charset=utf-8"}, TRUST),
        "/readme.txt": (200, {"Content-Type": "text/plain; charset=utf-8"}, b"Plain   text\n\n  kept  as served\n"),
        "/latin1": (200, {"Content-Type": "text/html; charset=ISO-8859-1"}, "<p>Café terms</p>".encode("latin-1")),
        "/pdf": (200, {"Content-Type": "application/pdf"}, b"%PDF-1.7 synthetic"),
        "/nocontenttype": (200, {}, b"<p>hello</p>"),
        "/badjson": (200, {"Content-Type": "application/json"}, b'{"policies": [1, 2'),
        "/shell": (200, html, JS_SHELL),
        "/unauthorized": (401, html, b"<p>Sign in</p>"),
        "/forbidden": (403, html, b"<p>Forbidden</p>"),
        "/ratelimited": (429, {"Content-Type": "text/plain", "Retry-After": "60"}, b"slow down"),
        "/error": (500, html, b"<p>Internal Server Error</p>"),
    }
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("WEB_TARGET_NAME", "legal page")
    monkeypatch.delenv("WEB_VERIFY_SSL", raising=False)
    monkeypatch.setattr(wp, "load_dotenv", lambda: None)

    def run(path_or_url: str):
        url = server + path_or_url if path_or_url.startswith("/") else path_or_url
        monkeypatch.setenv("WEB_PAGE_URL", url)
        code = run_fetcher()
        evidence = json.loads((tmp_path / "web_page_text_legal_page.json").read_text())
        status_file = tmp_path / "status.json"
        status = json.loads(status_file.read_text()) if status_file.exists() else None
        return code, evidence, status

    return run


# --- success -------------------------------------------------------------------

def test_html_page_yields_one_line_per_block(site):
    code, ev, status = site("/asa")
    assert (code, status) == (0, None)
    lines = ev["text"].split("\n")
    assert any(SLA in line for line in lines), "the SLA clause must sit on one line"
    assert SUPPORT in lines
    assert ev["title"] == "Access and Services Agreement | Example Legal (synthetic)"
    assert ev["last_updated"] == "March 3, 2025"
    assert ev["http_status"] == 200 and ev["content_type"] == "text/html; charset=utf-8"
    assert ev["text_length"] == len(ev["text"])
    assert "json" not in ev and "metadata" not in ev


def test_html_noise_is_dropped_and_chrome_is_kept(site):
    _, ev, _ = site("/asa")
    text = ev["text"]
    for dropped in ("font-family", "dataLayer", "January 1, 1999", "from CSS", "enable JavaScript",
                    "decorative icon", "template content"):
        assert dropped not in text
    for kept in ("Home", "Terms & Conditions", "Security & Trust", "© 2025 Example, Inc.",
                 "Tier Response", "Standard One business day"):
        assert kept in text.split("\n")
    assert " " not in text and "  " not in text
    assert all(line == line.strip() and line for line in text.split("\n"))


def test_curly_apostrophes_are_kept_verbatim(site):
    code, ev, _ = site("/dpa")
    assert code == 0
    assert DPA_CLAUSE in ev["text"].split("\n")
    assert "Paramify’s reasonable opinion" in ev["text"]
    assert "Paramify’s obligations" in ev["text"]  # from &rsquo;
    assert "'s" not in ev["text"]
    assert ev["last_updated"] == "1 February 2025", "the first dated line wins"


def test_json_is_parsed_and_kept_verbatim(site):
    code, ev, _ = site("/trust.json")
    assert code == 0
    assert ev["json"] == json.loads(TRUST)
    assert ev["text"] == TRUST.decode("utf-8")
    assert ev["title"] is None
    assert list(ev)[-2:] == ["json", "text"]


def test_plus_json_media_types_are_json(site):
    code, ev, _ = site("/trust.vnd")
    assert code == 0 and ev["json"]["company"] == "Example, Inc."


def test_plain_text_is_kept_as_served(site):
    code, ev, _ = site("/readme.txt")
    assert code == 0
    assert ev["text"] == "Plain   text\n\n  kept  as served\n"


def test_header_charset_decodes_the_body(site):
    code, ev, _ = site("/latin1")
    assert code == 0 and ev["text"] == "Café terms"


def test_fixed_fields_come_first_in_order(site):
    _, ev, _ = site("/asa")
    assert list(ev) == FIXED_FIELDS + ["text"]


def test_redirect_chain_and_final_url_are_recorded(site, server):
    code, ev, _ = site("/hop/2")
    assert code == 0
    assert ev["url"] == f"{server}/hop/2" and ev["final_url"] == f"{server}/asa"
    assert ev["redirects"] == [
        {"url": f"{server}/hop/2", "status": 302, "location": "/hop/1"},
        {"url": f"{server}/hop/1", "status": 302, "location": "/asa"},
    ]


def test_five_redirects_are_allowed(site):
    code, ev, _ = site("/hop/5")
    assert code == 0 and len(ev["redirects"]) == 5


def test_request_headers(site):
    site("/asa")
    assert _Handler.seen_headers["User-Agent"] == f"paramify-fetchers web_page_text/{wpt.VERSION}"
    assert _Handler.seen_headers["Accept"] == "text/html, application/json;q=0.9, text/plain;q=0.8"


def test_sha256_is_of_the_body_bytes(site):
    import hashlib

    _, ev, _ = site("/asa")
    assert ev["sha256"] == hashlib.sha256(ASA).hexdigest()
    assert ev["text_sha256"] == hashlib.sha256(ev["text"].encode("utf-8")).hexdigest()


def test_text_sha256_ignores_markup_only_changes(site):
    _, before, _ = site("/asa")
    _Handler.routes["/asa"] = (200, {"Content-Type": "text/html"}, ASA.replace(b"app.js", b"app.v2.js"))
    _, after, _ = site("/asa")
    assert before["sha256"] != after["sha256"]
    assert before["text_sha256"] == after["text_sha256"]


# --- failures ------------------------------------------------------------------

def _assert_failed(code, ev, status, kind, contract_code, reason_fragment):
    assert code == 1
    assert status["code"] == contract_code
    assert reason_fragment in status["error"]
    assert ev["metadata"]["partial_failure"] is True
    (failure,) = ev["metadata"]["api_failures"]
    assert set(failure) == {"operation", "type", "message"}
    assert failure["type"] == kind and failure["operation"].startswith("GET ")
    assert ev["text"] is None and ev["text_length"] == 0 and ev["sha256"] is None and ev["text_sha256"] is None
    assert list(ev)[: len(FIXED_FIELDS)] == FIXED_FIELDS


@pytest.mark.parametrize(
    "path, contract_code, http_status",
    [
        ("/does-not-exist", "target_unreachable", 404),
        ("/unauthorized", "auth_failed", 401),
        ("/forbidden", "not_authorized", 403),
        ("/ratelimited", "rate_limited", 429),
        ("/error", "target_unreachable", 500),
    ],
)
def test_non_200_fails(site, path, contract_code, http_status):
    code, ev, status = site(path)
    _assert_failed(code, ev, status, "http_error", contract_code, f"HTTP {http_status}")
    assert ev["http_status"] == http_status


def test_network_error_fails(site):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    code, ev, status = site(f"http://127.0.0.1:{port}/")
    _assert_failed(code, ev, status, "network_error", "target_unreachable", "network layer")
    assert ev["http_status"] == 0


def test_tls_error_fails(site, monkeypatch):
    def refuse(self, url, **kwargs):
        assert kwargs["verify"] is True
        raise requests.exceptions.SSLError("certificate verify failed: self-signed certificate")

    monkeypatch.setattr(requests.Session, "get", refuse)
    code, ev, status = site("https://self-signed.example.test/")
    _assert_failed(code, ev, status, "tls_error", "target_unreachable", "TLS verification")


def test_verify_ssl_false_is_passed_through(site, monkeypatch):
    seen = {}

    def capture(self, url, **kwargs):
        seen.update(kwargs)
        raise requests.exceptions.ConnectionError("stop here")

    monkeypatch.setattr(requests.Session, "get", capture)
    monkeypatch.setenv("WEB_VERIFY_SSL", "false")
    site("https://self-signed.example.test/")
    assert seen["verify"] is False and seen["timeout"] == 30 and seen["stream"] is True


def test_too_many_redirects_fails(site):
    code, ev, status = site("/hop/6")
    _assert_failed(code, ev, status, "too_many_redirects", "target_unreachable", "more than 5 times")


@pytest.mark.parametrize("path, shown", [("/pdf", "application/pdf"), ("/nocontenttype", "(none)")])
def test_unsupported_content_type_fails(site, path, shown):
    code, ev, status = site(path)
    _assert_failed(code, ev, status, "unsupported_content_type", "target_unreachable", shown)
    assert ev["http_status"] == 200


def test_declared_body_over_limit_fails(site):
    _Handler.routes["/big"] = (200, {"Content-Type": "text/plain"}, b"x" * (wp.MAX_BODY_BYTES + 1))
    code, ev, status = site("/big")
    _assert_failed(code, ev, status, "body_too_large", "target_unreachable", "declared")


def test_streamed_body_over_limit_fails(site):
    # No Content-Length: HTTP/1.0 close-delimited, so only the streaming cap can catch it.
    _Handler.routes["/big"] = (200, {"Content-Type": "text/plain", "_no_length": "1"}, b"x" * (wp.MAX_BODY_BYTES + 1))
    code, ev, status = site("/big")
    _assert_failed(code, ev, status, "body_too_large", "target_unreachable", "exceeds")


def test_invalid_json_fails(site):
    code, ev, status = site("/badjson")
    _assert_failed(code, ev, status, "invalid_json", "target_unreachable", "not valid JSON")


def test_javascript_shell_page_fails_as_empty(site):
    code, ev, status = site("/shell")
    _assert_failed(code, ev, status, "empty_text", "target_unreachable", "JavaScript")


@pytest.mark.parametrize("url", ["ftp://example.com/terms", "file:///etc/passwd", "example.com/terms"])
def test_non_http_url_is_bad_config(site, url):
    code, ev, status = site(url)
    _assert_failed(code, ev, status, "bad_url", "bad_config", "not an http(s) URL")


@pytest.mark.parametrize("missing", ["WEB_PAGE_URL", "WEB_TARGET_NAME"])
def test_missing_env_is_bad_config(site, monkeypatch, tmp_path, missing):
    monkeypatch.setenv("WEB_PAGE_URL", "https://example.test/")
    monkeypatch.delenv(missing)
    assert run_fetcher() == 1
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "bad_config" and missing in status["error"]
    (written,) = list(tmp_path.glob("web_page_text_*.json"))
    assert json.loads(written.read_text())["metadata"]["api_failures"][0]["type"] == "missing_config"


# --- pure logic and wiring -------------------------------------------------------

@pytest.mark.parametrize(
    "line, expected",
    [
        ("Last Updated: March 3, 2025", "March 3, 2025"),
        ("Last modified - 2025-03-03", "2025-03-03"),
        ("Effective as of Jan. 5th, 2024", "Jan. 5th, 2024"),
        ("Updated – 3/3/2025", "3/3/2025"),
        ("Effective date: 3 March 2025", "3 March 2025"),
        ("Last revised on September 2024", "September 2024"),
        ("We updated our cookie banner", None),
        ("Updated daily", None),
    ],
)
def test_last_updated_capture(line, expected):
    assert wp.find_last_updated(f"Intro\n{line}\nOutro") == expected


def test_unclosed_head_is_closed_by_body():
    text, title = wp.html_to_text("<html><head><title>T</title><body><p>Visible</p></body></html>")
    assert (text, title) == ("Visible", "T")


def test_pre_keeps_its_line_breaks():
    text, _ = wp.html_to_text("<pre>line one\nline two</pre><p>a\nb</p>")
    assert text.split("\n") == ["line one", "line two", "a b"]


def test_every_env_var_read_is_declared():
    spec = yaml.safe_load((FETCHER_DIR / "fetcher.yaml").read_text())
    declared = {field["env"] for field in spec["target_schema"].values()}
    source = (FETCHER_DIR / "fetcher.py").read_text() + Path(wp.__file__).read_text()
    read = set(re.findall(r'(?:get_env|env_bool|os\.environ\.get)\("([A-Z_]+)"', source))
    assert read - {"EVIDENCE_DIR", "LOG_LEVEL"} <= declared
    assert spec["version"] == wpt.VERSION and spec["name"] == wpt.NAME
    assert "ksis" not in spec
