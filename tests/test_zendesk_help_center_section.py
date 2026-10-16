"""zendesk_help_center_section against a local stand-in for a public Help Center.

The fixtures under tests/fixtures/zendesk/ are SYNTHETIC: invented values, with the key
set checked against the live support.paramify.com Help Center API on 2026-10-16 (offset
pagination via `count` and a same-host `next_page`). "collected_at" is frozen at
2026-10-16T15:00:00Z.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_DIR = REPO_ROOT / "fetchers" / "zendesk" / "help_center_section"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "zendesk"

_spec = importlib.util.spec_from_file_location("zendesk_help_center_section_under_test", FETCHER_DIR / "fetcher.py")
zd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zd)

API = "/api/v2/help_center/en-us/sections/47348382411923"
SECTION_PATH = "/hc/en-us/sections/47348382411923-Recommended-Secure-Configuration"
NOW = "2026-10-16T15:00:00Z"
JSON = {"Content-Type": "application/json; charset=utf-8"}
HTML = {"Content-Type": "text/html; charset=utf-8"}

FIXED_FIELDS = [
    "collected_at", "target_name", "section_url", "help_center", "locale", "anonymous", "section",
    "article_count", "reported_count", "articles_updated_max", "articles_updated_min", "days_since_last_update",
    "all_articles_public", "public_page_challenges", "all_user_segments_everyone", "mentions_top_level_admin",
    "scg_terms", "articles",
]


class _Handler(BaseHTTPRequestHandler):
    routes: Dict[str, Tuple[int, Dict[str, str], bytes]] = {}
    seen: list = []

    def do_GET(self) -> None:  # noqa: N802
        _Handler.seen.append((self.path, dict(self.headers)))
        status, headers, body = self.routes.get(self.path, (404, JSON, b'{"error": "RecordNotFound"}'))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def fixture(name: str, base: str) -> dict:
    return json.loads((FIXTURES / name).read_text().replace("{BASE}", base))


@pytest.fixture
def site(server, monkeypatch, tmp_path):
    page1, page2 = fixture("synthetic_articles_page1.json", server), fixture("synthetic_articles_page2.json", server)
    docs = {"section": fixture("synthetic_section.json", server), "page1": page1, "page2": page2}

    def publish():
        _Handler.routes = {
            f"{API}.json": (200, JSON, json.dumps(docs["section"]).encode()),
            f"{API}/articles.json?per_page=100": (200, JSON, json.dumps(docs["page1"]).encode()),
            f"{API}/articles.json?page=2&per_page=2": (200, JSON, json.dumps(docs["page2"]).encode()),
            "/hc/en-us/articles/360001-Configuring-top-level-administrator-accounts": (200, HTML, b"<p>ok</p>"),
            "/hc/en-us/articles/360002-Single-sign-on-SSO-with-SAML": (200, HTML, b"<p>ok</p>"),
            "/hc/en-us/articles/360003-Audit-log-retention-settings":
                (302, {"Location": "/hc/en-us/signin?return_to=%2Fhc%2Fen-us%2Farticles%2F360003"}, b""),
            "/hc/en-us/signin?return_to=%2Fhc%2Fen-us%2Farticles%2F360003": (200, HTML, b"<p>Sign in</p>"),
        }
        _Handler.seen = []

    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("ZENDESK_TARGET_NAME", "scg")
    for name in ("ZENDESK_BASE_URL", "ZENDESK_LOCALE", "ZENDESK_VERIFY_SSL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(zd, "load_dotenv", lambda: None)
    monkeypatch.setattr(zd, "current_timestamp", lambda: NOW)

    def run(section_url: str = None, **routes):
        publish()
        _Handler.routes.update(routes)
        monkeypatch.setenv("ZENDESK_SECTION_URL", section_url or server + SECTION_PATH)
        code = zd.main()
        evidence = json.loads((tmp_path / "zendesk_help_center_section_scg.json").read_text())
        status_file = tmp_path / "status.json"
        return code, evidence, json.loads(status_file.read_text()) if status_file.exists() else None

    return run, docs, server


def test_section_is_collected_across_pages(site):
    run, _, base = site
    code, ev, status = run()
    assert (code, status) == (0, None)
    assert list(ev) == FIXED_FIELDS
    assert ev["help_center"] == base and ev["locale"] == "en-us" and ev["anonymous"] is True
    assert ev["section"] == {"id": 47348382411923, "name": "Recommended Secure Configuration",
                             "html_url": base + SECTION_PATH, "updated_at": "2026-09-30T18:22:11Z"}
    assert ev["article_count"] == ev["reported_count"] == 3
    assert [a["id"] for a in ev["articles"]] == [360001, 360002, 360003]
    assert ev["articles_updated_max"] == "2026-09-30T18:22:11Z"
    assert ev["articles_updated_min"] == "2026-07-20T08:00:00Z"
    assert ev["days_since_last_update"] == 15


def test_article_fields_text_and_dates(site):
    run, docs, _ = site
    _, ev, _ = run()
    first = ev["articles"][0]
    vendor = docs["page1"]["articles"][0]
    for field in zd.ARTICLE_FIELDS:
        assert first[field] == vendor[field]
    assert first["body"] == vendor["body"]
    assert "Configure SSO and require MFA for every administrator." in first["text"].split("\n")
    assert first["last_updated"] == "September 30, 2026"
    assert first["text_length"] == len(first["text"]) and len(first["text_sha256"]) == 64
    assert "Settings > Security" in ev["articles"][1]["text"]


def test_a_page_that_sends_anonymous_users_to_sign_in_is_a_finding(site):
    run, _, base = site
    code, ev, _ = run()
    assert code == 0
    restricted = ev["articles"][2]["public_page_status"]
    assert restricted["http_status"] == 200 and restricted["redirected_to_signin"] is True
    assert restricted["final_url"].startswith(base + "/hc/en-us/signin")
    assert ev["articles"][0]["public_page_status"]["redirected_to_signin"] is False
    assert ev["all_articles_public"] is False


def test_all_public_when_every_page_loads(site):
    run, _, _ = site
    _, ev, _ = run(**{"/hc/en-us/articles/360003-Audit-log-retention-settings": (200, HTML, b"<p>ok</p>")})
    assert ev["all_articles_public"] is True


def test_an_article_page_error_is_recorded_not_fatal(site):
    run, _, _ = site
    code, ev, _ = run(**{"/hc/en-us/articles/360002-Single-sign-on-SSO-with-SAML": (404, HTML, b"gone")})
    assert code == 0 and ev["articles"][1]["public_page_status"]["http_status"] == 404
    assert ev["all_articles_public"] is False


CHALLENGE = (403, {"Content-Type": "text/html", "cf-mitigated": "challenge", "Server": "cloudflare"},
             b"<title>Just a moment...</title>")


def test_a_cloudflare_challenge_leaves_public_access_unverified(site):
    # Measured 2026-10-16: support.paramify.com answers every non-browser GET of an article page this way.
    run, _, _ = site
    code, ev, _ = run(**{
        "/hc/en-us/articles/360001-Configuring-top-level-administrator-accounts": CHALLENGE,
        "/hc/en-us/articles/360002-Single-sign-on-SSO-with-SAML": CHALLENGE,
        "/hc/en-us/articles/360003-Audit-log-retention-settings": CHALLENGE,
    })
    assert code == 0
    assert all(a["public_page_status"]["bot_challenge"] is True for a in ev["articles"])
    assert ev["all_articles_public"] is None and ev["public_page_challenges"] == 3


def test_a_sign_in_redirect_beats_a_challenge(site):
    run, _, _ = site
    _, ev, _ = run(**{"/hc/en-us/articles/360001-Configuring-top-level-administrator-accounts": CHALLENGE})
    assert ev["all_articles_public"] is False and ev["public_page_challenges"] == 1


def test_user_segments(site):
    run, docs, _ = site
    _, ev, _ = run()
    assert ev["all_user_segments_everyone"] is True
    docs["page2"]["articles"][0]["user_segment_id"] = 360000123
    _, ev, _ = run()
    assert ev["all_user_segments_everyone"] is False and ev["articles"][2]["user_segment_id"] == 360000123


def test_scg_heuristics(site):
    run, _, _ = site
    _, ev, _ = run()
    assert ev["mentions_top_level_admin"] is True
    assert ev["scg_terms"] == {"access": True, "configure": True, "operate": True, "decommission": True}


def test_scg_heuristics_need_admin_in_the_same_article(site):
    run, docs, _ = site
    docs["page1"]["articles"][0]["body"] = "<p>Configure your workspace. Decommission old projects.</p>"
    _, ev, _ = run()
    assert ev["mentions_top_level_admin"] is False
    # article 2 mentions administrators + configure, so only that term survives
    assert ev["scg_terms"] == {"access": False, "configure": True, "operate": False, "decommission": False}


def test_request_is_anonymous(site):
    run, _, _ = site
    run()
    for _, headers in _Handler.seen:
        assert "Authorization" not in headers and "Cookie" not in headers
        assert headers["User-Agent"] == f"paramify-fetchers zendesk_help_center_section/{zd.VERSION}"


def test_empty_section_is_recorded(site):
    run, docs, _ = site
    docs["page1"] = {**docs["page1"], "articles": [], "count": 0, "next_page": None}
    code, ev, status = run()
    assert (code, status) == (0, None)
    assert ev["article_count"] == 0 and ev["all_articles_public"] is None
    assert ev["days_since_last_update"] is None and ev["articles_updated_max"] is None


# --- failures --------------------------------------------------------------------------

def _assert_failed(code, ev, status, kind, contract_code):
    assert code == 1 and status["code"] == contract_code
    (failure,) = ev["metadata"]["api_failures"]
    assert ev["metadata"]["partial_failure"] is True
    assert set(failure) == {"operation", "type", "message"} and failure["type"] == kind
    assert ev["articles"] == [] and ev["article_count"] is None


def test_count_mismatch_fails(site):
    run, docs, _ = site
    docs["page2"] = {**docs["page2"], "count": 4}
    code, ev, status = run()
    _assert_failed(code, ev, status, "count_mismatch", "target_unreachable")
    assert "count=4" in status["error"]


@pytest.mark.parametrize("status_code, contract_code",
                         [(401, "auth_failed"), (403, "not_authorized"), (404, "target_unreachable"),
                          (429, "rate_limited"), (500, "target_unreachable")])
def test_api_errors_fail(site, status_code, contract_code):
    run, _, _ = site
    code, ev, status = run(**{f"{API}/articles.json?page=2&per_page=2": (status_code, JSON, b'{"error": "x"}')})
    _assert_failed(code, ev, status, "http_error", contract_code)
    assert f"HTTP {status_code}" in status["error"]


def test_section_404_fails(site):
    run, _, _ = site
    _assert_failed(*run(**{f"{API}.json": (404, JSON, b'{"error": "RecordNotFound"}')}), "http_error",
                   "target_unreachable")


def test_a_page_without_count_fails(site):
    run, docs, _ = site
    docs["page1"] = {k: v for k, v in docs["page1"].items() if k != "count"}
    _assert_failed(*run(), "unexpected_shape", "target_unreachable")


def test_next_page_off_the_help_center_fails(site):
    run, docs, _ = site
    docs["page1"] = {**docs["page1"], "next_page": "https://evil.example.com/api/v2/x.json"}
    _assert_failed(*run(), "pagination", "target_unreachable")


def test_a_next_page_loop_fails(site, server):
    run, docs, _ = site
    docs["page2"] = {**docs["page2"], "next_page": f"{server}{API}/articles.json?page=2&per_page=2"}
    _assert_failed(*run(), "pagination", "target_unreachable")


@pytest.mark.parametrize("url", ["https://support.example.com/hc/en-us/articles/1", "ftp://x/hc/en-us/sections/1",
                                 "not a url", "12345"])
def test_bad_section_url_is_bad_config(site, url):
    run, _, _ = site
    code, ev, status = run(url)
    _assert_failed(code, ev, status, "bad_url", "bad_config")


def test_bare_section_id_with_base_url(site, monkeypatch, server):
    run, _, _ = site
    monkeypatch.setenv("ZENDESK_BASE_URL", server)
    code, ev, _ = run("47348382411923")
    assert code == 0 and ev["article_count"] == 3 and ev["locale"] == "en-us"


def test_missing_env_is_bad_config(site, monkeypatch, tmp_path):
    monkeypatch.delenv("ZENDESK_SECTION_URL", raising=False)
    assert zd.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


@pytest.mark.parametrize(
    "url, expected",
    [("https://support.paramify.com/hc/en-us/sections/47348382411923-Recommended-Secure-Configuration",
      ("https://support.paramify.com", "en-us", "47348382411923")),
     ("https://help.example.com/hc/pt-br/sections/42", ("https://help.example.com", "pt-br", "42"))],
)
def test_resolve_section(url, expected):
    assert zd.resolve_section(url, "", "") == expected


def test_every_env_var_read_is_declared():
    spec = yaml.safe_load((FETCHER_DIR / "fetcher.yaml").read_text())
    declared = {field["env"] for field in spec["target_schema"].values()}
    source = (FETCHER_DIR / "fetcher.py").read_text()
    import re

    read = set(re.findall(r'env\("([A-Z_]+)"\)', source)) | set(re.findall(r'"(ZENDESK_[A-Z_]+)"', source))
    assert read <= declared
    assert spec["version"] == zd.VERSION and spec["name"] == zd.NAME and "ksis" not in spec
