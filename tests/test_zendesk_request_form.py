"""zendesk_request_form against a local stand-in for the Zendesk Support API and Help Center.

The fixtures under tests/fixtures/zendesk/synthetic_ticket_*.json are SYNTHETIC: invented ids
and tags, with field names from Zendesk's API documentation. synthetic_ticket_forms_anonymous.json
follows the shape of a live anonymous ticket_forms response (2026-10-16); the authenticated shapes
are UNVERIFIED against a live response. The stand-in serves `anon` routes to requests that carry
no Authorization header, so the anonymous and the authenticated ticket_forms reads can differ.
The forms, labels and Reason options mirror Paramify's public "Submit a request" page as Isaac
Teuscher described it on 2026-10-16. "collected_at" is frozen at 2026-10-16T15:00:00Z.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_DIR = REPO_ROOT / "fetchers" / "zendesk" / "request_form"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "zendesk"

_spec = importlib.util.spec_from_file_location("zendesk_request_form_under_test", FETCHER_DIR / "fetcher.py")
zd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zd)

NOW = "2026-10-16T15:00:00Z"
EMAIL = "auditor@example.com"
TOKEN = "fake-token-for-tests"
BASIC = "Basic " + base64.b64encode(f"{EMAIL}/token:{TOKEN}".encode()).decode()
JSON = {"Content-Type": "application/json; charset=utf-8"}
HTML = {"Content-Type": "text/html; charset=utf-8"}
FORMS = "/api/v2/ticket_forms.json"
FIELDS = "/api/v2/ticket_fields.json"
FIELDS_2 = "/api/v2/ticket_fields.json?page=2"
REQUESTS_NEW = "/hc/en-us/requests/new"
SIGNIN = "/hc/en-us/signin?return_to=%2Fhc%2Fen-us%2Frequests%2Fnew"
CHALLENGE = (403, {**HTML, "cf-mitigated": "challenge", "Server": "cloudflare"}, b"<title>Just a moment...</title>")

FIXED_FIELDS = [
    "collected_at", "target_name", "base_url", "help_center", "locale", "ticket_form_ids", "credentials_supplied",
    "authenticated", "anonymous_forms_ok", "forms_end_user_visible", "forms_end_user_visible_source",
    "security_report_option", "has_security_report_option", "required_portal_fields", "requests_new_public",
    "requests_new_status", "form_count", "field_count", "pagination", "forms", "anonymous_forms_error",
    "anonymous_forms",
]
UNAUTHENTICATED = (401, JSON, b'{"error":"Couldn\'t authenticate you"}')
REQUIRED = ["Subject", "Description", "Reason/How can we help?", "Product"]


class _Handler(BaseHTTPRequestHandler):
    routes: Dict[str, Tuple[int, Dict[str, str], bytes]] = {}
    anon: Dict[str, Tuple[int, Dict[str, str], bytes]] = {}
    seen: list = []

    def do_GET(self) -> None:  # noqa: N802
        _Handler.seen.append((self.path, dict(self.headers)))
        table = self.anon if "Authorization" not in self.headers and self.path in self.anon else self.routes
        status, headers, body = table.get(self.path, (404, JSON, b'{"error": "RecordNotFound"}'))
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


def as_cursor(page1: dict, page2: dict, base: str) -> Dict[str, dict]:
    """The same fields served with cursor pagination (meta.has_more + links.next) instead of offset."""
    after = "/api/v2/ticket_fields.json?page%5Bafter%5D=eyJvIjoiNCJ9&page%5Bsize%5D=100"
    first = {"ticket_fields": page1["ticket_fields"], "meta": {"has_more": True, "after_cursor": "eyJvIjoiNCJ9",
             "before_cursor": None}, "links": {"next": base + after, "prev": None}}
    last = {"ticket_fields": page2["ticket_fields"], "meta": {"has_more": False, "after_cursor": None,
            "before_cursor": "eyJvIjoiNSJ9"}, "links": {"next": None, "prev": base + FIELDS}}
    return {FIELDS: first, after: last}


@pytest.fixture
def site(server, monkeypatch, tmp_path):
    docs = {"forms": fixture("synthetic_ticket_forms.json", server),
            "anon_forms": fixture("synthetic_ticket_forms_anonymous.json", server),
            "fields1": fixture("synthetic_ticket_fields_page1.json", server),
            "fields2": fixture("synthetic_ticket_fields_page2.json", server)}

    def publish():
        _Handler.routes = {
            FORMS: (200, JSON, json.dumps(docs["forms"]).encode()),
            FIELDS: (200, JSON, json.dumps(docs["fields1"]).encode()),
            FIELDS_2: (200, JSON, json.dumps(docs["fields2"]).encode()),
            REQUESTS_NEW: (200, {**HTML, "Set-Cookie": "_help_center_session=x; path=/"}, b"<form>ok</form>"),
        }
        # Live: ticket_forms answers anonymously with the end-user-visible forms; ticket_fields does not.
        _Handler.anon = {FORMS: (200, JSON, json.dumps(docs["anon_forms"]).encode()), FIELDS: UNAUTHENTICATED}
        _Handler.seen = []

    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("ZENDESK_TARGET_NAME", "support")
    monkeypatch.setenv("ZENDESK_BASE_URL", server)
    monkeypatch.setenv("ZENDESK_EMAIL", EMAIL)
    monkeypatch.setenv("ZENDESK_API_TOKEN", TOKEN)
    for name in ("ZENDESK_TICKET_FORM_IDS", "ZENDESK_LOCALE", "ZENDESK_VERIFY_SSL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(zd, "load_dotenv", lambda: None)
    monkeypatch.setattr(zd, "current_timestamp", lambda: NOW)

    def encode(routes):
        return {path: (200, JSON, json.dumps(doc).encode()) if isinstance(doc, dict) else doc
                for path, doc in routes.items()}

    def run(anon=None, **routes):
        publish()
        _Handler.routes.update(encode(routes))
        _Handler.anon.update(encode(anon or {}))
        code = zd.main()
        evidence = json.loads((tmp_path / "zendesk_request_form_support.json").read_text())
        status_file = tmp_path / "status.json"
        return code, evidence, json.loads(status_file.read_text()) if status_file.exists() else None

    return run, docs, server


def add_security_option(docs: dict) -> None:
    reason = next(f for f in docs["fields1"]["ticket_fields"] if f["id"] == 900004)
    reason["custom_field_options"].append({"id": 90000408, "name": "Security Vulnerability Report",
                                           "raw_name": "Security Vulnerability Report",
                                           "value": "reason_security_vulnerability", "default": False})


# --- the real-shaped form -----------------------------------------------------------------

def test_forms_and_fields_are_collected(site):
    run, docs, base = site
    code, ev, status = run()
    assert (code, status) == (0, None)
    assert list(ev) == FIXED_FIELDS
    assert ev["help_center"] == base and ev["locale"] == "en-us"
    assert ev["credentials_supplied"] is True and ev["authenticated"] is True
    assert ev["form_count"] == 2 and ev["field_count"] == 7 and ev["forms_end_user_visible"] == 1
    assert ev["forms_end_user_visible_source"] == "authenticated"
    assert ev["pagination"] == {
        "ticket_forms": {"style": "offset", "pages": 1, "collected": 2, "reported_count": 2},
        "ticket_fields": {"style": "offset", "pages": 2, "collected": 7, "reported_count": 7},
    }
    form = ev["forms"][0]
    vendor = docs["forms"]["ticket_forms"][0]
    for name in zd.FORM_FIELDS:
        assert form[name] == vendor[name]
    assert "raw_name" not in form and form["missing_field_ids"] == []
    assert [f["title_in_portal"] for f in form["fields"]] == [
        "Subject", "Description", "Status", "Reason/How can we help?", "Internet browser", "Product"]


def test_field_records_are_verbatim(site):
    run, docs, _ = site
    _, ev, _ = run()
    product = ev["forms"][0]["fields"][5]
    vendor = docs["fields2"]["ticket_fields"][1]
    for name in zd.FIELD_FIELDS[:-1]:
        assert product[name] == vendor[name]
    assert product["description"] == "The module applicable to the ticket"
    assert product["custom_field_options"] == [{"name": "Paramify", "value": "product_paramify", "default": False}]
    assert ev["forms"][0]["fields"][4]["custom_field_options"] is None  # a text field has no options
    reason = ev["forms"][0]["fields"][3]
    assert [o["name"] for o in reason["custom_field_options"]] == [
        "Compliance Framework Question", "General Paramify How-to Question",
        "Technical Question, i.e. deployment, SSO setup, etc", "Bug/Incident", "Enhancement Request",
        "New Feature Request", "I have a different problem"]


def test_the_real_shaped_form_has_no_security_option(site):
    run, _, _ = site
    _, ev, _ = run()
    assert ev["has_security_report_option"] is False and ev["security_report_option"] == []


def test_required_portal_fields(site):
    run, _, _ = site
    _, ev, _ = run()
    # "Your email address" is the anonymous requester field, not a ticket field, so it is absent.
    assert ev["required_portal_fields"] == REQUIRED


def test_a_security_vulnerability_option_is_found(site):
    run, docs, _ = site
    add_security_option(docs)
    _, ev, _ = run()
    assert ev["has_security_report_option"] is True
    assert ev["security_report_option"] == [{
        "form_id": 360010001, "source": "field_option", "field_id": 900004, "field": "Reason/How can we help?",
        "text": "Security Vulnerability Report", "value": "reason_security_vulnerability"}]


def test_a_security_form_name_is_found(site):
    run, docs, _ = site
    docs["forms"]["ticket_forms"][0]["display_name"] = "Report a vulnerability (responsible disclosure)"
    _, ev, _ = run()
    assert ev["security_report_option"] == [{"form_id": 360010001, "source": "form.display_name",
                                             "text": "Report a vulnerability (responsible disclosure)"}]


def test_hidden_forms_fields_and_inactive_fields_do_not_count(site):
    run, docs, _ = site
    docs["forms"]["ticket_forms"][1]["name"] = "Security incident (internal)"
    add_security_option(docs)
    reason = next(f for f in docs["fields1"]["ticket_fields"] if f["id"] == 900004)
    reason["active"] = False
    _, ev, _ = run()
    assert ev["has_security_report_option"] is False
    assert "Reason/How can we help?" not in ev["required_portal_fields"]
    reason["active"], reason["visible_in_portal"] = True, False
    _, ev, _ = run()
    assert ev["has_security_report_option"] is False


def test_no_end_user_visible_form(site):
    run, docs, _ = site
    docs["forms"]["ticket_forms"][0]["end_user_visible"] = False
    code, ev, _ = run()
    assert code == 0 and ev["forms_end_user_visible"] == 0
    assert ev["required_portal_fields"] == [] and ev["has_security_report_option"] is False
    docs["forms"]["ticket_forms"][0]["end_user_visible"] = True
    docs["forms"]["ticket_forms"][0]["active"] = False
    _, ev, _ = run()
    assert ev["forms_end_user_visible"] == 0


def test_ticket_form_ids_filter(site, monkeypatch):
    run, _, _ = site
    monkeypatch.setenv("ZENDESK_TICKET_FORM_IDS", " 360010002 ")
    _, ev, _ = run()
    assert ev["ticket_form_ids"] == [360010002] and [f["id"] for f in ev["forms"]] == [360010002]
    assert ev["forms_end_user_visible"] == 0
    # The anonymous list never has the hidden form; filtering it out is not a failure.
    assert ev["anonymous_forms_ok"] is True and ev["anonymous_forms"] == []


def test_a_field_id_with_no_field_is_listed(site):
    run, docs, _ = site
    docs["forms"]["ticket_forms"][0]["ticket_field_ids"].append(999999)
    code, ev, _ = run()
    assert code == 0 and ev["forms"][0]["missing_field_ids"] == [999999]


# --- pagination ---------------------------------------------------------------------------

def test_cursor_pagination(site):
    run, docs, base = site
    pages = as_cursor(docs["fields1"], docs["fields2"], base)
    code, ev, _ = run(**pages)
    assert code == 0 and ev["field_count"] == 7
    assert ev["pagination"]["ticket_fields"] == {"style": "cursor", "pages": 2, "collected": 7,
                                                 "reported_count": None}
    assert ev["required_portal_fields"] == REQUIRED


def test_cursor_has_more_without_next_fails(site):
    run, docs, base = site
    pages = as_cursor(docs["fields1"], docs["fields2"], base)
    pages[FIELDS]["links"]["next"] = None
    _assert_failed(*run(**pages), "pagination", "target_unreachable")


def test_count_mismatch_fails(site):
    run, docs, _ = site
    docs["fields2"]["count"] = 8
    code, ev, status = run()
    _assert_failed(code, ev, status, "count_mismatch", "target_unreachable")
    assert "count=8" in status["error"]


def test_a_page_with_no_pagination_keys_fails(site):
    run, docs, _ = site
    docs["forms"] = {"ticket_forms": docs["forms"]["ticket_forms"]}
    _assert_failed(*run(), "unexpected_shape", "target_unreachable")


def test_next_page_off_the_instance_fails(site):
    run, docs, _ = site
    docs["fields1"]["next_page"] = "https://evil.example.com/api/v2/ticket_fields.json?page=2"
    _assert_failed(*run(), "pagination", "target_unreachable")
    assert not any("evil" in path for path, _ in _Handler.seen)


def test_a_next_page_loop_fails(site, server):
    run, docs, _ = site
    docs["fields2"]["next_page"] = server + FIELDS_2
    _assert_failed(*run(), "pagination", "target_unreachable")


# --- the anonymous request page -----------------------------------------------------------

def test_the_request_page_is_public(site):
    run, _, base = site
    _, ev, _ = run()
    assert ev["requests_new_public"] is True
    assert ev["requests_new_status"] == {"url": base + REQUESTS_NEW, "http_status": 200,
                                         "final_url": base + REQUESTS_NEW, "redirected_to_signin": False,
                                         "bot_challenge": False, "error": None}


def test_a_cloudflare_challenge_is_unverified_not_false(site):
    run, _, _ = site
    code, ev, _ = run(**{REQUESTS_NEW: CHALLENGE})
    assert code == 0 and ev["requests_new_public"] is None
    assert ev["requests_new_status"]["bot_challenge"] is True and ev["requests_new_status"]["http_status"] == 403


def test_a_sign_in_redirect_is_false(site):
    run, _, base = site
    code, ev, _ = run(**{REQUESTS_NEW: (302, {"Location": SIGNIN}, b""), SIGNIN: (200, HTML, b"<p>Sign in</p>")})
    assert code == 0 and ev["requests_new_public"] is False
    assert ev["requests_new_status"]["redirected_to_signin"] is True
    assert ev["requests_new_status"]["final_url"] == base + SIGNIN


def test_a_request_page_error_is_false_and_not_fatal(site):
    run, _, _ = site
    code, ev, _ = run(**{REQUESTS_NEW: (404, HTML, b"gone")})
    assert code == 0 and ev["requests_new_public"] is False and ev["requests_new_status"]["http_status"] == 404


def test_api_calls_carry_the_token_and_the_anonymous_reads_do_not(site):
    run, _, _ = site
    run()
    assert [path for path, _ in _Handler.seen] == [FORMS, FORMS, FIELDS, FIELDS_2, REQUESTS_NEW]
    (anonymous, forms, fields, fields_2, page) = [headers for _, headers in _Handler.seen]
    for headers in (forms, fields, fields_2):
        assert headers["Authorization"] == BASIC
    for headers in (anonymous, page):
        assert "Authorization" not in headers and "Cookie" not in headers
    assert all(h["User-Agent"] == f"paramify-fetchers zendesk_request_form/{zd.VERSION}" for _, h in _Handler.seen)


# --- the anonymous forms list -------------------------------------------------------------

def test_anonymous_forms_are_recorded_verbatim(site):
    run, docs, _ = site
    code, ev, _ = run()
    assert code == 0 and ev["anonymous_forms_ok"] is True and ev["anonymous_forms_error"] is None
    (form,) = ev["anonymous_forms"]
    vendor = docs["anon_forms"]["ticket_forms"][0]
    assert list(form) == zd.FORM_FIELDS
    for name in zd.FORM_FIELDS:
        assert form[name] == vendor.get(name)
    assert form["agent_conditions"] is None  # absent from the live anonymous shape
    assert form["end_user_visible"] is True and len(form["ticket_field_ids"]) == 6


def test_bad_credentials_fall_back_to_anonymous_on_forms_and_fail_on_fields(site):
    """The live answer to bad Basic auth (2026-10-16): 200 on ticket_forms, 401 on ticket_fields."""
    run, docs, _ = site
    code, ev, status = run(**{FORMS: docs["anon_forms"], FIELDS: UNAUTHENTICATED})
    _assert_failed(code, ev, status, "http_error", "auth_failed")
    assert "HTTP 401" in status["error"] and "authenticate you" in status["error"] and FIELDS in status["error"]
    assert ev["credentials_supplied"] is True and ev["authenticated"] is False
    assert ev["forms_end_user_visible"] == 1 and ev["forms_end_user_visible_source"] == "anonymous"
    assert [f["id"] for f in ev["anonymous_forms"]] == [360010001]
    assert list(ev)[:len(FIXED_FIELDS)] == FIXED_FIELDS


def test_an_anonymous_forms_error_is_recorded_and_not_fatal(site):
    run, _, _ = site
    code, ev, status = run(anon={FORMS: (403, JSON, b'{"error": "Forbidden"}')})
    assert (code, status) == (0, None)
    assert ev["anonymous_forms_ok"] is False and ev["anonymous_forms"] == []
    assert "HTTP 403" in ev["anonymous_forms_error"]
    assert ev["authenticated"] is True and ev["forms_end_user_visible_source"] == "authenticated"


def test_an_anonymous_network_error_is_null_not_false(site, monkeypatch):
    run, _, _ = site
    real = zd.list_all

    def flaky(http, url, key, origin, verify, auth):
        if auth is None:
            raise zd.CollectionError("GET failed: ConnectionError", "network_error")
        return real(http, url, key, origin, verify, auth)

    monkeypatch.setattr(zd, "list_all", flaky)
    code, ev, _ = run()
    assert code == 0 and ev["anonymous_forms_ok"] is None and ev["anonymous_forms_error"]


def test_both_lists_failing_leaves_forms_end_user_visible_null(site):
    run, _, _ = site
    code, ev, status = run(anon={FORMS: UNAUTHENTICATED}, **{FIELDS: UNAUTHENTICATED})
    _assert_failed(code, ev, status, "http_error", "auth_failed", anonymous=False)
    assert ev["forms_end_user_visible"] is None and ev["forms_end_user_visible_source"] is None


# --- failures -----------------------------------------------------------------------------

def _assert_failed(code, ev, status, kind, contract_code, anonymous=True, authenticated=None):
    """`anonymous`: whether the anonymous forms read happened and succeeded before the failure.

    `authenticated` is what the evidence must say when the failure is not a 401 (always false on one).
    """
    assert code == 1 and status["code"] == contract_code
    (failure,) = ev["metadata"]["api_failures"]
    assert ev["metadata"]["partial_failure"] is True
    assert set(failure) == {"operation", "type", "message"} and failure["type"] == kind
    assert ev["forms"] == [] and ev["has_security_report_option"] is None and ev["requests_new_public"] is None
    assert ev["authenticated"] is (False if contract_code == "auth_failed" else authenticated)
    if anonymous:
        assert ev["anonymous_forms_ok"] is True and [f["id"] for f in ev["anonymous_forms"]] == [360010001]
        assert ev["forms_end_user_visible"] == 1 and ev["forms_end_user_visible_source"] == "anonymous"
    else:
        assert ev["anonymous_forms"] == [] and ev["anonymous_forms_ok"] is not True


@pytest.mark.parametrize("status_code, contract_code",
                         [(401, "auth_failed"), (403, "not_authorized"), (404, "target_unreachable"),
                          (429, "rate_limited"), (500, "target_unreachable")])
@pytest.mark.parametrize("path", [FORMS, FIELDS_2])
def test_api_errors_fail(site, path, status_code, contract_code):
    run, _, _ = site
    code, ev, status = run(**{path: (status_code, JSON, b'{"error": "Couldn\'t authenticate you"}')})
    _assert_failed(code, ev, status, "http_error", contract_code)
    assert f"HTTP {status_code}" in status["error"]


@pytest.mark.parametrize("missing", ["ZENDESK_EMAIL", "ZENDESK_API_TOKEN", "ZENDESK_BASE_URL"])
def test_missing_secrets_or_base_url_is_bad_config(site, monkeypatch, missing):
    run, _, _ = site
    monkeypatch.delenv(missing)
    code, ev, status = run()
    _assert_failed(code, ev, status, "missing_config", "bad_config", anonymous=False)
    assert missing in status["error"] and _Handler.seen == []
    assert ev["credentials_supplied"] is (missing == "ZENDESK_BASE_URL")


@pytest.mark.parametrize("url", ["http://support.example.com", "ftp://support.example.com", "not a url"])
def test_a_non_https_base_url_is_bad_config(site, monkeypatch, url):
    run, _, _ = site
    monkeypatch.setenv("ZENDESK_BASE_URL", url)
    _assert_failed(*run(), "bad_url", "bad_config", anonymous=False)
    assert _Handler.seen == []


@pytest.mark.parametrize("raw", ["abc", "1,,x", " , "])
def test_bad_ticket_form_ids_is_bad_config(site, monkeypatch, raw):
    run, _, _ = site
    monkeypatch.setenv("ZENDESK_TICKET_FORM_IDS", raw)
    _assert_failed(*run(), "bad_config", "bad_config", anonymous=False)


def test_an_unknown_ticket_form_id_fails(site, monkeypatch):
    run, _, _ = site
    monkeypatch.setenv("ZENDESK_TICKET_FORM_IDS", "360010001,123")
    code, ev, status = run()
    _assert_failed(code, ev, status, "form_not_found", "bad_config", authenticated=True)
    assert "[123]" in status["error"]


# --- the token stays secret ---------------------------------------------------------------

@pytest.mark.parametrize("routes", [{}, {FORMS: (401, JSON, b'{"error": "Couldn\'t authenticate you"}')},
                                    {FIELDS_2: (500, JSON, ("echo " + TOKEN).encode())}],
                         ids=["success", "auth_failed", "error_body_echoes_token"])
def test_the_token_never_reaches_evidence_status_or_logs(site, tmp_path, caplog, capsys, monkeypatch, routes):
    run, _, _ = site
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    with caplog.at_level(logging.DEBUG):
        run(**routes)
    captured = capsys.readouterr()
    written = "".join(p.read_text() for p in tmp_path.iterdir() if p.is_file())
    for text in (written, caplog.text, captured.out, captured.err):
        assert TOKEN not in text
        assert base64.b64encode(f"{EMAIL}/token:{TOKEN}".encode()).decode() not in text


# --- contract -----------------------------------------------------------------------------

def test_every_env_var_read_is_declared():
    spec = yaml.safe_load((FETCHER_DIR / "fetcher.yaml").read_text())
    declared = {field["env"] for field in spec["target_schema"].values()} | {s["env"] for s in spec["secrets"]}
    source = (FETCHER_DIR / "fetcher.py").read_text()
    read = set(re.findall(r"env\([\"']([A-Z_]+)[\"']\)", source)) | set(re.findall(r'"(ZENDESK_[A-Z_]+)"', source))
    assert read <= declared and {"ZENDESK_EMAIL", "ZENDESK_API_TOKEN"} <= read
    assert all(s["required"] is True for s in spec["secrets"])
    assert spec["version"] == zd.VERSION and spec["name"] == zd.NAME and "ksis" not in spec
    assert spec["evidence_set"]["reference_id"] == "EVD-ZENDESK-REQUEST-FORM"
