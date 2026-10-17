"""Cover for the cornerstone fetchers against an in-process fake Reporting API.

No network and no credentials: ``requests.post`` / ``requests.get`` in the
shared client are replaced with a small fake that answers the OAuth token URL
and the RAPI OData views with response shapes from Cornerstone's published
docs (csod.dev Reporting > Paging, Getting Started > Authentication) and the
Training and Transcript RTDW spec v26.03.

What this proves: the token exchange and its JSON body, the portal-URL guard,
redirect refusal, $count-then-page reads with de-duplication, the nextLink
guards, the status and retraining maths, null-not-zero for an unresolved
course, and the exit-code contract. What it cannot prove: that a real portal
exposes every selected column. That still needs one live run against a pilot or
stage portal.

Run: ``pytest tests/test_cornerstone_fetchers.py``
"""

from __future__ import annotations

import importlib.util
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CSOD = REPO_ROOT / "fetchers" / "cornerstone"
sys.path.insert(0, str(CSOD / "_shared"))

import csod_client  # noqa: E402

PORTAL = "https://acme.csod.com"
TOKEN_URL = PORTAL + "/services/api/oauth2/token"
VIEWS = PORTAL + "/services/api/x/odata/api/views/"
# Never commit a credential-looking literal, even a fake one: the value is made
# fresh for each run, so the repo holds no secret and the leak checks below
# still look for a value no response could contain by chance.
SECRET = secrets.token_urlsafe(24)
NOW = datetime.now(timezone.utc)

AWARENESS = "11111111-1111-1111-1111-111111111111"
AWARENESS_OLD = "22222222-2222-2222-2222-222222222222"
DEVSEC = "33333333-3333-3333-3333-333333333333"


def iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


class FakeResponse:
    def __init__(self, status: int, body: Any, headers: Optional[Dict[str, str]] = None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> Any:
        return self._body


def training(oid: str, title: str, ref: str = "", code: str = "", modified_days: float = 100) -> Dict[str, Any]:
    return {"object_id": oid, "lo_title": title, "lo_type": "Online Class", "lo_object_type": "CRSE",
            "lo_version": "2026.1", "lo_active": "Y", "lo_status": "APPR", "lo_create_dt": iso(900),
            "lo_modified_dt": iso(modified_days), "training_version_effective_dt": None,
            "is_latest_training_version": True, "course_code": code, "lo_training_ref": ref}


def tx(user: int, oid: str, reg: int = 1, *, created: float = 30, comp: Optional[float] = None,
       due: Optional[float] = None, start: Optional[float] = None, exempt: Optional[float] = None,
       removed: bool = False) -> Dict[str, Any]:
    return {"transc_user_id": user, "transc_object_id": oid, "reg_num": reg, "user_lo_status_id": 1,
            "user_lo_create_dt": iso(created), "user_lo_assigned_dt": iso(created), "user_lo_reg_dt": iso(created),
            "user_lo_start_dt": iso(start) if start is not None else None,
            "user_lo_comp_dt": iso(comp) if comp is not None else None,
            "user_lo_min_due_date": iso(due) if due is not None else None,
            "user_lo_pct_complete": 0, "user_lo_pass": comp is not None, "is_removed": removed, "archived": False,
            "exempt_dt": iso(exempt) if exempt is not None else None, "is_assigned": True, "is_required": True,
            "is_latest_reg_num": 1, "user_lo_last_modified_dt": iso(created)}


class FakeCsod:
    def __init__(self) -> None:
        self.trainings: List[Dict[str, Any]] = []
        self.transcripts: List[Dict[str, Any]] = []
        self.users: List[Dict[str, Any]] = []
        self.page_size = 2
        self.token_calls = 0
        self.token_bodies: List[Dict[str, Any]] = []
        self.auth_status = 200
        self.view_status: Dict[str, int] = {}
        self.count_bonus: Dict[str, int] = {}
        self.duplicate_first_row = False
        self.next_link_override: Optional[str] = None
        self.repeat_next_link = False
        self.fail_once_429 = False
        self.gets: List[Dict[str, Any]] = []

    def post(self, url, json=None, data=None, headers=None, timeout=None, allow_redirects=True):
        assert allow_redirects is False, "credentials must never follow a redirect"
        assert url == TOKEN_URL
        self.token_calls += 1
        self.token_bodies.append(json)
        if self.auth_status != 200:
            return FakeResponse(self.auth_status, {"status": "400", "error": {"description": "bad"}})
        assert json["grantType"] == "client_credentials"
        return FakeResponse(200, {"access_token": f"tok{self.token_calls}", "expires_in": 3600,
                                  "scope": json["scope"], "token_type": "Bearer"})

    def _rows(self, view: str, flt: str) -> List[Dict[str, Any]]:
        if view == "vw_rpt_training":
            return [t for t in self.trainings
                    if any(f"'{v}'" in flt for v in (t["lo_title"], t["lo_training_ref"], t["course_code"]) if v)
                    or f"object_id eq {t['object_id']}" in flt]
        if view == "vw_rpt_transcript":
            return [r for r in self.transcripts if f"transc_object_id eq {r['transc_object_id']}" in flt]
        if view == "vw_rpt_user":
            return list(self.users)
        raise AssertionError(view)

    def get(self, url, headers=None, params=None, timeout=None, allow_redirects=True):
        assert allow_redirects is False, "credentials must never follow a redirect"
        assert headers["Authorization"].startswith("Bearer tok")
        assert headers["Prefer"].startswith("odata.maxpagesize=")
        parsed = urlparse(url)
        assert parsed.path.startswith("/services/api/x/odata/api/views/")
        view = parsed.path.rsplit("/", 1)[-1]
        self.gets.append({"view": view, "params": params, "url": url})
        if self.fail_once_429:
            self.fail_once_429 = False
            return FakeResponse(429, {}, {"Retry-After": "0"})
        if view in self.view_status:
            return FakeResponse(self.view_status[view], {"error": {"message": "Unauthorized"}})
        if params and params.get("$count") == "true":
            rows = self._rows(view, params.get("$filter", ""))
            return FakeResponse(200, {"@odata.count": len(rows) + self.count_bonus.get(view, 0), "value": []})
        if params:
            flt, page = params.get("$filter", ""), 0
        else:
            q = parse_qs(parsed.query)
            flt, page = q["f"][0], int(q["p"][0])
        rows = self._rows(view, flt)
        chunk = rows[page * self.page_size:(page + 1) * self.page_size]
        if self.duplicate_first_row and page == 1 and rows:
            chunk = [rows[0]] + chunk
        body: Dict[str, Any] = {"@odata.context": VIEWS + "$metadata#" + view, "value": chunk}
        if (page + 1) * self.page_size < len(rows):
            from urllib.parse import urlencode
            nxt = 1 if self.repeat_next_link else page + 1
            body["@odata.nextLink"] = self.next_link_override or (
                VIEWS + view + "?" + urlencode({"f": flt, "p": nxt}))
        return FakeResponse(200, body)


@pytest.fixture
def fake(monkeypatch, tmp_path) -> FakeCsod:
    f = FakeCsod()
    monkeypatch.setattr(csod_client.requests, "post", f.post)
    monkeypatch.setattr(csod_client.requests, "get", f.get)
    monkeypatch.setattr(csod_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(csod_client, "load_dotenv", lambda *a, **k: False)
    for name in ("CSOD_USER_POPULATION_FILTER", "CSOD_ALLOW_CUSTOM_ENDPOINTS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CSOD_CLIENT_ID", "client-id")
    monkeypatch.setenv("CSOD_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("CSOD_PORTAL_URL", PORTAL)
    monkeypatch.setenv("CSOD_MIN_REQUEST_INTERVAL", "0")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("CSOD_SECURITY_AWARENESS_COURSES", "Annual Security Awareness")
    monkeypatch.setenv("CSOD_SECURE_DEVELOPMENT_COURSES", "SEC-DEV-101")
    monkeypatch.setenv("CSOD_ROLE_BASED_COURSES", "Annual Security Awareness")
    monkeypatch.setenv("CSOD_INCIDENT_RESPONSE_COURSES", "Annual Security Awareness")
    f.trainings = [training(AWARENESS, "Annual Security Awareness", ref="SAT-2026"),
                   training(AWARENESS_OLD, "Annual Security Awareness", ref="SAT-2025", modified_days=500),
                   training(DEVSEC, "Secure Development", code="SEC-DEV-101")]
    f.transcripts = [
        tx(1, AWARENESS, comp=10),                         # completed, current
        tx(2, AWARENESS_OLD, comp=400, created=420),        # completed, stale
        tx(3, AWARENESS, due=5),                            # overdue (due 5 days ago)
        tx(4, AWARENESS, due=-20, start=2),                 # in progress, not yet due
        tx(5, AWARENESS, due=-20),                          # not started
        tx(6, AWARENESS, exempt=3),                         # exempt
        tx(7, AWARENESS, comp=5, removed=True),             # removed: excluded
        tx(8, AWARENESS_OLD, comp=200, created=210),        # last year's course, still current
        tx(8, AWARENESS, reg=1, due=-30, created=1),        # ...and a new assignment not yet done
        tx(9, DEVSEC, comp=20),
    ]
    return f


def load(short: str) -> Any:
    path = CSOD / short / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"cornerstone_{short}_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(short: str, tmp_path: Path) -> tuple[int, Dict[str, Any]]:
    module = load(short)
    code = csod_client.run_fetcher(module.collect, f"cornerstone_{short}.json", module.logger)
    return code, json.loads((tmp_path / f"cornerstone_{short}.json").read_text())


def users_by_id(ev: Dict[str, Any], course: int = 0) -> Dict[Any, Dict[str, Any]]:
    return {u["user_id"]: u for u in ev["courses"][course]["users"]}


# --- happy path and maths -------------------------------------------------


def test_awareness_statuses_and_summary(fake, tmp_path):
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0, ev
    assert ev["status"] == "success" and ev["config_resolution"]["status"] == "resolved"
    course = ev["courses"][0]
    assert {t["object_id"] for t in course["trainings"]} == {AWARENESS, AWARENESS_OLD}
    u = users_by_id(ev)
    assert set(u) == {1, 2, 3, 4, 5, 6, 8}, "removed registration must be excluded"
    assert u[1]["status"] == "completed" and u[1]["current"] is True
    assert u[2]["status"] == "completed" and u[2]["needs_retraining"] is True
    assert u[3]["status"] == "overdue" and u[3]["latest_registration"]["days_overdue"] >= 4
    assert u[4]["status"] == "in_progress" and u[5]["status"] == "not_started"
    assert u[6]["status"] == "exempt" and u[6]["current"] is True
    # Latest registration is the new open one, but last year's completion is still inside 365 days.
    assert u[8]["status"] == "not_started" and u[8]["current"] is True and u[8]["registrations"] == 2
    s = course["summary"]
    assert s["users_in_scope"] == 7 and s["current"] == 3 and s["needs_retraining"] == 4
    assert s["overdue"] == 1 and s["removed_registrations_excluded"] == 1
    assert s["completion_rate_pct"] == round(3 * 100 / 7, 2)
    assert ev["summary"]["users_current_on_all_courses"] == 3
    old = next(t for t in course["trainings"] if t["object_id"] == AWARENESS_OLD)
    assert old["content_changed_within_review_interval"] is False
    assert ev["metadata"]["complete"] is True and ev["metadata"]["partial_failure"] is False


def test_token_request_and_scopes(fake, tmp_path):
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0
    body = fake.token_bodies[0]
    assert body["clientId"] == "client-id" and body["clientSecret"] == SECRET
    assert body["scope"].split() == ["vw_rpt_training:read", "vw_rpt_transcript:read"]
    assert ev["portal"]["environment"] == "production" and ev["portal"]["token_lifetime_seconds"] == 3600


def test_every_read_is_counted_then_paged(fake, tmp_path):
    run("security_awareness_training", tmp_path)
    transcript_gets = [g for g in fake.gets if g["view"] == "vw_rpt_transcript"]
    assert transcript_gets[0]["params"]["$count"] == "true" and transcript_gets[0]["params"]["$top"] == "0"
    assert "transc_user_id" in transcript_gets[1]["params"]["$select"]
    assert len(transcript_gets) >= 4, "the transcript read should span several pages"


def test_duplicates_across_pages_are_dropped(fake, tmp_path):
    fake.duplicate_first_row = True
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0
    stats = [c for c in ev["collection"] if c["view"] == "vw_rpt_transcript"][0]
    assert stats["duplicates_dropped"] >= 1 and stats["complete"] is True
    assert ev["courses"][0]["summary"]["users_in_scope"] == 7


def test_population_adds_not_assigned_and_drops_outsiders(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_USER_POPULATION_FILTER", "user_status_id eq 1")
    fake.users = [{"user_id": i} for i in (1, 2, 3, 10, 11)]
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0
    assert "vw_rpt_user:read" in fake.token_bodies[0]["scope"].split()
    u = users_by_id(ev)
    assert set(u) == {1, 2, 3, 10, 11}
    assert u[10]["status"] == "not_assigned" and u[10]["needs_retraining"] is True
    s = ev["courses"][0]["summary"]
    assert s["not_assigned"] == 2 and s["users_outside_population_excluded"] == 4
    assert ev["summary"]["population_size"] == 5


def test_all_four_fetchers_run_and_claim_ced_rat(fake, tmp_path):
    import yaml
    for short in ("security_awareness_training", "role_based_training",
                  "secure_development_training", "incident_response_training"):
        code, ev = run(short, tmp_path)
        assert code == 0, (short, ev.get("message"))
        assert ev["training_group"]["key"] == short and ev["training_group"]["ksi"] == "KSI-CED-RAT"
        meta = yaml.safe_load((CSOD / short / "fetcher.yaml").read_text())
        assert meta["ksis"] == ["KSI-CED-RAT"] and meta["name"] == f"cornerstone_{short}"
    code, ev = run("secure_development_training", tmp_path)
    assert set(users_by_id(ev)) == {9}


# --- null, not zero ---------------------------------------------------------


def test_unresolved_course_is_null_not_zero_and_exits_0(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_SECURITY_AWARENESS_COURSES", "Annual Security Awareness,Typo Course")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0, "a config typo must not fail the run"
    assert ev["status"] == "partial_or_empty"
    assert ev["config_resolution"] == {**ev["config_resolution"], "status": "partial", "unmatched": ["Typo Course"]}
    typo = ev["courses"][1]
    assert typo["resolved"] is False and typo["summary"]["completion_rate_pct"] is None
    assert typo["summary"]["users_in_scope"] is None and typo["summary"]["current"] is None
    assert ev["summary"]["completion_rate_pct"] is None and ev["summary"]["users_in_scope"] is None
    assert "Typo Course" in ev["message"]


def test_missing_course_config_is_bad_config(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("CSOD_SECURITY_AWARENESS_COURSES")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config"
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


# --- completeness and failures ------------------------------------------------


def test_fewer_rows_than_count_is_a_failure(fake, tmp_path):
    fake.count_bonus["vw_rpt_transcript"] = 5
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and ev["metadata"]["complete"] is False
    assert ev["api_failures"][0]["type"] == "Incomplete"
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "partial_failure"


def test_next_link_to_another_host_is_not_followed(fake, tmp_path):
    fake.next_link_override = "https://evil.example/services/api/x/odata/api/views/vw_rpt_transcript?p=1"
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1
    assert "left the portal" in ev["api_failures"][0]["message"]
    assert not any("evil.example" in g["url"] for g in fake.gets)


def test_repeated_next_link_is_a_stall(fake, tmp_path):
    fake.repeat_next_link = True
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1
    assert "repeated" in ev["api_failures"][0]["message"]


def test_page_cap_is_a_failure(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_MAX_PAGES", "1")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and ev["api_failures"][0]["type"] == "PageCap"


def test_missing_scope_is_not_authorized(fake, tmp_path):
    fake.view_status["vw_rpt_transcript"] = 401
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1
    assert fake.token_calls == 2, "a 401 gets exactly one fresh token"
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_rate_limit_is_retried(fake, tmp_path):
    fake.fail_once_429 = True
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0


def test_redirect_is_refused(fake, tmp_path):
    fake.view_status["vw_rpt_training"] = 302
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and "redirect refused" in ev["api_failures"][0]["message"]


def test_bad_auth_is_clean_and_secret_never_leaks(fake, tmp_path):
    fake.auth_status = 400
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and ev["error_code"] == "auth_failed"
    blob = json.dumps(ev) + (tmp_path / "status.json").read_text()
    assert SECRET not in blob


def test_secret_never_in_successful_evidence(fake, tmp_path):
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and SECRET not in json.dumps(ev) and "tok1" not in json.dumps(ev)


# --- the portal URL guard ----------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://acme.csod.com", "https://acme.csod.com/", "https://acme-pilot.csod.com", "https://ACME.csod.com",
])
def test_portal_url_accepted(url):
    assert csod_client.normalize_portal_url(url).startswith("https://")


@pytest.mark.parametrize("url", [
    "http://acme.csod.com",
    "https://evil.com\\.csod.com",
    "https://evil.com/.csod.com",
    "https://user@acme.csod.com",
    "https://acme.csod.com.evil.com",
    "https://a.b.csod.com",
    "https://csod.com",
    "https://acme.csod.com/services/api",
    "https://acme.csod.com?x=1",
    "https://acme.csod.com:8443",
    "",
])
def test_portal_url_rejected(url, monkeypatch):
    monkeypatch.delenv("CSOD_ALLOW_CUSTOM_ENDPOINTS", raising=False)
    with pytest.raises(csod_client.CsodConfigError):
        csod_client.normalize_portal_url(url)


def test_bad_portal_is_bad_config_and_no_request_sent(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_PORTAL_URL", "https://evil.example")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config"
    assert fake.token_calls == 0


def test_client_refuses_paths_outside_views(fake):
    client = csod_client.build_client(["vw_rpt_training:read"])
    with pytest.raises(ValueError):
        client.get_json("x", PORTAL + "/services/api/x/users/v2/employees")


def test_odata_string_escaping():
    assert csod_client.odata_string("O'Brien's course") == "'O''Brien''s course'"


def test_non_guid_object_id_is_never_put_in_a_filter(fake, tmp_path):
    fake.trainings[0]["object_id"] = "x or 1 eq 1"
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and "not GUIDs" in ev["api_failures"][0]["message"]
    assert not any(g["view"] == "vw_rpt_transcript" for g in fake.gets)


# --- review-pass regressions (pentest, QA, security) -------------------------


@pytest.mark.parametrize("path", [
    "../../oauth2/token", "%2e%2e/%2e%2e/oauth2/token", "%2E%2E/x", "./vw_rpt_user", "vw_rpt_user%2f..%2fx",
])
def test_next_link_dot_segments_are_refused(path):
    client = csod_client.CsodClient.__new__(csod_client.CsodClient)
    client._host = "acme.csod.com"
    assert not client._check_next_link(VIEWS + path)


def test_next_link_default_port_is_same_host():
    client = csod_client.CsodClient.__new__(csod_client.CsodClient)
    client._host = "acme.csod.com"
    assert client._check_next_link("https://acme.csod.com:443/services/api/x/odata/api/views/vw_rpt_user?p=1")
    assert not client._check_next_link("https://acme.csod.com:8443/services/api/x/odata/api/views/vw_rpt_user")


def test_get_json_refuses_dot_segments(fake):
    client = csod_client.build_client(["vw_rpt_training:read"])
    with pytest.raises(ValueError):
        client.get_json("x", VIEWS + "../../oauth2/token")


def test_unresolved_course_lists_no_users_even_with_population(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_SECURITY_AWARENESS_COURSES", "Typo Course")
    monkeypatch.setenv("CSOD_USER_POPULATION_FILTER", "user_status_id eq 1")
    fake.users = [{"user_id": i} for i in (1, 2, 3)]
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and ev["courses"][0]["users"] == []
    assert ev["courses"][0]["summary"]["not_assigned"] is None


def test_population_ids_match_across_int_and_string(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_USER_POPULATION_FILTER", "user_status_id eq 1")
    fake.users = [{"user_id": "1"}, {"user_id": "3"}]
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0
    statuses = {str(u["user_id"]): u["status"] for u in ev["courses"][0]["users"]}
    assert statuses == {"1": "completed", "3": "overdue"}


def test_string_count_is_accepted(fake, monkeypatch):
    client = csod_client.build_client(["vw_rpt_training:read"])
    monkeypatch.setattr(client, "get_json", lambda *a, **k: {"@odata.count": "42", "value": []})
    assert client.view_count("vw_rpt_training", None) == 42 and client.api_failures == []


def test_allowlist_bypass_is_recorded_in_evidence(fake, tmp_path, monkeypatch):
    code, ev = run("security_awareness_training", tmp_path)
    assert ev["portal"]["custom_endpoint_override"] is False
    monkeypatch.setenv("CSOD_ALLOW_CUSTOM_ENDPOINTS", "true")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and ev["portal"]["custom_endpoint_override"] is True
