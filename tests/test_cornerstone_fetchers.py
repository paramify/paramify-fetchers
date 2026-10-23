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
    monkeypatch.delenv("CSOD_ALLOW_CUSTOM_ENDPOINTS", raising=False)
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
    monkeypatch.setenv("CSOD_USER_POPULATION_FILTER", "user_status_id eq 1")
    for name in ("CSOD_SECURITY_AWARENESS_POPULATION_FILTER", "CSOD_ROLE_BASED_POPULATION_FILTER",
                 "CSOD_SECURE_DEVELOPMENT_POPULATION_FILTER", "CSOD_INCIDENT_RESPONSE_POPULATION_FILTER",
                 "CSOD_WITHDRAWN_STATUS_IDS", "CSOD_FAILED_STATUS_IDS"):
        monkeypatch.delenv(name, raising=False)
    f.users = [{"user_id": i} for i in range(1, 10)]
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
    assert set(u) == set(range(1, 10))
    assert u[7]["status"] == "not_assigned", "a removed registration leaves the user never-assigned"
    assert u[9]["status"] == "not_assigned"
    assert u[1]["status"] == "completed" and u[1]["current"] is True
    assert u[2]["status"] == "completed" and u[2]["needs_retraining"] is True
    assert u[3]["status"] == "overdue" and u[3]["latest_registration"]["days_overdue"] >= 4
    assert u[4]["status"] == "in_progress" and u[5]["status"] == "not_started"
    assert u[6]["status"] == "exempt" and u[6]["current"] is True
    # Latest registration is the new open one, but last year's completion is still inside 365 days.
    assert u[8]["status"] == "not_started" and u[8]["current"] is True and u[8]["registrations"] == 2
    s = course["summary"]
    assert s["users_in_scope"] == 9 and s["current"] == 3 and s["needs_retraining"] == 6
    assert s["overdue"] == 1 and s["not_assigned"] == 2 and s["removed_registrations_excluded"] == 1
    assert s["completion_rate_pct"] == round(3 * 100 / 9, 2)
    assert ev["summary"]["users_current_on_all_courses"] == 3 and ev["summary"]["population_size"] == 9
    old = next(t for t in course["trainings"] if t["object_id"] == AWARENESS_OLD)
    assert old["content_changed_within_review_interval"] is False
    assert ev["metadata"]["complete"] is True and ev["metadata"]["partial_failure"] is False


def test_token_request_and_scopes(fake, tmp_path):
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0
    body = fake.token_bodies[0]
    assert body["clientId"] == "client-id" and body["clientSecret"] == SECRET
    assert body["scope"].split() == ["vw_rpt_training:read", "vw_rpt_transcript:read", "vw_rpt_user:read"]
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
    assert ev["courses"][0]["summary"]["users_in_scope"] == 9


def test_population_adds_not_assigned_and_drops_outsiders(fake, tmp_path):
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
    assert users_by_id(ev)[9]["status"] == "completed" and ev["courses"][0]["summary"]["completed"] == 1


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
    assert client.get_json("x", PORTAL + "/services/api/x/users/v2/employees") is None
    assert client.api_failures[0]["type"] == "RefusedUrl"
    assert all(g["view"] != "employees" for g in fake.gets)


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
    assert client.get_json("x", VIEWS + "../../oauth2/token") is None
    assert client.api_failures[0]["type"] == "RefusedUrl" and len(fake.gets) == 0


def test_unresolved_course_lists_no_users_even_with_population(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_SECURITY_AWARENESS_COURSES", "Typo Course")
    fake.users = [{"user_id": i} for i in (1, 2, 3)]
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and ev["courses"][0]["users"] == []
    assert ev["courses"][0]["summary"]["not_assigned"] is None


def test_population_ids_match_across_int_and_string(fake, tmp_path, monkeypatch):
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


def test_raw_cornerstone_status_id_is_exposed(fake, tmp_path):
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0
    assert users_by_id(ev)[1]["latest_registration"]["cornerstone_status_id"] == 1


# --- Bruce's review (PR #175) ------------------------------------------------


def test_no_population_means_null_rate_and_not_success(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("CSOD_USER_POPULATION_FILTER")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and ev["status"] == "partial_or_empty"
    assert "vw_rpt_user:read" not in fake.token_bodies[0]["scope"].split()
    assert ev["summary"]["completion_rate_pct"] is None
    assert ev["courses"][0]["summary"]["completion_rate_pct"] is None
    assert ev["courses"][0]["summary"]["users_in_scope"] == 7, "counts are still reported"
    assert "population" in ev["message"]


def test_per_fetcher_population_override_wins(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_ROLE_BASED_POPULATION_FILTER", "ou_id eq 42")
    code, ev = run("role_based_training", tmp_path)
    assert code == 0 and ev["config"]["user_population_filter"] == "ou_id eq 42"
    pop = [g for g in fake.gets if g["view"] == "vw_rpt_user"]
    assert pop and pop[0]["params"]["$filter"] == "ou_id eq 42"


def test_failed_attempt_is_not_completed(fake, tmp_path):
    fake.transcripts.append(tx(2, AWARENESS, reg=2, created=5, comp=2))
    fake.transcripts[-1]["user_lo_pass"] = False
    code, ev = run("security_awareness_training", tmp_path)
    u = users_by_id(ev)[2]
    assert u["status"] == "failed" and u["current"] is False
    assert u["last_completed_at"] is not None and u["days_since_last_completion"] >= 399


def test_withdrawn_status_id_from_config(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_WITHDRAWN_STATUS_IDS", "7, 9")
    fake.transcripts[0]["user_lo_status_id"] = 9  # user 1's completed row
    code, ev = run("security_awareness_training", tmp_path)
    u = users_by_id(ev)[1]
    assert u["status"] == "withdrawn" and u["current"] is False
    assert ev["config"]["withdrawn_status_ids"] == [7, 9]


def test_bad_status_id_list_is_bad_config(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CSOD_WITHDRAWN_STATUS_IDS", "Withdrawn")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config"


def test_exemption_ages_like_a_completion(fake, tmp_path):
    fake.transcripts = [tx(6, AWARENESS, exempt=400, created=410)]
    fake.users = [{"user_id": 6}]
    code, ev = run("security_awareness_training", tmp_path)
    u = users_by_id(ev)[6]
    assert u["status"] == "exempt" and u["current"] is False and u["last_exempt_at"] is not None


def test_overdue_assignment_beats_recent_completion(fake, tmp_path):
    fake.transcripts = [tx(8, AWARENESS_OLD, comp=100, created=110), tx(8, AWARENESS, due=3, created=40)]
    fake.users = [{"user_id": 8}]
    code, ev = run("security_awareness_training", tmp_path)
    u = users_by_id(ev)[8]
    assert u["status"] == "overdue" and u["current"] is False and u["days_since_last_completion"] == 100


def test_course_alternatives_count_as_one_course(fake, tmp_path, monkeypatch):
    fake.trainings[1]["lo_title"] = "2025 Security Awareness"
    monkeypatch.setenv("CSOD_SECURITY_AWARENESS_COURSES", "Annual Security Awareness | 2025 Security Awareness")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and ev["status"] == "success"
    course = ev["courses"][0]
    assert course["name"] == "Annual Security Awareness|2025 Security Awareness"
    assert {t["object_id"] for t in course["trainings"]} == {AWARENESS, AWARENESS_OLD}
    assert users_by_id(ev)[8]["current"] is True, "last year's version still counts"
    assert ev["config_resolution"]["matched"] == [course["name"]]


def test_guid_case_mismatch_is_still_attributed(fake, tmp_path):
    for t in fake.trainings:
        t["object_id"] = t["object_id"].upper()
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and ev["courses"][0]["summary"]["completed"] == 2
    assert ev["summary"]["transcript_rows_unattributed"] == 0


def test_rows_read_but_none_attributed_is_a_failure(fake, tmp_path, monkeypatch):
    real = fake._rows

    def wrong_rows(view, flt):
        rows = real(view, flt)
        if view == "vw_rpt_transcript":
            rows = [{**r, "transc_object_id": "99999999-9999-9999-9999-999999999999", "reg_num": i}
                    for i, r in enumerate(rows)]
        return rows
    monkeypatch.setattr(fake, "_rows", wrong_rows)
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and "none belong" in ev["api_failures"][0]["message"]


def test_explicit_443_next_link_goes_through_get_json(fake, tmp_path):
    fake.next_link_override = VIEWS + "vw_rpt_transcript?f=unused&p=1"
    client = csod_client.build_client(["vw_rpt_training:read"])
    link = "https://ACME.csod.com:443/services/api/x/odata/api/views/vw_rpt_training"
    assert client._check_next_link(link)
    payload = client.get_json("x", link, params={"$filter": "lo_title eq 'none'"})
    assert payload is not None and payload["value"] == [] and client.api_failures == []


def test_url_outside_views_is_recorded_not_raised(fake):
    client = csod_client.build_client(["vw_rpt_training:read"])
    assert client.get_json("x", VIEWS + "../../oauth2/token") is None
    assert client.api_failures[0]["type"] == "RefusedUrl"


def test_401_on_last_retry_is_not_authorized(fake, tmp_path, monkeypatch):
    calls = {"n": 0}

    def flaky(url, **kw):
        calls["n"] += 1
        if calls["n"] <= csod_client.MAX_RETRIES:
            return FakeResponse(429, {}, {"Retry-After": "0"})
        return FakeResponse(401, {"error": {"message": "Unauthorized"}})
    monkeypatch.setattr(csod_client.requests, "get", flaky)
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 1 and ev["api_failures"][0]["status_code"] == 401
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_401_then_fresh_token_recovers(fake, tmp_path, monkeypatch):
    seen = {"n": 0}
    original = fake.get

    def once_401(url, **kw):
        seen["n"] += 1
        if seen["n"] == 1:
            return FakeResponse(401, {})
        return original(url, **kw)
    monkeypatch.setattr(csod_client.requests, "get", once_401)
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and fake.token_calls == 2


def test_token_expiry_mid_run_renews(fake, tmp_path, monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(csod_client.time, "monotonic", lambda: clock["t"])
    original_post = fake.post

    def short_token(url, **kw):
        r = original_post(url, **kw)
        r._body["expires_in"] = 90  # renewed 60 s early, so 30 s of use
        return r
    monkeypatch.setattr(csod_client.requests, "post", short_token)
    original_get = fake.get

    def ticking_get(url, **kw):
        clock["t"] += 20
        return original_get(url, **kw)
    monkeypatch.setattr(csod_client.requests, "get", ticking_get)
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and fake.token_calls > 1
    assert all(g["url"] for g in fake.gets)


def test_expires_in_zero_is_not_an_hour(fake, tmp_path):
    client = csod_client.build_client(["vw_rpt_training:read"])
    client._token_expires_at = 0.0  # as a zero lifetime leaves it: already expired
    client.get_json("x", VIEWS + "vw_rpt_training", params={"$filter": "lo_title eq 'none'"})
    assert fake.token_calls == 2, "an expired token is renewed before the call"


def test_rows_without_user_id_are_skipped_and_counted(fake, tmp_path):
    fake.transcripts.append(tx(0, AWARENESS, reg=7, comp=1))
    fake.transcripts[-1]["transc_user_id"] = None
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0
    assert all(u["user_id"] is not None and u["user_id"] != "None" for u in ev["courses"][0]["users"])
    assert ev["courses"][0]["summary"]["rows_without_user_id_excluded"] == 1
    assert ev["courses"][0]["summary"]["users_in_scope"] == 9


def test_course_names_resolve_in_one_query(fake, tmp_path, monkeypatch):
    fake.trainings[1]["lo_title"] = "Insider Threat Awareness"
    monkeypatch.setenv("CSOD_SECURITY_AWARENESS_COURSES", "Annual Security Awareness, Insider Threat Awareness")
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0 and ev["config_resolution"]["status"] == "resolved"
    training_gets = [g for g in fake.gets if g["view"] == "vw_rpt_training"]
    assert len(training_gets) == 2, "one $count and one page for both names together"
    assert {t["object_id"] for t in ev["courses"][0]["trainings"]} == {AWARENESS}
    assert {t["object_id"] for t in ev["courses"][1]["trainings"]} == {AWARENESS_OLD}


def test_long_course_lists_are_chunked_under_the_url_limit():
    import training_completion as tc
    names = [f"Course number {i} with a fairly long descriptive title" for i in range(40)]
    chunks = tc._name_chunks(names)
    assert len(chunks) > 1 and sum(len(c) for c in chunks) == 40
    from urllib.parse import urlencode
    for chunk in chunks:
        url = VIEWS + "vw_rpt_training?" + urlencode({"$select": ",".join(tc.TRAINING_SELECT),
                                                      "$filter": tc._course_filter(chunk)})
        assert len(url) < 2083


def test_reauth_does_not_consume_a_retry(fake, tmp_path, monkeypatch):
    calls = {"n": 0}
    original = fake.get

    def flaky(url, **kw):
        calls["n"] += 1
        if calls["n"] <= csod_client.MAX_RETRIES:
            return FakeResponse(429, {}, {"Retry-After": "0"})
        if calls["n"] == csod_client.MAX_RETRIES + 1:
            return FakeResponse(401, {})
        return original(url, **kw)
    monkeypatch.setattr(csod_client.requests, "get", flaky)
    code, ev = run("security_awareness_training", tmp_path)
    assert code == 0, "a 401 on the last attempt still gets one fresh token and the retry succeeds"
    assert fake.token_calls == 2
