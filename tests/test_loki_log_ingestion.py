"""loki_log_ingestion over Loki query API responses shaped like the documented /loki/api/v1/query (vector),
/loki/api/v1/query_range (streams) and /loki/api/v1/series results: no Loki, no network.

Three expected sources: pods is arriving now; falco went quiet three hours ago; keycloak has sent nothing in the
search window at all.
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "loki_log_ingestion"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
spec = importlib.util.spec_from_file_location("loki_log_ingestion_under_test",
                                              REPO_ROOT / "fetchers" / "loki" / "log_ingestion" / "fetcher.py")
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)

NOW = datetime(2025, 11, 20, 1, 33, 20, tzinfo=timezone.utc)
NOW_NS = int(NOW.timestamp()) * 10**9
SOURCES = 'pods={namespace=~".+", container!=""}; falco={namespace="falco"}; keycloak={app="keycloak"}'
# selector -> (lines in window, seconds since newest line or None, streams in window)
STATE = {'{namespace=~".+", container!=""}': (18342, 30, 3), '{namespace="falco"}': (0, 3 * 3600, 0),
         '{app="keycloak"}': (0, None, 0)}


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


class Response:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.text = json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("Expecting value")
        return self._body


class Loki:
    """A fake requests.Session answering GETs as Loki would for STATE; `broken` maps a (path, selector) to a status."""

    def __init__(self, state=None, broken=None):
        self.state, self.broken, self.calls = state or STATE, broken or {}, []

    def get(self, url, params=None, timeout=None, allow_redirects=None, headers=None):
        path = url.split("://", 1)[1].split("/", 1)[1]
        path = "/" + path
        selector = params.get("match[]") or params["query"]
        if path.endswith("/query"):
            selector = selector[len("sum(count_over_time("):selector.rindex("[")]
        self.calls.append((path, selector, dict(headers or {})))
        if (path, selector) in self.broken:
            status = self.broken[(path, selector)]
            return Response(200, fixture("query_error.json")) if status == "query_error" else Response(status, {"message": "boom"})
        lines, age, streams = self.state[selector]
        if path.endswith("/query"):
            body = fixture("query_vector.json") if lines else fixture("query_vector_empty.json")
            if lines:
                body["data"]["result"][0]["value"][1] = str(lines)
        elif path.endswith("/query_range"):
            body = fixture("query_range_streams.json") if age is not None else fixture("query_range_empty.json")
            if age is not None:
                body["data"]["result"][0]["values"][0][0] = str(NOW_NS - age * 10**9)
        else:
            body = fixture("series.json")
            body["data"] = body["data"][:streams]
        return Response(200, body)


@pytest.fixture
def run(monkeypatch, tmp_path):
    def go(session=None, **env):
        session = session or Loki()
        settings = {"LOKI_BASE_URL": "http://loki.example.test/", "LOKI_EXPECTED_SOURCES": SOURCES}
        settings.update(env)
        for key in ("LOKI_BASE_URL", "LOKI_EXPECTED_SOURCES", "LOKI_TENANT_ID", "LOKI_TOKEN", "LOKI_WINDOW_MINUTES",
                    "LOKI_SEARCH_HOURS", "LOKI_MAX_AGE_MINUTES"):
            monkeypatch.delenv(key, raising=False)
        for key, value in settings.items():
            if value is not None:
                monkeypatch.setenv(key, value)
        monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
        monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
        monkeypatch.setattr(fx, "load_dotenv", lambda *a, **k: None)
        monkeypatch.setattr(fx.time, "sleep", lambda s: None)
        monkeypatch.setattr(fx.requests, "Session", lambda: session)
        real_collect = fx.collect
        monkeypatch.setattr(fx, "collect", lambda *a, **k: real_collect(*a, now=NOW))
        code = fx.main()
        status = tmp_path / "status.json"
        return code, json.loads((tmp_path / "loki_log_ingestion.json").read_text()), session, \
            json.loads(status.read_text()) if status.exists() else None
    return go


def test_sources_arriving_and_quiet_are_told_apart(run, assert_summary_documented):
    code, ev, _, _ = run()
    s = ev["summary"]
    assert code == 0 and s["expected_sources"] == ["pods", "falco", "keycloak"]
    assert (s["sources_ingesting"], s["sources_not_ingesting"], s["sources_not_ingesting_names"]) == (1, 2, ["falco", "keycloak"])
    assert (s["all_expected_sources_ingesting"], s["sources_not_seen_in_search_window"]) == (False, 1)
    # falco was last seen three hours ago; keycloak, never seen, is not counted in the longest age.
    assert s["longest_minutes_since_newest_entry"] == 180.0
    # No maximum age adopted: staleness is not judged.
    assert (s["max_age_minutes"], s["sources_stale"]) == (None, None)
    assert_summary_documented("loki/log_ingestion", s)


def test_each_source_records_counts_and_newest_time(run):
    _, ev, _, _ = run()
    by = {r["name"]: r for r in ev["results"]["sources"]}
    assert (by["pods"]["lines_in_window"], by["pods"]["streams_in_window"], by["pods"]["minutes_since_newest"]) == (18342, 3, 0.5)
    assert by["pods"]["newest_entry"] == "2025-11-20T01:32:50Z" and by["pods"]["ingesting"] is True
    assert (by["falco"]["ingesting"], by["falco"]["seen_in_search_window"]) == (False, True)
    assert (by["keycloak"]["newest_entry"], by["keycloak"]["seen_in_search_window"]) == (None, False)


def test_log_lines_and_labels_are_never_copied(run):
    _, ev, _, _ = run()
    text = json.dumps(ev)
    assert "SECRET-LINE" not in text and "falco-abcde" not in text


def test_a_maximum_age_judges_staleness(run, assert_summary_documented):
    code, ev, _, _ = run(LOKI_MAX_AGE_MINUTES="60")
    s = ev["summary"]
    # falco is three hours old and keycloak was never seen: both stale.
    assert code == 0 and (s["max_age_minutes"], s["sources_stale"]) == (60, 2)
    assert {r["name"]: r["stale"] for r in ev["results"]["sources"]} == {"pods": False, "falco": True, "keycloak": True}
    assert_summary_documented("loki/log_ingestion", s)


def test_every_source_arriving(run):
    session = Loki(state={k: (5, 10, 1) for k in STATE})
    code, ev, _, _ = run(session=session, LOKI_MAX_AGE_MINUTES="15")
    s = ev["summary"]
    assert code == 0 and (s["all_expected_sources_ingesting"], s["sources_stale"], s["sources_not_ingesting_names"]) == (True, 0, [])


def test_windows_tenant_and_token_reach_loki(run):
    session = Loki()
    run(session=session, LOKI_TENANT_ID="tenant-a", LOKI_TOKEN="t0ken", LOKI_WINDOW_MINUTES="15")
    assert all(h.get("X-Scope-OrgID") == "tenant-a" and h.get("Authorization") == "Bearer t0ken" for _, _, h in session.calls)
    assert len(session.calls) == 9


def test_window_setting_reaches_the_count_query(monkeypatch):
    seen = []

    class Recorder(Loki):
        def get(self, url, params=None, **kw):
            seen.append(params)
            return super().get(url, params=params, **kw)

    client = fx.LokiClient("http://loki.example.test", session=Recorder())
    fx.collect(client, [{"name": "falco", "selector": '{namespace="falco"}'}], 15, 6, None, now=NOW)
    assert seen[0]["query"] == 'sum(count_over_time({namespace="falco"}[15m]))'
    assert int(seen[1]["start"]) == NOW_NS - 6 * 3600 * 10**9 and seen[1]["limit"] == "1" and seen[1]["direction"] == "backward"


def test_a_failed_query_leaves_the_judgement_null(run, assert_summary_documented):
    session = Loki(broken={("/loki/api/v1/query_range", '{namespace="falco"}'): 503})
    code, ev, _, status = run(session=session)
    s = ev["summary"]
    assert code == 1 and s["sources_unread"] == 1
    for k in ("sources_ingesting", "sources_not_ingesting", "all_expected_sources_ingesting",
              "sources_not_seen_in_search_window", "longest_minutes_since_newest_entry"):
        assert s[k] is None, k
    assert ev["metadata"]["api_failures"][0]["operation"] == "newest entry (falco)"
    assert status["code"] == "partial_failure"
    assert_summary_documented("loki/log_ingestion", s)


def test_a_query_loki_rejects_is_recorded(run):
    session = Loki(broken={("/loki/api/v1/query", '{app="keycloak"}'): "query_error"})
    code, ev, _, _ = run(session=session)
    assert code == 1 and ev["metadata"]["api_failures"][0]["type"] == "QueryError"
    assert ev["summary"]["all_expected_sources_ingesting"] is None


def test_refused_credentials_are_auth_failed(run):
    session = Loki(broken={(p, s): 401 for s in STATE for p in ("/loki/api/v1/query", "/loki/api/v1/query_range",
                                                               "/loki/api/v1/series")})
    code, _, _, status = run(session=session)
    assert code == 1 and status["code"] == "auth_failed"


@pytest.mark.parametrize("env", [{"LOKI_EXPECTED_SOURCES": "pods=namespace"},
                                 {"LOKI_EXPECTED_SOURCES": 'falco={namespace="falco"}; FALCO={app="keycloak"}'},
                                 {"LOKI_EXPECTED_SOURCES": None},
                                 {"LOKI_MAX_AGE_MINUTES": "an hour"},
                                 {"LOKI_BASE_URL": None}])
def test_bad_settings_fail_as_bad_config(run, env):
    code, ev, _, status = run(**env)
    assert code == 1 and status["code"] == "bad_config"
    assert ev["metadata"]["api_failures"][0]["operation"].startswith("config")


def test_parse_sources():
    sources, invalid = fx.parse_sources(' a={x="1"} ;; b = {y=~"2|3"} ; bad ; c={z="4"} | json')
    assert sources == [{"name": "a", "selector": '{x="1"}'}, {"name": "b", "selector": '{y=~"2|3"}'}]
    assert invalid == ["bad", 'c={z="4"} | json']
