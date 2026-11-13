"""Splunk fetchers, driven without a Splunk deployment.

Shape tests hold every fetcher to the category's pattern (fetchers/splunk/README.md,
"Adding a fetcher"). Pure-logic tests pin the rules that decide a verdict. The run
tests drive each fetcher through the shared run() against FakeSplunk, a stand-in
for requests.Session serving one small, consistent deployment, and check the ways
Splunk returns partial data without an HTTP error: a paging.total that disagrees
with the entries, a WARN on a search, and a token missing a capability.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pytest
import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SPLUNK = REPO_ROOT / "fetchers" / "splunk"
FETCHERS = ["log_source_freshness", "data_inputs", "index_activity", "index_retention",
            "alert_rules", "alert_delivery", "role_index_access"]


def _load(name):
    spec = importlib.util.spec_from_file_location(f"splunk_{name}_under_test", SPLUNK / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODS = {name: _load(name) for name in FETCHERS}
sc = sys.modules["splunk_client"]
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
from fetcher_status import STATUS_CODES  # noqa: E402

NOW = time.time()
BASE = "https://splunk.test:8089"


# --- the shape every fetcher follows -------------------------------------------

CATEGORY = yaml.safe_load((REPO_ROOT / "fetchers" / "_categories" / "splunk.yaml").read_text())
README = (SPLUNK / "README.md").read_text()


@pytest.mark.parametrize("name", FETCHERS)
def test_every_fetcher_follows_the_shape(name):
    m, spec = MODS[name], yaml.safe_load((SPLUNK / name / "fetcher.yaml").read_text())
    assert m.NAME == spec["name"] == f"splunk_{name}"
    assert callable(m.collect) and m.CAPABILITIES and "search" in m.CAPABILITIES
    declared = {f["env"] for f in {**CATEGORY["config_schema"], **spec.get("config_schema", {})}.values()}
    assert {env for env, _ in getattr(m, "CONFIG", {}).values()} <= declared
    assert len(spec["evidence_set"]["instructions"].split()) <= 80


@pytest.mark.parametrize("name", FETCHERS)
def test_the_readme_lists_every_capability_a_fetcher_checks(name):
    row = next(line for line in README.splitlines() if line.startswith(f"| `splunk_{name}` |") and "`search`" in line)
    assert all(f"`{cap}`" in row for cap in MODS[name].CAPABILITIES)


# --- pure logic --------------------------------------------------------------

def test_disallowed_index_patterns_win_over_allowed_ones():
    ria = MODS["role_index_access"]
    names = {"_audit", "_internal", "main", "web"}
    assert ria.expand({"_*"}, names) - ria.expand({"_audit"}, names) == {"_internal"}


def test_a_roles_effective_indexes_subtract_its_denials():
    ria = MODS["role_index_access"]
    roles = {"auditor": {"srchIndexesAllowed": ["*", "_*"], "srchIndexesDisallowed": ["_audit"]}}
    derived = ria.access(roles, ["auditor"], {"search"}, {"_audit", "_internal", "main"})
    assert derived["effective_indexes"] == ["_internal", "main"]
    assert derived["can_search_all_internal"] is False


def test_inheritance_is_followed_through_every_level():
    roles = {"a": {"imported_roles": ["b"]}, "b": {"imported_roles": "c"}, "c": {"imported_roles": ["a"]}}
    assert MODS["role_index_access"].inherited(roles, "a") == {"b", "c"}


def test_star_never_reaches_internal_indexes_and_underscore_patterns_do():
    ria = MODS["role_index_access"]
    names = {"_audit", "_internal", "main", "web"}
    assert ria.expand({"*"}, names) == {"main", "web"}
    assert ria.expand({"_aud*"}, names) == {"_audit"}
    assert not ria.matches("*", "_audit")


def test_alert_classification_follows_splunk_webs_filter():
    is_alert = MODS["alert_rules"].is_alert
    assert is_alert({"is_scheduled": True, "alert_type": "number of events"})
    assert is_alert({"is_scheduled": True, "alert_type": "always", "alert.track": True, "actions": "email"})
    assert is_alert({"is_scheduled": "1", "alert_type": "always", "alert.track": "1"})  # stringified flags
    assert not is_alert({"is_scheduled": True, "alert_type": "always", "alert.track": "0", "actions": "email"})
    assert is_alert({"is_scheduled": True, "alert_type": "always", "dispatch.earliest_time": "rt-5m",
                     "dispatch.latest_time": "rt", "actions": "webhook"})
    assert not is_alert({"is_scheduled": False, "alert_type": "number of events", "actions": "email"})


def test_telemetry_only_action_is_not_a_notification():
    row = _alert_row(["outputtelemetry"])
    assert row["has_notification_action"] is False
    assert _alert_row(["outputtelemetry", "webhook"])["has_notification_action"] is True


def _alert_row(actions):
    entry = {"name": "a", "id": f"{BASE}/servicesNS/nobody/search/saved/searches/a",
             "content": {"actions": ",".join(actions), "alert_type": "number of events"}}
    return MODS["alert_rules"].alert_row(entry, {}, {}, 30)


def test_input_stanza_types():
    it = MODS["data_inputs"].input_type
    assert it("monitor:///var/log/secure") == "monitor"
    assert it("fschange:/etc") == "fschange"
    assert it("splunktcp://9997") == "splunktcp"
    assert it("splunktcptoken://fwd") is None
    for not_an_input in ("default", "SSL", "script", "blacklist:x", "filter:allow:x"):
        assert it(not_an_input) is None


def test_rest_input_matches_its_stanza_through_the_double_encoded_id():
    di = MODS["data_inputs"]
    entry = {"name": "/var/log/secure", "id": f"{BASE}/servicesNS/nobody/search/data/inputs/monitor/%252Fvar%252Flog%252Fsecure",
             "content": {"eai:location": "/data/inputs/monitor"}}
    assert di.stanza_of(entry, {"monitor:///var/log/secure", "default"}) == "monitor:///var/log/secure"
    assert di.stanza_of(entry, {"default"}) is None


def test_delivery_outcome():
    outcome = MODS["alert_delivery"].outcome
    assert outcome(None) == "not_attempted"
    assert outcome({"attempts": "2", "succeeded": "2"}) == "succeeded"
    assert outcome({"attempts": "2", "succeeded": "1"}) == "failed"
    assert outcome({"attempts": "0", "succeeded": "0"}) == "failed"


def test_index_staleness_rules():
    ia = MODS["index_activity"]

    def row(content, times, counts):
        return ia.index_row({"name": "main", "content": {"datatype": "event", **content}}, counts,
                            {"main": times} if times else {}, NOW, 60)

    fresh = row({}, {"last_indexed": NOW - 120}, {"main": {"count": 5, "size_bytes": 1, "servers": {"s"}}})
    assert (fresh["holds_data"], fresh["stale"]) == (True, False)
    quiet = row({}, {"last_indexed": NOW - 7200}, {"main": {"count": 5, "size_bytes": 1, "servers": {"s"}}})
    assert quiet["stale"] is True
    future = row({}, {"last_indexed": NOW + 7200}, {"main": {"count": 5, "size_bytes": 1, "servers": {"s"}}})
    assert future["stale"] is True
    empty = row({}, None, {"main": {"count": 0, "size_bytes": 0, "servers": {"s"}}})
    assert (empty["holds_data"], empty["stale"]) == (False, True)
    disabled = row({"disabled": True}, None, {})
    assert (disabled["holds_data"], disabled["stale"]) == (None, True)


def test_retention_and_freeze_rules():
    ir = MODS["index_retention"]
    assert ir.retention_days({"frozenTimePeriodInSecs": "188697600"}) == 2184
    assert ir.retention_days({"frozenTimePeriodInSecs": 0}) == 0  # freeze immediately, not "unset"
    assert ir.retention_days({"frozenTimePeriodInSecs": "soon"}) is None
    assert ir.archives_on_freeze({"coldToFrozenDir": "/archive"})
    assert ir.archives_on_freeze({"coldToFrozenScript": "archive.sh"})
    assert not ir.archives_on_freeze({"coldToFrozenDir": " "})


def test_both_value_renderings_decode():
    assert (sc.as_bool(True), sc.as_bool("0"), sc.as_bool("true"), sc.as_bool(1)) == (True, False, True, True)
    assert sc.as_bool("maybe") is None and sc.as_bool(None) is None
    assert (sc.as_int(5), sc.as_int("0"), sc.as_int("12.0")) == (5, 0, 12)
    assert sc.as_int(True) is None and sc.as_int("n/a") is None


def test_silence_is_judged_in_both_directions():
    assert sc.silence(NOW - 120, NOW, 60) == (2, False)
    assert sc.silence(NOW - 7200, NOW, 60)[1] is True
    assert sc.silence(NOW + 7200, NOW, 60)[1] is True
    assert sc.silence(None, NOW, 60) == (None, True)


# --- client resilience ---------------------------------------------------------

class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers, self.reason = status, body, headers or {}, "reason"

    @property
    def text(self):
        return self._body if isinstance(self._body, str) else json.dumps(self._body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def _client_with(monkeypatch, answers):
    sleeps = []
    monkeypatch.setattr(sc.time, "sleep", sleeps.append)
    client = sc.SplunkClient(BASE, "t")
    calls = iter(answers)

    def request(*_a, **_k):
        answer = next(calls)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(client.session, "request", request)
    return client, sleeps


def test_rate_limit_is_retried_honouring_retry_after(monkeypatch):
    client, sleeps = _client_with(monkeypatch, [_Resp(429, {}, {"Retry-After": "3"}), _Resp(200, {"entry": []})])
    assert client.get("services/server/info") == {"entry": []}
    assert sleeps == [3.0] and client.failures == []


def test_retries_are_bounded_and_the_last_answer_is_reported(monkeypatch):
    client, sleeps = _client_with(monkeypatch, [_Resp(503, {})] * (sc.MAX_RETRIES + 1))
    assert client.get("services/server/info") is None
    assert len(sleeps) == sc.MAX_RETRIES and client.failures[0]["type"] == "HTTP 503"


def test_a_tls_failure_is_not_retried(monkeypatch):
    client, sleeps = _client_with(monkeypatch, [requests.exceptions.SSLError("bad cert")])
    assert client.get("services/server/info") is None
    assert sleeps == [] and client.codes == ["target_unreachable"]


def test_a_ca_bundle_verifies_even_when_verify_ssl_is_off():
    client = sc.SplunkClient(BASE, "t", verify_ssl=False, ca_bundle="/etc/ssl/ca.pem")
    assert client.session.verify == "/etc/ssl/ca.pem" and client.tls_verified is True
    assert sc.SplunkClient(BASE, "t", verify_ssl=False).tls_verified is False


# --- a fake deployment -----------------------------------------------------------

CAPS = ["admin_all_objects", "list_all_roles", "list_all_users", "list_inputs", "rest_properties_get", "search"]
INDEXES = {"main": "event", "_audit": "event", "_internal": "event", "_metrics": "metric"}
SS = f"{BASE}/servicesNS/nobody/search/saved/searches"


def _entry(name, content, id_=None, app="search", owner="nobody"):
    return {"name": name, "id": id_ or f"{BASE}/servicesNS/{owner}/{app}/x/{quote(name)}",
            "acl": {"app": app, "owner": owner, "sharing": "app"}, "content": content}


def _index(name, datatype):
    return _entry(name, {"disabled": False, "datatype": datatype, "totalEventCount": 10, "currentDBSizeMB": "1",
                         "frozenTimePeriodInSecs": 7776000 if name == "_audit" else "188697600",
                         "enableDataIntegrityControl": name == "_audit",
                         "coldToFrozenDir": "/archive/_audit" if name == "_audit" else "",
                         "maxTotalDataSizeMB": "500000", "minTime": NOW - 86400, "maxTime": NOW - 60})


SAVED = [
    _entry("Failed logins", {"is_scheduled": True, "alert_type": "number of events", "alert.track": True,
                             "actions": "email", "action.email.to": "soc@example.com", "cron_schedule": "*/15 * * * *",
                             "alert.severity": 4, "disabled": False}, f"{SS}/Failed%20logins"),
    _entry("Tracked report", {"is_scheduled": True, "alert_type": "always", "alert.track": True, "actions": "email",
                              "disabled": False}, f"{SS}/Tracked%20report"),
    _entry("Telemetry", {"is_scheduled": True, "alert_type": "number of events", "alert.track": False,
                         "actions": "outputtelemetry", "disabled": False}, f"{SS}/Telemetry"),
    _entry("Nightly report", {"is_scheduled": True, "alert_type": "always", "alert.track": False, "actions": "",
                              "disabled": False}, f"{SS}/Nightly%20report"),
    _entry("Bookmark", {"is_scheduled": False, "alert_type": "always", "actions": ""}, f"{SS}/Bookmark"),
]
ALERTS = [e for e in SAVED if e["name"] in ("Failed logins", "Tracked report", "Telemetry")]

ROLES = [
    _entry("admin", {"capabilities": CAPS[:-1] + ["delete_by_keyword"], "imported_capabilities": ["search"],
                     "srchIndexesAllowed": ["*", "_*"], "imported_srchIndexesAllowed": ["main"],
                     "imported_roles": ["user"]}),
    _entry("user", {"capabilities": ["search"], "srchIndexesAllowed": ["main"], "srchTimeWin": "86400"}),
]
USERS = [
    _entry("collector", {"type": "Splunk", "roles": ["admin"], "capabilities": CAPS + ["delete_by_keyword"],
                         "last_successful_login": NOW - 3600}),
    _entry("analyst", {"type": "SAML", "roles": ["user"], "capabilities": ["search"],
                       "last_successful_login": NOW - 200 * 86400}),
    _entry("provisioned", {"type": "Splunk", "roles": ["user"], "capabilities": ["search"]}),
]

INPUTS = [
    _entry("/var/log/secure", {"eai:location": "/data/inputs/monitor", "index": "default", "sourcetype": "linux_secure",
                               "host": "web01", "host_resolved": "web01", "disabled": False},
           f"{BASE}/servicesNS/nobody/search/data/inputs/monitor/%252Fvar%252Flog%252Fsecure"),
    _entry("9997", {"eai:location": "/data/inputs/tcp/cooked", "disabled": False},
           f"{BASE}/servicesNS/nobody/search/data/inputs/tcp/cooked/9997"),
]
EMAIL_ACTION = _entry("email", {"command": "sendemail \"to=$action.email.to$\" | sendemail", "use_tls": "1",
                                "mailserver": "smtp.example.com:587", "track_alert": "1"}, app="system")


def _searches(m):
    times = {"first_event": NOW - 86400, "last_event": NOW - 60, "last_indexed": NOW - 60}
    return {
        # The client's searchable_indexes() runs the same SPL.
        sc.SEARCHABLE_INDEXES_SPL: [{"indexes": list(INDEXES)}],
        m["log_source_freshness"].HOSTS_SPL: [{"host": "web01", "count": "5", **times}, {"host": "sh1", "count": "9", **times}],
        m["log_source_freshness"].HOST_COUNT_SPL: [{"hosts": "2"}],
        m["log_source_freshness"].FORWARDERS_SPL: [{"hostname": "web01", "fwd_type": "uf", "version": "10.4.3",
                                                    "source_ip": "10.0.0.5", "last_connected": NOW - 120}],
        m["index_activity"].COUNTS_SPL: [{"index": n, "count": "10", "size_bytes": "1024", "server": "sh1"} for n in INDEXES],
        m["index_activity"].EVENT_TIMES_SPL: [{"index": n, **times} for n, t in INDEXES.items() if t == "event"],
        m["index_activity"].METRIC_TIMES_SPL: [{"index": "_metrics", **times}],
        m["data_inputs"].RECEIVED_SPL: [
            {"host": "web01", "index": "main", "sourcetype": "linux_secure", "count": "5", "sources": "1", **times},
            {"host": "sh1", "index": "_internal", "sourcetype": "splunkd", "count": "9", "sources": "2", **times}],
        m["data_inputs"].RECEIVED_CHECK_SPL: [{"host": "web01", "index": "main", "sourcetypes": "1"},
                                              {"host": "sh1", "index": "_internal", "sourcetypes": "1"}],
        m["alert_rules"].RUNS_SPL: [{"savedsearch_id": "nobody;search;Failed logins", "runs": "96", "skipped": "0",
                                     "last_run": NOW - 300, "last_status": "success", "last_user": "nobody"}],
        m["alert_rules"].FIRED_SPL: [{"ss_user": "nobody", "ss_app": "search", "ss_name": "Failed logins",
                                      "fired": "3", "last_fired": NOW - 900}],
        m["alert_delivery"].INTERNAL_EARLIEST_SPL: [{"earliest": NOW - 30 * 86400}],
        m["alert_delivery"].TRIGGERED_SPL: [{"savedsearch_id": "nobody;search;Failed logins", "sid": "sid1",
                                             "triggered_at": NOW - 900, "alert_actions": "email"}],
        m["alert_delivery"].EMAIL_SOURCE + m["alert_delivery"].EMAIL_PIPELINE: [
            {"delivery_sid": "sid1", "attempts": "1", "succeeded": "1", "last_attempt": NOW - 890,
             "last_success": NOW - 890, "mailserver": "smtp.example.com:587", "recipients": "'soc@example.com'"}],
        m["alert_delivery"].EMAIL_ERROR_SOURCE + m["alert_delivery"].EMAIL_ERROR_PIPELINE: [],
        m["alert_delivery"].MODALERT_SOURCE + m["alert_delivery"].MODALERT_PIPELINE: [],
    }


class FakeSplunk:
    """A requests.Session stand-in serving one consistent deployment; `fault` breaks it one way."""

    def __init__(self, fault=None):
        self.fault, self.headers, self.verify = fault, {}, True
        self.searches = _searches(MODS)
        stanzas = ["default", "volume:hot", *INDEXES]
        self.routes = {
            "services/server/info": {"entry": [{"content": {"version": "10.4.3", "host": "sh1",
                                                            "server_roles": ["indexer", "search_head"]}}]},
            "services/authentication/current-context": {"entry": [{"content": {
                "username": "collector", "capabilities": [] if fault == "nocaps" else CAPS}}]},
            "services/data/indexes": [_index(n, t) for n, t in INDEXES.items()],
            "services/properties/indexes": {"entry": [{"name": s} for s in stanzas]},
            "services/properties/indexes/default/defaultDatabase": "main",
            "services/authorization/roles": ROLES,
            "services/authentication/users": USERS,
            "servicesNS/-/-/saved/searches": SAVED,
            "servicesNS/-/-/configs/conf-savedsearches": [],
            "servicesNS/-/-/alerts/alert_actions": [EMAIL_ACTION],
            "servicesNS/-/-/alerts/fired_alerts/-": [
                _entry("-", {}), _entry("Failed logins_1", {"savedsearch_name": "Failed logins"},
                                        f"{BASE}/servicesNS/nobody/search/alerts/fired_alerts/Failed%20logins")],
            "servicesNS/-/-/configs/conf-alert_actions": [EMAIL_ACTION],
            "servicesNS/nobody/system/properties/alert_actions/email/auth_username": "svc-splunk",
            "servicesNS/nobody/system/properties/alert_actions/email/oauth_client_id": "",
            "servicesNS/nobody/search/properties/savedsearches/Failed%20logins": {
                "entry": [{"name": "action.email.use_tls", "content": "1"}]},
            "servicesNS/nobody/search/properties/alert_actions/email/use_ssl": "0",
            "services/properties/inputs": {"entry": [{"name": s} for s in (
                "default", "SSL", "monitor:///var/log/secure", "splunktcp://9997", "fschange:/etc")]},
            "servicesNS/-/-/data/inputs/all": INPUTS,
            "servicesNS/-/-/configs/conf-inputs": [_entry("fschange:/etc", {})],
            "services/properties/inputs/fschange%3A%2Fetc": {"entry": [{"name": "signedaudit", "content": "true"},
                                                                     {"name": "disabled", "content": "0"}]},
        }

    def request(self, method, url, timeout=None, params=None, data=None):
        path = url[len(BASE) + 1:]
        if method == "POST" and path == "services/search/jobs":
            if data["search"] not in self.searches:
                return _Resp(400, {"messages": [{"type": "ERROR", "text": f"unknown search {data['search']}"}]})
            messages = [{"type": "WARN", "text": "Search filters restricted results"}] if self.fault == "warn" else []
            return _Resp(200, {"results": self.searches[data["search"]], "messages": messages})
        if path not in self.routes:
            return _Resp(404, {"messages": [{"type": "ERROR", "text": f"no route {path}"}]})
        body = self.routes[path]
        if path == "services/data/indexes" and (params or {}).get("datatype") != "all":
            body = [e for e in body if e["content"]["datatype"] != "metric"]  # Splunk's default is datatype=event
        if path == "services/data/indexes" and self.fault == "badshape":
            body = [{"name": e["name"]} for e in body]  # entries with no content block
        if isinstance(body, list):
            entries = ALERTS if (params or {}).get("search") else body
            extra = 1 if self.fault == "short" else 0
            body = {"entry": entries, "paging": {"total": len(entries) + extra, "offset": 0, "perPage": 0}}
        return _Resp(200, body)


def _run(name, monkeypatch, tmp_path, fault=None, env=None):
    monkeypatch.setattr(sc.requests, "Session", lambda: FakeSplunk(fault))
    monkeypatch.setattr(sc.time, "sleep", lambda _s: None)
    monkeypatch.setattr(sc, "load_dotenv", lambda *a, **k: None)
    for key in list(sc.os.environ):
        if key.startswith("SPLUNK_"):
            monkeypatch.delenv(key)
    status = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))
    monkeypatch.setenv("SPLUNK_BASE_URL", BASE)
    monkeypatch.setenv("SPLUNK_TOKEN", "t0k3n")
    monkeypatch.setenv("SPLUNK_TARGET_NAME", "prod")
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    m = MODS[name]
    code = sc.run(m.NAME, m.collect, m.CAPABILITIES, getattr(m, "CONFIG", None))
    out = tmp_path / "evidence" / f"splunk_{name}_prod.json"
    evidence = json.loads(out.read_text()) if out.exists() else None
    return code, evidence, json.loads(status.read_text()) if status.exists() else None


@pytest.mark.parametrize("name", FETCHERS)
def test_a_complete_collection_exits_zero(name, monkeypatch, tmp_path):
    code, evidence, status = _run(name, monkeypatch, tmp_path)
    assert evidence["metadata"]["api_failures"] == []
    assert (code, status, evidence["metadata"]["partial_failure"]) == (0, None, False)
    assert evidence["metadata"]["tls_verified"] is True and evidence["summary"]


@pytest.mark.parametrize("fault", ["short", "warn", "nocaps"])
@pytest.mark.parametrize("name", FETCHERS)
def test_partial_data_fails_the_collection(name, fault, monkeypatch, tmp_path):
    code, evidence, status = _run(name, monkeypatch, tmp_path, fault)
    assert code == 1 and evidence["metadata"]["partial_failure"] is True
    assert status["code"] in STATUS_CODES and status["error"]
    if fault == "nocaps":
        assert status["code"] == "not_authorized" and "MissingCapability" in json.dumps(evidence["metadata"])


def test_an_unexpected_response_still_leaves_evidence_and_a_reason(monkeypatch, tmp_path):
    code, evidence, status = _run("index_retention", monkeypatch, tmp_path, "badshape")
    assert code == 1 and status["code"] == "internal_error"
    assert evidence["metadata"]["partial_failure"] is True and evidence["summary"] == {}


def test_a_config_value_that_is_not_a_number_is_bad_config(monkeypatch, tmp_path):
    code, evidence, status = _run("alert_rules", monkeypatch, tmp_path, env={"SPLUNK_ALERT_LOOKBACK_DAYS": "soon"})
    assert (code, evidence, status["code"]) == (1, None, "bad_config")


def test_role_index_access_verdicts(monkeypatch, tmp_path):
    _, evidence, _ = _run("role_index_access", monkeypatch, tmp_path)
    users = {u["name"]: u for u in evidence["users"]}
    assert users["collector"]["can_search_all_internal"] and users["collector"]["delete_by_keyword"]
    assert users["analyst"]["effective_indexes"] == ["main"] and users["analyst"]["dormant"] is True
    assert users["provisioned"]["never_logged_in"] is True and users["provisioned"]["dormant"] is False
    assert evidence["summary"]["users_dormant"] == ["analyst"]
    assert evidence["summary"]["users_never_logged_in"] == ["provisioned"]
    assert evidence["metadata"]["dormant_days"] == 90


def test_alert_rules_verdicts(monkeypatch, tmp_path):
    _, evidence, _ = _run("alert_rules", monkeypatch, tmp_path)
    alerts = {a["name"]: a for a in evidence["alerts"]}
    assert set(alerts) == {"Failed logins", "Tracked report", "Telemetry"}
    assert alerts["Failed logins"]["fired_in_window"] == 3 and alerts["Failed logins"]["email_recipients"] == ["soc@example.com"]
    assert alerts["Telemetry"]["has_notification_action"] is False
    assert [s["name"] for s in evidence["other_scheduled_searches"]] == ["Nightly report"]


def test_index_retention_verdicts(monkeypatch, tmp_path):
    _, evidence, _ = _run("index_retention", monkeypatch, tmp_path)
    summary = evidence["summary"]
    assert summary["data_integrity_control_enabled"] == ["_audit"]
    assert summary["shortest_retention_days"] == 90
    assert summary["indexes_archiving_on_freeze"] == ["_audit"]
    assert "_metrics" in {i["name"] for i in evidence["indexes"]}  # datatype=all reaches metric indexes
    assert set(evidence["indexes"][0]) == {"name", "datatype", "enabled", "internal", "data_integrity_control",
                                           "retention_days", "archives_on_freeze", "cold_to_frozen_dir",
                                           "max_total_size_mb", "app"}


def test_data_inputs_and_delivery_verdicts(monkeypatch, tmp_path):
    _, inputs, _ = _run("data_inputs", monkeypatch, tmp_path)
    rows = {r["stanza"]: r for r in inputs["inputs"]}
    assert rows["monitor:///var/log/secure"]["index_resolved"] == "main"
    assert rows["fschange:/etc"]["index_resolved"] == "_audit" and rows["fschange:/etc"]["listed_by_rest"] is False
    assert rows["splunktcp://9997"]["index_resolved"] is None
    _, delivery, _ = _run("alert_delivery", monkeypatch, tmp_path)
    row = delivery["deliveries"][0]
    assert (row["triggered"], row["succeeded"], row["last_outcome"]) == (1, 1, "succeeded")
    assert row["transport_encrypted"] is True and delivery["email_settings"][0]["auth_username_set"] is True
