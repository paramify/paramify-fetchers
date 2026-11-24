"""keycloak_admin_events, against real responses captured from Keycloak 26.8.2 (tests/fixtures/keycloak_admin_events).

The sandbox realm stored sign-in and admin events: two good sign-ins, two wrong passwords then a brute-force lockout
and three sign-ins it blocked, a user created then disabled, a password reset, role grants, and the collector's own
token requests. IDs are placeholders. No network.
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "keycloak_admin_events"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "keycloak" / "_shared"))
spec = importlib.util.spec_from_file_location("keycloak_admin_events_under_test",
                                              REPO_ROOT / "fetchers" / "keycloak" / "admin_events" / "fetcher.py")
ae = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ae)
client_mod = sys.modules["keycloak_client"]

BASE = "https://keycloak.admin.example.com"
NOW = datetime(2026, 11, 18, 1, 0, tzinfo=timezone.utc)
EVENTS = json.loads((FIXTURES / "events.json").read_text())
ADMIN_EVENTS = json.loads((FIXTURES / "admin-events.json").read_text())
CONFIG = json.loads((FIXTURES / "events-config.json").read_text())


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self):
        return self._body


class _Keycloak:
    """A client-credentials token, then the realm's event reads; GET only for the admin API."""

    def __init__(self, refused=(), events=None, admin_events=None):
        self.refused = set(refused)
        self.streams = {"/events": EVENTS if events is None else events, "/admin-events": ADMIN_EVENTS if admin_events is None else admin_events}
        self.gets = []

    def post(self, url, data=None, timeout=None):
        return _Resp(200, {"access_token": "tok", "expires_in": 300})

    def get(self, url, params=None, timeout=None, allow_redirects=True, headers=None):
        tail = urlparse(url).path[len("/admin/realms/example-realm"):]
        self.gets.append((tail, dict(params or {})))
        if tail in self.refused:
            return _Resp(403, {"error": "unknown_error"})
        if tail == "/events/config":
            return _Resp(200, CONFIG)
        stream = self.streams[tail]
        first, size = int((params or {}).get("first", 0)), int((params or {}).get("max", ae.PAGE))
        return _Resp(200, stream[first:first + size])


@pytest.fixture
def keycloak(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Keycloak(**kwargs)
        monkeypatch.setattr(client_mod.requests, "Session", lambda: session)
        return session

    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(ae, "datetime", type("FrozenDatetime", (datetime,), {"now": classmethod(lambda cls, tz=None: NOW)}))
    for name, value in (("EVIDENCE_DIR", str(tmp_path)), ("FETCHER_STATUS_FILE", str(tmp_path / "status.json")),
                        ("KEYCLOAK_BASE_URL", BASE), ("KEYCLOAK_REALM", "example-realm"),
                        ("KEYCLOAK_CLIENT_ID", "paramify-reader"), ("KEYCLOAK_CLIENT_SECRET", "client-secret-value")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(ae.LOOKBACK_ENV, raising=False)
    return serve


def _evidence(tmp_path):
    return json.loads((tmp_path / "keycloak_admin_events.json").read_text())


def test_real_events_give_sign_in_and_admin_counts(keycloak, tmp_path, assert_summary_documented):
    keycloak()
    assert ae.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["login_events_storage_enabled"], s["admin_events_storage_enabled"], s["admin_events_details_enabled"]) == (True, True, True)
    # Wrong passwords and sign-ins blocked by the lockout are counted apart.
    assert (s["logins_succeeded"], s["logins_failed"], s["logins_blocked"], s["lockouts"]) == (2, 2, 3, 1)
    assert (s["users_created"], s["users_disabled"], s["credential_resets"]) == (3, 1, 1)
    assert s["admin_events"] == len(ADMIN_EVENTS) and s["admin_privileged_changes"] > 0
    assert_summary_documented("keycloak/admin_events", s)


def test_recency_leaves_out_the_collectors_own_token_requests():
    s = ae.summarize(CONFIG, EVENTS, ADMIN_EVENTS, 7, NOW, own_client_id="paramify-reader")
    own = [e for e in EVENTS if e.get("clientId") == "paramify-reader"]
    newest_other = max(e["time"] for e in EVENTS if e.get("clientId") != "paramify-reader")
    assert s["collector_token_requests"] == len(own) > 0
    assert s["newest_login_event"] == ae._iso(newest_other)
    assert ae.summarize(CONFIG, own, [], 7, NOW, own_client_id="paramify-reader")["newest_login_event"] is None


def test_no_personal_data_or_changed_objects_reach_the_evidence(keycloak, tmp_path):
    keycloak()
    ae.main()
    text = (tmp_path / "keycloak_admin_events.json").read_text()
    raw = json.dumps(EVENTS + ADMIN_EVENTS)
    for field in ("ipAddress", "username", "userId", "representation", "token_id", "@example.com"):
        assert field in raw and field not in text, field


def test_events_are_read_page_by_page(keycloak, tmp_path, monkeypatch):
    monkeypatch.setattr(ae, "PAGE", 5)
    session = keycloak()
    assert ae.main() == 0
    firsts = [int(p["first"]) for t, p in session.gets if t == "/events"]
    assert firsts == list(range(0, len(EVENTS) + 1, 5))[: len(firsts)] and len(firsts) == len(EVENTS) // 5 + 1
    assert _evidence(tmp_path)["summary"]["login_events"] == len(EVENTS)


def test_a_window_over_the_cap_is_null_not_undercounted(keycloak, tmp_path, monkeypatch):
    monkeypatch.setattr(ae, "PAGE", 5)
    monkeypatch.setattr(ae, "MAX_EVENTS", 5)
    keycloak()
    assert ae.main() == 1
    ev = _evidence(tmp_path)
    assert (ev["summary"]["login_events"], ev["summary"]["logins_failed"]) == (None, None)
    assert any(f["type"] == "Too many events" for f in ev["metadata"]["api_failures"])


def test_an_unreadable_stream_leaves_only_its_own_fields_null(keycloak, tmp_path):
    keycloak(refused=("/events",))
    assert ae.main() == 1
    ev = _evidence(tmp_path)
    s = ev["summary"]
    assert (s["login_events"], s["lockouts"], s["newest_login_event"]) == (None, None, None)
    assert s["admin_events"] == len(ADMIN_EVENTS)
    assert "needs the role view-events of the realm-management client" in ev["metadata"]["api_failures"][0]["message"]


def test_a_user_counts_as_disabled_only_from_its_changed_object():
    def update(rep):
        return {"operationType": "UPDATE", "resourceType": "USER", "representation": rep}
    assert ae._disables_user(update('{"enabled": false, "username": "x"}')) is True
    assert ae._disables_user(update('{"enabled": true}')) is False
    assert ae._disables_user(update(None)) is None   # details off: unknown, never counted
    assert ae._disables_user(update("not json")) is None


def test_an_out_of_range_lookback_is_bad_config(keycloak, tmp_path, monkeypatch):
    monkeypatch.setenv(ae.LOOKBACK_ENV, "365")
    keycloak()
    assert ae.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


@pytest.mark.parametrize("saved, expected", [(["LOGIN", "LOGIN_ERROR"], True), (["LOGIN"], False), (None, None)])
def test_sign_in_storage_counts_only_when_both_types_are_saved(saved, expected):
    config = dict(CONFIG, enabledEventTypes=saved) if saved is not None else {k: v for k, v in CONFIG.items() if k != "enabledEventTypes"}
    assert ae.summarize(config, [], [], 7, NOW)["login_events_storage_enabled"] is expected


# --- review fixes ---

DAY_MS = 86_400_000
NOW_MS = int(NOW.timestamp() * 1000)
WINDOW_START_MS = NOW_MS - 7 * DAY_MS


class _ByDayKeycloak(_Keycloak):
    """Serves /events the way Keycloak does: dateFrom applied by whole day (UTC), newest first, first/max offsets.
    `between_pages` runs after each page, to change the store while the fetcher reads it. Stops a runaway loop."""

    def __init__(self, events, between_pages=None, **kwargs):
        super().__init__(events=events, admin_events=[], **kwargs)
        self.between_pages = between_pages

    def get(self, url, params=None, timeout=None, allow_redirects=True, headers=None):
        tail = urlparse(url).path[len("/admin/realms/example-realm"):]
        if tail != "/events":
            return super().get(url, params, timeout, allow_redirects, headers)
        self.gets.append((tail, dict(params or {})))
        assert len(self.gets) < 50, "the event read never ends"
        day = datetime.strptime(params["dateFrom"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        stored = sorted((e for e in self.streams[tail] if e["time"] >= day.timestamp() * 1000), key=lambda e: -e["time"])
        first, size = int(params["first"]), int(params["max"])
        page = stored[first:first + size]
        if self.between_pages:
            self.between_pages(self.streams[tail])
        return _Resp(200, page)


def _sign_in(i, time_ms, kind="LOGIN", client="web-app"):
    return {"id": f"evt-{i}", "time": time_ms, "type": kind, "clientId": client}


def test_a_busy_first_day_before_the_window_start_does_not_loop(keycloak, tmp_path, monkeypatch):
    # A full page and more of events on the window's first day, but before its start: Keycloak returns them, because
    # dateFrom is a day. The read must advance by what the server returned and stop once it is past the window start.
    monkeypatch.setattr(ae, "PAGE", 5)
    inside = [_sign_in(i, NOW_MS - 1000 * (i + 1)) for i in range(12)]
    before_start = [_sign_in(100 + i, WINDOW_START_MS - 1000 * (i + 1)) for i in range(6)]
    session = _ByDayKeycloak(inside + before_start)
    monkeypatch.setattr(client_mod.requests, "Session", lambda: session)
    assert ae.main() == 0
    assert _evidence(tmp_path)["summary"]["login_events"] == 12
    firsts = [int(p["first"]) for t, p in session.gets if t == "/events"]
    assert firsts == [0, 5, 10]  # the third page holds the last 2 in the window and the first 3 before it


def test_an_event_stored_while_paging_is_neither_counted_twice_nor_past_the_window_end(keycloak, tmp_path, monkeypatch):
    monkeypatch.setattr(ae, "PAGE", 2)
    stored = [_sign_in(i, NOW_MS - 1000 * (i + 1)) for i in range(3)]
    added = []

    def arrive(events):
        if not added:  # one new sign-in after the first page, newer than the window end
            added.append(_sign_in(99, NOW_MS + 5000))
            events.append(added[0])

    session = _ByDayKeycloak(stored, between_pages=arrive)
    monkeypatch.setattr(client_mod.requests, "Session", lambda: session)
    assert ae.main() == 0
    ev = _evidence(tmp_path)
    assert ev["summary"]["login_events"] == 3 and ev["summary"]["logins_succeeded"] == 3
    assert ev["results"]["window_end"] == "2026-11-18T01:00:00Z"
    assert ev["summary"]["newest_login_event"] == ae._iso(NOW_MS - 1000)


def _update_user(rep, resource="USER"):
    return {"operationType": "UPDATE", "resourceType": resource, "representation": rep, "time": NOW_MS - 1000}


def test_users_disabled_is_null_when_the_changed_object_is_not_kept():
    disabled = _update_user('{"enabled": false}')
    details_off = dict(CONFIG, adminEventsDetailsEnabled=False)
    assert ae.summarize(CONFIG, [], [disabled], 7, NOW)["users_disabled"] == 1
    assert ae.summarize(details_off, [], [_update_user(None)], 7, NOW)["users_disabled"] is None
    # Details on now, but an update stored while they were off has no changed object.
    assert ae.summarize(CONFIG, [], [disabled, _update_user(None)], 7, NOW)["users_disabled"] is None
    assert ae.summarize(CONFIG, [], [disabled, _update_user("not json")], 7, NOW)["users_disabled"] is None
    # An update to something else, without a changed object, doesn't hide a user change.
    assert ae.summarize(CONFIG, [], [disabled, _update_user(None, "CLIENT")], 7, NOW)["users_disabled"] == 1
    assert ae.admin_record(_update_user(None))["user_disabled"] is None


def test_newest_sign_in_counts_only_sign_in_events():
    # Storage on, but only token, logout and service-account events are saved: no user sign-in is stored.
    others = [_sign_in(1, NOW_MS - 2000, "CODE_TO_TOKEN"), _sign_in(2, NOW_MS - 1000, "LOGOUT"),
              _sign_in(3, NOW_MS - 500, "CLIENT_LOGIN", "other-service"), _sign_in(4, NOW_MS - 100, "CLIENT_LOGIN", "paramify-reader")]
    config = dict(CONFIG, enabledEventTypes=["CODE_TO_TOKEN", "REFRESH_TOKEN", "LOGOUT", "CLIENT_LOGIN"])
    s = ae.summarize(config, others, [], 7, NOW, own_client_id="paramify-reader")
    assert (s["newest_login_event"], s["hours_since_newest_login_event"]) == (None, None)
    failed = _sign_in(5, NOW_MS - 3000, "LOGIN_ERROR")
    assert ae.summarize(CONFIG, others + [failed], [], 7, NOW, own_client_id="paramify-reader")["newest_login_event"] == ae._iso(failed["time"])


@pytest.mark.parametrize("operation", ["CREATE", "DELETE"])
def test_a_client_scope_assignment_is_a_privileged_change(operation):
    event = {"operationType": operation, "resourceType": "CLIENT_SCOPE_CLIENT_MAPPING", "time": NOW_MS - 1000}
    assert ae.summarize(CONFIG, [], [event], 7, NOW)["admin_privileged_changes"] == 1
    assert ae.admin_record(event)["privileged"] is True


def test_the_access_text_names_the_client_for_an_account_in_master():
    text = (REPO_ROOT / "fetchers" / "keycloak" / "admin_events" / "fetcher.yaml").read_text()
    assert "<realm>-realm client in master" in text
