"""azure_flexible_server_backups: server projection, backup recency against the window, replica and restore handling, retention against the authorized period, null-not-zero summaries, and a full run against synthetic ARM responses. No SDK or network."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_flexible_server_backups_under_test", AZURE / "flexible_server_backups" / "fetcher.py")
db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(db)
azure_rest = sys.modules["azure_rest"]

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
SETTINGS = {"window_hours": 26, "required_retention_days": None, "restore_lookback_days": 365}
SUB = "/subscriptions/s1"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_server(name, engine="postgresql", role="Primary", source=None, retention=7, geo="Enabled", created=None, state="Ready"):
    ns = db.ENGINES[engine]["namespace"]
    props = {"state": state, "replicationRole": role,
             "backup": {"backupRetentionDays": retention, "geoRedundantBackup": geo, "earliestRestoreDate": "2026-11-10T00:00:00Z"}}
    if source:
        props["sourceServerResourceId"] = source
    return {"id": f"{SUB}/resourceGroups/rg1/providers/{ns}/flexibleServers/{name}", "name": name, "location": "eastus",
            "properties": props, "systemData": {"createdAt": created or "2026-01-01T00:00:00Z"}}


def backup(hours_ago, now=NOW):
    return {"name": f"b{hours_ago}", "properties": {"backupType": "FULL", "source": "Automatic", "completedTime": iso(now - timedelta(hours=hours_ago))}}


def test_server_record_reads_backup_settings_and_tells_replicas_from_restores():
    s = db.server_record("postgresql", raw_server("pg1"))
    assert (s["backup_retention_days"], s["geo_redundant_backup"], s["replica"], s["restored_from"]) == (7, True, False, None)
    rep = db.server_record("mysql", raw_server("r1", "mysql", role="Replica", source="/src"))
    assert (rep["replica"], rep["restored_from"]) == (True, None)
    restored = db.server_record("postgresql", raw_server("pitr", source="/src", role="None"))
    assert (restored["replica"], restored["restored_from"]) == (False, "/src")
    assert db.server_record("postgresql", raw_server("x", geo=None))["geo_redundant_backup"] is None


def test_newest_completed_backup_is_judged_against_the_window():
    s = db.server_record("postgresql", raw_server("pg1"))
    fresh = db.with_backups(s, [backup(30), backup(5)], SETTINGS, NOW)
    assert (fresh["latest_automatic_backup"], fresh["hours_since_latest_automatic_backup"], fresh["backup_within_window"]) == (iso(NOW - timedelta(hours=5)), 5.0, True)
    stale = db.with_backups(s, [backup(40)], SETTINGS, NOW)
    assert stale["backup_within_window"] is False
    assert db.with_backups(s, [], SETTINGS, NOW)["backup_within_window"] is False
    assert db.with_backups(s, None, SETTINGS, NOW)["backup_within_window"] is None


def _servers():
    a = db.with_backups(db.server_record("postgresql", raw_server("pg1", retention=35)), [backup(5)], SETTINGS, NOW)
    b = db.with_backups(db.server_record("mysql", raw_server("my1", "mysql", retention=7, geo="Disabled")), [backup(50)], SETTINGS, NOW)
    r = {**db.server_record("mysql", raw_server("r1", "mysql", role="Replica", source="/x")), "backups_read": False,
         "automatic_backups": None, "manual_backups": None, "unknown_type_backups": None, "unknown_backup_labels": None, "latest_automatic_backup": None, "latest_manual_backup": None,
         "hours_since_latest_automatic_backup": None, "backup_within_window": None, "manual_backup_within_window": None}
    p = db.with_backups(db.server_record("postgresql", raw_server("pitr", source="/src", role="None", created=iso(NOW - timedelta(days=20)))),
                        [backup(3)], SETTINGS, NOW)
    return [a, b, r, p]


def test_summary_judges_backup_servers_and_skips_replicas():
    s = db.summarize(_servers(), SETTINGS, NOW)
    assert (s["database_servers_postgresql"], s["database_servers_mysql"], s["replica_servers"], s["backup_servers"], s["backup_servers_read"]) == (2, 2, 1, 3, 3)
    assert (s["servers_with_automatic_backup_within_window"], s["servers_without_automatic_backup_within_window"], s["max_hours_since_automatic_backup"]) == (2, ["my1"], 50.0)
    assert (s["servers_geo_redundant_backup"], s["min_backup_retention_days"], s["max_backup_retention_days"]) == (2, 7, 35)
    assert (s["servers_retention_below_required"], s["restored_servers_within_lookback"]) == (None, 1)


def test_retention_is_counted_only_against_a_configured_authorized_period():
    s = db.summarize(_servers(), {**SETTINGS, "required_retention_days": 35}, NOW)
    assert (s["servers_retention_below_required"], s["required_retention_days"]) == (2, 35)


def test_longer_retention_meets_the_requirement_and_unknown_retention_is_counted_apart():
    longer = db.with_backups(db.server_record("postgresql", raw_server("long", retention=35)), [backup(5)], SETTINGS, NOW)
    short = db.with_backups(db.server_record("postgresql", raw_server("short", retention=7)), [backup(5)], SETTINGS, NOW)
    unknown = db.with_backups(db.server_record("mysql", raw_server("unk", "mysql", retention=None)), [backup(5)], SETTINGS, NOW)
    s = db.summarize([longer, short, unknown], {**SETTINGS, "required_retention_days": 14}, NOW)
    assert (s["servers_retention_below_required"], s["servers_retention_unknown"]) == (1, 1)


def test_a_stopped_server_is_counted_so_its_missing_backup_has_a_reason():
    stopped = db.with_backups(db.server_record("postgresql", raw_server("off", state="Stopped")), [backup(80)], SETTINGS, NOW)
    s = db.summarize([stopped], SETTINGS, NOW)
    assert (s["stopped_servers"], s["servers_without_automatic_backup_within_window"]) == (1, ["off"])


def test_one_api_version_serves_both_the_server_list_and_the_backups_list():
    types = [{"resourceType": "flexibleServers", "apiVersions": ["2022-12-01", "2023-06-01", "2024-08-01"]},
             {"resourceType": "flexibleServers/backups", "apiVersions": ["2022-12-01", "2023-06-01"]}]
    assert db.choose_api_version(db.shared_versions(types), "2024-08-01") == "2023-06-01"
    assert db.shared_versions(types[:1]) == ["2022-12-01", "2023-06-01", "2024-08-01"]  # backups type not listed


def test_an_unread_backup_list_or_server_list_leaves_verdicts_null():
    servers = _servers()
    servers[0] = db.with_backups(db.server_record("postgresql", raw_server("pg1")), None, SETTINGS, NOW)
    s = db.summarize(servers, SETTINGS, NOW)
    assert (s["backup_servers_read"], s["servers_with_automatic_backup_within_window"], s["max_hours_since_automatic_backup"]) == (2, None, None)
    unlisted = db.summarize([], SETTINGS, NOW, listed=False)
    assert (unlisted["backup_servers"], unlisted["servers_geo_redundant_backup"], unlisted["restored_servers_within_lookback"]) == (None, None, None)


def test_api_version_is_the_newest_stable_at_or_below_the_preferred():
    assert db.choose_api_version(["2022-12-01", "2024-08-01", "2025-01-01-preview", "2026-01-01"], "2024-08-01") == "2024-08-01"
    assert db.choose_api_version(["2021-05-01", "2023-06-01-preview"], "2023-12-30") == "2021-05-01"
    assert db.choose_api_version([], "2024-08-01") == "2024-08-01"


def test_summary_matches_the_instructions(assert_summary_documented):
    s = db.summarize(_servers(), SETTINGS, NOW)
    s.update({"postgresql_provider_registration_status": "registered", "mysql_provider_registration_status": "registered"})
    s.update(db.ResourceExclusions().summary([], ("database_server",), {"database_servers": 4}))
    assert_summary_documented("azure/flexible_server_backups", s)


# --- full run against synthetic ARM responses ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text, self.headers = status, body, "", json.dumps(body), {}

    def json(self):
        return self._body


class _Arm:
    def __init__(self, mysql_registered=True, refused_backups=()):
        self.mysql_registered, self.refused = mysql_registered, set(refused_backups)
        self.urls = []

    def get(self, url, params=None, headers=None, timeout=None, allow_redirects=True):
        path = urlparse(url).path
        query = {**{k: v[0] for k, v in parse_qs(urlparse(url).query).items()}, **(params or {})}
        self.urls.append((path, query.get("api-version")))
        now = datetime.now(timezone.utc)
        for engine, spec in db.ENGINES.items():
            ns = spec["namespace"]
            if path.endswith(f"/providers/{ns}"):
                registered = engine == "postgresql" or self.mysql_registered
                return _Resp(200, {"registrationState": "Registered" if registered else "NotRegistered",
                                   "resourceTypes": [{"resourceType": "flexibleServers", "apiVersions": ["2021-05-01", "2022-12-01", spec["preferred"]]},
                                                     {"resourceType": "flexibleServers/backups", "apiVersions": ["2021-05-01", "2022-12-01", spec["preferred"]]}]})
            if path.endswith(f"/providers/{ns}/flexibleServers"):
                return _Resp(200, {"value": [raw_server("pg1"), raw_server("pg-replica", role="AsyncReplica", source="/src")]} if engine == "postgresql"
                             else {"value": [raw_server("my1", "mysql", geo="Disabled")]})
        if path.endswith("/backups"):
            name = path.split("/")[-2]
            if name in self.refused:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": [backup(4, now), backup(28, now)]})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


@pytest.fixture
def arm(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Arm(**kwargs)
        monkeypatch.setattr("requests.Session", lambda: session)
        return session

    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: _Cred())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "s1")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for env in ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", "AZURE_RESOURCE_EXCLUSIONS", "AZURE_TARGET_SUBSCRIPTION_ONLY",
                db.WINDOW_ENV, db.RETENTION_ENV, db.LOOKBACK_ENV):
        monkeypatch.delenv(env, raising=False)
    return serve


def _evidence(tmp_path):
    [path] = tmp_path.glob("azure_flexible_server_backups_s1.json")
    return json.loads(path.read_text())


def test_main_reads_both_engines_and_skips_replica_backups(arm, tmp_path):
    session = arm()
    assert db.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["backup_servers"], s["replica_servers"], s["servers_with_automatic_backup_within_window"], s["servers_geo_redundant_backup"]) == (2, 1, 2, 1)
    assert (s["postgresql_provider_registration_status"], s["mysql_provider_registration_status"]) == ("registered", "registered")
    backup_calls = [p for p, _ in session.urls if p.endswith("/backups")]
    assert len(backup_calls) == 2 and not any("pg-replica" in p for p in backup_calls)
    assert {v for p, v in session.urls if "DBforPostgreSQL/flexibleServers" in p} == {"2024-08-01"}


def test_an_unreadable_backup_list_fails_the_run_and_leaves_verdicts_null(arm, tmp_path):
    arm(refused_backups=("my1",))
    assert db.main() != 0
    s = _evidence(tmp_path)["summary"]
    assert (s["backup_servers_read"], s["servers_with_automatic_backup_within_window"], s["max_hours_since_automatic_backup"]) == (1, None, None)


def test_an_unregistered_provider_has_no_servers_and_succeeds(arm, tmp_path):
    arm(mysql_registered=False)
    assert db.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["database_servers_mysql"], s["mysql_provider_registration_status"], s["backup_servers"]) == (0, "not_registered", 1)


def test_an_invalid_retention_setting_fails_the_run(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(db.RETENTION_ENV, "a week")
    arm()
    assert db.main() != 0
    assert _evidence(tmp_path)["summary"]["servers_retention_below_required"] is None


def test_restored_servers_are_counted_only_once_an_interval_is_adopted():
    unset = db.summarize(_servers(), {**SETTINGS, "restore_lookback_days": None}, NOW)
    assert (unset["restored_servers_within_lookback"], unset["restore_lookback_days"]) == (None, None)
    assert db.summarize(_servers(), {**SETTINGS, "restore_lookback_days": 10}, NOW)["restored_servers_within_lookback"] == 0


FIXTURES = REPO_ROOT / "tests" / "fixtures" / "flexible_server_backups"


def manual_backup(hours_ago, now=NOW):
    """A PostgreSQL on-demand backup, labelled as Microsoft's published example labels it."""
    return {"name": f"m{hours_ago}", "properties": {"backupType": "Customer On-Demand", "source": "Customer Initiated",
                                                   "completedTime": iso(now - timedelta(hours=hours_ago))}}


def _kinds(engine, fixture):
    return [db.backup_kind(engine, b) for b in json.loads((FIXTURES / fixture).read_text())["value"]]


def test_postgresql_backups_are_classified_from_microsofts_published_list():
    assert _kinds("postgresql", "postgresql-backups-2024-08-01.json") == [db.AUTOMATIC, db.MANUAL]


def test_mysql_automatic_backups_are_classified_from_microsofts_published_list():
    assert set(_kinds("mysql", "mysql-backups-2023-12-30.json")) == {db.AUTOMATIC}


def test_labels_are_matched_exactly_and_anything_else_is_unknown_never_automatic():
    def kind(engine, backup_type, source=None):
        return db.backup_kind(engine, {"properties": {"backupType": backup_type, "source": source}})
    assert kind("postgresql", "FULL", "automatic") == db.AUTOMATIC  # case does not matter
    assert kind("postgresql", "Full") == db.AUTOMATIC  # source absent on older API versions
    # The old substring rules would have read these as automatic or manual; now they are unknown.
    for engine, backup_type, source in (("postgresql", "Customer_On_Demand", None), ("postgresql", "Incremental", "Automatic"),
                                        ("mysql", "FULL", "On-Demand"), ("mysql", "FULL", None), ("mysql", None, "Automatic"),
                                        ("mysql", "FULL", "Customer Initiated")):
        assert kind(engine, backup_type, source) == db.UNKNOWN, (engine, backup_type, source)


def test_an_unrecognized_backup_cannot_stand_in_for_broken_automation():
    odd = {"name": "odd", "properties": {"backupType": "FULL", "source": "On-Demand", "completedTime": iso(NOW - timedelta(hours=1))}}
    s = db.with_backups(db.server_record("mysql", raw_server("my1", "mysql")), [backup(80), odd], SETTINGS, NOW)
    assert (s["automatic_backups"], s["unknown_type_backups"], s["unknown_backup_labels"], s["backup_within_window"]) == (1, 1, ["FULL / On-Demand"], False)
    summary = db.summarize([s], SETTINGS, NOW)
    assert (summary["servers_with_automatic_backup_within_window"], summary["servers_with_unknown_backup_types"]) == (0, 1)


def test_a_recent_manual_backup_does_not_hide_broken_automation():
    s = db.with_backups(db.server_record("postgresql", raw_server("pg1")), [backup(80), manual_backup(2)], SETTINGS, NOW)
    assert (s["automatic_backups"], s["manual_backups"], s["backup_within_window"], s["manual_backup_within_window"]) == (1, 1, False, True)
    summary = db.summarize([s], SETTINGS, NOW)
    assert (summary["servers_with_automatic_backup_within_window"], summary["servers_relying_on_manual_backup"], summary["servers_with_manual_backups"]) == (0, 1, 1)
    assert summary["max_hours_since_automatic_backup"] == 80.0


def test_a_restored_server_without_a_creation_date_is_unknown_not_recent():
    undated = db.server_record("postgresql", raw_server("pitr", source="/src", role="None"))
    undated["created"] = None
    s = db.summarize([db.with_backups(undated, [backup(3)], SETTINGS, NOW)], {**SETTINGS, "restore_lookback_days": 365}, NOW)
    assert (s["restored_servers_within_lookback"], s["restored_servers_date_unknown"]) == (0, 1)


def test_a_mysql_on_demand_backup_is_manual_although_labelled_automatic():
    # Microsoft's published MySQL on-demand example: FULL / Automatic, told apart only by its customer_ name.
    on_demand = json.loads((FIXTURES / "mysql-backup-on-demand-2023-12-30.json").read_text())
    assert (on_demand["properties"]["backupType"], on_demand["properties"]["source"]) == ("FULL", "Automatic")
    assert db.backup_kind("mysql", on_demand) == db.MANUAL
    assert set(_kinds("mysql", "mysql-backups-2023-12-30.json")) == {db.AUTOMATIC}


def test_a_recent_mysql_on_demand_backup_does_not_hide_stale_automatic_backups():
    automatic = json.loads((FIXTURES / "mysql-backups-2023-12-30.json").read_text())["value"]
    on_demand = json.loads((FIXTURES / "mysql-backup-on-demand-2023-12-30.json").read_text())
    now = max(db.parse_time(b["properties"]["completedTime"]) for b in automatic) + timedelta(days=5)
    recent = {**on_demand, "properties": {**on_demand["properties"], "completedTime": (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}}
    server = db.server_record("mysql", raw_server("my1", "mysql"))
    s = db.with_backups(server, automatic + [recent], SETTINGS, now)
    assert (s["backup_within_window"], s["manual_backup_within_window"], s["manual_backups"]) == (False, True, 1)


def test_a_live_mysql_backup_list_is_all_automatic_and_within_the_window():
    # A real Azure Government response (identifiers replaced): daily-<time>-<id> names, FULL / Automatic, no provisioningState.
    live = json.loads((FIXTURES / "mysql-backups-live-2024-12-30.json").read_text())["value"]
    assert all("provisioningState" not in b["properties"] for b in live)
    assert [db.backup_kind("mysql", b) for b in live] == [db.AUTOMATIC] * 7
    newest = max(db.parse_time(b["properties"]["completedTime"]) for b in live)
    s = db.with_backups(db.server_record("mysql", raw_server("my1", "mysql")), live, SETTINGS, newest + timedelta(hours=4))
    assert (s["automatic_backups"], s["manual_backups"], s["unknown_type_backups"], s["backup_within_window"]) == (7, 0, 0, True)


def test_an_on_demand_mysql_backup_named_with_a_hyphen_is_manual():
    on_demand = json.loads((FIXTURES / "mysql-backup-on-demand-2023-12-30.json").read_text())
    hyphen = {**on_demand, "name": on_demand["name"].replace("customer_", "customer-", 1)}
    assert hyphen["name"].startswith("customer-") and db.backup_kind("mysql", hyphen) == db.MANUAL
    assert db.backup_kind("mysql", {**on_demand, "name": "daily-20261117t212716-00000000"}) == db.AUTOMATIC
