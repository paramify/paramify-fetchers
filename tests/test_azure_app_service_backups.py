"""azure_app_service_backups, driven by a fake WebSiteManagementClient and Resource Graph.

Pins what the evidence must never say: an app with stale backups reported as backed up,
a backup configuration the identity could not read reported as "not configured", silent
exclusions, or a SAS token or connection string written out. No SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backups = _load("app_service_backups")

SUB = "00000000-0000-0000-0000-000000000001"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-web/providers/Microsoft.Web/sites"
STORAGE_ID = f"/subscriptions/{SUB}/resourceGroups/rg-st/providers/Microsoft.Storage/storageAccounts/stbackups"
SAS = "sv=2024-11-04&ss=b&srt=sco&sp=rwdlac&se=2027-01-01&sig=SECRETSIG%3D"
CONTAINER = "https://stbackups.blob.core.windows.net/webapp-backups"
NOW = datetime(2026, 10, 3, 8, 0, tzinfo=timezone.utc)
SETTINGS = {"restore_point_window_hours": 48, "recovery_point_objective_hours": None, "restore_test_window_days": 365}
DENIED = Exception(
    "(AuthorizationFailed) The client does not have authorization to perform action "
    "'Microsoft.Web/sites/config/list/action'"
)


class ResourceNotFoundError(Exception):
    pass


NOT_FOUND = ResourceNotFoundError("(NotFound) Backup configuration not found for site")


def ago(hours):
    return NOW - timedelta(hours=hours)


def snapshot_times(newest_hours_ago=0.5, count=60, skip=()):
    """Hourly automatic backups, newest first, with the 7-digit unzoned timestamps the API returns."""
    return [
        ns(time=ago(newest_hours_ago + i).strftime("%Y-%m-%dT%H:%M:%S.1234567"))
        for i in range(count)
        if i not in skip
    ]


def site(name, sku="Standard", kind="app,linux"):
    return ns(id=f"{RG}/{name}", name=name, kind=kind, location="eastus", state="Running", sku=sku,
              server_farm_id=f"/subscriptions/{SUB}/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/plan")


def database():
    return ns(database_type="SqlAzure", name="appdb", connection_string_name="Default",
              connection_string="Server=tcp:db;Password=hunter2")


def backup(backup_id, status, created, scheduled=True, log=None, restored=None):
    return ns(id=f"{RG}/web-std/backups/{backup_id}", backup_id=backup_id, properties=ns(name=f"nightly_{backup_id}"),
              name=f"web-std/{backup_id}", status=status, scheduled=scheduled, created=created,
              finished_time_stamp=created, last_restore_time_stamp=restored, size_in_bytes=1024,
              website_size_in_bytes=900, storage_account_url=f"{CONTAINER}?{SAS}",
              blob_name=f"web-std_{backup_id}.zip", log=log, databases=[database()])


def configuration(enabled=True, unit="Day", interval=1, retention=30, schedule=True):
    return ns(
        backup_name="nightly", enabled=enabled, storage_account_url=f"{CONTAINER}?{SAS}", databases=[database()],
        backup_schedule=ns(frequency_interval=interval, frequency_unit=unit, keep_at_least_one_backup=True,
                           retention_period_in_days=retention, start_time=ago(500), last_execution_time=ago(6))
        if schedule else None,
    )


def call(table, name):
    def fn(*args):
        if args not in table:
            raise AssertionError(f"unexpected call {name}{args}")
        value = table[args]
        if isinstance(value, Exception):
            raise value
        return value
    return fn


DEFAULT_HISTORY = [backup(1, "Succeeded", ago(54)), backup(2, "Failed", ago(6)), backup(3, "Succeeded", ago(30))]


def web_client(*, sites=None, snapshots=None, history=None, config=None, gets=None):
    sites = sites if sites is not None else [
        site("web-std"), site("web-basic", sku="Basic", kind="app"), site("web-free", sku="Free"),
        site("func", kind="functionapp,linux"),
    ]
    return ns(web_apps=ns(
        list=lambda: sites,
        get=call(gets or {}, "get"),
        list_snapshots=call({("rg-web", "web-std"): snapshot_times(), ("rg-web", "web-basic"): snapshot_times()}
                            | (snapshots or {}), "list_snapshots"),
        list_backups=call({("rg-web", "web-std"): DEFAULT_HISTORY, ("rg-web", "web-basic"): []}
                          | (history or {}), "list_backups"),
        get_backup_configuration=call({("rg-web", "web-std"): configuration(),
                                       ("rg-web", "web-basic"): NOT_FOUND} | (config or {}),
                                      "get_backup_configuration"),
    ))


def rows(*entries):
    return [{"id": f"{RG}/{name}", "name": name, "kind": kind, "type": kind_type}
            for name, kind, kind_type in entries]


SITE, SLOT = "microsoft.web/sites", "microsoft.web/sites/slots"
DEFAULT_GRAPH = rows(("web-std", "app,linux", SITE), ("web-basic", "app", SITE), ("web-free", "app,linux", SITE),
                     ("func", "functionapp,linux", SITE), ("func-rg-only", "functionapp", SITE),
                     ("web-std/slots/staging", "app,linux", SLOT), ("func/slots/stage", "functionapp", SLOT))
STORAGE_ROWS = [{"id": STORAGE_ID, "name": "stbackups", "location": "eastus", "replication": "Standard_RAGRS"}]


def run(monkeypatch, client, graph=DEFAULT_GRAPH, storage=STORAGE_ROWS, settings=SETTINGS):
    monkeypatch.setattr(backups, "web_client", lambda *a: client)
    monkeypatch.setattr(backups, "resource_graph_client", lambda cred: object())
    queries = []

    def query(_client, _sub, text):
        queries.append(text)
        found = storage if "storageaccounts" in text else graph
        if isinstance(found, Exception):
            raise found
        return {"rows": found, "total_records": len(found), "pages": 1}

    monkeypatch.setattr(backups, "query_all", query)
    collector = backups.Collector(logging.getLogger("test"))
    apps, inventory, exclusions, accounts = backups.collect(SUB, object(), collector, settings, NOW)
    summary = backups.summarize(apps, inventory, exclusions, accounts, settings)
    return ns(apps={a["name"]: a for a in apps}, inventory=inventory, exclusions=exclusions, storage=accounts,
              summary=summary, collector=collector, queries=queries)


def test_observed_restore_points_and_configured_intervals(monkeypatch):
    r = run(monkeypatch, web_client())
    assert r.collector.ok
    assert sorted(r.apps) == ["web-basic", "web-free", "web-std"]

    std = r.apps["web-std"]
    assert std["automatic_backups"]["count"] == 60
    assert std["automatic_backups"]["includes_linked_databases"] is False
    assert std["latest_restore_point"] == "2026-10-03T07:30:00Z"
    assert std["latest_restore_point_age_hours"] == 0.5
    assert std["restore_points_in_window"] == 49
    assert std["largest_restore_point_gap_hours"] == 1.0
    assert std["effective_backup_interval_hours"] == 1.0
    assert std["configured_backup_interval_hours"] == 1
    assert std["custom_backup_interval_hours"] == 24
    assert std["custom_backup_retention_days"] == 30
    assert std["custom_backup_configuration_status"] == "found"
    assert std["custom_backup_history"]["latest_status"] == "Failed"
    assert std["custom_backup_history"]["latest_succeeded"] == "2026-10-02T02:00:00Z"
    assert std["custom_backup_history"]["by_status"] == {"Failed": 1, "Succeeded": 2}
    assert [b["backup_id"] for b in std["custom_backup_history"]["recent"]] == [2, 3, 1]
    assert std["custom_backup_history"]["recent"][0]["name"] == "nightly_2"
    assert std["backed_up"] is True
    assert std["meets_recovery_point_objective"] is None

    basic = r.apps["web-basic"]
    assert basic["custom_backup_configuration_status"] == "not_configured"
    assert basic["custom_backup_configuration_found"] is False
    assert basic["custom_backup_configured"] is False
    assert basic["backed_up"] is True

    s = r.summary
    assert s["total_web_apps"] == 3
    assert s["apps_backed_up"] == 2
    assert s["apps_not_backed_up"] == 1
    assert s["all_web_apps_backed_up"] is False
    assert s["max_latest_restore_point_age_hours"] == 0.5
    assert s["longest_effective_backup_interval_hours"] == 1.0
    assert s["longest_configured_backup_interval_hours"] == 1
    assert s["apps_latest_custom_backup_failed"] == 1
    assert s["recovery_point_objective_hours"] is None
    assert s["all_web_apps_meet_recovery_point_objective"] is None


def test_stale_automatic_backups_are_not_backed_up(monkeypatch):
    stale = snapshot_times(newest_hours_ago=240)
    client = web_client(snapshots={("rg-web", "web-basic"): stale})
    settings = {**SETTINGS, "recovery_point_objective_hours": 24}
    r = run(monkeypatch, client, settings=settings)
    basic = r.apps["web-basic"]
    assert basic["has_automatic_backups"] is True
    assert basic["configured_backup_interval_hours"] == 1
    assert basic["latest_restore_point_age_hours"] == 240.0
    assert basic["restore_points_in_window"] == 0
    assert basic["effective_backup_interval_hours"] is None
    assert basic["backed_up"] is False
    assert basic["meets_recovery_point_objective"] is False
    assert r.summary["all_web_apps_backed_up"] is False
    assert r.summary["max_latest_restore_point_age_hours"] == 240.0
    assert r.summary["apps_missing_recovery_point_objective"] == 2


def test_largest_gap_inside_the_window_drives_the_effective_interval(monkeypatch):
    holey = snapshot_times(skip=range(10, 16))
    for rpo, meets in ((4, False), (8, True)):
        settings = {**SETTINGS, "recovery_point_objective_hours": rpo}
        r = run(monkeypatch, web_client(snapshots={("rg-web", "web-basic"): holey}), settings=settings)
        basic = r.apps["web-basic"]
        assert basic["largest_restore_point_gap_hours"] == 7.0
        assert basic["effective_backup_interval_hours"] == 7.0
        assert basic["meets_recovery_point_objective"] is meets
    assert r.summary["largest_restore_point_gap_hours"] == 7.0


def test_custom_backups_alone_back_an_app_up(monkeypatch):
    client = web_client(snapshots={("rg-web", "web-std"): []})
    r = run(monkeypatch, client)
    std = r.apps["web-std"]
    assert std["has_automatic_backups"] is False
    assert std["latest_restore_point_age_hours"] == 30.0
    assert std["largest_restore_point_gap_hours"] is None
    assert std["effective_backup_interval_hours"] is None
    assert std["backed_up"] is True
    assert std["configured_backup_interval_hours"] == 24


def test_free_tier_app_is_not_backed_up_and_gets_no_calls(monkeypatch):
    r = run(monkeypatch, web_client())
    free = r.apps["web-free"]
    assert r.collector.ok
    assert free["backups_supported"] is False
    assert free["custom_backup_configuration_status"] == "not_read"
    assert free["backed_up"] is False
    assert free["meets_recovery_point_objective"] is None
    assert r.summary["apps_on_tier_without_backups"] == 1


def test_reader_403_on_configuration_is_unknown_not_a_failure(monkeypatch):
    r = run(monkeypatch, web_client(config={("rg-web", "web-std"): DENIED}))
    std = r.apps["web-std"]
    assert r.collector.ok
    assert std["custom_backup_configuration_status"] == "not_authorized"
    assert std["custom_backup_configuration_found"] is None
    assert std["custom_backup_configuration"] is None
    assert std["custom_backup_configured"] is None
    assert std["scheduled_custom_backup_enabled"] is None
    assert std["custom_backup_retention_days"] is None
    assert std["configured_backup_interval_hours"] == 1
    assert std["backed_up"] is True
    assert std["custom_backup_history"]["count"] == 3
    assert r.summary["apps_custom_backup_configuration_not_authorized"] == 1
    assert r.summary["apps_custom_backup_configuration_unknown"] == 1


def test_other_configuration_errors_still_fail_the_run(monkeypatch):
    broken = Exception("(InternalServerError) Something went wrong")
    r = run(monkeypatch, web_client(config={("rg-web", "web-std"): broken}))
    assert not r.collector.ok
    assert r.apps["web-std"]["custom_backup_configuration_status"] == "error"
    assert r.apps["web-std"]["custom_backup_configured"] is None


def test_backed_up_is_unknown_when_a_read_failed_and_nothing_fresh_was_seen(monkeypatch):
    client = web_client(snapshots={("rg-web", "web-basic"): DENIED, ("rg-web", "web-std"): DENIED})
    r = run(monkeypatch, client)
    assert r.apps["web-basic"]["automatic_backups"] is None
    assert r.apps["web-basic"]["backed_up"] is None
    assert r.apps["web-std"]["backed_up"] is True
    assert r.summary["apps_backed_up_unknown"] == 1
    assert r.summary["all_web_apps_backed_up"] is False


def test_exclusions_list_function_apps_and_slots_with_reasons(monkeypatch):
    r = run(monkeypatch, web_client())
    functions, slots = r.exclusions["function_apps"], r.exclusions["deployment_slots"]
    assert functions["count"] == 2
    assert [f["name"] for f in functions["resources"]] == ["func", "func-rg-only"]
    assert "function app" in functions["reason"]
    assert slots["count"] == 2
    assert [s["name"] for s in slots["resources"]] == ["func/slots/stage", "web-std/slots/staging"]
    assert "production" in slots["reason"]
    assert r.summary["excluded_function_apps"] == 2
    assert r.summary["excluded_deployment_slots"] == 2


def test_failed_resource_graph_query_leaves_slots_unknown(monkeypatch):
    r = run(monkeypatch, web_client(), graph=RuntimeError("Resource Graph reported 7 rows but paging returned 6"))
    assert not r.collector.ok
    assert r.inventory is None
    assert sorted(r.apps) == ["web-basic", "web-free", "web-std"]
    assert r.exclusions["deployment_slots"]["count"] is None
    assert r.exclusions["function_apps"]["count"] == 1
    assert r.summary["resource_graph_web_apps"] is None


def test_custom_backup_storage_account_is_resolved(monkeypatch):
    r = run(monkeypatch, web_client())
    assert r.apps["web-std"]["custom_backup_storage_accounts"] == ["stbackups"]
    assert r.storage == [{
        "name": "stbackups", "apps": ["web-std"], "resolved": True, "id": STORAGE_ID, "location": "eastus",
        "replication": "Standard_RAGRS", "geo_redundant": True, "immutable_storage_with_versioning": False,
    }]
    assert any("'stbackups'" in q for q in r.queries)
    assert r.summary["custom_backup_storage_accounts_geo_redundant"] == 1


@pytest.mark.parametrize("storage,resolved,geo,ok", [
    ([], False, None, True),
    (RuntimeError("Resource Graph throttled"), None, None, False),
    ([{"id": STORAGE_ID, "name": "stbackups", "replication": "Standard_LRS", "versionImmutability": True}],
     True, False, True),
])
def test_storage_account_outside_subscription_or_unreadable(monkeypatch, storage, resolved, geo, ok):
    r = run(monkeypatch, web_client(), storage=storage)
    assert r.storage[0]["resolved"] is resolved
    assert r.storage[0]["geo_redundant"] is geo
    assert r.collector.ok is ok


def test_restore_from_a_custom_backup_inside_the_window(monkeypatch):
    for days, expected in ((100, True), (400, False)):
        history = [backup(1, "Succeeded", ago(30), restored=ago(24 * days))]
        r = run(monkeypatch, web_client(history={("rg-web", "web-std"): history}))
        assert r.apps["web-std"]["custom_backup_history"]["latest_restore"] == backups.iso(ago(24 * days))
        assert r.apps["web-std"]["custom_backup_restored_in_window"] is expected
    assert r.apps["web-basic"]["custom_backup_restored_in_window"] is False
    assert r.summary["apps_with_custom_backup_restore_in_window"] == 0


def test_no_sas_token_or_connection_string_in_the_evidence(monkeypatch):
    log = f"Storage access failed for {CONTAINER}/web-std_2.zip?{SAS}."
    client = web_client(history={("rg-web", "web-std"): [backup(2, "Failed", ago(6), log=log)]})
    r = run(monkeypatch, client)
    text = json.dumps(r.apps, default=str)
    assert "SECRETSIG" not in text and "sig=" not in text
    assert "hunter2" not in text and "connection_string\"" not in text
    std = r.apps["web-std"]
    assert std["custom_backup_configuration"]["storage_url"] == CONTAINER
    assert std["custom_backup_configuration"]["storage_container"] == "webapp-backups"
    assert std["custom_backup_configuration"]["databases"] == [
        {"database_type": "SqlAzure", "name": "appdb", "connection_string_name": "Default"}]
    assert std["custom_backup_history"]["recent"][0]["log"] == f"Storage access failed for {CONTAINER}/web-std_2.zip"
    assert std["custom_backup_history"]["latest_succeeded"] is None


@pytest.mark.parametrize("unit,interval,retention,hours,indefinite", [
    ("Hour", 2, 0, 2, True),
    ("Day", 7, 14, 168, False),
])
def test_schedule_interval_and_retention(monkeypatch, unit, interval, retention, hours, indefinite):
    client = web_client(config={("rg-web", "web-std"): configuration(unit=unit, interval=interval, retention=retention)},
                        snapshots={("rg-web", "web-std"): []})
    std = run(monkeypatch, client).apps["web-std"]
    assert std["custom_backup_interval_hours"] == hours
    assert std["configured_backup_interval_hours"] == hours
    assert std["custom_backup_retention_indefinite"] is indefinite


@pytest.mark.parametrize("config", [configuration(enabled=False), configuration(schedule=False)])
def test_configured_storage_without_an_enabled_schedule_is_not_scheduled(monkeypatch, config):
    std = run(monkeypatch, web_client(config={("rg-web", "web-std"): config})).apps["web-std"]
    assert std["custom_backup_configured"] is True
    assert std["scheduled_custom_backup_enabled"] is False
    assert std["custom_backup_interval_hours"] is None


def test_resource_graph_finds_an_app_the_list_missed(monkeypatch):
    graph = DEFAULT_GRAPH + rows(("web-missed", "app", SITE), ("web-deleted", "app", SITE))
    client = web_client(
        gets={("rg-web", "web-missed"): site("web-missed"),
              ("rg-web", "web-deleted"): ResourceNotFoundError("(ResourceNotFound) site not found")},
        snapshots={("rg-web", "web-missed"): snapshot_times()}, history={("rg-web", "web-missed"): []},
        config={("rg-web", "web-missed"): NOT_FOUND},
    )
    r = run(monkeypatch, client, graph)
    assert r.collector.ok
    assert r.apps["web-missed"]["backed_up"] is True
    assert r.inventory["added_from_resource_graph"] == [f"{RG}/web-missed"]
    assert r.inventory["resource_graph_stale"] == [f"{RG}/web-deleted"]
    assert r.inventory["resource_graph_web_apps"] == 5
    assert r.summary["web_apps_added_from_resource_graph"] == 1


def test_app_missing_from_resource_graph_is_reported_not_dropped(monkeypatch):
    r = run(monkeypatch, web_client(), rows(("WEB-STD", "app,linux", SITE)))
    assert sorted(r.apps) == ["web-basic", "web-free", "web-std"]
    assert r.inventory["not_in_resource_graph"] == [f"{RG}/web-basic", f"{RG}/web-free"]


def test_resource_graph_query_does_not_assign_to_kind():
    assert "kind =" not in backups.SITES_QUERY.replace("kind ==", "")


@pytest.mark.parametrize("values,expected", [
    ([True, True], True),
    ([True, None], None),
    ([False, None], False),
    ([], None),
])
def test_all_true_is_three_valued(values, expected):
    assert backups.all_true(values) is expected


def test_settings_defaults_and_overrides(monkeypatch, caplog):
    for env in (backups.WINDOW_ENV, backups.RPO_ENV, backups.RESTORE_WINDOW_ENV):
        monkeypatch.delenv(env, raising=False)
    assert backups.read_settings() == SETTINGS
    monkeypatch.setenv(backups.WINDOW_ENV, "96")
    monkeypatch.setenv(backups.RPO_ENV, "4")
    with caplog.at_level(logging.WARNING):
        settings = backups.read_settings()
    assert settings["restore_point_window_hours"] == 96
    assert settings["recovery_point_objective_hours"] == 4
    assert "thinned" in caplog.text


def test_main_under_reader_exits_zero_and_explains_the_unknown(monkeypatch, tmp_path):
    client = web_client(config={("rg-web", "web-std"): DENIED})
    monkeypatch.setattr(backups, "web_client", lambda *a: client)
    monkeypatch.setattr(backups, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(backups, "query_all", lambda _c, _s, text: {
        "rows": STORAGE_ROWS if "storageaccounts" in text else DEFAULT_GRAPH, "total_records": 0, "pages": 1})
    monkeypatch.setattr(backups, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(backups, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(backups, "utc_now", lambda: NOW)
    status = tmp_path / "status.json"
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))
    monkeypatch.setenv(backups.RPO_ENV, "24")

    assert backups.main() == 0
    evidence = json.loads((tmp_path / f"azure_app_service_backups_{SUB}.json").read_text())
    assert evidence["metadata"]["partial_failure"] is False
    results, summary = evidence["results"], evidence["summary"]
    assert results["evaluated_at"] == "2026-10-03T08:00:00Z"
    assert results["settings"]["recovery_point_objective_hours"] == 24
    assert results["custom_backup_configuration_access"]["apps_not_authorized"] == 1
    assert "config/list/action" in results["custom_backup_configuration_access"]["note"]
    assert any("opt-in" in line for line in results["limitations"])
    assert summary["apps_custom_backup_configuration_not_authorized"] == 1
    assert summary["apps_meeting_recovery_point_objective"] == 2
    assert not status.exists()


def test_sdk_models_project_the_backup_name_and_unwrap_enums():
    models = pytest.importorskip("azure.mgmt.web.models")
    item = models.BackupItem({
        "id": f"{RG}/web-std/backups/7", "name": "web-std/7",
        "properties": {"id": 7, "name": "nightly_7", "status": "Succeeded", "scheduled": True,
                       "created": "2026-10-03T01:02:03.4567891Z", "lastRestoreTimeStamp": "2026-09-01T00:00:00Z",
                       "storageAccountUrl": f"{CONTAINER}?{SAS}"},
    })
    record = backups.project_backup_item(item)
    assert record["name"] == "nightly_7"
    assert record["backup_id"] == 7
    assert record["status"] == "Succeeded"
    assert record["created"] == "2026-10-03T01:02:03Z"
    assert record["last_restored"] == "2026-09-01T00:00:00Z"
    assert record["storage_url"] == CONTAINER

    request = models.BackupRequest({"properties": {
        "enabled": True, "storageAccountUrl": f"{CONTAINER}?{SAS}",
        "backupSchedule": {"frequencyInterval": 12, "frequencyUnit": "Hour", "keepAtLeastOneBackup": True,
                           "retentionPeriodInDays": 0},
        "databases": [{"databaseType": "SqlAzure", "name": "db", "connectionString": "Password=hunter2"}],
    }})
    config = backups.project_backup_configuration(request)
    assert config["schedule"]["frequency_unit"] == "Hour"
    assert backups.interval_hours(config["schedule"]) == 12
    assert config["databases"][0]["database_type"] == "SqlAzure"
    assert "hunter2" not in json.dumps(config)
