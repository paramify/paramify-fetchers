"""azure_app_service_backups, driven by a fake WebSiteManagementClient and Resource Graph.

Pins what the evidence must never say: a backup configuration the identity could not
read reported as "not configured", or a SAS token or connection string written out.
No SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
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
SAS = "sv=2024-11-04&ss=b&srt=sco&sp=rwdlac&se=2027-01-01&sig=SECRETSIG%3D"
CONTAINER = "https://stbackups.blob.core.windows.net/webapp-backups"
DENIED = Exception(
    "(AuthorizationFailed) The client does not have authorization to perform action "
    "'Microsoft.Web/sites/config/list/action'"
)


class ResourceNotFoundError(Exception):
    pass


NOT_FOUND = ResourceNotFoundError("(NotFound) Backup configuration not found for site")


def at(day, hour=0):
    return datetime(2026, 10, day, hour, tzinfo=timezone.utc)


def site(name, sku="Standard", kind="app,linux"):
    return ns(id=f"{RG}/{name}", name=name, kind=kind, location="eastus", state="Running", sku=sku,
              server_farm_id=f"/subscriptions/{SUB}/resourceGroups/rg-web/providers/Microsoft.Web/serverfarms/plan")


def database():
    return ns(database_type="SqlAzure", name="appdb", connection_string_name="Default",
              connection_string="Server=tcp:db;Password=hunter2")


def backup(backup_id, status, created, scheduled=True, log=None):
    return ns(id=f"{RG}/web-std/backups/{backup_id}", backup_id=backup_id, properties=ns(name=f"nightly_{backup_id}"),
              name=f"web-std/{backup_id}", status=status, scheduled=scheduled, created=created,
              finished_time_stamp=created, last_restore_time_stamp=None, size_in_bytes=1024,
              website_size_in_bytes=900, storage_account_url=f"{CONTAINER}?{SAS}",
              blob_name=f"web-std_{backup_id}.zip", log=log, databases=[database()])


def configuration(enabled=True, unit="Day", interval=1, retention=30, schedule=True):
    return ns(
        backup_name="nightly", enabled=enabled, storage_account_url=f"{CONTAINER}?{SAS}", databases=[database()],
        backup_schedule=ns(frequency_interval=interval, frequency_unit=unit, keep_at_least_one_backup=True,
                           retention_period_in_days=retention, start_time=at(1), last_execution_time=at(13))
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


SNAPSHOTS = [ns(time="2026-09-13T23:01:00.9388571"), ns(time="2026-10-13T20:14:12.2391630")]


def web_client(*, sites=None, snapshots=None, history=None, config=None, gets=None):
    sites = sites if sites is not None else [
        site("web-std"), site("web-basic", sku="Basic", kind="app"), site("web-free", sku="Free"),
        site("func", kind="functionapp,linux"),
    ]
    return ns(web_apps=ns(
        list=lambda: sites,
        get=call(gets or {}, "get"),
        list_snapshots=call({("rg-web", "web-std"): SNAPSHOTS, ("rg-web", "web-basic"): SNAPSHOTS} | (snapshots or {}),
                            "list_snapshots"),
        list_backups=call({
            ("rg-web", "web-std"): [backup(1, "Succeeded", at(11)), backup(2, "Failed", at(12)),
                                    backup(3, "Succeeded", at(13))],
            ("rg-web", "web-basic"): [],
        } | (history or {}), "list_backups"),
        get_backup_configuration=call({("rg-web", "web-std"): configuration(),
                                       ("rg-web", "web-basic"): NOT_FOUND} | (config or {}),
                                      "get_backup_configuration"),
    ))


def graph_rows(*names_and_kinds):
    return [{"id": f"{RG}/{name}", "name": name, "kind": kind} for name, kind in names_and_kinds]


DEFAULT_GRAPH = graph_rows(("web-std", "app,linux"), ("web-basic", "app"), ("web-free", "app,linux"),
                           ("func", "functionapp,linux"))


def run(monkeypatch, client, rows=DEFAULT_GRAPH):
    monkeypatch.setattr(backups, "web_client", lambda *a: client)
    monkeypatch.setattr(backups, "resource_graph_client", lambda cred: object())

    def query(_client, _sub, _query):
        if isinstance(rows, Exception):
            raise rows
        return {"rows": rows, "total_records": len(rows), "pages": 1}

    monkeypatch.setattr(backups, "query_all", query)
    collector = backups.Collector(logging.getLogger("test"))
    apps, inventory = backups.collect(SUB, object(), collector)
    return {a["name"]: a for a in apps}, inventory, backups.summarize(apps, inventory), collector


def test_backed_up_apps_and_their_intervals(monkeypatch):
    apps, inventory, summary, collector = run(monkeypatch, web_client())
    assert collector.ok
    assert sorted(apps) == ["web-basic", "web-free", "web-std"]

    std = apps["web-std"]
    assert std["automatic_backups"] == {"count": 2, "latest": "2026-10-13T20:14:12Z", "oldest": "2026-09-13T23:01:00Z",
                                        "interval_hours": 1, "retention_days": 30}
    assert std["custom_backup_configured"] is True
    assert std["scheduled_custom_backup_enabled"] is True
    assert std["custom_backup_interval_hours"] == 24
    assert std["custom_backup_retention_days"] == 30
    assert std["custom_backup_retention_indefinite"] is False
    assert std["custom_backup_history"]["latest_status"] == "Succeeded"
    assert std["custom_backup_history"]["latest_succeeded"] == "2026-10-13T00:00:00Z"
    assert std["custom_backup_history"]["by_status"] == {"Failed": 1, "Succeeded": 2}
    assert [b["backup_id"] for b in std["custom_backup_history"]["recent"]] == [3, 2, 1]
    assert std["custom_backup_history"]["recent"][0]["name"] == "nightly_3"
    assert std["backed_up"] is True
    assert std["effective_backup_interval_hours"] == 1
    assert std["latest_restore_point"] == "2026-10-13T20:14:12Z"

    basic = apps["web-basic"]
    assert basic["custom_backup_configuration_found"] is False
    assert basic["custom_backup_configured"] is False
    assert basic["scheduled_custom_backup_enabled"] is False
    assert basic["backed_up"] is True

    assert summary["total_web_apps"] == 3
    assert summary["apps_with_automatic_backups"] == 2
    assert summary["apps_with_scheduled_custom_backup"] == 1
    assert summary["apps_backed_up"] == 2
    assert summary["apps_not_backed_up"] == 1
    assert summary["all_web_apps_backed_up"] is False
    assert summary["longest_effective_backup_interval_hours"] == 1
    assert inventory["added_from_resource_graph"] == []


def test_free_tier_app_is_not_backed_up_and_gets_no_calls(monkeypatch):
    apps, _, summary, collector = run(monkeypatch, web_client())
    free = apps["web-free"]
    assert collector.ok
    assert free["backups_supported"] is False
    assert free["has_automatic_backups"] is False
    assert free["custom_backup_configured"] is False
    assert free["backed_up"] is False
    assert free["automatic_backups"] is None
    assert summary["apps_on_tier_without_backups"] == 1


def test_unreadable_backup_configuration_is_null_not_false(monkeypatch):
    client = web_client(config={("rg-web", "web-std"): DENIED})
    apps, _, summary, collector = run(monkeypatch, client)
    std = apps["web-std"]
    assert not collector.ok
    assert backups.classify_failure_code(collector.failures) == "not_authorized"
    assert "config/list/action" in collector.failures[0]["message"]
    assert std["custom_backup_configuration_found"] is None
    assert std["custom_backup_configuration"] is None
    assert std["custom_backup_configured"] is None
    assert std["scheduled_custom_backup_enabled"] is None
    assert std["custom_backup_retention_days"] is None
    assert std["backed_up"] is True
    assert std["custom_backup_history"]["count"] == 3
    assert summary["apps_custom_backup_configuration_unknown"] == 1
    assert summary["apps_with_custom_backup_configured"] == 0


def test_backed_up_is_unknown_when_nothing_proves_it(monkeypatch):
    client = web_client(config={("rg-web", "web-basic"): DENIED}, snapshots={("rg-web", "web-basic"): DENIED})
    apps, _, summary, _ = run(monkeypatch, client)
    basic = apps["web-basic"]
    assert basic["has_automatic_backups"] is None
    assert basic["automatic_backups"] is None
    assert basic["backed_up"] is None
    assert summary["apps_backed_up_unknown"] == 1
    assert summary["all_web_apps_backed_up"] is False


def test_no_sas_token_or_connection_string_in_the_evidence(monkeypatch):
    log = f"Storage access failed for {CONTAINER}/web-std_2.zip?{SAS}."
    client = web_client(history={("rg-web", "web-std"): [backup(2, "Failed", at(12), log=log)]})
    apps, _, summary, _ = run(monkeypatch, client)
    text = json.dumps(apps, default=str)
    assert "SECRETSIG" not in text and "sig=" not in text
    assert "hunter2" not in text and "connection_string\"" not in text
    std = apps["web-std"]
    assert std["custom_backup_configuration"]["storage_url"] == CONTAINER
    assert std["custom_backup_configuration"]["storage_account"] == "stbackups"
    assert std["custom_backup_configuration"]["storage_container"] == "webapp-backups"
    assert std["custom_backup_configuration"]["databases"] == [
        {"database_type": "SqlAzure", "name": "appdb", "connection_string_name": "Default"}]
    assert std["custom_backup_history"]["recent"][0]["log"] == f"Storage access failed for {CONTAINER}/web-std_2.zip"
    assert std["custom_backup_history"]["latest_succeeded"] is None
    assert summary["apps_latest_custom_backup_failed"] == 1


@pytest.mark.parametrize("unit,interval,retention,hours,indefinite", [
    ("Hour", 2, 0, 2, True),
    ("Day", 7, 14, 168, False),
])
def test_schedule_interval_and_retention(monkeypatch, unit, interval, retention, hours, indefinite):
    client = web_client(config={("rg-web", "web-std"): configuration(unit=unit, interval=interval, retention=retention)},
                        snapshots={("rg-web", "web-std"): []})
    apps, _, _, _ = run(monkeypatch, client)
    std = apps["web-std"]
    assert std["has_automatic_backups"] is False
    assert std["custom_backup_interval_hours"] == hours
    assert std["custom_backup_retention_indefinite"] is indefinite
    assert std["effective_backup_interval_hours"] == hours


@pytest.mark.parametrize("config", [configuration(enabled=False), configuration(schedule=False)])
def test_configured_storage_without_an_enabled_schedule_is_not_scheduled(monkeypatch, config):
    apps, _, _, _ = run(monkeypatch, web_client(config={("rg-web", "web-std"): config}))
    std = apps["web-std"]
    assert std["custom_backup_configured"] is True
    assert std["scheduled_custom_backup_enabled"] is False
    assert std["custom_backup_interval_hours"] is None
    assert std["custom_backup_retention_days"] is None


def test_resource_graph_finds_an_app_the_list_missed(monkeypatch):
    rows = DEFAULT_GRAPH + graph_rows(("web-missed", "app"), ("web-deleted", "app"), ("func-2", "functionapp"))
    client = web_client(
        gets={("rg-web", "web-missed"): site("web-missed"),
              ("rg-web", "web-deleted"): ResourceNotFoundError("(ResourceNotFound) site not found")},
        snapshots={("rg-web", "web-missed"): SNAPSHOTS}, history={("rg-web", "web-missed"): []},
        config={("rg-web", "web-missed"): NOT_FOUND},
    )
    apps, inventory, summary, collector = run(monkeypatch, client, rows)
    assert collector.ok
    assert "web-missed" in apps and apps["web-missed"]["backed_up"] is True
    assert inventory["added_from_resource_graph"] == [f"{RG}/web-missed"]
    assert inventory["resource_graph_stale"] == [f"{RG}/web-deleted"]
    assert inventory["resource_graph_web_apps"] == 5
    assert inventory["listed_web_apps"] == 3
    assert summary["web_apps_added_from_resource_graph"] == 1


def test_app_missing_from_resource_graph_is_reported_not_dropped(monkeypatch):
    apps, inventory, _, collector = run(monkeypatch, web_client(), graph_rows(("WEB-STD", "app,linux")))
    assert collector.ok
    assert sorted(apps) == ["web-basic", "web-free", "web-std"]
    assert inventory["not_in_resource_graph"] == [f"{RG}/web-basic", f"{RG}/web-free"]


def test_failed_resource_graph_query_still_collects_the_listed_apps(monkeypatch):
    apps, inventory, summary, collector = run(monkeypatch, web_client(), RuntimeError("Resource Graph reported 4 rows but paging returned 3"))
    assert not collector.ok
    assert inventory is None
    assert sorted(apps) == ["web-basic", "web-free", "web-std"]
    assert summary["resource_graph_web_apps"] is None


def test_resource_graph_query_does_not_assign_to_kind():
    assert "kind =" not in backups.WEB_SITES_QUERY.replace("kind ==", "")


@pytest.mark.parametrize("values,expected", [
    ([True, True], True),
    ([True, None], None),
    ([False, None], False),
    ([], None),
])
def test_all_web_apps_backed_up_is_three_valued(values, expected):
    assert backups.all_true(values) is expected


def test_main_writes_evidence_and_exits_non_zero_when_configuration_is_denied(monkeypatch, tmp_path):
    client = web_client(config={("rg-web", "web-std"): DENIED})
    monkeypatch.setattr(backups, "web_client", lambda *a: client)
    monkeypatch.setattr(backups, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(backups, "query_all", lambda *a: {"rows": DEFAULT_GRAPH, "total_records": 4, "pages": 1})
    monkeypatch.setattr(backups, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(backups, "provider_registration_status", lambda *a: "registered")
    status = tmp_path / "status.json"
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))

    assert backups.main() == 1
    evidence = json.loads((tmp_path / f"azure_app_service_backups_{SUB}.json").read_text())
    assert evidence["metadata"]["partial_failure"] is True
    assert evidence["summary"]["apps_custom_backup_configuration_unknown"] == 1
    assert json.loads(status.read_text())["code"] == "not_authorized"


def test_sdk_models_project_the_backup_name_and_unwrap_enums():
    models = pytest.importorskip("azure.mgmt.web.models")
    item = models.BackupItem({
        "id": f"{RG}/web-std/backups/7", "name": "web-std/7",
        "properties": {"id": 7, "name": "nightly_7", "status": "Succeeded", "scheduled": True,
                       "created": "2026-10-13T01:02:03.4567891Z",
                       "storageAccountUrl": f"{CONTAINER}?{SAS}"},
    })
    record = backups.project_backup_item(item)
    assert record["name"] == "nightly_7"
    assert record["backup_id"] == 7
    assert record["status"] == "Succeeded"
    assert record["created"] == "2026-10-13T01:02:03Z"
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
