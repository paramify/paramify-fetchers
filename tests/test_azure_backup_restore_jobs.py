"""azure_backup_recovery_status restore jobs: the windowed job list, the details join, and null counts on failed reads."""

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
FETCHER = REPO_ROOT / "fetchers" / "azure" / "backup_recovery_status" / "fetcher.py"
sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))

spec = importlib.util.spec_from_file_location("azure_backup_restore_jobs_under_test", FETCHER)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)
Collector = sys.modules["azure_common"].Collector

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
VAULT = "/subscriptions/s1/resourceGroups/rg-a/providers/Microsoft.RecoveryServices/vaults/rsv-a"


def _collector():
    return Collector(logging.getLogger("test_backup_restore_jobs"))


def _job(name, status="Completed", start="2026-09-20T10:00:00Z", end="2026-09-20T10:45:00Z", duration="PT45M",
         operation="Restore", entity="db-a", workload="SQLDataBase"):
    return ns(id=f"{VAULT}/backupJobs/{name}", name=name,
              properties=ns(operation=operation, status=status, start_time=start, end_time=end, duration=duration,
                            entity_friendly_name=entity, job_type="AzureWorkloadJob", workload_type=workload,
                            backup_management_type="AzureWorkload"))


def _details(bag):
    return ns(properties=ns(extended_info=ns(property_bag=bag)))


# --- parsing ---

@pytest.mark.parametrize("value, seconds", [
    ("PT3M1.8153383S", 181.8), ("PT1H2M", 3720.0), ("P1DT1S", 86401.0), (timedelta(minutes=2), 120.0),
    (None, None), ("", None), ("P", None), ("3 minutes", None),
])
def test_duration_seconds_reads_iso_and_timedelta(value, seconds):
    assert backup.duration_seconds(value) == seconds


@pytest.mark.parametrize("text, workload, expected", [
    # Day first in 24-hour form, as SQL-in-VM restores write it: 05/09 is 5 September.
    ("05/09/2026 15:08:12", "SQLDataBase", datetime(2026, 9, 5, 15, 8, 12, tzinfo=timezone.utc)),
    ("24/09/2026 15:08", "SQLDataBase", datetime(2026, 9, 24, 15, 8, tzinfo=timezone.utc)),
    ("09/24/2026 3:08:12 PM", "SQLDataBase", None),
    # Month first with AM/PM, as Azure Files restores write it (az CLI's test_afs_cross_region_restore recording).
    ("9/25/2026 6:36:19 AM", "AzureFileShare", datetime(2026, 9, 25, 6, 36, 19, tzinfo=timezone.utc)),
    ("09/24/2026 3:08:12 PM", "AzureFileShare", datetime(2026, 9, 24, 15, 8, 12, tzinfo=timezone.utc)),
    ("24/09/2026 15:08:12", "AzureFileShare", None),
    # ISO 8601 reads for any workload.
    ("2026-09-24T15:08:12Z", "VM", datetime(2026, 9, 24, 15, 8, 12, tzinfo=timezone.utc)),
    ("2026-09-24T15:08:12Z", None, datetime(2026, 9, 24, 15, 8, 12, tzinfo=timezone.utc)),
    ("24/09/2026 3:08:12 PM", "SQLDataBase", None), ("soon", "SQLDataBase", None), (None, "SQLDataBase", None),
])
def test_recovery_point_time_reads_the_form_its_workload_writes_or_iso(text, workload, expected):
    assert backup.parse_recovery_point_time(text, workload) == expected


@pytest.mark.parametrize("workload, expected", [
    ("SQLDataBase", datetime(2026, 5, 3, 14, 0, tzinfo=timezone.utc)), ("AzureFileShare", None), ("VM", None),
    ("SAPHanaDatabase", None), (None, None),
])
def test_an_ambiguous_time_reads_only_for_a_workload_whose_form_is_known(workload, expected):
    # 03/05 is 3 May day first and 5 March month first; no real sample shows which a VM or SAP HANA restore writes.
    assert backup.parse_recovery_point_time("03/05/2026 14:00:00", workload) == expected


def test_property_bag_drops_url_query_strings():
    bag = backup.project_job_property_bag(_details({
        "Config Blob Uri": "https://sa.blob.core.windows.net/c/config.json?sv=2026&sig=abc", "Job Type": "Restore"}))
    assert bag == {"Config Blob Uri": "https://sa.blob.core.windows.net/c/config.json", "Job Type": "Restore"}


# --- one job ---

def test_restore_job_record_joins_the_recovery_point_and_target():
    job = backup.project_job(_job("j1"))
    record = backup.restore_job_record(job, {
        "Job Type": "Recovery to an alternate location", "Recovery Point Time in UTC": "20/09/2026 04:00:00",
        "Target Storage Account Name": "sa-target", "RestoreDestination": "share-b", "Data Transferred (in MB)": "5"})
    assert (record["succeeded"], record["duration_seconds"], record["duration_minutes"]) == (True, 2700.0, 45.0)
    assert record["restore_type"] == "Recovery to an alternate location"
    assert record["restore_target"] == {"Target Storage Account Name": "sa-target", "RestoreDestination": "share-b"}
    assert (record["recovery_point_time"], record["recovery_point_age_hours"]) == ("2026-09-20T04:00:00Z", 6.0)
    assert record["details_read"] is True


def test_unread_details_leave_the_details_fields_null():
    record = backup.restore_job_record(backup.project_job(_job("j1")), None)
    assert record["details_read"] is False
    assert [record[k] for k in ("restore_type", "restore_target", "recovery_point_time",
                                "recovery_point_age_hours", "job_properties")] == [None] * 5


def test_a_recovery_point_after_the_restore_started_reads_null():
    record = backup.restore_job_record(backup.project_job(_job("j1")),
                                       {"Recovery Point Time in UTC": "21/09/2026 04:00:00"})
    assert (record["recovery_point_time_text"], record["recovery_point_time"]) == ("21/09/2026 04:00:00", None)
    assert record["recovery_point_age_hours"] is None


def test_only_completed_counts_as_succeeded():
    for status, succeeded in (("Completed", True), ("CompletedWithWarnings", False), ("Failed", False),
                              ("InProgress", False)):
        assert backup.restore_job_record(backup.project_job(_job("j", status=status)), {})["succeeded"] is succeeded


# --- the job list ---

def test_job_windows_cover_the_window_in_slices_of_at_most_30_days():
    windows = list(backup.job_windows(NOW, 365))
    assert len(windows) == 13 and windows[0][1] == NOW and windows[-1][0] == NOW - timedelta(days=365)
    assert all(end - start <= timedelta(days=30) for start, end in windows)
    assert all(a[0] == b[1] for a, b in zip(windows, windows[1:]))


def test_restore_job_filter_uses_the_az_cli_date_format():
    start, end = datetime(2026, 9, 1, 13, 5, tzinfo=timezone.utc), datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)
    assert backup.restore_job_filter(start, end) == (
        "operation eq 'Restore' and startTime eq '2026-09-01 01:05:00 PM' and endTime eq '2026-10-01 12:00:00 AM'")


def test_list_restore_jobs_dedupes_across_slices_and_drops_other_operations():
    filters = []

    def list_jobs(vault_name, resource_group_name, filter):
        filters.append(filter)
        return [_job("j1"), _job("b1", operation="Backup"), _job("j2", operation="Restore (Full)")]

    client = ns(backup_jobs=ns(list=list_jobs))
    jobs = backup.list_restore_jobs(client, "rg-a", "rsv-a", 60, NOW, _collector())
    assert [j["name"] for j in jobs] == ["j1", "j2"] and len(filters) == 2


def test_a_failed_slice_makes_the_list_unread():
    calls = []

    def list_jobs(vault_name, resource_group_name, filter):
        calls.append(filter)
        if len(calls) == 2:
            raise RuntimeError("(AuthorizationFailed) no access")
        return [_job("j1")]

    collector = _collector()
    assert backup.list_restore_jobs(ns(backup_jobs=ns(list=list_jobs)), "rg-a", "rsv-a", 365, NOW, collector) is None
    # Stops at the failure rather than repeat it for every slice.
    assert len(calls) == 2 and len(collector.failures) == 1


# --- counts ---

def _vault(jobs):
    return {"id": VAULT, "name": "rsv-a", "resource_group": "rg-a", "restore_jobs": jobs}


def test_vault_and_summary_counts():
    jobs = [backup.restore_job_record(backup.project_job(j), bag) for j, bag in (
        (_job("j1", end="2026-09-20T10:45:00Z"), {"Recovery Point Time in UTC": "20/09/2026 04:00:00"}),
        (_job("j2", start="2026-09-25T10:00:00Z", end="2026-09-25T12:00:00Z", duration="PT2H"),
         {"Recovery Point Time in UTC": "24/09/2026 10:00:00"}),
        (_job("j3", status="Failed", start="2026-09-28T10:00:00Z"), {}),
        (_job("j4", start="2026-09-29T10:00:00Z", end="2026-09-29T10:10:00Z", duration="PT10M"), {}),
    )]
    vault = {**_vault(None), **backup.vault_restore_fields(jobs)}
    assert [j["name"] for j in vault["restore_jobs"]] == ["j4", "j3", "j2", "j1"]
    assert (vault["total_restore_jobs"], vault["succeeded_restore_jobs"],
            vault["latest_succeeded_restore_time"]) == (4, 3, "2026-09-29T10:10:00Z")
    summary = backup.summarize_restores([vault], 365, NOW)
    assert summary == {
        "restore_job_window_days": 365, "restore_jobs_read": True, "total_restore_jobs": 4,
        "succeeded_restore_jobs": 3, "failed_restore_jobs": 1, "restore_jobs_by_status": {"Completed": 3, "Failed": 1},
        "vaults_with_succeeded_restore": 1, "latest_succeeded_restore_time": "2026-09-29T10:10:00Z",
        "days_since_latest_succeeded_restore": 1.6, "longest_succeeded_restore_minutes": 120.0,
        "max_recovery_point_age_hours": 24.0, "succeeded_restores_without_recovery_point_time": 1,
    }


def test_an_unread_vault_makes_every_restore_count_null_not_zero():
    read = {**_vault(None), **backup.vault_restore_fields([])}
    unread = {**_vault(None), **backup.vault_restore_fields(None)}
    assert (unread["restore_jobs"], unread["restore_jobs_read"], unread["total_restore_jobs"],
            unread["succeeded_restore_jobs"]) == ([], False, None, None)
    summary = backup.summarize_restores([read, unread], 365, NOW)
    assert summary["restore_job_window_days"] == 365 and summary["restore_jobs_read"] is False
    assert all(v is None for k, v in summary.items() if k not in ("restore_job_window_days", "restore_jobs_read"))


def _item(name, rg):
    return {"id": f"{VAULT}/backupFabrics/Azure/protectionContainers/c/protectedItems/{name}-{rg}",
            "name": f"{name}-{rg}", "friendly_name": name,
            "source_resource_id": f"/subscriptions/s1/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}"}


def test_a_restore_job_stays_in_scope_while_an_in_scope_item_shares_its_name():
    jobs = [backup.project_job(_job("j-dev", entity="web01")),
            backup.project_job(_job("j-prod", status="Failed", entity="web01")),
            backup.project_job(_job("j-db", entity="db01"))]
    vault = {**_vault(jobs), "location": "regionwest",
             "backup_protected_items": [_item("web01", "rg-dev"), _item("web01", "rg-prod"), _item("db01", "rg-dev")]}
    vaults, excluded = backup.exclude_protected_items(backup.ResourceExclusions(["rg:rg-dev"]), [vault])
    assert [i["name"] for i in vaults[0]["backup_protected_items"]] == ["web01-rg-prod"]
    # A web01 job can't say which web01 it restored, and one of them is in scope, so both stay.
    assert [j["name"] for j in vaults[0]["restore_jobs"]] == ["j-dev", "j-prod"]
    assert [(e["kind"], e["name"]) for e in excluded] == [
        ("protected_item", "web01-rg-dev"), ("protected_item", "db01-rg-dev"), ("restore_job", "db01")]


def test_a_restore_job_takes_its_own_items_pattern_whatever_order_split_lists_entries_in():
    class Reversed(backup.ResourceExclusions):
        def split(self, items, kind, **keys):
            kept, excluded = super().split(items, kind, **keys)
            return kept, excluded[::-1]

    jobs = [backup.project_job(_job("j-web", entity="web01")), backup.project_job(_job("j-db", entity="db01"))]
    vault = {**_vault(jobs), "location": "regionwest",
             "backup_protected_items": [_item("web01", "rg-dev"), _item("db01", "rg-test")]}
    _, excluded = backup.exclude_protected_items(Reversed(["rg:rg-dev", "rg:rg-test"]), [vault])
    assert sorted((e["name"], e["pattern"]) for e in excluded if e["kind"] == "restore_job") == [
        ("db01", "rg:rg-test"), ("web01", "rg:rg-dev")]


def test_unread_details_on_a_succeeded_restore_leave_the_max_age_null():
    jobs = [backup.restore_job_record(backup.project_job(_job("j1")), {"Recovery Point Time in UTC": "20/09/2026 04:00:00"}),
            backup.restore_job_record(backup.project_job(_job("j2")), None)]
    summary = backup.summarize_restores([{**_vault(None), **backup.vault_restore_fields(jobs)}], 365, NOW)
    assert summary["max_recovery_point_age_hours"] is None
    assert summary["succeeded_restores_without_recovery_point_time"] == 1


def test_a_restore_whose_workload_form_is_unknown_keeps_its_text_and_is_counted_without_a_time():
    vm = backup.restore_job_record(backup.project_job(_job("j-vm", workload="VM", entity="vm-a")),
                                   {"Recovery Point Time in UTC": "03/05/2026 14:00:00"})
    assert (vm["recovery_point_time_text"], vm["recovery_point_time"], vm["recovery_point_age_hours"]) == (
        "03/05/2026 14:00:00", None, None)
    sql = backup.restore_job_record(backup.project_job(_job("j-sql")), {"Recovery Point Time in UTC": "20/09/2026 04:00:00"})
    summary = backup.summarize_restores([{**_vault(None), **backup.vault_restore_fields([vm, sql])}], 365, NOW)
    assert (summary["max_recovery_point_age_hours"], summary["succeeded_restores_without_recovery_point_time"]) == (6.0, 1)


# --- end to end ---

def _run(monkeypatch, tmp_path, list_jobs, get_details, recovery_client=None, window="90"):
    vault = ns(id=VAULT, name="rsv-a", location="regionwest", properties=ns())
    client = ns(backup_policies=ns(list=lambda **_: []), backup_protected_items=ns(list=lambda **_: []),
                backup_jobs=ns(list=list_jobs), job_details=ns(get=get_details))
    recovery_client = recovery_client or (lambda **_: ns(vaults=ns(list_by_subscription_id=lambda: [vault])))
    monkeypatch.setitem(sys.modules, "azure.mgmt.recoveryservices", ns(RecoveryServicesClient=recovery_client))
    monkeypatch.setitem(sys.modules, "azure.mgmt.recoveryservicesbackup",
                        ns(RecoveryServicesBackupClient=lambda **_: client))
    monkeypatch.setattr(backup, "load_dotenv", lambda: None)
    monkeypatch.setattr(backup, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(backup, "credential", lambda: object())
    monkeypatch.setattr(backup, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(backup, "utc_now", lambda: NOW)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv(backup.RESTORE_WINDOW_ENV, window)
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)
    code = backup.main()
    return code, json.loads((tmp_path / "azure_backup_recovery_status_s1.json").read_text())


def test_main_reports_restore_jobs_with_their_details(monkeypatch, tmp_path):
    details = []

    def get_details(vault_name, resource_group_name, job_name):
        details.append((vault_name, resource_group_name, job_name))
        return _details({"Recovery Point Time in UTC": "20/09/2026 04:00:00"})

    code, evidence = _run(monkeypatch, tmp_path, lambda **_: [_job("j1")], get_details)
    vault = evidence["results"]["recovery_services_vaults"][0]
    assert code == 0 and details == [("rsv-a", "rg-a", "j1")]
    assert [(j["name"], j["recovery_point_age_hours"]) for j in vault["restore_jobs"]] == [("j1", 6.0)]
    assert (evidence["summary"]["restore_job_window_days"], evidence["summary"]["total_restore_jobs"],
            evidence["summary"]["in_scope_restore_jobs"], evidence["summary"]["excluded_restore_jobs"]) == (90, 1, 1, 0)


@pytest.mark.parametrize("window, used, requested, code, slices", [
    ("9O", 365, "9O", 1, 13), ("0", 365, 0, 1, 13), ("3650", 365, 3650, 0, 13), ("60", 60, 60, 0, 2),
])
def test_main_records_a_bad_window_as_bad_config_and_keeps_the_value_asked_for(
        monkeypatch, tmp_path, window, used, requested, code, slices):
    filters = []
    returned, evidence = _run(monkeypatch, tmp_path, lambda **kw: filters.append(kw["filter"]) or [],
                              lambda **_: pytest.fail("no job to read"), window=window)
    assert (returned, len(filters)) == (code, slices)
    assert (evidence["summary"]["restore_job_window_days"],
            evidence["results"]["restore_job_window_days_requested"]) == (used, requested)
    if code:
        status = json.loads((tmp_path / "status.json").read_text())
        assert status["code"] == "bad_config" and backup.RESTORE_WINDOW_ENV in status["error"]
        assert [f["operation"] for f in evidence["metadata"]["api_failures"]] == [f"config {backup.RESTORE_WINDOW_ENV}"]


def test_main_fails_and_reports_null_when_the_job_list_is_refused(monkeypatch, tmp_path):
    def refuse(**_):
        raise RuntimeError("(AuthorizationFailed) does not have authorization to perform backupJobs/read")

    code, evidence = _run(monkeypatch, tmp_path, refuse, lambda **_: pytest.fail("no job to read"))
    vault, summary = evidence["results"]["recovery_services_vaults"][0], evidence["summary"]
    assert code == 1
    assert (vault["restore_jobs_read"], vault["total_restore_jobs"]) == (False, None)
    assert (summary["restore_jobs_read"], summary["total_restore_jobs"], summary["succeeded_restore_jobs"],
            summary["in_scope_restore_jobs"]) == (False, None, None, None)
    assert [f["operation"] for f in evidence["metadata"]["api_failures"]] == [
        "recoveryservicesbackup.backup_jobs.list (rsv-a)"]


def _refuse_vaults(*_, **__):
    raise RuntimeError("(AuthorizationFailed) does not have authorization to perform vaults/read")


@pytest.mark.parametrize("recovery_client", [
    _refuse_vaults, lambda **_: ns(vaults=ns(list_by_subscription_id=_refuse_vaults)),
], ids=["client_init_fails", "vault_list_refused"])
def test_main_reports_null_not_zero_when_the_vault_list_is_not_read(monkeypatch, tmp_path, recovery_client):
    no_vault = lambda **_: pytest.fail("no vault was listed")  # noqa: E731
    code, evidence = _run(monkeypatch, tmp_path, no_vault, no_vault, recovery_client)
    summary = evidence["summary"]
    assert code == 1 and evidence["results"]["recovery_services_vaults"] == []
    assert (summary["restore_job_window_days"], summary["restore_jobs_read"], summary["in_scope_restore_jobs"],
            summary["in_scope_recovery_services_vaults"], summary["in_scope_protected_items"],
            summary["retention_threshold_days"]) == (90, False, None, None, None, 30)
    restore_counts = set(backup.summarize_restores([], 90, NOW)) - {"restore_job_window_days", "restore_jobs_read"}
    vault_counts = set(backup.summarize([])) - {"retention_threshold_days"}
    assert {k: summary[k] for k in restore_counts | vault_counts} == dict.fromkeys(restore_counts | vault_counts)


def test_main_reports_zero_when_the_vault_list_is_read_and_empty(monkeypatch, tmp_path):
    no_vault = lambda **_: pytest.fail("no vault was listed")  # noqa: E731
    code, evidence = _run(monkeypatch, tmp_path, no_vault, no_vault,
                          lambda **_: ns(vaults=ns(list_by_subscription_id=lambda: [])))
    summary = evidence["summary"]
    assert code == 0
    assert (summary["restore_jobs_read"], summary["total_restore_jobs"], summary["total_recovery_services_vaults"],
            summary["total_protected_items"], summary["in_scope_restore_jobs"],
            summary["in_scope_recovery_services_vaults"], summary["in_scope_protected_items"]) == (True, 0, 0, 0, 0, 0, 0)


def test_real_sdk_models_project():
    models = pytest.importorskip("azure.mgmt.recoveryservicesbackup.models")
    job = models.JobResource({
        "id": f"{VAULT}/backupJobs/j1", "name": "j1",
        "properties": {
            "jobType": "AzureWorkloadJob", "workloadType": "SQLDataBase", "duration": "PT3M1.8153383S",
            "extendedInfo": {"propertyBag": {"Job Type": "Recovery to an alternate database",
                                             "Recovery Point Time in UTC": "24/09/2026 15:08:12",
                                             "Target resource group": "rg-b"}},
            "entityFriendlyName": "db1", "backupManagementType": "AzureWorkload", "operation": "Restore (Full)",
            "status": "Completed", "startTime": "2026-09-24T15:11:29.1675192Z", "endTime": "2026-09-24T15:14:30.98Z",
        },
    })
    record = backup.restore_job_record(backup.project_job(job), backup.project_job_property_bag(job))
    assert (record["operation"], record["start_time"], record["duration_seconds"]) == (
        "Restore (Full)", "2026-09-24T15:11:29Z", 181.8)
    assert (record["recovery_point_time"], record["recovery_point_age_hours"]) == ("2026-09-24T15:08:12Z", 0.05)
    assert record["restore_target"] == {"Target resource group": "rg-b"}
