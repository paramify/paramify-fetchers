"""azure_velero_backups: location parsing, backup and restore judgement, null-not-zero summaries, the blob read boundary, and a full run against synthetic ARM and Blob responses. No SDK or network."""

from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_velero_backups_under_test", AZURE / "velero_backups" / "fetcher.py")
vb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vb)
azure_rest = sys.modules["azure_rest"]

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
SETTINGS = {"success_window_hours": 26, "expiry_grace_hours": 24, "container_names": ["velero"], "explicit_locations": [], "restore_test_interval_days": None,
            "expected_schedules": None, "rpo_hours": None, "missed_run_lookback_days": 7,
            "retry_suffix": None, "validation_label": None}
SUB = "/subscriptions/s1"
ACCOUNT_ID = f"{SUB}/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/backupsa"
ENDPOINT = "https://backupsa.blob.core.windows.net/"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def backup(name, phase="Completed", schedule="daily", done_hours_ago=6, expires_in_hours=700, attempted=1, completed=1, now=NOW):
    done = now - timedelta(hours=done_hours_ago)
    return {"kind": "Backup", "metadata": {"name": name, "labels": {"velero.io/schedule-name": schedule} if schedule else {}},
            "status": {"phase": phase, "startTimestamp": iso(done - timedelta(minutes=5)), "completionTimestamp": iso(done),
                       "expiration": iso(now + timedelta(hours=expires_in_hours)),
                       "volumeSnapshotsAttempted": attempted, "volumeSnapshotsCompleted": completed}}


def results(errors=0, warnings=0):
    return {"errors": {"velero": ["e"] * errors, "cluster": [], "namespaces": {}},
            "warnings": {"velero": [], "cluster": [], "namespaces": {"ns1": ["w"] * warnings}}}


def location(backups=(), restores=(), read=True, restores_read=True, **kw):
    return {"backups_read": read, "backups_unreadable": 0, "backups": list(backups), "restores_read": restores_read,
            "restores": list(restores), "geo_replicated": kw.get("geo", True), "customer_managed_key": kw.get("cmk", False)}


# --- pure transforms ---

def test_locations_parse_account_container_and_optional_prefix():
    locs, invalid = vb.parse_locations("BackupSA/velero, other/vel/cluster-a/ , bad")
    assert locs == [{"account": "backupsa", "container": "velero", "prefix": ""},
                    {"account": "other", "container": "vel", "prefix": "cluster-a"}]
    assert invalid == ["bad"]


def test_account_record_reads_replication_and_key_source():
    raw = {"id": ACCOUNT_ID, "name": "BackupSA", "sku": {"name": "Standard_RAGRS"},
           "properties": {"encryption": {"keySource": "Microsoft.Keyvault"}, "primaryEndpoints": {"blob": ENDPOINT}}}
    rec = vb.account_record(raw)
    assert (rec["name"], rec["geo_replicated"], rec["customer_managed_key"], rec["blob_endpoint"]) == ("backupsa", True, True, ENDPOINT)
    lrs = vb.account_record({"id": ACCOUNT_ID, "name": "x", "sku": {"name": "Standard_LRS"}, "properties": {"encryption": {"keySource": "Microsoft.Storage"}}})
    assert (lrs["geo_replicated"], lrs["customer_managed_key"]) == (False, False)


def test_backup_past_expiry_beyond_grace_counts_and_snapshot_shortfall_is_flagged():
    old = vb.backup_record("b1", backup("b1", expires_in_hours=-30, attempted=3, completed=2), NOW, 24)
    assert (old["expired_not_deleted"], old["volume_snapshots_incomplete"], old["schedule"]) == (True, True, "daily")
    inside_grace = vb.backup_record("b2", backup("b2", expires_in_hours=-10), NOW, 24)
    assert inside_grace["expired_not_deleted"] is False


def test_restore_is_clean_only_when_its_results_list_no_errors():
    assert vb.restore_record("r1", results(warnings=2), "2026-11-10T00:00:00Z")["clean"] is True
    assert vb.restore_record("r2", results(errors=1), None)["clean"] is False
    assert vb.restore_record("r3", None, None) == {"name": "r3", "results_read": False, "errors": None, "warnings": None,
                                                   "clean": None, "results_written": None}


def test_summary_judges_each_schedule_by_its_newest_completed_backup():
    bk = [vb.backup_record(n, b, NOW, 24) for n, b in (
        ("d1", backup("d1", done_hours_ago=6)), ("d0", backup("d0", done_hours_ago=30)),
        ("w1", backup("w1", schedule="weekly", done_hours_ago=100)), ("f1", backup("f1", phase="Failed", schedule="weekly", done_hours_ago=2)),
        ("m1", backup("m1", schedule=None, phase="PartiallyFailed")))]
    rs = [vb.restore_record("r1", results(), iso(NOW - timedelta(days=3, hours=1))), vb.restore_record("r2", results(errors=1), iso(NOW))]
    s = vb.summarize([location(bk, rs)], SETTINGS, NOW)
    assert (s["backups_total"], s["backups_completed"], s["backups_failed"], s["backups_partially_failed"]) == (5, 3, 1, 1)
    assert (s["schedules_observed"], s["schedules_with_success_within_window"], s["schedules_without_success_within_window"]) == (2, 1, ["weekly"])
    assert s["max_hours_since_scheduled_success"] == 100.0
    assert (s["restores_total"], s["restores_without_errors"], s["restores_with_errors"], s["days_since_last_clean_restore"]) == (2, 1, 1, 3)


def test_unread_locations_or_unfinished_discovery_leave_counts_null_not_zero():
    unread = vb.summarize([location(read=False, restores_read=False)], SETTINGS, NOW)
    assert (unread["backups_total"], unread["restores_total"], unread["backup_locations"], unread["backup_locations_read"]) == (None, None, 1, 0)
    undiscovered = vb.summarize([], SETTINGS, NOW, discovered=False)
    assert (undiscovered["backup_locations"], undiscovered["backups_total"], undiscovered["restores_total"]) == (None, None, None)
    empty = vb.summarize([], SETTINGS, NOW)
    assert (empty["backup_locations"], empty["backups_total"], empty["schedules_observed"]) == (0, 0, 0)


def test_a_schedule_without_any_completed_backup_leaves_the_max_age_null():
    bk = [vb.backup_record("f1", backup("f1", phase="Failed"), NOW, 24)]
    s = vb.summarize([location(bk)], SETTINGS, NOW)
    assert (s["schedules_with_success_within_window"], s["max_hours_since_scheduled_success"]) == (0, None)


def test_summary_matches_the_instructions(assert_summary_documented):
    s = vb.summarize([location()], SETTINGS, NOW)
    s.update(vb.ResourceExclusions().summary([], ("storage_account",), {"storage_accounts": 1}))
    assert_summary_documented("azure/velero_backups", s)


def test_blob_reads_refuse_any_endpoint_arm_did_not_return():
    reader = vb.BlobReader(namedtuple("C", "session cred")(None, None), [ENDPOINT])
    for endpoint in ("https://evil.blob.core.windows.net/", "http://backupsa.blob.core.windows.net/"):
        with pytest.raises(ValueError, match="untrusted"):
            reader._get(endpoint, "velero")


# --- full run against synthetic ARM and Blob responses ---

class _Resp:
    def __init__(self, status, body=None, content=None, headers=None):
        self.status_code, self._body, self.reason = status, body, ""
        self.content = content if content is not None else json.dumps(body or {}).encode()
        self.text = self.content.decode(errors="replace")
        self.headers = headers or {}

    def json(self):
        return self._body


def _list_xml(names):
    blobs = "".join(f"<Blob><Name>{n}</Name><Properties><Last-Modified>Fri, 13 Nov 2026 01:00:00 GMT</Last-Modified></Properties></Blob>" for n in names)
    return f'<?xml version="1.0"?><EnumerationResults><Blobs>{blobs}</Blobs><NextMarker/></EnumerationResults>'.encode()


class _Azure:
    """requests.Session for subscription s1: one GRS account with a 'velero' container, two backups and one restore."""

    def __init__(self, blob_status=200):
        self.blob_status, self.urls, self.headers = blob_status, [], []
        now = datetime.now(timezone.utc)
        self.blobs = {
            "backups/daily-1/velero-backup.json": json.dumps(backup("daily-1", done_hours_ago=5, now=now)).encode(),
            "backups/daily-1/daily-1.tar.gz": b"x",
            "backups/old-1/velero-backup.json": json.dumps(backup("old-1", schedule=None, expires_in_hours=-48, now=now)).encode(),
            "restores/r1/restore-r1-results.gz": gzip.compress(json.dumps(results()).encode()),
            "restores/r1/restore-r1-logs.gz": b"x",
        }

    def get(self, url, params=None, headers=None, timeout=None, allow_redirects=True):
        self.urls.append(url)
        self.headers.append(headers or {})
        host, path = urlparse(url).netloc, urlparse(url).path
        if host == "backupsa.blob.core.windows.net":
            if self.blob_status != 200:
                return _Resp(self.blob_status, content=b"<Error/>", headers={"x-ms-error-code": "AuthorizationPermissionMismatch"})
            if (params or {}).get("comp") == "list":
                return _Resp(200, content=_list_xml(sorted(n for n in self.blobs if n.startswith(params["prefix"]))))
            return _Resp(200, content=self.blobs[path.split("/velero/", 1)[1]])
        if path.endswith("/providers/Microsoft.Storage/storageAccounts"):
            return _Resp(200, {"value": [{"id": ACCOUNT_ID, "name": "backupsa", "sku": {"name": "Standard_GRS"}, "location": "eastus",
                                          "properties": {"encryption": {"keySource": "Microsoft.Storage"}, "primaryEndpoints": {"blob": ENDPOINT}}}]})
        if path.endswith("/blobServices/default/containers"):
            return _Resp(200, {"value": [{"name": "velero"}, {"name": "logs"}]})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok-" + scope, 9_999_999_999)


@pytest.fixture
def azure(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Azure(**kwargs)
        monkeypatch.setattr("requests.Session", lambda: session)
        return session

    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: _Cred())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "s1")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for env in ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", "AZURE_RESOURCE_EXCLUSIONS", "AZURE_TARGET_SUBSCRIPTION_ONLY",
                vb.CONTAINERS_ENV, vb.LOCATIONS_ENV, vb.WINDOW_ENV, vb.GRACE_ENV, vb.INTERVAL_ENV,
                vb.EXPECTED_ENV, vb.RPO_ENV, vb.MISSED_LOOKBACK_ENV, vb.RETRY_SUFFIX_ENV, vb.VALIDATION_LABEL_ENV):
        monkeypatch.delenv(env, raising=False)
    return serve


def _evidence(tmp_path):
    [path] = tmp_path.glob("azure_velero_backups_s1.json")
    return json.loads(path.read_text())


def test_main_reads_backups_and_restores_from_the_velero_container(azure, tmp_path):
    session = azure()
    assert vb.main() == 0
    ev = _evidence(tmp_path)
    s = ev["summary"]
    assert ev["metadata"]["partial_failure"] is False
    assert (s["backup_locations"], s["backup_locations_read"], s["backup_locations_geo_replicated"], s["backup_locations_customer_managed_key"]) == (1, 1, 1, 0)
    assert (s["backups_total"], s["backups_completed"], s["expired_backups_not_deleted"]) == (2, 2, 1)
    assert (s["schedules_observed"], s["schedules_with_success_within_window"]) == (1, 1)
    assert s["restores_total"] == 1 and s["restores_without_errors"] == 1
    blob_calls = [h for u, h in zip(session.urls, session.headers) if "blob.core" in u]
    assert blob_calls and all(h["Authorization"] == "Bearer tok-https://storage.azure.com/.default" and h["x-ms-version"] for h in blob_calls)
    assert not any("logs" in u and "blob.core" in u for u in session.urls)


def test_a_missing_data_role_fails_the_run_and_leaves_counts_null(azure, tmp_path):
    azure(blob_status=403)
    assert vb.main() != 0
    s = _evidence(tmp_path)["summary"]
    assert (s["backup_locations"], s["backup_locations_read"], s["backups_total"], s["restores_total"]) == (1, 0, None, None)
    assert "AuthorizationPermissionMismatch" in (tmp_path / "status.json").read_text()


def test_an_explicit_location_outside_the_subscription_fails_the_run(azure, tmp_path, monkeypatch):
    monkeypatch.setenv(vb.LOCATIONS_ENV, "elsewhere/velero")
    azure()
    assert vb.main() != 0
    s = _evidence(tmp_path)["summary"]
    assert (s["backup_locations"], s["backups_total"]) == (None, None)


def test_strict_subscription_mode_still_reads_blobs_from_arm_returned_endpoints(azure, tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", "true")
    session = azure()
    assert vb.main() == 0
    assert _evidence(tmp_path)["summary"]["backups_total"] == 2
    assert all(urlparse(u).netloc in ("management.azure.com", "backupsa.blob.core.windows.net") for u in session.urls)


# --- real Velero 1.16 objects captured from a sandbox (tests/fixtures/velero) ---

REAL = REPO_ROOT / "tests" / "fixtures" / "velero"
# 1h03m after the 5-minute backup expired, and before Velero's hourly cleanup removed it.
CAPTURED = datetime(2026, 11, 17, 1, 0, tzinfo=timezone.utc)


class _RealVelero(_Azure):
    """Serves the captured container: every real blob name in the listing, and real bytes for the ones the fetcher reads."""

    def __init__(self):
        super().__init__()
        self.blobs = {n: (REAL / n).read_bytes() if (REAL / n).exists() else None
                      for n in (REAL / "blob-names.txt").read_text().split()}
        self.fetched = []

    def get(self, url, params=None, headers=None, timeout=None, allow_redirects=True):
        if "blob.core" in url and (params or {}).get("comp") != "list":
            name = urlparse(url).path.split("/velero/", 1)[1]
            self.fetched.append(name)
            if self.blobs.get(name) is None:
                return _Resp(404, content=b"<Error/>", headers={"x-ms-error-code": "BlobNotFound"})
        return super().get(url, params, headers, timeout, allow_redirects)


def test_real_velero_objects_are_judged_as_velero_wrote_them(monkeypatch):
    monkeypatch.setenv(vb.GRACE_ENV, "1")
    for env in (vb.CONTAINERS_ENV, vb.LOCATIONS_ENV, vb.WINDOW_ENV, "AZURE_TARGET_SUBSCRIPTION_ONLY", "AZURE_RESOURCE_EXCLUSIONS",
                vb.EXPECTED_ENV, vb.RPO_ENV, vb.MISSED_LOOKBACK_ENV, vb.INTERVAL_ENV):
        monkeypatch.delenv(env, raising=False)
    session = _RealVelero()
    client = azure_rest.AzureRestClient(_Cred(), session)
    collector = sys.modules["azure_common"].Collector(vb.logger)
    results, s = vb.collect(client, "s1", collector, now=CAPTURED)
    assert collector.failures == []
    # Only the two backup records and the restore results were read; tarballs, logs and other files were not.
    assert sorted(session.fetched) == ["backups/manual-1/velero-backup.json", "backups/short-lived/velero-backup.json",
                                       "restores/r1/restore-r1-results.gz"]
    assert (s["backups_total"], s["backups_completed"], s["backups_failed"], s["backups_metadata_unreadable"]) == (2, 2, 0, 0)
    # Manual backups carry no schedule label; the hourly schedule had not fired when these were captured.
    assert (s["schedules_observed"], s["schedules_with_success_within_window"], s["max_hours_since_scheduled_success"]) == (0, 0, None)
    # The 5-minute backup is past its expiration by more than the 1-hour grace and is still stored.
    assert s["expired_backups_not_deleted"] == 1
    assert [b["name"] for b in results["backup_locations"][0]["backups"] if b["expired_not_deleted"]] == ["short-lived"]
    # The real restore lists no errors ("errors": {}) and one namespace warning, so it is clean.
    [restore] = results["backup_locations"][0]["restores"]
    assert (restore["errors"], restore["warnings"], restore["clean"]) == (0, 1, True)
    assert (s["restores_total"], s["restores_without_errors"], s["restores_with_errors"], s["restores_results_missing"]) == (1, 1, 0, 0)
    # No volumes in the sandbox workload: Velero omits the snapshot counters, which read as nothing attempted.
    assert s["backups_volume_snapshots_incomplete"] == 0


def test_restore_interval_is_judged_only_once_adopted():
    rs = [vb.restore_record("r1", results(), iso(NOW - timedelta(days=40)))]
    assert vb.summarize([location([], rs)], SETTINGS, NOW)["clean_restore_within_interval"] is None
    adopted = {**SETTINGS, "restore_test_interval_days": 30}
    assert vb.summarize([location([], rs)], adopted, NOW)["clean_restore_within_interval"] is False
    assert vb.summarize([location([], rs)], {**adopted, "restore_test_interval_days": 60}, NOW)["clean_restore_within_interval"] is True
    assert vb.summarize([location([], [])], adopted, NOW)["clean_restore_within_interval"] is False


# --- expected schedules, missed runs and the recovery point objective ---

def _daily(hours_ago_list, schedule="daily", phase="Completed"):
    return [vb.backup_record(f"{schedule}-{h}", backup(f"{schedule}-{h}", schedule=schedule, done_hours_ago=h, phase=phase), NOW, 24)
            for h in hours_ago_list]


def test_expected_schedules_parse_name_and_interval():
    assert vb.parse_expected(None) == (None, [])
    assert vb.parse_expected("daily:24, weekly-db:168 , bad, x:0") == (
        [{"name": "daily", "interval_hours": 24}, {"name": "weekly-db", "interval_hours": 168}], ["bad", "x:0"])


def test_missed_daily_runs_are_each_24_hour_period_without_a_completed_backup():
    # Completed 6, 30, 54 and 126 hours ago: periods 0, 1, 2 and 5 are covered; 3, 4 and 6 are missed.
    bk = _daily([6, 30, 54, 126]) + _daily([78], phase="Failed")
    settings = {**SETTINGS, "expected_schedules": [{"name": "daily", "interval_hours": 24}], "rpo_hours": 168}
    [c] = vb.schedule_checks(bk, settings, NOW)
    assert (c["periods_checked"], c["missed_runs"], c["hours_since_success"], c["exceeds_rpo"]) == (7, 3, 6.0, False)


def test_an_expected_schedule_with_no_backups_is_reported_and_exceeds_the_rpo():
    settings = {**SETTINGS, "expected_schedules": [{"name": "daily", "interval_hours": 24}, {"name": "weekly", "interval_hours": 168}], "rpo_hours": 168}
    s = vb.summarize([location(_daily([6]))], settings, NOW)
    assert (s["expected_schedules"], s["expected_schedules_without_backups"], s["expected_schedules_without_backups_names"]) == (2, 1, ["weekly"])
    assert (s["missed_scheduled_runs"], s["schedules_with_missed_runs"], s["schedules_exceeding_rpo"]) == (7, 2, 1)


def test_rpo_is_judged_against_observed_schedules_when_none_are_listed():
    s = vb.summarize([location(_daily([200], schedule="old") + _daily([5]))], {**SETTINGS, "rpo_hours": 168}, NOW)
    assert (s["expected_schedules"], s["missed_scheduled_runs"], s["schedules_exceeding_rpo"]) == (None, None, 1)


def test_without_listed_schedules_or_an_rpo_the_new_counts_stay_null():
    s = vb.summarize([location(_daily([5]))], SETTINGS, NOW)
    assert (s["expected_schedules"], s["expected_schedules_without_backups"], s["missed_scheduled_runs"], s["schedules_exceeding_rpo"], s["rpo_hours"]) == (None, None, None, None, None)


def test_a_restore_without_a_readable_date_is_unknown_and_never_recent():
    rs = [vb.restore_record("r1", results(), None), vb.restore_record("r2", results(), iso(NOW - timedelta(days=90)))]
    s = vb.summarize([location([], rs)], {**SETTINGS, "restore_test_interval_days": 30}, NOW)
    assert (s["restores_without_errors"], s["restores_date_unknown"], s["days_since_last_clean_restore"], s["clean_restore_within_interval"]) == (2, 1, 90, False)


def test_invalid_expected_schedules_or_rpo_fail_the_run(azure, tmp_path, monkeypatch):
    monkeypatch.setenv(vb.EXPECTED_ENV, "daily")
    monkeypatch.setenv(vb.RPO_ENV, "a week")
    azure()
    assert vb.main() != 0
    s = _evidence(tmp_path)["summary"]
    assert (s["expected_schedules"], s["expected_schedules_without_backups"], s["rpo_hours"]) == (None, None, None)


def test_real_sandbox_shows_the_daily_schedule_has_not_produced_a_backup(monkeypatch):
    monkeypatch.setenv(vb.EXPECTED_ENV, "daily:24")
    monkeypatch.setenv(vb.RPO_ENV, "168")
    for env in (vb.CONTAINERS_ENV, vb.LOCATIONS_ENV, vb.WINDOW_ENV, vb.INTERVAL_ENV, vb.MISSED_LOOKBACK_ENV, "AZURE_TARGET_SUBSCRIPTION_ONLY", "AZURE_RESOURCE_EXCLUSIONS"):
        monkeypatch.delenv(env, raising=False)
    client = azure_rest.AzureRestClient(_Cred(), _RealVelero())
    results, s = vb.collect(client, "s1", sys.modules["azure_common"].Collector(vb.logger), now=CAPTURED)
    # The schedule existed in the cluster but had not run yet: storage holds only the two manual backups.
    assert (s["expected_schedules"], s["expected_schedules_without_backups"], s["expected_schedules_without_backups_names"]) == (1, 1, ["daily"])
    assert (s["missed_scheduled_runs"], s["schedules_exceeding_rpo"]) == (7, 1)
    assert results["schedules"][0]["backups"] == 0


# --- review fixes: retention-bounded, gap-based missed runs; per-schedule windows; history; blob reads ---

def _runs(schedule, done_times, ttl_hours, phase="Completed", attempted=1, completed=1, name=None):
    out = []
    for i, done in enumerate(done_times):
        raw = {"metadata": {"labels": {"velero.io/schedule-name": schedule}},
               "status": {"phase": phase, "startTimestamp": iso(done - timedelta(minutes=5)), "completionTimestamp": iso(done),
                          "expiration": iso(done + timedelta(hours=ttl_hours)),
                          "volumeSnapshotsAttempted": attempted, "volumeSnapshotsCompleted": completed}}
        out.append(vb.backup_record(name or f"{schedule}-{i}", raw, NOW, 24))
    return out


def _expected(name, hours, **extra):
    return {**SETTINGS, "expected_schedules": [{"name": name, "interval_hours": hours}], **extra}


def test_backups_velero_deleted_at_the_end_of_their_retention_are_not_missed_runs():
    # Every run succeeded; only the retained backups are in storage.
    hourly = _runs("hourly", [NOW - timedelta(hours=h, minutes=10) for h in range(24)], ttl_hours=24)
    [c] = vb.schedule_checks(hourly, _expected("hourly", 1), NOW)
    assert (c["missed_runs"], c["hours_checked_for_missed_runs"]) == (0, 24.0)
    daily = _runs("daily", [NOW - timedelta(hours=h) for h in (2, 26, 50)], ttl_hours=72)
    [c] = vb.schedule_checks(daily, _expected("daily", 24), NOW)
    assert (c["missed_runs"], c["periods_checked"]) == (0, 3)


def test_a_backup_finishing_a_few_minutes_late_is_not_a_missed_run():
    # Daily at 02:00 for 8 days, except yesterday's finished at 02:05; the fetcher runs at 02:03.
    now = datetime(2026, 11, 16, 2, 3, tzinfo=timezone.utc)
    times = [datetime(2026, 11, 16 - d, 2, 5 if d == 1 else 0, tzinfo=timezone.utc) for d in range(1, 9)]
    bk = []
    for i, done in enumerate(times):
        raw = {"metadata": {"labels": {"velero.io/schedule-name": "daily"}},
               "status": {"phase": "Completed", "completionTimestamp": iso(done), "expiration": iso(done + timedelta(days=30))}}
        bk.append(vb.backup_record(f"d{i}", raw, now, 24))
    [c] = vb.schedule_checks(bk, _expected("daily", 24), now)
    assert c["missed_runs"] == 0


def test_a_real_gap_still_counts_each_missed_interval():
    daily = _runs("daily", [NOW - timedelta(hours=h) for h in (2, 98)], ttl_hours=720)
    [c] = vb.schedule_checks(daily, _expected("daily", 24), NOW)
    assert c["missed_runs"] == 5  # 3 runs missed between the two backups, 2 before the older one


def test_a_listed_weekly_schedule_is_judged_against_its_own_interval():
    weekly = _runs("weekly", [NOW - timedelta(hours=100)], ttl_hours=720)
    s = vb.summarize([location(weekly)], _expected("weekly", 168), NOW)
    assert (s["schedules_observed"], s["schedules_with_success_within_window"]) == (1, 1)
    s = vb.summarize([location(weekly)], SETTINGS, NOW)  # not listed: the 26-hour default applies
    assert s["schedules_with_success_within_window"] == 0
    assert vb.success_window_hours(24, SETTINGS) == 26 and vb.success_window_hours(168, SETTINGS) == 184


def test_resolved_failures_stay_in_history_but_are_not_current():
    resolved = _runs("daily", [NOW - timedelta(hours=50)], 720, phase="Failed", name="daily-failed-old")
    current = _runs("hourly", [NOW - timedelta(hours=1)], 720, phase="PartiallyFailed", name="hourly-failed-new")
    ok = _runs("daily", [NOW - timedelta(hours=26)], 720)
    snaps_old = _runs("weekly", [NOW - timedelta(hours=200)], 720, attempted=2, completed=1, name="weekly-old")
    snaps_ok = _runs("weekly", [NOW - timedelta(hours=30)], 720, name="weekly-new")
    rs = [vb.restore_record("r-bad-old", results(errors=1), iso(NOW - timedelta(days=5))),
          vb.restore_record("r-good", results(), iso(NOW - timedelta(days=2))),
          vb.restore_record("r-bad-new", results(errors=2), iso(NOW - timedelta(days=1)))]
    s = vb.summarize([location(resolved + current + ok + snaps_old + snaps_ok, rs)], SETTINGS, NOW)
    assert (s["backups_failed"], s["backups_partially_failed"], s["backups_failed_unresolved"]) == (1, 1, 1)
    assert (s["backups_volume_snapshots_incomplete"], s["backups_volume_snapshots_incomplete_unresolved"]) == (1, 0)
    # r-good is a different restore, so it resolves neither failure: storage doesn't say which backup each one used.
    assert (s["restores_with_errors"], s["restores_with_errors_unresolved"]) == (2, 2)


def _validation_backup(name, phase, hours_ago):
    raw = {"metadata": {"name": name, "labels": {"validation-test": "true", "ticket": "TICKET-1"}},
           "status": {"phase": phase, "completionTimestamp": iso(NOW - timedelta(hours=hours_ago)),
                      "expiration": iso(NOW + timedelta(days=30))}}
    return vb.backup_record(name, raw, NOW, 24)


def test_a_failure_is_resolved_only_by_its_own_successful_retry():
    # Interruption tests named restore-drill-interrupt-<date>; a retry has the same name plus -retry.
    bk = [_validation_backup("restore-drill-interrupt-20261104", "Failed", 100),
          _validation_backup("restore-drill-interrupt-20261104-retry", "Completed", 99),
          _validation_backup("restore-drill-interrupt-20261110", "Failed", 30),
          _validation_backup("restore-drill-interrupt-20261110-retry", "Failed", 29)]
    rs = [vb.restore_record("restore-drill-interrupt-20261104", results(errors=1), iso(NOW - timedelta(hours=98))),
          vb.restore_record("restore-drill-interrupt-20261104-retry", results(), iso(NOW - timedelta(hours=97)))]
    settings = {**SETTINGS, "retry_suffix": "-retry", "validation_label": ("validation-test", "true")}
    s = vb.summarize([location(bk, rs)], settings, NOW)
    # The 20261104 backup and restore are resolved by their retries; the 20261110 test and its failed retry stay current.
    assert (s["backups_failed"], s["backups_failed_unresolved"], s["failures_resolved_by_retry"]) == (3, 2, 2)
    assert (s["restores_with_errors"], s["restores_with_errors_unresolved"]) == (1, 0)
    # Validation backups are counted, never excluded: all four carry the label and three failed.
    assert (s["validation_backups"], s["validation_backups_failed"], s["validation_label"]) == (4, 3, "validation-test=true")
    # Without a retry suffix nothing is resolved by retry, and nothing is hidden.
    plain = vb.summarize([location(bk, rs)], SETTINGS, NOW)
    assert (plain["backups_failed_unresolved"], plain["failures_resolved_by_retry"], plain["validation_backups"]) == (3, None, None)
    assert plain["restores_with_errors_unresolved"] == 1


@pytest.mark.parametrize("different_field", ["storage_account", "container", "prefix"])
@pytest.mark.parametrize("failure_kind", ["backup", "snapshots", "restore"])
def test_only_a_retry_in_the_same_location_resolves_a_failure(different_field, failure_kind):
    identity = {"storage_account": "backupsa", "container": "velero", "prefix": "cluster-a"}
    original, unrelated = location(), location()
    original.update(identity)
    unrelated.update({**identity, different_field: "other"})
    if failure_kind == "restore":
        failed = vb.restore_record("drill", results(errors=1), iso(NOW - timedelta(hours=10)))
        retry = vb.restore_record("drill-retry", results(), iso(NOW - timedelta(hours=2)))
        records, unresolved = "restores", "restores_with_errors_unresolved"
        resolved_field = "error_resolved"
    else:
        raw = backup("drill", schedule=None, done_hours_ago=10,
                     phase="Failed" if failure_kind == "backup" else "Completed",
                     attempted=2, completed=1)
        failed = vb.backup_record("drill", raw, NOW, 24)
        retry = vb.backup_record("drill-retry", backup("drill-retry", schedule=None, done_hours_ago=2), NOW, 24)
        records = "backups"
        unresolved = "backups_failed_unresolved" if failure_kind == "backup" else "backups_volume_snapshots_incomplete_unresolved"
        resolved_field = "failure_resolved" if failure_kind == "backup" else "snapshots_resolved"
    original[records].append(failed)
    unrelated[records].append(retry)
    settings = {**SETTINGS, "retry_suffix": "-retry"}

    summary = vb.summarize([original, unrelated], settings, NOW)
    assert summary[unresolved] == 1
    assert summary["failures_resolved_by_retry"] == 0
    assert failed[resolved_field] is False
    assert failed["resolved_by_retry"] is False

    original[records].append(dict(retry))
    recovered = vb.summarize([original, unrelated], settings, NOW)
    assert recovered[unresolved] == 0
    assert recovered["failures_resolved_by_retry"] == 1
    assert failed[resolved_field] is True
    assert failed["resolved_by_retry"] is True


def test_a_validation_label_not_in_key_value_form_is_bad_config():
    assert vb.parse_label("validation-test=true") == ("validation-test", "true")
    assert vb.parse_label("validation-test") is None and vb.parse_label("=true") is None and vb.parse_label(None) is None


def test_unresolved_counts_stay_null_when_a_location_is_unread():
    s = vb.summarize([location(read=False, restores_read=False)], SETTINGS, NOW)
    assert (s["backups_failed_unresolved"], s["restores_with_errors_unresolved"]) == (None, None)


def test_blob_reads_retry_a_dropped_connection(monkeypatch):
    import requests

    class Flaky:
        calls = 0

        def get(self, url, **kw):
            Flaky.calls += 1
            if Flaky.calls == 1:
                raise requests.ConnectionError("reset")
            return _Resp(200, content=_list_xml(["backups/b1/velero-backup.json"]))

    monkeypatch.setattr(vb.time, "sleep", lambda s: None)
    reader = vb.BlobReader(namedtuple("C", "session cred")(Flaky(), _Cred()), [ENDPOINT])
    assert [b["name"] for b in reader.list(ENDPOINT, "velero", "backups/")] == ["backups/b1/velero-backup.json"]
    assert Flaky.calls == 2


def test_blob_list_xml_with_an_entity_declaration_is_refused():
    evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><EnumerationResults><Blobs/></EnumerationResults>'

    class Evil:
        def get(self, url, **kw):
            return _Resp(200, content=evil)

    reader = vb.BlobReader(namedtuple("C", "session cred")(Evil(), _Cred()), [ENDPOINT])
    with pytest.raises(Exception, match="(?i)entit|forbidden"):
        reader.list(ENDPOINT, "velero", "backups/")


def test_a_gap_that_crosses_the_window_start_counts_only_runs_due_inside_it():
    # Daily backups with the default 30-day retention and a 7-day lookback.
    now = datetime(2026, 11, 16, 3, 0, tzinfo=timezone.utc)
    window_start = now - timedelta(days=7)

    def day(d):
        return now - timedelta(days=d, hours=1)  # each backup finished at 02:00, d days ago

    # Backups stopped from day -20 to day -7 and succeeded every day since day -6: nothing due in the window was missed.
    recovered = [day(d) for d in range(30, 20, -1)] + [day(d) for d in range(6, 0, -1)]
    assert vb.count_missed(sorted(recovered), 24, window_start, now) == 0
    # An outage from day -10 to day -3: only the four runs due inside the window count, not the seven of the whole gap.
    outage = [day(d) for d in range(30, 10, -1)] + [day(d) for d in (2, 1)]
    assert vb.count_missed(sorted(outage), 24, window_start, now) == 4


def test_a_failed_backup_without_a_schedule_stays_unresolved():
    failed = vb.backup_record("manual-failed", backup("manual-failed", phase="Failed", schedule=None, done_hours_ago=10), NOW, 24)
    later = vb.backup_record("manual-ok", backup("manual-ok", schedule=None, done_hours_ago=2), NOW, 24)
    s = vb.summarize([location([failed, later])], SETTINGS, NOW)
    assert (s["backups_failed"], s["backups_failed_unresolved"]) == (1, 1)
    scheduled_failed = vb.backup_record("d-failed", backup("d-failed", phase="Failed", done_hours_ago=10), NOW, 24)
    scheduled_ok = vb.backup_record("d-ok", backup("d-ok", done_hours_ago=2), NOW, 24)
    assert vb.summarize([location([scheduled_failed, scheduled_ok])], SETTINGS, NOW)["backups_failed_unresolved"] == 0


def test_a_clean_restore_of_something_else_never_resolves_a_failed_restore():
    # A failed restore, then a clean restore with an unrelated name: still a current failure.
    rs = [vb.restore_record("restore-app-a", results(errors=3), iso(NOW - timedelta(days=2))),
          vb.restore_record("restore-app-b", results(), iso(NOW - timedelta(days=1)))]
    s = vb.summarize([location([], rs)], {**SETTINGS, "retry_suffix": "-retry"}, NOW)
    assert (s["restores_with_errors"], s["restores_with_errors_unresolved"], s["failures_resolved_by_retry"]) == (1, 1, 0)
    retried = rs + [vb.restore_record("restore-app-a-retry", results(), iso(NOW - timedelta(hours=12)))]
    s = vb.summarize([location([], retried)], {**SETTINGS, "retry_suffix": "-retry"}, NOW)
    assert (s["restores_with_errors_unresolved"], s["failures_resolved_by_retry"]) == (0, 1)
