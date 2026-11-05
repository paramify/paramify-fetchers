"""azure_backup_vault_protection: policy retention and schedule, instance protection, recovery point judgement, API version choice. Synthetic payloads, no SDK or network."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_backup_vault_protection_under_test",
                                               AZURE / "backup_vault_protection" / "fetcher.py")
bv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bv)
azure_rest = sys.modules["azure_rest"]
azure_common = sys.modules["azure_common"]
ResourceExclusions = sys.modules["resource_exclusions"].ResourceExclusions

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
SUB = "/subscriptions/s1"
VAULT = f"{SUB}/resourceGroups/rg1/providers/Microsoft.DataProtection/backupVaults/bv1"
POLICY = f"{VAULT}/backupPolicies/daily"
DISK = f"{SUB}/resourceGroups/rg-app/providers/Microsoft.Compute/disks/data1"
SETTINGS = {"retention_threshold_days": 30, "window_hours": 48, "lookback_days": 35, "rpo_hours": None}


def raw_policy(name="daily", interval="P1D", delete_after="P30D", store="VaultStore", extra_rules=()):
    rules = [
        {"name": "BackupDaily", "objectType": "AzureBackupRule",
         "backupParameters": {"backupType": "Incremental", "objectType": "AzureBackupParams"},
         "dataStore": {"dataStoreType": store, "objectType": "DataStoreInfoBase"},
         "trigger": {"objectType": "ScheduleBasedTriggerContext",
                     "schedule": {"repeatingTimeIntervals": [f"R/2026-01-01T02:00:00+00:00/{interval}"],
                                  "timeZone": "UTC"}}},
        {"name": "Default", "objectType": "AzureRetentionRule", "isDefault": True,
         "lifecycles": [{"deleteAfter": {"duration": delete_after, "objectType": "AbsoluteDeleteOption"},
                         "sourceDataStore": {"dataStoreType": store, "objectType": "DataStoreInfoBase"}}]},
        *extra_rules,
    ]
    return {"id": f"{VAULT}/backupPolicies/{name}", "name": name,
            "properties": {"objectType": "BackupPolicy", "datasourceTypes": ["Microsoft.Compute/disks"],
                           "policyRules": rules}}


def raw_instance(n=1, state="ProtectionConfigured", policy=POLICY, source=DISK, kind="Microsoft.Compute/disks",
                 error=None):
    props = {
        "objectType": "BackupInstance", "friendlyName": f"disk{n}",
        "dataSourceInfo": {"datasourceType": kind, "resourceID": source, "resourceType": kind,
                           "resourceName": f"data{n}", "resourceLocation": "usgovvirginia", "objectType": "Datasource"},
        "policyInfo": {"policyId": policy}, "currentProtectionState": state,
        "protectionStatus": {"status": "ProtectionConfigured"}, "provisioningState": "Succeeded",
    }
    if error:
        props["protectionErrorDetails"] = error
    return {"id": f"{VAULT}/backupInstances/bi{n}", "name": f"bi{n}", "properties": props}


def raw_vault(name="bv1", store="GeoRedundant", soft_delete="On", immutability="Unlocked", crr="Enabled"):
    return {"id": f"{SUB}/resourceGroups/rg1/providers/Microsoft.DataProtection/backupVaults/{name}", "name": name,
            "location": "usgovvirginia", "identity": {"type": "SystemAssigned"},
            "properties": {"provisioningState": "Succeeded",
                           "storageSettings": [{"datastoreType": "VaultStore", "type": store}],
                           "securitySettings": {"softDeleteSettings": {"state": soft_delete, "retentionDurationInDays": 14},
                                                "immutabilitySettings": {"state": immutability}},
                           "featureSettings": {"crossRegionRestoreSettings": {"state": crr}},
                           "isVaultProtectedByResourceGuard": False, "replicatedRegions": ["usgovtexas"],
                           "bcdrSecurityLevel": "Good", "secureScore": "Adequate"}}


def raw_point(hours_ago, kind="Full", state="Completed", base=None):
    when = (base or NOW).timestamp() - hours_ago * 3600
    stamp = datetime.fromtimestamp(when, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"id": f"{VAULT}/backupInstances/bi1/recoveryPoints/{int(when)}",
            "properties": {"objectType": "AzureBackupDiscreteRecoveryPoint", "recoveryPointTime": stamp,
                           "recoveryPointType": kind, "recoveryPointState": state,
                           "recoveryPointDataStoresDetails": [{"type": "Snapshot"}, {"type": "BackupStorage"}]}}


# --- durations and schedules ---

@pytest.mark.parametrize("value, hours", [
    ("P1D", 24), ("PT4H", 4), ("P1W", 168), ("P30D", 720), ("P1M", 720), ("P1Y", 8760), ("P1DT12H", 36),
    ("p7d", 168), ("", None), (None, None), ("P", None), ("30 days", None),
])
def test_iso_durations_convert_to_hours(value, hours):
    assert bv.duration_hours(value) == hours


@pytest.mark.parametrize("value, hours", [
    ("R/2026-01-01T02:00:00+00:00/P1D", 24), ("R/2026-01-01T02:00:00Z/PT4H", 4), ("P1D", None), ("", None),
])
def test_repeating_interval_gives_the_backup_interval(value, hours):
    assert bv.interval_hours(value) == hours


def test_policy_record_reads_schedule_and_retention():
    weekly = {"name": "Weekly", "objectType": "AzureRetentionRule", "isDefault": False,
              "lifecycles": [{"deleteAfter": {"duration": "P12W"}, "sourceDataStore": {"dataStoreType": "VaultStore"},
                              "targetDataStoreCopySettings": [{"dataStore": {"dataStoreType": "ArchiveStore"},
                                                               "copyAfter": {"objectType": "ImmediateCopyOption"}}]}]}
    policy = bv.with_threshold(bv.policy_record(raw_policy(extra_rules=[weekly])), 30)
    assert (policy["backup_interval_hours"], policy["default_retention_days"], policy["max_retention_days"],
            policy["vaulted"], policy["meets_retention_threshold"]) == (24, 30, 84, True, True)
    assert policy["backup_rules"][0]["schedule_intervals"] == ["R/2026-01-01T02:00:00+00:00/P1D"]
    assert policy["retention_rules"][1]["lifecycles"][0]["copies_to"] == ["ArchiveStore"]


def test_policy_below_threshold_or_without_retention_does_not_meet_it():
    short = bv.with_threshold(bv.policy_record(raw_policy(delete_after="P7D")), 30)
    assert (short["max_retention_days"], short["meets_retention_threshold"]) == (7, False)
    raw = raw_policy()
    raw["properties"]["policyRules"] = [raw["properties"]["policyRules"][0]]
    none = bv.with_threshold(bv.policy_record(raw), 30)
    assert (none["max_retention_days"], none["meets_retention_threshold"]) == (None, False)


def test_operational_only_policy_is_not_vaulted():
    policy = bv.policy_record(raw_policy(store="OperationalStore"))
    assert policy["vaulted"] is False


# --- instances ---

def policies():
    return {azure_common.arm_id_key(POLICY): bv.with_threshold(bv.policy_record(raw_policy()), 30)}


def test_instance_record_joins_its_policy():
    record = bv.instance_record(raw_instance(), policies())
    assert {k: record[k] for k in ("policy_name", "policy_backup_interval_hours", "policy_max_retention_days",
                                   "meets_retention_threshold", "protected", "datasource_type", "protection_error")} == {
        "policy_name": "daily", "policy_backup_interval_hours": 24, "policy_max_retention_days": 30,
        "meets_retention_threshold": True, "protected": True, "datasource_type": "Microsoft.Compute/disks",
        "protection_error": None}


def test_instance_with_unknown_policy_or_error_state():
    record = bv.instance_record(raw_instance(policy=f"{VAULT}/backupPolicies/gone", state="ProtectionError",
                                             error={"code": "UserErrorX", "message": "boom"}), policies())
    assert (record["policy_name"], record["policy_max_retention_days"], record["meets_retention_threshold"],
            record["protected"], record["protection_error"]["code"]) == ("gone", None, None, False, "UserErrorX")


def test_an_unread_policy_list_leaves_retention_unknown_not_short():
    instances = [bv.instance_record(raw_instance(1), {}), bv.instance_record(raw_instance(2), policies())]
    judged_all = [bv.with_recovery_points(i, bv.RECOVERY_POINTS_READ, [], SETTINGS, NOW) for i in instances]
    summary = bv.summarize([vault_with(judged_all)], SETTINGS)
    # The unknown instance is neither adequate nor short, so no share of instances can be stated.
    assert (summary["backup_instances_meeting_retention_threshold"], summary["backup_instances_retention_unknown"],
            summary["retention_threshold_percentage"]) == (1, 1, None)


@pytest.mark.parametrize("kind, vaulted, applicable", [
    ("Microsoft.Compute/disks", True, True),
    ("Microsoft.Storage/storageAccounts/blobServices", False, False),
    ("AzureBlob", False, False),
    ("Microsoft.Storage/storageAccounts/blobServices", True, True),
    ("Microsoft.Storage/storageAccounts/blobServices", None, True),  # policy unread: do not assume continuous protection
])
def test_recovery_points_apply_unless_blob_backup_is_operational_only(kind, vaulted, applicable):
    instance = {"datasource_type": kind, "datasource_resource_type": "Microsoft.Storage/storageAccounts",
                "policy_vaulted": vaulted}
    assert bv.recovery_points_applicable(instance) is applicable


# --- recovery point judgement ---

def judged(points, status=bv.RECOVERY_POINTS_READ, interval=24, rpo=None):
    instance = {**bv.instance_record(raw_instance(), policies()), "policy_backup_interval_hours": interval}
    return bv.with_recovery_points(instance, status, [bv.recovery_point_record(p) for p in points],
                                   {**SETTINGS, "rpo_hours": rpo}, NOW)


def test_newest_point_inside_the_window_is_backed_up():
    record = judged([raw_point(30), raw_point(6), raw_point(100)])
    assert (record["recovery_points_in_window"], record["latest_recovery_point_age_hours"],
            record["backed_up_in_window"], record["recovery_point_overdue"],
            record["latest_recovery_point"]["data_stores"]) == (2, 6.0, True, False, ["BackupStorage", "Snapshot"])


def test_old_newest_point_is_not_backed_up_and_overdue():
    record = judged([raw_point(60)])
    assert (record["backed_up_in_window"], record["recovery_point_overdue"]) == (False, True)


def test_no_point_in_lookback_is_not_backed_up():
    record = judged([])
    assert (record["recovery_points_in_window"], record["latest_recovery_point"], record["backed_up_in_window"],
            record["recovery_point_overdue"]) == (0, None, False, True)


def test_overdue_follows_the_policy_interval_not_the_window():
    weekly = judged([raw_point(100)], interval=168)
    assert (weekly["backed_up_in_window"], weekly["recovery_point_overdue"]) == (False, False)
    unknown = judged([raw_point(100)], interval=None)
    assert unknown["recovery_point_overdue"] is None
    monthly = judged([raw_point(100)], interval=720)  # 2 x 30 days exceeds the 35-day lookback
    assert monthly["recovery_point_overdue"] is None


@pytest.mark.parametrize("rpo, meets", [(None, None), (4, False), (12, True)])
def test_recovery_point_objective(rpo, meets):
    assert judged([raw_point(6)], rpo=rpo)["meets_recovery_point_objective"] is meets


@pytest.mark.parametrize("status", [bv.RECOVERY_POINTS_ERROR, bv.RECOVERY_POINTS_NOT_APPLICABLE])
def test_unread_points_leave_every_verdict_null(status):
    record = judged([], status=status, rpo=4)
    assert (record["recovery_points_in_window"], record["backed_up_in_window"], record["recovery_point_overdue"],
            record["meets_recovery_point_objective"]) == (None, None, None, None)


# --- vaults and summary ---

def test_vault_record_reads_protection_settings():
    vault = bv.vault_record(raw_vault())
    assert {k: vault[k] for k in ("vault_store_redundancy", "soft_delete_enabled", "soft_delete_retention_days",
                                  "immutability_enabled", "cross_region_restore_enabled", "replicated_regions",
                                  "resource_group")} == {
        "vault_store_redundancy": "GeoRedundant", "soft_delete_enabled": True, "soft_delete_retention_days": 14,
        "immutability_enabled": True, "cross_region_restore_enabled": True, "replicated_regions": ["usgovtexas"],
        "resource_group": "rg1"}
    bare = bv.vault_record(raw_vault(store="LocallyRedundant", soft_delete="Off", immutability="Disabled", crr="Disabled"))
    assert (bare["soft_delete_enabled"], bare["immutability_enabled"], bare["cross_region_restore_enabled"]) == (
        False, False, False)


def vault_with(instances, instances_read=True):
    return {**bv.vault_record(raw_vault()), "backup_policies": list(policies().values()),
            "backup_instances": instances, "policies_read": True, "instances_read": instances_read,
            "total_backup_policies": 1, "total_backup_instances": len(instances) if instances_read else None}


def test_a_vault_whose_instance_list_failed_leaves_vault_verdicts_null():
    fresh = judged([raw_point(6)])
    summary = bv.summarize([vault_with([fresh]), vault_with([], instances_read=False)], SETTINGS)
    assert (summary["vaults_instances_listed"], summary["vaults_with_backup_instances"],
            summary["vaults_without_backup_instances"], summary["all_backup_instances_backed_up"],
            summary["total_backup_instances"]) == (False, None, None, None, None)
    # Every instance count is partial, so each reads null rather than a number a check could pass on.
    for key in ("backup_instances_not_backed_up_in_window", "backup_instances_backed_up_in_window",
                "backup_instances_overdue", "retention_threshold_percentage", "backup_instances_by_datasource_type"):
        assert summary[key] is None, key
    assert summary["retention_threshold_days"] == SETTINGS["retention_threshold_days"]


def test_summary_counts_backed_up_overdue_and_unknown():
    fresh = judged([raw_point(6)])
    stale = {**judged([raw_point(60)]), "id": f"{VAULT}/backupInstances/bi2"}
    failed = {**judged([], status=bv.RECOVERY_POINTS_ERROR), "id": f"{VAULT}/backupInstances/bi3"}
    blob = {**judged([], status=bv.RECOVERY_POINTS_NOT_APPLICABLE), "id": f"{VAULT}/backupInstances/bi4",
            "datasource_type": "Microsoft.Storage/storageAccounts/blobServices"}
    summary = bv.summarize([vault_with([fresh, stale, failed, blob])], SETTINGS)
    assert {k: summary[k] for k in (
        "total_backup_instances", "backup_instances_recovery_points_read", "backup_instances_backed_up_in_window",
        "backup_instances_not_backed_up_in_window", "backup_instances_overdue",
        "backup_instances_recovery_points_unknown", "backup_instances_recovery_points_not_applicable",
        "max_latest_recovery_point_age_hours", "all_backup_instances_backed_up", "retention_threshold_percentage",
        "all_backup_instances_meet_recovery_point_objective")} == {
        "total_backup_instances": 4, "backup_instances_recovery_points_read": 2,
        "backup_instances_backed_up_in_window": 1, "backup_instances_not_backed_up_in_window": 1,
        "backup_instances_overdue": 1, "backup_instances_recovery_points_unknown": 1,
        "backup_instances_recovery_points_not_applicable": 1, "max_latest_recovery_point_age_hours": 60.0,
        "all_backup_instances_backed_up": False, "retention_threshold_percentage": 100,
        "all_backup_instances_meet_recovery_point_objective": None}
    assert summary["backup_instances_by_datasource_type"] == {"Microsoft.Compute/disks": 3,
                                                               "Microsoft.Storage/storageAccounts/blobServices": 1}


def test_all_backed_up_is_null_when_any_is_unknown_and_true_when_all_are_fresh():
    fresh = judged([raw_point(6)])
    failed = {**judged([], status=bv.RECOVERY_POINTS_ERROR), "id": "x"}
    assert bv.summarize([vault_with([fresh, failed])], SETTINGS)["all_backup_instances_backed_up"] is None
    assert bv.summarize([vault_with([fresh])], SETTINGS)["all_backup_instances_backed_up"] is True
    assert bv.summarize([vault_with([])], SETTINGS)["all_backup_instances_backed_up"] is None
    assert bv.summarize([], SETTINGS)["total_backup_vaults"] == 0


@pytest.mark.parametrize("listed, chosen", [
    (["2023-05-01", "2024-04-01", "2025-07-01", "2026-07-01", "2026-08-31-preview"], "2025-07-01"),
    (["2023-05-01", "2024-04-01"], "2024-04-01"),
    (["2026-07-01"], "2025-07-01"),
    ([], "2025-07-01"),
])
def test_api_version_is_the_newest_stable_the_cloud_lists_at_or_below_the_preferred(listed, chosen):
    assert bv.choose_api_version(listed) == chosen


# --- collection through a fake ARM ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


class _Arm:
    """requests.Session for subscription s1: one vault (paged), one policy, two instances and their recovery points."""

    def __init__(self, registered=True, refuse_filter=False, refused=(), versions=None, failed_lists=()):
        self.registered, self.refuse_filter, self.refused = registered, refuse_filter, set(refused)
        self.failed_lists = tuple(failed_lists)  # path suffixes answered with 403
        self.versions = versions if versions is not None else ["2024-04-01", "2025-07-01", "2026-07-01"]
        self.urls: list[str] = []

    def get(self, url, params=None, headers=None, timeout=None):
        query = {**{k: v[0] for k, v in parse_qs(urlparse(url).query).items()}, **(params or {})}
        self.urls.append(url.split("?")[0] + "?" + "&".join(f"{k}={v}" for k, v in sorted(query.items())))
        path = urlparse(url).path
        if any(path.endswith(suffix) for suffix in self.failed_lists):
            return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
        if path.endswith("/providers/Microsoft.DataProtection"):
            return _Resp(200, {"registrationState": "Registered" if self.registered else "NotRegistered",
                               "resourceTypes": [{"resourceType": "backupVaults", "apiVersions": self.versions}]})
        if path.endswith("/providers/Microsoft.DataProtection/backupVaults"):
            if "skip" in url:
                return _Resp(200, {"value": [raw_vault("bv2", store="LocallyRedundant")]})
            next_link = f"https://management.azure.com{path}?api-version={query['api-version']}&$skipToken=skip"
            return _Resp(200, {"value": [raw_vault()], "nextLink": next_link})
        if path.endswith("/backupPolicies"):
            return _Resp(200, {"value": [raw_policy()] if "/bv1/" in path else []})
        if path.endswith("/backupInstances"):
            return _Resp(200, {"value": [raw_instance(1), raw_instance(2)] if "/bv1/" in path else []})
        if path.endswith("/recoveryPoints"):
            name = path.split("/")[-2]
            if name in self.refused:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            if query.get("$filter") and self.refuse_filter:
                return _Resp(400, {"error": {"code": "BadRequest", "message": "filter"}})
            # main() judges points against the real clock, so stamp them relative to it, not NOW
            return _Resp(200, {"value": [raw_point(6 if name == "bi1" else 90, base=datetime.now(timezone.utc))]})
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
    for env in ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", "AZURE_RESOURCE_EXCLUSIONS",
                bv.RPO_ENV, bv.WINDOW_ENV, bv.LOOKBACK_ENV, bv.RETENTION_THRESHOLD_ENV):
        monkeypatch.delenv(env, raising=False)
    return serve


def _evidence(tmp_path):
    [path] = tmp_path.glob("azure_backup_vault_protection_s1.json")
    return json.loads(path.read_text())


def test_main_reads_every_vault_policy_instance_and_recovery_point(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(bv.RPO_ENV, "24")
    session = arm()
    assert bv.main() == 0
    evidence = _evidence(tmp_path)
    assert evidence["metadata"]["partial_failure"] is False
    summary = evidence["summary"]
    assert (summary["total_backup_vaults"], summary["vaults_with_backup_instances"], summary["total_backup_policies"],
            summary["total_backup_instances"], summary["api_version"], summary["provider_registration_status"]) == (
        2, 1, 1, 2, "2025-07-01", "registered")
    assert (summary["backup_instances_backed_up_in_window"], summary["backup_instances_not_backed_up_in_window"],
            summary["backup_instances_overdue"], summary["all_backup_instances_backed_up"],
            summary["backup_instances_meeting_recovery_point_objective"],
            summary["all_backup_instances_meet_recovery_point_objective"]) == (1, 1, 1, False, 1, False)
    assert summary["vaults_by_vault_store_redundancy"] == {"GeoRedundant": 1, "LocallyRedundant": 1}
    [bv1, bv2] = evidence["results"]["backup_vaults"]
    assert [i["name"] for i in bv1["backup_instances"]] == ["bi1", "bi2"]
    assert bv1["backup_instances"][0]["latest_recovery_point"]["recovery_point_type"] == "Full"
    assert evidence["results"]["api_versions_listed"] == ["2024-04-01", "2025-07-01", "2026-07-01"]
    # Every request carried the chosen version, and recovery points were filtered to the lookback.
    assert {parse_qs(urlparse(u).query).get("api-version", [None])[0] for u in session.urls
            if "backupVaults" in u} == {"2025-07-01"}
    assert any("$filter" in u and "startDate" in u for u in session.urls)


def test_a_cloud_that_refuses_the_date_filter_lists_every_recovery_point(arm, tmp_path):
    session = arm(refuse_filter=True)
    assert bv.main() == 0
    assert _evidence(tmp_path)["summary"]["backup_instances_recovery_points_read"] == 2
    unfiltered = [u for u in session.urls if u.endswith("recoveryPoints?api-version=2025-07-01")]
    filtered = [u for u in session.urls if "recoveryPoints" in u and "$filter" in u]
    assert len(filtered) == 2
    assert len(unfiltered) == 2


def test_a_refused_recovery_point_list_fails_the_run_and_keeps_the_instance(arm, tmp_path):
    arm(refused=("bi2",))
    assert bv.main() == 1
    evidence = _evidence(tmp_path)
    assert evidence["metadata"]["partial_failure"] is True
    summary = evidence["summary"]
    assert (summary["backup_instances_recovery_points_read"], summary["backup_instances_recovery_points_unknown"],
            summary["all_backup_instances_backed_up"]) == (1, 1, None)
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_an_unregistered_provider_reports_no_vaults_and_succeeds(arm, tmp_path):
    session = arm(registered=False)
    assert bv.main() == 0
    summary = _evidence(tmp_path)["summary"]
    assert (summary["provider_registration_status"], summary["total_backup_vaults"]) == ("not_registered", 0)
    assert not any("backupVaults" in u for u in session.urls)


def test_a_cloud_listing_only_older_versions_uses_its_newest(arm, tmp_path):
    session = arm(versions=["2023-05-01", "2024-04-01"])
    assert bv.main() == 0
    assert _evidence(tmp_path)["summary"]["api_version"] == "2024-04-01"
    assert all("api-version=2024-04-01" in u for u in session.urls if "backupVaults" in u)


def test_exclusions_skip_a_vault_and_an_instance_by_its_protected_resource(arm, tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "id:*/backupVaults/bv2, rg:rg-app")
    session = arm()
    assert bv.main() == 0
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert (summary["total_backup_vaults"], summary["excluded_backup_vaults"], summary["total_backup_instances"],
            summary["excluded_backup_instances"], summary["resource_exclusion_patterns_unmatched"]) == (1, 1, 0, 2, [])
    assert {e["kind"] for e in evidence["results"]["excluded"]} == {"backup_vault", "backup_instance"}
    assert not any("/bv2/" in u or "recoveryPoints" in u for u in session.urls)


@pytest.mark.parametrize("env, value", [
    (bv.WINDOW_ENV, "1000"),  # 1000 hours of window inside a 35-day lookback
    (bv.RPO_ENV, "900"),
    (bv.RPO_ENV, "24h"),
    (bv.RPO_ENV, "0"),
])
def test_a_conflicting_or_malformed_setting_fails_as_bad_config(arm, tmp_path, monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    arm()
    assert bv.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


def test_an_unreadable_recovery_point_item_is_a_recorded_failure_not_a_crash(arm, tmp_path, monkeypatch):
    session = arm()
    real_get = session.get

    def get(url, params=None, headers=None, timeout=None):
        response = real_get(url, params=params, headers=headers, timeout=timeout)
        if "recoveryPoints" in url:
            return _Resp(200, {"value": ["not a recovery point"]})
        return response

    monkeypatch.setattr(session, "get", get)
    assert bv.main() == 1
    assert _evidence(tmp_path)["summary"]["backup_instances_recovery_points_unknown"] == 2


def test_an_invalid_exclusion_pattern_fails_the_run(arm, tmp_path):
    arm()
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AZURE_RESOURCE_EXCLUSIONS", "bv2")
        assert bv.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


VAULT_COUNTS = ("total_backup_vaults", "vaults_instances_listed", "soft_delete_enabled_vaults",
                "vaults_by_vault_store_redundancy", "total_backup_policies", "total_backup_instances",
                "backup_instances_not_backed_up_in_window", "retention_threshold_percentage", "in_scope_backup_vaults",
                "in_scope_backup_instances")


def test_a_refused_vault_list_leaves_every_count_null_not_zero(arm, tmp_path):
    arm(failed_lists=("/providers/Microsoft.DataProtection/backupVaults",))
    assert bv.main() == 1
    evidence = _evidence(tmp_path)
    assert evidence["metadata"]["partial_failure"] is True
    summary = evidence["summary"]
    for key in VAULT_COUNTS:
        assert summary[key] is None, key
    assert summary["retention_threshold_days"] == bv.DEFAULT_RETENTION_THRESHOLD_DAYS
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_a_refused_policy_list_leaves_the_policy_totals_null(arm, tmp_path):
    arm(failed_lists=("/bv1/backupPolicies",))
    assert bv.main() == 1
    summary = _evidence(tmp_path)["summary"]
    assert (summary["total_backup_policies"], summary["policies_meeting_retention_threshold"],
            summary["policies_without_readable_retention"]) == (None, None, None)
    # The vaults and instances were read, so their counts stand; retention can't be judged without the policy.
    assert (summary["total_backup_vaults"], summary["total_backup_instances"]) == (2, 2)
    assert (summary["backup_instances_retention_unknown"], summary["retention_threshold_percentage"]) == (2, None)


def test_a_refused_instance_list_leaves_every_instance_count_null(arm, tmp_path):
    arm(failed_lists=("/bv1/backupInstances",))
    assert bv.main() == 1
    summary = _evidence(tmp_path)["summary"]
    assert (summary["total_backup_vaults"], summary["vaults_instances_listed"], summary["total_backup_policies"]) == (
        2, False, 1)
    for key in ("total_backup_instances", "backup_instances_not_backed_up_in_window",
                "backup_instances_backed_up_in_window", "retention_threshold_percentage", "in_scope_backup_instances"):
        assert summary[key] is None, key
