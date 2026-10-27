"""GCP fetcher verdict logic (Cloud SQL PITR, OS Login 2FA, GKE Binary Authorization): pure functions, no SDK or network."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GCP = REPO_ROOT / "fetchers" / "gcp"
sys.path.insert(0, str(GCP / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"gcp_{name}_under_test", GCP / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cloud_sql = _load("cloud_sql_encryption_status")
cloud_sql_backup = _load("cloud_sql_backup_configuration")
compute = _load("compute_instance_configuration")
gke = _load("gke_cluster_configuration")


# --- Cloud SQL point-in-time recovery (REST JSON, camelCase) ---

def sql_instance(database_version, **backup):
    return {"name": "db", "databaseVersion": database_version,
            "settings": {"backupConfiguration": {"enabled": True, **backup}}}


@pytest.mark.parametrize("version, backup, expected", [
    # MySQL recovers from the binary log; the generic toggle stays false there.
    ("MYSQL_8_0", {"pointInTimeRecoveryEnabled": False, "binaryLogEnabled": True}, True),
    ("MYSQL_8_0", {"binaryLogEnabled": True}, True),
    ("MYSQL_5_7", {"binaryLogEnabled": False}, False),
    # An unused toggle must not make a MySQL instance look protected.
    ("MYSQL_8_0", {"pointInTimeRecoveryEnabled": True, "binaryLogEnabled": False}, False),
    ("POSTGRES_15", {"pointInTimeRecoveryEnabled": True}, True),
    ("POSTGRES_15", {"pointInTimeRecoveryEnabled": False, "binaryLogEnabled": True}, False),
    ("SQLSERVER_2019_STANDARD", {"pointInTimeRecoveryEnabled": True}, True),
    ("SQLSERVER_2019_STANDARD", {}, False),
])
def test_cloud_sql_pitr_is_read_per_engine(version, backup, expected):
    record = cloud_sql.instance_record(sql_instance(version, **backup))
    assert record["point_in_time_recovery_enabled"] is expected
    assert record["pitr_toggle_enabled"] is bool(backup.get("pointInTimeRecoveryEnabled"))
    assert record["binary_log_enabled"] is bool(backup.get("binaryLogEnabled"))


def test_cloud_sql_pitr_agrees_with_the_backup_fetcher():
    for version in ("MYSQL_8_0", "POSTGRES_15", "SQLSERVER_2022_ENTERPRISE"):
        for toggle in (True, False):
            for binlog in (True, False):
                backup = {"pointInTimeRecoveryEnabled": toggle, "binaryLogEnabled": binlog}
                assert cloud_sql.point_in_time_recovery(backup, version) is \
                    cloud_sql_backup.point_in_time_recovery(backup, version)


def test_cloud_sql_summary_counts_pitr_instances():
    instances = [
        cloud_sql.instance_record(sql_instance("MYSQL_8_0", pointInTimeRecoveryEnabled=False, binaryLogEnabled=True)),
        cloud_sql.instance_record(sql_instance("POSTGRES_15", pointInTimeRecoveryEnabled=False)),
    ]
    assert cloud_sql.summarize(instances)["point_in_time_recovery_instances"] == 1


# --- Compute OS Login 2FA (GAPIC to_dict, metadata items) ---

def metadata(**flags):
    return {"items": [{"key": k.replace("_", "-"), "value": v} for k, v in flags.items()]}


def project(**flags):
    return compute.project_record({"commonInstanceMetadata": metadata(**flags)})


def vm(**flags):
    return {"name": "vm-1", "metadata": metadata(**flags)}


def test_project_2fa_without_os_login_is_not_enabled():
    defaults = project(enable_oslogin_2fa="TRUE")
    assert defaults["os_login_enabled"] is False
    assert defaults["os_login_2fa_configured"] is True
    assert defaults["os_login_2fa_enabled"] is False


def test_project_2fa_with_os_login_is_enabled():
    defaults = project(enable_oslogin="TRUE", enable_oslogin_2fa="TRUE")
    assert defaults["os_login_2fa_enabled"] is True


def test_instance_2fa_flag_without_os_login_is_not_counted():
    defaults = project()
    record = compute.instance_record(vm(enable_oslogin_2fa="TRUE"), defaults)
    assert record["os_login_enabled"] is False
    assert record["os_login_2fa_configured"] is True
    assert record["os_login_2fa_enabled"] is False
    summary = compute.summarize([record], defaults)
    assert summary["os_login_2fa_instances"] == 0
    assert summary["project_os_login_2fa_enabled"] is False


def test_instance_os_login_off_overrides_project_2fa():
    defaults = project(enable_oslogin="TRUE", enable_oslogin_2fa="TRUE")
    record = compute.instance_record(vm(enable_oslogin="FALSE"), defaults)
    assert record["os_login_2fa_configured"] is True
    assert record["os_login_2fa_enabled"] is False


def test_instance_os_login_on_inherits_project_2fa_flag():
    # Each key resolves on its own: OS Login from the instance, 2FA from the project
    # even though the project itself has OS Login off.
    defaults = project(enable_oslogin_2fa="TRUE")
    record = compute.instance_record(vm(enable_oslogin="TRUE"), defaults)
    assert record["os_login_enabled"] is True
    assert record["os_login_2fa_enabled"] is True
    assert compute.summarize([record], defaults)["os_login_2fa_instances"] == 1


def test_failed_project_call_defaults_everything_off():
    defaults = compute.project_record(None)
    assert defaults["os_login_2fa_enabled"] is False
    assert defaults["os_login_2fa_configured"] is False


# --- GKE Binary Authorization (GAPIC to_dict, string enums) ---

@pytest.mark.parametrize("binauthz, expected", [
    ({"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE", "enabled": False}, True),
    ({"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"}, True),
    # A newer enforcing mode the code has never seen still reads as enforcing.
    ({"evaluation_mode": "POLICY_BINDINGS", "enabled": False}, True),
    ({"evaluation_mode": "DISABLED", "enabled": False}, False),
    # The API ignores the deprecated flag once a mode is set.
    ({"evaluation_mode": "DISABLED", "enabled": True}, False),
    # No mode: the deprecated flag still decides.
    ({"evaluation_mode": "EVALUATION_MODE_UNSPECIFIED", "enabled": True}, True),
    ({"evaluation_mode": "EVALUATION_MODE_UNSPECIFIED", "enabled": False}, False),
    ({"enabled": True}, True),
    ({}, False),
    (None, False),
])
def test_gke_binary_authorization(binauthz, expected):
    cluster = {"name": "c1"}
    if binauthz is not None:
        cluster["binary_authorization"] = binauthz
    record = gke.cluster_record(cluster)
    assert record["binary_authorization_enabled"] is expected
    assert record["binary_authorization_legacy_enabled"] is bool((binauthz or {}).get("enabled"))


def test_gke_binary_authorization_reads_rest_spelling():
    record = gke.cluster_record(
        {"name": "c1", "binaryAuthorization": {"evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"}}
    )
    assert record["binary_authorization_enabled"] is True
    assert record["binary_authorization_mode"] == "PROJECT_SINGLETON_POLICY_ENFORCE"


def test_gke_summary_counts_evaluation_mode_clusters():
    clusters = [
        gke.cluster_record({"name": "enforce", "binary_authorization": {
            "evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE", "enabled": False}}),
        gke.cluster_record({"name": "off", "binary_authorization": {
            "evaluation_mode": "DISABLED", "enabled": False}}),
    ]
    assert gke.summarize(clusters)["binary_authorization_clusters"] == 1
