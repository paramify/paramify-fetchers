"""Disk, Key Vault, storage and SQL Managed Instance fetchers: a list that could not be read gives null counts, never 0.

A fake client refuses the list (or a sub-list a count is built from) and the test asserts that every total, count and
percentage built from it is null; the lists the run did read keep their numbers.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace as ns

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_null_counts_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


disks = _load("disk_encryption_status")
vaults = _load("key_vault_configuration")
storage = _load("storage_encryption_status")
mi_encryption = _load("sql_managed_instance_encryption")
mi_backups = _load("sql_managed_instance_backups")

SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg-a"
DENIED = PermissionError("(AuthorizationFailed) 403 no read access")
NOT_COUNTS = ("provider_registration_status", "resource_exclusion_patterns", "resource_exclusion_patterns_unmatched")


def _denied(*_args, **_kwargs):
    raise DENIED


def _collector():
    return sys.modules["azure_common"].Collector(logging.getLogger("test"))


def _run(module, monkeypatch, tmp_path, filename):
    monkeypatch.setattr(module, "load_dotenv", lambda: None)
    monkeypatch.setattr(module, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(module, "credential", lambda: object())
    monkeypatch.setattr(module, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv(ENV, raising=False)
    code = module.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _assert_all_null(summary, keep=()):
    counts = {k: v for k, v in summary.items() if k not in NOT_COUNTS and k not in keep}
    assert counts and all(v is None for v in counts.values()), {k: v for k, v in counts.items() if v is not None}


# --- azure_disk_encryption_status ---

def test_disks_unread_list_gives_null_counts(monkeypatch, tmp_path, assert_summary_documented):
    client = ns(disks=ns(list=_denied))
    monkeypatch.setitem(sys.modules, "azure.mgmt.compute", ns(ComputeManagementClient=lambda **_: client))
    code, evidence = _run(disks, monkeypatch, tmp_path, "azure_disk_encryption_status")
    assert code == 1
    _assert_all_null(evidence["summary"])
    assert evidence["results"]["disks"] == []
    assert_summary_documented("azure/disk_encryption_status", evidence["summary"])


def test_disks_read_empty_list_still_counts_zero():
    summary = disks.summarize([])
    assert summary["total_disks"] == 0 and summary["cmk_percentage"] == 0


# --- azure_key_vault_configuration ---

def _vault(name):
    return ns(id=f"{RG}/providers/Microsoft.KeyVault/vaults/{name}", name=name, location="regionwest",
              properties=ns(enable_rbac_authorization=True))


def test_key_vaults_unread_list_gives_null_counts(monkeypatch, tmp_path, assert_summary_documented):
    client = ns(vaults=ns(list_by_subscription=_denied))
    monkeypatch.setitem(sys.modules, "azure.mgmt.keyvault", ns(KeyVaultManagementClient=lambda **_: client))
    code, evidence = _run(vaults, monkeypatch, tmp_path, "azure_key_vault_configuration")
    assert code == 1
    _assert_all_null(evidence["summary"])
    assert evidence["results"]["key_vaults"] == []
    assert_summary_documented("azure/key_vault_configuration", evidence["summary"])


def test_key_vaults_unread_diagnostic_settings_null_the_counts_built_from_them(monkeypatch):
    def settings(resource_uri):
        if resource_uri.endswith("kv-b"):
            raise DENIED
        return []

    client = ns(vaults=ns(list_by_subscription=lambda: [_vault("kv-a"), _vault("kv-b")]))
    monitor = ns(diagnostic_settings=ns(list=settings))
    monkeypatch.setitem(sys.modules, "azure.mgmt.keyvault", ns(KeyVaultManagementClient=lambda **_: client))
    monkeypatch.setitem(sys.modules, "azure.mgmt.monitor", ns(MonitorManagementClient=lambda **_: monitor))
    found = vaults.collect_key_vaults("s1", object(), _collector())
    summary = vaults.summarize(found)
    for key in ("vaults_with_diagnostic_settings", "vaults_with_audit_logging", "vaults_without_audit_logging",
                "audit_logging_percentage"):
        assert summary[key] is None, key
    assert summary["vaults_audit_logging_unknown"] == 1
    assert summary["total_key_vaults"] == 2 and summary["rbac_authorization_vaults"] == 2


# --- azure_storage_encryption_status ---

def _account(name):
    return ns(id=f"{RG}/providers/Microsoft.Storage/storageAccounts/{name}", name=name, location="regionwest",
              sku=ns(name="Standard_RAGRS"), encryption=ns(key_source="Microsoft.Storage"))


def _storage_client(accounts, containers, get_properties=None):
    return ns(
        storage_accounts=ns(list=accounts, get_properties=get_properties or (lambda *a, **k: ns(geo_replication_stats=None))),
        blob_services=ns(get_service_properties=lambda *a: ns()),
        file_services=ns(get_service_properties=lambda *a: ns()),
        blob_containers=ns(list=containers),
    )


def test_storage_unread_account_list_gives_null_counts(monkeypatch, tmp_path, assert_summary_documented):
    client = _storage_client(_denied, lambda *a: [])
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", ns(StorageManagementClient=lambda **_: client))
    code, evidence = _run(storage, monkeypatch, tmp_path, "azure_storage_encryption_status")
    assert code == 1
    _assert_all_null(evidence["summary"])
    assert evidence["summary"]["in_scope_containers"] is None
    assert_summary_documented("azure/storage_encryption_status", evidence["summary"])


def test_storage_unread_container_list_nulls_container_counts(monkeypatch, tmp_path, assert_summary_documented):
    def containers(group, name):
        if name == "sa-b":
            raise DENIED
        return [ns(id=f"{RG}/c1", name="c1", public_access="Blob")]

    client = _storage_client(lambda: iter([_account("sa-a"), _account("sa-b")]), containers)
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", ns(StorageManagementClient=lambda **_: client))
    code, evidence = _run(storage, monkeypatch, tmp_path, "azure_storage_encryption_status")
    summary = evidence["summary"]
    assert code == 1
    for key in ("total_containers", "containers_with_public_access_level", "anonymously_accessible_containers",
                "containers_with_immutability_policy", "containers_with_legal_hold", "in_scope_containers",
                "excluded_containers"):
        assert summary[key] is None, key
    assert summary["accounts_with_containers_not_collected"] == 1
    assert summary["total_storage_accounts"] == 2 and summary["in_scope_storage_accounts"] == 2
    assert_summary_documented("azure/storage_encryption_status", summary)


def test_storage_unread_replication_status_nulls_the_counts_built_from_it(monkeypatch):
    client = _storage_client(lambda: iter([_account("sa-a")]), lambda *a: [], _denied)
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", ns(StorageManagementClient=lambda **_: client))
    found = storage.collect_storage_accounts("s1", object(), _collector())
    summary = storage.summarize(found)
    assert summary["geo_redundant_accounts"] == 1
    assert summary["geo_replication_live_accounts"] is None and summary["geo_failover_ready_accounts"] is None


# --- azure_sql_managed_instance_encryption / _backups ---

MI = f"{RG}/providers/Microsoft.Sql/managedInstances/mi-a"


def _instance():
    return ns(id=MI, name="mi-a", location="eastus", state="Ready", current_backup_storage_redundancy="Geo",
              requested_backup_storage_redundancy="Geo")


def _mi_client(instances, databases, protector=None):
    def call(value):
        def fn(*args):
            if isinstance(value, Exception):
                raise value
            return value
        return fn

    return ns(
        managed_instances=ns(list=instances),
        managed_databases=ns(list_by_instance=call(databases)),
        managed_instance_encryption_protectors=ns(get=call(protector or ns(server_key_type="ServiceManaged"))),
        managed_database_transparent_data_encryption=ns(get=call(ns(state="Enabled"))),
        managed_backup_short_term_retention_policies=ns(get=call(ns(retention_days=7))),
        managed_instance_long_term_retention_policies=ns(get=call(ns(weekly_retention="P4W", monthly_retention="PT0S",
                                                                      yearly_retention="PT0S", week_of_year=0))),
        instance_failover_groups=ns(list_by_location=call([])),
    )


def _db():
    return ns(id=f"{MI}/databases/app", name="app", status="Online")


def test_mi_encryption_unread_instance_list_gives_null_counts(monkeypatch, tmp_path, assert_summary_documented):
    monkeypatch.setattr(mi_encryption, "sql_client", lambda *a: _mi_client(_denied, []))
    code, evidence = _run(mi_encryption, monkeypatch, tmp_path, "azure_sql_managed_instance_encryption")
    assert code == 1
    _assert_all_null(evidence["summary"])
    assert_summary_documented("azure/sql_managed_instance_encryption", evidence["summary"])


def test_mi_encryption_unread_database_list_nulls_tde_counts(monkeypatch):
    client = _mi_client(lambda: [_instance()], DENIED)
    monkeypatch.setattr(mi_encryption, "sql_client", lambda *a: client)
    summary = mi_encryption.summarize(mi_encryption.collect("s1", object(), _collector()))
    for key in ("total_user_databases", "tde_enabled_user_databases", "tde_disabled_user_databases",
                "tde_unknown_user_databases"):
        assert summary[key] is None, key
    assert summary["total_managed_instances"] == 1


def test_mi_encryption_unread_protector_nulls_key_counts(monkeypatch):
    client = _mi_client(lambda: [_instance()], [_db()], protector=DENIED)
    monkeypatch.setattr(mi_encryption, "sql_client", lambda *a: client)
    summary = mi_encryption.summarize(mi_encryption.collect("s1", object(), _collector()))
    assert summary["instances_customer_managed_key"] is None and summary["instances_key_auto_rotation"] is None
    assert summary["tde_enabled_user_databases"] == 1


def test_mi_backups_unread_instance_list_gives_null_counts(monkeypatch, tmp_path, assert_summary_documented):
    monkeypatch.setattr(mi_backups, "sql_client", lambda *a: _mi_client(_denied, []))
    monkeypatch.setattr(mi_backups, "read_failover_history", lambda *a: ([], {"days": 90, "complete": True}))
    code, evidence = _run(mi_backups, monkeypatch, tmp_path, "azure_sql_managed_instance_backups")
    summary = evidence["summary"]
    assert code == 1
    failover_fields = ("failover_history_days", "failover_history_read", *mi_backups.summarize_failovers(
        [], {"days": 90}, mi_backups.utc_now()))
    _assert_all_null(summary, keep=(*failover_fields, "excluded_failovers", "in_scope_failovers"))
    for key in ("total_managed_instances", "total_user_databases", "instances_by_current_backup_storage_redundancy",
                "total_instance_failover_groups", "in_scope_managed_instances", "in_scope_instance_failover_groups"):
        assert summary[key] is None, key
    assert_summary_documented("azure/sql_managed_instance_backups", summary)


def test_mi_backups_unread_database_list_nulls_database_counts(monkeypatch):
    client = _mi_client(lambda: [_instance()], DENIED)
    monkeypatch.setattr(mi_backups, "sql_client", lambda *a: client)
    found, groups, unlisted = mi_backups.collect("s1", object(), _collector())
    summary = mi_backups.summarize(found, groups, not unlisted)
    for key in ("total_user_databases", "databases_retention_at_least_7_days", "databases_retention_below_7_days",
                "databases_missing_retention_policy", "databases_retention_unknown",
                "databases_with_long_term_retention", "databases_long_term_retention_unknown"):
        assert summary[key] is None, key
    assert summary["total_managed_instances"] == 1


def test_mi_backups_unread_failover_group_list_nulls_membership_count(monkeypatch):
    client = _mi_client(lambda: [_instance()], [_db()])
    client.instance_failover_groups = ns(list_by_location=_denied)
    monkeypatch.setattr(mi_backups, "sql_client", lambda *a: client)
    found, groups, unlisted = mi_backups.collect("s1", object(), _collector())
    summary = mi_backups.summarize(found, groups, not unlisted)
    assert summary["instances_in_failover_group"] is None and summary["total_instance_failover_groups"] is None
    assert summary["instances_failover_group_unknown"] == 1


def test_storage_unread_service_properties_null_versioning_and_soft_delete_counts(monkeypatch):
    def blob_props(group, name):
        if name == "sa-b":
            raise DENIED
        return ns()

    def file_props(group, name):
        raise RuntimeError("File is not supported for the account.")

    client = _storage_client(lambda: iter([_account("sa-a"), _account("sa-b")]), lambda *a: [])
    client.blob_services = ns(get_service_properties=blob_props)
    client.file_services = ns(get_service_properties=file_props)
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", ns(StorageManagementClient=lambda **_: client))
    found = storage.collect_storage_accounts("s1", object(), _collector())
    assert {a["name"]: a["blob_properties_status"] for a in found} == {"sa-a": "collected", "sa-b": "failed"}
    assert {a["file_service_properties_status"] for a in found} == {"not_supported"}
    summary = storage.summarize(found)
    assert summary["blob_versioning_accounts"] is None and summary["container_soft_delete_accounts"] is None
    assert summary["share_soft_delete_accounts"] == 0  # not_supported is expected, not a failure


# --- a list that was read and is empty still counts 0 ---

def test_key_vaults_read_empty_list_counts_zero(monkeypatch, tmp_path):
    client = ns(vaults=ns(list_by_subscription=lambda: []))
    monkeypatch.setitem(sys.modules, "azure.mgmt.keyvault", ns(KeyVaultManagementClient=lambda **_: client))
    code, evidence = _run(vaults, monkeypatch, tmp_path, "azure_key_vault_configuration")
    summary = evidence["summary"]
    assert code == 0 and summary["total_key_vaults"] == 0 and summary["in_scope_key_vaults"] == 0
    assert summary["total_access_policies"] == 0


def test_storage_read_empty_list_counts_zero(monkeypatch, tmp_path):
    client = _storage_client(lambda: iter([]), lambda *a: [])
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", ns(StorageManagementClient=lambda **_: client))
    code, evidence = _run(storage, monkeypatch, tmp_path, "azure_storage_encryption_status")
    summary = evidence["summary"]
    assert code == 0 and summary["total_storage_accounts"] == 0 and summary["in_scope_storage_accounts"] == 0
    assert summary["total_containers"] == 0 and summary["in_scope_containers"] == 0


def test_mi_encryption_read_empty_list_counts_zero(monkeypatch, tmp_path):
    monkeypatch.setattr(mi_encryption, "sql_client", lambda *a: _mi_client(lambda: [], []))
    code, evidence = _run(mi_encryption, monkeypatch, tmp_path, "azure_sql_managed_instance_encryption")
    summary = evidence["summary"]
    assert code == 0 and summary["total_managed_instances"] == 0 and summary["in_scope_managed_instances"] == 0
    assert summary["tde_enabled_user_databases"] == 0


def test_mi_backups_read_empty_list_counts_zero(monkeypatch, tmp_path):
    monkeypatch.setattr(mi_backups, "sql_client", lambda *a: _mi_client(lambda: [], []))
    monkeypatch.setattr(mi_backups, "read_failover_history", lambda *a: ([], {"days": 90, "complete": True}))
    code, evidence = _run(mi_backups, monkeypatch, tmp_path, "azure_sql_managed_instance_backups")
    summary = evidence["summary"]
    assert code == 0 and summary["total_managed_instances"] == 0 and summary["in_scope_managed_instances"] == 0
    assert summary["total_instance_failover_groups"] == 0 and summary["in_scope_instance_failover_groups"] == 0
