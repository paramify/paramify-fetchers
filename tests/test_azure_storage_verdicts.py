"""Azure Storage geo-replication, access-key age, containers and ownership tags. Synthetic fixtures, no SDK or network."""

from __future__ import annotations

import importlib.util
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


st = _load("storage_encryption_status")
Collector = sys.modules["azure_common"].Collector

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-storage"


def collector():
    return Collector(logging.getLogger("test_storage"))


def account(name="sa1", sku="Standard_LRS", key1=None, key2=None, policy_days=None, tags=None,
            allow_public=False, **extra):
    return ns(
        id=f"{RG}/providers/Microsoft.Storage/storageAccounts/{name}", name=name, location="eastus",
        encryption=None, network_rule_set=None, sku=ns(name=sku), tags=tags,
        key_policy=ns(key_expiration_period_in_days=policy_days) if policy_days is not None else None,
        key_creation_time=ns(key1=key1, key2=key2), allow_blob_public_access=allow_public,
        primary_location="eastus", secondary_location="westus" if "GRS" in sku else None,
        status_of_primary="available", status_of_secondary="available" if "GRS" in sku else None,
        last_geo_failover_time=None, **extra,
    )


def record(model, **kw):
    return st.account_record(st.project_storage_account(model), NOW, **kw)


class StorageError(Exception):
    pass


def container(name, public="None", metadata=None, immutability=False, legal_hold=False, versioning=None):
    return ns(id=f"{RG}/c/{name}", name=name, public_access=public, metadata=metadata,
              has_immutability_policy=immutability, has_legal_hold=legal_hold,
              immutable_storage_with_versioning=versioning, last_modified_time=NOW)


class FakeClient:
    def __init__(self, accounts, stats=None, stats_error=None, containers=None, containers_error=None):
        def get_properties(group, name, expand=None):
            assert expand == "geoReplicationStats"
            if stats_error:
                raise stats_error
            return ns(geo_replication_stats=stats)

        def list_keys(*_, **__):
            raise AssertionError("listKeys must never be called")

        def list_containers(group, name):
            if containers_error:
                raise containers_error
            return iter(containers or [])

        props = ns(id="x", name="default", type="t", default_service_version=None,
                   container_delete_retention_policy=None, is_versioning_enabled=None,
                   share_delete_retention_policy=None, protocol_settings=None)
        self.storage_accounts = ns(list=lambda: iter(accounts), get_properties=get_properties, list_keys=list_keys,
                                   regenerate_key=list_keys, list_account_sas=list_keys, list_service_sas=list_keys)
        self.blob_services = ns(get_service_properties=lambda g, n: props)
        self.file_services = ns(get_service_properties=lambda g, n: props)
        self.blob_containers = ns(list=list_containers)


def collect(monkeypatch, *accounts, **client_kw):
    client = FakeClient(list(accounts), **client_kw)
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", ns(StorageManagementClient=lambda **_: client))
    c = collector()
    return st.collect_storage_accounts("sub", object(), c, NOW), c


# --- geo-replication ---

@pytest.mark.parametrize("sku, geo, read_access", [
    ("Standard_LRS", False, False), ("Standard_ZRS", False, False), ("Premium_LRS", False, False),
    ("Standard_GRS", True, False), ("Standard_GZRS", True, False),
    ("Standard_RAGRS", True, True), ("Standard_RAGZRS", True, True),
])
def test_geo_redundancy_from_sku(sku, geo, read_access):
    r = record(account(sku=sku))
    assert (r["geo_redundant"], r["read_access_secondary"]) == (geo, read_access)


def test_geo_stats_collected_with_sync_lag(monkeypatch):
    stats = ns(status="Live", last_sync_time=NOW - timedelta(minutes=12, seconds=30), can_failover=True,
               can_planned_failover=False, post_failover_redundancy="Standard_LRS", post_planned_failover_redundancy=None)
    (r,), c = collect(monkeypatch, account(sku="Standard_RAGRS"), stats=stats)
    g = r["geo_replication_stats"]
    assert (g["stats_status"], g["status"], g["sync_lag_minutes"], g["can_failover"], c.ok) == (
        "collected", "Live", 12, True, True)
    assert g["last_sync_time"] == "2026-10-19T11:47:30Z"
    summary = st.summarize([r])
    assert (summary["geo_redundant_accounts"], summary["geo_replication_live_accounts"],
            summary["geo_failover_ready_accounts"], summary["geo_replication_max_sync_lag_minutes"]) == (1, 1, 1, 12)


def test_locally_redundant_account_is_not_asked_for_stats(monkeypatch):
    (r,), c = collect(monkeypatch, account(sku="Standard_LRS"), stats_error=AssertionError("must not be called"))
    assert (r["geo_replication_stats"], c.ok) == (None, True)


def test_last_sync_time_unavailable_is_a_posture(monkeypatch):
    error = StorageError("(LastSyncTimeUnavailable) Last sync time is unavailable for account sa1.")
    (r,), c = collect(monkeypatch, account(sku="Standard_GRS"), stats_error=error)
    assert (r["geo_replication_stats"]["stats_status"], c.ok) == ("unavailable", True)


def test_other_geo_stats_failure_fails_the_run(monkeypatch):
    (r,), c = collect(monkeypatch, account(sku="Standard_GRS"), stats_error=StorageError("(500) boom"))
    assert (r["geo_replication_stats"]["stats_status"], c.ok) == ("failed", False)


def test_geo_account_with_no_stats_returned(monkeypatch):
    (r,), _ = collect(monkeypatch, account(sku="Standard_GRS"), stats=None)
    assert r["geo_replication_stats"]["stats_status"] == "not_applicable"


# --- access-key age ---

def test_key_age_against_expiry_policy():
    r = record(account(key1=NOW - timedelta(days=120), key2=NOW - timedelta(days=10), policy_days=90))
    assert [(k["name"], k["age_days"], k["exceeds_expiration_period"]) for k in r["access_keys"]] == [
        ("key1", 120, True), ("key2", 10, False)]
    assert (r["access_key_max_age_days"], r["access_keys_within_expiration_period"]) == (120, False)
    assert r["access_keys"][0]["created"] == "2026-06-21T12:00:00Z"


def test_key_age_without_policy_is_reported_but_not_judged():
    r = record(account(key1=NOW - timedelta(days=400), key2=NOW - timedelta(days=400)))
    assert [k["exceeds_expiration_period"] for k in r["access_keys"]] == [None, None]
    assert (r["access_key_max_age_days"], r["access_keys_within_expiration_period"]) == (400, None)
    summary = st.summarize([r])
    assert (summary["accounts_with_access_key_older_than_90_days"],
            summary["accounts_with_access_key_beyond_expiration_period"]) == (1, 0)


@pytest.mark.parametrize("key1, key2, within", [
    (None, None, None),
    (NOW - timedelta(days=5), None, None),
    (NOW - timedelta(days=100), None, False),
    (NOW - timedelta(days=5), NOW - timedelta(days=6), True),
])
def test_within_expiration_period(key1, key2, within):
    assert record(account(key1=key1, key2=key2, policy_days=90))["access_keys_within_expiration_period"] is within


def test_unknown_key_creation_time_counts_as_unknown_age():
    summary = st.summarize([record(account(key1=None, key2=None)), record(account(key1=NOW, key2=NOW))])
    assert (summary["access_key_age_known_accounts"], summary["access_key_max_age_days"]) == (1, 0)


def test_collection_never_calls_list_keys(monkeypatch):
    (r,), c = collect(monkeypatch, account(key1=NOW - timedelta(days=1), key2=NOW - timedelta(days=1)))
    assert (r["access_key_max_age_days"], c.ok) == (1, True)


# --- containers ---

def test_containers_with_access_level_metadata_keys_and_immutability(monkeypatch):
    listed = [
        container("public", public="Blob", metadata={"owner": "someone", "classification": "internal"}),
        container("locked", immutability=True, legal_hold=True, versioning=ns(enabled=True), metadata={}),
        container("unknown-meta"),
    ]
    (r,), c = collect(monkeypatch, account(allow_public=True), containers=listed)
    by_name = {x["name"]: x for x in r["containers"]}
    assert (r["containers_status"], c.ok) == ("collected", True)
    assert by_name["public"]["metadata_keys"] == ["classification", "owner"]
    assert "someone" not in str(r["containers"])
    assert (by_name["locked"]["metadata_keys"], by_name["unknown-meta"]["metadata_keys"]) == ([], None)
    assert (by_name["public"]["anonymous_access_effective"], by_name["locked"]["anonymous_access_effective"]) == (
        True, False)
    assert (by_name["locked"]["has_immutability_policy"], by_name["locked"]["has_legal_hold"],
            by_name["locked"]["version_level_immutability"]) == (True, True, True)
    summary = st.summarize([r])
    assert (summary["total_containers"], summary["containers_with_public_access_level"],
            summary["anonymously_accessible_containers"], summary["containers_with_immutability_policy"],
            summary["containers_with_legal_hold"]) == (3, 1, 1, 1, 1)


def test_public_container_level_is_not_effective_when_the_account_forbids_it(monkeypatch):
    (r,), _ = collect(monkeypatch, account(allow_public=False), containers=[container("c", public="Container")])
    assert (r["containers"][0]["public_access"], r["containers"][0]["anonymous_access_effective"]) == (
        "Container", False)


def test_account_without_blob_service_is_not_supported(monkeypatch):
    error = StorageError("(FeatureNotSupportedForAccount) Blob is not supported for the account.")
    (r,), c = collect(monkeypatch, account(), containers_error=error)
    assert (r["containers_status"], r["containers"], c.ok) == ("not_supported", None, True)


def test_container_list_failure_fails_the_run(monkeypatch):
    (r,), c = collect(monkeypatch, account(), containers_error=StorageError("(500) boom"))
    assert (r["containers_status"], c.ok) == ("failed", False)
    assert st.summarize([r])["accounts_with_containers_not_collected"] == 1


# --- ownership tags ---

def test_owner_and_classification_from_default_tag_keys():
    r = record(account(tags={"data-owner": "team-a", "Data Classification": "Confidential", "Env": "prod"}))
    assert (r["owner_tag"], r["classification_tag"]) == ("team-a", "Confidential")
    assert list(r["tags"]) == ["Data Classification", "Env", "data-owner"]


def test_configured_tag_keys_replace_the_defaults(monkeypatch):
    monkeypatch.setenv(st.OWNER_TAG_KEYS_ENV, "CostCenter, Application")
    monkeypatch.setenv(st.CLASSIFICATION_TAG_KEYS_ENV, "Exposure")
    (r,), _ = collect(monkeypatch, account(tags={"Application": "app", "Owner": "ignored", "exposure": "internal"}))
    assert (r["owner_tag"], r["classification_tag"]) == ("app", "internal")


def test_empty_tag_value_does_not_count():
    r = record(account(tags={"Owner": "", "OwnerEmail": "a@example.com"}))
    assert r["owner_tag"] == "a@example.com"
    summary = st.summarize([r, record(account(tags=None))])
    assert (summary["accounts_with_owner_tag"], summary["accounts_with_classification_tag"]) == (1, 0)


# --- the existing evidence is unchanged ---

def test_existing_account_and_summary_keys_are_kept():
    r = record(account())
    assert {"id", "name", "location", "resource_group", "encryption_type", "customer_managed_key",
            "infrastructure_encryption", "enable_https_traffic_only", "minimum_tls_version",
            "allow_blob_public_access", "public_network_access", "network_rule_set",
            "private_endpoint_connections", "key_expiration_period_in_days", "allow_shared_key_access",
            "default_to_entra_authorization", "replication_settings", "allow_cross_tenant_replication",
            "blob_properties", "file_service_properties"} <= set(r)
    assert {"total_storage_accounts", "customer_managed_key_storage", "platform_managed_key_storage",
            "cmk_percentage", "infrastructure_encryption_accounts", "https_only_accounts",
            "minimum_tls_1_2_accounts", "public_blob_access_accounts", "shared_key_access_accounts",
            "private_endpoint_accounts", "key_expiration_policy_accounts", "blob_versioning_accounts",
            "container_soft_delete_accounts", "share_soft_delete_accounts"} <= set(st.summarize([r]))
    assert st.account_record(st.project_storage_account(account()))["customer_managed_key"] is False
