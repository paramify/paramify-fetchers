"""aks / redis cache / managed redis / rbac custom roles: a list that could not be read gives null counts, not 0."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

from resource_exclusions import ENV  # noqa: E402


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_null_counts_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


aks = _load("aks_cluster_configuration")
redis_cache = _load("redis_cache_configuration")
managed_redis = _load("managed_redis_configuration")
rbac = _load("rbac_custom_roles")

NOT_COUNTS = ("excluded_", "in_scope_", "resource_exclusion_patterns", "provider_registration_status")


def _run_refused(m, monkeypatch, tmp_path, collect_name, operation, filename, result):
    """Runs main() with the top-level list refused (a 403), as the collect function reports it."""
    def refuse(subscription_id, cred, collector, *args, **kwargs):
        collector.record(operation, PermissionError("(AuthorizationFailed) 403"))
        return result

    monkeypatch.setattr(m, collect_name, refuse)
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv(ENV, raising=False)
    code = m.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


@pytest.mark.parametrize("m, collect_name, operation, filename, result, sentinel", [
    (aks, "collect_clusters", "containerservice.managed_clusters.list", "azure_aks_cluster_configuration", None,
     "total_clusters"),
    (redis_cache, "collect_caches", "redis.redis.list_by_subscription", "azure_redis_cache_configuration", None,
     "total_caches"),
    (managed_redis, "collect_clusters", "redisenterprise.redis_enterprise.list", "azure_managed_redis_configuration",
     None, "total_clusters"),
    (rbac, "collect_custom_roles", "authorization.role_definitions.list", "azure_rbac_custom_roles", (None, 0),
     "custom_role_definitions"),
], ids=["aks", "redis_cache", "managed_redis", "rbac_custom_roles"])
def test_a_refused_list_leaves_every_count_null(m, collect_name, operation, filename, result, sentinel,
                                                monkeypatch, tmp_path):
    code, evidence = _run_refused(m, monkeypatch, tmp_path, collect_name, operation, filename, result)
    counts = {k: v for k, v in evidence["summary"].items() if not k.startswith(NOT_COUNTS)}
    assert code == 1 and sentinel in counts
    assert set(counts.values()) == {None}, {k: v for k, v in counts.items() if v is not None}


def test_summaries_of_a_read_empty_list_are_still_numbers():
    expected_pool_fields = set(aks.summarize_expected_pools(None, None))
    for summary in (aks.summarize([]), redis_cache.summarize([]), managed_redis.summarize([]), rbac.summarize([], 5)):
        # all_agent_pools_fips is null for a read estate with no pools, by design; the expected-pool fields are null
        # while their setting is unset (a policy not adopted stays unevaluated), never because the list was empty
        assert summary and all(v is not None for k, v in summary.items() if k != "all_agent_pools_fips" and k not in expected_pool_fields)
    assert rbac.summarize([], 5)["builtin_role_definitions"] == 5
    # Once listed, they are numbers for a read empty estate: a bound pool in a cluster that isn't there is missing.
    listed = aks.summarize([], aks.parse_expected_pools("prod-aks/web")[0])
    assert all(listed[k] is not None for k in expected_pool_fields)
    assert (listed["expected_autoscaling_pools_missing"], listed["all_expected_pools_autoscaling"]) == (1, False)


def _cache(extras):
    return redis_cache.cache_record({"id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cache/Redis/c",
                                     "name": "c", "sku_name": "Premium"}, extras)


FULL_EXTRAS = {"firewall_rules": [], "access_policies": [], "access_policy_assignments": [],
               "patch_schedule": [], "linked_servers": [], "diagnostic_settings": []}
SUBLIST_COUNTS = {
    "firewall_rules": "firewall_allows_all_ips_caches",
    "access_policy_assignments": "access_policy_assignments",
    "patch_schedule": "maintenance_window_caches",
    "linked_servers": "geo_replicated_caches",
    "diagnostic_settings": "audit_logging_enabled_caches",
}


@pytest.mark.parametrize("unread", sorted(SUBLIST_COUNTS))
def test_redis_cache_count_is_null_while_one_caches_sublist_is_unread(unread):
    read = _cache(FULL_EXTRAS)
    broken = _cache({**FULL_EXTRAS, unread: None})
    assert redis_cache.summarize([read])[SUBLIST_COUNTS[unread]] == 0
    summary = redis_cache.summarize([read, broken])
    assert summary[SUBLIST_COUNTS[unread]] is None
    assert all(summary[v] == 0 for k, v in SUBLIST_COUNTS.items() if k != unread)  # the other reads succeeded
    assert summary["total_caches"] == 2


def _cluster(databases):
    cluster = {"id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cache/redisEnterprise/c",
               "name": "c", "minimum_tls_version": "1.2"}
    return managed_redis.cluster_record(cluster, databases)


def test_managed_redis_database_counts_are_null_while_one_clusters_database_list_is_unread():
    database = managed_redis.database_record({"id": "d1", "client_protocol": "Encrypted",
                                              "access_keys_authentication": "Disabled"})
    read = _cluster([database])
    assert managed_redis.summarize([read])["total_databases"] == 1
    summary = managed_redis.summarize([read, _cluster(None)])
    for key in ("total_databases", "encrypted_protocol_databases", "plaintext_protocol_databases",
                "access_keys_disabled_databases", "access_keys_enabled_databases",
                "tls_only_clusters", "tls_only_percentage"):
        assert summary[key] is None, key
    assert summary["total_clusters"] == 2 and summary["databases_unread_clusters"] == 1
