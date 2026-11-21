"""Summary counts added for capability Validators: database data encryption key source (PostgreSQL and MySQL), AKS
autoscaling node pools and node OS auto-upgrade. Runs without the Azure SDKs: the fetchers read models through
model_attr (attribute access), so SimpleNamespace stands in for the SDK objects and the projection code still runs.
That the SDK models still declare these fields is pinned in test_azure_sdk_surface.py (the azure-sdk CI job)."""

from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path
from types import SimpleNamespace as NS

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pg = _load("postgresql_configuration")
my = _load("mysql_configuration")
aks = _load("aks_cluster_configuration")


def _server(encryption):
    """The attributes the projections read; data_encryption absent when Azure returned none."""
    return NS(id="/subscriptions/s/resourceGroups/rg/providers/x/flexibleServers/db", name="db", type=None, location="eastus",
              version=None, state="Ready", fully_qualified_domain_name=None, auth_config=None,
              network=NS(public_network_access="Disabled", delegated_subnet_resource_id=None),
              backup=NS(backup_retention_days=7, geo_redundant_backup="Disabled"), high_availability=None,
              data_encryption=NS(type=encryption) if encryption else None)


def _record(module, project, encryption):
    params = list(inspect.signature(module.server_record).parameters)
    args = [project(_server(encryption))] + [{} if "param" in p else [] for p in params[1:]]
    return module.server_record(*args)


def test_postgresql_key_source_comes_through_the_projection():
    got = [_record(pg, pg.project_postgresql_server, e)["customer_managed_key"] for e in ("AzureKeyVault", "SystemManaged", None)]
    assert got == [True, False, None]


def test_mysql_key_source_comes_through_the_projection():
    got = [_record(my, my.project_mysql_server, e)["customer_managed_key"] for e in ("AzureKeyVault", "SystemManaged", None)]
    assert got == [True, False, None]


def test_database_summaries_count_customer_keys_and_keep_unknown_apart():
    for module, project in ((pg, pg.project_postgresql_server), (my, my.project_mysql_server)):
        s = module.summarize([_record(module, project, e) for e in ("AzureKeyVault", "SystemManaged", None)])
        assert (s["customer_managed_key_servers"], s["data_encryption_unknown_servers"]) == (1, 1)


def _cluster(channel, pools):
    return {"agent_pool_profiles": [{"enable_auto_scaling": a} for a in pools], "node_os_upgrade_channel": channel,
            "private_cluster": False, "api_server_access_restricted": False, "authorized_ip_ranges": [], "rbac_enabled": True,
            "azure_rbac_enabled": False, "local_accounts_disabled": False, "workload_identity_enabled": False,
            "network_policy_enabled": False, "auto_upgrade_enabled": False, "defender_enabled": False,
            "azure_monitor_enabled": False, "node_public_ip_pools": [], "kubernetes_version": "1.30"}


def test_aks_counts_autoscaling_pools_and_node_os_auto_upgrade():
    clusters = [_cluster("NodeImage", [True, False]), _cluster("SecurityPatch", [True]), _cluster("Unmanaged", [False]), _cluster(None, [])]
    s = aks.summarize(clusters)
    assert (s["autoscaling_agent_pools"], s["node_os_auto_upgrade_clusters"], s["node_os_upgrade_channel_unknown_clusters"]) == (2, 2, 1)
    # Unmanaged is its own count: not automatic, and not read as unpatched either.
    assert s["node_os_unmanaged_clusters"] == 1


def test_aks_new_counts_are_null_when_the_cluster_list_was_unread():
    s = aks.summarize(None)
    assert (s["autoscaling_agent_pools"], s["node_os_auto_upgrade_clusters"], s["node_os_upgrade_channel_unknown_clusters"]) == (None, None, None)
    assert s["node_os_unmanaged_clusters"] is None


# --- autoscaling for expected pools ---

def _pool(name, autoscaling, count, min_count=None):
    return {"name": name, "enable_auto_scaling": autoscaling, "count": count, "min_count": min_count, "mode": "User"}


def _aks(name, *pools):
    return aks.cluster_record({"id": f"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/{name}",
                               "name": name, "agent_pool_profiles": list(pools)})


def _staging():
    # A fixed-size system pool (deliberately not listed), and three autoscaling user pools, one scaled to zero.
    return _aks("stage-aks", _pool("system", False, 3), _pool("web", True, 4, 2), _pool("workers", True, 2, 1), _pool("batch", True, 0, 0))


def test_expected_pools_parse_pool_or_cluster_and_pool():
    expected, invalid = aks.parse_expected_pools("web, stage-aks/WORKERS, batch, x/Too-Long-Pool-Name, a/b/c, ")
    assert expected == [{"cluster": None, "pool": "web"}, {"cluster": "stage-aks", "pool": "workers"}, {"cluster": None, "pool": "batch"}]
    assert invalid == ["x/Too-Long-Pool-Name", "a/b/c"]


def test_every_expected_pool_autoscaling_passes_and_a_zero_node_pool_stays_expected():
    s = aks.summarize([_staging()], aks.parse_expected_pools("web, workers, batch")[0])
    assert (s["expected_autoscaling_pools"], s["expected_autoscaling_pools_missing"], s["expected_autoscaling_pools_not_autoscaling"]) == (3, 0, 0)
    assert (s["expected_autoscaling_pools_at_zero_nodes"], s["all_expected_pools_autoscaling"]) == (1, True)
    [batch] = [c for c in aks.expected_pool_checks([_staging()], [{"cluster": None, "pool": "batch"}])]
    assert (batch["present"], batch["node_count"], batch["min_count"]) == (True, 0, 0)


def test_missing_and_non_autoscaling_expected_pools_are_named():
    cluster = _aks("stage-aks", _pool("system", False, 3), _pool("web", False, 4), _pool("workers", True, 2, 1))
    s = aks.summarize([cluster], aks.parse_expected_pools("web, workers, batch")[0])
    assert (s["expected_autoscaling_pools_missing_names"], s["expected_autoscaling_pools_not_autoscaling_names"]) == (
        ["stage-aks/batch"], ["stage-aks/web"])
    assert s["all_expected_pools_autoscaling"] is False


def test_a_bound_pool_in_a_cluster_that_is_not_there_is_missing():
    s = aks.summarize([_staging()], aks.parse_expected_pools("prod-aks/web")[0])
    assert (s["expected_autoscaling_pools"], s["expected_autoscaling_pools_missing_names"], s["all_expected_pools_autoscaling"]) == (
        1, ["prod-aks/web"], False)


def test_an_unbound_pool_is_checked_in_every_cluster():
    other = _aks("tools-aks", _pool("system", False, 1))
    s = aks.summarize([_staging(), other], aks.parse_expected_pools("web")[0])
    assert (s["expected_autoscaling_pools"], s["expected_autoscaling_pools_missing_names"]) == (2, ["tools-aks/web"])
    bound = aks.summarize([_staging(), other], aks.parse_expected_pools("stage-aks/web")[0])
    assert (bound["expected_autoscaling_pools"], bound["all_expected_pools_autoscaling"]) == (1, True)


def test_expected_pool_fields_are_null_while_unset_or_when_clusters_were_unread():
    unset = aks.summarize([_staging()])
    assert {k: unset[k] for k in aks.summarize_expected_pools(None, None)} == dict.fromkeys(aks.summarize_expected_pools(None, None))
    unread = aks.summarize(None, aks.parse_expected_pools("web")[0])
    assert all(unread[k] is None for k in aks.summarize_expected_pools(None, None))


def test_min_count_comes_through_the_projection():
    profile = NS(name="batch", enable_auto_scaling=True, count=0, min_count=0, max_count=5)
    assert aks.project_agent_pool_profile(profile)["min_count"] == 0
