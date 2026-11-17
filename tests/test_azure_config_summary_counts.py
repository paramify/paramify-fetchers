"""Summary counts added for capability Validators: database data encryption key source (PostgreSQL and MySQL), AKS
autoscaling node pools and node OS auto-upgrade. Built from real SDK models deserialized from wire JSON, so an SDK that
renamed a field would fail here instead of reading every server as unknown. No network."""

from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

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


def _record(module, projected):
    params = list(inspect.signature(module.server_record).parameters)
    args = [projected] + [{} if "param" in p else [] for p in params[1:]]
    return module.server_record(*args)


def _pg(encryption):
    from azure.mgmt.postgresqlflexibleservers.models import Server
    props = {"backup": {"backupRetentionDays": 7, "geoRedundantBackup": "Disabled"}}
    if encryption:
        props["dataEncryption"] = {"type": encryption}
    return _record(pg, pg.project_postgresql_server(Server({"id": "/subscriptions/s/resourceGroups/rg/providers/x/flexibleServers/pg",
                                                            "name": "pg", "properties": props})))


def _my(encryption):
    from azure.mgmt.rdbms.mysql_flexibleservers.models import Server
    props = {"backup": {"backupRetentionDays": 7, "geoRedundantBackup": "Disabled"}}
    if encryption:
        props["dataEncryption"] = {"type": encryption}
    return _record(my, my.project_mysql_server(Server.deserialize({"id": "/subscriptions/s/resourceGroups/rg/providers/x/flexibleServers/my",
                                                                   "name": "my", "properties": props})))


def test_postgresql_key_source_is_read_from_the_sdk_model():
    assert (_pg("AzureKeyVault")["customer_managed_key"], _pg("SystemManaged")["customer_managed_key"], _pg(None)["customer_managed_key"]) == (True, False, None)


def test_mysql_key_source_is_read_from_the_sdk_model():
    assert (_my("AzureKeyVault")["customer_managed_key"], _my("SystemManaged")["customer_managed_key"], _my(None)["customer_managed_key"]) == (True, False, None)


def test_database_summaries_count_customer_keys_and_keep_unknown_apart():
    for module, make in ((pg, _pg), (my, _my)):
        s = module.summarize([make("AzureKeyVault"), make("SystemManaged"), make(None)])
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


def test_aks_new_counts_are_null_when_the_cluster_list_was_unread():
    s = aks.summarize(None)
    assert (s["autoscaling_agent_pools"], s["node_os_auto_upgrade_clusters"], s["node_os_upgrade_channel_unknown_clusters"]) == (None, None, None)


def test_aks_node_os_channel_comes_from_the_sdk_model():
    from azure.mgmt.containerservice.models import ManagedCluster
    cluster = ManagedCluster({"location": "eastus", "properties": {"autoUpgradeProfile": {"nodeOSUpgradeChannel": "SecurityPatch"}}})
    assert aks.project_managed_cluster(cluster)["node_os_upgrade_channel"] == "SecurityPatch"
