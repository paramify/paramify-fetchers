"""aks_cluster_configuration 0.3.0: node pool FIPS, node image, Trusted Launch and SSH fields. No network."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load():
    path = REPO_ROOT / "fetchers" / "azure" / "aks_cluster_configuration" / "fetcher.py"
    spec = importlib.util.spec_from_file_location("aks_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


aks = _load()


def pool(name, **kw):
    """A fake ManagedClusterAgentPoolProfile; unspecified attributes read as None, like a model that omits them."""
    base = dict(name=name, enable_node_public_ip=None, mode="System", count=3, vm_size="Standard_D4s_v5",
                os_type="Linux", os_sku="Ubuntu", os_disk_type=None, enable_encryption_at_host=True,
                enable_auto_scaling=None, orchestrator_version="1.31.2", vnet_subnet_id=None,
                enable_fips=None, node_image_version=None, security_profile=None)
    base.update(kw)
    return NS(**base)


def _records(pools):
    """Projection then normalization, the same two steps the fetcher runs on a real model."""
    return [aks.agent_pool_record(aks.project_agent_pool_profile(p)) for p in pools]


def test_fips_and_node_fields_are_projected_and_tri_state():
    pools = [
        pool("fips", enable_fips=True, node_image_version="AKSUbuntu-2204gen2fipscontainerd-202610.21.0",
             security_profile=NS(enable_secure_boot=True, enable_vtpm=True, ssh_access="Disabled")),
        pool("plain", enable_fips=False, node_image_version="AKSUbuntu-2204gen2containerd-202610.21.0",
             security_profile=NS(enable_secure_boot=False, enable_vtpm=False, ssh_access="LocalUser")),
        pool("old"),  # a pool whose API version returned none of the new fields
    ]
    recs = _records(pools)
    fips, plain, old = recs
    assert fips["enable_fips"] is True and fips["ssh_access"] == "Disabled" and fips["secure_boot_enabled"] is True
    assert plain["enable_fips"] is False and plain["ssh_access"] == "LocalUser" and plain["vtpm_enabled"] is False
    assert old["enable_fips"] is None and old["node_image_version"] is None and old["ssh_access"] is None
    assert old["secure_boot_enabled"] is None, "an omitted flag must stay unknown, never become False"


def test_node_security_summary_counts_unknown_apart():
    recs = _records([
        pool("a", enable_fips=True, node_image_version="img-2", security_profile=NS(enable_secure_boot=True, enable_vtpm=True, ssh_access="Disabled")),
        pool("b", enable_fips=True, node_image_version="img-1", security_profile=NS(enable_secure_boot=None, enable_vtpm=None, ssh_access="LocalUser")),
        pool("c"),
    ])
    s = aks.summarize_node_security(recs)
    assert s["fips_enabled_agent_pools"] == 2 and s["fips_disabled_agent_pools"] == 0 and s["fips_unknown_agent_pools"] == 1
    assert s["all_agent_pools_fips"] is None, "one unknown pool means the all-FIPS claim is not decidable"
    assert s["ssh_disabled_agent_pools"] == 1 and s["ssh_local_user_agent_pools"] == 1 and s["ssh_access_unknown_agent_pools"] == 1
    assert s["secure_boot_enabled_agent_pools"] == 1 and s["trusted_launch_unknown_agent_pools"] == 2
    assert s["node_image_versions"] == ["img-1", "img-2"]


def test_all_pools_fips_is_true_only_when_every_pool_answers_true():
    yes = _records([pool("a", enable_fips=True), pool("b", enable_fips=True)])
    no = _records([pool("a", enable_fips=True), pool("b", enable_fips=False)])
    assert aks.summarize_node_security(yes)["all_agent_pools_fips"] is True
    assert aks.summarize_node_security(no)["all_agent_pools_fips"] is False
    # No pools: nothing to judge, so null, not false.
    assert aks.summarize_node_security([])["all_agent_pools_fips"] is None and aks.summarize_node_security([])["fips_unknown_agent_pools"] == 0


def test_cluster_summary_carries_node_security_keys():
    recs = _records([pool("a", enable_fips=True)])
    cluster = {"private_cluster": False, "api_server_access_restricted": False, "authorized_ip_ranges": [],
               "rbac_enabled": True, "azure_rbac_enabled": False, "local_accounts_disabled": False,
               "workload_identity_enabled": False, "network_policy_enabled": False, "auto_upgrade_enabled": False,
               "defender_enabled": False, "azure_monitor_enabled": False, "node_public_ip_pools": [],
               "agent_pool_profiles": recs, "kubernetes_version": "1.31.2"}
    s = aks.summarize([cluster])
    assert s["fips_enabled_agent_pools"] == 1 and s["total_agent_pools"] == 1 and s["all_agent_pools_fips"] is True


def test_tri_state_reads_strings_by_text_not_truthiness():
    assert aks._tri_state("false") is False and aks._tri_state("True") is True
    assert aks._tri_state("") is None and aks._tri_state("maybe") is None and aks._tri_state(None) is None


@pytest.mark.parametrize("value", [None, False, True, "false"])
def test_cluster_observations_preserve_sdk_flags_before_normalization(value):
    cluster = NS(enable_rbac=value, disable_local_accounts=value,
                 api_server_access_profile=NS(enable_private_cluster=value))
    row = json.loads(json.dumps(aks.cluster_record(aks.project_managed_cluster(cluster))))
    observed = row["configuration_observations"]
    assert observed["rbac_enabled"] == value
    assert observed["local_accounts_disabled"] == value
    assert observed["enable_private_cluster"] == value
    assert type(observed["rbac_enabled"]) is type(value)
    # Existing normalized flags keep their meaning, including string truthiness.
    assert row["rbac_enabled"] is bool(value)
    assert row["local_accounts_disabled"] is bool(value)
    assert row["private_cluster"] is bool(value)


@pytest.mark.parametrize("ranges", [None, [], ["0.0.0.0/0"], ["0.0.0.0/32"], ["192.0.2.0/24"]])
def test_cluster_observations_preserve_nullable_authorized_ip_ranges(ranges):
    cluster = NS(api_server_access_profile=NS(enable_private_cluster=False, authorized_ip_ranges=ranges))
    row = json.loads(json.dumps(aks.cluster_record(aks.project_managed_cluster(cluster))))
    assert row["configuration_observations"]["authorized_ip_ranges"] == ranges
    assert row["authorized_ip_ranges"] == (ranges or [])
    # The native flag still treats any non-empty list as restricted; the
    # observation alone does not establish whether these ranges are approved.
    assert row["api_server_access_restricted"] is bool(ranges)


def test_omitted_cluster_fields_stay_unknown_in_observations():
    row = aks.cluster_record(aks.project_managed_cluster(NS()))
    assert row["configuration_observations"] == {
        "rbac_enabled": None,
        "local_accounts_disabled": None,
        "enable_private_cluster": None,
        "authorized_ip_ranges": None,
    }
    assert row["rbac_enabled"] is False
    assert row["local_accounts_disabled"] is False
    assert row["private_cluster"] is False
    assert row["authorized_ip_ranges"] == []
