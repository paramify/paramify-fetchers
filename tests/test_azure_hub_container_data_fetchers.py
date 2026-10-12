"""Decision logic of the AI hub, container workloads and data services fetchers.

No Azure SDK, credentials or network: the pure functions that decide what the evidence
claims, each case one whose verdict would be false evidence if it regressed — an unset
public-access value read as private, a 0.0.0.0-255.255.255.255 firewall rule read as
restricted, an unread rule set read as open, a Key Vault secret reference counted as a
secret stored in the app.

Run: ``pytest tests/test_azure_hub_container_data_fetchers.py``
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))


def _load(short_name: str):
    spec = importlib.util.spec_from_file_location(
        f"azure_{short_name}_under_test", AZURE / short_name / "fetcher.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hub = _load("ai_hub_configuration")
cw = _load("container_workloads_configuration")
ds = _load("data_services_configuration")

SUB = "/subscriptions/11111111-1111-1111-1111-111111111111"
RG = f"{SUB}/resourceGroups/ai"


# --------------------------------------------------------------------------- #
# AI hubs and projects
# --------------------------------------------------------------------------- #


def _workspace(kind="Hub", **props):
    return {"id": f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/w1", "name": "w1", "kind": kind,
            "properties": props}


@pytest.mark.parametrize(
    "props,exposure",
    [
        ({"publicNetworkAccess": "Disabled"}, "private"),
        ({"publicNetworkAccess": "Enabled", "ipAllowlist": ["1.2.3.4/32"]}, "restricted"),
        ({"publicNetworkAccess": "Enabled"}, "open"),
        ({}, "open"),  # Azure's default is Enabled
    ],
)
def test_workspace_network_exposure(props, exposure):
    assert hub.project_workspace(_workspace(**props))["network_exposure"] == exposure


def test_workspace_defaults_are_the_weak_settings():
    """Unset managed network, datastore auth and encryption read as Azure's defaults, not as protections."""
    record = hub.project_workspace(_workspace())
    assert record["managed_network_isolation_mode"] == "Disabled"
    assert record["outbound_restricted"] is False
    assert record["system_datastores_auth_mode"] == "accessKey"
    assert record["identity_based_datastore_access"] is False
    assert record["customer_managed_key"] is False


def test_workspace_protections_when_set():
    record = hub.project_workspace(
        _workspace(
            managedNetwork={"isolationMode": "AllowOnlyApprovedOutbound",
                            "outboundRules": {"pypi": {"type": "FQDN", "category": "UserDefined", "destination": "pypi.org"}}},
            systemDatastoresAuthMode="identity",
            encryption={"status": "Enabled", "keyVaultProperties": {"keyIdentifier": "https://kv/keys/k/1"}},
        )
    )
    assert record["outbound_restricted"] is True
    assert record["outbound_rules"] == [{"name": "pypi", "type": "FQDN", "category": "UserDefined",
                                         "destination": "pypi.org", "status": None}]
    assert record["identity_based_datastore_access"] is True
    assert record["customer_managed_key"] is True


def test_project_without_hub_is_flagged():
    assert hub.project_workspace(_workspace("Project"))["project_without_hub"] is True
    linked = hub.project_workspace(_workspace("Project", hubResourceId=f"{RG}/providers/x/workspaces/h"))
    assert linked["project_without_hub"] is False and linked["hub_name"] == "h"


@pytest.mark.parametrize(
    "auth,secret", [("ApiKey", True), ("AAD", False), ("ManagedIdentity", False), ("None", False), ("Brand New", None)]
)
def test_hub_connection_stored_secret(auth, secret):
    connection = hub.project_connection({"name": "c", "properties": {"authType": auth, "target": "https://x/?sig=S"}})
    assert connection["uses_stored_secret"] is secret
    assert connection["target"] == "https://x/"


# --------------------------------------------------------------------------- #
# Container workloads
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "vnet,pna,exposure",
    [
        (NS(internal=True, infrastructure_subnet_id="s"), None, "internal"),
        (NS(internal=False, infrastructure_subnet_id="s"), "Disabled", "private"),
        (NS(internal=False, infrastructure_subnet_id="s"), "Enabled", "public"),
        (None, None, "public"),  # consumption-only, no VNet: Azure's default is Enabled
    ],
)
def test_environment_exposure(vnet, pna, exposure):
    env = NS(id="e", name="e", location="eastus", tags=None, identity=None, vnet_configuration=vnet,
             public_network_access=pna, peer_authentication=None, peer_traffic_configuration=None,
             app_logs_configuration=None, zone_redundant=None, workload_profiles=None)
    record = cw.project_environment(env)
    assert record["network_exposure"] == exposure
    assert record["mtls_enabled"] is False and record["peer_traffic_encryption_enabled"] is False


@pytest.mark.parametrize(
    "key_vault_url,stored", [(None, True), ("https://kv.vault.azure.net/secrets/s", False)]
)
def test_secret_stored_in_app_unless_key_vault_reference(key_vault_url, stored):
    assert cw.project_secret(NS(name="s", key_vault_url=key_vault_url, identity=None))["stored_in_app"] is stored


@pytest.mark.parametrize(
    "identity,password_ref,password_based",
    [(None, "reg-pwd", True), ("system", "reg-pwd", False), (None, None, False)],
)
def test_registry_password_based(identity, password_ref, password_based):
    reg = NS(server="r.azurecr.io", identity=identity, password_secret_ref=password_ref)
    assert cw.project_registry(reg)["password_based"] is password_based


@pytest.mark.parametrize(
    "name,flagged",
    [("DD_API_KEY", True), ("DbConnectionString", True), ("CLIENT_SECRET", True), ("DD_SITE", False), ("LOG_LEVEL", False)],
)
def test_secret_like_env_var_names(name, flagged):
    assert cw.secret_like(name) is flagged


def test_instance_container_secure_env_vars_are_not_plain():
    """The Container Instances list response redacts secure values: neither value nor secureValue."""
    container = NS(name="c", image="gcr.io/x/agent:1", ports=None,
                   environment_variables=[NS(name="DD_API_KEY", value=None, secure_value=None),
                                          NS(name="DD_SITE", value="us", secure_value=None),
                                          NS(name="DB_PASSWORD", value="plain", secure_value=None)])
    record = cw.project_instance_container(container)
    assert record["env_vars_secure"] == 1 and record["env_vars_plain"] == 2
    assert record["plain_env_vars_with_secret_like_names"] == ["DB_PASSWORD"]
    assert record["registry"] == "gcr.io"


@pytest.mark.parametrize("image,registry", [("nginx:1.25", "docker.io"), ("myacr.azurecr.io/app:1", "myacr.azurecr.io"), ("localhost:5000/app", "localhost:5000")])
def test_registry_host(image, registry):
    assert cw.registry_host(image) == registry


def test_container_group_public_ip_and_stored_storage_key():
    group = NS(id="g", name="g", location="eastus", tags=None, os_type="Linux", identity=None, restart_policy="Always",
               ip_address=NS(type="Public", dns_name_label="app", ports=[NS(port=80)]), subnet_ids=None,
               containers=[], init_containers=None,
               image_registry_credentials=[NS(server="r", username="u", identity=None)],
               encryption_properties=None, confidential_compute_properties=None, diagnostics=None,
               volumes=[NS(azure_file=NS(share_name="s"), secret=None), NS(azure_file=None, secret={"k": "v"})])
    record = cw.project_container_group(group)
    assert record["public_ip"] is True and record["exposed_ports"] == [80]
    assert record["registries_password_based"] == 1
    assert record["azure_file_volumes"] == 1 and record["secret_volumes"] == 1


@pytest.mark.parametrize(
    "external,env,facing",
    [(True, {"internal_only": False}, True), (True, {"internal_only": True}, False), (False, {"internal_only": False}, False), (True, None, True)],
)
def test_internet_facing(external, env, facing):
    assert cw.internet_facing(external, env) is facing


# --------------------------------------------------------------------------- #
# Data services
# --------------------------------------------------------------------------- #


def _rule(start, end):
    return ds.project_firewall_rule(NS(name="r", properties=NS(start_ip_address=start, end_ip_address=end)))


def test_firewall_rule_classification():
    assert _rule("0.0.0.0", "255.255.255.255")["allow_all"] is True
    azure = _rule("0.0.0.0", "0.0.0.0")
    assert azure["allow_azure_services"] is True and azure["allow_all"] is False
    assert _rule("10.0.0.1", "10.0.0.9")["allow_all"] is False


@pytest.mark.parametrize(
    "pna,rules,expected",
    [
        ("Disabled", [_rule("0.0.0.0", "255.255.255.255")], "disabled"),
        ("Enabled", [_rule("0.0.0.0", "255.255.255.255")], "allow_all"),
        ("Enabled", [_rule("10.0.0.1", "10.0.0.9")], "restricted"),
        ("Enabled", [], "no_rules"),
    ],
)
def test_mongo_public_access(pna, rules, expected):
    assert ds.mongo_public_access(pna, rules) == expected


@pytest.mark.parametrize("version,below", [("1.0", True), ("1.1", True), ("1.2", False), (None, False)])
def test_tls_below_1_2(version, below):
    assert ds.tls_below_1_2(version) is below


def test_kusto_cluster_trust_and_exposure():
    cluster = NS(id="k", name="k", location="eastus", tags=None, sku=None, zones=None, identity=None, state="Running",
                 public_network_access="Enabled", allowed_ip_range_list=[], virtual_network_configuration=None,
                 private_endpoint_connections=None, restrict_outbound_network_access="Disabled", allowed_fqdn_list=None,
                 enable_disk_encryption=True, enable_double_encryption=False, key_vault_properties=None,
                 trusted_external_tenants=[NS(value="*")], accepted_audiences=None, enable_purge=True,
                 enable_streaming_ingest=False)
    record = ds.project_kusto_cluster(cluster)
    assert record["trusts_any_tenant"] is True
    assert record["network_exposure"] == "open"  # an empty allow-list does not restrict
    assert record["customer_managed_key"] is False and record["outbound_restricted"] is False


def test_kusto_database_periods_in_days():
    db = NS(id="d", name="c/d", kind="ReadWrite", soft_delete_period=timedelta(days=365), hot_cache_period=timedelta(days=31))
    record = ds.project_database(db)
    assert record["name"] == "d" and record["soft_delete_days"] == 365 and record["hot_cache_days"] == 31


@pytest.mark.parametrize("role,admin", [("AllDatabasesAdmin", True), ("Admin", True), ("AllDatabasesViewer", False), ("Viewer", False)])
def test_kusto_admin_roles(role, admin):
    assert ds.project_principal(NS(role=role, principal_type="User", principal_name="n", principal_id="p", tenant_id="t"))["admin"] is admin


def _namespace(pna="Enabled", disable_local_auth=False):
    return ds.project_namespace(NS(id="n", name="n", location="eastus", tags=None, sku=None, identity=None, status="Active",
                                   minimum_tls_version="1.2", public_network_access=pna, private_endpoint_connections=None,
                                   disable_local_auth=disable_local_auth, zone_redundant=True, kafka_enabled=True, encryption=None))


def _rules(default_action="Allow", pna="Enabled"):
    return NS(default_action=default_action, public_network_access=pna, trusted_service_access_enabled=False,
              ip_rules=[], virtual_network_rules=[])


@pytest.mark.parametrize(
    "namespace_pna,rules,exposure",
    [
        ("Enabled", _rules("Allow"), "open"),
        ("Enabled", _rules("Deny"), "restricted"),
        ("Enabled", _rules("Allow", "Disabled"), "private"),
        ("Disabled", _rules("Allow"), "private"),
        ("Enabled", None, None),  # rule set unread: unknown, not open
        ("Disabled", None, "private"),
    ],
)
def test_event_hub_network_exposure(namespace_pna, rules, exposure):
    record = ds.namespace_record(_namespace(namespace_pna), rules, [], [])
    assert record["network_exposure"] == exposure


def test_shared_key_full_control_needs_local_auth_and_manage_rights():
    manage = ds.project_authorization_rule(NS(name="RootManageSharedAccessKey", rights=["Listen", "Manage", "Send"]))
    listen = ds.project_authorization_rule(NS(name="reader", rights=["Listen"]))
    assert manage["manage"] is True and listen["manage"] is False
    assert ds.namespace_record(_namespace(), _rules(), [manage, listen], [])["shared_key_full_control"] is True
    assert ds.namespace_record(_namespace(disable_local_auth=True), _rules(), [manage], [])["shared_key_full_control"] is False
    assert ds.namespace_record(_namespace(), _rules(), None, [])["shared_key_full_control"] is None


def test_local_auth_enabled_by_default():
    assert _namespace(disable_local_auth=None)["local_auth_enabled"] is True
    assert _namespace(disable_local_auth=True)["local_auth_enabled"] is False


# --------------------------------------------------------------------------- #
# Review additions: datastores, endpoints, compute, Easy Auth, image provenance
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "credentials_type,stored", [("AccountKey", True), ("Sas", True), ("ServicePrincipal", True), ("None", False), (None, False)]
)
def test_datastore_stored_credentials(credentials_type, stored):
    raw = {"name": "d", "properties": {"datastoreType": "AzureBlob", "credentials": {"credentialsType": credentials_type}}}
    assert hub.project_datastore(raw)["stored_credentials"] is stored


@pytest.mark.parametrize(
    "kind,props,key_auth,public",
    [
        ("online", {"authMode": "Key", "publicNetworkAccess": "Enabled"}, True, True),
        ("online", {"authMode": "AADToken", "publicNetworkAccess": "Disabled"}, False, False),
        ("online", {"authMode": "AMLToken"}, False, True),  # unset public access defaults to Enabled
        ("serverless", {"authMode": "Key"}, True, True),  # serverless endpoints are always public
    ],
)
def test_endpoint_auth_and_exposure(kind, props, key_auth, public):
    record = hub.project_endpoint({"name": "e", "properties": props}, kind)
    assert record["key_auth"] is key_auth and record["public"] is public


def test_compute_defaults():
    aml = hub.project_compute({"name": "c", "properties": {"computeType": "AmlCompute", "properties": {}}})
    assert aml["public_ip"] is True  # AmlCompute nodes get public IPs unless switched off
    instance = hub.project_compute(
        {"name": "i", "properties": {"computeType": "ComputeInstance", "properties": {"sshSettings": {"sshPublicAccess": "Enabled"}}}}
    )
    assert instance["ssh_public"] is True and instance["public_ip"] is None


def test_distinct_connections_count_inherited_once():
    conn = {"name": "c", "category": "AIServices", "auth_type": "ApiKey", "target": "https://x", "uses_stored_secret": True,
            "is_shared_to_all": True, "unauthenticated": False}
    base = dict(kind="Hub", network_exposure="open", private_endpoint_but_public_access=False, project_without_hub=False,
                managed_network_isolation_mode="Disabled", outbound_restricted=False, hbi_workspace=False,
                customer_managed_key=False, identity_based_datastore_access=False, data_isolation_enabled=False,
                v1_legacy_mode=False, identity_type="SystemAssigned", diagnostic_logs_exported=False,
                datastores=[], endpoints=[], computes=[])
    workspaces = [{**base, "connections": [conn]}, {**base, "kind": "Project", "connections": [conn]}]
    summary = hub.summarize(workspaces)
    assert summary["total_connections"] == 2 and summary["distinct_connections"] == 1
    assert summary["distinct_connections_using_stored_secrets"] == 1


@pytest.mark.parametrize(
    "image,tag,mutable,digest",
    [
        ("datadoghq.azurecr.io/forwarder:latest", "latest", True, False),
        ("gcr.io/datadoghq/agent:7.66.1", "7.66.1", False, False),
        ("nginx", None, True, False),
        ("myacr.azurecr.io/app@sha256:abcd", None, False, True),
        ("localhost:5000/app:v1", "v1", False, False),  # the port colon is not a tag
    ],
)
def test_image_reference(image, tag, mutable, digest):
    assert cw.image_reference(image) == {"image_tag": tag, "image_tag_mutable": mutable, "image_pinned_by_digest": digest}


def test_easy_auth_states():
    assert cw.project_auth_config(None)["auth_enabled"] is None  # unread: unknown, never protected
    assert cw.project_auth_config([])["auth_enabled"] is False
    enabled = NS(properties=NS(platform=NS(enabled=True), global_validation=NS(unauthenticated_client_action="Return401"),
                               identity_providers=NS(azure_active_directory=NS(enabled=True), google=None, github=None,
                                                     apple=None, facebook=None, twitter=None, custom_open_id_connect_providers=None)))
    record = cw.project_auth_config([enabled])
    assert record["auth_enabled"] is True
    assert record["unauthenticated_client_action"] == "Return401"
    assert record["auth_identity_providers"] == ["azure_active_directory"]


def test_callout_policy_allowed():
    assert ds.project_callout_policy(NS(callout_type="sql", callout_uri_regex=".*", outbound_access="Allow"))["allowed"] is True
    assert ds.project_callout_policy(NS(callout_type="sql", callout_uri_regex=".*", outbound_access="Deny"))["allowed"] is False


def test_geo_replica_regions_exclude_primary():
    ns = NS(id="n", name="n", location="eastus", tags=None, sku=None, identity=None, status="Active",
            minimum_tls_version="1.2", public_network_access="Enabled", private_endpoint_connections=None,
            disable_local_auth=False, zone_redundant=True, kafka_enabled=True, encryption=None,
            geo_data_replication=NS(locations=[NS(location_name="eastus", role_type="Primary"), NS(location_name="westus", role_type="Secondary")]))
    record = ds.project_namespace(ns)
    assert record["geo_replication_locations"] == ["eastus", "westus"] and record["geo_replica_regions"] == 1
