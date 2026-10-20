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
    [
        (True, {"network_exposure": "public"}, True),
        (True, {"network_exposure": "internal"}, False),
        # External ingress on an environment with public network access Disabled is not internet-facing.
        (True, {"network_exposure": "private"}, False),
        (False, {"network_exposure": "public"}, False),
        (True, None, True),
    ],
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
        # Judged on width, not the exact 0.0.0.0-255.255.255.255 pair:
        ("Enabled", [_rule("0.0.0.0", "127.255.255.255"), _rule("128.0.0.0", "255.255.255.255")], "allow_all"),
        ("Enabled", [_rule("1.0.0.0", "255.255.255.255")], "broad"),  # near-total
        ("Enabled", [_rule("10.0.0.0", "10.255.255.255")], "restricted"),  # exactly a /8 is not broad
        # "Allow Azure services" admits every Azure-hosted client from any tenant, so it is broad:
        ("Enabled", [_rule("0.0.0.0", "0.0.0.0")], "broad"),
        ("Enabled", [_rule("10.0.0.1", "10.0.0.9"), _rule("0.0.0.0", "0.0.0.0")], "broad"),
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
    "credentials_type,stored",
    [
        ("AccountKey", True),
        ("Sas", True),
        ("ServicePrincipal", True),
        ("Certificate", True),
        ("KerberosKeytab", True),
        ("KerberosPassword", True),
        ("None", False),  # identity-based access
        (None, None),  # no type returned: unknown, never "no stored credential"
        ("SomethingNew", None),  # unrecognised type: unknown
    ],
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
        ("serverless", {"authMode": "Key"}, True, None),  # follows its workspace; resolved in collect
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
    assert instance["ssh_public"] is True and instance["public_ip"] is True  # enableNodePublicIp defaults to true
    cluster = hub.project_compute(
        {"name": "k", "properties": {"computeType": "AmlCompute", "properties": {"remoteLoginPortPublicAccess": "Enabled"}}}
    )
    assert cluster["ssh_public"] is True  # AmlCompute exposes SSH through remoteLoginPortPublicAccess
    closed = hub.project_compute(
        {"name": "k", "properties": {"computeType": "AmlCompute", "properties": {"remoteLoginPortPublicAccess": "Disabled"}}}
    )
    assert closed["ssh_public"] is False


def test_distinct_connections_count_inherited_once():
    def conn():
        return {"name": "c", "category": "AIServices", "auth_type": "ApiKey", "target": "https://x",
                "uses_stored_secret": True, "is_shared_to_all": True, "unauthenticated": False}

    base = dict(kind="Hub", network_exposure="open", private_endpoint_but_public_access=False, project_without_hub=False,
                managed_network_isolation_mode="Disabled", outbound_restricted=False, hbi_workspace=False,
                customer_managed_key=False, identity_based_datastore_access=False, data_isolation_enabled=False,
                v1_legacy_mode=False, identity_type="SystemAssigned", diagnostic_logs_exported=False,
                datastores=[], endpoints=[], computes=[])
    hub_a = {**base, "id": "/w/hub-a", "hub_resource_id": None, "connections": [conn()]}
    # A project repeats its hub's connections under its own id (measured live); counted once.
    project = {**base, "id": "/w/proj", "kind": "Project", "hub_resource_id": "/W/HUB-A", "connections": [conn()]}
    # A second hub with an identical connection is a separate connection, not merged by target.
    hub_b = {**base, "id": "/w/hub-b", "hub_resource_id": None, "connections": [conn()]}
    workspaces = [hub_a, project, hub_b]
    hub.mark_hub_repeats(workspaces)
    assert [c["repeats_hub_connection"] for w in workspaces for c in w["connections"]] == [False, True, False]
    summary = hub.summarize(workspaces)
    assert summary["total_connections"] == 3 and summary["distinct_connections"] == 2
    assert summary["distinct_connections_using_stored_secrets"] == 2


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
                               identity_providers=NS(azure_active_directory=NS(enabled=True), google=None, git_hub=NS(enabled=True),
                                                     apple=None, facebook=None, twitter=None, azure_static_web_apps=NS(enabled=True),
                                                     custom_open_id_connect_providers=None)))
    record = cw.project_auth_config([enabled])
    assert record["auth_enabled"] is True
    assert record["unauthenticated_client_action"] == "Return401"
    # azure-mgmt-appcontainers 5.x spells the attribute git_hub.
    assert record["auth_identity_providers"] == ["azure_active_directory", "azure_static_web_apps", "git_hub"]


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


def test_mongo_firewall_coverage_merges_overlaps():
    cover = ds.firewall_coverage([_rule("10.0.0.0", "10.0.0.255"), _rule("10.0.0.128", "10.0.1.255"), _rule("0.0.0.0", "0.0.0.0")])
    assert cover["firewall_allowed_address_count"] == 512  # overlap merged; Azure-services rule excluded


@pytest.mark.parametrize(
    "enabled,action,required",
    [
        (False, None, False),  # Easy Auth off
        (True, "AllowAnonymous", False),  # on, but every caller is let through
        (True, "Return401", True),
        (True, "RedirectToLoginPage", True),
        (True, None, None),  # on without an action: unknown, never read as protected
        (None, None, None),  # configs unread
    ],
)
def test_easy_auth_allow_anonymous_is_not_protection(enabled, action, required):
    assert cw.auth_required(enabled, action) is required


@pytest.mark.parametrize(
    "destination,diagnostics,exported",
    [
        ("log-analytics", None, True),  # the environment ships logs to the workspace itself
        ("azure-monitor", [], False),
        ("azure-monitor", [{"workspace_id": "ws", "logs": [{"category": "ContainerAppConsoleLogs", "enabled": True}]}], True),
        ("azure-monitor", None, None),  # settings unread
        (None, None, False),  # no destination
    ],
)
def test_environment_logs_exported(destination, diagnostics, exported):
    assert cw.environment_logs_exported(destination, diagnostics) is exported


# --------------------------------------------------------------------------- #
# collect()-level: the real collection paths over fake clients (no Azure SDK, no network)
# --------------------------------------------------------------------------- #

import logging  # noqa: E402
import types  # noqa: E402

from azure_common import Collector  # noqa: E402


class _Group:
    def __init__(self, **methods):
        self._methods = methods

    def __getattr__(self, name):
        return self._methods.get(name, lambda *a, **k: [])


class _Client:
    def __init__(self, **groups):
        self._groups = groups

    def __getattr__(self, name):
        return self._groups.get(name, _Group())


def _collector():
    return Collector(logging.getLogger("test"))


def _fake_module(monkeypatch, dotted, **attrs):
    module = types.ModuleType(dotted)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, dotted, module)


def test_collect_ai_hub(monkeypatch):
    hub_id, proj_id = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/h", f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/p"
    conn = lambda ws: {"id": f"{ws}/connections/aoai", "name": "aoai", "properties": {"authType": "ApiKey", "category": "AzureOpenAI"}}  # noqa: E731
    lists = {
        f"{SUB}/providers/Microsoft.MachineLearningServices/workspaces": [
            {"id": hub_id, "name": "h", "kind": "Hub", "properties": {}},
            {"id": proj_id, "name": "p", "kind": "Project", "properties": {"hubResourceId": hub_id}},
        ],
        f"{hub_id}/connections": [conn(hub_id)],
        f"{proj_id}/connections": [conn(proj_id)],
        f"{hub_id}/computes": [{"name": "k", "properties": {"computeType": "AmlCompute", "properties": {"remoteLoginPortPublicAccess": "Enabled"}}}],
        f"{hub_id}/datastores": [{"name": "d", "properties": {"credentials": {"credentialsType": "KerberosKeytab"}}}],
    }
    paths = []

    def list_all(client, path, version):
        paths.append(path)
        return {"items": lists.get(path, []), "pages": 1}

    monkeypatch.setattr(hub, "arm_rest_client", lambda cred: "rest")
    monkeypatch.setattr(hub, "list_all", list_all)
    monkeypatch.setattr(hub, "monitor_client", lambda sub, cred: "monitor")
    diag = {hub_id: [{"workspace_id": "ws", "logs": [{"category": "AmlComputeJobEvent", "enabled": True}]}], proj_id: []}
    monkeypatch.setattr(hub, "list_diagnostic_settings", lambda monitor, rid: diag[rid])
    records = {w["name"]: w for w in hub.collect(SUB.split("/")[-1], object(), _collector())}
    assert all("?" not in p for p in paths)  # api-version goes to list_all, never into the path
    assert records["h"]["computes"][0]["ssh_public"] is True
    assert records["h"]["datastores"][0]["stored_credentials"] is True
    assert records["h"]["diagnostic_logs_exported"] is True  # any log category, not only ComputeInstanceEvent
    assert records["p"]["diagnostic_logs_exported"] is False
    assert records["p"]["connections"][0]["repeats_hub_connection"] is True
    assert hub.summarize(list(records.values()))["distinct_connections"] == 1


def test_collect_container_apps(monkeypatch):
    env_id = f"{RG}/providers/Microsoft.App/managedEnvironments/e"
    env = {"id": env_id, "name": "e", "resource_group": "ai", "internal_only": False, "network_exposure": "public",
           "app_logs_destination": "log-analytics"}
    app = {"id": f"{RG}/providers/Microsoft.App/containerApps/a", "name": "a", "resource_group": "ai",
           "environment_id": env_id, "ingress_external": True}
    anonymous = NS(properties=NS(platform=NS(enabled=True), global_validation=NS(unauthenticated_client_action="AllowAnonymous"),
                                 identity_providers=None))
    apps_client = _Client(
        managed_environments=_Group(list_by_subscription=lambda: [env]),
        container_apps=_Group(list_by_subscription=lambda: [app]),
        container_apps_auth_configs=_Group(list_by_container_app=lambda rg, name: [anonymous]),
    )
    _fake_module(monkeypatch, "azure.mgmt.appcontainers", ContainerAppsAPIClient=lambda **k: apps_client)
    _fake_module(monkeypatch, "azure.mgmt.containerinstance", ContainerInstanceManagementClient=lambda **k: _Client())
    monkeypatch.setattr(cw, "project_environment", lambda e: dict(e))
    monkeypatch.setattr(cw, "project_workload", lambda kind, w: dict(w))
    monkeypatch.setattr(cw, "monitor_client", lambda sub, cred: "monitor")
    monkeypatch.setattr(cw, "list_diagnostic_settings", lambda monitor, rid: [])
    environments, apps, _, _ = cw.collect(SUB.split("/")[-1], object(), _collector())
    assert apps[0]["internet_facing"] is True and apps[0]["auth_enabled"] is True
    assert apps[0]["auth_required"] is False  # AllowAnonymous lets everyone in
    assert environments[0]["audit_logs_exported"] is True  # log-analytics, with no diagnostic settings at all


def test_collect_mongo_firewall_width(monkeypatch):
    cluster = {"id": f"{RG}/providers/Microsoft.DocumentDB/mongoClusters/m", "name": "m", "resource_group": "ai",
               "public_network_access": "Enabled"}
    halves = [NS(name=n, properties=NS(start_ip_address=a, end_ip_address=b))
              for n, a, b in (("low", "0.0.0.0", "127.255.255.255"), ("high", "128.0.0.0", "255.255.255.255"))]
    mongo = _Client(mongo_clusters=_Group(list=lambda: [cluster]),
                    firewall_rules=_Group(list_by_mongo_cluster=lambda rg, name: halves))
    _fake_module(monkeypatch, "azure.mgmt.mongocluster", MongoClusterMgmtClient=lambda **k: mongo)
    _fake_module(monkeypatch, "azure.mgmt.kusto", KustoManagementClient=lambda **k: _Client())
    _fake_module(monkeypatch, "azure.mgmt.eventhub", EventHubManagementClient=lambda **k: _Client())
    monkeypatch.setattr(ds, "project_mongo_cluster", lambda m: dict(m))
    monkeypatch.setattr(ds, "monitor_client", lambda sub, cred: "monitor")
    monkeypatch.setattr(ds, "list_diagnostic_settings", lambda monitor, rid: [
        {"workspace_id": "ws", "logs": [{"category": "vcoremongorequests", "enabled": True}]}])
    records, _, _ = ds.collect(SUB.split("/")[-1], object(), _collector())
    assert records[0]["public_access"] == "allow_all"  # two halves cover every address
    assert records[0]["firewall_allowed_address_percentage"] == 100.0
    assert records[0]["audit_logs_exported"] is True  # category matched case-insensitively


# --------------------------------------------------------------------------- #
# PR #149 review fixes
# --------------------------------------------------------------------------- #

import foundry_connections  # noqa: E402  (on sys.path once a fetcher is loaded)
import ip_ranges  # noqa: E402


@pytest.mark.parametrize(
    "target,expected",
    [
        ("mongodb://admin:pass@db.example.com:27017/app?ssl=true", "mongodb://db.example.com:27017/app"),
        ("https://user:token@github.com/org/repo.git", "https://github.com/org/repo.git"),
        ("https://acct.blob.core.windows.net/c?sv=2024&sig=SECRET", "https://acct.blob.core.windows.net/c"),
        (
            "Server=tcp:db.example.com,1433;Database=app;User ID=svc;Password=hunter2;",
            "Server=tcp:db.example.com,1433;Database=app;User ID=<redacted>;Password=<redacted>",
        ),
        (
            "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=abc==;EndpointSuffix=core.windows.net",
            "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=<redacted>;EndpointSuffix=core.windows.net",
        ),
        ("admin:pass@db.example.com", "db.example.com"),
        ("https://my-openai.openai.azure.com/", "https://my-openai.openai.azure.com/"),
        (None, ""),
    ],
)
def test_connection_target_never_keeps_credentials(target, expected):
    assert foundry_connections.strip_query(target) == expected


def test_connection_fields_redact_target():
    raw = {"name": "c", "properties": {"authType": "UsernamePassword", "target": "mongodb://admin:pass@h/db"}}
    assert foundry_connections.connection_fields(raw)["target"] == "mongodb://h/db"


@pytest.mark.parametrize(
    "entries,allow_all",
    [(["0.0.0.0/0"], True), (["0.0.0.0/1", "128.0.0.0/1"], True), (["10.0.0.0/8"], False),
     (["1.2.3.4"], False), (["::/0"], False), ([], False), (["not-an-ip"], False)],
)
def test_cidrs_allow_all(entries, allow_all):
    assert ip_ranges.cidrs_allow_all(entries) is allow_all


@pytest.mark.parametrize(
    "pna,allowlist,exposure",
    [("Enabled", ["1.2.3.4/32"], "restricted"), ("Enabled", ["0.0.0.0/0"], "open"), ("Disabled", ["0.0.0.0/0"], "private")],
)
def test_hub_allowlist_that_admits_everything_is_open(pna, allowlist, exposure):
    assert hub.network_exposure(pna, allowlist) == exposure


def _kusto(**overrides):
    fields = dict(id="k", name="k", location="eastus", tags=None, sku=None, zones=None, identity=None, state="Running",
                  public_network_access="Enabled", allowed_ip_range_list=["1.2.3.4/32"], virtual_network_configuration=None,
                  private_endpoint_connections=None, restrict_outbound_network_access="Disabled", allowed_fqdn_list=None,
                  enable_disk_encryption=True, enable_double_encryption=False, key_vault_properties=None,
                  trusted_external_tenants=[], accepted_audiences=None, enable_purge=False,
                  enable_streaming_ingest=False, callout_policies=None)
    fields.update(overrides)
    return ds.project_kusto_cluster(NS(**fields))


def test_kusto_allowlist_that_admits_everything_is_open():
    assert _kusto()["network_exposure"] == "restricted"
    assert _kusto(allowed_ip_range_list=["0.0.0.0/0"])["network_exposure"] == "open"


def test_kusto_vnet_injection_respects_state():
    assert _kusto(virtual_network_configuration=NS(state="Enabled", subnet_id="s"))["vnet_injected"] is True
    left = _kusto(virtual_network_configuration=NS(state="Disabled", subnet_id="s"))
    assert left["vnet_injected"] is False and left["vnet_injection_state"] == "Disabled"


def test_kusto_callout_policies_read_from_cluster_model():
    # Reader cannot call the listCalloutPolicies POST action; the cluster model carries the same data.
    policy = NS(callout_type="webapi", callout_uri_regex=".*", outbound_access="Allow", callout_id="x")
    assert _kusto(callout_policies=[policy])["callout_policies"][0]["allowed"] is True
    assert _kusto()["callout_policies"] == []  # Azure omits the property when none is set


def test_collect_does_not_call_list_callout_policies():
    import inspect
    assert "list_callout_policies" not in inspect.getsource(ds.collect)


@pytest.mark.parametrize("masks,exposure", [(["1.2.3.4"], "restricted"), (["0.0.0.0/0"], "open")])
def test_event_hubs_deny_with_allow_all_ip_rule_is_open(masks, exposure):
    rules = NS(default_action="Deny", public_network_access="Enabled", trusted_service_access_enabled=False,
               ip_rules=[NS(ip_mask=m) for m in masks], virtual_network_rules=[])
    record = ds.namespace_record(_namespace(), rules, [], [])
    assert record["network_exposure"] == exposure


def _hub_ws(kind, wid, hub_id=None, **props):
    raw = {"id": wid, "name": wid.rsplit("/", 1)[-1], "kind": kind, "properties": {"hubResourceId": hub_id, **props}}
    record = hub.project_workspace(raw)
    record["endpoints"] = []
    return record


def test_project_inherits_network_isolation_and_encryption_from_hub():
    hub_id = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/hub"
    parent = _hub_ws("Hub", hub_id, publicNetworkAccess="Disabled",
                        managedNetwork={"isolationMode": "AllowOnlyApprovedOutbound"},
                        encryption={"status": "Enabled", "keyVaultProperties": {"keyIdentifier": "https://kv/keys/k"}})
    project = _hub_ws("Project", f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/p", hub_id)
    assert project["network_exposure"] == "open"  # Azure's default before inheritance
    hub.apply_hub_inheritance([parent, project])
    assert project["network_exposure"] == "private"
    assert project["outbound_restricted"] is True and project["customer_managed_key"] is True
    assert project["inherited_from_hub"] == ["network_access", "managed_network_isolation", "encryption"]
    assert "_unset" not in project and "_unset" not in parent


def test_project_own_settings_win_and_unknown_hub_keeps_defaults():
    hub_id = f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/hub"
    parent = _hub_ws("Hub", hub_id, publicNetworkAccess="Disabled")
    own = _hub_ws("Project", f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/own", hub_id,
                     publicNetworkAccess="Enabled")
    orphan = _hub_ws("Project", f"{RG}/providers/Microsoft.MachineLearningServices/workspaces/o", "/other/hub")
    hub.apply_hub_inheritance([parent, own, orphan])
    # Its own network setting wins; isolation and encryption it left unset still come from the hub.
    assert own["network_exposure"] == "open" and "network_access" not in own["inherited_from_hub"]
    assert orphan["network_exposure"] == "open"  # hub not visible: Azure's default, never assumed private


@pytest.mark.parametrize("exposure,public", [("private", False), ("restricted", True), ("open", True)])
def test_serverless_endpoint_follows_workspace(exposure, public):
    endpoint = hub.project_endpoint({"name": "e", "properties": {"authMode": "Key"}}, "serverless")
    online = hub.project_endpoint({"name": "o", "properties": {"authMode": "Key", "publicNetworkAccess": "Enabled"}}, "online")
    workspace = {"network_exposure": exposure, "endpoints": [endpoint, online]}
    hub.resolve_serverless_public([workspace])
    assert endpoint["public"] is public and online["public"] is True


def test_container_group_log_analytics_counts_as_exported(monkeypatch):
    group = {"id": f"{RG}/providers/Microsoft.ContainerInstance/containerGroups/g", "name": "g", "resource_group": "ai",
             "log_analytics_configured": True}
    _fake_module(monkeypatch, "azure.mgmt.appcontainers", ContainerAppsAPIClient=lambda **k: _Client())
    aci = _Client(container_groups=_Group(list=lambda: [group]))
    _fake_module(monkeypatch, "azure.mgmt.containerinstance", ContainerInstanceManagementClient=lambda **k: aci)
    monkeypatch.setattr(cw, "project_container_group", lambda g: dict(g))
    monkeypatch.setattr(cw, "monitor_client", lambda sub, cred: "monitor")
    monkeypatch.setattr(cw, "list_diagnostic_settings", lambda monitor, rid: [])  # no diagnostic settings at all
    _, _, _, groups = cw.collect(SUB.split("/")[-1], object(), _collector())
    assert groups[0]["logs_exported"] is True


def test_marketplace_partner_destination_counts_as_exported():
    # #149 review [8]: the shared record must carry marketplace_partner_id, or diagnostics.py never sees it.
    import azure_common
    import diagnostics
    setting = NS(id="s", name="s", storage_account_id=None, workspace_id=None, event_hub_authorization_rule_id=None,
                 event_hub_name=None, marketplace_partner_id="/partner/datadog",
                 logs=[NS(category="ContainerInstanceLog", category_group=None, enabled=True)])
    record = azure_common.diagnostic_setting_record(setting)
    assert record["marketplace_partner_id"] == "/partner/datadog"
    assert diagnostics.audit_logging_summary([record], ("ContainerInstanceLog",))["audit_logging_enabled"] is True
