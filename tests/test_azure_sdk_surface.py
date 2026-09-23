"""Pin the Azure SDK surface the fetchers actually read.

Every azure-mgmt major that has broken this category broke it SILENTLY — wrong or
empty evidence rather than an exception. requirements.txt lists six such changes,
and not one of them would have been caught here: CI installs `.[dev]` and
`.[dev,tui]` but never `.[azure]`, so no test in this suite has ever imported an
Azure SDK. A Dependabot PR widening an azure pin therefore goes green on evidence
that proves nothing about Azure — see PR #59, which relaxed the load-bearing
`azure-mgmt-monitor<7` and passed all twelve checks.

This module is that missing gate. It asserts the surface in the three shapes a
major bump actually takes it away:

    client import      the client class moved package       (PolicyClient)
    operation group    a group vanished off the client      (monitor 7)
    method             a method vanished off a group        (postgres 2)

plus the model-field renames that produce *wrong* rather than empty evidence
(sql 4, keyvault 14).

No credentials, no network: azure-mgmt clients build their operation groups
during __init__, so a fake credential that raises on use is enough to introspect
the entire surface. The whole module skips unless the azure extra is installed,
so the ordinary `.[dev]` jobs are unaffected. The `azure-sdk (surface)` CI job
installs `.[dev,azure]` and runs it — that job is what gates azure bumps.

This is deliberately NOT a return to the fixture-driven Azure fetcher tests
dropped in 65d59f3. Those pinned the shape of transforms, which live verification
covers directly. This pins the shape of the *vendor SDK*, which live verification
does not cover at all: a fetcher can only be verified against the one SDK version
that happens to be installed. Same intent as tools/crowdstrike_schema_check.py,
one rung lower — operation groups rather than response fields.

Adding a fetcher that reads a new operation group or model field? Add a row. The
cost of a row is one line; the cost of a missing row is a silently empty evidence
set in a customer's package.
"""

from __future__ import annotations

import importlib

import pytest

# The whole module is meaningless without the azure extra.
pytest.importorskip(
    "azure.mgmt.monitor",
    reason="azure extra not installed; run `pip install -e '.[dev,azure]'`",
)

SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"


class _FakeCredential:
    """Satisfies construction, refuses to be used.

    If anything here tries to authenticate, that is a bug in the test — the
    surface is meant to be readable without a tenant.
    """

    def get_token(self, *scopes: str, **kwargs: object) -> object:  # noqa: D102
        raise AssertionError("test_azure_sdk_surface must not make network calls")

    def close(self) -> None:  # noqa: D102
        pass


def _import(module: str, name: str) -> object:
    return getattr(importlib.import_module(module), name)


def _build(module: str, client_name: str) -> object:
    """Instantiate a management client offline.

    Two signatures are in play: most ARM clients take (credential,
    subscription_id), while Graph is tenant-scoped and takes (credential) alone.

    Data-plane clients (KeyClient) are deliberately NOT constructed here — they
    require a real vault URL, and their methods are plain class attributes, so
    the class itself is the honest thing to introspect: a `group` of None in
    REQUIRED_SURFACE introspects the class rather than an instance.
    """
    client_cls = _import(module, client_name)
    last: Exception | None = None
    for args in ((_FakeCredential(), SUBSCRIPTION_ID), (_FakeCredential(),)):
        try:
            return client_cls(*args)  # type: ignore[operator]
        except TypeError as exc:
            last = exc
    raise AssertionError(f"could not construct {client_name} offline: {last}")


def _model_fields(model: type) -> set[str]:
    """Declared field names, across both Azure model generations.

    msrest-era models carry `_attribute_map`; newer TypeSpec models carry
    `_attr_to_rest_field` plus plain annotations. Reading only one of them makes
    this check silently vacuous on half the SDKs.
    """
    found: set[str] = set()
    for attr in ("_attribute_map", "_attr_to_rest_field"):
        found |= set(getattr(model, attr, {}) or {})
    for klass in getattr(model, "__mro__", ()):
        found |= set(getattr(klass, "__annotations__", {}) or {})
    return {f for f in found if not f.startswith("_")}


# ---------------------------------------------------------------------------
# Client imports
# ---------------------------------------------------------------------------
# Several fetchers already do a lazy try/except across two homes; the candidate
# lists mirror that exactly, so a client living in either place passes. At least
# one must resolve.
#
# (label, [(module, class), ...], needed by)
CLIENT_IMPORTS: list[tuple[str, list[tuple[str, str]], str]] = [
    (
        "PolicyClient",
        [
            ("azure.mgmt.resource.policy", "PolicyClient"),
            ("azure.mgmt.resource", "PolicyClient"),
        ],
        "azure/policy_assignments — PolicyClient left azure-mgmt-resource for "
        "its own distribution (pinned ==1.0.0b3, pre-release only)",
    ),
    (
        "ResourceManagementClient",
        [
            ("azure.mgmt.resource.resources", "ResourceManagementClient"),
            ("azure.mgmt.resource", "ResourceManagementClient"),
        ],
        "_shared/azure_common — azure-mgmt-resource 26 dropped the root "
        "re-export; provider registration is how 'not in use' is told from "
        "'in use but empty'",
    ),
    (
        "RecoveryServicesBackupClient",
        [
            ("azure.mgmt.recoveryservicesbackup", "RecoveryServicesBackupClient"),
            (
                "azure.mgmt.recoveryservicesbackup.activestamp",
                "RecoveryServicesBackupClient",
            ),
        ],
        "azure/backup_recovery_status",
    ),
]


@pytest.mark.parametrize(
    "label,candidates,needed_by", CLIENT_IMPORTS, ids=[c[0] for c in CLIENT_IMPORTS]
)
def test_client_is_importable(
    label: str, candidates: list[tuple[str, str]], needed_by: str
) -> None:
    """A client with a relocated home must resolve from one of them."""
    tried = []
    for module, name in candidates:
        try:
            assert _import(module, name) is not None
            return
        except (ImportError, AttributeError) as exc:
            tried.append(f"{module}.{name}: {type(exc).__name__}")
    pytest.fail(
        f"{label} is not importable from any known home.\n"
        f"  tried: {'; '.join(tried)}\n"
        f"  needed by: {needed_by}\n"
        f"  A bump probably moved it again. Add the new home to this row and to "
        f"the fetcher's lazy import before widening the pin."
    )


# ---------------------------------------------------------------------------
# Operation groups and their methods
# ---------------------------------------------------------------------------
# The heart of the gate. Each row is one operation group a fetcher reads, with
# the methods it calls on it. A plain string is required; a TUPLE means "any of
# these", mirroring a fallback the fetcher already implements (postgres resolves
# servers.list vs servers.list_by_subscription at runtime).
#
# A group of None means the methods live on the client itself, not a group.
#
# (module, client, group | None, methods, affected fetchers)
Method = str | tuple[str, ...]
REQUIRED_SURFACE: list[tuple[str, str, str | None, list[Method], str]] = [
    # --- shared plumbing: every azure fetcher depends on these two -----------
    (
        "azure.mgmt.subscription",
        "SubscriptionClient",
        "subscriptions",
        ["list"],
        "_shared/azure_common — subscription discovery for all 27 fetchers",
    ),
    (
        "azure.mgmt.resource.resources",
        "ResourceManagementClient",
        "providers",
        ["get"],
        "_shared/azure_common — provider registration state (NOT_REGISTERED)",
    ),
    # --- monitor: the PR #59 regression -------------------------------------
    (
        "azure.mgmt.monitor",
        "MonitorManagementClient",
        "diagnostic_settings",
        ["list"],
        "azure/diagnostic_settings, azure/container_registry_configuration, "
        "azure/app_service_configuration",
    ),
    (
        "azure.mgmt.monitor",
        "MonitorManagementClient",
        "activity_log_alerts",
        ["list_by_subscription_id"],
        "azure/activity_log_alerts",
    ),
    # --- network: PR #57 widens this to <33 ---------------------------------
    (
        "azure.mgmt.network",
        "NetworkManagementClient",
        "network_security_groups",
        ["list_all"],
        "azure/network_security_groups",
    ),
    (
        "azure.mgmt.network",
        "NetworkManagementClient",
        "virtual_networks",
        ["list_all"],
        "azure/network_security_groups",
    ),
    (
        "azure.mgmt.network",
        "NetworkManagementClient",
        "network_interfaces",
        ["list_all"],
        "azure/network_security_groups — NIC-level NSG association",
    ),
    # --- backup: PR #58 widens this to <12 ----------------------------------
    (
        "azure.mgmt.recoveryservices",
        "RecoveryServicesClient",
        "vaults",
        ["list_by_subscription_id"],
        "azure/backup_recovery_status",
    ),
    (
        "azure.mgmt.recoveryservicesbackup",
        "RecoveryServicesBackupClient",
        "backup_policies",
        ["list"],
        "azure/backup_recovery_status",
    ),
    (
        "azure.mgmt.recoveryservicesbackup",
        "RecoveryServicesBackupClient",
        "backup_protected_items",
        ["list"],
        "azure/backup_recovery_status",
    ),
    # --- storage -------------------------------------------------------------
    (
        "azure.mgmt.storage",
        "StorageManagementClient",
        "storage_accounts",
        ["list"],
        "azure/storage_encryption_status",
    ),
    (
        "azure.mgmt.storage",
        "StorageManagementClient",
        "blob_services",
        ["get_service_properties"],
        "azure/storage_encryption_status",
    ),
    (
        "azure.mgmt.storage",
        "StorageManagementClient",
        "file_services",
        ["get_service_properties"],
        "azure/storage_encryption_status",
    ),
    # --- Defender for Cloud --------------------------------------------------
    (
        "azure.mgmt.security",
        "SecurityCenter",
        "pricings",
        ["list"],
        "azure/defender_plans",
    ),
    # --- RBAC ----------------------------------------------------------------
    (
        "azure.mgmt.authorization",
        "AuthorizationManagementClient",
        "role_definitions",
        ["list"],
        "azure/rbac_custom_roles, azure/rbac_role_assignments",
    ),
    (
        "azure.mgmt.authorization",
        "AuthorizationManagementClient",
        "role_assignments",
        ["list_for_subscription"],
        "azure/rbac_role_assignments",
    ),
    # --- compute -------------------------------------------------------------
    (
        "azure.mgmt.compute",
        "ComputeManagementClient",
        "disks",
        ["list"],
        "azure/disk_encryption_status",
    ),
    (
        "azure.mgmt.compute",
        "ComputeManagementClient",
        "virtual_machines",
        ["list_all"],
        "azure/vm_hardening_status",
    ),
    (
        "azure.mgmt.compute",
        "ComputeManagementClient",
        "virtual_machine_extensions",
        ["list"],
        "azure/vm_hardening_status",
    ),
    (
        "azure.mgmt.compute",
        "ComputeManagementClient",
        "virtual_machine_scale_sets",
        ["list_all"],
        "azure/vm_hardening_status",
    ),
    (
        "azure.mgmt.compute",
        "ComputeManagementClient",
        "virtual_machine_scale_set_vms",
        ["list"],
        "azure/vm_hardening_status",
    ),
    # --- containers ----------------------------------------------------------
    (
        "azure.mgmt.containerservice",
        "ContainerServiceClient",
        "managed_clusters",
        ["list"],
        "azure/aks_cluster_configuration",
    ),
    (
        "azure.mgmt.containerregistry",
        "ContainerRegistryManagementClient",
        "registries",
        ["list"],
        "azure/container_registry_configuration",
    ),
    # --- SQL: the `status` -> `state` rename lives in the model table below --
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "servers",
        ["list"],
        "azure/sql_encryption_status, azure/sql_server_configuration",
    ),
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "encryption_protectors",
        ["get"],
        "azure/sql_encryption_status",
    ),
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "databases",
        ["list_by_server"],
        "azure/sql_encryption_status",
    ),
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "transparent_data_encryptions",
        ["get"],
        "azure/sql_encryption_status",
    ),
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "firewall_rules",
        ["list_by_server"],
        "azure/sql_server_configuration",
    ),
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "server_blob_auditing_policies",
        ["list_by_server"],
        "azure/sql_server_configuration",
    ),
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "server_security_alert_policies",
        ["get"],
        "azure/sql_server_configuration",
    ),
    (
        "azure.mgmt.sql",
        "SqlManagementClient",
        "server_vulnerability_assessments",
        ["get"],
        "azure/sql_server_configuration",
    ),
    # --- MySQL / PostgreSQL --------------------------------------------------
    (
        "azure.mgmt.rdbms.mysql_flexibleservers",
        "MySQLManagementClient",
        "servers",
        ["list"],
        "azure/mysql_configuration",
    ),
    (
        "azure.mgmt.rdbms.mysql_flexibleservers",
        "MySQLManagementClient",
        "configurations",
        ["list_by_server"],
        "azure/mysql_configuration",
    ),
    (
        "azure.mgmt.postgresqlflexibleservers",
        "PostgreSQLManagementClient",
        "servers",
        # postgres 2 dropped `list`; the fetcher resolves either at runtime.
        [("list", "list_by_subscription")],
        "azure/postgresql_configuration",
    ),
    (
        "azure.mgmt.postgresqlflexibleservers",
        "PostgreSQLManagementClient",
        "configurations",
        ["get"],
        "azure/postgresql_configuration",
    ),
    (
        "azure.mgmt.postgresqlflexibleservers",
        "PostgreSQLManagementClient",
        "firewall_rules",
        ["list_by_server"],
        "azure/postgresql_configuration",
    ),
    # --- Cosmos DB -----------------------------------------------------------
    (
        "azure.mgmt.cosmosdb",
        "CosmosDBManagementClient",
        "database_accounts",
        ["list"],
        "azure/cosmosdb_configuration",
    ),
    # --- Key Vault (control plane) ------------------------------------------
    (
        "azure.mgmt.keyvault",
        "KeyVaultManagementClient",
        "vaults",
        ["list_by_subscription"],
        "azure/key_vault_configuration, azure/key_vault_key_rotation",
    ),
    (
        "azure.mgmt.keyvault",
        "KeyVaultManagementClient",
        "keys",
        ["list", "get"],
        "azure/key_vault_key_rotation",
    ),
    (
        "azure.mgmt.keyvault",
        "KeyVaultManagementClient",
        "secrets",
        ["list"],
        "azure/key_vault_key_rotation",
    ),
    # --- Key Vault (data plane): methods sit on the client itself -----------
    (
        "azure.keyvault.keys",
        "KeyClient",
        None,
        ["list_properties_of_keys", "get_key_rotation_policy"],
        "azure/key_vault_key_rotation — rotation policy is data-plane only",
    ),
    # --- app platform --------------------------------------------------------
    (
        "azure.mgmt.web",
        "WebSiteManagementClient",
        "web_apps",
        [
            "list",
            "get_configuration",
            "get_auth_settings_v2_without_secrets",
            "list_host_keys",
            "list_application_settings",
        ],
        "azure/app_service_configuration, azure/function_app_configuration, "
        "azure/app_service_plans",
    ),
    (
        "azure.mgmt.web",
        "WebSiteManagementClient",
        "app_service_plans",
        ["list"],
        "azure/app_service_plans",
    ),
    (
        "azure.mgmt.databricks",
        "AzureDatabricksManagementClient",
        "workspaces",
        ["list_by_subscription"],
        "azure/databricks_workspace_configuration",
    ),
    # --- policy --------------------------------------------------------------
    (
        "azure.mgmt.resource.policy",
        "PolicyClient",
        "policy_assignments",
        ["list"],
        "azure/policy_assignments",
    ),
    (
        "azure.mgmt.resource.policy",
        "PolicyClient",
        "policy_definitions",
        ["get_built_in", "get_at_management_group", "get"],
        "azure/policy_assignments — definition names are resolved for display",
    ),
    (
        "azure.mgmt.resource.policy",
        "PolicyClient",
        "policy_set_definitions",
        ["get_built_in", "get_at_management_group", "get"],
        "azure/policy_assignments",
    ),
]


def _surface_id(row: tuple[str, str, str | None, list[Method], str]) -> str:
    _, client, group, _, _ = row
    return f"{client}.{group}" if group else client


@pytest.mark.parametrize(
    "module,client,group,methods,affects",
    REQUIRED_SURFACE,
    ids=[_surface_id(r) for r in REQUIRED_SURFACE],
)
def test_operation_group_surface(
    module: str,
    client: str,
    group: str | None,
    methods: list[Method],
    affects: str,
) -> None:
    """Every operation group and method a fetcher calls must still exist."""
    if group is None:
        # Methods on the client itself: introspect the class, so data-plane
        # clients needing a real endpoint are never constructed.
        holder: object = _import(module, client)
        where = client
    else:
        holder = getattr(_build(module, client), group, None)
        where = f"{client}.{group}"
        assert holder is not None, (
            f"{where} is gone.\n"
            f"  affected fetchers: {affects}\n"
            f"  This is the azure-mgmt-monitor 7.0.0 failure mode: the client "
            f"still constructs, so the fetcher records an empty evidence set "
            f"instead of raising. Do not widen the pin to reach this version."
        )

    missing = []
    for method in methods:
        names = (method,) if isinstance(method, str) else method
        if not any(callable(getattr(holder, n, None)) for n in names):
            missing.append(" or ".join(names))

    available = sorted(
        a for a in dir(holder) if not a.startswith("_") and callable(getattr(holder, a, None))
    )
    assert not missing, (
        f"{where} no longer exposes: {'; '.join(missing)}\n"
        f"  affected fetchers: {affects}\n"
        f"  available methods: {', '.join(available)}\n"
        f"  azure-mgmt-postgresqlflexibleservers 2 dropped `servers.list` this "
        f"way. If a method was renamed rather than removed, add the new name as "
        f"a tuple on this row and teach the fetcher to resolve both."
    )


# ---------------------------------------------------------------------------
# Model fields
# ---------------------------------------------------------------------------
# The worst class: the call succeeds and returns objects, but the field the
# fetcher reads was renamed or pushed down a level, so the evidence says "not
# encrypted" about a database that is encrypted.
#
# (module, model, required fields, affected fetchers)
REQUIRED_MODEL_FIELDS: list[tuple[str, str, list[str], str]] = [
    (
        "azure.mgmt.sql.models",
        "TransparentDataEncryptionProperties",
        ["state"],
        "azure/sql_encryption_status — azure-mgmt-sql 4 renamed `status` to "
        "`state`; reading the old name yields None, i.e. 'not encrypted'",
    ),
    (
        "azure.mgmt.keyvault.models",
        "Vault",
        ["properties"],
        "azure/key_vault_configuration — azure-mgmt-keyvault 14 stopped "
        "flattening `properties` onto the vault",
    ),
    # azure-mgmt-network 31 is a TypeSpec SDK: these fields are declared on the
    # nested *PropertiesFormat model and flattened onto the resource for attribute
    # access, so the properties model is where a rename would show.
    (
        "azure.mgmt.network.models",
        "NetworkSecurityGroupPropertiesFormat",
        ["security_rules", "default_security_rules"],
        "azure/network_security_groups — default rules carry the platform's "
        "AllowInternetOutBound; losing them reads as 'no egress allowed'",
    ),
    (
        "azure.mgmt.network.models",
        "SecurityRulePropertiesFormat",
        ["priority", "destination_address_prefix", "destination_address_prefixes"],
        "azure/network_security_groups — outbound rules are evaluated in "
        "priority order against their destination",
    ),
    # SiteConfigResource (get_configuration) nests these under `properties`,
    # a SiteConfig; the resource flattens it for attribute access.
    (
        "azure.mgmt.web.models",
        "SiteConfig",
        [
            "ip_security_restrictions",
            "ip_security_restrictions_default_action",
            "scm_ip_security_restrictions",
            "scm_ip_security_restrictions_default_action",
            "scm_ip_security_restrictions_use_main",
        ],
        "azure/app_service_configuration — a renamed restriction field reads as "
        "'no rules', which evaluates to 'allows all traffic'",
    ),
    (
        "azure.mgmt.web.models",
        "IpSecurityRestriction",
        ["ip_address", "action", "priority", "vnet_subnet_resource_id", "headers"],
        "azure/app_service_configuration — access-restriction rule evaluation",
    ),
    (
        "azure.mgmt.web.models",
        "AppServicePlanProperties",
        ["zone_redundant", "number_of_workers", "per_site_scaling", "elastic_scale_enabled"],
        "azure/app_service_plans — a renamed zone_redundant reads as 'not zone "
        "redundant' on a plan that is",
    ),
    (
        "azure.mgmt.web.models",
        "SkuDescription",
        ["name", "tier", "capacity"],
        "azure/app_service_plans — sku.capacity is the plan's instance count",
    ),
    (
        "azure.mgmt.web.models",
        "SiteProperties",
        ["server_farm_id", "redundancy_mode"],
        "azure/app_service_plans — server_farm_id is how sites join their plan",
    ),
    (
        "azure.mgmt.network.models",
        "NetworkInterfacePropertiesFormat",
        ["network_security_group", "virtual_machine", "ip_configurations"],
        "azure/network_security_groups — a renamed NSG field would read as "
        "'NIC unprotected'",
    ),
]


@pytest.mark.parametrize(
    "module,model,fields,affects",
    REQUIRED_MODEL_FIELDS,
    ids=[f"{c[1]}.{'+'.join(c[2])}" for c in REQUIRED_MODEL_FIELDS],
)
def test_model_fields_present(
    module: str, model: str, fields: list[str], affects: str
) -> None:
    """A model field a fetcher reads must still be declared."""
    declared = _model_fields(_import(module, model))  # type: ignore[arg-type]
    missing = [f for f in fields if f not in declared]
    assert not missing, (
        f"{model} no longer declares: {', '.join(missing)}\n"
        f"  declared fields: {', '.join(sorted(declared))}\n"
        f"  affected fetchers: {affects}\n"
        f"  This produces WRONG evidence rather than empty evidence, which is "
        f"worse — the control reads as unimplemented."
    )


# ---------------------------------------------------------------------------
# Microsoft Graph
# ---------------------------------------------------------------------------
GRAPH_BUILDERS = [
    ("organization", "_shared/entra_graph — tenant name resolution"),
    ("applications", "azure/entra_app_registrations"),
    ("users", "azure/entra_mfa_status"),
    ("directory_roles", "azure/entra_privileged_roles"),
    ("identity", "azure/entra_conditional_access_policies"),
]


@pytest.mark.parametrize(
    "builder,affects", GRAPH_BUILDERS, ids=[b[0] for b in GRAPH_BUILDERS]
)
def test_graph_request_builders_present(builder: str, affects: str) -> None:
    """The Graph request builders the entra_* fetchers walk must still exist."""
    client = _build("msgraph", "GraphServiceClient")
    assert getattr(client, builder, None) is not None, (
        f"GraphServiceClient.{builder} is gone.\n"
        f"  affected fetchers: {affects}\n"
        f"  msgraph-sdk is pinned <2; a major bump restructures the builders."
    )


def test_monitor_pin_still_needed() -> None:
    """Assert the *reason* for the azure-mgmt-monitor pin, not the pin itself.

    If a future release restores `diagnostic_settings`, this starts failing and
    says so — the `<7` ceiling in pyproject.toml/requirements.txt and the
    Dependabot ignore rule can then be lifted together. A pin nobody revisits
    becomes stale debt.
    """
    import azure.mgmt.monitor as monitor

    version = str(getattr(monitor, "VERSION", "unknown"))
    client = _build("azure.mgmt.monitor", "MonitorManagementClient")
    has_group = getattr(client, "diagnostic_settings", None) is not None

    if version.split(".")[0] not in {"6", "unknown"} and has_group:
        pytest.fail(
            f"azure-mgmt-monitor {version} exposes diagnostic_settings again. "
            f"The <7 pin and the azure-mgmt-monitor ignore rule in "
            f".github/dependabot.yml can both be lifted."
        )
    assert has_group, (
        f"azure-mgmt-monitor {version} has no diagnostic_settings operation "
        f"group, so the installed version violates the >=6.0.2,<7 pin."
    )
