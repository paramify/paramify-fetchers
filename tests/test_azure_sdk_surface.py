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
    """`name` may be dotted, for a class nested inside another (kiota's query params)."""
    obj: object = importlib.import_module(module)
    for part in name.split("."):
        obj = getattr(obj, part)
    return obj


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
        "azure/app_service_configuration, azure/key_vault_configuration",
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
    (
        "azure.mgmt.security",
        "SecurityCenter",
        "assessments",
        ["list"],
        "azure/defender_assessments",
    ),
    (
        "azure.mgmt.security",
        "SecurityCenter",
        "regulatory_compliance_standards",
        ["list"],
        "azure/defender_regulatory_compliance",
    ),
    (
        "azure.mgmt.security",
        "SecurityCenter",
        "assessments_metadata",
        ["list_by_subscription"],
        "azure/defender_assessments — the only source of severity; "
        "assessments.list returns no metadata",
    ),
    (
        "azure.mgmt.security",
        "SecurityCenter",
        "regulatory_compliance_controls",
        ["list"],
        "azure/defender_regulatory_compliance",
    ),
    (
        "azure.mgmt.security",
        "SecurityCenter",
        "regulatory_compliance_assessments",
        ["list"],
        "azure/defender_regulatory_compliance",
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
    # --- Log Analytics ---------------------------------------------------------
    (
        "azure.mgmt.loganalytics",
        "LogAnalyticsManagementClient",
        "workspaces",
        ["list"],
        "azure/log_analytics_workspaces",
    ),
    (
        "azure.mgmt.loganalytics",
        "LogAnalyticsManagementClient",
        "tables",
        ["list_by_workspace"],
        "azure/log_analytics_workspaces — per-table retention",
    ),
    (
        "azure.mgmt.loganalytics",
        "LogAnalyticsManagementClient",
        "data_exports",
        ["list_by_workspace"],
        "azure/log_analytics_workspaces",
    ),
    (
        "azure.mgmt.loganalytics",
        "LogAnalyticsManagementClient",
        "intelligence_packs",
        ["list"],
        "azure/log_analytics_workspaces — Sentinel onboarding (SecurityInsights)",
    ),
    # --- Resource Graph: the inventory query sits on the client itself --------
    (
        "azure.mgmt.resourcegraph",
        "ResourceGraphClient",
        None,
        ["resources"],
        "azure/resource_inventory, azure/front_door_origins (origin regions)",
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
        ["get_built_in", "get_at_management_group", "get", "list_built_in"],
        "azure/policy_assignments — definition names are resolved for display, and "
        "initiative members' effects from one list_built_in",
    ),
    (
        "azure.mgmt.resource.policy",
        "PolicyClient",
        "policy_set_definitions",
        ["get_built_in", "get_at_management_group", "get"],
        "azure/policy_assignments",
    ),
    # --- policy compliance ---------------------------------------------------
    (
        "azure.mgmt.policyinsights",
        "PolicyInsightsClient",
        "policy_states",
        ["summarize_for_subscription", "list_query_results_for_subscription"],
        "azure/policy_compliance",
    ),
    (
        "azure.mgmt.policyinsights",
        "PolicyInsightsClient",
        "remediations",
        ["list_for_subscription"],
        "azure/policy_compliance",
    ),
    # --- Front Door WAF ------------------------------------------------------
    (
        "azure.mgmt.frontdoor",
        "FrontDoorManagementClient",
        "policies",
        ["list_by_subscription"],
        "azure/front_door_waf_policies, azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.frontdoor",
        "FrontDoorManagementClient",
        "managed_rule_sets",
        ["list"],
        "azure/front_door_waf_policies — rule-set definitions, the denominator of enabled_rules",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "profiles",
        ["list"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "afd_endpoints",
        ["list_by_profile"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "routes",
        ["list_by_endpoint"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "afd_custom_domains",
        ["list_by_profile"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "security_policies",
        ["list_by_profile"],
        "azure/front_door_waf_coverage — on a client pinned to api-version 2026-07-01",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "secrets",
        ["list_by_profile"],
        "azure/front_door_tls — certificate type, issuer and expiry behind each custom domain",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "rule_sets",
        ["list_by_profile"],
        "azure/front_door_tls, azure/front_door_origins — rule-set redirects and origin overrides",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "rules",
        ["list_by_rule_set"],
        "azure/front_door_tls, azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "afd_origin_groups",
        ["list_by_profile"],
        "azure/front_door_origins — on a client pinned to api-version 2026-07-01",
    ),
    (
        "azure.mgmt.cdn",
        "CdnManagementClient",
        "afd_origins",
        ["list_by_origin_group"],
        "azure/front_door_origins — on a client pinned to api-version 2026-07-01",
    ),
    (
        "azure.mgmt.monitor",
        "MonitorManagementClient",
        "diagnostic_settings_category",
        ["list"],
        "azure/front_door_waf_coverage — which log categories a profile emits, and their groups",
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
    # --- policy effects: a missing field reads as an unresolved effect ------
    # The model_base generation declares these on the *Properties models and
    # flattens them onto PolicyDefinition / PolicySetDefinition for attribute
    # access, so the Properties models are the honest thing to pin.
    (
        "azure.mgmt.resource.policy.models",
        "PolicyDefinitionProperties",
        ["policy_rule", "parameters", "display_name", "policy_type"],
        "azure/policy_assignments — the effect is policyRule.then.effect, often a "
        "parameter reference resolved against `parameters`",
    ),
    (
        "azure.mgmt.resource.policy.models",
        "PolicySetDefinitionProperties",
        ["policy_definitions", "parameters", "display_name", "policy_type"],
        "azure/policy_assignments — initiative members and the defaults they inherit",
    ),
    (
        "azure.mgmt.resource.policy.models",
        "PolicyDefinitionReference",
        ["policy_definition_id", "policy_definition_reference_id", "parameters"],
        "azure/policy_assignments — the value an initiative passes each member",
    ),
    (
        "azure.mgmt.resource.policy.models",
        "ParameterDefinitionsValue",
        ["default_value"],
        "azure/policy_assignments — the default an unset effect parameter falls back to",
    ),
    # --- Defender regulatory compliance: a renamed count reads as 0 failed ---
    (
        "azure.mgmt.security.models",
        "RegulatoryComplianceStandard",
        ["name", "state", "passed_controls", "failed_controls", "skipped_controls",
         "unsupported_controls"],
        "azure/defender_regulatory_compliance",
    ),
    (
        "azure.mgmt.security.models",
        "RegulatoryComplianceControl",
        ["name", "description", "state", "passed_assessments", "failed_assessments",
         "skipped_assessments"],
        "azure/defender_regulatory_compliance",
    ),
    (
        "azure.mgmt.security.models",
        "RegulatoryComplianceAssessment",
        ["name", "description", "state", "passed_resources", "failed_resources",
         "skipped_resources", "unsupported_resources"],
        "azure/defender_regulatory_compliance",
    ),
    # --- policy compliance: a renamed count reads as "0 non-compliant" -------
    (
        "azure.mgmt.policyinsights.models",
        "SummaryResults",
        ["non_compliant_resources", "non_compliant_policies", "resource_details",
         "policy_details", "query_results_uri"],
        "azure/policy_compliance — the headline counts",
    ),
    (
        "azure.mgmt.policyinsights.models",
        "PolicyAssignmentSummary",
        ["policy_assignment_id", "policy_set_definition_id", "results", "policy_definitions"],
        "azure/policy_compliance — per-assignment compliance",
    ),
    (
        "azure.mgmt.policyinsights.models",
        "PolicyDefinitionSummary",
        ["policy_definition_id", "policy_definition_reference_id", "effect", "results"],
        "azure/policy_compliance — non-compliant initiative members",
    ),
    (
        "azure.mgmt.policyinsights.models",
        "ComplianceDetail",
        ["compliance_state", "count"],
        "azure/policy_compliance",
    ),
    (
        "azure.mgmt.policyinsights.models",
        "PolicyState",
        ["resource_id", "compliance_state", "policy_assignment_id",
         "policy_definition_id", "policy_definition_action", "timestamp"],
        "azure/policy_compliance — the itemized non-compliant records",
    ),
    (
        "azure.mgmt.policyinsights.models",
        "Remediation",
        ["policy_assignment_id", "provisioning_state", "deployment_status"],
        "azure/policy_compliance",
    ),
    (
        "azure.mgmt.policyinsights.models",
        "RemediationDeploymentSummary",
        ["total_deployments", "successful_deployments", "failed_deployments"],
        "azure/policy_compliance",
    ),
    (
        "msgraph.generated.models.service_principal",
        "ServicePrincipal",
        [
            "service_principal_type",
            "app_owner_organization_id",
            "alternative_names",
            "password_credentials",
            "key_credentials",
        ],
        "azure/entra_service_principals — a missing field reads as None, so every "
        "principal would look credential-free or of unknown ownership",
    ),
    (
        "msgraph.generated.models.application",
        "Application",
        ["federated_identity_credentials"],
        "azure/entra_service_principals — the $expand target; without it every "
        "application reads as non-federated",
    ),
    (
        "msgraph.generated.applications.applications_request_builder",
        "ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters",
        ["select", "expand"],
        "azure/entra_service_principals — federated credentials arrive only via $expand",
    ),
    (
        "msgraph.generated.models.authentication_methods_policy",
        "AuthenticationMethodsPolicy",
        ["authentication_method_configurations", "policy_migration_state", "registration_enforcement"],
        "azure/entra_authentication_policy — a missing field reads as no methods "
        "configured, i.e. SMS looks disabled",
    ),
    (
        "msgraph.generated.models.authentication_method_configuration",
        "AuthenticationMethodConfiguration",
        ["state", "exclude_targets"],
        "azure/entra_authentication_policy — `state` is the enabled/disabled fact",
    ),
    (
        "msgraph.generated.models.identity_security_defaults_enforcement_policy",
        "IdentitySecurityDefaultsEnforcementPolicy",
        ["is_enabled"],
        "azure/entra_authentication_policy — security defaults on/off",
    ),
    (
        "msgraph.generated.models.group_setting",
        "GroupSetting",
        ["template_id", "values"],
        "azure/entra_authentication_policy — password protection settings",
    ),
    (
        "msgraph.generated.models.service_plan_info",
        "ServicePlanInfo",
        ["service_plan_name", "provisioning_status"],
        "azure/entra_authentication_policy — the Entra ID P1/P2 licence check",
    ),
    (
        "azure.mgmt.resourcegraph.models",
        "QueryRequestOptions",
        ["skip_token", "top", "result_format"],
        "azure/resource_inventory — paging; without skip_token the inventory "
        "stops at the first 1000 resources",
    ),
    (
        "azure.mgmt.resourcegraph.models",
        "QueryResponse",
        ["skip_token", "total_records", "result_truncated", "data"],
        "azure/resource_inventory — the page loop and its completeness check",
    ),
    (
        "azure.mgmt.loganalytics.models",
        "Workspace",
        ["properties"],
        "azure/log_analytics_workspaces — azure-mgmt-loganalytics 14 keeps "
        "`properties` nested, as keyvault 14 does",
    ),
    (
        "azure.mgmt.loganalytics.models",
        "WorkspaceProperties",
        [
            "sku",
            "retention_in_days",
            "workspace_capping",
            "public_network_access_for_ingestion",
            "public_network_access_for_query",
            "features",
        ],
        "azure/log_analytics_workspaces",
    ),
    (
        "azure.mgmt.loganalytics.models",
        "WorkspaceFeatures",
        ["enable_log_access_using_only_resource_permissions", "disable_local_auth"],
        "azure/log_analytics_workspaces — the access control mode; a rename "
        "reads every workspace as 'workspace permissions only'",
    ),
    (
        "azure.mgmt.loganalytics.models",
        "TableProperties",
        [
            "plan",
            "retention_in_days",
            "total_retention_in_days",
            "retention_in_days_as_default",
            "total_retention_in_days_as_default",
        ],
        "azure/log_analytics_workspaces — per-table retention",
    ),
    (
        "azure.mgmt.monitor.models",
        "DiagnosticSettingsResource",
        ["storage_account_id", "workspace_id", "event_hub_authorization_rule_id", "logs"],
        "azure/key_vault_configuration, azure/diagnostic_settings — monitor 6.x "
        "flattens `properties`; an unflattened release reads every vault as "
        "having no audit-log destination",
    ),
    (
        "azure.mgmt.monitor.models",
        "LogSettings",
        ["category", "category_group", "enabled"],
        "azure/key_vault_configuration — the AuditEvent / audit-group match",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "WebApplicationFirewallPolicy",
        ["properties", "sku"],
        "azure/front_door_waf_policies — 2.0.0 moved every policy field under `properties`",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "WebApplicationFirewallPolicyProperties",
        ["policy_settings", "managed_rules", "custom_rules", "security_policy_links",
         "provisioning_state", "resource_state"],
        "azure/front_door_waf_policies",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "PolicySettings",
        ["enabled_state", "mode", "request_body_check"],
        "azure/front_door_waf_policies — `mode` decides the blocking verdict",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleSet",
        ["rule_set_type", "rule_set_version", "rule_set_action", "exclusions", "rule_group_overrides"],
        "azure/front_door_waf_policies",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleGroupOverride",
        ["rule_group_name", "rules", "exclusions"],
        "azure/front_door_waf_policies — an override with no `rules` disables the whole group",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleOverride",
        ["rule_id", "enabled_state", "action", "exclusions"],
        "azure/front_door_waf_policies",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "CustomRule",
        ["name", "priority", "enabled_state", "rule_type", "action", "rate_limit_threshold",
         "rate_limit_duration_in_minutes", "match_conditions", "group_by"],
        "azure/front_door_waf_policies — rate-limit rules",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "MatchCondition",
        ["match_variable", "selector", "operator", "negate_condition", "match_value"],
        "azure/front_door_waf_policies — an Allow rule matching every request makes the policy not blocking",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleSetDefinitionProperties",
        ["rule_set_type", "rule_set_version", "rule_groups"],
        "azure/front_door_waf_policies",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleGroupDefinition",
        ["rule_group_name", "rules"],
        "azure/front_door_waf_policies",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleDefinition",
        ["rule_id", "default_state", "default_action"],
        "azure/front_door_waf_policies — default_state decides a rule nobody overrode",
    ),
    (
        "azure.mgmt.cdn.models",
        "Profile",
        ["properties", "sku"],
        "azure/front_door_waf_coverage — sku separates Front Door from classic CDN",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDEndpointProperties",
        ["host_name", "enabled_state", "deployment_status"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn.models",
        "RouteProperties",
        ["custom_domains", "supported_protocols", "patterns_to_match", "link_to_default_domain",
         "https_redirect", "enabled_state"],
        "azure/front_door_waf_coverage — which hosts a route serves",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDDomainProperties",
        ["host_name", "domain_validation_state"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn.models",
        "RouteProperties",
        ["forwarding_protocol", "origin_group", "origin_path", "rule_sets"],
        "azure/front_door_tls, azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDDomainProperties",
        ["tls_settings"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDDomainHttpsParameters",
        ["certificate_type", "minimum_tls_version", "cipher_suite_set_type", "customized_cipher_suite_set", "secret"],
        "azure/front_door_tls — minimum_tls_version applies only when the cipher-suite set is Customized",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDDomainHttpsCustomizedCipherSuiteSet",
        ["cipher_suite_set_for_tls12", "cipher_suite_set_for_tls13"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecretProperties",
        ["parameters"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "CustomerCertificateParameters",
        ["subject", "subject_alternative_names", "certificate_authority", "thumbprint", "expiration_date",
         "secret_source", "secret_version", "use_latest_version"],
        "azure/front_door_tls — a customer certificate's expiry and Key Vault source",
    ),
    (
        "azure.mgmt.cdn.models",
        "ManagedCertificateParameters",
        ["subject", "expiration_date"],
        "azure/front_door_tls — a managed certificate's expiry",
    ),
    (
        "azure.mgmt.cdn.models",
        "RuleProperties",
        ["order", "match_processing_behavior", "conditions", "actions"],
        "azure/front_door_tls, azure/front_door_origins — evaluation order and Stop",
    ),
    (
        "azure.mgmt.cdn.models",
        "RequestSchemeMatchConditionParameters",
        ["operator", "negate_condition", "match_values"],
        "azure/front_door_tls — a redirect limited to HTTP requests",
    ),
    (
        "azure.mgmt.cdn.models",
        "UrlRedirectActionParameters",
        ["redirect_type", "destination_protocol"],
        "azure/front_door_tls — a rule-set HTTP→HTTPS redirect",
    ),
    (
        "azure.mgmt.cdn.models",
        "RouteConfigurationOverrideActionParameters",
        ["origin_group_override"],
        "azure/front_door_origins — a rule that changes the origin group or forwarding protocol",
    ),
    (
        "azure.mgmt.cdn.models",
        "OriginGroupOverride",
        ["origin_group", "forwarding_protocol"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOriginGroupProperties",
        ["load_balancing_settings", "health_probe_settings", "session_affinity_state", "authentication"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOriginProperties",
        ["azure_origin", "host_name", "http_port", "https_port", "origin_host_header", "priority", "weight",
         "shared_private_link_resource", "enabled_state", "enforce_certificate_name_check"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "SharedPrivateLinkResourceProperties",
        ["private_link", "private_link_location", "group_id", "status"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "LoadBalancingSettingsParameters",
        ["sample_size", "successful_samples_required", "additional_latency_in_milliseconds"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "HealthProbeParameters",
        ["probe_path", "probe_request_type", "probe_protocol", "probe_interval_in_seconds"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "OriginAuthenticationProperties",
        ["type", "scope", "user_assigned_identity"],
        "azure/front_door_origins — managed-identity origin authentication",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecurityPolicyWebApplicationFirewallParameters",
        ["waf_policy", "associations"],
        "azure/front_door_waf_coverage — isProfileLevel is read by wire key, not modeled in 14.x",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecurityPolicyWebApplicationFirewallAssociation",
        ["domains", "patterns_to_match"],
        "azure/front_door_waf_coverage — routes is read by wire key, not modeled in 14.x",
    ),
    (
        "azure.mgmt.cdn.models",
        "ActivatedResourceReference",
        ["id", "is_active"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.monitor.models",
        "DiagnosticSettingsCategoryResource",
        ["category_type", "category_groups"],
        "azure/front_door_waf_coverage — a category captured through its group (allLogs, audit)",
    ),
    (
        "azure.mgmt.monitor.models",
        "DiagnosticSettingsResource",
        ["event_hub_name", "marketplace_partner_id"],
        "azure/front_door_waf_coverage — the remaining WAF-log destinations",
    ),
    # --- Front Door: the `properties` pivots azure-mgmt-cdn 14 / frontdoor 2 moved fields under
    (
        "azure.mgmt.frontdoor.models",
        "WebApplicationFirewallPolicy",
        ["location"],
        "azure/front_door_waf_policies",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleSetList",
        ["managed_rule_sets"],
        "azure/front_door_waf_policies — exceptionsList is read by wire key beside it",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleExclusion",
        ["match_variable", "selector_match_operator", "selector"],
        "azure/front_door_waf_policies — exclusions",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "CustomRuleList",
        ["rules"],
        "azure/front_door_waf_policies — custom and rate-limit rules",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "GroupByVariable",
        ["variable_name"],
        "azure/front_door_waf_policies",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleSetDefinition",
        ["properties"],
        "azure/front_door_waf_policies — rule-set definitions",
    ),
    (
        "azure.mgmt.cdn.models",
        "ProfileProperties",
        ["resource_state"],
        "azure/front_door_*",
    ),
    (
        "azure.mgmt.cdn.models",
        "Sku",
        ["name"],
        "azure/front_door_* — the SKU that separates Front Door from classic CDN",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDEndpoint",
        ["properties"],
        "azure/front_door_*",
    ),
    (
        "azure.mgmt.cdn.models",
        "Route",
        ["properties"],
        "azure/front_door_*",
    ),
    (
        "azure.mgmt.cdn.models",
        "ResourceReference",
        ["id"],
        "azure/front_door_* — route origin group, rule sets, certificate secret, private link target",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDDomain",
        ["properties"],
        "azure/front_door_tls, azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecurityPolicy",
        ["properties"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecurityPolicyProperties",
        ["parameters", "deployment_status", "provisioning_state"],
        "azure/front_door_waf_coverage",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecurityPolicyWebApplicationFirewallParameters",
        ["type"],
        "azure/front_door_waf_coverage — only WebApplicationFirewall policies attach a WAF",
    ),
    (
        "azure.mgmt.cdn.models",
        "Secret",
        ["properties"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "CustomerCertificateParameters",
        ["type"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "ManagedCertificateParameters",
        ["type"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "AzureFirstPartyManagedCertificateParameters",
        ["type", "subject", "subject_alternative_names", "certificate_authority", "thumbprint",
         "expiration_date", "secret_source"],
        "azure/front_door_tls — a first-party managed certificate's expiry",
    ),
    (
        "azure.mgmt.cdn.models",
        "RuleSet",
        ["id", "name"],
        "azure/front_door_tls, azure/front_door_origins — the join from a route's ruleSets",
    ),
    (
        "azure.mgmt.cdn.models",
        "Rule",
        ["properties"],
        "azure/front_door_tls, azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "DeliveryRuleRequestSchemeCondition",
        ["name", "parameters"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "UrlRedirectAction",
        ["name", "parameters"],
        "azure/front_door_tls",
    ),
    (
        "azure.mgmt.cdn.models",
        "DeliveryRuleRouteConfigurationOverrideAction",
        ["name", "parameters"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOriginGroup",
        ["properties"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOriginGroupProperties",
        ["provisioning_state", "deployment_status"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOrigin",
        ["properties"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOriginProperties",
        ["provisioning_state", "deployment_status"],
        "azure/front_door_origins",
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
# Front Door: wire-key reads, polymorphic models, the pinned api-version
# ---------------------------------------------------------------------------
# Fields azure-mgmt-cdn 14 / azure-mgmt-frontdoor 2 do not model are read by their
# wire key through the dict-backed hybrid models (`_shared/frontdoor.wire`). If a
# release drops that backing, `.get` vanishes and the read returns None: WAF scope
# reads as "none" and the coverage verdict is wrong with no error.
#
# (module, model, body, wire-key path, expected value, affected fetchers)
WIRE_KEY_READS: list[tuple[str, str, dict, list[str], object, str]] = [
    (
        "azure.mgmt.cdn.models",
        "SecurityPolicyWebApplicationFirewallParameters",
        {"type": "WebApplicationFirewall", "isProfileLevel": True},
        ["isProfileLevel"],
        True,
        "azure/front_door_waf_coverage — profile-level WAF scope",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecurityPolicyWebApplicationFirewallAssociation",
        {"domains": [], "routes": [{"id": "/r1"}]},
        ["routes"],
        [{"id": "/r1"}],
        "azure/front_door_waf_coverage — route-level WAF scope",
    ),
    (
        "azure.mgmt.frontdoor.models",
        "ManagedRuleSetList",
        {"managedRuleSets": [], "exceptionsList": {"exceptions": [{"matchVariable": "RequestUri"}]}},
        ["exceptionsList", "exceptions"],
        [{"matchVariable": "RequestUri"}],
        "azure/front_door_waf_policies — WAF exceptions",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOriginProperties",
        {"hostName": "o.example.net", "certificateNameCheckValidationMode": "OriginHostname"},
        ["certificateNameCheckValidationMode"],
        "OriginHostname",
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "AFDOriginProperties",
        {"hostName": "o.example.net", "customCertificateSubjects": ["o.example.net"]},
        ["customCertificateSubjects"],
        ["o.example.net"],
        "azure/front_door_origins",
    ),
    (
        "azure.mgmt.cdn.models",
        "OriginAuthenticationProperties",
        {"type": "SystemAssignedIdentity", "tokenDestinationHeader": "X-Azure-Authorization"},
        ["tokenDestinationHeader"],
        "X-Azure-Authorization",
        "azure/front_door_origins",
    ),
]


@pytest.mark.parametrize(
    "module,model,body,path,expected,affects",
    WIRE_KEY_READS,
    ids=[f"{c[1]}.{'.'.join(c[3])}" for c in WIRE_KEY_READS],
)
def test_front_door_wire_key_reads(
    module: str, model: str, body: dict, path: list[str], expected: object, affects: str
) -> None:
    """An unmodeled wire key must stay readable with `.get` on the deserialized model."""
    value: object = _import(module, model)(body)  # type: ignore[operator]
    for key in path:
        assert hasattr(value, "get"), (
            f"{model} no longer supports .get('{key}') — the hybrid model lost its dict backing.\n"
            f"  affected fetchers: {affects}\n"
            f"  _shared/frontdoor.wire() would return None and the field would read as absent."
        )
        value = value.get(key)  # type: ignore[attr-defined]
    assert value == expected, f"{model} wire key {'.'.join(path)} read {value!r}, expected {expected!r} ({affects})"


# A discriminated field must still deserialize to the subclass that carries the
# fields the fetcher reads; the base class has none of them, so every read is None.
#
# (module, model, body, attribute path, expected class, affected fetchers)
POLYMORPHIC_READS: list[tuple[str, str, dict, list[object], str, str]] = [
    (
        "azure.mgmt.cdn.models",
        "SecretProperties",
        {"parameters": {"type": "CustomerCertificate", "expirationDate": "2027-01-01T00:00:00+00:00"}},
        ["parameters"],
        "CustomerCertificateParameters",
        "azure/front_door_tls — certificate expiry",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecretProperties",
        {"parameters": {"type": "ManagedCertificate", "expirationDate": "2027-01-01T00:00:00+00:00"}},
        ["parameters"],
        "ManagedCertificateParameters",
        "azure/front_door_tls — certificate expiry",
    ),
    (
        "azure.mgmt.cdn.models",
        "SecretProperties",
        {"parameters": {"type": "AzureFirstPartyManagedCertificate"}},
        ["parameters"],
        "AzureFirstPartyManagedCertificateParameters",
        "azure/front_door_tls — certificate expiry",
    ),
    (
        "azure.mgmt.cdn.models",
        "RuleProperties",
        {"conditions": [{"name": "RequestScheme", "parameters": {
            "typeName": "DeliveryRuleRequestSchemeConditionParameters", "operator": "Equal", "matchValues": ["HTTP"]}}]},
        ["conditions", 0],
        "DeliveryRuleRequestSchemeCondition",
        "azure/front_door_tls — rule-set HTTP→HTTPS redirect",
    ),
    (
        "azure.mgmt.cdn.models",
        "RuleProperties",
        {"actions": [{"name": "UrlRedirect", "parameters": {
            "typeName": "DeliveryRuleUrlRedirectActionParameters", "redirectType": "Moved", "destinationProtocol": "Https"}}]},
        ["actions", 0],
        "UrlRedirectAction",
        "azure/front_door_tls — rule-set HTTP→HTTPS redirect",
    ),
    (
        "azure.mgmt.cdn.models",
        "RuleProperties",
        {"actions": [{"name": "RouteConfigurationOverride", "parameters": {
            "typeName": "DeliveryRuleRouteConfigurationOverrideActionParameters",
            "originGroupOverride": {"originGroup": {"id": "/og"}, "forwardingProtocol": "HttpOnly"}}}]},
        ["actions", 0],
        "DeliveryRuleRouteConfigurationOverrideAction",
        "azure/front_door_origins — a rule that changes the forwarding protocol",
    ),
]


@pytest.mark.parametrize(
    "module,model,body,path,expected,affects",
    POLYMORPHIC_READS,
    ids=[f"{c[1]}->{c[4]}" for c in POLYMORPHIC_READS],
)
def test_front_door_polymorphic_reads(
    module: str, model: str, body: dict, path: list[object], expected: str, affects: str
) -> None:
    """A discriminated Front Door field must deserialize to the subclass the fetcher reads."""
    value: object = _import(module, model)(body)  # type: ignore[operator]
    for step in path:
        value = value[step] if isinstance(step, int) else getattr(value, step)  # type: ignore[index]
    assert type(value).__name__ == expected, (
        f"{model}.{'.'.join(map(str, path))} deserialized to {type(value).__name__}, not {expected}.\n"
        f"  affected fetchers: {affects}\n"
        f"  The base class carries none of the fields read, so they would all be None."
    )


def test_cdn_client_honours_pinned_api_version() -> None:
    """Security policies and origins are read on a client built with api_version=2026-07-01.

    The per-call `api_version` kwarg is silently ignored by azure-mgmt-cdn 14; the
    client-level one is what reaches the request. If the constructor stops honouring it,
    isProfileLevel and associations[].routes stop coming back and WAF scope reads as none.
    """
    from azure.mgmt.cdn import CdnManagementClient

    client = CdnManagementClient(_FakeCredential(), SUBSCRIPTION_ID, api_version="2026-07-01")
    config = getattr(client, "_config", None)
    assert getattr(config, "api_version", None) == "2026-07-01", (
        "CdnManagementClient no longer records api_version from its constructor.\n"
        "  affected fetchers: azure/front_door_waf_coverage, azure/front_door_origins"
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
    ("service_principals", "azure/entra_service_principals"),
    ("policies", "azure/entra_authentication_policy"),
    ("group_settings", "azure/entra_authentication_policy"),
    ("group_setting_templates", "azure/entra_authentication_policy"),
    ("subscribed_skus", "azure/entra_authentication_policy"),
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
