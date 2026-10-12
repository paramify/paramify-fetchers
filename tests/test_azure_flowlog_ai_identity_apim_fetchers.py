"""Decision logic of the flow log, AI services, managed identity and API Management fetchers.

No Azure SDK, credentials or network: the pure functions that decide what the evidence
claims, each case one whose verdict would be false evidence if it regressed — an unread
region reported as unlogged, Microsoft's default content filter reported as non-blocking,
an unset protocol switch read the wrong way, an unreadable role list reported as "no roles".

Run: ``pytest tests/test_azure_flowlog_ai_identity_apim_fetchers.py``
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
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


flow = _load("network_flow_logs")
ai = _load("ai_services_configuration")
mi = _load("managed_identity_configuration")
apim = _load("api_management_configuration")

SUB = "/subscriptions/11111111-1111-1111-1111-111111111111"
VNET = f"{SUB}/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/hub"
NSG = f"{SUB}/resourceGroups/net/providers/Microsoft.Network/networkSecurityGroups/web"


# --------------------------------------------------------------------------- #
# Flow logs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "target,expected",
    [
        (NSG, "network_security_group"),
        (VNET, "virtual_network"),
        (f"{VNET}/subnets/app", "subnet"),
        (f"{SUB}/resourceGroups/net/providers/Microsoft.Network/networkInterfaces/nic1", "network_interface"),
        (None, "unknown"),
    ],
)
def test_flow_log_target_type(target, expected):
    assert flow.target_type(target) == expected


def _vnet(location="eastus", *subnets):
    return {"id": VNET, "name": "hub", "location": location, "subnets": list(subnets)}


def _subnet(name, nsg=None, in_use=True):
    return {
        "id": f"{VNET}/subnets/{name}",
        "name": name,
        "network_security_group_id": nsg,
        "nsg_supported": name.lower() not in flow.NO_NSG_SUBNETS,
        "in_use": in_use,
    }


def _log(filters=None):
    return {"enabled_filtering_criteria": filters}


def test_subnet_covered_by_vnet_subnet_or_nsg_flow_log():
    vnet = _vnet("eastus", _subnet("a"), _subnet("b", NSG), _subnet("c"))
    record = flow.vnet_record(vnet, {VNET.lower(): _log()}, set(), {"eastus"})
    assert [s["coverage"] for s in record["subnets"]] == ["vnet", "vnet", "vnet"]
    assert record["coverage"] == "full"

    by_nsg = flow.vnet_record(vnet, {NSG.lower(): _log()}, set(), {"eastus"})
    assert [s["coverage"] for s in by_nsg["subnets"]] == ["none", "nsg", "none"]
    assert by_nsg["coverage"] == "partial"


def test_filtered_vnet_flow_log_is_not_full_coverage():
    vnet = _vnet("eastus", _subnet("a"))
    record = flow.vnet_record(vnet, {VNET.lower(): _log("dstport=443")}, set(), {"eastus"})
    assert record["subnets"][0]["coverage"] == "vnet_filtered"
    assert record["coverage"] == "partial"
    # An unfiltered NSG flow log on the same subnet still counts as full.
    vnet = _vnet("eastus", _subnet("a", NSG))
    both = flow.vnet_record(vnet, {VNET.lower(): _log("x"), NSG.lower(): _log()}, set(), {"eastus"})
    assert both["subnets"][0]["coverage"] == "nsg"
    assert both["subnets"][0]["flow_log_sources"] == ["vnet_filtered", "nsg"]


def test_unread_region_is_unknown_not_unlogged():
    record = flow.vnet_record(_vnet("westus", _subnet("a")), {}, {"westus"}, {"westus"})
    assert record["subnets"][0]["coverage"] == "unknown"
    assert record["coverage"] == "unknown"


def test_missing_network_watcher_only_when_the_list_was_read():
    assert flow.vnet_record(_vnet("westus"), {}, set(), {"eastus"})["network_watcher_in_region"] is False
    assert flow.vnet_record(_vnet("westus"), {}, set(), None)["network_watcher_in_region"] is None


def _flow_log(enabled, days):
    return NS(
        id="fl",
        name="fl",
        location="eastus",
        enabled=True,
        provisioning_state="Succeeded",
        target_resource_id=NSG,
        enabled_filtering_criteria=None,
        storage_id=f"{SUB}/resourceGroups/logs/providers/Microsoft.Storage/storageAccounts/st1",
        retention_policy=NS(enabled=enabled, days=days),
        format=None,
        flow_analytics_configuration=None,
    )


@pytest.mark.parametrize(
    "enabled,days,indefinite,retention_days",
    [
        (True, 7, False, 7),
        (True, 0, True, None),  # a 0-day policy deletes nothing
        (False, 90, True, None),  # no policy: storage keeps records until something deletes them
    ],
)
def test_retention_without_a_policy_is_indefinite(enabled, days, indefinite, retention_days):
    record = flow.project_flow_log(_flow_log(enabled, days))
    assert record["retained_indefinitely"] is indefinite
    assert record["retention_days"] == retention_days
    assert record["storage_account_name"] == "st1" and record["storage_account_resource_group"] == "logs"


def test_retention_thresholds_ignore_indefinite_logs():
    logs = [
        {"enabled": True, "retention_days": 30, "retained_indefinitely": False},
        {"enabled": True, "retention_days": 200, "retained_indefinitely": False},
        {"enabled": True, "retention_days": None, "retained_indefinitely": True},
    ]
    for log in logs:
        log.update(target_type="network_security_group", legacy_nsg_flow_log=True, enabled_filtering_criteria=None,
                   target_attached=True, traffic_analytics_enabled=False, traffic_analytics_interval_minutes=None)
    summary = flow.summarize([], logs, [])
    assert summary["enabled_flow_logs_retained_under_90_days"] == 1
    assert summary["enabled_flow_logs_retained_under_365_days"] == 2
    assert summary["enabled_flow_logs_retained_indefinitely"] == 1
    assert summary["minimum_retention_days"] == 30


def test_in_use_subnet_counts_exclude_empty_and_no_nsg_subnets():
    vnet = _vnet(
        "eastus",
        _subnet("app", NSG),
        _subnet("db"),  # in use, no NSG: only a VNet flow log can reach it
        _subnet("spare", in_use=False),
        _subnet("GatewaySubnet"),  # Azure allows no NSG here
    )
    summary = flow.summarize([], [], [flow.vnet_record(vnet, {NSG.lower(): _log()}, set(), {"eastus"})])
    assert summary["subnets_in_use"] == 3
    assert summary["subnets_in_use_covered"] == 1
    assert summary["subnets_in_use_without_nsg"] == 1
    assert summary["subnets_in_use_nsg_not_supported"] == 1
    assert summary["total_subnets"] == 4


@pytest.mark.parametrize(
    "target,nsgs,expected",
    [
        (NSG, {NSG.lower(): True}, True),
        (NSG, {NSG.lower(): False}, False),  # NSG on nothing: the flow log has no traffic to log
        (NSG, {}, False),  # NSG deleted
        (NSG, None, None),  # NSG list unread
        (VNET, None, True),
        (f"{SUB}/resourceGroups/net/providers/Microsoft.Network/networkInterfaces/n1", {}, None),
    ],
)
def test_target_attached(target, nsgs, expected):
    flow_log = {"target_resource_id": target, "target_type": flow.target_type(target)}
    assert flow.target_attached(flow_log, nsgs, [_vnet("eastus")]) is expected


# --------------------------------------------------------------------------- #
# AI services
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "pna,default_action,expected",
    [
        ("Disabled", "Allow", "private"),
        ("Enabled", "Deny", "restricted"),
        ("Enabled", "Allow", "open"),
        (None, None, "open"),  # Azure's defaults are Enabled / Allow
    ],
)
def test_network_exposure(pna, default_action, expected):
    assert ai.network_exposure(pna, default_action) == expected


def _account(**props):
    return NS(
        id=f"{SUB}/resourceGroups/ai/providers/Microsoft.CognitiveServices/accounts/a1",
        name="a1",
        kind="AIServices",
        sku=NS(name="S0"),
        location="eastus",
        tags=None,
        identity=None,
        properties=NS(**props),
    )


@pytest.mark.parametrize(
    "disable_local_auth,keys_enabled", [(True, False), (False, True), (None, True)]
)
def test_api_keys_enabled_by_default(disable_local_auth, keys_enabled):
    assert ai.project_account(_account(disable_local_auth=disable_local_auth))["api_keys_enabled"] is keys_enabled


@pytest.mark.parametrize(
    "key_source,cmk",
    [(None, False), ("Microsoft.CognitiveServices", False), ("Microsoft.KeyVault", True)],
)
def test_customer_managed_key(key_source, cmk):
    account = _account(encryption=NS(key_source=key_source, key_vault_properties=None))
    assert ai.project_account(account)["customer_managed_key"] is cmk


def test_private_endpoint_with_public_access_is_flagged():
    pe = [NS(id="pe1", properties=NS(private_link_service_connection_state=NS(status="Approved")))]
    account = ai.project_account(_account(public_network_access="Enabled", private_endpoint_connections=pe))
    assert account["private_endpoint_but_public_access"] is True
    closed = ai.project_account(_account(public_network_access="Disabled", private_endpoint_connections=pe))
    assert closed["private_endpoint_but_public_access"] is False


def _policy(*filters, policy_type="SystemManaged", mode="Blocking"):
    return NS(
        name="p",
        properties=NS(
            type=policy_type,
            mode=mode,
            base_policy_name=None,
            custom_blocklists=None,
            content_filters=[
                NS(name=n, source=src, enabled=en, blocking=bl, severity_threshold="Medium")
                for n, src, en, bl in filters
            ],
        ),
    )


HARM = [(n, src, True, True) for n in ("Hate", "Sexual", "Violence", "Selfharm") for src in ("Prompt", "Completion")]
JAILBREAK = ("Jailbreak", "Prompt", True, True)


def test_microsofts_default_policy_is_blocking_despite_annotate_only_filters():
    """DefaultV2 annotates Protected Material Code instead of blocking it."""
    policy = ai.project_rai_policy(_policy(*HARM, JAILBREAK, ("Protected Material Code", "Completion", True, False)))
    assert policy["harm_filters_enabled_and_blocking"] is True
    assert policy["jailbreak_blocking"] is True
    assert policy["weaker_than_default"] is False
    assert policy["non_blocking_filters"] == ["Protected Material Code (Completion)"]


def test_harm_filter_off_or_missing_is_non_blocking():
    off = [*HARM[:-1], ("Selfharm", "Completion", True, False)]
    assert ai.project_rai_policy(_policy(*off))["harm_filters_enabled_and_blocking"] is False
    missing = [f for f in HARM if f[0] != "Violence"]
    assert ai.project_rai_policy(_policy(*missing))["harm_filters_enabled_and_blocking"] is False


def test_custom_policy_without_jailbreak_protection_is_weaker_than_default():
    bypass = ai.project_rai_policy(_policy(*HARM, ("Jailbreak", "Prompt", False, False), policy_type="UserManaged"))
    assert bypass["custom"] is True and bypass["weaker_than_default"] is True
    # A system-managed policy is Microsoft's, never "weaker than default".
    system = ai.project_rai_policy(_policy(*HARM, ("Jailbreak", "Prompt", False, False)))
    assert system["weaker_than_default"] is False


def test_asynchronous_mode_is_flagged():
    assert ai.project_rai_policy(_policy(*HARM, JAILBREAK, mode="Asynchronous_filter"))["asynchronous_filtering"] is True
    assert ai.project_rai_policy(_policy(*HARM, JAILBREAK))["asynchronous_filtering"] is False


@pytest.mark.parametrize(
    "policy_name,policies,expected",
    [
        (None, {}, "none"),
        ("p", None, "unknown"),
        ("p", {}, "missing"),
        ("p", {"p": {"harm_filters_enabled_and_blocking": True, "jailbreak_blocking": False,
                     "indirect_attack_blocking": False, "asynchronous_filtering": False}}, "blocking"),
        ("p", {"p": {"harm_filters_enabled_and_blocking": False, "jailbreak_blocking": True,
                     "indirect_attack_blocking": False, "asynchronous_filtering": False}}, "non_blocking"),
    ],
)
def test_deployment_content_filter_status(policy_name, policies, expected):
    assert ai.deployment_record({"rai_policy_name": policy_name}, policies)["content_filter"] == expected


def test_deployment_jailbreak_status_is_independent_of_harm_filters():
    policies = {"p": {"harm_filters_enabled_and_blocking": True, "jailbreak_blocking": False,
                      "indirect_attack_blocking": True, "asynchronous_filtering": False}}
    record = ai.deployment_record({"rai_policy_name": "p"}, policies)
    assert record["jailbreak_protection"] == "non_blocking"
    assert record["indirect_attack_protection"] == "blocking"


@pytest.mark.parametrize(
    "sku,scope",
    [
        ("GlobalStandard", "global"),
        ("GlobalProvisionedManaged", "global"),
        ("DataZoneStandard", "data_zone"),
        ("Standard", "regional"),
        ("ProvisionedManaged", "regional"),
        ("SomethingNew", "unknown"),
        (None, "unknown"),
    ],
)
def test_processing_scope(sku, scope):
    assert ai.processing_scope(sku) == scope


def _setting(*logs, workspace="ws"):
    return {
        "workspace_id": workspace,
        "storage_account_id": None,
        "event_hub_authorization_rule_id": None,
        "logs": [{"category": c, "category_group": g, "enabled": e} for c, g, e in logs],
    }


@pytest.mark.parametrize(
    "diagnostics,expected",
    [
        (None, None),  # settings unread
        ([], False),
        ([_setting((None, "allLogs", True))], True),
        ([_setting(("Audit", None, True))], True),
        ([_setting(("RequestResponse", None, True))], False),  # logs, but not audit
        ([_setting(("Audit", None, False))], False),
        ([_setting(("Audit", None, True), workspace=None)], False),  # no destination
    ],
)
def test_audit_logs_exported(diagnostics, expected):
    assert ai.audit_logs_exported(diagnostics) is expected


@pytest.mark.parametrize(
    "auth,secret",
    [
        ("ApiKey", True),
        ("CustomKeys", True),
        ("SAS", True),
        ("AAD", False),
        ("ProjectManagedIdentity", False),  # the SDK has no model for this type; wire JSON keeps it
        ("None", False),
        ("SomethingNew", None),
    ],
)
def test_connection_stored_secret(auth, secret):
    connection = ai.project_connection({"name": "c", "properties": {"authType": auth}}, "account", None)
    assert connection["uses_stored_secret"] is secret
    assert connection["unauthenticated"] is (auth == "None")


def test_connection_target_drops_query_string():
    raw = {"name": "c", "properties": {"authType": "SAS", "target": "https://st.blob.core.windows.net/c?sv=1&sig=SECRET"}}
    assert ai.project_connection(raw, "account", None)["target"] == "https://st.blob.core.windows.net/c"


@pytest.mark.parametrize(
    "props,exposure,auth_mode",
    [
        ({"publicNetworkAccess": "Disabled"}, "private", "entra_or_api_key"),
        ({"publicNetworkAccess": "Enabled", "networkRuleSet": {"ipRules": [{"value": "1.2.3.4"}]}}, "restricted", "entra_or_api_key"),
        ({"publicNetworkAccess": "Enabled", "disableLocalAuth": True}, "open", "entra_only"),
        ({"authOptions": {"apiKeyOnly": {}}}, "open", "api_key_only"),
    ],
)
def test_search_service_exposure_and_auth(props, exposure, auth_mode):
    service = ai.project_search_service({"id": f"{SUB}/resourceGroups/ai/providers/Microsoft.Search/searchServices/s", "properties": props})
    assert service["network_exposure"] == exposure and service["auth_mode"] == auth_mode


# --------------------------------------------------------------------------- #
# Managed identities
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "scope,expected",
    [
        (SUB, "subscription"),
        (f"{SUB}/resourceGroups/net", "resource_group"),
        (VNET, "resource"),
        ("/providers/Microsoft.Management/managementGroups/root", "management_group"),
        ("/", "root"),
    ],
)
def test_scope_level(scope, expected):
    assert mi.scope_level(scope) == expected


@pytest.mark.parametrize(
    "issuer,expected",
    [
        ("https://token.actions.githubusercontent.com", "github_actions"),
        ("https://vstoken.dev.azure.com/abc", "azure_devops"),
        ("https://eastus.oic.prod-aks.azure.com/tenant/guid/", "aks_workload_identity"),
        ("https://example.com", "other"),
    ],
)
def test_issuer_kind(issuer, expected):
    assert mi.issuer_kind(issuer) == expected


def _role(actions=(), not_actions=(), data_actions=()):
    return NS(permissions=[NS(actions=list(actions), not_actions=list(not_actions),
                              data_actions=list(data_actions), not_data_actions=[])])


@pytest.mark.parametrize(
    "role,expected",
    [
        # Owner: everything, including granting access.
        (_role(["*"]), {"full_control": True, "can_grant_access": True, "can_read_keys": True, "full_data_access": False}),
        # Contributor: everything except Microsoft.Authorization writes.
        (_role(["*"], ["Microsoft.Authorization/*/Write", "Microsoft.Authorization/*/Delete"]),
         {"full_control": True, "can_grant_access": False, "can_read_keys": True, "full_data_access": False}),
        # Storage Account Contributor: no data actions, but listKeys hands back full data access.
        (_role(["Microsoft.Storage/storageAccounts/*"]),
         {"full_control": False, "can_grant_access": False, "can_read_keys": True, "full_data_access": False}),
        # Storage Blob Data Owner: wildcard data actions.
        (_role([], [], ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*"]),
         {"full_control": False, "can_grant_access": False, "can_read_keys": False, "full_data_access": True}),
        # Reader: nothing of the above.
        (_role(["*/read"]), {"full_control": False, "can_grant_access": False, "can_read_keys": False, "full_data_access": False}),
        # A custom role that can assign roles, judged the same as a built-in.
        (_role(["Microsoft.Authorization/roleAssignments/write"]),
         {"full_control": False, "can_grant_access": True, "can_read_keys": False, "full_data_access": False}),
    ],
    ids=["owner", "contributor", "storage-account-contributor", "blob-data-owner", "reader", "custom-grant"],
)
def test_role_capabilities_come_from_permissions(role, expected):
    assert mi.role_capabilities(role) == expected


def test_unresolved_role_has_unknown_capabilities():
    record = mi.project_role_assignment(
        NS(role_definition_id=f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/zzz", scope=SUB,
           principal_id="p1", condition=None),
        {},
    )
    assert record["role_resolved"] is False and record["can_grant_access"] is None


def test_unread_roles_and_graph_are_unknown_not_none():
    record = mi.identity_record({"principal_id": "p1"}, None, None)
    assert record["role_assignments"] is None and record["has_broad_role"] is None
    assert record["role_full_data_access"] is None and record["graph_app_roles"] is None
    empty = mi.identity_record({"principal_id": "p1"}, {}, {})
    assert empty["role_assignments"] == [] and empty["role_can_grant_access"] is False


def _fic(subject=None, audiences=("api://AzureADTokenExchange",), expression=None):
    props = {"issuer": "https://token.actions.githubusercontent.com", "subject": subject, "audiences": list(audiences)}
    if expression:
        props["claimsMatchingExpression"] = {"value": expression, "languageVersion": 1}
    return mi.project_federated_credential({"name": "f", "properties": props})


@pytest.mark.parametrize(
    "subject,kind,broad",
    [
        ("repo:org/app:ref:refs/heads/main", "branch", False),
        ("repo:org/app:environment:prod", "environment", False),
        ("repo:org/app:pull_request", "pull_request", True),  # any PR's workflow can sign in
        ("repo:org/*:ref:refs/heads/main", "branch", True),
    ],
)
def test_github_subject_breadth(subject, kind, broad):
    fic = _fic(subject)
    assert fic["github_subject_kind"] == kind and fic["broad_subject"] is broad


def test_claims_matching_expression_is_broad():
    assert _fic(None, expression="claims['sub'] matches 'repo:org/*'")["broad_subject"] is True


@pytest.mark.parametrize(
    "audiences,nonstandard",
    [(["api://AzureADTokenExchange"], False), (["api://AzureADTokenExchangeUSGov"], False), (["https://other"], True), ([], True)],
)
def test_nonstandard_audience(audiences, nonstandard):
    assert _fic("repo:org/app:ref:refs/heads/main", audiences=audiences)["nonstandard_audience"] is nonstandard


@pytest.mark.parametrize(
    "permission,privileged",
    [("Directory.ReadWrite.All", True), ("Sites.FullControl.All", True), ("Mail.Send", True), ("User.Read.All", False)],
)
def test_privileged_graph_permission(permission, privileged):
    assert mi.privileged_graph_permission(permission) is privileged


@pytest.mark.parametrize(
    "identity_type,system,users",
    [
        ("SystemAssigned", True, 0),
        ("SystemAssigned, UserAssigned", True, 1),
        ("UserAssigned", False, 1),
        ("None", False, 0),
    ],
)
def test_resource_identities(identity_type, system, users):
    uai = {f"{SUB}/resourceGroups/id/providers/Microsoft.ManagedIdentity/userAssignedIdentities/u1": {}} if users else {}
    resource = NS(id="r1", name="r1", type="t", identity=NS(type=identity_type, principal_id="p", user_assigned_identities=uai))
    holder = mi.resource_identities(resource)
    assert holder["system_assigned"] is system and len(holder["user_assigned_ids"]) == users


# --------------------------------------------------------------------------- #
# API Management
# --------------------------------------------------------------------------- #

OLD = datetime(2017, 6, 1, tzinfo=timezone.utc)
NEW = datetime(2025, 6, 1, tzinfo=timezone.utc)
TLS10 = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10"
CIPHER = "Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers."


@pytest.mark.parametrize(
    "props,created,enabled,source",
    [
        ({TLS10: "False"}, OLD, False, "explicit"),
        ({TLS10: "True"}, NEW, True, "explicit"),
        ({}, OLD, True, "default"),  # unset on a pre-April-2018 service: Azure leaves it on
        ({}, NEW, False, "default"),
    ],
)
def test_legacy_protocol_defaults_follow_creation_date(props, created, enabled, source):
    setting = apim.protocol_settings(props, created)["client_tls_1_0"]
    assert setting == {"enabled": enabled, "source": source}


def test_unset_ciphers_are_on_by_default():
    """Azure leaves the CBC / RSA-key-exchange suites on until each is set to False."""
    ciphers = apim.cipher_settings({CIPHER + "TripleDes168": "False"}, NEW)
    assert ciphers["TLS_RSA_WITH_AES_128_CBC_SHA"] == {
        "enabled": True, "source": "default", "weaknesses": ["cbc", "no_forward_secrecy"]
    }
    assert ciphers["TripleDes168"]["enabled"] is False
    assert len([c for c in ciphers.values() if c["enabled"]]) == 9


def test_switched_off_ciphers_are_off():
    props = {CIPHER + name: "False" for name in apim.DEFAULT_ON_CIPHERS}
    assert not any(c["enabled"] for c in apim.cipher_settings(props, NEW).values())


@pytest.mark.parametrize("version,enforced", [(None, False), ("2019-12-01", True), ("2021-08-01", True), ("2018-01-01", False)])
def test_minimum_api_version_enforced(version, enforced):
    assert apim.api_version_enforced(version) is enforced


@pytest.mark.parametrize(
    "scope,kind",
    [
        (f"{SUB}/resourceGroups/a/providers/Microsoft.ApiManagement/service/s/", "all_apis"),
        (f"{SUB}/resourceGroups/a/providers/Microsoft.ApiManagement/service/s/apis", "all_apis"),
        (f"{SUB}/resourceGroups/a/providers/Microsoft.ApiManagement/service/s/products/starter", "product"),
        (f"{SUB}/resourceGroups/a/providers/Microsoft.ApiManagement/service/s/apis/echo", "api"),
    ],
)
def test_subscription_scope_kind(scope, kind):
    assert apim.subscription_scope_kind(scope) == kind


def _api(subscription_required=False, oauth=False, policy=(), operations=()):
    return {
        "subscription_required": subscription_required,
        "oauth2_or_openid_configured": oauth,
        "policy_elements": list(policy) if policy is not None else None,
        "operations": [{"policy_elements": o} for o in operations] if operations is not None else None,
    }


@pytest.mark.parametrize(
    "api,global_elements,products,expected",
    [
        (_api(subscription_required=True), [], [], True),
        (_api(policy=["validate-jwt"]), [], [], True),
        (_api(), ["validate-azure-ad-token"], [], True),  # global policy protects it
        (_api(), [], [["validate-jwt"]], True),  # a containing product protects it
        (_api(operations=[["validate-jwt"], ["validate-jwt"]]), [], [], True),
        (_api(operations=[["validate-jwt"], []]), [], [], False),  # one open operation
        (_api(), [], [], False),
        (_api(policy=None), [], [], None),  # API policy unread
        (_api(), [], [None], None),  # product policy unread
    ],
)
def test_api_access_control(api, global_elements, products, expected):
    assert apim.api_access_control(api, global_elements, products) is expected


def test_policy_elements_match_whole_element_names():
    xml = "<policies><inbound><rate-limit-by-key calls='5' /><ip-filter action='allow'/></inbound></policies>"
    assert apim.policy_elements(xml) == ["ip-filter", "rate-limit-by-key"]


def test_days_until_expiry():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert apim.days_until(datetime(2026, 1, 21, tzinfo=timezone.utc), now) == 20
    assert apim.days_until(datetime(2025, 12, 1, tzinfo=timezone.utc), now) < 0
    assert apim.days_until(None, now) is None


def test_backend_auth_configured_without_values():
    with_header = NS(name="b", protocol="http", url="https://x", tls=None, resource_id=None,
                     credentials=NS(header={"x-key": ["{{secret}}"]}, query=None, authorization=None,
                                    certificate=None, certificate_ids=None))
    record = apim.project_backend(with_header)
    assert record["auth_configured"] is True and "credentials" not in record


def test_gateway_logs_count_as_audit_logs():
    setting = {"workspace_id": "ws", "storage_account_id": None, "event_hub_authorization_rule_id": None,
               "logs": [{"category": "GatewayLogs", "category_group": None, "enabled": True}]}
    assert apim.logs_exported([setting], categories=("gatewaylogs",)) is True


def test_sign_up_unavailable_in_v2_tier_is_not_a_failure():
    class Fails:
        class sign_up_settings:  # noqa: N801 — mirrors the SDK operation group
            @staticmethod
            def get(rg, name):
                raise RuntimeError("(MethodNotAllowedInPricingTier) Method not allowed in StandardV2 pricing tier")

    collector = apim.Collector(apim.logger)
    assert apim.sign_up_status(Fails, "rg", "svc", collector) == "not_available_in_tier"
    assert collector.ok
