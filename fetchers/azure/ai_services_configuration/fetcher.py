#!/usr/bin/env python3
"""Azure AI services and AI Search: access, keys, encryption, logging, models, content filters and outbound connections."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from arm_rest import arm_rest_client, list_all  # noqa: E402
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    list_diagnostic_settings,
    model_attr,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from diagnostics import audit_logging_summary  # noqa: E402
from foundry_connections import compact, connection_fields  # noqa: E402

logger = logging.getLogger("azure_ai_services_configuration")

# Connections and AI Search are read as wire JSON: azure-mgmt-cognitiveservices drops
# connection auth types it has no model for (ProjectManagedIdentity reads as None), and
# the repo has no AI Search SDK.
CONNECTIONS_API = "2025-06-01"
SEARCH_API = "2025-05-01"

# Kinds that host model deployments, content filters, projects and connections.
MODEL_KINDS = {"aiservices", "openai"}
MICROSOFT_MANAGED_KEY_SOURCE = "microsoft.cognitiveservices"
# The harm categories a content filter must block. Others (e.g. Protected Material Code) are
# annotate-only in Microsoft's own default policy, so they are listed, not judged.
HARM_CATEGORIES = ("hate", "sexual", "violence", "selfharm")
# A threshold is the lowest severity blocked, so High blocks least. Microsoft's DefaultV2 blocks every harm
# category at Medium on prompts and completions (learn.microsoft.com/azure/foundry/guardrails/default-safety-policies).
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
DEFAULT_HARM_THRESHOLD = "medium"
FIRST_PARTY_PUBLISHERS = {"openai", "microsoft"}


def network_exposure(public_network_access, default_action) -> str:
    """private / restricted / open — how reachable the endpoint is.

    Azure treats an unset publicNetworkAccess as Enabled and an unset network rule
    default as Allow, so unset reads as open, never as private.
    """
    if str(public_network_access or "").lower() == "disabled":
        return "private"
    if str(default_action or "allow").lower() == "deny":
        return "restricted"
    return "open"


ACCOUNT_AUDIT_CATEGORIES = ("Audit",)
# AI Search has no Audit category: its resource log, one record per request, is OperationLogs.
SEARCH_AUDIT_CATEGORIES = ("OperationLogs",)


def audit_logs_exported(diagnostics, categories=ACCOUNT_AUDIT_CATEGORIES):
    """One of `categories`, or the audit / allLogs group, exported; None when settings could not be read."""
    return audit_logging_summary(diagnostics, categories)["audit_logging_enabled"]


def processing_scope(sku) -> str:
    """Where a deployment may process data, from its deployment type."""
    name = compact(sku)
    if name.startswith("global"):
        return "global"
    if name.startswith("datazone"):
        return "data_zone"
    if name in ("standard", "provisionedmanaged", "batch"):
        return "regional"
    return "unknown"


def project_account(account) -> dict:
    props = model_attr(account, "properties")
    acls = model_attr(props, "network_acls")
    encryption = model_attr(props, "encryption")
    vault = model_attr(encryption, "key_vault_properties")
    identity = model_attr(account, "identity")
    sku = model_attr(account, "sku")
    connections = [
        {
            "id": model_attr(c, "id"),
            "status": model_attr(
                model_attr(model_attr(c, "properties"), "private_link_service_connection_state"), "status"
            ),
        }
        for c in model_attr(props, "private_endpoint_connections") or []
    ]
    disable_local_auth = model_attr(props, "disable_local_auth")
    key_source = model_attr(encryption, "key_source")
    pna = model_attr(props, "public_network_access")
    default_action = model_attr(acls, "default_action")
    exposure = network_exposure(pna, default_action)
    return {
        "id": model_attr(account, "id"),
        "name": model_attr(account, "name"),
        "kind": model_attr(account, "kind"),
        "sku": model_attr(sku, "name"),
        "location": model_attr(account, "location"),
        "resource_group": resource_group_from_id(model_attr(account, "id")),
        "tags": model_attr(account, "tags") or {},
        "custom_sub_domain_name": model_attr(props, "custom_sub_domain_name"),
        "provisioning_state": model_attr(props, "provisioning_state"),
        "identity_type": model_attr(identity, "type"),
        "user_assigned_identity_ids": sorted((model_attr(identity, "user_assigned_identities") or {}).keys()),
        "public_network_access": pna,
        "network_acls_default_action": default_action,
        "network_acls_bypass": model_attr(acls, "bypass"),
        "ip_rules": [model_attr(r, "value") for r in model_attr(acls, "ip_rules") or []],
        "virtual_network_rule_ids": [model_attr(r, "id") for r in model_attr(acls, "virtual_network_rules") or []],
        "private_endpoint_connections": connections,
        "network_exposure": exposure,
        "private_endpoint_but_public_access": bool(connections) and exposure != "private",
        "disable_local_auth": disable_local_auth,
        # disableLocalAuth defaults to false: unset means API keys work.
        "api_keys_enabled": disable_local_auth is not True,
        "encryption_key_source": key_source,
        "customer_managed_key": bool(key_source) and str(key_source).lower() != MICROSOFT_MANAGED_KEY_SOURCE,
        "key_vault_uri": model_attr(vault, "key_vault_uri"),
        "key_name": model_attr(vault, "key_name"),
        "restrict_outbound_network_access": model_attr(props, "restrict_outbound_network_access"),
        "allowed_fqdn_list": model_attr(props, "allowed_fqdn_list") or [],
        "user_owned_storage_ids": [
            model_attr(s, "resource_id") for s in model_attr(props, "user_owned_storage") or []
        ],
        "stored_completions_disabled": model_attr(props, "stored_completions_disabled"),
        "allow_project_management": model_attr(props, "allow_project_management"),
    }


def project_deployment(deployment) -> dict:
    props = model_attr(deployment, "properties")
    model = model_attr(props, "model")
    sku = model_attr(deployment, "sku")
    publisher = model_attr(model, "format")
    return {
        "name": model_attr(deployment, "name"),
        "model_name": model_attr(model, "name"),
        "model_publisher": publisher,
        "third_party_publisher": bool(publisher) and compact(publisher) not in FIRST_PARTY_PUBLISHERS,
        "model_version": model_attr(model, "version"),
        "sku": model_attr(sku, "name"),
        "processing_scope": processing_scope(model_attr(sku, "name")),
        "capacity": model_attr(sku, "capacity"),
        "rai_policy_name": model_attr(props, "rai_policy_name"),
        "version_upgrade_option": model_attr(props, "version_upgrade_option"),
        "provisioning_state": model_attr(props, "provisioning_state"),
    }


def filter_blocking(filters: list, category: str) -> bool:
    """Every filter of a category present, enabled and blocking."""
    matching = [f for f in filters if compact(f["name"]) == category]
    return bool(matching) and all(f["enabled"] is True and f["blocking"] is True for f in matching)


def project_rai_policy(policy) -> dict:
    props = model_attr(policy, "properties")
    filters = [
        {
            "name": model_attr(f, "name"),
            "source": model_attr(f, "source"),
            "enabled": model_attr(f, "enabled"),
            "blocking": model_attr(f, "blocking"),
            "severity_threshold": model_attr(f, "severity_threshold"),
        }
        for f in model_attr(props, "content_filters") or []
    ]
    harm = [f for f in filters if compact(f["name"]) in HARM_CATEGORIES]
    harm_ok = {compact(f["name"]) for f in harm} == set(HARM_CATEGORIES) and all(
        f["enabled"] is True and f["blocking"] is True for f in harm
    )
    jailbreak = filter_blocking(filters, "jailbreak")
    ranks = [SEVERITY_RANK.get(compact(f["severity_threshold"])) for f in harm]
    # True when no harm filter blocks less than the default; None when a threshold is missing or unrecognised.
    if any(r is not None and r > SEVERITY_RANK[DEFAULT_HARM_THRESHOLD] for r in ranks):
        thresholds_ok = False
    elif not ranks or any(r is None for r in ranks):
        thresholds_ok = None
    else:
        thresholds_ok = True
    policy_type = model_attr(props, "type")
    custom = compact(policy_type) != "systemmanaged"
    if not custom:
        weaker = False
    elif not (harm_ok and jailbreak) or thresholds_ok is False:
        weaker = True
    else:
        weaker = None if thresholds_ok is None else False
    mode = model_attr(props, "mode")
    return {
        "name": model_attr(policy, "name"),
        "type": policy_type,
        "custom": custom,
        "mode": mode,
        "asynchronous_filtering": compact(mode) in ("asynchronous", "asynchronousfilter", "deferred"),
        "base_policy_name": model_attr(props, "base_policy_name"),
        "content_filters": filters,
        # Every harm category present, and each of its prompt and completion filters on and blocking.
        "harm_filters_enabled_and_blocking": harm_ok,
        "harm_thresholds_at_least_default": thresholds_ok,
        "harm_filters_looser_than_default": sorted(
            f"{f['name']} ({f['source']}): {f['severity_threshold']}"
            for f in harm
            if (SEVERITY_RANK.get(compact(f["severity_threshold"])) or 0) > SEVERITY_RANK[DEFAULT_HARM_THRESHOLD]
        ),
        "jailbreak_blocking": jailbreak,
        "indirect_attack_blocking": filter_blocking(filters, "indirectattack"),
        "custom_blocklists": [model_attr(b, "blocklist_name") for b in model_attr(props, "custom_blocklists") or []],
        "non_blocking_filters": sorted(
            f"{f['name']} ({f['source']})" for f in filters if not (f["enabled"] is True and f["blocking"] is True)
        ),
        # A custom policy that drops below Microsoft's default protection; null when a threshold is unknown.
        "weaker_than_default": weaker,
    }


def project_project(project) -> dict:
    props = model_attr(project, "properties")
    return {
        "name": basename(model_attr(project, "name")),
        "id": model_attr(project, "id"),
        "identity_type": model_attr(model_attr(project, "identity"), "type"),
        "is_default": model_attr(props, "is_default"),
        "provisioning_state": model_attr(props, "provisioning_state"),
    }


def project_connection(raw: dict, level: str, project) -> dict:
    """One Foundry connection, tagged with the level (account / project) it was listed at."""
    return {**connection_fields(raw), "level": level, "project": project}


def project_search_service(raw: dict) -> dict:
    props = raw.get("properties") or {}
    rules = props.get("networkRuleSet") or {}
    ip_rules = [r.get("value") for r in rules.get("ipRules") or []]
    pna = props.get("publicNetworkAccess")
    disable_local_auth = props.get("disableLocalAuth")
    auth_options = props.get("authOptions") or {}
    cmk = props.get("encryptionWithCmk") or {}
    connections = [
        {
            "id": c.get("id"),
            "status": ((c.get("properties") or {}).get("privateLinkServiceConnectionState") or {}).get("status"),
        }
        for c in props.get("privateEndpointConnections") or []
    ]
    # AI Search has no default action: an empty IP rule list with public access on is open.
    if str(pna or "").lower() == "disabled":
        exposure = "private"
    elif ip_rules:
        exposure = "restricted"
    else:
        exposure = "open"
    if disable_local_auth is True:
        auth_mode = "entra_only"
    elif "apiKeyOnly" in auth_options:
        auth_mode = "api_key_only"
    else:
        auth_mode = "entra_or_api_key"
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "location": raw.get("location"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "sku": (raw.get("sku") or {}).get("name"),
        "identity_type": (raw.get("identity") or {}).get("type"),
        "public_network_access": pna,
        "ip_rules": ip_rules,
        "network_rule_bypass": rules.get("bypass"),
        "private_endpoint_connections": connections,
        "network_exposure": exposure,
        "disable_local_auth": disable_local_auth,
        "api_keys_enabled": disable_local_auth is not True,
        "auth_mode": auth_mode,
        "cmk_enforcement": cmk.get("enforcement"),
        "cmk_compliance_status": cmk.get("encryptionComplianceStatus"),
        "data_exfiltration_protections": props.get("dataExfiltrationProtections") or [],
        "replica_count": props.get("replicaCount"),
        "partition_count": props.get("partitionCount"),
        "semantic_search": props.get("semanticSearch"),
        "status": props.get("status"),
    }


def policy_status(name, policies_by_name, flag: str) -> str:
    """blocking / non_blocking / none / missing / unknown for one deployment against one policy flag."""
    if not name:
        return "none"
    if policies_by_name is None:
        return "unknown"
    if name not in policies_by_name:
        return "missing"
    return "blocking" if policies_by_name[name][flag] else "non_blocking"


def deployment_record(deployment: dict, policies_by_name) -> dict:
    """The deployment with the protections its content filter (RAI) policy gives it.

    content_filter judges the four harm categories (hate, sexual, violence, self-harm);
    jailbreak_protection and indirect_attack_protection the Prompt Shields filters. Each is
    blocking, non_blocking, none (no policy named), missing (named policy not on the
    account) or unknown (policies could not be listed).
    """
    name = deployment["rai_policy_name"]
    policy = (policies_by_name or {}).get(name)
    return {
        **deployment,
        "content_filter": policy_status(name, policies_by_name, "harm_filters_enabled_and_blocking"),
        "jailbreak_protection": policy_status(name, policies_by_name, "jailbreak_blocking"),
        "indirect_attack_protection": policy_status(name, policies_by_name, "indirect_attack_blocking"),
        "asynchronous_filtering": None if policy is None else policy["asynchronous_filtering"],
    }


def summarize(accounts: list[dict], search_services: list[dict]) -> dict:
    total = len(accounts)
    deployments = [d for a in accounts for d in a["deployments"] or []]
    policies = [p for a in accounts for p in a["content_filter_policies"] or []]
    # Project connections are kept per project; an account-level repeat of one is not counted twice.
    connections = [
        c for a in accounts for c in a["connections"] or [] if not c.get("repeats_project_connection")
    ]

    def count(items, pred):
        return sum(1 for i in items if pred(i))

    entra_only = count(accounts, lambda a: not a["api_keys_enabled"])
    summary = {
        "total_accounts": total,
        "accounts_by_kind": {
            k: count(accounts, lambda a, k=k: a["kind"] == k) for k in sorted({a["kind"] for a in accounts})
        },
        "accounts_open_to_all_networks": count(accounts, lambda a: a["network_exposure"] == "open"),
        "accounts_network_restricted": count(accounts, lambda a: a["network_exposure"] == "restricted"),
        "accounts_private_only": count(accounts, lambda a: a["network_exposure"] == "private"),
        "accounts_with_private_endpoints": count(accounts, lambda a: a["private_endpoint_connections"]),
        "accounts_with_private_endpoint_but_public_access": count(
            accounts, lambda a: a["private_endpoint_but_public_access"]
        ),
        "accounts_with_api_keys_enabled": total - entra_only,
        "accounts_entra_only": entra_only,
        "accounts_entra_only_percentage": coverage_percentage(entra_only, total),
        "accounts_with_customer_managed_key": count(accounts, lambda a: a["customer_managed_key"]),
        "accounts_without_managed_identity": count(
            accounts, lambda a: str(a["identity_type"] or "none").lower() == "none"
        ),
        "accounts_with_outbound_restricted": count(accounts, lambda a: a["restrict_outbound_network_access"] is True),
        "accounts_with_diagnostic_settings": count(accounts, lambda a: a["diagnostic_settings"]),
        "accounts_audit_logs_exported": count(accounts, lambda a: a["audit_logs_exported"] is True),
        "accounts_audit_logs_unknown": count(accounts, lambda a: a["audit_logs_exported"] is None),
        "total_deployments": len(deployments),
        "deployments_global_processing": count(deployments, lambda d: d["processing_scope"] == "global"),
        "deployments_data_zone_processing": count(deployments, lambda d: d["processing_scope"] == "data_zone"),
        "deployments_regional_processing": count(deployments, lambda d: d["processing_scope"] == "regional"),
        "deployments_processing_scope_unknown": count(deployments, lambda d: d["processing_scope"] == "unknown"),
        "deployments_third_party_publisher": count(deployments, lambda d: d["third_party_publisher"]),
        "deployments_by_model_publisher": {
            p: count(deployments, lambda d, p=p: (d["model_publisher"] or "unknown") == p)
            for p in sorted({d["model_publisher"] or "unknown" for d in deployments})
        },
        "deployments_jailbreak_protection": count(deployments, lambda d: d["jailbreak_protection"] == "blocking"),
        "deployments_indirect_attack_protection": count(
            deployments, lambda d: d["indirect_attack_protection"] == "blocking"
        ),
        "deployments_asynchronous_filtering": count(deployments, lambda d: d["asynchronous_filtering"] is True),
        "deployments_with_automatic_version_upgrade": count(
            deployments,
            lambda d: d["version_upgrade_option"] in ("OnceNewDefaultVersionAvailable", "OnceCurrentVersionExpired"),
        ),
        "content_filter_policies_custom": count(policies, lambda p: p["custom"]),
        "content_filter_policies_weaker_than_default": count(policies, lambda p: p["weaker_than_default"] is True),
        "content_filter_policies_weaker_unknown": count(policies, lambda p: p["weaker_than_default"] is None),
        "content_filter_policies_custom_unused": count(policies, lambda p: p["custom"] and p["in_use"] is False),
        "total_projects": sum(len(a["projects"] or []) for a in accounts),
        "total_connections": len(connections),
        "connections_using_stored_secrets": count(connections, lambda c: c["uses_stored_secret"] is True),
        "connections_unauthenticated": count(connections, lambda c: c["unauthenticated"]),
        "connections_auth_type_unrecognized": count(connections, lambda c: c["uses_stored_secret"] is None),
        "connections_unknown_accounts": count(
            accounts, lambda a: a["connections"] is None and str(a["kind"] or "").lower() in MODEL_KINDS
        ),
        "remote_tool_connections": count(connections, lambda c: compact(c["category"]) == "remotetool"),
        # Grounding with Bing sends queries to Bing, outside the Azure compliance boundary.
        "grounding_with_bing_connections": count(
            connections, lambda c: compact(c["category"]).startswith("groundingwithbing")
        ),
        "total_search_services": len(search_services),
        "search_services_open_to_all_networks": count(search_services, lambda s: s["network_exposure"] == "open"),
        "search_services_with_api_keys_enabled": count(search_services, lambda s: s["api_keys_enabled"]),
        "search_services_cmk_enforced": count(
            search_services, lambda s: str(s["cmk_enforcement"] or "").lower() == "enabled"
        ),
        "search_services_audit_logs_exported": count(search_services, lambda s: s["audit_logs_exported"] is True),
    }
    for status in ("blocking", "non_blocking", "none", "missing", "unknown"):
        summary[f"deployments_content_filter_{status}"] = count(
            deployments, lambda d, s=status: d["content_filter"] == s
        )
    return summary


def collect_account(client, rest, monitor, account: dict, collector: Collector) -> dict:
    rg, name = account["resource_group"], account["name"]
    label = f"{rg}/{name}"
    diagnostics = None
    if monitor is not None:
        diagnostics = collector.guard(
            f"monitor.diagnostic_settings.list({label})", lambda: list_diagnostic_settings(monitor, account["id"])
        )
    deployments = policies = projects = connections = []
    if str(account["kind"] or "").lower() in MODEL_KINDS:
        deployments = collector.guard(
            f"cognitiveservices.deployments.list({label})",
            lambda: [project_deployment(d) for d in client.deployments.list(rg, name)],
        )
        policies = collector.guard(
            f"cognitiveservices.rai_policies.list({label})",
            lambda: [project_rai_policy(p) for p in client.rai_policies.list(rg, name)],
        )
        projects = collector.guard(
            f"cognitiveservices.projects.list({label})",
            lambda: [project_project(p) for p in client.projects.list(rg, name)],
        )
        connections = collector.guard(
            f"cognitiveservices.connections.list({label})",
            lambda: [
                project_connection(c, "account", None)
                for c in list_all(rest, f"{account['id']}/connections", CONNECTIONS_API)["items"]
            ],
        )
        for project in projects or []:
            rows = collector.guard(
                f"cognitiveservices.project_connections.list({label}/{project['name']})",
                lambda project=project: [
                    project_connection(c, "project", project["name"])
                    for c in list_all(rest, f"{project['id']}/connections", CONNECTIONS_API)["items"]
                ],
            )
            connections = None if rows is None or connections is None else connections + rows
    if connections:
        # The account list repeats each project's connections under an account-scoped id (measured).
        in_projects = {c["name"] for c in connections if c["level"] == "project"}
        for c in connections:
            c["repeats_project_connection"] = c["level"] == "account" and c["name"] in in_projects
    by_name = None if policies is None else {p["name"]: p for p in policies}
    records = None if deployments is None else [deployment_record(d, by_name) for d in deployments]
    used = {d["rai_policy_name"] for d in records or []}
    for policy in policies or []:
        policy["in_use"] = None if records is None else policy["name"] in used
    return {
        **account,
        "diagnostic_settings": diagnostics,
        "audit_logs_exported": audit_logs_exported(diagnostics),
        "deployments": None if records is None else sorted(records, key=lambda d: d["name"] or ""),
        "content_filter_policies": None if policies is None else sorted(policies, key=lambda p: p["name"] or ""),
        "projects": None if projects is None else sorted(projects, key=lambda p: p["name"] or ""),
        "connections": None
        if connections is None
        else sorted(connections, key=lambda c: (c["project"] or "", c["name"] or "")),
    }


def collect(subscription_id, cred, collector: Collector) -> tuple:
    def _client():
        from azure.mgmt.cognitiveservices import (
            CognitiveServicesManagementClient,  # lazy
        )

        return CognitiveServicesManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("cognitiveservices.CognitiveServicesManagementClient (init)", _client)
    rest = collector.guard("arm_rest.arm_rest_client (init)", lambda: arm_rest_client(cred))
    if client is None or rest is None:
        return [], []
    accounts = collector.guard(
        "cognitiveservices.accounts.list",
        lambda: [project_account(a) for a in client.accounts.list()],
        default=[],
    )
    search = collector.guard(
        "search.searchServices.list",
        lambda: [
            project_search_service(s)
            for s in list_all(
                rest, f"/subscriptions/{subscription_id}/providers/Microsoft.Search/searchServices", SEARCH_API
            )["items"]
        ],
        default=[],
    )
    monitor = (
        collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
        if accounts or search
        else None
    )
    records = [collect_account(client, rest, monitor, a, collector) for a in accounts]
    for service in search:
        diagnostics = None
        if monitor is not None:
            diagnostics = collector.guard(
                f"monitor.diagnostic_settings.list({service['resource_group']}/{service['name']})",
                lambda service=service: list_diagnostic_settings(monitor, service["id"]),
            )
        service["diagnostic_settings"] = diagnostics
        service["audit_logs_exported"] = audit_logs_exported(diagnostics, SEARCH_AUDIT_CATEGORIES)
    return (
        sorted(records, key=lambda r: r["id"] or ""),
        sorted(search, key=lambda r: r["id"] or ""),
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    accounts: list = []
    search_services: list = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.CognitiveServices")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.CognitiveServices is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        accounts, search_services = collect(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "accounts": accounts,
            "search_services": search_services,
            "provider_registration_status": registration,
        },
        summary={**summarize(accounts, search_services), "provider_registration_status": registration},
    )
    filename = f"azure_ai_services_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
