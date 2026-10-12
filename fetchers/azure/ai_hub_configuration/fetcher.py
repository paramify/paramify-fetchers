#!/usr/bin/env python3
"""Azure AI hubs and projects (Machine Learning workspaces): network isolation, encryption, datastores, endpoints, compute and connections."""

import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    arm_list,
    basename,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    list_diagnostic_settings,
    logs_exported,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_ai_hub_configuration")

# Read as ARM JSON: azure-mgmt-machinelearningservices 1.x predates hubs, projects,
# managed networks and connection auth types.
WORKSPACES_API = "2024-10-01"
WORKSPACES_PATH = "/providers/Microsoft.MachineLearningServices/workspaces"

# Connection auth types that keep a credential in the connection, and those that keep none.
STORED_SECRET_AUTH = {
    "apikey",
    "customkeys",
    "pat",
    "usernamepassword",
    "accesskey",
    "sas",
    "accountkey",
    "serviceprincipal",
    "oauth2",
}
KEYLESS_AUTH = {"aad", "managedidentity", "projectmanagedidentity", "agenticidentity", "useridentity"}
# systemDatastoresAuthMode values that avoid the storage account key.
IDENTITY_DATASTORE_MODES = {"identity", "userdelegationsas"}
# Datastore credential types that keep a secret in the workspace; None means identity-based access.
STORED_CREDENTIAL_TYPES = {"accountkey", "sas", "serviceprincipal", "certificate"}


def compact(name) -> str:
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


def stored_secret(auth_type):
    """True for auth types that keep a credential in the connection, False for keyless, None if unrecognised."""
    kind = compact(auth_type)
    if kind in STORED_SECRET_AUTH:
        return True
    if kind in KEYLESS_AUTH or kind == "none":
        return False
    return None


def strip_query(target) -> str:
    """A connection target without query string or fragment, which can carry a SAS token."""
    text = str(target or "")
    if "://" not in text:
        return text
    parts = urlsplit(text)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def network_exposure(public_network_access, ip_allowlist) -> str:
    """private / restricted / open. Azure treats an unset publicNetworkAccess as Enabled."""
    if str(public_network_access or "").lower() == "disabled":
        return "private"
    if ip_allowlist:
        return "restricted"
    return "open"


def project_outbound_rule(name: str, rule: dict) -> dict:
    destination = rule.get("destination")
    if isinstance(destination, dict):
        destination = destination.get("serviceResourceId") or destination.get("serviceTag") or str(destination)
    return {
        "name": name,
        "type": rule.get("type"),
        "category": rule.get("category"),
        "destination": destination,
        "status": rule.get("status"),
    }


def project_workspace(raw: dict) -> dict:
    props = raw.get("properties") or {}
    managed = props.get("managedNetwork") or {}
    isolation = managed.get("isolationMode") or "Disabled"
    encryption = props.get("encryption") or {}
    key_id = (encryption.get("keyVaultProperties") or {}).get("keyIdentifier")
    identity = raw.get("identity") or {}
    pna = props.get("publicNetworkAccess")
    allowlist = props.get("ipAllowlist") or []
    connections = [
        {
            "id": c.get("id"),
            "status": ((c.get("properties") or {}).get("privateLinkServiceConnectionState") or {}).get("status"),
        }
        for c in props.get("privateEndpointConnections") or []
    ]
    hub_id = props.get("hubResourceId")
    kind = raw.get("kind") or "Default"
    # Azure's documented default when systemDatastoresAuthMode is unset.
    datastore_mode = props.get("systemDatastoresAuthMode") or "accessKey"
    exposure = network_exposure(pna, allowlist)
    serverless = props.get("serverlessComputeSettings") or {}
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "kind": kind,
        "location": raw.get("location"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "tags": raw.get("tags") or {},
        "sku": (raw.get("sku") or {}).get("name"),
        "identity_type": identity.get("type"),
        "user_assigned_identity_ids": sorted((identity.get("userAssignedIdentities") or {}).keys()),
        "provisioning_state": props.get("provisioningState"),
        "hub_resource_id": hub_id,
        "hub_name": basename(hub_id),
        "project_without_hub": compact(kind) == "project" and not hub_id,
        "public_network_access": pna,
        "ip_allowlist": allowlist,
        "private_endpoint_connections": connections,
        "network_exposure": exposure,
        "private_endpoint_but_public_access": bool(connections) and exposure != "private",
        "allow_public_access_when_behind_vnet": props.get("allowPublicAccessWhenBehindVnet"),
        "managed_network_isolation_mode": isolation,
        "managed_network_status": (managed.get("status") or {}).get("status"),
        "outbound_restricted": compact(isolation) == "allowonlyapprovedoutbound",
        "outbound_rules": sorted(
            (project_outbound_rule(n, r or {}) for n, r in (managed.get("outboundRules") or {}).items()),
            key=lambda r: r["name"] or "",
        ),
        "serverless_compute_no_public_ip": serverless.get("serverlessComputeNoPublicIP"),
        "hbi_workspace": bool(props.get("hbiWorkspace")),
        "v1_legacy_mode": bool(props.get("v1LegacyMode")),
        "data_isolation_enabled": bool(props.get("enableDataIsolation")),
        "allow_role_assignment_on_resource_group": props.get("allowRoleAssignmentOnRG"),
        "encryption_status": encryption.get("status"),
        "customer_managed_key": compact(encryption.get("status")) == "enabled" and bool(key_id),
        "key_identifier": key_id,
        "system_datastores_auth_mode": datastore_mode,
        "identity_based_datastore_access": compact(datastore_mode) in IDENTITY_DATASTORE_MODES,
        "key_vault_id": props.get("keyVault"),
        "storage_account_id": props.get("storageAccount"),
        "container_registry_id": props.get("containerRegistry"),
        "application_insights_id": props.get("applicationInsights"),
    }


def project_datastore(raw: dict) -> dict:
    """A datastore and how the workspace authenticates to it; the credential itself is never returned by the list."""
    props = raw.get("properties") or {}
    cred = (props.get("credentials") or {}).get("credentialsType")
    return {
        "name": raw.get("name"),
        "datastore_type": props.get("datastoreType"),
        "credentials_type": cred,
        "stored_credentials": compact(cred) in STORED_CREDENTIAL_TYPES,
        "is_default": props.get("isDefault"),
    }


def project_endpoint(raw: dict, kind: str) -> dict:
    """An online (managed) or serverless model endpoint: who may call it and from where."""
    props = raw.get("properties") or {}
    auth = props.get("authMode")
    pna = props.get("publicNetworkAccess")
    return {
        "name": raw.get("name"),
        "kind": kind,
        "auth_mode": auth,
        "key_auth": compact(auth) == "key",
        "public_network_access": pna,
        # Online endpoints default to Enabled; serverless endpoints have no setting and are public.
        "public": str(pna or "enabled").lower() != "disabled",
        "state": props.get("provisioningState") or props.get("endpointState"),
        "model_id": (props.get("modelSettings") or {}).get("modelId"),
    }


def project_compute(raw: dict) -> dict:
    props = raw.get("properties") or {}
    inner = props.get("properties") or {}
    compute_type = props.get("computeType")
    public_ip = inner.get("enableNodePublicIp")
    # AmlCompute nodes get public IPs unless enableNodePublicIp is set to false.
    if public_ip is None and compact(compute_type) == "amlcompute":
        public_ip = True
    ssh = (inner.get("sshSettings") or {}).get("sshPublicAccess")
    return {
        "name": raw.get("name"),
        "compute_type": compute_type,
        "state": props.get("provisioningState"),
        "public_ip": None if public_ip is None else bool(public_ip),
        "ssh_public_access": ssh,
        "ssh_public": compact(ssh) == "enabled",
        "remote_login_port_public_access": inner.get("remoteLoginPortPublicAccess"),
    }


def project_connection(raw: dict) -> dict:
    """One workspace connection; credentials are never read (the list does not return them)."""
    props = raw.get("properties") or {}
    auth = props.get("authType")
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "category": props.get("category"),
        "auth_type": auth,
        "uses_stored_secret": stored_secret(auth),
        "unauthenticated": compact(auth) == "none",
        "target": strip_query(props.get("target")),
        "is_shared_to_all": props.get("isSharedToAll"),
    }


def summarize(workspaces: list[dict]) -> dict:
    connections = [c for w in workspaces for c in w["connections"] or []]
    # A project inherits its hub's connections: count each (category, auth, target) once across workspaces.
    distinct = {(c["category"], c["auth_type"], c["target"]): c for c in connections}.values()
    datastores = [d for w in workspaces for d in w["datastores"] or []]
    endpoints = [e for w in workspaces for e in w["endpoints"] or []]
    computes = [c for w in workspaces for c in w["computes"] or []]

    def count(items, pred):
        return sum(1 for i in items if pred(i))

    kinds = sorted({w["kind"] for w in workspaces})
    return {
        "total_workspaces": len(workspaces),
        "workspaces_by_kind": {k: count(workspaces, lambda w, k=k: w["kind"] == k) for k in kinds},
        "hubs": count(workspaces, lambda w: compact(w["kind"]) == "hub"),
        "projects": count(workspaces, lambda w: compact(w["kind"]) == "project"),
        "projects_without_hub": count(workspaces, lambda w: w["project_without_hub"]),
        "workspaces_open_to_all_networks": count(workspaces, lambda w: w["network_exposure"] == "open"),
        "workspaces_network_restricted": count(workspaces, lambda w: w["network_exposure"] == "restricted"),
        "workspaces_private_only": count(workspaces, lambda w: w["network_exposure"] == "private"),
        "workspaces_with_private_endpoint_but_public_access": count(
            workspaces, lambda w: w["private_endpoint_but_public_access"]
        ),
        "workspaces_managed_network_disabled": count(
            workspaces, lambda w: compact(w["managed_network_isolation_mode"]) == "disabled"
        ),
        "workspaces_managed_network_internet_outbound": count(
            workspaces, lambda w: compact(w["managed_network_isolation_mode"]) == "allowinternetoutbound"
        ),
        "workspaces_outbound_restricted": count(workspaces, lambda w: w["outbound_restricted"]),
        "workspaces_hbi": count(workspaces, lambda w: w["hbi_workspace"]),
        "workspaces_customer_managed_key": count(workspaces, lambda w: w["customer_managed_key"]),
        "workspaces_identity_based_datastore_access": count(
            workspaces, lambda w: w["identity_based_datastore_access"]
        ),
        "workspaces_data_isolation_enabled": count(workspaces, lambda w: w["data_isolation_enabled"]),
        "workspaces_v1_legacy_mode": count(workspaces, lambda w: w["v1_legacy_mode"]),
        "workspaces_without_managed_identity": count(
            workspaces, lambda w: compact(w["identity_type"] or "none") == "none"
        ),
        "workspaces_diagnostic_logs_exported": count(workspaces, lambda w: w["diagnostic_logs_exported"] is True),
        "workspaces_diagnostic_logs_unknown": count(workspaces, lambda w: w["diagnostic_logs_exported"] is None),
        "total_datastores": len(datastores),
        "datastores_with_stored_credentials": count(datastores, lambda d: d["stored_credentials"]),
        "workspaces_datastores_unknown": count(workspaces, lambda w: w["datastores"] is None),
        "total_endpoints": len(endpoints),
        "endpoints_key_auth": count(endpoints, lambda e: e["key_auth"]),
        "endpoints_public": count(endpoints, lambda e: e["public"]),
        "endpoints_public_with_key_auth": count(endpoints, lambda e: e["public"] and e["key_auth"]),
        "workspaces_endpoints_unknown": count(workspaces, lambda w: w["endpoints"] is None),
        "total_computes": len(computes),
        "computes_public_ip": count(computes, lambda c: c["public_ip"] is True),
        "computes_ssh_public": count(computes, lambda c: c["ssh_public"]),
        "workspaces_computes_unknown": count(workspaces, lambda w: w["computes"] is None),
        "total_connections": len(connections),
        "connections_using_stored_secrets": count(connections, lambda c: c["uses_stored_secret"] is True),
        "connections_unauthenticated": count(connections, lambda c: c["unauthenticated"]),
        "connections_auth_type_unrecognized": count(connections, lambda c: c["uses_stored_secret"] is None),
        "connections_shared_to_all": count(connections, lambda c: c["is_shared_to_all"] is True),
        "distinct_connections": len(distinct),
        "distinct_connections_using_stored_secrets": count(distinct, lambda c: c["uses_stored_secret"] is True),
        "workspaces_connections_unknown": count(workspaces, lambda w: w["connections"] is None),
    }


def collect(subscription_id, cred, collector: Collector) -> list[dict]:
    def _client():
        # Any management client supplies the authenticated ARM pipeline; this one is already a dependency.
        try:
            from azure.mgmt.resource.resources import ResourceManagementClient  # lazy
        except ImportError:  # pragma: no cover - depends on installed SDK version
            from azure.mgmt.resource import ResourceManagementClient  # lazy

        return ResourceManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("resource.ResourceManagementClient (init)", _client)
    if client is None:
        return []
    workspaces = collector.guard(
        "machinelearningservices.workspaces.list",
        lambda: [
            project_workspace(w)
            for w in arm_list(client, f"/subscriptions/{subscription_id}{WORKSPACES_PATH}?api-version={WORKSPACES_API}")
        ],
        default=[],
    )
    monitor = (
        collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
        if workspaces
        else None
    )
    records = []
    for workspace in workspaces:
        label = f"{workspace['resource_group']}/{workspace['name']}"
        connections = collector.guard(
            f"machinelearningservices.connections.list({label})",
            lambda workspace=workspace: [
                project_connection(c)
                for c in arm_list(client, f"{workspace['id']}/connections?api-version={WORKSPACES_API}")
            ],
        )
        def _sub(name, project, workspace=workspace, label=label):
            rows = collector.guard(
                f"machinelearningservices.{name}.list({label})",
                lambda: [project(r) for r in arm_list(client, f"{workspace['id']}/{name}?api-version={WORKSPACES_API}")],
            )
            return None if rows is None else sorted(rows, key=lambda r: r["name"] or "")

        online = _sub("onlineEndpoints", lambda r: project_endpoint(r, "online"))
        serverless = _sub("serverlessEndpoints", lambda r: project_endpoint(r, "serverless"))
        diagnostics = None
        if monitor is not None:
            diagnostics = collector.guard(
                f"monitor.diagnostic_settings.list({label})",
                lambda workspace=workspace: list_diagnostic_settings(monitor, workspace["id"]),
            )
        records.append(
            {
                **workspace,
                "connections": None if connections is None else sorted(connections, key=lambda c: c["name"] or ""),
                "datastores": _sub("datastores", project_datastore),
                "endpoints": None if online is None or serverless is None else online + serverless,
                "computes": _sub("computes", project_compute),
                "diagnostic_settings": diagnostics,
                "diagnostic_logs_exported": logs_exported(diagnostics, categories=("computeinstanceevent",)),
            }
        )
    return sorted(records, key=lambda r: r["id"] or "")


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

    workspaces: list = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.MachineLearningServices"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.MachineLearningServices is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        workspaces = collect(subscription_id, cred, collector)
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
        results={"workspaces": workspaces, "provider_registration_status": registration},
        summary={**summarize(workspaces), "provider_registration_status": registration},
    )
    filename = f"azure_ai_hub_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
