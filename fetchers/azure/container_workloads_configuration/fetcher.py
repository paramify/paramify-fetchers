#!/usr/bin/env python3
"""Azure Container Apps environments, apps and jobs, and Container Instances: exposure, traffic encryption, secrets and logging."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    list_diagnostic_settings,
    logs_exported,
    model_attr,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_container_workloads_configuration")

# A plain (non-secret) environment variable whose name suggests it carries a credential.
SECRET_NAME_MARKERS = (
    "secret",
    "password",
    "passwd",
    "pwd",
    "apikey",
    "token",
    "connectionstring",
    "connstr",
    "accesskey",
    "privatekey",
    "credential",
    "sastoken",
    "clientsecret",
)


def compact(name) -> str:
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


def secret_like(name) -> bool:
    return any(marker in compact(name) for marker in SECRET_NAME_MARKERS)


def identity_type(resource):
    return model_attr(model_attr(resource, "identity"), "type")


def prop(obj, name):
    """A TypeSpec model attribute, flattened or nested under `properties`."""
    value = model_attr(obj, name)
    return value if value is not None else model_attr(model_attr(obj, "properties"), name)


def image_reference(image) -> dict:
    """Whether an image reference pins what runs: a digest is immutable; `latest` or no tag is not."""
    text = str(image or "")
    digest = "@sha256:" in text
    last = text.split("@", 1)[0].rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    return {
        "image_tag": tag,
        "image_pinned_by_digest": digest,
        "image_tag_mutable": not digest and (tag is None or tag.lower() == "latest"),
    }


def registry_host(image) -> str:
    """The registry an image is pulled from: a host-like first path segment, else Docker Hub.

    `nginx:1.25` has no path, so its colon is a tag, not a port.
    """
    first, slash, _ = str(image or "").partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        return first
    return "docker.io"


# --------------------------------------------------------------------------- #
# Container Apps
# --------------------------------------------------------------------------- #

def project_environment(env) -> dict:
    vnet = model_attr(env, "vnet_configuration")
    internal = bool(model_attr(vnet, "internal") or False)
    pna = model_attr(env, "public_network_access")
    mtls = model_attr(model_attr(model_attr(env, "peer_authentication"), "mtls"), "enabled")
    peer_encryption = model_attr(model_attr(model_attr(env, "peer_traffic_configuration"), "encryption"), "enabled")
    profiles = [model_attr(p, "workload_profile_type") for p in model_attr(env, "workload_profiles") or []]
    if internal:
        exposure = "internal"
    elif str(pna or "").lower() == "disabled":
        exposure = "private"
    else:
        exposure = "public"
    return {
        "id": model_attr(env, "id"),
        "name": model_attr(env, "name"),
        "location": model_attr(env, "location"),
        "resource_group": resource_group_from_id(model_attr(env, "id")),
        "tags": model_attr(env, "tags") or {},
        "identity_type": identity_type(env),
        "infrastructure_subnet_id": model_attr(vnet, "infrastructure_subnet_id"),
        "internal_only": internal,
        "public_network_access": pna,
        "network_exposure": exposure,
        "mtls_enabled": bool(mtls or False),
        "peer_traffic_encryption_enabled": bool(peer_encryption or False),
        "app_logs_destination": model_attr(model_attr(env, "app_logs_configuration"), "destination"),
        "zone_redundant": bool(model_attr(env, "zone_redundant") or False),
        "workload_profiles": profiles,
        "consumption_only": not profiles,
    }


def project_secret(secret) -> dict:
    key_vault = bool(model_attr(secret, "key_vault_url"))
    return {
        "name": model_attr(secret, "name"),
        "key_vault_backed": key_vault,
        "identity_used": bool(model_attr(secret, "identity")),
        "stored_in_app": not key_vault,
    }


def project_registry(registry) -> dict:
    return {
        "server": model_attr(registry, "server"),
        "identity_used": bool(model_attr(registry, "identity")),
        "password_secret_ref": model_attr(registry, "password_secret_ref"),
        "password_based": not model_attr(registry, "identity") and bool(model_attr(registry, "password_secret_ref")),
    }


def project_app_container(container) -> dict:
    env = model_attr(container, "env") or []
    plain = [model_attr(e, "name") for e in env if not model_attr(e, "secret_ref")]
    image = model_attr(container, "image")
    return {
        "name": model_attr(container, "name"),
        "image": image,
        "registry": registry_host(image),
        **image_reference(image),
        "env_vars_from_secrets": sum(1 for e in env if model_attr(e, "secret_ref")),
        "env_vars_plain": len(plain),
        "plain_env_vars_with_secret_like_names": sorted(n for n in plain if secret_like(n)),
    }


def project_workload(kind: str, workload) -> dict:
    """A Container App or a Container Apps job: the parts that hold secrets or face the network."""
    config = model_attr(workload, "configuration")
    template = model_attr(workload, "template")
    env_id = model_attr(workload, "environment_id")
    secrets = [project_secret(s) for s in model_attr(config, "secrets") or []]
    registries = [project_registry(r) for r in model_attr(config, "registries") or []]
    containers = [
        project_app_container(c)
        for c in (model_attr(template, "containers") or []) + (model_attr(template, "init_containers") or [])
    ]
    record = {
        "id": model_attr(workload, "id"),
        "name": model_attr(workload, "name"),
        "kind": kind,
        "location": model_attr(workload, "location"),
        "resource_group": resource_group_from_id(model_attr(workload, "id")),
        "tags": model_attr(workload, "tags") or {},
        "environment_id": env_id,
        "environment_name": basename(env_id),
        "identity_type": identity_type(workload),
        "workload_profile_name": model_attr(workload, "workload_profile_name"),
        "secrets": secrets,
        "secrets_stored_in_app": sum(1 for s in secrets if s["stored_in_app"]),
        "registries": registries,
        "registries_password_based": sum(1 for r in registries if r["password_based"]),
        "containers": containers,
        "plain_env_vars_with_secret_like_names": sum(
            len(c["plain_env_vars_with_secret_like_names"]) for c in containers
        ),
        "volume_storage_types": sorted({str(model_attr(v, "storage_type")) for v in model_attr(template, "volumes") or []}),
    }
    if kind == "job":
        record["trigger_type"] = model_attr(config, "trigger_type")
    else:
        ingress = model_attr(config, "ingress")
        restrictions = model_attr(ingress, "ip_security_restrictions") or []
        record.update(
            {
                "ingress_enabled": ingress is not None,
                "ingress_external": bool(model_attr(ingress, "external") or False),
                "ingress_allow_insecure": bool(model_attr(ingress, "allow_insecure") or False),
                "ingress_transport": model_attr(ingress, "transport"),
                "ingress_client_certificate_mode": model_attr(ingress, "client_certificate_mode"),
                "ingress_ip_restrictions": len(restrictions),
                "active_revisions_mode": model_attr(config, "active_revisions_mode"),
            }
        )
    return record


def project_auth_config(configs) -> dict:
    """Easy Auth on a Container App: whether the platform requires sign-in before traffic reaches it.

    `configs` is the app's auth config list (Azure keeps one, named "current"); None when it
    could not be read.
    """
    if configs is None:
        return {"auth_enabled": None, "unauthenticated_client_action": None, "auth_identity_providers": None}
    current = next(iter(configs), None)
    platform = prop(current, "platform") if current is not None else None
    validation = prop(current, "global_validation") if current is not None else None
    providers = prop(current, "identity_providers") if current is not None else None
    enabled = bool(model_attr(platform, "enabled") or False)
    return {
        "auth_enabled": enabled,
        "unauthenticated_client_action": model_attr(validation, "unauthenticated_client_action"),
        "auth_identity_providers": sorted(
            name for name in ("azure_active_directory", "google", "github", "apple", "facebook", "twitter", "custom_open_id_connect_providers")
            if model_attr(providers, name)
        ),
    }


def internet_facing(ingress_external: bool, environment) -> bool:
    """External ingress on an environment that is not internal-only; an unlisted environment counts as not internal."""
    return bool(ingress_external) and (environment is None or not environment["internal_only"])


# --------------------------------------------------------------------------- #
# Container Instances
# --------------------------------------------------------------------------- #

def project_instance_container(container) -> dict:
    env = model_attr(container, "environment_variables") or []
    # The list response redacts secure values: a variable with neither value nor secureValue is secure.
    plain = [model_attr(e, "name") for e in env if model_attr(e, "value") is not None]
    image = model_attr(container, "image")
    return {
        "name": model_attr(container, "name"),
        "image": image,
        "registry": registry_host(image),
        **image_reference(image),
        "ports": [model_attr(p, "port") for p in model_attr(container, "ports") or []],
        "env_vars_secure": len(env) - len(plain),
        "env_vars_plain": len(plain),
        "plain_env_vars_with_secret_like_names": sorted(n for n in plain if secret_like(n)),
    }


def project_container_group(group) -> dict:
    ip = model_attr(group, "ip_address")
    ip_type = model_attr(ip, "type")
    containers = [
        project_instance_container(c)
        for c in (model_attr(group, "containers") or []) + (model_attr(group, "init_containers") or [])
    ]
    credentials = [
        {
            "server": model_attr(c, "server"),
            "identity_used": bool(model_attr(c, "identity")),
            # The list response omits passwords; a username without an identity means one is set.
            "password_based": bool(model_attr(c, "username")) and not model_attr(c, "identity"),
        }
        for c in model_attr(group, "image_registry_credentials") or []
    ]
    volumes = model_attr(group, "volumes") or []
    diagnostics = model_attr(group, "diagnostics")
    return {
        "id": model_attr(group, "id"),
        "name": model_attr(group, "name"),
        "location": model_attr(group, "location"),
        "resource_group": resource_group_from_id(model_attr(group, "id")),
        "tags": model_attr(group, "tags") or {},
        "os_type": model_attr(group, "os_type"),
        "identity_type": identity_type(group),
        "restart_policy": model_attr(group, "restart_policy"),
        "ip_address_type": ip_type,
        "public_ip": str(ip_type or "").lower() == "public",
        "dns_name_label": model_attr(ip, "dns_name_label"),
        "exposed_ports": [model_attr(p, "port") for p in model_attr(ip, "ports") or []],
        "subnet_ids": [model_attr(s, "id") for s in model_attr(group, "subnet_ids") or []],
        "containers": containers,
        "plain_env_vars_with_secret_like_names": sum(
            len(c["plain_env_vars_with_secret_like_names"]) for c in containers
        ),
        "image_registry_credentials": credentials,
        "registries_password_based": sum(1 for c in credentials if c["password_based"]),
        "customer_managed_key": model_attr(group, "encryption_properties") is not None,
        "confidential_compute": model_attr(group, "confidential_compute_properties") is not None,
        "log_analytics_configured": model_attr(diagnostics, "log_analytics") is not None,
        # An Azure Files volume stores the storage account key in the container group definition.
        "azure_file_volumes": sum(1 for v in volumes if model_attr(v, "azure_file") is not None),
        "secret_volumes": sum(1 for v in volumes if model_attr(v, "secret") is not None),
    }


# --------------------------------------------------------------------------- #

def summarize(environments, apps, jobs, groups) -> dict:
    workloads = apps + jobs
    containers = [c for w in workloads + groups for c in w["containers"]]

    def count(items, pred):
        return sum(1 for i in items if pred(i))

    return {
        "total_environments": len(environments),
        "environments_internal_only": count(environments, lambda e: e["network_exposure"] == "internal"),
        "environments_private": count(environments, lambda e: e["network_exposure"] == "private"),
        "environments_public": count(environments, lambda e: e["network_exposure"] == "public"),
        "environments_without_vnet": count(environments, lambda e: not e["infrastructure_subnet_id"]),
        "environments_mtls_enabled": count(environments, lambda e: e["mtls_enabled"]),
        "environments_peer_traffic_encryption_enabled": count(environments, lambda e: e["peer_traffic_encryption_enabled"]),
        "environments_without_log_destination": count(
            environments, lambda e: compact(e["app_logs_destination"]) in ("", "none")
        ),
        "environments_zone_redundant": count(environments, lambda e: e["zone_redundant"]),
        "environments_audit_logs_exported": count(environments, lambda e: e["audit_logs_exported"] is True),
        "environments_audit_logs_unknown": count(environments, lambda e: e["audit_logs_exported"] is None),
        "total_container_apps": len(apps),
        "container_apps_internet_facing": count(apps, lambda a: a["internet_facing"]),
        "container_apps_allow_insecure": count(apps, lambda a: a["ingress_allow_insecure"]),
        "container_apps_without_ip_restrictions": count(
            apps, lambda a: a["internet_facing"] and not a["ingress_ip_restrictions"]
        ),
        "container_apps_internet_facing_without_auth": count(
            apps, lambda a: a["internet_facing"] and a["auth_enabled"] is False
        ),
        "container_apps_auth_unknown": count(apps, lambda a: a["auth_enabled"] is None),
        "total_jobs": len(jobs),
        "workloads_with_secrets_stored_in_app": count(workloads, lambda w: w["secrets_stored_in_app"]),
        "workloads_registries_password_based": count(workloads, lambda w: w["registries_password_based"]),
        "workloads_plain_env_vars_with_secret_like_names": count(
            workloads, lambda w: w["plain_env_vars_with_secret_like_names"]
        ),
        "workloads_without_managed_identity": count(
            workloads, lambda w: compact(w["identity_type"] or "none") == "none"
        ),
        "total_containers": len(containers),
        "containers_with_mutable_image_tag": count(containers, lambda c: c["image_tag_mutable"]),
        "containers_image_pinned_by_digest": count(containers, lambda c: c["image_pinned_by_digest"]),
        "image_registries": sorted({c["registry"] for c in containers}),
        "total_container_groups": len(groups),
        "container_groups_public_ip": count(groups, lambda g: g["public_ip"]),
        "container_groups_in_vnet": count(groups, lambda g: g["subnet_ids"]),
        "container_groups_registries_password_based": count(groups, lambda g: g["registries_password_based"]),
        "container_groups_plain_env_vars_with_secret_like_names": count(
            groups, lambda g: g["plain_env_vars_with_secret_like_names"]
        ),
        "container_groups_without_managed_identity": count(
            groups, lambda g: compact(g["identity_type"] or "none") == "none"
        ),
        "container_groups_customer_managed_key": count(groups, lambda g: g["customer_managed_key"]),
        "container_groups_confidential_compute": count(groups, lambda g: g["confidential_compute"]),
        "container_groups_azure_file_volumes": count(groups, lambda g: g["azure_file_volumes"]),
        "container_groups_logs_exported": count(groups, lambda g: g["logs_exported"] is True),
        "container_groups_logs_unknown": count(groups, lambda g: g["logs_exported"] is None),
    }


def collect(subscription_id, cred, collector: Collector) -> tuple:
    def _clients():
        from azure.mgmt.appcontainers import ContainerAppsAPIClient  # lazy
        from azure.mgmt.containerinstance import (
            ContainerInstanceManagementClient,  # lazy
        )

        kwargs = {"credential": cred, "subscription_id": subscription_id, **arm_client_kwargs()}
        return ContainerAppsAPIClient(**kwargs), ContainerInstanceManagementClient(**kwargs)

    clients = collector.guard("container clients (init)", _clients)
    if clients is None:
        return [], [], [], []
    apps_client, aci_client = clients

    environments = collector.guard(
        "appcontainers.managed_environments.list_by_subscription",
        lambda: [project_environment(e) for e in apps_client.managed_environments.list_by_subscription()],
        default=[],
    )
    apps = collector.guard(
        "appcontainers.container_apps.list_by_subscription",
        lambda: [project_workload("container_app", a) for a in apps_client.container_apps.list_by_subscription()],
        default=[],
    )
    jobs = collector.guard(
        "appcontainers.jobs.list_by_subscription",
        lambda: [project_workload("job", j) for j in apps_client.jobs.list_by_subscription()],
        default=[],
    )
    groups = collector.guard(
        "containerinstance.container_groups.list",
        lambda: [project_container_group(g) for g in aci_client.container_groups.list()],
        default=[],
    )
    monitor = (
        collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
        if environments or groups
        else None
    )

    def diagnostics_for(resource: dict):
        if monitor is None:
            return None
        return collector.guard(
            f"monitor.diagnostic_settings.list({resource['resource_group']}/{resource['name']})",
            lambda: list_diagnostic_settings(monitor, resource["id"]),
        )

    env_by_id = {(e["id"] or "").lower(): e for e in environments}
    for env in environments:
        env["diagnostic_settings"] = diagnostics_for(env)
        env["audit_logs_exported"] = logs_exported(
            env["diagnostic_settings"], categories=("containerappsystemlogs", "containerappconsolelogs")
        )
    for app in apps:
        configs = collector.guard(
            f"appcontainers.container_apps_auth_configs.list_by_container_app({app['resource_group']}/{app['name']})",
            lambda app=app: list(
                apps_client.container_apps_auth_configs.list_by_container_app(app["resource_group"], app["name"])
            ),
        )
        app.update(project_auth_config(configs))
        env = env_by_id.get((app["environment_id"] or "").lower())
        # Internet-facing needs external ingress on an environment that is not internal-only.
        app["environment_internal_only"] = None if env is None else env["internal_only"]
        app["internet_facing"] = internet_facing(app["ingress_external"], env)
    for group in groups:
        group["diagnostic_settings"] = diagnostics_for(group)
        group["logs_exported"] = logs_exported(
            group["diagnostic_settings"], categories=("containerinstancelog", "containerevent")
        )
    key = lambda r: r["id"] or ""  # noqa: E731
    return sorted(environments, key=key), sorted(apps, key=key), sorted(jobs, key=key), sorted(groups, key=key)


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

    environments: list = []
    apps: list = []
    jobs: list = []
    groups: list = []
    registration = {}
    if subscription_id and cred is not None:
        for namespace in ("Microsoft.App", "Microsoft.ContainerInstance"):
            registration[namespace] = provider_registration_status(collector, subscription_id, cred, namespace)
            if registration[namespace] == NOT_REGISTERED:
                logger.warning(
                    "%s is not registered on subscription %s — reporting status not_registered",
                    namespace,
                    subscription_id,
                )
        environments, apps, jobs, groups = collect(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )
    registration = {
        "provider_registration_status_container_apps": registration.get("Microsoft.App", REGISTRATION_UNKNOWN),
        "provider_registration_status_container_instances": registration.get(
            "Microsoft.ContainerInstance", REGISTRATION_UNKNOWN
        ),
    }

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "environments": environments,
            "container_apps": apps,
            "jobs": jobs,
            "container_groups": groups,
            **registration,
        },
        summary={**summarize(environments, apps, jobs, groups), **registration},
    )
    filename = f"azure_container_workloads_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
