#!/usr/bin/env python3
"""
Azure App Service web-app transport, identity and declared-runtime posture.

Ported from Prowler prowler/providers/azure/services/app/app_service.py (Apache-2.0),
with two deviations. Auth settings come from the GET
`get_auth_settings_v2_without_secrets`, not Prowler's POST `get_auth_settings_v2`
(which needs `Microsoft.Web/sites/config/list/Action`), so plain Reader suffices. And
the resource group is parsed from the ARM id: `Site.resource_group`, which Prowler
reads, does not exist on azure-mgmt-web 11.x and reads as None, silently breaking
every per-app GET. Function apps are a separate evidence set.

Beyond Prowler: the access restrictions (main and SCM site) that `config/web` already
returns, and each app's diagnostic settings from azure-mgmt-monitor.
"""

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
    coverage_percentage,
    credential,
    dig,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_app_service_configuration")

# `kind` is comma-joined: "app", "app,linux", "app,linux,container", "functionapp",
# "functionapp,linux". Prowler's split.
WEB_APP_KIND_PREFIX = "app"
FUNCTION_APP_KIND_PREFIX = "functionapp"

# minTlsVersion is a bare version string on this API ("1.0" … "1.3"), not the
# "TLS1_2" spelling azure-mgmt-storage uses.
MODERN_TLS_VERSIONS = ("1.2", "1.3")

# ftpsState: "AllAllowed" (plaintext FTP accepted), "FtpsOnly", "Disabled".
FTP_DISABLED_STATES = ("Disabled",)
FTP_ENCRYPTED_STATES = ("Disabled", "FtpsOnly")

# An access-restriction `ip_address` that matches every caller. "Any" is what ARM
# writes into the synthetic "Allow all" rule on an app with no restrictions (seen
# live); "Internet" is the service tag for the whole public Internet.
ALL_ADDRESSES = ("any", "*", "0.0.0.0/0", "::/0", "internet")


# --- projection: the only azure-mgmt model access ---

def project_site(site) -> dict:
    """Read a `Site` model into a flat snake_case dict, un-defaulted: `None` means the
    API did not return the field (`identity` is absent without a managed identity).
    """
    identity = model_attr(site, "identity")
    return {
        "id": model_attr(site, "id"),
        "name": model_attr(site, "name"),
        "location": model_attr(site, "location"),
        "kind": model_attr(site, "kind"),
        "state": model_attr(site, "state"),
        "default_host_name": model_attr(site, "default_host_name"),
        "https_only": model_attr(site, "https_only"),
        "client_cert_enabled": model_attr(site, "client_cert_enabled"),
        "client_cert_mode": model_attr(site, "client_cert_mode"),
        "public_network_access": model_attr(site, "public_network_access"),
        "virtual_network_subnet_id": model_attr(site, "virtual_network_subnet_id"),
        "identity": {
            "principal_id": model_attr(identity, "principal_id"),
            "tenant_id": model_attr(identity, "tenant_id"),
            "type": model_attr(identity, "type"),
        },
    }


def project_site_config(config) -> dict:
    """Read a `SiteConfigResource` (web_apps.get_configuration) into a flat dict.

    `ftps_state` / `min_tls_version` are SDK `str` enums; `model_attr` unwraps them, or
    the evidence carries "FtpsState.DISABLED" and comparisons silently stop matching.
    """
    return {
        "id": model_attr(config, "id"),
        "name": model_attr(config, "name"),
        # --- declared runtime versions (all kept: only one is set per app) ---
        "linux_fx_version": model_attr(config, "linux_fx_version"),
        "windows_fx_version": model_attr(config, "windows_fx_version"),
        "java_version": model_attr(config, "java_version"),
        "php_version": model_attr(config, "php_version"),
        "python_version": model_attr(config, "python_version"),
        "net_framework_version": model_attr(config, "net_framework_version"),
        "node_version": model_attr(config, "node_version"),
        "http20_enabled": model_attr(config, "http20_enabled"),
        "ftps_state": model_attr(config, "ftps_state"),
        "min_tls_version": model_attr(config, "min_tls_version"),
        "remote_debugging_enabled": model_attr(config, "remote_debugging_enabled"),
        "always_on": model_attr(config, "always_on"),
        "http_logging_enabled": model_attr(config, "http_logging_enabled"),
        # --- access restrictions ---
        "ip_security_restrictions": [
            project_ip_restriction(r)
            for r in (model_attr(config, "ip_security_restrictions") or [])
        ],
        "ip_security_restrictions_default_action": model_attr(
            config, "ip_security_restrictions_default_action"
        ),
        "scm_ip_security_restrictions": [
            project_ip_restriction(r)
            for r in (model_attr(config, "scm_ip_security_restrictions") or [])
        ],
        "scm_ip_security_restrictions_default_action": model_attr(
            config, "scm_ip_security_restrictions_default_action"
        ),
        "scm_ip_security_restrictions_use_main": model_attr(
            config, "scm_ip_security_restrictions_use_main"
        ),
    }


def project_ip_restriction(rule) -> dict:
    """Read an `IpSecurityRestriction` — one access-restriction rule."""
    return {
        "name": model_attr(rule, "name"),
        "priority": model_attr(rule, "priority"),
        "action": model_attr(rule, "action"),
        "tag": model_attr(rule, "tag"),
        "ip_address": model_attr(rule, "ip_address"),
        "subnet_mask": model_attr(rule, "subnet_mask"),
        "vnet_subnet_resource_id": model_attr(rule, "vnet_subnet_resource_id"),
        "headers": model_attr(rule, "headers"),
        "description": model_attr(rule, "description"),
    }


def project_diagnostic_setting(setting) -> dict:
    """Read a `DiagnosticSettingsResource` — one log/metric export target. Same
    projection as azure_container_registry_configuration's.
    """
    return {
        "id": model_attr(setting, "id"),
        "name": model_attr(setting, "name") or basename(model_attr(setting, "id")),
        "storage_account_id": model_attr(setting, "storage_account_id"),
        "workspace_id": model_attr(setting, "workspace_id"),
        "event_hub_name": model_attr(setting, "event_hub_name"),
        "logs": [
            {
                "category": model_attr(log, "category"),
                "category_group": model_attr(log, "category_group"),
                "enabled": model_attr(log, "enabled"),
            }
            for log in (model_attr(setting, "logs") or [])
        ],
    }


def project_auth_settings(settings) -> dict:
    """Read a `SiteAuthSettingsV2` into a flat dict.

    `platform.enabled` is what Prowler's app_ensure_auth_is_set_up check reads;
    `global_validation` goes beyond Prowler — auth being switched on and
    unauthenticated callers actually being rejected are different facts.
    """
    platform = model_attr(settings, "platform")
    global_validation = model_attr(settings, "global_validation")
    return {
        "platform_enabled": model_attr(platform, "enabled"),
        "platform_runtime_version": model_attr(platform, "runtime_version"),
        "require_authentication": model_attr(global_validation, "require_authentication"),
        "unauthenticated_client_action": model_attr(
            global_validation, "unauthenticated_client_action"
        ),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def is_web_app(kind) -> bool:
    """Prowler's split: `kind` starting with "app" is a web app, not a function app.

    No `kind` counts as a web app — Prowler's default (`getattr(app, "kind", "app")`),
    and the API omits `kind` only for plain Windows web apps.
    """
    text = str(kind or WEB_APP_KIND_PREFIX).lower()
    return text.startswith(WEB_APP_KIND_PREFIX) and not text.startswith(
        FUNCTION_APP_KIND_PREFIX
    )


def effective_client_cert_mode(client_cert_enabled, client_cert_mode) -> str:
    """Ported verbatim from Prowler's `App._get_client_cert_mode`.

    ARM keeps `clientCertMode` at its last value after `clientCertEnabled` is switched
    off, so the raw mode alone reads as "Required" on an app that no longer asks for a
    certificate; this collapses the pair into the mode the portal shows.
    """
    enabled = bool(client_cert_enabled or False)
    mode = str(client_cert_mode or "Ignore")
    if enabled and mode == "OptionalInteractiveUser":
        return "Optional"
    if enabled and mode == "Optional":
        return "Allow"
    if enabled and mode == "Required":
        return "Required"
    return "Ignore"


def web_app_record(site: dict) -> dict:
    """Normalize one projected web app into an evidence record.

    Azure omits a false-y field rather than returning `false` (confirmed live), so
    booleans are coerced with `bool(x or False)` — a validator asserting `false` would
    not match `null`. `configuration` / `authentication` stay None until the per-app
    enrichment, so None means "not collected", not "collected and empty".
    """
    resource_id = site.get("id")
    identity = site.get("identity") or {}
    identity_type = identity.get("type")
    return {
        "id": resource_id,
        "name": site.get("name"),
        "location": site.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "kind": site.get("kind"),
        "state": site.get("state"),
        "default_host_name": site.get("default_host_name"),
        "https_only": bool(site.get("https_only") or False),
        "client_cert_enabled": bool(site.get("client_cert_enabled") or False),
        "client_cert_mode": site.get("client_cert_mode"),
        "effective_client_cert_mode": effective_client_cert_mode(
            site.get("client_cert_enabled"), site.get("client_cert_mode")
        ),
        "public_network_access": site.get("public_network_access"),
        "vnet_integrated": bool(site.get("virtual_network_subnet_id")),
        "vnet_subnet_id": site.get("virtual_network_subnet_id"),
        # "None" is the literal identity type ARM returns.
        "identity": {
            "principal_id": identity.get("principal_id"),
            "tenant_id": identity.get("tenant_id"),
            "type": identity_type,
        },
        "managed_identity_enabled": str(identity_type or "None").lower() != "none",
        "configuration": None,
        "authentication": None,
        # None until the diagnostic-settings enrichment; [] means collected, none set.
        "monitor_diagnostic_settings": None,
    }


def configuration_record(config: dict) -> dict:
    """Normalize a projected site configuration — runtime versions plus hardening."""
    return {
        "linux_fx_version": config.get("linux_fx_version"),
        "windows_fx_version": config.get("windows_fx_version"),
        "java_version": config.get("java_version"),
        "php_version": config.get("php_version"),
        "python_version": config.get("python_version"),
        "net_framework_version": config.get("net_framework_version"),
        "node_version": config.get("node_version"),
        "http20_enabled": bool(config.get("http20_enabled") or False),
        "ftps_state": config.get("ftps_state"),
        "min_tls_version": config.get("min_tls_version"),
        "remote_debugging_enabled": bool(config.get("remote_debugging_enabled") or False),
        "always_on": bool(config.get("always_on") or False),
        "http_logging_enabled": bool(config.get("http_logging_enabled") or False),
        **access_restrictions_record(config),
    }


def ip_restriction_record(rule: dict) -> dict:
    """Normalize one access-restriction rule."""
    return {
        "name": rule.get("name"),
        "priority": rule.get("priority"),
        "action": rule.get("action"),
        "tag": rule.get("tag"),
        "ip_address": rule.get("ip_address"),
        "subnet_mask": rule.get("subnet_mask"),
        "vnet_subnet_resource_id": rule.get("vnet_subnet_resource_id"),
        "has_header_conditions": bool(rule.get("headers")),
        "description": rule.get("description"),
    }


def _matches_all_callers(rule: dict) -> bool:
    """Does a rule match every caller? An address of "Any" (or 0.0.0.0/0, or the
    Internet tag) with no VNet scope and no header condition narrowing it.
    """
    return (
        str(rule.get("ip_address") or "").strip().lower() in ALL_ADDRESSES
        and not rule.get("vnet_subnet_resource_id")
        and not rule.get("has_header_conditions")
    )


def allows_all_traffic(rules: list[dict], default_action) -> bool:
    """Does this site's access-restriction list let every caller through?

    Rules evaluate in priority order (lowest number first); the first one matching
    every caller decides. If none does, unmatched traffic gets the default action,
    and ARM leaves that unset on most apps: then an app with no rules allows all,
    and an app with any rule denies the rest (App Service's implicit "Deny all").
    Whether the site is reachable at all is a separate fact —
    `public_network_access` — which this does not read.
    """
    ordered = sorted(
        rules,
        key=lambda r: r["priority"] if isinstance(r.get("priority"), int) else 1 << 31,
    )
    for rule in ordered:
        if _matches_all_callers(rule):
            return str(rule.get("action") or "Allow").lower() == "allow"
    if default_action:
        return str(default_action).lower() == "allow"
    return not rules


def access_restrictions_record(config: dict) -> dict:
    """The main and SCM (Kudu / deployment) sites' access restrictions.

    With `scm_ip_security_restrictions_use_main` set, the SCM site enforces the main
    site's rules, so its effective answer is the main site's.
    """
    main_rules = [ip_restriction_record(r) for r in (config.get("ip_security_restrictions") or [])]
    scm_rules = [
        ip_restriction_record(r) for r in (config.get("scm_ip_security_restrictions") or [])
    ]
    main_default = config.get("ip_security_restrictions_default_action")
    scm_default = config.get("scm_ip_security_restrictions_default_action")
    use_main = bool(config.get("scm_ip_security_restrictions_use_main") or False)
    main_open = allows_all_traffic(main_rules, main_default)
    return {
        "ip_security_restrictions": main_rules,
        "ip_security_restrictions_default_action": main_default,
        "scm_ip_security_restrictions": scm_rules,
        "scm_ip_security_restrictions_default_action": scm_default,
        "scm_ip_security_restrictions_use_main": use_main,
        "main_site_allows_all_traffic": main_open,
        "scm_site_allows_all_traffic": (
            main_open if use_main else allows_all_traffic(scm_rules, scm_default)
        ),
    }


def diagnostic_setting_record(setting: dict) -> dict:
    """Normalize one projected diagnostic setting, coercing the per-category enables."""
    return {
        "id": setting.get("id"),
        "name": setting.get("name"),
        "storage_account_id": setting.get("storage_account_id"),
        "workspace_id": setting.get("workspace_id"),
        "event_hub_name": setting.get("event_hub_name"),
        "logs": [
            {
                "category": log.get("category"),
                "category_group": log.get("category_group"),
                "enabled": bool(log.get("enabled") or False),
            }
            for log in (setting.get("logs") or [])
        ],
    }


def has_enabled_log(app: dict) -> bool:
    """Does the app export at least one ENABLED log category? A setting can exist
    with every category switched off, so settings alone are not enough.
    """
    return any(
        log["enabled"]
        for setting in (app.get("monitor_diagnostic_settings") or [])
        for log in (setting.get("logs") or [])
    )


def authentication_record(settings: dict) -> dict:
    """Normalize projected auth settings — App Service Authentication ("Easy Auth")."""
    return {
        "auth_enabled": bool(settings.get("platform_enabled") or False),
        "auth_runtime_version": settings.get("platform_runtime_version"),
        "require_authentication": bool(settings.get("require_authentication") or False),
        "unauthenticated_client_action": settings.get("unauthenticated_client_action"),
    }


def summarize(apps: list[dict]) -> dict:
    """Transport, identity and runtime coverage across the subscription's web apps."""
    total = len(apps)
    https_only = sum(1 for a in apps if a["https_only"])
    managed_identity = sum(1 for a in apps if a["managed_identity_enabled"])
    return {
        "total_web_apps": total,
        "https_only_apps": https_only,
        "https_only_percentage": coverage_percentage(https_only, total),
        "managed_identity_apps": managed_identity,
        "managed_identity_percentage": coverage_percentage(managed_identity, total),
        "auth_enabled_apps": sum(1 for a in apps if dig(a, "authentication", "auth_enabled")),
        "client_cert_required_apps": sum(
            1 for a in apps if a["effective_client_cert_mode"] == "Required"
        ),
        "minimum_tls_1_2_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "min_tls_version") or "") in MODERN_TLS_VERSIONS
        ),
        "http2_enabled_apps": sum(
            1 for a in apps if dig(a, "configuration", "http20_enabled")
        ),
        "ftp_deployment_disabled_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "ftps_state") or "") in FTP_DISABLED_STATES
        ),
        "ftp_encrypted_or_disabled_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "ftps_state") or "") in FTP_ENCRYPTED_STATES
        ),
        "remote_debugging_enabled_apps": sum(
            1 for a in apps if dig(a, "configuration", "remote_debugging_enabled")
        ),
        "always_on_apps": sum(1 for a in apps if dig(a, "configuration", "always_on")),
        "http_logging_enabled_apps": sum(
            1 for a in apps if dig(a, "configuration", "http_logging_enabled")
        ),
        "vnet_integrated_apps": sum(1 for a in apps if a["vnet_integrated"]),
        "public_network_access_disabled_apps": sum(
            1 for a in apps if str(a["public_network_access"] or "").lower() == "disabled"
        ),
        # The versions are per app; this only shows the runtime projection was populated.
        "apps_with_declared_runtime": sum(
            1
            for a in apps
            if any(
                dig(a, "configuration", field)
                for field in (
                    "linux_fx_version",
                    "windows_fx_version",
                    "java_version",
                    "php_version",
                    "python_version",
                    "net_framework_version",
                    "node_version",
                )
            )
        ),
        # --- access restrictions (None configuration = not collected, not counted) ---
        "main_site_allows_all_traffic_apps": sum(
            1 for a in apps if dig(a, "configuration", "main_site_allows_all_traffic")
        ),
        "scm_site_allows_all_traffic_apps": sum(
            1 for a in apps if dig(a, "configuration", "scm_site_allows_all_traffic")
        ),
        "any_site_allows_all_traffic_apps": sum(
            1
            for a in apps
            if dig(a, "configuration", "main_site_allows_all_traffic")
            or dig(a, "configuration", "scm_site_allows_all_traffic")
        ),
        "scm_uses_main_site_restrictions_apps": sum(
            1 for a in apps if dig(a, "configuration", "scm_ip_security_restrictions_use_main")
        ),
        # --- diagnostic settings ---
        "apps_with_diagnostic_settings": sum(
            1 for a in apps if a.get("monitor_diagnostic_settings")
        ),
        "apps_with_enabled_logs": sum(1 for a in apps if has_enabled_log(a)),
    }


# --- collection (lazy azure imports) ---

def collect_web_apps(subscription_id, cred, collector: Collector) -> list[dict]:
    """One web_apps.list(), then two Reader-permitted GETs per app: `config/web` for the
    runtime versions and protocol settings, `config/authsettingsV2` for Easy Auth.
    """
    from azure.mgmt.web import WebSiteManagementClient

    def _client():
        return WebSiteManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("web.WebSiteManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            web_app_record(project_site(site))
            for site in client.web_apps.list()
            if is_web_app(model_attr(site, "kind"))
        ]

    apps = collector.guard("web.web_apps.list", _list, default=[])

    for app in apps:
        group, name = app.get("resource_group"), app.get("name")
        if not group or not name:
            collector.record(
                "web.web_apps.get_configuration",
                RuntimeError(f"web app {name!r} has no resource group in its id"),
            )
            continue
        config = collector.guard(
            f"web.web_apps.get_configuration ({name})",
            lambda group=group, name=name: project_site_config(
                client.web_apps.get_configuration(resource_group_name=group, name=name)
            ),
        )
        if config is not None:
            app["configuration"] = configuration_record(config)
        settings = collector.guard(
            f"web.web_apps.get_auth_settings_v2_without_secrets ({name})",
            lambda group=group, name=name: project_auth_settings(
                client.web_apps.get_auth_settings_v2_without_secrets(
                    resource_group_name=group, name=name
                )
            ),
        )
        if settings is not None:
            app["authentication"] = authentication_record(settings)

    if apps:
        _attach_diagnostic_settings(subscription_id, cred, collector, apps)

    return sorted(apps, key=lambda r: r.get("id") or "")


def _attach_diagnostic_settings(subscription_id, cred, collector: Collector, apps) -> None:
    """Fill each app's `monitor_diagnostic_settings` in place: one Reader GET per app
    on Microsoft.Insights, a second SDK because the settings are not a Microsoft.Web
    resource. A failed call leaves the app's value None ("not collected").
    """

    def _monitor_client():
        from azure.mgmt.monitor import MonitorManagementClient  # lazy

        client = MonitorManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )
        # azure-mgmt-monitor 7.0.0 dropped the operation group entirely.
        if getattr(client, "diagnostic_settings", None) is None:
            raise RuntimeError(
                "installed azure-mgmt-monitor has no diagnostic_settings operation "
                "group (removed in 7.0.0) — pin azure-mgmt-monitor>=6.0.2,<7"
            )
        return client

    monitor = collector.guard("monitor.MonitorManagementClient (init)", _monitor_client)
    if monitor is None:
        return

    for app in apps:
        resource_id, name = app.get("id"), app.get("name")
        if not resource_id:
            continue
        # resource_uri is substituted unquoted after a "/", so no leading slash.
        app["monitor_diagnostic_settings"] = collector.guard(
            f"monitor.diagnostic_settings.list ({name})",
            lambda resource_id=resource_id: sorted(
                (
                    diagnostic_setting_record(project_diagnostic_setting(setting))
                    for setting in monitor.diagnostic_settings.list(
                        resource_uri=resource_id.lstrip("/")
                    )
                ),
                key=lambda r: r.get("id") or "",
            ),
        )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # dominate the runner's stderr tail. Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    apps: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-app result is legible: Azure returns
        # an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Web"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Web is not registered on subscription %s — no App Service "
                "in use; reporting status not_registered",
                subscription_id,
            )
        apps = collect_web_apps(subscription_id, cred, collector)
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
            "web_apps": apps,
            "provider_registration_status": registration,
        },
        summary={**summarize(apps), "provider_registration_status": registration},
    )

    filename = (
        f"azure_app_service_configuration_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
