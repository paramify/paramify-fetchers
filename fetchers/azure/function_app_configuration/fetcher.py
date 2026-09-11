#!/usr/bin/env python3
"""
Azure Functions (function app) network, transport, key and app-setting posture.

Ported from the FunctionApp half of Prowler
prowler/providers/azure/services/app/app_service.py (Apache-2.0), except that Prowler
keeps `function_keys` and `environment_variables` values in memory and this fetcher
keeps neither: keys are reported as presence plus NAMES, settings as NAMES only, so no
key material and no setting value ever reaches the evidence.

Reader is NOT sufficient. Two calls are ARM POST `/action` operations:
`web_apps.list_host_keys()` (POST .../host/listkeys) needs
`Microsoft.Web/sites/host/listkeys/action`, and `web_apps.list_application_settings()`
(POST .../config/appsettings/list) needs `Microsoft.Web/sites/config/list/Action` —
the custom role Prowler documents for its function-app checks, the only Prowler Azure
checks needing more than Reader. A ReadOnly resource lock rejects both too
(ScopeLocked). A refusal becomes a per-app `status: "not_authorized"` and does NOT
fail the run; any other error on those calls does. Web apps are a separate set.
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

logger = logging.getLogger("azure_function_app_configuration")

# `kind` is comma-joined: "functionapp", "functionapp,linux", … . Prowler's split.
FUNCTION_APP_KIND_PREFIX = "functionapp"

# Per-block collection status for the two privileged POST /action calls.
COLLECTED = "collected"
NOT_AUTHORIZED = "not_authorized"
UNAVAILABLE = "unavailable"

# "The principal may not make this call", as opposed to a transient or structural
# failure. ScopeLocked is here because a ReadOnly resource lock rejects ARM POST
# /action (HTTP 409) even for a principal holding the action — the same evidence gap.
NOT_AUTHORIZED_MARKERS = (
    "authorizationfailed",
    "does not have authorization",
    "not authorized",
    "forbidden",
    "(403)",
    "scopelocked",
    "scope(s) are locked",
)

# App-setting NAMES worth reporting the presence of. FUNCTIONS_EXTENSION_VERSION holds the
# Functions host version ("~4") Prowler's latest-runtime check reads; its VALUE is not.
FUNCTIONS_EXTENSION_VERSION_SETTING = "FUNCTIONS_EXTENSION_VERSION"
FUNCTIONS_WORKER_RUNTIME_SETTING = "FUNCTIONS_WORKER_RUNTIME"
APPLICATION_INSIGHTS_SETTING = "APPINSIGHTS_INSTRUMENTATIONKEY"
APPLICATION_INSIGHTS_CONNECTION_SETTING = "APPLICATIONINSIGHTS_CONNECTION_STRING"

MODERN_TLS_VERSIONS = ("1.2", "1.3")
FTP_DISABLED_STATES = ("Disabled",)
FTP_ENCRYPTED_STATES = ("Disabled", "FtpsOnly")


# --- projection: the only azure-mgmt model access ---

def project_function_app(site) -> dict:
    """Read a function app's `Site` model into a flat snake_case dict, un-defaulted:
    `None` means the API did not return the field.
    """
    identity = model_attr(site, "identity")
    return {
        "id": model_attr(site, "id"),
        "name": model_attr(site, "name"),
        "location": model_attr(site, "location"),
        "kind": model_attr(site, "kind"),
        "state": model_attr(site, "state"),
        "public_network_access": model_attr(site, "public_network_access"),
        "virtual_network_subnet_id": model_attr(site, "virtual_network_subnet_id"),
        "https_only": model_attr(site, "https_only"),
        "identity": {
            "principal_id": model_attr(identity, "principal_id"),
            "tenant_id": model_attr(identity, "tenant_id"),
            "type": model_attr(identity, "type"),
        },
    }


def project_function_config(config) -> dict:
    """Read a function app's `SiteConfigResource` (get_configuration) into a flat dict.

    `ftps_state` / `min_tls_version` are SDK `str` enums; `model_attr` unwraps them so the
    evidence never carries "FtpsState.DISABLED".
    """
    return {
        "linux_fx_version": model_attr(config, "linux_fx_version"),
        "windows_fx_version": model_attr(config, "windows_fx_version"),
        "net_framework_version": model_attr(config, "net_framework_version"),
        "ftps_state": model_attr(config, "ftps_state"),
        "min_tls_version": model_attr(config, "min_tls_version"),
        "http20_enabled": model_attr(config, "http20_enabled"),
        "remote_debugging_enabled": model_attr(config, "remote_debugging_enabled"),
        "always_on": model_attr(config, "always_on"),
    }


def project_host_keys(host_keys) -> dict:
    """Read a `HostKeys` model into NAMES AND PRESENCE ONLY — never key material.

    `master_key` is a string and `function_keys` / `system_keys` are name -> secret maps;
    only the map keys and a master-key boolean leave here, so the secrets are dropped at
    the SDK boundary where nothing downstream can leak one.
    """
    function_keys = model_attr(host_keys, "function_keys") or {}
    system_keys = model_attr(host_keys, "system_keys") or {}
    return {
        "function_key_names": sorted(str(name) for name in function_keys),
        "system_key_names": sorted(str(name) for name in system_keys),
        "master_key_configured": bool(model_attr(host_keys, "master_key")),
    }


def project_application_settings(settings) -> dict:
    """Read a `StringDictionary` (list_application_settings) into NAMES ONLY — the values
    in `properties` (connection strings, keys, anything) are dropped at the SDK boundary.
    """
    properties = model_attr(settings, "properties") or {}
    return {"names": sorted(str(name) for name in properties)}


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def is_function_app(kind) -> bool:
    """Prowler's split: `kind` starting with "functionapp" is a function app."""
    return str(kind or "").lower().startswith(FUNCTION_APP_KIND_PREFIX)


def is_not_authorized(exc: BaseException) -> bool:
    """Is this failure "you may not make this call", rather than a broken call?

    Matched on the message, not the type: ARM answers a missing action with
    HttpResponseError(403 AuthorizationFailed) and a ReadOnly lock with
    HttpResponseError(409 ScopeLocked) — same type as a 500, different meaning.
    """
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return any(marker in message for marker in NOT_AUTHORIZED_MARKERS)


def _one_line(text, limit: int = 200) -> str:
    collapsed = " ".join(str(text).split())
    return collapsed[:limit].rstrip() + " ..." if len(collapsed) > limit else collapsed


def unavailable_block(status: str, reason) -> dict:
    """The shape a privileged block takes when the call could not be made: booleans stay
    None, because "not allowed to look" must not read as "no keys are configured".
    """
    return {
        "status": status,
        "reason": _one_line(reason) if reason else None,
        "function_keys_configured": None,
        "function_key_names": [],
        "system_key_names": [],
        "master_key_configured": None,
    }


def access_keys_record(host_keys: dict) -> dict:
    """Normalize projected host keys into the access-key evidence block — presence and
    names only. Prowler's app_function_access_keys_configured check reads the same fact
    (are there any function keys), just from the full key map.
    """
    names = list(host_keys.get("function_key_names") or [])
    return {
        "status": COLLECTED,
        "reason": None,
        "function_keys_configured": bool(names),
        "function_key_names": names,
        "system_key_names": list(host_keys.get("system_key_names") or []),
        "master_key_configured": bool(host_keys.get("master_key_configured") or False),
    }


def unavailable_settings_block(status: str, reason) -> dict:
    """The application-settings block when the POST could not be made."""
    return {
        "status": status,
        "reason": _one_line(reason) if reason else None,
        "names": [],
        "count": None,
        "functions_extension_version_configured": None,
        "functions_worker_runtime_configured": None,
        "application_insights_configured": None,
    }


def application_settings_record(settings: dict) -> dict:
    """Normalize projected application settings — NAMES and presence flags only.

    FUNCTIONS_EXTENSION_VERSION and FUNCTIONS_WORKER_RUNTIME are reported as configured or
    not, never as their value, so the runtime version in the evidence is
    get_configuration's `linux_fx_version` rather than the Functions host version.
    """
    names = list(settings.get("names") or [])
    present = {name.upper() for name in names}
    return {
        "status": COLLECTED,
        "reason": None,
        "names": names,
        "count": len(names),
        "functions_extension_version_configured": FUNCTIONS_EXTENSION_VERSION_SETTING in present,
        "functions_worker_runtime_configured": FUNCTIONS_WORKER_RUNTIME_SETTING in present,
        "application_insights_configured": bool(
            present & {APPLICATION_INSIGHTS_SETTING, APPLICATION_INSIGHTS_CONNECTION_SETTING}
        ),
    }


def function_app_record(site: dict) -> dict:
    """Normalize one projected function app into an evidence record.

    `public_access` is Prowler's derived boolean: ARM omits `publicNetworkAccess` unless
    it was explicitly set, and anything other than "Disabled" (absent included) means the
    app is reachable from the internet. Booleans are coerced with `bool(x or False)`
    because Azure omits a false-y field rather than returning `false`, and a validator
    asserting `false` would not match `null`.
    """
    resource_id = site.get("id")
    identity = site.get("identity") or {}
    identity_type = identity.get("type")
    public_network_access = site.get("public_network_access")
    return {
        "id": resource_id,
        "name": site.get("name"),
        "location": site.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "kind": site.get("kind"),
        "state": site.get("state"),
        "public_network_access": public_network_access,
        "public_access": str(public_network_access or "").lower() != "disabled",
        "vnet_subnet_id": site.get("virtual_network_subnet_id"),
        "vnet_integrated": bool(site.get("virtual_network_subnet_id")),
        "https_only": bool(site.get("https_only") or False),
        # "None" is the literal identity type ARM returns.
        "identity": {
            "principal_id": identity.get("principal_id"),
            "tenant_id": identity.get("tenant_id"),
            "type": identity_type,
        },
        "managed_identity_enabled": str(identity_type or "None").lower() != "none",
        # Filled in by the per-app enrichment; None means "not collected".
        "configuration": None,
        "access_keys": None,
        "application_settings": None,
    }


def configuration_record(config: dict) -> dict:
    """Normalize a projected function app configuration — runtime plus transport."""
    return {
        "linux_fx_version": config.get("linux_fx_version"),
        "windows_fx_version": config.get("windows_fx_version"),
        "net_framework_version": config.get("net_framework_version"),
        "ftps_state": config.get("ftps_state"),
        "min_tls_version": config.get("min_tls_version"),
        "http20_enabled": bool(config.get("http20_enabled") or False),
        "remote_debugging_enabled": bool(config.get("remote_debugging_enabled") or False),
        "always_on": bool(config.get("always_on") or False),
    }


def summarize(apps: list[dict]) -> dict:
    """Exposure and key-management coverage across the subscription's function apps.

    The `*_not_authorized` counts are evidence, not diagnostics: they say how much posture
    the run's permissions could not read, so a zero in `access_keys_configured_apps` is
    never mistaken for "no app uses keys".
    """
    total = len(apps)
    https_only = sum(1 for a in apps if a["https_only"])
    managed_identity = sum(1 for a in apps if a["managed_identity_enabled"])
    return {
        "total_function_apps": total,
        "https_only_apps": https_only,
        "https_only_percentage": coverage_percentage(https_only, total),
        "managed_identity_apps": managed_identity,
        "managed_identity_percentage": coverage_percentage(managed_identity, total),
        "publicly_accessible_apps": sum(1 for a in apps if a["public_access"]),
        "public_network_access_disabled_apps": sum(1 for a in apps if not a["public_access"]),
        "vnet_integrated_apps": sum(1 for a in apps if a["vnet_integrated"]),
        "minimum_tls_1_2_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "min_tls_version") or "") in MODERN_TLS_VERSIONS
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
        "apps_with_declared_runtime": sum(
            1
            for a in apps
            if any(
                dig(a, "configuration", field)
                for field in ("linux_fx_version", "windows_fx_version", "net_framework_version")
            )
        ),
        "access_keys_configured_apps": sum(
            1 for a in apps if dig(a, "access_keys", "function_keys_configured")
        ),
        "access_keys_not_authorized_apps": sum(
            1 for a in apps if dig(a, "access_keys", "status") == NOT_AUTHORIZED
        ),
        "application_settings_not_authorized_apps": sum(
            1 for a in apps if dig(a, "application_settings", "status") == NOT_AUTHORIZED
        ),
        "application_insights_configured_apps": sum(
            1 for a in apps if dig(a, "application_settings", "application_insights_configured")
        ),
        "functions_extension_version_configured_apps": sum(
            1
            for a in apps
            if dig(a, "application_settings", "functions_extension_version_configured")
        ),
    }


# --- collection (lazy azure imports) ---

def _privileged_call(collector: Collector, operation: str, app_name: str, fn):
    """Run one POST /action call, classifying a permission failure as evidence.

    Returns (value, status, reason). A not-authorized failure is deliberately NOT routed
    through `Collector.guard`: the run stays exit 0 and names the unreadable block in the
    evidence, rather than failing the whole collection because Reader is what the operator
    granted. Anything else is recorded as a real API failure.
    """
    try:
        return fn(), COLLECTED, None
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_not_authorized(exc):
            logger.warning(
                "%s: not authorized for %s — reporting status %s (needs the "
                "Microsoft.Web/sites/host/listkeys/action and "
                "Microsoft.Web/sites/config/list/Action permissions; a ReadOnly "
                "resource lock also blocks these POSTs): %s",
                operation,
                app_name,
                NOT_AUTHORIZED,
                _one_line(exc),
            )
            return None, NOT_AUTHORIZED, exc
        collector.record(f"{operation} ({app_name})", exc)
        return None, UNAVAILABLE, exc


def collect_function_apps(subscription_id, cred, collector: Collector) -> list[dict]:
    """One web_apps.list(), then three per-app calls: `config/web` (GET, Reader) for the
    runtime and FTPS state, `host/listkeys` and `config/appsettings/list` (POST /action,
    beyond Reader) for the key and settings posture.
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
            function_app_record(project_function_app(site))
            for site in client.web_apps.list()
            if is_function_app(model_attr(site, "kind"))
        ]

    apps = collector.guard("web.web_apps.list", _list, default=[])

    for app in apps:
        group, name = app.get("resource_group"), app.get("name")
        if not group or not name:
            collector.record(
                "web.web_apps.get_configuration",
                RuntimeError(f"function app {name!r} has no resource group in its id"),
            )
            continue

        config = collector.guard(
            f"web.web_apps.get_configuration ({name})",
            lambda group=group, name=name: project_function_config(
                client.web_apps.get_configuration(resource_group_name=group, name=name)
            ),
        )
        if config is not None:
            app["configuration"] = configuration_record(config)

        host_keys, status, reason = _privileged_call(
            collector,
            "web.web_apps.list_host_keys",
            name,
            lambda group=group, name=name: project_host_keys(
                client.web_apps.list_host_keys(resource_group_name=group, name=name)
            ),
        )
        app["access_keys"] = (
            access_keys_record(host_keys)
            if host_keys is not None
            else unavailable_block(status, reason)
        )

        settings, status, reason = _privileged_call(
            collector,
            "web.web_apps.list_application_settings",
            name,
            lambda group=group, name=name: project_application_settings(
                client.web_apps.list_application_settings(
                    resource_group_name=group, name=name
                )
            ),
        )
        app["application_settings"] = (
            application_settings_record(settings)
            if settings is not None
            else unavailable_settings_block(status, reason)
        )

    return sorted(apps, key=lambda r: r.get("id") or "")


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
                "Microsoft.Web is not registered on subscription %s — no Functions "
                "in use; reporting status not_registered",
                subscription_id,
            )
        apps = collect_function_apps(subscription_id, cred, collector)
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
            "function_apps": apps,
            "provider_registration_status": registration,
        },
        summary={**summarize(apps), "provider_registration_status": registration},
    )

    filename = (
        f"azure_function_app_configuration_"
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
