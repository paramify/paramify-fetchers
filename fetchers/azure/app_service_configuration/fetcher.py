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
returns, and each app's diagnostic settings from azure-mgmt-monitor. Also cipher suites,
basic-auth publishing, Key Vault references and runtime end of support (webAppStacks),
and an opt-in scan for app settings and connection strings that hold a literal secret.
"""

import logging
import os
import re
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_service import is_not_authorized, is_web_app, web_client  # noqa: E402
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
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_app_service_configuration")

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

# App Service's fixed cipher suite order (the SDK's TlsCipherSuites enum); a minimum blocks every suite after it.
TLS_CIPHER_SUITE_ORDER = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
)
TLS13_CIPHER_SUITES = TLS_CIPHER_SUITE_ORDER[:2]

# Declared runtimes on a Windows app, in config/web; a Linux app declares one in linux_fx_version.
WINDOWS_RUNTIME_SETTINGS = (
    "net_framework_version",
    "php_version",
    "python_version",
    "node_version",
    "java_version",
)
CUSTOM_CONTAINER_PREFIXES = ("docker|", "compose|", "kube|")
JAVA_RUNTIME_KEY = re.compile(r"java\d+Runtime")
# A Windows app's Node version is this app setting, not config/web; only config/list returns it.
NODE_VERSION_SETTING = "WEBSITE_NODE_DEFAULT_VERSION"
# The one setting value written: kept only when it is a version number.
NODE_VERSION_SHAPE = re.compile(r"^~?\d+(\.\d+){0,2}$")
NODE_VERSION_UNRECOGNISED = "unrecognised"
# The .NET Framework version every Windows app carries unless .NET (Core) replaces it.
WINDOWS_DEFAULT_FRAMEWORK = "v4.0"
NODE_VERSION_UNREAD = (
    f"the Windows default; a Node app's version is in {NODE_VERSION_SETTING}, which only the opt-in "
    "literal-secret scan reads"
)

# Opt-in literal-secret scan: config/list returns setting values, which are classified here and never kept.
SCAN_ENV = "AZURE_APP_SERVICE_SCAN_LITERAL_SECRETS"
CONFIG_LIST_PERMISSION = "Microsoft.Web/sites/config/list/action"
SCAN_OFF, SCAN_DONE, SCAN_NOT_AUTHORIZED, SCAN_NOT_READ, SCAN_ERROR = (
    "off", "scanned", "not_authorized", "not_read", "error"
)
SETTING_REFERENCE_PREFIXES = ("@microsoft.keyvault(", "@microsoft.appconfiguration(")
CREDENTIAL_IN_VALUE = re.compile(
    r"(?:^|[;,\s])\w*(?:password|pwd|accountkey|sharedaccesskey|sharedaccesssignature|accesskey|secret|apikey|"
    r"subscriptionkey)\s*=\s*(?!(?:true|false)\s*(?:[;,]|$))[^;,\s]"
    r"|[?&]sig=[^&\s]"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|://[^/\s:@]*:[^/\s@]+@",
    re.IGNORECASE,
)
SECRET_NAME_PARTS = ("password", "passwd", "secret", "apikey", "accesskey", "accountkey", "privatekey", "credential")
SECRET_NAME_WORDS = frozenset({"key", "token", "pwd", "sas"})
# A name that points at or describes a secret rather than holding one.
NOT_SECRET_NAME_WORDS = frozenset({
    "id", "name", "uri", "url", "endpoint", "vault", "version", "header", "enabled", "path", "file",
    "lifetime", "expiry", "expiration", "type",
})
# Named like secrets, documented as not secret.
NOT_SECRET_SETTINGS = frozenset({"appinsights_instrumentationkey", "applicationinsights_connection_string"})
# A value made wholly of key=value; pairs: a connection string, judged by its value only.
KEY_VALUE_PAIRS = re.compile(r"(?:\s*[^=;\s][^=;]*=[^;]*;)+(?:\s*[^=;\s][^=;]*=[^;]*)?\s*")
LIMITATIONS = [
    "Deployment slots are not read: web_apps.list() returns production sites, and each slot carries its own "
    "TLS, access restrictions, basic-auth policy and settings.",
    f"On Windows, a Node app's version is the {NODE_VERSION_SETTING} app setting, which only config/list "
    f"returns, and is matched to the Node stack only. With the literal-secret scan off or refused, the .NET "
    f"Framework {WINDOWS_DEFAULT_FRAMEWORK} every such app carries reads as unknown rather than as its runtime. "
    "The portal and Visual Studio templates long added the setting to every Windows app, so it may be a stale "
    "default on a non-Node app; both runtimes are then judged.",
    f"The literal-secret scan is off unless {SCAN_ENV} is true, and needs {CONFIG_LIST_PERMISSION}, which "
    "returns setting values. Values are classified in memory and never written; only setting names and "
    f"the reason each was flagged are, plus {NODE_VERSION_SETTING} when it is a version number (anything else "
    f"is written as {NODE_VERSION_UNRECOGNISED}). A ReadOnly lock refuses config/list (409 ScopeLocked); that "
    "app reads not_read, not a collection failure.",
    "A setting holds a literal secret when it is not a Key Vault or App Configuration reference and either "
    "its value carries a credential (a key ending in Password, Pwd, AccountKey, SharedAccessKey, "
    "SharedAccessSignature, AccessKey, Secret, ApiKey or SubscriptionKey followed by = and a value other "
    "than true or false, such as ClientSecret= or DbPassword=; a SAS sig= parameter; a private key; or a password in a URL), or it is an app "
    "setting whose name contains password, passwd, secret, API key, access key, account key, private key or "
    "credential, or has the word key, token, pwd or sas, unless the name also has id, name, uri, url, "
    "endpoint, vault, version, header, enabled, path, file, lifetime, expiry, expiration or type, and whose "
    "value is a single word of at least 8 characters that is not a URL, a boolean or made wholly of "
    "key=value; pairs. "
    "Application Insights' instrumentation key and connection string never count.",
    "The scan is a heuristic, so 0 does not prove there are no literal secrets: a secret under an ordinary "
    "name with no credential syntax is missed, and a long non-secret value under a secret-like name is flagged.",
]


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
        "java_container": model_attr(config, "java_container"),
        "java_container_version": model_attr(config, "java_container_version"),
        "http20_enabled": model_attr(config, "http20_enabled"),
        "ftps_state": model_attr(config, "ftps_state"),
        "min_tls_version": model_attr(config, "min_tls_version"),
        "min_tls_cipher_suite": model_attr(config, "min_tls_cipher_suite"),
        "scm_min_tls_version": model_attr(config, "scm_min_tls_version"),
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


def project_key_vault_reference(ref) -> dict:
    """Read an `ApiKVReference`: where a setting resolves from, never its value."""
    return {
        "name": model_attr(ref, "name") or basename(model_attr(ref, "id")),
        "status": model_attr(ref, "status"),
        "source": model_attr(ref, "source"),
        "vault_name": model_attr(ref, "vault_name"),
        "secret_name": model_attr(ref, "secret_name"),
        "secret_version": model_attr(ref, "secret_version"),
        "identity_type": model_attr(ref, "identity_type"),
        "details": model_attr(ref, "details"),
    }


def project_literal_secrets(app_settings, connection_strings) -> dict:
    """Read config/list results into setting NAMES and reasons only; the Node version is the one value kept."""
    settings = model_attr(app_settings, "properties") or {}
    strings = model_attr(connection_strings, "properties") or {}
    node_version = next(
        (str(v).strip() for k, v in settings.items() if str(k).upper() == NODE_VERSION_SETTING and v), None
    )
    found = [
        {"name": str(name), "kind": "app_setting", "reason": reason}
        for name, value in settings.items()
        if (reason := literal_secret_reason(name, value))
    ] + [
        {"name": str(name), "kind": "connection_string", "reason": reason}
        for name, pair in strings.items()
        if (reason := literal_secret_reason(name, model_attr(pair, "value"), by_name=False))
    ]
    return {
        "app_settings_read": len(settings),
        "connection_strings_read": len(strings),
        "literal_secrets": sorted(found, key=lambda r: (r["kind"], r["name"])),
        "node_version": node_version if not node_version or NODE_VERSION_SHAPE.match(node_version)
        else NODE_VERSION_UNRECOGNISED,
    }


def _support_dates(settings) -> dict:
    eol = model_attr(settings, "end_of_life_date")
    return {
        "end_of_life_date": eol.isoformat() if isinstance(eol, datetime) else eol,
        "is_deprecated": bool(model_attr(settings, "is_deprecated") or False),
    }


def project_web_app_stack(stack) -> list[dict]:
    """Flatten one `WebAppStack` into runtimes spelled the way a site's config/web declares them."""
    name = model_attr(stack, "name") or model_attr(stack, "value")
    entries = []
    for major in model_attr(stack, "major_versions") or []:
        for minor in model_attr(major, "minor_versions") or []:
            settings = model_attr(minor, "stack_settings")
            base = {"stack": name, "version": model_attr(minor, "value")}
            for os_name in ("linux", "windows"):
                runtime = model_attr(settings, f"{os_name}_runtime_settings")
                if model_attr(runtime, "runtime_version"):
                    entries.append({**base, "os": os_name, "runtime": model_attr(runtime, "runtime_version"),
                                    **_support_dates(runtime)})
            linux_container = model_attr(settings, "linux_container_settings")
            # The SDK model names only java8/java11; java17Runtime and later are on the raw mapping.
            for key in (linux_container.keys() if isinstance(linux_container, Mapping) else ()):
                if JAVA_RUNTIME_KEY.fullmatch(key) and linux_container[key]:
                    entries.append({**base, "os": "linux", "runtime": linux_container[key],
                                    **_support_dates(linux_container)})
            windows_container = model_attr(settings, "windows_container_settings")
            if model_attr(windows_container, "java_container"):
                runtime = java_container_runtime(
                    model_attr(windows_container, "java_container"),
                    model_attr(windows_container, "java_container_version"),
                )
                entries.append({**base, "os": "windows", "runtime": runtime,
                                **_support_dates(windows_container)})
    return entries


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

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
        "basic_auth_publishing": None,
        "key_vault_references": None,
        "runtime_support": None,
        "literal_secret_scan": literal_secret_scan_record(SCAN_OFF),
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
        "java_container": config.get("java_container"),
        "java_container_version": config.get("java_container_version"),
        "http20_enabled": bool(config.get("http20_enabled") or False),
        "ftps_state": config.get("ftps_state"),
        "min_tls_version": config.get("min_tls_version"),
        "scm_min_tls_version": config.get("scm_min_tls_version"),
        "remote_debugging_enabled": bool(config.get("remote_debugging_enabled") or False),
        "always_on": bool(config.get("always_on") or False),
        "http_logging_enabled": bool(config.get("http_logging_enabled") or False),
        **access_restrictions_record(config),
        **cipher_suite_record(config.get("min_tls_version"), config.get("min_tls_cipher_suite")),
    }


def allowed_cipher_suites(min_tls_version, min_cipher_suite):
    """Suites a client can still negotiate; None for a minimum outside the known order."""
    if str(min_tls_version or "") == "1.3":
        return list(TLS13_CIPHER_SUITES)
    if not min_cipher_suite:
        return list(TLS_CIPHER_SUITE_ORDER)
    if min_cipher_suite not in TLS_CIPHER_SUITE_ORDER:
        return None
    return list(TLS_CIPHER_SUITE_ORDER[: TLS_CIPHER_SUITE_ORDER.index(min_cipher_suite) + 1])


def cipher_suite_record(min_tls_version, min_cipher_suite) -> dict:
    allowed = allowed_cipher_suites(min_tls_version, min_cipher_suite)
    return {
        "min_tls_cipher_suite": min_cipher_suite,
        "allowed_tls_cipher_suites": allowed,
        "allows_cbc_cipher_suites": None if allowed is None else any("_CBC_" in s for s in allowed),
        # TLS_RSA_* suites use static RSA key exchange: no forward secrecy.
        "allows_non_forward_secret_cipher_suites": (
            None if allowed is None else any(s.startswith("TLS_RSA_") for s in allowed)
        ),
    }


def basic_auth_record(scm_allowed, ftp_allowed) -> dict:
    """Basic-auth publishing: `disabled` is null when a policy read failed and neither read showed it on."""
    if scm_allowed or ftp_allowed:
        disabled = False
    elif scm_allowed is None or ftp_allowed is None:
        disabled = None
    else:
        disabled = True
    return {"scm_allowed": scm_allowed, "ftp_allowed": ftp_allowed, "disabled": disabled}


def key_vault_reference_record(ref: dict) -> dict:
    return {
        "name": ref.get("name"),
        "status": ref.get("status"),
        "resolved": str(ref.get("status") or "").lower() == "resolved",
        "source": ref.get("source"),
        "vault_name": ref.get("vault_name"),
        "secret_name": ref.get("secret_name"),
        "secret_version_pinned": bool(ref.get("secret_version")),
        "identity_type": ref.get("identity_type"),
        "details": ref.get("details"),
    }


def is_setting_reference(value) -> bool:
    return str(value or "").strip().lower().startswith(SETTING_REFERENCE_PREFIXES)


def name_words(name) -> list[str]:
    return re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name or "")).lower())


def secret_like_name(name) -> bool:
    if str(name or "").lower() in NOT_SECRET_SETTINGS:
        return False
    words = name_words(name)
    if NOT_SECRET_NAME_WORDS.intersection(words):
        return False
    joined = "".join(words)
    return any(part in joined for part in SECRET_NAME_PARTS) or bool(SECRET_NAME_WORDS.intersection(words))


def could_be_secret(text: str) -> bool:
    return (
        len(text) >= 8
        and not any(c.isspace() for c in text)
        and text.lower() not in ("true", "false")
        and not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.IGNORECASE)
        and not KEY_VALUE_PAIRS.fullmatch(text)
    )


def literal_secret_reason(name, value, by_name: bool = True):
    """Why a setting looks like it holds a literal secret (credential_in_value, secret_like_name), or None."""
    text = str(value or "").strip()
    if not text or is_setting_reference(text):
        return None
    if CREDENTIAL_IN_VALUE.search(text):
        return "credential_in_value"
    if by_name and secret_like_name(name) and could_be_secret(text):
        return "secret_like_name"
    return None


def literal_secret_scan_record(status: str, found: dict | None = None, reason: str | None = None) -> dict:
    """`literal_secrets` and `has_literal_secrets` are null unless the scan ran: off or refused is unknown."""
    found = found or {}
    secrets = found.get("literal_secrets")
    return {
        "status": status,
        "reason": reason,
        "app_settings_read": found.get("app_settings_read"),
        "connection_strings_read": found.get("connection_strings_read"),
        "literal_secrets": secrets,
        "has_literal_secrets": None if secrets is None else bool(secrets),
    }


def key_vault_reference_items(app: dict) -> list[dict]:
    refs = app.get("key_vault_references") or {}
    return [r for part in ("app_settings", "connection_strings") for r in (refs.get(part) or [])]


def java_container_runtime(container, version) -> str:
    return f"{container}|{version or ''}"


def runtime_index(entries: list[dict]) -> dict:
    """(os, lower-cased runtime) -> the stack entries declaring it, in stack-list order."""
    index: dict = {}
    for entry in entries:
        index.setdefault((entry["os"], str(entry["runtime"]).lower()), []).append(entry)
    return index


def is_windows_code_app(kind, config: dict) -> bool:
    return "linux" not in str(kind or "").lower() and not config.get("windows_fx_version")


def declared_runtimes(kind, config: dict, node_version=None) -> list[tuple[str, str, str]]:
    """(setting, value, os) for each runtime the app declares; "Off" and blanks are not declared."""
    if "linux" in str(kind or "").lower():
        candidates = [("linux_fx_version", config.get("linux_fx_version"), "linux")]
    elif config.get("windows_fx_version"):
        candidates = [("windows_fx_version", config.get("windows_fx_version"), "windows")]
    else:
        candidates = [(field, config.get(field), "windows") for field in WINDOWS_RUNTIME_SETTINGS]
        candidates.append((NODE_VERSION_SETTING, node_version, "windows"))
        if config.get("java_container"):
            candidates.append((
                "java_container",
                java_container_runtime(config["java_container"], config.get("java_container_version")),
                "windows",
            ))
    return [
        (setting, str(value).strip(), os_name)
        for setting, value, os_name in candidates
        if value and str(value).strip().lower() not in ("", "off")
    ]


def _parse_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def runtime_keys(setting, value: str) -> list[str]:
    """A Node setting may be "18.17.1" where the stack list says "~18" (or "10.14" for old versions)."""
    keys = [value.lower()]
    match = re.match(r"^~?(\d+)(?:\.(\d+))?", value) if setting == NODE_VERSION_SETTING else None
    if match:
        keys.append(f"~{match.group(1)}")
        if match.group(2):
            keys.append(f"{match.group(1)}.{match.group(2)}")
    return keys


def unread_default_record(setting, value) -> dict:
    return {
        "setting": setting, "value": value, "custom_container": False, "stack": None, "version": None,
        "end_of_life_date": None, "days_until_end_of_life": None, "is_deprecated": None,
        "past_end_of_support": None, "note": NODE_VERSION_UNREAD,
    }


def runtime_record(setting, value, os_name, index: dict, now: datetime) -> dict:
    custom_container = value.lower().startswith(CUSTOM_CONTAINER_PREFIXES)
    # A Node version like "17" or "7.4.0" would otherwise land on the Java or PHP stack.
    stack = "node" if setting == NODE_VERSION_SETTING else None
    entry = None if custom_container else next(
        (e for key in runtime_keys(setting, value) for e in index.get((os_name, key), [])
         if stack is None or str(e["stack"]).lower() == stack),
        None,
    )
    eol = _parse_time(entry["end_of_life_date"]) if entry and entry.get("end_of_life_date") else None
    if entry is None:
        past = None
    else:
        past = bool(entry["is_deprecated"] or (eol is not None and eol <= now))
    return {
        "setting": setting,
        "value": value,
        "custom_container": custom_container,
        "stack": entry["stack"] if entry else None,
        "version": entry["version"] if entry else None,
        "end_of_life_date": entry.get("end_of_life_date") if entry else None,
        "days_until_end_of_life": (eol.date() - now.date()).days if eol else None,
        "is_deprecated": entry["is_deprecated"] if entry else None,
        "past_end_of_support": past,
        "note": None,
    }


def runtime_support_record(
    kind, config: dict, index: dict, now: datetime, node_version=None, node_version_read: bool = False
) -> dict:
    """Any declared runtime past end of support makes the app past it; an unmatched one makes it unknown.

    On Windows the default .NET Framework v4.0 reads unknown while the Node setting is unread: it may be
    a Node app's default rather than its runtime.
    """
    runtimes = []
    for setting, value, os_name in declared_runtimes(kind, config, node_version):
        default = (is_windows_code_app(kind, config) and setting == "net_framework_version"
                   and value.lower() == WINDOWS_DEFAULT_FRAMEWORK)
        if default and not node_version_read:
            runtimes.append(unread_default_record(setting, value))
            continue
        runtimes.append(runtime_record(setting, value, os_name, index, now))
    verdicts = [r["past_end_of_support"] for r in runtimes]
    if any(verdicts):
        past = True
    elif not runtimes or None in verdicts:
        past = None
    else:
        past = False
    return {
        "declared_runtimes": runtimes,
        "past_end_of_support": past,
        "runtimes_past_end_of_support": [r["value"] for r in runtimes if r["past_end_of_support"]],
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


def summarize(apps: list[dict], scan_enabled: bool = False) -> dict:
    """Transport, identity and runtime coverage across the subscription's web apps."""
    total = len(apps)
    scans = [a.get("literal_secret_scan") or {} for a in apps]
    scanned = [s for s in scans if s.get("status") == SCAN_DONE]
    # Apps present but none scanned (403 or locked everywhere): the secret counts are unknown, not 0.
    secrets_counted = scan_enabled and (bool(scanned) or not apps)
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
        # --- TLS cipher suites ---
        "scm_minimum_tls_1_2_apps": sum(
            1
            for a in apps
            if str(dig(a, "configuration", "scm_min_tls_version") or "") in MODERN_TLS_VERSIONS
        ),
        "min_tls_cipher_suite_set_apps": sum(
            1 for a in apps if dig(a, "configuration", "min_tls_cipher_suite")
        ),
        "cbc_cipher_suites_allowed_apps": sum(
            1 for a in apps if dig(a, "configuration", "allows_cbc_cipher_suites")
        ),
        "non_forward_secret_cipher_suites_allowed_apps": sum(
            1 for a in apps if dig(a, "configuration", "allows_non_forward_secret_cipher_suites")
        ),
        # --- basic-auth publishing ---
        "scm_basic_auth_allowed_apps": sum(
            1 for a in apps if dig(a, "basic_auth_publishing", "scm_allowed")
        ),
        "ftp_basic_auth_allowed_apps": sum(
            1 for a in apps if dig(a, "basic_auth_publishing", "ftp_allowed")
        ),
        "basic_auth_publishing_disabled_apps": sum(
            1 for a in apps if dig(a, "basic_auth_publishing", "disabled") is True
        ),
        "basic_auth_publishing_unknown_apps": sum(
            1 for a in apps if dig(a, "basic_auth_publishing", "disabled") is None
        ),
        # --- Key Vault references ---
        "apps_with_key_vault_references": sum(1 for a in apps if key_vault_reference_items(a)),
        "key_vault_references": sum(len(key_vault_reference_items(a)) for a in apps),
        "unresolved_key_vault_references": sum(
            1 for a in apps for r in key_vault_reference_items(a) if not r["resolved"]
        ),
        "apps_with_unresolved_key_vault_references": sum(
            1 for a in apps if any(not r["resolved"] for r in key_vault_reference_items(a))
        ),
        # --- runtime end of support ---
        "apps_with_runtime_past_end_of_support": sum(
            1 for a in apps if dig(a, "runtime_support", "past_end_of_support") is True
        ),
        "apps_with_runtime_support_unknown": sum(
            1 for a in apps if dig(a, "runtime_support", "past_end_of_support") is None
        ),
        # --- opt-in literal-secret scan (null counts when off, or when no app could be scanned) ---
        "literal_secret_scan_enabled": scan_enabled,
        "apps_scanned_for_literal_secrets": len(scanned) if scan_enabled else None,
        "apps_literal_secret_scan_not_authorized": (
            sum(1 for s in scans if s.get("status") == SCAN_NOT_AUTHORIZED) if scan_enabled else None
        ),
        "apps_literal_secret_scan_not_read": (
            sum(1 for s in scans if s.get("status") == SCAN_NOT_READ) if scan_enabled else None
        ),
        "apps_with_literal_secrets": (
            sum(1 for s in scanned if s["has_literal_secrets"]) if secrets_counted else None
        ),
        "literal_secret_settings": sum(len(s["literal_secrets"]) for s in scanned) if secrets_counted else None,
    }


# --- collection (lazy azure imports) ---

def collect_web_apps(subscription_id, cred, collector: Collector, scan_secrets: bool = False) -> list[dict]:
    """One web_apps.list(), then Reader GETs per app (`config/web`, `config/authsettingsV2`, publishing
    policies, Key Vault references); with `scan_secrets`, the config/list POSTs for the literal-secret scan.
    """
    client = web_client(subscription_id, cred, collector)
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
    node_versions: dict = {}

    for app in apps:
        group, name = app.get("resource_group"), app.get("name")
        if not group or not name:
            collector.record(
                "web.web_apps.get_configuration",
                RuntimeError(f"web app {name!r} has no resource group in its id"),
            )
            if scan_secrets:
                app["literal_secret_scan"] = literal_secret_scan_record(
                    SCAN_NOT_READ, reason="the app's id has no resource group"
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
        _attach_publishing_and_references(client, collector, app, group, name)
        if scan_secrets:
            app["literal_secret_scan"], found = _scan_literal_secrets(client, collector, group, name)
            if found is not None:
                node_versions[app["id"]] = found["node_version"]

    if apps:
        _attach_runtime_support(client, collector, apps, datetime.now(timezone.utc), node_versions)
        _attach_diagnostic_settings(subscription_id, cred, collector, apps)

    return sorted(apps, key=lambda r: r.get("id") or "")


def _attach_publishing_and_references(client, collector: Collector, app, group, name) -> None:
    """basicPublishingCredentialsPolicies and configreferences: Reader GETs that return no setting values."""
    policies = {}
    for kind, call in (("scm", client.web_apps.get_scm_allowed), ("ftp", client.web_apps.get_ftp_allowed)):
        policies[kind] = collector.guard(
            f"web.web_apps.get_{kind}_allowed ({name})",
            lambda call=call: bool(model_attr(call(resource_group_name=group, name=name), "allow") or False),
        )
    app["basic_auth_publishing"] = basic_auth_record(policies["scm"], policies["ftp"])

    references = {}
    for part, method in (
        ("app_settings", "get_app_settings_key_vault_references"),
        ("connection_strings", "get_site_connection_string_key_vault_references"),
    ):
        call = getattr(client.web_apps, method)
        references[part] = collector.guard(
            f"web.web_apps.{method} ({name})",
            lambda call=call: sorted(
                (key_vault_reference_record(project_key_vault_reference(ref))
                 for ref in call(resource_group_name=group, name=name)),
                key=lambda r: r.get("name") or "",
            ),
        )
    app["key_vault_references"] = references


def is_scope_locked(exc: BaseException) -> bool:
    code = model_attr(getattr(exc, "error", None), "code")
    return str(code or "").lower() == "scopelocked" or "scopelocked" in str(exc).lower()


def _scan_literal_secrets(client, collector: Collector, group, name) -> tuple[dict, dict | None]:
    """(scan record, names and Node version or None). A 403 is the opt-in permission not granted; a 409 a lock."""
    try:
        found = project_literal_secrets(
            client.web_apps.list_application_settings(resource_group_name=group, name=name),
            client.web_apps.list_connection_strings(resource_group_name=group, name=name),
        )
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        if is_not_authorized(exc):
            return literal_secret_scan_record(SCAN_NOT_AUTHORIZED), None
        if is_scope_locked(exc):
            return literal_secret_scan_record(SCAN_NOT_READ, reason="a ReadOnly lock refuses config/list"), None
        collector.record(f"web.web_apps.list_application_settings/list_connection_strings ({name})", exc)
        return literal_secret_scan_record(SCAN_ERROR), None
    return literal_secret_scan_record(SCAN_DONE, found), found


def scan_enabled() -> bool:
    return os.environ.get(SCAN_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _attach_runtime_support(client, collector: Collector, apps, now: datetime, node_versions: dict) -> None:
    """One tenant-wide GET of Microsoft.Web/webAppStacks, joined to each app's declared runtimes."""
    entries = collector.guard(
        "web.provider.get_web_app_stacks",
        lambda: [entry for stack in client.provider.get_web_app_stacks() for entry in project_web_app_stack(stack)],
    )
    if entries is None:
        return
    index = runtime_index(entries)
    for app in apps:
        if app.get("configuration") is not None:
            app["runtime_support"] = runtime_support_record(
                app.get("kind"), app["configuration"], index, now,
                node_version=node_versions.get(app["id"]), node_version_read=app["id"] in node_versions,
            )


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
    scan_secrets = scan_enabled()
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
        apps = collect_web_apps(subscription_id, cred, collector, scan_secrets)
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
            "literal_secret_scan": {
                "enabled": scan_secrets,
                "permission": CONFIG_LIST_PERMISSION,
                "apps_not_authorized": sum(
                    1 for a in apps if dig(a, "literal_secret_scan", "status") == SCAN_NOT_AUTHORIZED
                ) if scan_secrets else None,
                "apps_not_read": sum(
                    1 for a in apps if dig(a, "literal_secret_scan", "status") == SCAN_NOT_READ
                ) if scan_secrets else None,
            },
            "limitations": LIMITATIONS,
            "provider_registration_status": registration,
        },
        summary={**summarize(apps, scan_secrets), "provider_registration_status": registration},
    )

    filename = (
        f"azure_app_service_configuration_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s (%d web apps)", path, len(apps))

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
