#!/usr/bin/env python3
"""Azure API Management: network exposure, TLS and ciphers, gateway policies, APIs, products, subscriptions, backends and secrets handling."""

import logging
import os
import re
import sys
from datetime import datetime, timezone
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
    credential,
    failure_reason,
    is_not_found,
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

logger = logging.getLogger("azure_api_management_configuration")

PREFIX = "Microsoft.WindowsAzure.ApiManagement.Gateway."
CIPHER_PREFIX = PREFIX + "Security.Ciphers."
# customProperties switches. Azure documents the protocol switches and TripleDes168 as
# defaulting to True only on services created on or before 1 April 2018, and the cipher
# switches below as defaulting to True on every service: they stay on until set to False.
PROTOCOL_KEYS = {
    "client_tls_1_0": "Security.Protocols.Tls10",
    "client_tls_1_1": "Security.Protocols.Tls11",
    "client_ssl_3_0": "Security.Protocols.Ssl30",
    "backend_tls_1_0": "Security.Backend.Protocols.Tls10",
    "backend_tls_1_1": "Security.Backend.Protocols.Tls11",
    "backend_ssl_3_0": "Security.Backend.Protocols.Ssl30",
}
DEFAULT_ON_CIPHERS = (
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
)
TRIPLE_DES = "TripleDes168"  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
LEGACY_DEFAULT_CUTOFF = datetime(2018, 4, 1, tzinfo=timezone.utc)
# Microsoft's recommended floor for the management API, below which secrets can be read back.
MIN_MANAGEMENT_API_VERSION = "2019-12-01"
EXPIRY_WARNING_DAYS = 30
# Policy elements whose presence is evidence; the XML itself is never written to the evidence.
POLICY_ELEMENTS = (
    "ip-filter",
    "rate-limit",
    "rate-limit-by-key",
    "quota",
    "quota-by-key",
    "validate-jwt",
    "validate-azure-ad-token",
    "check-header",
    "cors",
    "validate-content",
    "authentication-managed-identity",
    "authentication-certificate",
)
TOKEN_VALIDATION = ("validate-jwt", "validate-azure-ad-token")
UNSUPPORTED_IN_TIER = "methodnotallowedinpricingtier"


def legacy_default(created_at) -> bool:
    if created_at is None:
        return False
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return created_at <= LEGACY_DEFAULT_CUTOFF


def switch(props: dict, key: str, default: bool) -> dict:
    """One customProperties switch: its effective value and whether it was set or defaulted."""
    raw = props.get(key.lower())
    if raw is None:
        return {"enabled": default, "source": "default"}
    return {"enabled": str(raw).lower() == "true", "source": "explicit"}


def protocol_settings(custom_properties, created_at) -> dict:
    props = {k.lower(): v for k, v in (custom_properties or {}).items()}
    return {
        label: switch(props, PREFIX + suffix, legacy_default(created_at)) for label, suffix in PROTOCOL_KEYS.items()
    }


def cipher_weaknesses(name: str) -> list:
    """Why a cipher suite is weak: CBC mode, no forward secrecy (RSA key exchange), or 3DES."""
    reasons = []
    if name == TRIPLE_DES or "3DES" in name:
        reasons.append("3des")
    if "_CBC_" in name or name == TRIPLE_DES:
        reasons.append("cbc")
    if name.startswith("TLS_RSA_") or name == TRIPLE_DES:
        reasons.append("no_forward_secrecy")
    return reasons


def cipher_settings(custom_properties, created_at) -> dict:
    """Every cipher Azure lets you switch off, with its effective state; unset ones follow Azure's default."""
    props = {k.lower(): v for k, v in (custom_properties or {}).items()}
    out = {
        name: {**switch(props, CIPHER_PREFIX + name, True), "weaknesses": cipher_weaknesses(name)}
        for name in DEFAULT_ON_CIPHERS
    }
    out[TRIPLE_DES] = {
        **switch(props, CIPHER_PREFIX + TRIPLE_DES, legacy_default(created_at)),
        "weaknesses": cipher_weaknesses(TRIPLE_DES),
    }
    return out


def policy_elements(xml) -> list:
    """Security-relevant elements present in a policy document."""
    text = xml or ""
    return [e for e in POLICY_ELEMENTS if re.search(rf"<{re.escape(e)}[\s/>]", text)]


def days_until(expiry, now: datetime):
    if expiry is None:
        return None
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return (expiry - now).days


def api_version_enforced(min_api_version) -> bool:
    return bool(min_api_version) and str(min_api_version)[:10] >= MIN_MANAGEMENT_API_VERSION


def project_service(service, now: datetime) -> dict:
    sku = model_attr(service, "sku")
    vnet = model_attr(service, "virtual_network_configuration")
    created = model_attr(service, "created_at_utc")
    custom = model_attr(service, "custom_properties") or {}
    constraint = model_attr(service, "api_version_constraint")
    min_version = model_attr(constraint, "min_api_version")
    ciphers = cipher_settings(custom, created)
    hostnames = []
    for h in model_attr(service, "hostname_configurations") or []:
        expiry = model_attr(model_attr(h, "certificate"), "expiry")
        hostnames.append(
            {
                "type": model_attr(h, "type"),
                "host_name": model_attr(h, "host_name"),
                "certificate_source": model_attr(h, "certificate_source"),
                "key_vault_backed": bool(model_attr(h, "key_vault_id")),
                "certificate_expiry": expiry.isoformat() if expiry else None,
                "certificate_days_to_expiry": days_until(expiry, now),
                "negotiate_client_certificate": model_attr(h, "negotiate_client_certificate"),
                "default_ssl_binding": model_attr(h, "default_ssl_binding"),
            }
        )
    return {
        "id": model_attr(service, "id"),
        "name": model_attr(service, "name"),
        "location": model_attr(service, "location"),
        "resource_group": resource_group_from_id(model_attr(service, "id")),
        "tags": model_attr(service, "tags") or {},
        "sku": model_attr(sku, "name"),
        "capacity": model_attr(sku, "capacity"),
        "zones": model_attr(service, "zones") or [],
        "created_at_utc": created.isoformat() if created else None,
        "identity_type": model_attr(model_attr(service, "identity"), "type"),
        "gateway_url": model_attr(service, "gateway_url"),
        "developer_portal_url": model_attr(service, "developer_portal_url"),
        "public_network_access": model_attr(service, "public_network_access"),
        "virtual_network_type": model_attr(service, "virtual_network_type"),
        "virtual_network_subnet_id": model_attr(vnet, "subnet_resource_id"),
        "public_ip_addresses": model_attr(service, "public_ip_addresses") or [],
        "private_endpoint_connections": [
            {
                "id": model_attr(c, "id"),
                "status": model_attr(model_attr(c, "private_link_service_connection_state"), "status"),
            }
            for c in model_attr(service, "private_endpoint_connections") or []
        ],
        "nat_gateway_state": model_attr(service, "nat_gateway_state"),
        "gateway_disabled": model_attr(service, "disable_gateway"),
        "developer_portal_status": model_attr(service, "developer_portal_status"),
        "legacy_portal_status": model_attr(service, "legacy_portal_status"),
        "minimum_management_api_version": min_version,
        "minimum_api_version_enforced": api_version_enforced(min_version),
        "client_certificate_enabled": model_attr(service, "enable_client_certificate"),
        "http2_enabled": str(custom.get(PREFIX + "Protocols.Server.Http2", "false")).lower() == "true",
        "legacy_protocols": protocol_settings(custom, created),
        "ciphers": ciphers,
        "weak_ciphers_enabled": sorted(n for n, c in ciphers.items() if c["enabled"] and c["weaknesses"]),
        "hostnames": hostnames,
    }


def project_api(api) -> dict:
    auth = model_attr(api, "authentication_settings")
    protocols = [str(p) for p in model_attr(api, "protocols") or []]
    service_url = model_attr(api, "service_url")
    return {
        "name": model_attr(api, "name"),
        "display_name": model_attr(api, "display_name"),
        "path": model_attr(api, "path"),
        "api_type": model_attr(api, "api_type"),
        "is_current": model_attr(api, "is_current"),
        "protocols": protocols,
        "accepts_http": any(p.lower() in ("http", "ws") for p in protocols),
        "backend_uses_http": str(service_url or "").lower().startswith("http://"),
        "subscription_required": model_attr(api, "subscription_required"),
        "oauth2_or_openid_configured": bool(
            model_attr(auth, "o_auth2")
            or model_attr(auth, "openid")
            or model_attr(auth, "o_auth2_authentication_settings")
            or model_attr(auth, "openid_authentication_settings")
        ),
    }


def project_product(product) -> dict:
    return {
        "name": model_attr(product, "name"),
        "display_name": model_attr(product, "display_name"),
        "state": model_attr(product, "state"),
        "subscription_required": model_attr(product, "subscription_required"),
        "approval_required": model_attr(product, "approval_required"),
        "subscriptions_limit": model_attr(product, "subscriptions_limit"),
    }


def project_backend(backend) -> dict:
    tls = model_attr(backend, "tls")
    url = model_attr(backend, "url")
    creds = model_attr(backend, "credentials")
    return {
        "name": model_attr(backend, "name"),
        "protocol": model_attr(backend, "protocol"),
        "uses_http": str(url or "").lower().startswith("http://"),
        "validate_certificate_chain": model_attr(tls, "validate_certificate_chain"),
        "validate_certificate_name": model_attr(tls, "validate_certificate_name"),
        # Whether any credential is configured; the values are never read into the evidence.
        "auth_configured": bool(
            model_attr(creds, "header")
            or model_attr(creds, "query")
            or model_attr(creds, "authorization")
            or model_attr(creds, "certificate")
            or model_attr(creds, "certificate_ids")
        ),
        "azure_resource_id": model_attr(backend, "resource_id"),
    }


def subscription_scope_kind(scope) -> str:
    """all_apis (the service itself, or /apis), product, or api."""
    path = str(scope or "").rstrip("/").lower()
    if "/products/" in path:
        return "product"
    if re.search(r"/apis/[^/]+$", path):
        return "api"
    return "all_apis"


def project_subscription(sub) -> dict:
    """Scope, state and tracing only; primary and secondary keys are never read into the evidence."""
    scope = model_attr(sub, "scope")
    return {
        "name": model_attr(sub, "name"),
        "display_name": model_attr(sub, "display_name"),
        "scope_kind": subscription_scope_kind(scope),
        "built_in_all_access": model_attr(sub, "name") == "master",
        "state": model_attr(sub, "state"),
        "allow_tracing": model_attr(sub, "allow_tracing"),
    }


def project_named_value(named_value) -> dict:
    """Metadata only: the value of a named value is never read into the evidence."""
    secret = bool(model_attr(named_value, "secret"))
    key_vault = bool(model_attr(named_value, "key_vault"))
    return {
        "name": model_attr(named_value, "name"),
        "secret": secret,
        "key_vault_backed": key_vault,
        "secret_stored_in_api_management": secret and not key_vault,
    }


def project_certificate(cert, now: datetime) -> dict:
    expiry = model_attr(cert, "expiration_date")
    return {
        "name": model_attr(cert, "name"),
        "subject": model_attr(cert, "subject"),
        "expiration_date": expiry.isoformat() if expiry else None,
        "days_to_expiry": days_until(expiry, now),
        "key_vault_backed": bool(model_attr(cert, "key_vault")),
    }


def sign_up_status(client, rg, name, collector: Collector):
    """enabled / disabled, not_available_in_tier on v2 tiers, null when the read failed."""
    try:
        return "enabled" if model_attr(client.sign_up_settings.get(rg, name), "enabled") else "disabled"
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if UNSUPPORTED_IN_TIER in str(exc).lower().replace(" ", ""):
            return "not_available_in_tier"
        if is_not_found(exc):
            return "disabled"
        collector.record(f"apimanagement.sign_up_settings.get({rg}/{name})", exc)
        return None


def optional_policy(fn):
    """Elements of a policy that may not exist; [] on 404, raises otherwise for the caller's guard."""
    try:
        return policy_elements(model_attr(fn(), "value"))
    except Exception as exc:  # noqa: BLE001
        if is_not_found(exc):
            return []
        raise


def api_access_control(api: dict, global_elements, product_elements: list) -> object:
    """How an API is protected: subscription key, OAuth, or a token-validation policy at any level.

    Null when a policy that could protect it could not be read and nothing else does.
    """
    if api["subscription_required"] or api["oauth2_or_openid_configured"]:
        return True
    levels = [global_elements, api["policy_elements"], *product_elements]
    ops = [o["policy_elements"] for o in api["operations"] or []]
    if any(lvl and any(e in lvl for e in TOKEN_VALIDATION) for lvl in levels):
        return True
    if ops and all(o and any(e in o for e in TOKEN_VALIDATION) for o in ops):
        return True  # every operation validates a token
    if any(lvl is None for lvl in levels) or api["operations"] is None or any(o is None for o in ops):
        return None
    return False


def collect_service(client, monitor, service: dict, collector: Collector, now: datetime) -> dict:
    rg, name = service["resource_group"], service["name"]
    label = f"{rg}/{name}"

    def _list(operation, fn, project):
        rows = collector.guard(f"apimanagement.{operation}({label})", lambda: [project(r) for r in fn(rg, name)])
        return None if rows is None else sorted(rows, key=lambda r: r.get("name") or "")

    global_elements = collector.guard(
        f"apimanagement.policy.get({label})",
        lambda: optional_policy(lambda: client.policy.get(rg, name, "policy", format="rawxml")),
    )
    products = _list("product.list_by_service", client.product.list_by_service, project_product)
    apis_by_product: dict = {}
    for product in products or []:
        pid = product["name"]
        product["policy_elements"] = collector.guard(
            f"apimanagement.product_policy.get({label}/{pid})",
            lambda pid=pid: optional_policy(lambda: client.product_policy.get(rg, name, pid, "policy", format="rawxml")),
        )
        product["apis"] = collector.guard(
            f"apimanagement.product_api.list_by_product({label}/{pid})",
            lambda pid=pid: sorted(model_attr(a, "name") for a in client.product_api.list_by_product(rg, name, pid)),
        )
        for api_name in product["apis"] or []:
            apis_by_product.setdefault(api_name, []).append(product)

    apis = _list("api.list_by_service", client.api.list_by_service, project_api)
    for api in apis or []:
        aid = api["name"]
        api["policy_elements"] = collector.guard(
            f"apimanagement.api_policy.get({label}/{aid})",
            lambda aid=aid: optional_policy(lambda: client.api_policy.get(rg, name, aid, "policy", format="rawxml")),
        )
        operations = collector.guard(
            f"apimanagement.api_operation.list_by_api({label}/{aid})",
            lambda aid=aid: [
                {"name": model_attr(o, "name"), "method": model_attr(o, "method"), "url_template": model_attr(o, "url_template")}
                for o in client.api_operation.list_by_api(rg, name, aid)
            ],
        )
        for op in operations or []:
            op["policy_elements"] = collector.guard(
                f"apimanagement.api_operation_policy.get({label}/{aid}/{op['name']})",
                lambda aid=aid, op=op: optional_policy(
                    lambda: client.api_operation_policy.get(rg, name, aid, op["name"], "policy", format="rawxml")
                ),
            )
        api["operations"] = None if operations is None else sorted(operations, key=lambda o: o["name"] or "")
        api["products"] = sorted(p["name"] for p in apis_by_product.get(aid, []))
        product_levels = [p["policy_elements"] for p in apis_by_product.get(aid, [])]
        if products is None:
            product_levels.append(None)  # unread products could hold the protecting policy
        api["access_control"] = api_access_control(api, global_elements, product_levels)

    fragments = collector.guard(
        f"apimanagement.policy_fragment.list_by_service({label})",
        lambda: [model_attr(f, "name") for f in client.policy_fragment.list_by_service(rg, name)],
    )
    fragment_records = None
    if fragments is not None:
        fragment_records = []
        for fid in sorted(fragments):
            elements = collector.guard(
                f"apimanagement.policy_fragment.get({label}/{fid})",
                lambda fid=fid: policy_elements(model_attr(client.policy_fragment.get(rg, name, fid, format="rawxml"), "value")),
            )
            fragment_records.append({"name": fid, "policy_elements": elements})

    diagnostics = None
    if monitor is not None:
        diagnostics = collector.guard(
            f"monitor.diagnostic_settings.list({label})", lambda: list_diagnostic_settings(monitor, service["id"])
        )
    return {
        **service,
        "developer_portal_sign_up": sign_up_status(client, rg, name, collector),
        "global_policy_elements": global_elements,
        "policy_fragments": fragment_records,
        "apis": apis,
        "products": products,
        "subscriptions": _list("subscription.list", client.subscription.list, project_subscription),
        "backends": _list("backend.list_by_service", client.backend.list_by_service, project_backend),
        "identity_providers": _list(
            "identity_provider.list_by_service",
            client.identity_provider.list_by_service,
            lambda p: {"name": model_attr(p, "name"), "type": model_attr(p, "type_properties_type")},
        ),
        "named_values": _list("named_value.list_by_service", client.named_value.list_by_service, project_named_value),
        "certificates": _list(
            "certificate.list_by_service", client.certificate.list_by_service, lambda c: project_certificate(c, now)
        ),
        "loggers": _list(
            "logger.list_by_service",
            client.logger.list_by_service,
            lambda lg: {"name": model_attr(lg, "name"), "logger_type": model_attr(lg, "logger_type")},
        ),
        "diagnostic_settings": diagnostics,
        "audit_logs_exported": logs_exported(diagnostics, categories=("gatewaylogs",)),
    }


def summarize(services: list[dict]) -> dict:
    apis = [a for s in services for a in s["apis"] or []]
    products = [p for s in services for p in s["products"] or []]
    backends = [b for s in services for b in s["backends"] or []]
    named = [n for s in services for n in s["named_values"] or []]
    subs = [x for s in services for x in s["subscriptions"] or []]
    certs = [c["days_to_expiry"] for s in services for c in s["certificates"] or []]
    certs += [h["certificate_days_to_expiry"] for s in services for h in s["hostnames"]]
    certs = [d for d in certs if d is not None]

    def count(items, pred):
        return sum(1 for i in items if pred(i))

    def legacy_on(s):
        return any(p["enabled"] for p in s["legacy_protocols"].values())

    return {
        "total_services": len(services),
        "services_with_public_network_access": count(
            services, lambda s: str(s["public_network_access"] or "enabled").lower() != "disabled"
        ),
        "services_in_virtual_network": count(
            services, lambda s: str(s["virtual_network_type"] or "none").lower() in ("external", "internal")
        ),
        "services_with_private_endpoints": count(services, lambda s: s["private_endpoint_connections"]),
        "services_with_legacy_tls_or_ssl_enabled": count(services, legacy_on),
        "services_with_weak_ciphers_enabled": count(services, lambda s: s["weak_ciphers_enabled"]),
        "services_minimum_api_version_enforced": count(services, lambda s: s["minimum_api_version_enforced"]),
        "services_developer_portal_enabled": count(
            services, lambda s: str(s["developer_portal_status"] or "").lower() == "enabled"
        ),
        "services_developer_portal_sign_up_enabled": count(
            services, lambda s: s["developer_portal_sign_up"] == "enabled"
        ),
        "services_with_diagnostic_settings": count(services, lambda s: s["diagnostic_settings"]),
        "services_audit_logs_exported": count(services, lambda s: s["audit_logs_exported"] is True),
        "services_audit_logs_unknown": count(services, lambda s: s["audit_logs_exported"] is None),
        "total_apis": len(apis),
        "apis_accepting_http": count(apis, lambda a: a["accepts_http"]),
        "apis_without_access_control": count(apis, lambda a: a["access_control"] is False),
        "apis_access_control_unknown": count(apis, lambda a: a["access_control"] is None),
        "total_products": len(products),
        "published_products_without_subscription": count(
            products,
            lambda p: str(p["state"] or "").lower() == "published" and not p["subscription_required"],
        ),
        "total_subscriptions": len(subs),
        "active_all_apis_subscriptions": count(
            subs, lambda x: x["scope_kind"] == "all_apis" and str(x["state"] or "").lower() == "active"
        ),
        "subscriptions_with_tracing_allowed": count(subs, lambda x: x["allow_tracing"] is True),
        "total_backends": len(backends),
        "backends_using_http": count(backends, lambda b: b["uses_http"]),
        "backends_without_certificate_validation": count(
            backends,
            lambda b: b["validate_certificate_chain"] is False or b["validate_certificate_name"] is False,
        ),
        "backends_without_auth": count(backends, lambda b: not b["auth_configured"] and not b["azure_resource_id"]),
        "secret_named_values_not_in_key_vault": count(named, lambda n: n["secret_stored_in_api_management"]),
        "certificates_expired": sum(1 for d in certs if d < 0),
        "certificates_expiring_within_30_days": sum(1 for d in certs if 0 <= d <= EXPIRY_WARNING_DAYS),
    }


def collect(subscription_id, cred, collector: Collector) -> list[dict]:
    def _client():
        from azure.mgmt.apimanagement import ApiManagementClient  # lazy

        return ApiManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("apimanagement.ApiManagementClient (init)", _client)
    if client is None:
        return []
    now = datetime.now(timezone.utc)
    services = collector.guard(
        "apimanagement.api_management_service.list",
        lambda: [project_service(s, now) for s in client.api_management_service.list()],
        default=[],
    )
    monitor = (
        collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
        if services
        else None
    )
    return sorted(
        (collect_service(client, monitor, s, collector, now) for s in services), key=lambda r: r["id"] or ""
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

    services: list = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.ApiManagement")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.ApiManagement is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        services = collect(subscription_id, cred, collector)
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
        results={"services": services, "provider_registration_status": registration},
        summary={**summarize(services), "provider_registration_status": registration},
    )
    filename = f"azure_api_management_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
