#!/usr/bin/env python3
"""
Azure SQL server network exposure, authentication and audit posture

Per logical server: public network access and minimum TLS version, the Entra ID
administrator, firewall rules, blob auditing and its retention, the security alert
policy (Defender for SQL), and the vulnerability assessment.

Ported from prowler/providers/azure/services/sqlserver/sqlserver_service.py
(Apache-2.0); the thresholds below (TLS 1.2+, auditing retention > 90 days,
`administrator_type == "ActiveDirectory"`) are its checks' own. The two firewall
exposures are flagged separately, being different findings: 0.0.0.0-0.0.0.0 admits
every Azure tenant's compute, 0.0.0.0-255.255.255.255 every routable address.
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
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_sql_server_configuration")

# ServerExternalAdministrator.administrator_type. "ActiveDirectory" is the only member
# of the SDK's AdministratorType enum, so its presence is what proves an Entra ID admin
# is configured (Prowler's sqlserver_azuread_administrator_enabled).
ADMINISTRATOR_TYPE_ENTRA = "activedirectory"

# minimal_tls_version values that are not deprecated. Azure spells these as bare
# version numbers ("1.2"), unlike Storage's "TLS1_2".
RECOMMENDED_TLS_VERSIONS = ("1.2", "1.3")

# Azure represents both exposures as ordinary rules, distinguishable only by address.
AZURE_SERVICES_RULE = ("0.0.0.0", "0.0.0.0")
ENTIRE_INTERNET_RULE = ("0.0.0.0", "255.255.255.255")

# BlobAuditingPolicyState / SecurityAlertsPolicyState both serialize as
# "Enabled" / "Disabled".
STATE_ENABLED = "enabled"

# CIS / Prowler's sqlserver_auditing_retention_90_days: retention must EXCEED 90 days,
# so exactly 90 fails — the compare below is `>`, not `>=`. Retention 0 means "keep
# forever" in Azure's model and is handled separately, not as "less than 91".
AUDIT_RETENTION_MINIMUM_DAYS = 90
AUDIT_RETENTION_UNLIMITED = 0


# --- projection: azure-mgmt models in, flat dicts out ---

def project_sql_server(server) -> dict:
    """Read a `Server` model's attributes into a flat snake_case dict.

    `administrators` comes back as a TYPED `ServerExternalAdministrator`, not a
    plain dict, so `model_attr` works one level down as well.
    """
    administrators = model_attr(server, "administrators")
    return {
        "id": model_attr(server, "id"),
        "name": model_attr(server, "name"),
        "type": model_attr(server, "type"),
        "location": model_attr(server, "location"),
        "version": model_attr(server, "version"),
        "state": model_attr(server, "state"),
        "fully_qualified_domain_name": model_attr(server, "fully_qualified_domain_name"),
        "public_network_access": model_attr(server, "public_network_access"),
        "minimal_tls_version": model_attr(server, "minimal_tls_version"),
        "restrict_outbound_network_access": model_attr(
            server, "restrict_outbound_network_access"
        ),
        "administrators": {
            "sid": model_attr(administrators, "sid"),
            "login": model_attr(administrators, "login"),
            "administrator_type": model_attr(administrators, "administrator_type"),
            "principal_type": model_attr(administrators, "principal_type"),
            "tenant_id": model_attr(administrators, "tenant_id"),
            "azure_ad_only_authentication": model_attr(
                administrators, "azure_ad_only_authentication"
            ),
        },
    }


def project_firewall_rule(rule) -> dict:
    return {
        "id": model_attr(rule, "id"),
        "name": model_attr(rule, "name"),
        "start_ip_address": model_attr(rule, "start_ip_address"),
        "end_ip_address": model_attr(rule, "end_ip_address"),
    }


def project_auditing_policy(policy) -> dict:
    return {
        "id": model_attr(policy, "id"),
        "name": model_attr(policy, "name"),
        "type": model_attr(policy, "type"),
        "state": model_attr(policy, "state"),
        "retention_days": model_attr(policy, "retention_days"),
        "is_azure_monitor_target_enabled": model_attr(
            policy, "is_azure_monitor_target_enabled"
        ),
    }


def project_security_alert_policy(policy) -> dict:
    """Read a `ServerSecurityAlertPolicy` — Microsoft Defender for SQL."""
    return {
        "id": model_attr(policy, "id"),
        "name": model_attr(policy, "name"),
        "type": model_attr(policy, "type"),
        "state": model_attr(policy, "state"),
        "email_account_admins": model_attr(policy, "email_account_admins"),
        "email_addresses": model_attr(policy, "email_addresses"),
        "retention_days": model_attr(policy, "retention_days"),
    }


def project_vulnerability_assessment(assessment) -> dict:
    """`recurring_scans` is a typed model and often absent, hence the None-tolerant hop."""
    recurring_scans = model_attr(assessment, "recurring_scans")
    return {
        "id": model_attr(assessment, "id"),
        "name": model_attr(assessment, "name"),
        "type": model_attr(assessment, "type"),
        "storage_container_path": model_attr(assessment, "storage_container_path"),
        "recurring_scans": {
            "is_enabled": model_attr(recurring_scans, "is_enabled"),
            "emails": model_attr(recurring_scans, "emails"),
            "email_subscription_admins": model_attr(
                recurring_scans, "email_subscription_admins"
            ),
        },
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def firewall_rule_record(rule: dict) -> dict:
    addresses = (rule.get("start_ip_address"), rule.get("end_ip_address"))
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "start_ip_address": rule.get("start_ip_address"),
        "end_ip_address": rule.get("end_ip_address"),
        "allows_all_azure_services": addresses == AZURE_SERVICES_RULE,
        "allows_entire_internet": addresses == ENTIRE_INTERNET_RULE,
    }


def auditing_policy_record(policy: dict) -> dict:
    """`retention_days: 0` is Azure's "retain indefinitely", not "retain nothing", so it
    satisfies the >90-day rule; reading it as 0 < 91 would report the strongest possible
    retention as the weakest.
    """
    state = policy.get("state")
    retention = policy.get("retention_days")
    enabled = str(state or "").lower() == STATE_ENABLED
    unlimited = retention == AUDIT_RETENTION_UNLIMITED
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "type": policy.get("type"),
        "state": state,
        "enabled": enabled,
        "retention_days": retention,
        "retention_unlimited": unlimited,
        "retention_over_90_days": bool(
            enabled and (unlimited or (retention or 0) > AUDIT_RETENTION_MINIMUM_DAYS)
        ),
        "is_azure_monitor_target_enabled": bool(
            policy.get("is_azure_monitor_target_enabled") or False
        ),
    }


def security_alert_policy_record(policy: dict | None) -> dict | None:
    """Normalize the projected security alert policy — Microsoft Defender for SQL."""
    if not policy:
        return None
    state = policy.get("state")
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "type": policy.get("type"),
        "state": state,
        "enabled": str(state or "").lower() == STATE_ENABLED,
        "email_account_admins": bool(policy.get("email_account_admins") or False),
        "email_addresses": policy.get("email_addresses") or [],
        "retention_days": policy.get("retention_days"),
    }


def vulnerability_assessment_record(assessment: dict | None) -> dict | None:
    """Prowler reads VA as enabled from `storage_container_path` being set: without it
    the scan results have nowhere to go, so nothing is actually being assessed.
    """
    if not assessment:
        return None
    recurring = assessment.get("recurring_scans") or {}
    container_path = assessment.get("storage_container_path")
    return {
        "id": assessment.get("id"),
        "name": assessment.get("name"),
        "type": assessment.get("type"),
        "storage_container_path": container_path,
        "enabled": bool(container_path),
        "recurring_scans": {
            # Coerced: Azure omits these when never enabled, and a validator
            # asserting `false` would not match `null`.
            "is_enabled": bool(recurring.get("is_enabled") or False),
            "emails": recurring.get("emails") or [],
            "email_subscription_admins": bool(
                recurring.get("email_subscription_admins") or False
            ),
        },
    }


def server_record(
    server: dict,
    firewall_rules: list[dict],
    auditing_policies: list[dict],
    security_alert_policy: dict | None,
    vulnerability_assessment: dict | None,
) -> dict:
    resource_id = server.get("id")
    administrators = server.get("administrators") or {}
    administrator_type = administrators.get("administrator_type")
    tls_version = server.get("minimal_tls_version")
    alert_policy = security_alert_policy_record(security_alert_policy)
    assessment = vulnerability_assessment_record(vulnerability_assessment)

    return {
        "id": resource_id,
        "name": server.get("name"),
        "type": server.get("type"),
        "location": server.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "version": server.get("version"),
        "state": server.get("state"),
        "fully_qualified_domain_name": server.get("fully_qualified_domain_name"),
        # --- network exposure ---
        "public_network_access": server.get("public_network_access"),
        "public_network_access_disabled": str(
            server.get("public_network_access") or ""
        ).lower() in ("disabled", "securedbyperimeter"),
        "minimal_tls_version": tls_version,
        "minimal_tls_version_recommended": tls_version in RECOMMENDED_TLS_VERSIONS,
        "restrict_outbound_network_access": server.get("restrict_outbound_network_access"),
        "firewall_rules": firewall_rules,
        "total_firewall_rules": len(firewall_rules),
        "allows_all_azure_services": any(r["allows_all_azure_services"] for r in firewall_rules),
        "allows_entire_internet": any(r["allows_entire_internet"] for r in firewall_rules),
        # --- authentication ---
        "administrators": {
            "sid": administrators.get("sid"),
            "login": administrators.get("login"),
            "administrator_type": administrator_type,
            "principal_type": administrators.get("principal_type"),
            "tenant_id": administrators.get("tenant_id"),
            "azure_ad_only_authentication": bool(
                administrators.get("azure_ad_only_authentication") or False
            ),
        },
        "entra_administrator_configured": (
            str(administrator_type or "").lower() == ADMINISTRATOR_TYPE_ENTRA
        ),
        # --- audit ---
        "auditing_policies": auditing_policies,
        "auditing_enabled": any(p["enabled"] for p in auditing_policies),
        "auditing_retention_over_90_days": any(
            p["retention_over_90_days"] for p in auditing_policies
        ),
        # --- threat detection ---
        "security_alert_policy": alert_policy,
        "defender_for_sql_enabled": bool(alert_policy and alert_policy["enabled"]),
        "vulnerability_assessment": assessment,
        "vulnerability_assessment_enabled": bool(assessment and assessment["enabled"]),
    }


def summarize(servers: list[dict]) -> dict:
    """Auditing is the one setting here that is OFF by default, so it gets the
    percentage; the rest stay absolute counts.
    """
    total = len(servers)
    audited = sum(1 for s in servers if s["auditing_enabled"])
    return {
        "total_sql_servers": total,
        "auditing_enabled_servers": audited,
        "auditing_percentage": coverage_percentage(audited, total),
        "auditing_retention_over_90_days_servers": sum(
            1 for s in servers if s["auditing_retention_over_90_days"]
        ),
        "public_network_access_disabled_servers": sum(
            1 for s in servers if s["public_network_access_disabled"]
        ),
        "recommended_minimal_tls_servers": sum(
            1 for s in servers if s["minimal_tls_version_recommended"]
        ),
        "entra_administrator_servers": sum(
            1 for s in servers if s["entra_administrator_configured"]
        ),
        "entra_only_authentication_servers": sum(
            1 for s in servers if s["administrators"]["azure_ad_only_authentication"]
        ),
        "servers_allowing_all_azure_services": sum(
            1 for s in servers if s["allows_all_azure_services"]
        ),
        "servers_allowing_entire_internet": sum(
            1 for s in servers if s["allows_entire_internet"]
        ),
        "total_firewall_rules": sum(s["total_firewall_rules"] for s in servers),
        "defender_for_sql_enabled_servers": sum(
            1 for s in servers if s["defender_for_sql_enabled"]
        ),
        "vulnerability_assessment_enabled_servers": sum(
            1 for s in servers if s["vulnerability_assessment_enabled"]
        ),
        "vulnerability_assessment_recurring_scan_servers": sum(
            1
            for s in servers
            if (s["vulnerability_assessment"] or {}).get("recurring_scans", {}).get("is_enabled")
        ),
        "vulnerability_assessment_admin_notification_servers": sum(
            1
            for s in servers
            if (s["vulnerability_assessment"] or {})
            .get("recurring_scans", {})
            .get("email_subscription_admins")
        ),
    }


# --- collection (lazy azure imports) ---

# Azure answers "this optional sub-resource was never configured" with a 404, not an
# empty body. A server with no vulnerability assessment or no security alert policy is
# the common case: record the absence, never fail the run or drop the server.
NOT_FOUND_TYPES = ("resourcenotfounderror",)
NOT_FOUND_MARKERS = ("(resourcenotfound)", "(404)", "was not found", "could not be found")


def is_not_found(exc: BaseException) -> bool:
    """Azure's "that optional sub-resource does not exist" answer (also in siblings)."""
    if type(exc).__name__.lower() in NOT_FOUND_TYPES:
        return True
    message = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return any(marker in message for marker in NOT_FOUND_MARKERS)


def _optional_get(collector: Collector, operation: str, fn):
    """Run one GET whose absence is evidence, not a failure. See is_not_found()."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if is_not_found(exc):
            logger.info("%s: not configured (404) — recording as absent", operation)
            return None
        collector.record(operation, exc)
        return None


def collect_sql_servers(subscription_id, cred, collector: Collector) -> list[dict]:
    """One servers.list(), then four sub-resource calls per server — each guarded
    separately so one inaccessible server does not blank out the rest.
    """

    def _client():
        from azure.mgmt.sql import SqlManagementClient  # lazy

        return SqlManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    # Guarded: a missing azure-mgmt-sql becomes internal_error, evidence still written.
    client = collector.guard("sql.SqlManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [project_sql_server(s) for s in client.servers.list()]

    projected_servers = collector.guard("sql.servers.list", _list, default=[])

    servers: list[dict] = []
    for server in projected_servers:
        group, name = resource_group_from_id(server.get("id")), server.get("name")
        if not group or not name:
            collector.record(
                "sql.firewall_rules.list_by_server",
                RuntimeError(f"SQL server {name!r} has no resource group in its id"),
            )
            continue

        rules = collector.guard(
            f"sql.firewall_rules.list_by_server ({name})",
            lambda: [
                firewall_rule_record(project_firewall_rule(r))
                for r in client.firewall_rules.list_by_server(group, name)
            ],
            default=[],
        )
        policies = collector.guard(
            f"sql.server_blob_auditing_policies.list_by_server ({name})",
            lambda: [
                auditing_policy_record(project_auditing_policy(p))
                for p in client.server_blob_auditing_policies.list_by_server(group, name)
            ],
            default=[],
        )
        alert_policy = _optional_get(
            collector,
            f"sql.server_security_alert_policies.get ({name})",
            # "Default" is SecurityAlertPolicyName.DEFAULT's spelling on
            # azure-mgmt-sql 4.0.0 (Prowler passes lowercase "default"; the ARM path
            # segment is case-insensitive either way).
            lambda: project_security_alert_policy(
                client.server_security_alert_policies.get(group, name, "Default")
            ),
        )
        assessment = _optional_get(
            collector,
            f"sql.server_vulnerability_assessments.get ({name})",
            lambda: project_vulnerability_assessment(
                client.server_vulnerability_assessments.get(group, name, "default")
            ),
        )

        servers.append(
            server_record(
                server,
                sorted(rules, key=lambda r: r.get("name") or ""),
                sorted(policies, key=lambda p: p.get("name") or ""),
                alert_policy,
                assessment,
            )
        )

    return sorted(servers, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request/response header at INFO — far too noisy here.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    servers: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked first: an unregistered provider returns an empty list, not an error.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Sql"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Sql is not registered on subscription %s — no Azure SQL "
                "in use; reporting status not_registered",
                subscription_id,
            )
        servers = collect_sql_servers(subscription_id, cred, collector)
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
            "sql_servers": servers,
            "provider_registration_status": registration,
        },
        summary={**summarize(servers), "provider_registration_status": registration},
    )

    filename = (
        f"azure_sql_server_configuration_"
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
