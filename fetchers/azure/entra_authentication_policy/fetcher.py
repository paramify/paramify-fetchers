#!/usr/bin/env python3
"""
Microsoft Entra ID authentication policy: which sign-in methods the tenant allows

azure_entra_mfa_status says which methods users have REGISTERED. This fetcher says
which methods the tenant ALLOWS, which is the other half of a phishing-resistance
claim: a tenant where every user has a FIDO2 key still accepts SMS if the SMS method
is enabled. Four tenant-level reads:

- `GET /policies/authenticationMethodsPolicy`, every method configuration with its
  state, who it targets, and its method-specific settings, plus the registration
  campaign and the policy's migration state. SMS and Voice enabled are flagged weak.
  FIDO2 (which also carries passkeys, including passkeys in Microsoft Authenticator)
  and X.509 certificate enabled are flagged phishing-resistant. Windows Hello for
  Business is NOT in this policy (it is configured through device management), so it
  cannot be evidenced from here.
- `GET /policies/identitySecurityDefaultsEnforcementPolicy`: security defaults, the
  tenant-wide MFA enforcement a tenant without Conditional Access relies on.
- `GET /groupSettings` + `GET /groupSettingTemplates/{Password Rule Settings}`: Entra
  password protection (custom banned-password list, smart lockout). A tenant that has
  never changed these has no settings object at all, so the template's defaults are
  what applies, and are reported as such.
- `GET /subscribedSkus`: whether the tenant holds Entra ID P1/P2. Enforcing a CUSTOM
  banned-password list needs P1. On a Free tenant the directory setting can still
  read as enabled while the custom list is not enforced, so the list is reported as
  enforced only when it is both configured and licensed.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    write_evidence,
    report_failure,
)
from entra_graph import (  # noqa: E402
    aguard,
    graph_attr,
    graph_list,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

logger = logging.getLogger("azure_entra_authentication_policy")

STATE_ENABLED = "enabled"

# Method configuration ids, as Graph spells them in authenticationMethodConfigurations.
# Compared case-insensitively.
METHOD_SMS = "sms"
METHOD_VOICE = "voice"
METHOD_FIDO2 = "fido2"
METHOD_X509 = "x509certificate"

# One-time codes sent over the phone network: interceptable (SIM swap, SS7) and
# phishable. NIST SP 800-63B restricts both.
WEAK_METHODS = frozenset({METHOD_SMS, METHOD_VOICE})
# Bound to the origin, so a look-alike site cannot relay them. FIDO2 includes passkeys.
PHISHING_RESISTANT_METHODS = frozenset({METHOD_FIDO2, METHOD_X509})

# Until the policy's migration is complete, the legacy per-user MFA and SSPR policies
# still decide which methods work alongside this one, so an SMS method disabled HERE may
# still be usable.
MIGRATION_COMPLETE = "migrationComplete"

# The directory setting template for Entra password protection. A fixed, documented
# id, the same in every tenant.
PASSWORD_RULE_TEMPLATE_ID = "5cf42378-d67d-4f36-ba46-e8b86229381d"

# Service plans that make a tenant Entra ID P1 or P2 (P2 includes P1). Matched on
# `servicePlanName`, which is stable across the SKUs that bundle them (M365 E3/E5, EMS...).
PREMIUM_P1_PLAN = "AAD_PREMIUM"
PREMIUM_P2_PLAN = "AAD_PREMIUM_P2"
TIER_FREE = "free"
TIER_P1 = "p1"
TIER_P2 = "p2"


# --- projections: the only code here that touches a Graph model ---

def _targets(model, name: str) -> list[dict]:
    """include/exclude targets: who a method applies to (a group id, or "all_users")."""
    return sorted(
        (
            {
                "id": graph_attr(t, "id"),
                "target_type": graph_attr(t, "target_type"),
                # Only on include targets; None on an exclude target.
                "is_registration_required": graph_attr(t, "is_registration_required"),
            }
            for t in (getattr(model, name, None) or [])
        ),
        key=lambda t: (str(t["target_type"] or ""), str(t["id"] or "")),
    )


def _feature_state(model, name: str):
    """A Microsoft Authenticator feature setting's state (enabled/disabled/default)."""
    return graph_attr(getattr(model, name, None), "state")


def project_method_settings(method_id: str, config) -> dict:
    """The method-specific settings that change what a method proves.

    Read by name off whichever subclass kiota deserialized. A method this version of
    the SDK does not model comes back as the base class, with no settings, and still
    reports its id and state.
    """
    mid = method_id.lower()
    if mid == METHOD_FIDO2:
        restrictions = getattr(config, "key_restrictions", None)
        return {
            "is_attestation_enforced": graph_attr(config, "is_attestation_enforced"),
            "is_self_service_registration_allowed": graph_attr(
                config, "is_self_service_registration_allowed"
            ),
            "key_restrictions_enforced": graph_attr(restrictions, "is_enforced"),
            "key_restrictions_enforcement_type": graph_attr(restrictions, "enforcement_type"),
            "key_restrictions_aaguid_count": len(graph_list(restrictions, "aa_guids")),
        }
    if mid == METHOD_X509:
        mode = getattr(config, "authentication_mode_configuration", None)
        return {
            # x509CertificateSingleFactor vs x509CertificateMultiFactor: only the latter
            # satisfies an MFA requirement by itself.
            "default_authentication_mode": graph_attr(
                mode, "x509_certificate_authentication_default_mode"
            ),
            "certificate_user_binding_count": len(
                getattr(config, "certificate_user_bindings", None) or []
            ),
        }
    if mid == "microsoftauthenticator":
        features = getattr(config, "feature_settings", None)
        return {
            "is_software_oath_enabled": graph_attr(config, "is_software_oath_enabled"),
            "display_app_information_required_state": _feature_state(
                features, "display_app_information_required_state"
            ),
            "display_location_information_required_state": _feature_state(
                features, "display_location_information_required_state"
            ),
        }
    if mid == METHOD_VOICE:
        return {"is_office_phone_allowed": graph_attr(config, "is_office_phone_allowed")}
    if mid == "temporaryaccesspass":
        return {
            "is_usable_once": graph_attr(config, "is_usable_once"),
            "default_lifetime_in_minutes": graph_attr(config, "default_lifetime_in_minutes"),
            "maximum_lifetime_in_minutes": graph_attr(config, "maximum_lifetime_in_minutes"),
        }
    if mid == "email":
        return {
            "allow_external_id_to_use_email_otp": graph_attr(
                config, "allow_external_id_to_use_email_otp"
            )
        }
    return {}


def project_method_configuration(config) -> dict:
    method_id = str(graph_attr(config, "id") or "")
    return {
        "id": method_id,
        "odata_type": graph_attr(config, "odata_type"),
        "state": graph_attr(config, "state"),
        "include_targets": _targets(config, "include_targets"),
        "exclude_targets": _targets(config, "exclude_targets"),
        "settings": project_method_settings(method_id, config),
    }


def project_registration_campaign(policy) -> dict | None:
    """The "nudge users to register" campaign, if the policy carries one."""
    enforcement = getattr(policy, "registration_enforcement", None)
    campaign = getattr(enforcement, "authentication_methods_registration_campaign", None)
    if campaign is None:
        return None
    return {
        "state": graph_attr(campaign, "state"),
        "snooze_duration_in_days": graph_attr(campaign, "snooze_duration_in_days"),
        "include_targets": sorted(
            (
                {
                    "id": graph_attr(t, "id"),
                    "target_type": graph_attr(t, "target_type"),
                    "targeted_authentication_method": graph_attr(
                        t, "targeted_authentication_method"
                    ),
                }
                for t in (getattr(campaign, "include_targets", None) or [])
            ),
            key=lambda t: (str(t["id"] or ""), str(t["targeted_authentication_method"] or "")),
        ),
        "exclude_targets": _targets(campaign, "exclude_targets"),
    }


def project_methods_policy(policy) -> dict:
    return {
        "id": graph_attr(policy, "id"),
        "display_name": graph_attr(policy, "display_name"),
        "last_modified_date_time": graph_attr(policy, "last_modified_date_time"),
        "policy_version": graph_attr(policy, "policy_version"),
        "policy_migration_state": graph_attr(policy, "policy_migration_state"),
        "reconfirmation_in_days": graph_attr(policy, "reconfirmation_in_days"),
        "registration_campaign": project_registration_campaign(policy),
        "method_configurations": sorted(
            (
                project_method_configuration(c)
                for c in (getattr(policy, "authentication_method_configurations", None) or [])
            ),
            key=lambda m: m["id"].lower(),
        ),
    }


def project_setting(setting) -> dict:
    """A `GroupSetting` (a tenant directory setting object) as template id + values."""
    return {
        "id": graph_attr(setting, "id"),
        "display_name": graph_attr(setting, "display_name"),
        "template_id": graph_attr(setting, "template_id"),
        "values": {
            graph_attr(v, "name"): graph_attr(v, "value")
            for v in (getattr(setting, "values", None) or [])
        },
    }


def project_template_defaults(template) -> dict:
    return {
        graph_attr(v, "name"): graph_attr(v, "default_value")
        for v in (getattr(template, "values", None) or [])
    }


def project_sku(sku) -> dict:
    return {
        "sku_part_number": graph_attr(sku, "sku_part_number"),
        "capability_status": graph_attr(sku, "capability_status"),
        "service_plans": sorted(
            {
                graph_attr(p, "service_plan_name")
                for p in (getattr(sku, "service_plans", None) or [])
                if graph_attr(p, "provisioning_status") != "Disabled"
            }
            - {None}
        ),
    }


# --- pure transforms ---

def _as_bool(value):
    """Directory settings carry every value as a string ("true"/"false")."""
    if isinstance(value, bool) or value is None:
        return value
    text = str(value).strip().lower()
    if text in ("true", "false"):
        return text == "true"
    return None


def _as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def entra_tier(skus: list[dict] | None) -> str | None:
    """free / p1 / p2 from the tenant's enabled SKUs; None when the read failed.

    Only SKUs whose capabilityStatus is Enabled count: a lapsed (Warning/Suspended)
    subscription stops granting its features.
    """
    if skus is None:
        return None
    plans = {
        p
        for s in skus
        if str(s.get("capability_status") or "").lower() == "enabled"
        for p in s.get("service_plans") or []
    }
    if PREMIUM_P2_PLAN in plans:
        return TIER_P2
    if PREMIUM_P1_PLAN in plans:
        return TIER_P1
    return TIER_FREE


def password_protection(
    settings: list[dict] | None, template_defaults: dict | None, tier: str | None
) -> dict:
    """Effective Entra password protection settings, and where each came from.

    With no Password Rule Settings object, the template defaults are what the tenant
    runs on, so that is not a gap in collection. `settings_source` says which was read.
    A custom banned-password list is reported as enforced only when it is switched on,
    non-empty, AND the tenant is licensed for it (P1). Otherwise a Free tenant would
    read as protected by a list it cannot enforce.
    """
    configured = next(
        (s for s in settings or [] if str(s.get("template_id") or "").lower() == PASSWORD_RULE_TEMPLATE_ID),
        None,
    )
    if configured is None and template_defaults is None:
        source = None
    else:
        source = "directory_setting" if configured is not None else "template_defaults"
    values = dict(template_defaults or {})
    values.update((configured or {}).get("values") or {})

    banned_list = str(values.get("BannedPasswordList") or "")
    custom_count = len([w for w in banned_list.split("\t") if w.strip()])
    check_enabled = _as_bool(values.get("EnableBannedPasswordCheck"))
    licensed = None if tier is None else tier in (TIER_P1, TIER_P2)
    enforced = None
    if check_enabled is not None and licensed is not None:
        enforced = bool(check_enabled and custom_count and licensed)
    return {
        "settings_source": source,
        "directory_setting_id": (configured or {}).get("id"),
        "custom_banned_password_check_enabled": check_enabled,
        # The count only: the list itself is policy content, and its size is what an
        # assessor needs.
        "custom_banned_password_count": custom_count if source else None,
        "custom_banned_password_list_licensed": licensed,
        "custom_banned_password_list_enforced": enforced,
        "lockout_threshold": _as_int(values.get("LockoutThreshold")),
        "lockout_duration_in_seconds": _as_int(values.get("LockoutDurationInSeconds")),
        "on_premises_banned_password_check_enabled": _as_bool(
            values.get("EnableBannedPasswordCheckOnPremises")
        ),
        "on_premises_banned_password_check_mode": values.get("BannedPasswordCheckOnPremisesMode"),
    }


def method_records(policy: dict | None) -> list[dict]:
    """Each method configuration, with the weak / phishing-resistant classification."""
    records = []
    for m in (policy or {}).get("method_configurations") or []:
        mid = m["id"].lower()
        records.append(
            {
                **m,
                "enabled": str(m.get("state") or "").lower() == STATE_ENABLED,
                "is_weak_method": mid in WEAK_METHODS,
                "is_phishing_resistant_method": mid in PHISHING_RESISTANT_METHODS,
            }
        )
    return records


def summarize(
    policy: dict | None,
    methods: list[dict],
    security_defaults_enabled,
    tier: str | None,
    passwords: dict,
) -> dict:
    """The headline facts a validator asserts on.

    When the methods policy could not be read every method field is None, not False:
    `"sms_enabled": false` must mean SMS is off, never "we could not look".
    """
    readable = policy is not None
    enabled = sorted(m["id"] for m in methods if m["enabled"])
    by_id = {m["id"].lower(): m for m in methods}

    def method_enabled(mid: str):
        if not readable:
            return None
        return bool(by_id.get(mid, {}).get("enabled", False))

    weak = sorted(m["id"] for m in methods if m["enabled"] and m["is_weak_method"])
    strong = sorted(m["id"] for m in methods if m["enabled"] and m["is_phishing_resistant_method"])
    migration = (policy or {}).get("policy_migration_state")
    campaign = (policy or {}).get("registration_campaign") or {}
    return {
        "authentication_methods_policy_readable": readable,
        "total_methods": len(methods) if readable else None,
        "enabled_methods": enabled if readable else None,
        "enabled_method_count": len(enabled) if readable else None,
        # --- weak ---
        "sms_enabled": method_enabled(METHOD_SMS),
        "voice_enabled": method_enabled(METHOD_VOICE),
        "weak_methods_enabled": weak if readable else None,
        "weak_method_enabled": bool(weak) if readable else None,
        # --- phishing-resistant ---
        "fido2_enabled": method_enabled(METHOD_FIDO2),
        "x509_certificate_enabled": method_enabled(METHOD_X509),
        "phishing_resistant_methods_enabled": strong if readable else None,
        "phishing_resistant_method_enabled": bool(strong) if readable else None,
        # --- policy state ---
        "policy_migration_state": migration,
        # True means the legacy MFA/SSPR policies can still allow a method this policy
        # disables.
        "legacy_method_policies_apply": (migration != MIGRATION_COMPLETE) if migration else None,
        "registration_campaign_state": campaign.get("state"),
        "security_defaults_enabled": security_defaults_enabled,
        "entra_id_tier": tier,
        # --- password protection ---
        "password_settings_source": passwords["settings_source"],
        "custom_banned_password_check_enabled": passwords["custom_banned_password_check_enabled"],
        "custom_banned_password_count": passwords["custom_banned_password_count"],
        "custom_banned_password_list_enforced": passwords["custom_banned_password_list_enforced"],
        "lockout_threshold": passwords["lockout_threshold"],
        "lockout_duration_in_seconds": passwords["lockout_duration_in_seconds"],
    }


# --- collection (lazy msgraph imports) ---

async def _collect(collector: Collector, cred):
    """Each read guarded on its own, so one denied endpoint does not erase the rest."""

    async def _work(client):
        tenant = await resolve_tenant(collector, client)

        policy_model = await aguard(
            collector,
            "graph.policies.authenticationMethodsPolicy.get",
            lambda: client.policies.authentication_methods_policy.get(),
        )
        security_defaults = await aguard(
            collector,
            "graph.policies.identitySecurityDefaultsEnforcementPolicy.get",
            lambda: client.policies.identity_security_defaults_enforcement_policy.get(),
        )

        # A settings read that FAILS is not a settings object that is ABSENT: None vs [].
        before = len(collector.failures)
        settings = [
            project_setting(s)
            for s in await paginate(collector, "graph.groupSettings.get", client.group_settings)
        ]
        if len(collector.failures) > before:
            settings = None
        template = await aguard(
            collector,
            f"graph.groupSettingTemplates.get({PASSWORD_RULE_TEMPLATE_ID})",
            lambda: client.group_setting_templates.by_group_setting_template_id(
                PASSWORD_RULE_TEMPLATE_ID
            ).get(),
        )

        before = len(collector.failures)
        skus = [
            project_sku(s)
            for s in await paginate(collector, "graph.subscribedSkus.get", client.subscribed_skus)
        ]
        if len(collector.failures) > before:
            skus = None

        return {
            "tenant": tenant,
            "policy": project_methods_policy(policy_model) if policy_model is not None else None,
            "security_defaults_enabled": graph_attr(security_defaults, "is_enabled")
            if security_defaults is not None
            else None,
            "settings": settings,
            "template_defaults": project_template_defaults(template) if template is not None else None,
            "skus": skus,
        }

    return await with_graph_client(collector, cred, _work, default=None)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-*, msgraph, kiota and httpx stacks log every request at INFO, which
    # would dominate the runner's stderr tail. Warnings and errors still come through.
    for noisy in ("azure", "msgraph", "kiota", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    collected = asyncio.run(_collect(collector, cred)) if cred is not None else None
    collected = collected or {"tenant": {"tenant_source": "unresolved"}}

    policy = collected.get("policy")
    tier = entra_tier(collected.get("skus"))
    methods = method_records(policy)
    passwords = password_protection(
        collected.get("settings"), collected.get("template_defaults"), tier
    )
    tenant = collected["tenant"]

    # No `provider_registration_status()` call, deliberately: Graph is not an ARM
    # resource provider. Every tenant has an authentication methods policy on every
    # licence tier, so a missing one is a failed read, recorded above, never "not in use".
    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results={
            "authentication_methods_policy": (
                {k: v for k, v in policy.items() if k != "method_configurations"}
                if policy is not None
                else None
            ),
            "authentication_methods": methods,
            "security_defaults_enabled": collected.get("security_defaults_enabled"),
            "password_protection": passwords,
            "entra_id_tier": tier,
            "subscribed_skus": collected.get("skus"),
        },
        summary=summarize(
            policy, methods, collected.get("security_defaults_enabled"), tier, passwords
        ),
    )

    filename = f"azure_entra_authentication_policy_{tenant_filename_key(tenant)}.json"
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
