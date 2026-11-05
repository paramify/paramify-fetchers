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
  enabled is flagged phishing-resistant, and so is X.509 certificate enabled when its
  default authentication mode is multi-factor. Windows Hello for
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
- `GET /organization/{id}/certificateBasedAuthConfiguration` and, when granted
  PublicKeyInfrastructure.Read.All, the PKI-based trust store
  (`GET /directory/publicKeyInfrastructure/certificateBasedAuthConfigurations` and each
  one's certificateAuthorities): the certificate authorities trusted for
  certificate-based sign-in, each with its expiry (read from the certificate) and
  revocation list.
- With X.509 enabled, `GET /users` ($select authorizationInfo) and each targeted
  group's transitive members: which enabled member accounts the X.509 method targets,
  whether a username binding can match each to a certificate, and which weaker
  methods still apply to them.
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
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
    is_denied,
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
# X.509 is phishing-resistant only as a multi-factor method: see
# `is_phishing_resistant_method()`.
PHISHING_RESISTANT_METHODS = frozenset({METHOD_FIDO2, METHOD_X509})

# Certificate-based authentication's default mode. Only multi-factor satisfies an MFA
# requirement by itself; a single-factor certificate is a password substitute, still
# needing a second factor. Compared case-insensitively.
X509_MULTI_FACTOR = "x509certificatemultifactor"

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

# A method target naming every user, in place of a group id.
ALL_USERS = "all_users"
# Email one-time passcodes sign in guests only, so they are no member's sign-in method.
GUEST_ONLY_METHODS = frozenset({"email"})
# The two places Entra keeps the CAs trusted for certificate sign-in, and how each read went.
STORE_CLASSIC = "certificate_based_auth_configuration"
STORE_PKI = "public_key_infrastructure"
STORE_READ = "read"
STORE_NOT_AUTHORIZED = "not_authorized"
STORE_NOT_AVAILABLE = "not_available"
STORE_FAILED = "failed"
# Optional: without one, its store reads null and names the grant, and the run still succeeds.
CLASSIC_PERMISSION = "Organization.Read.All"
PKI_PERMISSION = "PublicKeyInfrastructure.Read.All"
# The certificate field each certificate user id type names (X509:<SKI>… is a SubjectKeyIdentifier id).
CERTIFICATE_ID_FIELDS = {"pn": "PrincipalName", "rfc822": "RFC822Name", "ski": "SubjectKeyIdentifier",
                         "sha1-pukey": "SHA1PublicKey", "s": "Subject"}
ISSUER_ID_FIELDS = ("IssuerAndSerialNumber", "IssuerAndSubject")
# User properties holding a name: only the certificate shows whether it carries that name.
NAME_PROPERTIES = {"userprincipalname": "user_principal_name",
                   "onpremisesuserprincipalname": "on_premises_user_principal_name"}
MAPPING_ID = "certificate_user_id"
MAPPING_UNVERIFIED = "unverified"
MAPPING_NONE = "none"
# The evidence lists at most this many of the targeted users that fail a check.
MAX_LISTED_USERS = 100
USER_SELECT = ("id", "userPrincipalName", "userType", "accountEnabled", "onPremisesUserPrincipalName",
               "authorizationInfo")


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
            "certificate_user_bindings": sorted(
                (
                    {
                        "x509_certificate_field": graph_attr(b, "x509_certificate_field"),
                        "user_property": graph_attr(b, "user_property"),
                        "priority": graph_attr(b, "priority"),
                        "trust_affinity_level": graph_attr(b, "trust_affinity_level"),
                    }
                    for b in getattr(config, "certificate_user_bindings", None) or []
                ),
                key=lambda b: (b["priority"] is None, b["priority"] or 0),
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


def certificate_details(der) -> dict:
    """The certificate's subject, validity and SHA-1 thumbprint; None throughout when it is missing or unreadable."""
    details = {"subject": None, "not_before": None, "not_after": None, "thumbprint": None}
    if not der:
        return details
    try:
        from cryptography import x509  # lazy
        from cryptography.hazmat.primitives import hashes  # lazy

        data = bytes(der)
        cert = (x509.load_pem_x509_certificate(data) if data.lstrip().startswith(b"-----BEGIN")
                else x509.load_der_x509_certificate(data))
    except Exception as exc:  # noqa: BLE001 — an unreadable certificate leaves its dates unknown
        logger.warning("a trusted certificate authority's certificate could not be read: %s", type(exc).__name__)
        return details
    return {
        "subject": cert.subject.rfc4514_string(),
        "not_before": _utc(cert.not_valid_before_utc),
        "not_after": _utc(cert.not_valid_after_utc),
        "thumbprint": cert.fingerprint(hashes.SHA1()).hex().upper(),
    }


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def project_certificate_authority(authority) -> dict:
    """One trusted `CertificateAuthority`; the certificate itself is kept out, its subject and dates read from it."""
    return {
        "trust_store": STORE_CLASSIC,
        "display_name": None,
        "issuer": graph_attr(authority, "issuer"),
        "issuer_ski": graph_attr(authority, "issuer_ski"),
        "is_root_authority": graph_attr(authority, "is_root_authority"),
        "certificate_revocation_list_url": graph_attr(authority, "certificate_revocation_list_url") or None,
        "delta_certificate_revocation_list_url": graph_attr(authority, "delta_certificate_revocation_list_url") or None,
        **certificate_details(getattr(authority, "certificate", None)),
    }


def project_pki_authority(authority) -> dict:
    """One `CertificateAuthorityDetail` from the PKI-based trust store, in the classic store's shape."""
    kind = str(graph_attr(authority, "certificate_authority_type") or "").lower()
    details = certificate_details(getattr(authority, "certificate", None))
    expires = getattr(authority, "expiration_date_time", None)
    return {
        "trust_store": STORE_PKI,
        "display_name": graph_attr(authority, "display_name"),
        "issuer": graph_attr(authority, "issuer"),
        "issuer_ski": graph_attr(authority, "issuer_subject_key_identifier"),
        "is_root_authority": True if kind == "root" else False if kind == "intermediate" else None,
        "certificate_revocation_list_url": graph_attr(authority, "certificate_revocation_list_url") or None,
        "delta_certificate_revocation_list_url":
            graph_attr(authority, "delta_certificate_revocation_list_url") or None,
        **details,
        # The service's own expiry and thumbprint stand in when the certificate can't be read.
        "not_after": details["not_after"] or (_utc(expires) if isinstance(expires, datetime) else None),
        "thumbprint": details["thumbprint"] or (str(graph_attr(authority, "thumbprint") or "").upper() or None),
    }


def certificate_id_field(value) -> str | None:
    """The certificate field a certificate user id is for; None when its format isn't one Entra documents."""
    text = str(value or "")
    if not text.lower().startswith("x509:<"):
        return None
    tag, _, rest = text[6:].partition(">")
    if tag.lower() == "i":
        rest = rest.upper()
        return ISSUER_ID_FIELDS[0] if "<SR>" in rest else ISSUER_ID_FIELDS[1] if "<S>" in rest else None
    return CERTIFICATE_ID_FIELDS.get(tag.lower())


def project_user(user) -> dict:
    """A user's sign-in identifiers; of its certificate user ids only the count and the types are kept."""
    info = getattr(user, "authorization_info", None)
    ids = getattr(info, "certificate_user_ids", None) or []
    return {
        "id": graph_attr(user, "id"),
        "user_principal_name": graph_attr(user, "user_principal_name"),
        "user_type": graph_attr(user, "user_type"),
        "account_enabled": graph_attr(user, "account_enabled"),
        "on_premises_user_principal_name": graph_attr(user, "on_premises_user_principal_name"),
        "certificate_user_ids_count": len(ids),
        "certificate_user_id_types": sorted({certificate_id_field(i) for i in ids} - {None}),
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


def x509_multi_factor_default(method: dict | None):
    """Whether X.509's default authentication mode is multi-factor; None when unknown.

    None covers both a policy with no X.509 configuration and one whose mode was not
    reported, so `false` always means the tenant chose single-factor.
    """
    mode = ((method or {}).get("settings") or {}).get("default_authentication_mode")
    if not mode:
        return None
    return str(mode).lower() == X509_MULTI_FACTOR


def is_phishing_resistant_method(method: dict) -> bool:
    """FIDO2 always; X.509 only when its default mode is multi-factor.

    A single-factor certificate does not satisfy MFA by itself, so counting it would let
    a tenant read as phishing-resistant on a method that still leans on a second, possibly
    phishable, factor. Authentication binding rules can raise specific certificates to
    multi-factor; they are not evaluated, so a tenant relying on them alone is not
    credited.
    """
    mid = str(method.get("id") or "").lower()
    if mid not in PHISHING_RESISTANT_METHODS:
        return False
    if mid == METHOD_X509:
        return x509_multi_factor_default(method) is True
    return True


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
                "is_phishing_resistant_method": is_phishing_resistant_method(m),
            }
        )
    return records


def authority_record(authority: dict, now: datetime) -> dict:
    """A trusted CA with its type, whether it publishes a revocation list, and whether it has expired."""
    root = authority.get("is_root_authority")
    not_after = authority.get("not_after")
    expires = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if not_after else None
    return {
        **authority,
        "authority_type": None if root is None else "root" if root else "intermediate",
        "has_crl": bool(authority.get("certificate_revocation_list_url")),
        "expired": None if expires is None else expires <= now,
        "days_until_expiry": None if expires is None else (expires - now).days,
    }


def _reaches(targets: list[dict], user_id: str, members: dict) -> bool | None:
    """Whether the targets name the user, directly, as every user or through a group; None when a group is unread."""
    unread = False
    for target in targets:
        tid = str(target.get("id") or "").lower()
        if tid == ALL_USERS or tid == user_id:
            return True
        if str(target.get("target_type") or "").lower() == "user":
            continue
        group = members.get(tid)
        if group is None:
            unread = True
        elif user_id in group:
            return True
    return None if unread else False


def method_applies(method: dict, user_id: str, members: dict) -> bool | None:
    """Whether an enabled method reaches the user and doesn't exclude them; None when that needs an unread group."""
    if not method.get("enabled"):
        return False
    uid = str(user_id or "").lower()
    included = _reaches(method.get("include_targets") or [], uid, members)
    excluded = _reaches(method.get("exclude_targets") or [], uid, members)
    if excluded or included is False:
        return False
    return None if included is None or excluded is None else True


def target_groups(methods: list[dict]) -> set[str]:
    """The group ids the enabled methods include or exclude, lower-cased."""
    return {
        str(t.get("id") or "").lower()
        for m in methods if m.get("enabled")
        for t in (m.get("include_targets") or []) + (m.get("exclude_targets") or [])
        if str(t.get("target_type") or "").lower() != "user" and str(t.get("id") or "").lower() not in ("", ALL_USERS)
    }


def is_weaker_method(method: dict) -> bool:
    """A member sign-in method other than X.509 that isn't phishing-resistant."""
    mid = method["id"].lower()
    return mid != METHOD_X509 and mid not in GUEST_ONLY_METHODS and not method["is_phishing_resistant_method"]


def _binding_matches(binding: dict, user: dict) -> bool | None:
    """Whether the binding can match the user to a certificate; None when only the certificate could tell."""
    prop = str(binding.get("user_property") or "").lower()
    field = str(binding.get("x509_certificate_field") or "").lower()
    if prop == "certificateuserids":
        known = {f.lower() for f in (*CERTIFICATE_ID_FIELDS.values(), *ISSUER_ID_FIELDS)}
        if field not in known:
            return None
        return field in {t.lower() for t in user.get("certificate_user_id_types") or []}
    if prop in NAME_PROPERTIES:
        return None if user.get(NAME_PROPERTIES[prop]) else False
    return None


def _any(values: list) -> bool | None:
    """True if any is True, else None if any is None, else False."""
    return True if True in values else None if None in values else False


def certificate_user_record(user: dict, bindings: list[dict], methods: list[dict], members: dict) -> dict:
    """A user the X.509 method targets: whether a binding matches them to a certificate, and the weaker methods
    that still reach them."""
    matches = {i: _binding_matches(b, user) for i, b in enumerate(bindings)}
    high = [matches[i] for i, b in enumerate(bindings) if str(b.get("trust_affinity_level") or "").lower() == "high"]
    reach = {m["id"]: method_applies(m, user["id"], members) for m in methods if m["enabled"] and is_weaker_method(m)}
    mapped = _any(list(matches.values())) if bindings else None
    return {
        "id": user["id"],
        "user_principal_name": user.get("user_principal_name"),
        "certificate_user_ids_count": user.get("certificate_user_ids_count"),
        "certificate_user_id_types": user.get("certificate_user_id_types") or [],
        # None when the policy reports no bindings: the rules that would match the user are unknown.
        "mapping": None if not bindings else {True: MAPPING_ID, None: MAPPING_UNVERIFIED, False: MAPPING_NONE}[mapped],
        "mapped": mapped,
        "mapped_high_affinity": _any(high) if bindings else None,
        "weaker_methods_enabled": sorted(mid for mid, applies in reach.items() if applies),
        "weaker_methods_unknown": sorted(mid for mid, applies in reach.items() if applies is None),
        "weaker_method_enabled": _any(list(reach.values())),
        "weak_method_enabled": _any([a for mid, a in reach.items() if mid.lower() in WEAK_METHODS]),
    }


def certificate_users(policy: dict | None, methods: list[dict], users: list[dict] | None,
                      members: dict) -> list[dict] | None:
    """Every enabled member account the X.509 method targets; [] when it is off, None when that can't be told."""
    if policy is None:
        return None
    x509 = next((m for m in methods if m["id"].lower() == METHOD_X509), None)
    if not (x509 or {}).get("enabled"):
        return []
    if users is None:
        return None
    bindings = (x509.get("settings") or {}).get("certificate_user_bindings") or []
    records = []
    for user in users:
        if user.get("account_enabled") is False or str(user.get("user_type") or "").lower() == "guest":
            continue
        applies = method_applies(x509, user["id"], members)
        if applies is None:
            return None
        if applies:
            records.append(certificate_user_record(user, bindings, methods, members))
    return sorted(records, key=lambda r: str(r.get("user_principal_name") or r["id"]).lower())


def fails_a_check(user: dict) -> bool:
    """Not matched to a certificate by a certificate user id, without any, or reached (or maybe) by a weaker method."""
    return (user["mapping"] != MAPPING_ID or not user["certificate_user_ids_count"]
            or user["weaker_method_enabled"] is not False)


def listed_users(users: list[dict] | None) -> list[dict] | None:
    """The targeted users that fail a check, the first MAX_LISTED_USERS of them; the counts cover every user."""
    return None if users is None else [u for u in users if fails_a_check(u)][:MAX_LISTED_USERS]


def _count(records: list[dict] | None, test) -> int | None:
    """How many records pass; None when the list is unknown or any record's answer is."""
    if records is None:
        return None
    answers = [test(r) for r in records]
    return None if None in answers else sum(1 for a in answers if a)


def _ski(authority: dict) -> str:
    return "".join(ch for ch in str(authority.get("issuer_ski") or "") if ch.isalnum()).lower()


def distinct_authorities(authorities: list[dict]) -> list[dict]:
    """One record per CA. A CA in both stores (same thumbprint, or the same key identifier when a certificate
    can't be read) is expired or CRL-less if either entry is."""
    groups: list[list[dict]] = []
    for authority in sorted(authorities, key=lambda a: not a.get("thumbprint")):
        thumbprint, ski = authority.get("thumbprint"), _ski(authority)
        same = next((g for g in groups if (thumbprint and any(a.get("thumbprint") == thumbprint for a in g))
                     or (not thumbprint and ski and any(_ski(a) == ski for a in g))), None)
        if same is None:
            groups.append([authority])
        else:
            same.append(authority)
    return [{"expired": _known_any([a["expired"] for a in entries]), "has_crl": all(a["has_crl"] for a in entries)}
            for entries in groups]


def _known_any(values: list) -> bool | None:
    """Readings of one certificate: True if any is True, else False if any is known, else None."""
    return True if True in values else False if False in values else None


def summarize_certificates(authorities: list[dict] | None, users: list[dict] | None,
                           stores: dict | None = None) -> dict:
    """The CA and certificate-mapping counts; the CA counts are null unless every trust store was read, so an
    unread store is never counted as empty."""
    stores = stores or {}
    complete = authorities is not None and all(
        (stores.get(store) or {}).get("status") == STORE_READ for store in (STORE_CLASSIC, STORE_PKI))
    distinct = distinct_authorities(authorities) if complete else None
    classic, pki = stores.get(STORE_CLASSIC) or {}, stores.get(STORE_PKI) or {}
    return {
        "trusted_certificate_authorities": len(distinct) if distinct is not None else None,
        "expired_certificate_authorities": _count(distinct, lambda a: a["expired"] is True),
        "certificate_authorities_expiry_unknown": _count(distinct, lambda a: a["expired"] is None),
        "certificate_authorities_without_crl": _count(distinct, lambda a: not a["has_crl"]),
        "classic_store_certificate_authorities": classic.get("certificate_authorities"),
        "classic_store_status": classic.get("status"),
        "classic_store_missing_permission": classic.get("missing_permission"),
        "pki_store_certificate_authorities": pki.get("certificate_authorities"),
        "pki_store_status": pki.get("status"),
        "pki_store_missing_permission": pki.get("missing_permission"),
        "x509_targeted_users": len(users) if users is not None else None,
        "x509_targeted_users_unmapped": _count(
            users, lambda u: None if u["mapping"] is None else u["mapping"] == MAPPING_NONE),
        "x509_targeted_users_mapping_unverified": _count(
            users, lambda u: None if u["mapping"] is None else u["mapping"] == MAPPING_UNVERIFIED),
        "x509_targeted_users_without_certificate_user_ids": _count(
            users, lambda u: not u["certificate_user_ids_count"]),
        "x509_targeted_users_with_weaker_methods": _count(users, lambda u: u["weaker_method_enabled"]),
        "x509_targeted_users_with_weak_methods": _count(users, lambda u: u["weak_method_enabled"]),
        "x509_certificate_users_truncated": (
            None if users is None else sum(1 for u in users if fails_a_check(u)) > MAX_LISTED_USERS),
    }


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
        # Only a multi-factor default makes an enabled X.509 method count above.
        "x509_certificate_multi_factor": x509_multi_factor_default(by_id.get(METHOD_X509))
        if readable
        else None,
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

        policy = project_methods_policy(policy_model) if policy_model is not None else None
        authorities, stores = await _certificate_authorities(collector, client, tenant.get("tenant_id"))
        users, members = await _certificate_targets(collector, client, method_records(policy))

        return {
            "tenant": tenant,
            "policy": policy,
            "security_defaults_enabled": graph_attr(security_defaults, "is_enabled")
            if security_defaults is not None
            else None,
            "settings": settings,
            "template_defaults": project_template_defaults(template) if template is not None else None,
            "skus": skus,
            "authorities": authorities,
            "certificate_authority_stores": stores,
            "users": users,
            "members": members,
        }

    return await with_graph_client(collector, cred, _work, default=None)


async def _certificate_authorities(collector: Collector, client, tenant_id) -> tuple:
    """(both stores' CAs, None unless both were read; {store: its status, CA count, the grant it lacks, and its own
    CAs, None when unread})."""
    classic, classic_status = await _classic_store(collector, client, tenant_id)
    pki, pki_status = await _pki_store(collector, client)
    stores = {
        store: {"status": status, "certificate_authorities": len(cas) if cas is not None else None,
                "missing_permission": permission if status == STORE_NOT_AUTHORIZED else None, "authorities": cas}
        for store, cas, status, permission in ((STORE_CLASSIC, classic, classic_status, CLASSIC_PERMISSION),
                                               (STORE_PKI, pki, pki_status, PKI_PERMISSION))
    }
    # An unread store is unknown, never empty, so the combined list needs both.
    both = classic_status == STORE_READ and pki_status == STORE_READ
    return (classic + pki if both else None), stores


async def _classic_store(collector: Collector, client, tenant_id) -> tuple:
    """(every CA in the tenant's classic certificate-based authentication configuration, read status); a refused
    read doesn't fail the run."""
    operation = "graph.organization.certificateBasedAuthConfiguration.get"
    if not tenant_id:
        collector.record(operation, RuntimeError("the tenant id is unknown, so its trusted CAs can't be read"))
        return None, STORE_FAILED
    try:
        configs = await paginate(collector, operation, client.organization.by_organization_id(
            tenant_id).certificate_based_auth_configuration, raise_on_error=True)
    except Exception as exc:  # noqa: BLE001 — classified: a refusal is the optional grant missing
        if is_denied(exc):
            logger.warning("the classic trust store was refused (needs %s); its CAs read null", CLASSIC_PERMISSION)
            return None, STORE_NOT_AUTHORIZED
        collector.record(operation, exc)
        return None, STORE_FAILED
    return [project_certificate_authority(a)
            for c in configs for a in getattr(c, "certificate_authorities", None) or []], STORE_READ


async def _pki_store(collector: Collector, client) -> tuple:
    """(the PKI-based trust store's CAs, read status); a refused read, or a cloud without the API, doesn't fail
    the run."""
    operation = "graph.directory.publicKeyInfrastructure.certificateBasedAuthConfigurations"
    authorities: list[dict] = []
    try:
        builder = client.directory.public_key_infrastructure.certificate_based_auth_configurations
        for pki in await paginate(collector, f"{operation}.get", builder, raise_on_error=True):
            pid = str(graph_attr(pki, "id") or "")
            authorities.extend(project_pki_authority(a) for a in await paginate(
                collector, f"{operation}({pid}).certificateAuthorities.get",
                builder.by_certificate_based_auth_pki_id(pid).certificate_authorities, raise_on_error=True))
    except Exception as exc:  # noqa: BLE001 — classified: a refusal is the optional grant missing
        if is_denied(exc):
            logger.warning("the PKI-based trust store was refused (needs %s); its CAs read null", PKI_PERMISSION)
            return None, STORE_NOT_AUTHORIZED
        if getattr(exc, "response_status_code", None) in (400, 404):
            logger.warning("the PKI-based trust store isn't available here; its CAs read null")
            return None, STORE_NOT_AVAILABLE
        collector.record(operation, exc)
        return None, STORE_FAILED
    return authorities, STORE_READ


async def _certificate_targets(collector: Collector, client, methods: list[dict]) -> tuple:
    """(users, {group id: member ids or None}), read only when X.509 is enabled; users is None when its read failed.
    When X.509 targets groups only, its users come from those groups instead of the whole directory."""
    x509 = next((m for m in methods if m["enabled"] and m["id"].lower() == METHOD_X509), None)
    if x509 is None:
        return None, {}
    from kiota_abstractions.base_request_configuration import RequestConfiguration
    from msgraph.generated.groups.item.transitive_members.graph_user.graph_user_request_builder import (
        GraphUserRequestBuilder,
    )
    from msgraph.generated.users.users_request_builder import UsersRequestBuilder

    include = target_groups([{"enabled": True, "include_targets": x509.get("include_targets") or []}])
    groups_only = all(str(t.get("target_type") or "").lower() != "user" and str(t.get("id") or "").lower() != ALL_USERS
                      for t in x509.get("include_targets") or [])
    users = None
    if not groups_only:
        config = RequestConfiguration(query_parameters=UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            select=list(USER_SELECT), top=999))
        before = len(collector.failures)
        users = [project_user(u)
                 for u in await paginate(collector, "graph.users.get(authorizationInfo)", client.users, config)]
        if len(collector.failures) > before:
            users = None
    group_config = RequestConfiguration(
        query_parameters=GraphUserRequestBuilder.GraphUserRequestBuilderGetQueryParameters(
            select=list(USER_SELECT), top=999))
    members: dict[str, set | None] = {}
    found: dict[str, dict] = {}
    for gid in sorted(target_groups(methods)):
        before = len(collector.failures)
        rows = await paginate(collector, f"graph.groups({gid}).transitiveMembers.graphUser.get",
                              client.groups.by_group_id(gid).transitive_members.graph_user, group_config)
        if len(collector.failures) > before:
            members[gid] = None
            continue
        projected = [project_user(r) for r in rows]
        members[gid] = {str(u["id"] or "").lower() for u in projected}
        if gid in include:
            found.update((str(u["id"] or "").lower(), u) for u in projected)
    if groups_only:
        users = None if any(members.get(g) is None for g in include) else list(found.values())
    logger.info("Read %s user(s) and %d targeted group(s) for X.509 sign-in",
                len(users) if users is not None else "no", len(members))
    return users, members


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
    now = datetime.now(timezone.utc)
    def records(raw):
        return None if raw is None else sorted(
            (authority_record(a, now) for a in raw),
            key=lambda a: (a["trust_store"], str(a.get("subject") or a.get("issuer") or ""),
                           str(a.get("issuer_ski") or "")))

    authorities = records(collected.get("authorities"))
    stores = collected.get("certificate_authority_stores")
    for store in (stores or {}).values():
        store["authorities"] = records(store.get("authorities"))
    users = certificate_users(policy, methods, collected.get("users"), collected.get("members") or {})

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
            "authentication_methods": methods if policy is not None else None,
            "security_defaults_enabled": collected.get("security_defaults_enabled"),
            "password_protection": passwords,
            "entra_id_tier": tier,
            "subscribed_skus": collected.get("skus"),
            "trusted_certificate_authorities": authorities,
            "certificate_authority_stores": stores,
            "x509_certificate_users": listed_users(users),
        },
        summary={
            **summarize(policy, methods, collected.get("security_defaults_enabled"), tier, passwords),
            **summarize_certificates(authorities, users, stores),
        },
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
