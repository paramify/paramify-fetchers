#!/usr/bin/env python3
"""
OCI IAM — every user, their MFA, their admin membership, and every standing credential

Every IAM user in the tenancy with MFA status, console capability, last login
and group membership, plus every long-lived credential they hold — API signing
keys, auth tokens, customer secret keys, SMTP credentials, database credentials
and OAuth2 client credentials — with each credential's age.

Evidence for KSI-IAM-APM (strong passwords with phishing-resistant MFA),
KSI-IAM-SNU (non-user authentication is appropriately secured and reviewed —
every credential here authenticates without a human at a login page) and
KSI-IAM-ELP (who holds tenancy administration).

Ported from Prowler's OCI identity service (Apache-2.0,
prowler/providers/oraclecloud/services/identity, commit c0fdd5b) — the
`identity_user_mfa_enabled_console_access`, `identity_user_*_rotated_90_days`
and `identity_tenancy_admin_users_no_api_keys` checks — with three departures,
each verified against a live identity-domain tenancy:

  * TENANCY ADMINS ARE MATCHED BY EXACT GROUP NAME. Prowler tests
    `"Administrators" in group.name`, so a group called NetworkAdministrators
    makes its members tenancy admins and their API keys a critical finding. The
    tenancy admin group is literally `Administrators`.

  * SMTP AND OAUTH2 CLIENT CREDENTIALS ARE COLLECTED. Prowler lists four
    credential types and omits these two; both are standing credentials that
    authenticate as the user.

  * A CONSOLE CAPABILITY IS NOT A PASSWORD. `can_use_console_password` is true
    for every user by default, including one that was created and never
    activated. `last_successful_login_time` is reported beside it, so a
    never-used account without MFA is distinguishable from a live one.

`is_mfa_activated` on the legacy IAM user was checked against the identity
domain's own MFA record for the same users (`mfa_status: ENROLLED` for the
enrolled user, none for the other) and agrees, so the legacy API is used for the
Default domain.

EVERY OTHER IDENTITY DOMAIN IS READ THROUGH ITS OWN SCIM API. The legacy IAM
API answers for the Default domain only: with a second domain staged, its user
was absent from the evidence and the run exited 0, so a user without MFA there
was invisible. Secondary domains are found by walking compartments (a domain
can live in any of them), and each one's users and six credential types are
read from the domain's endpoint and translated into the legacy shape, so one
set of judgements covers both. Every record says which domain it came from.
A secondary domain's Domain_Administrators group administers that domain, not
the tenancy, so it is reported as `is_domain_admin`, never as tenancy admin.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    age_in_days,
    build_payload,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    sanitize_for_filename,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_iam_users_credentials")

TENANCY_ADMIN_GROUP = "Administrators"

# CIS OCI Foundations 1.8-1.12, and Prowler's `maximum_expiration_days`.
ROTATION_DAYS = 90

# credential type -> IdentityClient list call
CREDENTIAL_CALLS = {
    "api_keys": "list_api_keys",
    "auth_tokens": "list_auth_tokens",
    "customer_secret_keys": "list_customer_secret_keys",
    "smtp_credentials": "list_smtp_credentials",
    "db_credentials": "list_db_credentials",
    "oauth2_client_credentials": "list_o_auth_client_credentials",
}

INACTIVE_STATES = frozenset({"DELETED", "DELETING", "INACTIVE"})

# The Default domain is read through the legacy IAM API above; every other
# active domain through SCIM.
DEFAULT_DOMAIN_TYPE = "DEFAULT"
DOMAIN_ADMIN_GROUP = "Domain_Administrators"
SCIM_PAGE = 50

# Every attribute scim_user reads, requested by name. `attributes` REPLACES the
# default set rather than adding to it: asking for `groups` alongside
# attribute_sets=all returned users without `active` or capabilities, and a
# no-MFA user read as inactive and dropped out of the finding.
SCIM_USER_ATTRIBUTES = ",".join((
    "userName", "active", "groups", "meta",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:mfa:User:mfaStatus",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User:lastSuccessfulLoginDate",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User:canUseConsolePassword",
    "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User:canUseApiKeys",
))

# credential type -> IdentityDomainsClient list call, filtered by user.
SCIM_CREDENTIAL_CALLS = {
    "api_keys": "list_api_keys",
    "auth_tokens": "list_auth_tokens",
    "customer_secret_keys": "list_customer_secret_keys",
    "smtp_credentials": "list_smtp_credentials",
    "db_credentials": "list_user_db_credentials",
    "oauth2_client_credentials": "list_o_auth2_client_credentials",
}

# SCIM extension blocks, as the SDK's to_dict names them.
EXT_MFA = "urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user"
EXT_STATE = "urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user"
EXT_CAPABILITIES = "urn_ietf_params_scim_schemas_oracle_idcs_extension_capabilities_user"


# --- pure transforms ---

def credential_record(credential: dict, *, now=None) -> dict:
    """One credential of any type, reduced to what rotation evidence needs.

    The six credential models share `lifecycle_state` and `time_created`; they
    disagree on the id (`key_id` for API keys) and expiry (`expires_on` for
    OAuth2). Secret material is never read: API keys carry `key_value` and
    tokens carry `token`, and neither is copied.
    """
    created = credential.get("time_created")
    age = age_in_days(created, now=now)
    return {
        "id": credential.get("id") or credential.get("key_id"),
        "fingerprint": credential.get("fingerprint"),
        "lifecycle_state": credential.get("lifecycle_state"),
        "time_created": iso(created),
        "time_expires": iso(credential.get("time_expires") or credential.get("expires_on")),
        "age_days": age,
        "older_than_rotation_window": age is not None and age > ROTATION_DAYS,
    }


def scim_credential(credential: dict) -> dict:
    """A SCIM credential in the legacy model's field names, for credential_record.

    SCIM spells state `status` and keeps creation under `meta.created`. API keys
    carry no status at all — an API key that exists is active — so None there
    reads as active, which is right.
    """
    meta = credential.get("meta") or {}
    return {
        "id": credential.get("ocid") or credential.get("id"),
        "fingerprint": credential.get("fingerprint"),
        "lifecycle_state": str(credential.get("status") or "").upper() or None,
        "time_created": meta.get("created"),
        "expires_on": credential.get("expires_on"),
    }


def scim_user(user: dict) -> dict:
    """A SCIM user in the legacy model's field names, for user_record.

    MFA is the domain's own record (the same source the legacy flag was checked
    against); an absent MFA block means not enrolled.
    """
    meta = user.get("meta") or {}
    mfa = user.get(EXT_MFA) or {}
    state = user.get(EXT_STATE) or {}
    capabilities = user.get(EXT_CAPABILITIES) or {}
    return {
        "id": user.get("ocid") or user.get("id"),
        "name": user.get("user_name"),
        # Absent `active` is UNKNOWN, never INACTIVE: an inactive user is left
        # out of every finding, so a missing field must not put them there.
        # UNKNOWN is judged as if active (see summarize).
        "lifecycle_state": (
            "ACTIVE" if user.get("active") is True
            else "INACTIVE" if user.get("active") is False
            else "UNKNOWN"
        ),
        "time_created": meta.get("created"),
        "last_successful_login_time": state.get("last_successful_login_date"),
        "is_mfa_activated": str(mfa.get("mfa_status") or "").upper() == "ENROLLED",
        "capabilities": {
            "can_use_console_password": capabilities.get("can_use_console_password"),
            "can_use_api_keys": capabilities.get("can_use_api_keys"),
        },
    }


def user_record(user: dict, *, group_names=(), credentials=None, now=None,
                domain: str = "Default", domain_admin_group: str | None = None) -> dict:
    """Normalize one user, joined to group names and credentials by type.

    `credentials` maps type -> list of credential records, or type -> None when
    that list call failed; a failed read is kept distinct from "none held".
    """
    capabilities = user.get("capabilities") or {}
    credentials = credentials or {}
    active = {
        kind: [c for c in (records or []) if c["lifecycle_state"] not in INACTIVE_STATES]
        for kind, records in credentials.items()
    }
    last_login = user.get("last_successful_login_time")
    return {
        "id": user.get("id"),
        "name": user.get("name"),
        "identity_domain": domain,
        "lifecycle_state": user.get("lifecycle_state"),
        "email_verified": user.get("email_verified"),
        "identity_provider_id": user.get("identity_provider_id"),
        "time_created": iso(user.get("time_created")),
        "last_successful_login_time": iso(last_login),
        "has_ever_logged_in": last_login is not None,
        "days_since_last_login": age_in_days(last_login, now=now),
        "is_mfa_activated": user.get("is_mfa_activated") is True,
        # Absent reads as capable, which is Oracle's default: read as False, a
        # missing capabilities block dropped the user out of the MFA finding.
        "can_use_console_password": capabilities.get("can_use_console_password") is not False,
        "can_use_api_keys": capabilities.get("can_use_api_keys") is True,
        "groups": sorted(group_names),
        # Only the Default domain's Administrators group is tenancy admin.
        "is_tenancy_admin": domain_admin_group is None and TENANCY_ADMIN_GROUP in group_names,
        "is_domain_admin": domain_admin_group is not None and domain_admin_group in group_names,
        "credentials": {kind: records for kind, records in sorted(credentials.items())},
        "unreadable_credential_types": sorted(k for k, v in credentials.items() if v is None),
        "active_credential_count": sum(len(v) for v in active.values()),
        "active_credentials_older_than_rotation_window": sum(
            1 for v in active.values() for c in v if c["older_than_rotation_window"]
        ),
    }


def summarize(users: list[dict]) -> dict:
    # A user whose state could not be read is judged as live: excluded, an
    # administrator without MFA vanished from both findings.
    live = [u for u in users if u["lifecycle_state"] in ("ACTIVE", "UNKNOWN")]
    console = [u for u in live if u["can_use_console_password"]]
    no_mfa = [u for u in console if not u["is_mfa_activated"]]
    admins = [u for u in live if u["is_tenancy_admin"]]

    def active_of(user, kind):
        return [c for c in (user["credentials"].get(kind) or []) if c["lifecycle_state"] not in INACTIVE_STATES]

    by_type = {
        kind: {
            "active": sum(len(active_of(u, kind)) for u in live),
            "older_than_90_days": sum(
                1 for u in live for c in active_of(u, kind) if c["older_than_rotation_window"]
            ),
        }
        for kind in CREDENTIAL_CALLS
    }
    return {
        "total_users": len(users),
        "active_users": sum(1 for u in live if u["lifecycle_state"] == "ACTIVE"),
        "console_capable_users": len(console),
        "console_capable_users_without_mfa": len(no_mfa),
        # The same finding with the never-activated accounts separated out.
        "console_users_without_mfa_who_have_logged_in": sum(1 for u in no_mfa if u["has_ever_logged_in"]),
        "mfa_percentage_of_console_users": (
            (len(console) - len(no_mfa)) * 100 // len(console) if console else 0
        ),
        "users_without_mfa": sorted(u["name"] for u in no_mfa if u["name"]),
        "tenancy_admins": len(admins),
        "tenancy_admin_names": sorted(u["name"] for u in admins if u["name"]),
        "tenancy_admins_with_api_keys": sum(1 for u in admins if active_of(u, "api_keys")),
        "identity_domains_collected": sorted({u["identity_domain"] for u in users}),
        "users_by_identity_domain": {
            d: sum(1 for u in users if u["identity_domain"] == d)
            for d in sorted({u["identity_domain"] for u in users})
        },
        "secondary_domain_admins": sorted(
            f"{u['identity_domain']}/{u['name']}" for u in live if u["is_domain_admin"] and u["name"]
        ),
        "credentials_by_type": by_type,
        "active_credentials_older_than_90_days": sum(v["older_than_90_days"] for v in by_type.values()),
        "users_with_unreadable_credentials": sum(1 for u in users if u["unreadable_credential_types"]),
        "users_never_logged_in": sum(1 for u in live if not u["has_ever_logged_in"]),
        # Non-zero means some users' state could not be read; they are counted
        # in the findings above as if active.
        "users_with_unknown_state": sum(1 for u in users if u["lifecycle_state"] == "UNKNOWN"),
    }


# --- collection ---

def collect(auth: dict, collector: Collector) -> list | None:
    """Users are tenancy-scoped in OCI IAM, so this reads the tenancy root only."""
    import oci  # lazy

    tenancy = auth.get("tenancy")
    identity = make_client(oci.identity.IdentityClient, auth)

    groups = collector.guard("identity.list_groups", lambda: list_all(identity.list_groups, tenancy), default=[]) or []
    group_names = {g.id: g.name for g in groups}

    raw_users = collector.guard("identity.list_users", lambda: list_all(identity.list_users, tenancy))
    if raw_users is None:
        return None

    users = []
    for user in raw_users:
        uid, label = user.id, short_ocid(user.id)
        memberships = collector.guard(
            f"identity.list_user_group_memberships ({label})",
            lambda u=uid: list_all(identity.list_user_group_memberships, tenancy, user_id=u),
            default=[],
        ) or []
        names = [group_names.get(m.group_id, m.group_id) for m in memberships
                 if m.lifecycle_state not in INACTIVE_STATES]

        credentials = {}
        for kind, call in CREDENTIAL_CALLS.items():
            found = collector.guard(
                f"identity.{call} ({label})",
                lambda c=call, u=uid: list_all(getattr(identity, c), u),
            )
            credentials[kind] = None if found is None else [credential_record(to_plain(x)) for x in found]

        users.append(user_record(to_plain(user), group_names=names, credentials=credentials))

    users.extend(_secondary_domain_users(auth, identity, collector))
    users.sort(key=lambda r: (r.get("identity_domain") or "", r.get("name") or "", r.get("id") or ""))
    return users


def _scim_all(list_fn, **kwargs) -> list:
    """Every SCIM page. SCIM pages by start_index/count, not opc-next-page."""
    found: list = []
    start = 1
    while True:
        page = list_fn(start_index=start, count=SCIM_PAGE, **kwargs).data
        found.extend(page.resources or [])
        if not page.resources or len(found) >= (page.total_results or 0):
            return found
        start += len(page.resources)


def _secondary_domain_users(auth: dict, identity, collector: Collector) -> list:
    """Users of every active non-Default identity domain, via that domain's SCIM API."""
    import oci  # lazy

    tenancy = auth.get("tenancy")
    compartments = walk_compartments(identity, tenancy, collector,
                                     include_subcompartments=True, tenancy=tenancy)
    users: list = []
    for comp in compartments:
        for domain in collector.guard(
            f"identity.list_domains ({comp['name']})",
            lambda c=comp["id"]: list_all(identity.list_domains, c),
            default=[],
        ) or []:
            if domain.type == DEFAULT_DOMAIN_TYPE or domain.lifecycle_state != "ACTIVE":
                continue
            domain_name = domain.display_name or domain.id
            client = make_client(oci.identity_domains.IdentityDomainsClient, auth,
                                 service_endpoint=domain.url)
            raw = collector.guard(
                f"identity_domains.list_users ({domain_name})",
                lambda cl=client: _scim_all(cl.list_users, attributes=SCIM_USER_ATTRIBUTES),
            )
            for user in raw or []:
                plain = to_plain(user)
                names = [g.get("display") for g in plain.get("groups") or [] if g.get("display")]
                credentials = {}
                for kind, call in SCIM_CREDENTIAL_CALLS.items():
                    found = collector.guard(
                        f"identity_domains.{call} ({domain_name}/{plain.get('user_name')})",
                        lambda cl=client, c=call, u=plain.get("id"): _scim_all(
                            getattr(cl, c), filter=f'user.value eq "{u}"'),
                    )
                    credentials[kind] = None if found is None else [
                        credential_record(scim_credential(to_plain(x))) for x in found]
                users.append(user_record(scim_user(plain), group_names=names, credentials=credentials,
                                         domain=domain_name,
                                         domain_admin_group=DOMAIN_ADMIN_GROUP))
    return users


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    auth: dict = {}
    users = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        try:
            users = collect(auth, collector)
        except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
            collector.record("identity.collect", exc)

    # Users live at the tenancy root whatever compartment a target names.
    scope = {"compartment_id": auth.get("tenancy"), "compartment_source": "tenancy_root"}
    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"users": users or []},
        summary=summarize(users or []),
        regional=False,  # IAM lives in the home region and answers tenancy-wide
    )

    target = auth.get("tenancy") or "unknown"
    filename = f"oci_iam_users_credentials_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
