#!/usr/bin/env python3
"""
OCI password policy — every identity domain's rules, against the CIS thresholds

Every identity domain in scope with each password policy it defines: length,
character classes, expiry, history, lockout, and which groups a policy is
scoped to. Also the tenancy's legacy IAM authentication policy, which is the
only password policy a tenancy without identity domains has.

Evidence for KSI-IAM-APM, "strong passwords with phishing-resistant MFA" — the
strong-passwords half. Pairs with `oci_iam_users_credentials` for the MFA half.

Ported from Prowler's OCI identity service (Apache-2.0,
prowler/providers/oraclecloud/services/identity, commit c0fdd5b) — the
`identity_password_policy_minimum_length_14`, `_prevents_reuse` and
`_expires_within_365_days` checks, with the same CIS thresholds (14 characters,
24 remembered, 365 days). Two additions:

  * LOCKOUT. `max_incorrect_attempts` and `lockout_duration` are on the same
    model and Prowler does not read them; an unlimited-attempts policy is the
    one setting that makes every other rule guessable.

  * PAGING. Prowler reads one page of `list_password_policies`. SCIM pages at 50
    by default; this follows `total_results`.

WHICH POLICY APPLIES. Every identity domain ships two templates,
`StandardPasswordPolicy` and `SimplePasswordPolicy`, next to its own
`PasswordPolicy`. Verified live: the legacy authentication policy reported a
minimum length of 12, matching the domain's `PasswordPolicy`
(`password_strength: Custom`, min 12), not either template (min 8). So the
templates are recorded but excluded from the judgement, as Prowler does. A
policy with `groups` set applies only to those groups, and is reported alongside
the domain default rather than replacing it.
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
    build_payload,
    finish,
    list_all,
    load_config,
    make_client,
    sanitize_for_filename,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_iam_password_policy")

TEMPLATE_POLICY_IDS = frozenset({"StandardPasswordPolicy", "SimplePasswordPolicy"})

# CIS OCI Foundations, as Prowler applies them.
CIS_MIN_LENGTH = 14
CIS_HISTORY = 24
CIS_MAX_EXPIRY_DAYS = 365
# No CIS number for lockout; NIST SP 800-63B caps consecutive failures at 100.
MAX_REASONABLE_ATTEMPTS = 10

SCIM_PAGE = 50


# --- pure transforms ---

def password_policy_record(policy: dict) -> dict:
    min_length = policy.get("min_length")
    history = policy.get("num_passwords_in_history")
    expires = policy.get("password_expires_after")
    attempts = policy.get("max_incorrect_attempts")
    groups = policy.get("groups") or []
    return {
        "id": policy.get("id"),
        "ocid": policy.get("ocid"),
        "name": policy.get("name"),
        "password_strength": policy.get("password_strength"),
        "is_template": policy.get("id") in TEMPLATE_POLICY_IDS,
        "priority": policy.get("priority"),
        "scoped_to_groups": sorted(g.get("value") for g in groups if isinstance(g, dict) and g.get("value")),
        "min_length": min_length,
        "max_length": policy.get("max_length"),
        "min_lower_case": policy.get("min_lower_case"),
        "min_upper_case": policy.get("min_upper_case"),
        "min_numerals": policy.get("min_numerals"),
        "min_special_chars": policy.get("min_special_chars"),
        "user_name_disallowed": policy.get("user_name_disallowed"),
        "dictionary_word_disallowed": policy.get("dictionary_word_disallowed"),
        "password_expires_after_days": expires,
        "num_passwords_in_history": history,
        "min_password_age": policy.get("min_password_age"),
        "max_incorrect_attempts": attempts,
        "lockout_duration_minutes": policy.get("lockout_duration"),
        # CIS judgements. None-valued settings fail: an unset rule is no rule.
        "meets_cis_min_length": min_length is not None and min_length >= CIS_MIN_LENGTH,
        "meets_cis_history": history is not None and history >= CIS_HISTORY,
        "meets_cis_expiry": expires is not None and expires <= CIS_MAX_EXPIRY_DAYS,
        "locks_out_after_bounded_attempts": attempts is not None and attempts <= MAX_REASONABLE_ATTEMPTS,
    }


def domain_record(domain: dict, policies=None) -> dict:
    """A domain with its policies; `policies` None means they could not be read."""
    records = [password_policy_record(p) for p in policies] if policies is not None else None
    effective = [p for p in records or [] if not p["is_template"]]
    return {
        "id": domain.get("id"),
        "display_name": domain.get("display_name"),
        "type": domain.get("type"),
        "compartment_id": domain.get("compartment_id"),
        "home_region": domain.get("home_region"),
        "lifecycle_state": domain.get("lifecycle_state"),
        "policies_readable": records is not None,
        "password_policies": records or [],
        "default_policy": next((p["name"] for p in effective if not p["scoped_to_groups"]), None),
        "group_scoped_policies": sorted(p["name"] for p in effective if p["scoped_to_groups"]),
    }


def legacy_policy_record(auth_policy: dict) -> dict:
    password = auth_policy.get("password_policy") or {}
    length = password.get("minimum_password_length")
    return {
        "minimum_password_length": length,
        "is_lowercase_characters_required": password.get("is_lowercase_characters_required"),
        "is_uppercase_characters_required": password.get("is_uppercase_characters_required"),
        "is_numeric_characters_required": password.get("is_numeric_characters_required"),
        "is_special_characters_required": password.get("is_special_characters_required"),
        "is_username_containment_allowed": password.get("is_username_containment_allowed"),
        "meets_cis_min_length": length is not None and length >= CIS_MIN_LENGTH,
    }


def summarize(domains: list[dict], legacy) -> dict:
    active = [d for d in domains if d["lifecycle_state"] == "ACTIVE"]
    judged = [p for d in active for p in d["password_policies"] if not p["is_template"]]

    def failing(flag):
        return sorted(f"{d['display_name']}/{p['name']}" for d in active for p in d["password_policies"]
                      if not p["is_template"] and not p[flag])

    return {
        "identity_domains": len(active),
        "domains_with_unreadable_policies": sum(1 for d in active if not d["policies_readable"]),
        # A domain whose only policies are Oracle's templates has none of its own.
        "domains_without_own_policy": sum(
            1 for d in active if d["policies_readable"] and d["default_policy"] is None
        ),
        "policies_evaluated": len(judged),
        "policies_below_cis_min_length": failing("meets_cis_min_length"),
        "policies_below_cis_history": failing("meets_cis_history"),
        "policies_exceeding_cis_expiry": failing("meets_cis_expiry"),
        "policies_without_bounded_lockout": failing("locks_out_after_bounded_attempts"),
        "all_policies_meet_cis": bool(judged) and all(
            p["meets_cis_min_length"] and p["meets_cis_history"] and p["meets_cis_expiry"] for p in judged
        ),
        "shortest_min_length": min((p["min_length"] for p in judged if p["min_length"] is not None), default=None),
        "legacy_minimum_password_length": legacy["minimum_password_length"] if legacy else None,
    }


# --- collection ---

def _all_password_policies(client) -> list:
    """Every SCIM page — Prowler reads only the first."""
    found: list = []
    start = 1
    while True:
        page = client.list_password_policies(start_index=start, count=SCIM_PAGE).data
        found.extend(page.resources or [])
        total = page.total_results or 0
        if not page.resources or len(found) >= total:
            return found
        start += len(page.resources)


def collect(auth: dict, collector: Collector):
    import oci  # lazy

    tenancy = auth.get("tenancy")
    identity = make_client(oci.identity.IdentityClient, auth)

    legacy_raw = collector.guard(
        "identity.get_authentication_policy",
        lambda: identity.get_authentication_policy(tenancy).data,
    )
    legacy = legacy_policy_record(to_plain(legacy_raw)) if legacy_raw is not None else None

    # Domains can be created in any compartment, so the whole tree is walked.
    compartments = walk_compartments(identity, tenancy, collector, include_subcompartments=True, tenancy=tenancy)
    domains = []
    for comp in compartments:
        for domain in collector.guard(
            f"identity.list_domains ({comp['name']})",
            lambda c=comp["id"]: list_all(identity.list_domains, c),
            default=[],
        ) or []:
            plain = to_plain(domain)
            client = make_client(oci.identity_domains.IdentityDomainsClient, auth,
                                 service_endpoint=plain.get("url"))
            raw = collector.guard(
                f"identity_domains.list_password_policies ({plain.get('display_name')}, {short_ocid(plain.get('id'))})",
                lambda cl=client: [to_plain(p) for p in _all_password_policies(cl)],
            )
            domains.append(domain_record(plain, raw))

    domains.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    return domains, legacy, len(compartments)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    auth: dict = {}
    domains, legacy, scanned = [], None, None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        try:
            domains, legacy, scanned = collect(auth, collector)
        except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
            collector.record("identity.collect", exc)

    scope = {"compartment_id": auth.get("tenancy"), "compartment_source": "tenancy_root"}
    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"identity_domains": domains, "legacy_authentication_policy": legacy},
        summary=summarize(domains, legacy),
        compartments_scanned=scanned,
        regional=False,  # IAM lives in the home region and answers tenancy-wide
    )

    target = auth.get("tenancy") or "unknown"
    filename = f"oci_iam_password_policy_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
