#!/usr/bin/env python3
"""
OCI Certificates — the trust material behind machine-to-machine communications

Every certificate and certificate authority in scope: who it identifies, the
validity window it is inside, the key and signature algorithms behind it,
whether it renews automatically, and whether it has been revoked.

This is the evidence for KSI-SVC-VCM, "the authenticity and integrity of
communications between machine-based information resources is persistently
validated using automation" — an indicator uncovered across the whole repo.
Certificates ARE that validation: a service presenting one is asserting its
identity, and a peer checking it is validating authenticity and integrity.

THE "USING AUTOMATION" CLAUSE IS THE POINT, and it is what makes this evidence
rather than a certificate inventory. A `CertificateRenewalRule` carries a
`renewal_interval` and an `advance_renewal_period`; a certificate that has one
re-issues itself before it lapses, and a certificate that does not is
hand-managed and will eventually expire in production. So the summary answers
"how many are on automatic renewal" as its headline, not "how many exist".

IMPORTED CERTIFICATES CANNOT AUTO-RENEW. `config_type` IMPORTED means the
material came from outside OCI, so no renewal rule is possible and OCI is not
the system of record for its lifecycle. Those are counted apart from
internally-issued certificates that simply have no rule configured — the second
group is a gap, the first is a boundary, and summing them would misstate both.

DO NOT "IMPROVE" THIS BY CALLING get_certificate PER CERTIFICATE. OCI inverts
the usual summary/detail relationship here, and the inversion is silent:

    CertificateSummary (from list_certificates) HAS current_version_summary
    Certificate        (from get_certificate)   DOES NOT

`current_version_summary` is where the entire validity window, serial number and
revocation status live, so a detail call per certificate would drop every expiry
date in this file and leave `days_until_expiry` null across the board — with no
error, because the field simply is not on that model. Verified by diffing the
two models' `swagger_types` against a live tenancy.

This is the exact opposite of `bastion_sessions`, where the fields that matter
are ONLY on the detail response and the per-resource get IS mandatory. Neither
instinct generalises; check the models per service.

Deliberately NOT included: the private keys. Nothing here reads certificate
content or any key material — only metadata. `list_certificates` and
`list_certificate_authorities` return neither, and no `get_certificate_bundle`
call is made, which is the call that would.
"""

import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    age_in_days,
    as_bool,
    build_payload,
    coverage_percentage,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    resolve_scope,
    sanitize_for_filename,
    service_not_subscribed,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_certificates")

# Key algorithms considered adequate. RSA2048 is the floor FedRAMP-relevant
# guidance accepts; anything OCI offers below it would be flagged, and the
# enum currently has no such value, so this is a guard against a future one
# rather than a filter on today's.
STRONG_KEY_ALGORITHMS = frozenset({"RSA2048", "RSA4096", "ECDSA_P256", "ECDSA_P384"})

# SHA-1 and MD5 signatures are not in OCI's enum at all, which is why this is a
# positive list: an algorithm this fetcher does not recognise is reported as
# unrecognised rather than quietly counted as strong.
STRONG_SIGNATURE_ALGORITHMS = frozenset({
    "SHA256_WITH_RSA", "SHA384_WITH_RSA", "SHA512_WITH_RSA",
    "SHA256_WITH_ECDSA", "SHA384_WITH_ECDSA", "SHA512_WITH_ECDSA",
})

# Certificate material that came from outside OCI; no renewal rule is possible.
IMPORTED_CONFIG_TYPE = "IMPORTED"

# Issued by an OCI CA from the customer's own CSR: OCI never holds the private
# key, so it cannot renew one either. Reported, but not as a manual-renewal gap,
# because no setting in OCI would clear it.
EXTERNAL_KEY_CONFIG_TYPE = "MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA"

# A certificate on its way out is not posture; it is kept in the record list
# and left out of every finding.
GONE_STATES = frozenset({"DELETING", "DELETED", "SCHEDULING_DELETION", "PENDING_DELETION"})

# Expiry horizons. A certificate inside 30 days needs action now; 90 days is the
# planning horizon. Fixed and documented rather than configurable, so the
# evidence means the same thing in every tenancy.
EXPIRY_URGENT_DAYS = 30
EXPIRY_WARNING_DAYS = 90

# ISO-8601 durations, which is how OCI expresses renewal intervals ("P30D").
_DURATION = re.compile(
    r"^P(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)


# --- pure transforms ---

def duration_days(value) -> int | None:
    """An ISO-8601 duration as whole days, or None when unparseable.

    OCI expresses `renewal_interval` and `advance_renewal_period` as ISO-8601
    durations ("P30D", "P1Y"). Reported in days because every other date field
    here is, and a reader comparing "P30D" against a 45-day validity window has
    to do the conversion anyway. Years and months are approximated at 365 and 30
    days: the value is used for ordering and legibility, never for arithmetic on
    an actual date.
    """
    if not value:
        return None
    match = _DURATION.match(str(value).strip())
    if not match or not any(match.groupdict().values()):
        return None
    part = {k: int(v) if v else 0 for k, v in match.groupdict().items()}
    return (
        part["years"] * 365
        + part["months"] * 30
        + part["days"]
        + part["hours"] // 24
    )


def renewal_rule(rules) -> dict:
    """The renewal rule off a certificate's `certificate_rules` list, flattened.

    The list is polymorphic on `rule_type` and CERTIFICATE_RENEWAL_RULE is
    currently its only member; anything else is ignored rather than assumed to
    be a renewal rule, so a new rule type cannot silently read as one.
    """
    for rule in rules or []:
        if str(rule.get("rule_type") or "").upper() != "CERTIFICATE_RENEWAL_RULE":
            continue
        interval = rule.get("renewal_interval")
        advance = rule.get("advance_renewal_period")
        return {
            "auto_renews": True,
            "renewal_interval": interval,
            "renewal_interval_days": duration_days(interval),
            "advance_renewal_period": advance,
            "advance_renewal_period_days": duration_days(advance),
        }
    return {
        "auto_renews": False,
        "renewal_interval": None,
        "renewal_interval_days": None,
        "advance_renewal_period": None,
        "advance_renewal_period_days": None,
    }


def version_facts(version, *, now=None) -> dict:
    """Validity window, expiry distance and revocation off a version summary."""
    version = version or {}
    validity = version.get("validity") or {}
    revocation = version.get("revocation_status") or {}
    not_after = validity.get("time_of_validity_not_after")

    # age_in_days counts backwards from now, so a future expiry is negative days
    # ago. Negated here to read as "days until expiry", which is what the field
    # is called and what every threshold below compares against.
    ago = age_in_days(not_after, now=now)
    days_until_expiry = -ago if ago is not None else None

    return {
        "version_number": version.get("version_number"),
        "serial_number": version.get("serial_number"),
        "valid_from": iso(validity.get("time_of_validity_not_before")),
        "valid_until": iso(not_after),
        "days_until_expiry": days_until_expiry,
        "is_expired": days_until_expiry < 0 if days_until_expiry is not None else None,
        "expires_within_30_days": (
            0 <= days_until_expiry <= EXPIRY_URGENT_DAYS
            if days_until_expiry is not None else None
        ),
        "expires_within_90_days": (
            0 <= days_until_expiry <= EXPIRY_WARNING_DAYS
            if days_until_expiry is not None else None
        ),
        # A revoked certificate still listed ACTIVE is worth seeing.
        "is_revoked": bool(revocation.get("time_of_revocation")),
        "revocation_reason": revocation.get("revocation_reason"),
        "revoked_at": iso(revocation.get("time_of_revocation")),
    }


def certificate_record(certificate: dict, *, now=None) -> dict:
    """Normalize one certificate into an evidence record."""
    subject = certificate.get("subject") or {}
    config_type = certificate.get("config_type")
    key_algorithm = certificate.get("key_algorithm")
    signature_algorithm = certificate.get("signature_algorithm")
    imported = str(config_type or "").upper() == IMPORTED_CONFIG_TYPE
    external_key = str(config_type or "").upper() == EXTERNAL_KEY_CONFIG_TYPE
    renewal = renewal_rule(certificate.get("certificate_rules"))

    return {
        "id": certificate.get("id"),
        "name": certificate.get("name"),
        "description": certificate.get("description"),
        "compartment_id": certificate.get("compartment_id"),
        "issuer_certificate_authority_id": certificate.get("issuer_certificate_authority_id"),
        "lifecycle_state": certificate.get("lifecycle_state"),
        "common_name": subject.get("common_name"),
        "organization": subject.get("organization"),
        "config_type": config_type,
        # Imported material has no renewal rule available, so its absence is a
        # boundary rather than a gap. Counted separately in the summary.
        "is_imported": imported,
        "has_externally_managed_key": external_key,
        "certificate_profile_type": certificate.get("certificate_profile_type"),
        "key_algorithm": key_algorithm,
        "signature_algorithm": signature_algorithm,
        "uses_strong_key_algorithm": key_algorithm in STRONG_KEY_ALGORITHMS,
        "uses_strong_signature_algorithm": signature_algorithm in STRONG_SIGNATURE_ALGORITHMS,
        "time_created": iso(certificate.get("time_created")),
        **renewal,
        # An internally-issued certificate with no renewal rule is the gap this
        # indicator asks about: validation that is not automated.
        "renewal_is_manual": not renewal["auto_renews"] and not imported and not external_key,
        **version_facts(certificate.get("current_version_summary"), now=now),
    }


def authority_record(authority: dict, *, now=None) -> dict:
    """Normalize one certificate authority.

    A CA's own expiry matters more than any leaf's: when it lapses, every
    certificate beneath it stops validating at once.
    """
    subject = authority.get("subject") or {}
    signing_algorithm = authority.get("signing_algorithm")

    return {
        "id": authority.get("id"),
        "name": authority.get("name"),
        "description": authority.get("description"),
        "compartment_id": authority.get("compartment_id"),
        "issuer_certificate_authority_id": authority.get("issuer_certificate_authority_id"),
        "lifecycle_state": authority.get("lifecycle_state"),
        "common_name": subject.get("common_name"),
        "organization": subject.get("organization"),
        "config_type": authority.get("config_type"),
        # A CA backed by a Vault key has its private key in a KMS rather than in
        # the service, which is the stronger arrangement and worth recording.
        "kms_key_id": authority.get("kms_key_id"),
        "backed_by_kms_key": bool(authority.get("kms_key_id")),
        "signing_algorithm": signing_algorithm,
        "uses_strong_signing_algorithm": signing_algorithm in STRONG_SIGNATURE_ALGORITHMS,
        "time_created": iso(authority.get("time_created")),
        **version_facts(authority.get("current_version_summary"), now=now),
    }


def summarize(
    certificates: list[dict],
    authorities: list[dict],
    *,
    api_readable: bool = True,
) -> dict:
    """Aggregate into the automation question SVC-VCM asks."""
    active = [c for c in certificates if c["lifecycle_state"] == "ACTIVE"]
    all_certificates = certificates
    certificates = [c for c in certificates if c["lifecycle_state"] not in GONE_STATES]
    renewable = [c for c in certificates if not c["is_imported"] and not c["has_externally_managed_key"]]
    auto = [c for c in certificates if c["auto_renews"]]
    manual = [c for c in certificates if c["renewal_is_manual"]]

    intervals = [c["renewal_interval_days"] for c in auto if c["renewal_interval_days"]]
    expiries = [
        c["days_until_expiry"] for c in certificates
        if c["days_until_expiry"] is not None and not c["is_expired"]
    ]
    ca_expiries = [
        a["days_until_expiry"] for a in authorities
        if a["days_until_expiry"] is not None and not a["is_expired"]
    ]

    return {
        # False when the Certificates service is not subscribed (recorded in
        # metadata.skipped_calls) or the list call failed — not "no certificates".
        "certificates_service_readable": api_readable,
        "total_certificates": len(all_certificates),
        "certificates_pending_deletion": len(all_certificates) - len(certificates),
        "active_certificates": len(active),
        "total_certificate_authorities": len(authorities),
        # The headline: automated renewal is the "using automation" clause.
        "certificates_with_automatic_renewal": len(auto),
        "certificates_requiring_manual_renewal": len(manual),
        "imported_certificates": sum(1 for c in certificates if c["is_imported"]),
        "certificates_with_externally_managed_keys": sum(
            1 for c in certificates if c["has_externally_managed_key"]
        ),
        # Over the certificates OCI could renew: imported and external-key ones
        # have no renewal rule to turn on.
        "automatic_renewal_percentage": coverage_percentage(len(auto), len(renewable)),
        "shortest_renewal_interval_days": min(intervals) if intervals else None,
        "longest_renewal_interval_days": max(intervals) if intervals else None,
        # Expiry pressure.
        "expired_certificates": sum(1 for c in certificates if c["is_expired"]),
        "certificates_expiring_within_30_days": sum(
            1 for c in certificates if c["expires_within_30_days"]
        ),
        "certificates_expiring_within_90_days": sum(
            1 for c in certificates if c["expires_within_90_days"]
        ),
        "soonest_certificate_expiry_days": min(expiries) if expiries else None,
        # No validity window came back, so the expiry counts above cannot include them.
        "certificates_with_unknown_expiry": sum(1 for c in certificates if c["days_until_expiry"] is None),
        "revoked_certificates": sum(1 for c in certificates if c["is_revoked"]),
        # Algorithm strength.
        "certificates_with_strong_key_algorithm": sum(
            1 for c in certificates if c["uses_strong_key_algorithm"]
        ),
        "certificates_with_strong_signature_algorithm": sum(
            1 for c in certificates if c["uses_strong_signature_algorithm"]
        ),
        "key_algorithms_in_use": sorted(
            {c["key_algorithm"] for c in certificates if c["key_algorithm"]}
        ),
        "signature_algorithms_in_use": sorted(
            {c["signature_algorithm"] for c in certificates if c["signature_algorithm"]}
        ),
        # Authorities. A lapsed CA invalidates every certificate beneath it, so
        # its expiry is reported separately rather than pooled with the leaves.
        "expired_certificate_authorities": sum(1 for a in authorities if a["is_expired"]),
        "certificate_authorities_expiring_within_90_days": sum(
            1 for a in authorities if a["expires_within_90_days"]
        ),
        "soonest_authority_expiry_days": min(ca_expiries) if ca_expiries else None,
        "certificate_authorities_backed_by_kms_key": sum(
            1 for a in authorities if a["backed_by_kms_key"]
        ),
        "certificate_common_names": sorted(
            {c["common_name"] for c in certificates if c["common_name"]}
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    """Certificates and certificate authorities across every compartment in scope."""
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    certs = make_client(oci.certificates_management.CertificatesManagementClient, auth)

    compartments = walk_compartments(
        identity,
        scope["compartment_id"],
        collector,
        include_subcompartments=include_sub,
        tenancy=auth.get("tenancy"),
    )

    certificates: list[dict] = []
    authorities: list[dict] = []
    unreadable = 0

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        found = collector.guard(
            f"certificates_management.list_certificates ({cname})",
            lambda c=cid: list_all(certs.list_certificates, compartment_id=c),
            tolerate=service_not_subscribed,
        )
        if found is None:
            unreadable += 1
            continue
        certificates.extend(certificate_record(to_plain(c)) for c in found)

        for authority in collector.guard(
            f"certificates_management.list_certificate_authorities ({cname})",
            lambda c=cid: list_all(certs.list_certificate_authorities, compartment_id=c),
            default=[],
        ) or []:
            authorities.append(authority_record(to_plain(authority)))

    if compartments and unreadable == len(compartments):
        return None, None, len(compartments)

    certificates.sort(key=lambda r: (r.get("name") or "", r.get("id") or ""))
    authorities.sort(key=lambda r: (r.get("name") or "", r.get("id") or ""))
    return certificates, authorities, len(compartments)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    include_sub = as_bool(os.environ.get("OCI_INCLUDE_SUBCOMPARTMENTS"), default=True)

    auth: dict = {}
    scope: dict = {"compartment_id": None, "compartment_source": "unresolved"}
    certificates = authorities = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            # Guarded as a whole: building a client parses the signing key, so a
            # malformed OCI_PRIVATE_KEY raises here rather than inside a guard.
            try:
                certificates, authorities, scanned = collect(
                    auth, scope, collector, include_sub=include_sub
                )
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("certificates_management.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "certificates": certificates or [],
            "certificate_authorities": authorities or [],
        },
        summary=summarize(
            certificates or [], authorities or [], api_readable=certificates is not None
        ),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_certificates_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)

    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
