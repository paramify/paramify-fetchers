#!/usr/bin/env python3
"""
GCP Cloud KMS Key Configuration

Every key ring and crypto key in one project, across every KMS location: purpose,
protection level, rotation schedule, primary version state, the grace period
before a destroyed version is really gone, and who holds IAM on the key and on its
ring. The data-at-rest evidence sets report which resources use a customer-managed
key; this reports whether the key itself is managed properly — `allUsers` on a key
or ring being the critical one, since it makes the CMEK on every resource
referencing that key decorative. No key material is read: cryptoKeys.list and
getIamPolicy return metadata and policy only.

Ported from Prowler's GCP KMS service (Apache-2.0).
"""

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    basename,
    build_payload,
    coverage_percentage,
    credentials,
    dig_any,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_kms_key_configuration")

# The CIS rotation interval Prowler checks, applied to both halves of its rule:
# the configured rotation period and the distance to the next rotation.
_MAX_ROTATION_DAYS = 90

_SECONDS_PER_DAY = 24 * 3600

# The two members that mean "not access-controlled".
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})

# Only a symmetric encrypt/decrypt key can carry a rotation period; asymmetric
# and MAC keys rotate by new version, so "no rotation period" on one of those is
# the API's design, not a misconfiguration.
_ROTATABLE_PURPOSES = frozenset({"ENCRYPT_DECRYPT"})

# HSM holds key material in dedicated hardware; EXTERNAL* holds it outside Google.
_HSM_PROTECTION_LEVELS = frozenset({"HSM"})
_EXTERNAL_PROTECTION_LEVELS = frozenset({"EXTERNAL", "EXTERNAL_VPC"})

# Prowler's iam_role_kms_enforce_separation_of_duties role split, evaluated per
# key: whoever administers a key should not also be able to use it.
_KMS_ADMIN_ROLES = frozenset({"roles/cloudkms.admin"})
_KMS_USE_ROLES = frozenset(
    {
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.cryptoKeyEncrypter",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/cloudkms.signer",
        "roles/cloudkms.signerVerifier",
    }
)


# --- pure transforms ---

def parse_timestamp(value) -> datetime | None:
    """RFC3339 timestamp string → aware datetime, or None when absent/odd."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def duration_seconds(value) -> int | None:
    """A protobuf Duration in any of the shapes it serializes to → seconds.

    `to_dict()` renders a Duration as the string "7776000s"; off the message or
    out of captured JSON it can instead be {"seconds": 7776000}. Prowler assumes
    the string form and slices the trailing "s" by hand, crashing on the dict.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, dict):
        seconds = value.get("seconds")
        return int(seconds) if seconds is not None else None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.endswith("s"):
        text = text[:-1]
    try:
        return int(float(text))
    except ValueError:
        return None


def duration_days(value) -> int | None:
    """A protobuf Duration → whole days, the unit rotation policy is written in."""
    seconds = duration_seconds(value)
    return seconds // _SECONDS_PER_DAY if seconds is not None else None


def duration_text(value) -> str | None:
    """A protobuf Duration, normalized to the API's own "<seconds>s" spelling.

    Either input shape then reads the same in the evidence, instead of leaking a
    Python dict repr into a field a validator might match on.
    """
    seconds = duration_seconds(value)
    if seconds is not None:
        return f"{seconds}s"
    return None if value is None else str(value)


def resource_segment(resource_name: str | None, key: str) -> str | None:
    """The segment following `key` in a KMS resource path.

    Location and key ring are read out of the name by label, not by index:
    Prowler takes `name.split("/")[3]`, which breaks the moment the path shape
    changes.
    """
    parts = (resource_name or "").split("/")
    if key in parts:
        index = parts.index(key) + 1
        if index < len(parts):
            return parts[index] or None
    return None


def iam_summary(bindings: list[dict] | None) -> dict:
    """Public exposure and separation of duties for one key or key ring policy."""
    bindings = bindings or []
    members = {m for b in bindings for m in (b.get("members") or [])}
    admins = {
        m
        for b in bindings
        if b.get("role") in _KMS_ADMIN_ROLES
        for m in (b.get("members") or [])
    }
    users = {
        m
        for b in bindings
        if b.get("role") in _KMS_USE_ROLES
        for m in (b.get("members") or [])
    }
    public = sorted(members & _PUBLIC_MEMBERS)
    return {
        "iam_bindings": sorted(
            (
                {"role": b.get("role"), "members": sorted(set(b.get("members") or []))}
                for b in bindings
            ),
            key=lambda b: b["role"] or "",
        ),
        "iam_member_count": len(members),
        "public_members": public,
        "publicly_accessible": bool(public),
        "kms_admin_members": sorted(admins),
        "kms_use_members": sorted(users),
        "separation_of_duties_members": sorted(admins & users),
        "separation_of_duties_violated": bool(admins & users),
    }


def crypto_key_record(key: dict, bindings: list[dict] | None, now: datetime) -> dict:
    """Normalize one crypto key into an evidence record."""
    name = dig_any(key, "name")
    purpose = dig_any(key, "purpose") or None
    rotation_period = dig_any(key, "rotation_period")
    rotation_days = duration_days(rotation_period)
    next_rotation = dig_any(key, "next_rotation_time") or None
    next_rotation_at = parse_timestamp(next_rotation)
    days_until = (next_rotation_at - now).days if next_rotation_at else None

    template_protection = dig_any(key, "version_template", "protection_level") or None
    primary = dig_any(key, "primary") or {}
    destroy_duration = dig_any(key, "destroy_scheduled_duration")

    rotation_within = rotation_days is not None and rotation_days <= _MAX_ROTATION_DAYS
    next_within = days_until is not None and abs(days_until) <= _MAX_ROTATION_DAYS

    record = {
        "name": name,
        "key_id": basename(name),
        "key_ring": resource_segment(name, "keyRings"),
        "location": resource_segment(name, "locations"),
        "purpose": purpose,
        "create_time": dig_any(key, "create_time") or None,
        "rotation_supported": purpose in _ROTATABLE_PURPOSES,
        "rotation_enabled": rotation_period is not None,
        "rotation_period": duration_text(rotation_period),
        "rotation_period_days": rotation_days,
        "next_rotation_time": next_rotation,
        "days_until_next_rotation": days_until,
        "rotation_period_within_max_days": rotation_within,
        "next_rotation_within_max_days": next_within,
        # Prowler's kms_key_rotation_max_90_days: BOTH halves must hold.
        "meets_rotation_interval": rotation_within and next_within,
        "max_rotation_days": _MAX_ROTATION_DAYS,
        "protection_level": template_protection,
        "algorithm": dig_any(key, "version_template", "algorithm") or None,
        "hardware_backed": template_protection in _HSM_PROTECTION_LEVELS,
        "external_key": template_protection in _EXTERNAL_PROTECTION_LEVELS,
        "primary_version_id": basename(dig_any(primary, "name")),
        "primary_version_state": dig_any(primary, "state") or None,
        "primary_protection_level": dig_any(primary, "protection_level") or None,
        "primary_algorithm": dig_any(primary, "algorithm") or None,
        "primary_generate_time": dig_any(primary, "generate_time") or None,
        "primary_version_enabled": (dig_any(primary, "state") or None) == "ENABLED",
        # How long a destroyed version can still be restored. 24h is the API floor.
        "destroy_scheduled_duration": duration_text(destroy_duration),
        "destroy_scheduled_days": duration_days(destroy_duration),
        "import_only": bool(dig_any(key, "import_only")),
        "crypto_key_backend": dig_any(key, "crypto_key_backend") or None,
    }
    record.update(iam_summary(bindings))
    return record


def key_ring_record(ring: dict, keys: list[dict], bindings: list[dict] | None) -> dict:
    """Normalize one key ring, with the count of keys under it."""
    name = dig_any(ring, "name")
    record = {
        "name": name,
        "key_ring_id": basename(name),
        "location": resource_segment(name, "locations"),
        "create_time": dig_any(ring, "create_time") or None,
        "crypto_key_count": len(keys),
        "crypto_keys": sorted(k["key_id"] or "" for k in keys),
    }
    record.update(iam_summary(bindings))
    return record


def summarize(
    rings: list[dict], keys: list[dict], locations: list[str], api_readable: bool = True
) -> dict:
    purposes: dict[str, int] = {}
    protection: dict[str, int] = {}
    states: dict[str, int] = {}
    for key in keys:
        purposes[key["purpose"] or "UNKNOWN"] = purposes.get(key["purpose"] or "UNKNOWN", 0) + 1
        level = key["protection_level"] or "UNKNOWN"
        protection[level] = protection.get(level, 0) + 1
        state = key["primary_version_state"] or "NONE"
        states[state] = states.get(state, 0) + 1

    # Compliance denominator: only ENCRYPT_DECRYPT keys can carry a rotation period.
    eligible = [k for k in keys if k["rotation_supported"]]
    compliant = [k for k in eligible if k["meets_rotation_interval"]]
    rotation_days = [
        k["rotation_period_days"] for k in keys if k["rotation_period_days"] is not None
    ]
    destroy_days = [
        k["destroy_scheduled_days"] for k in keys if k["destroy_scheduled_days"] is not None
    ]

    return {
        # False means the Cloud KMS API is disabled or unreadable on this project,
        # not that the project has no keys.
        "kms_api_readable": api_readable,
        "locations_scanned": len(locations),
        "total_key_rings": len(rings),
        "total_crypto_keys": len(keys),
        "keys_by_purpose": dict(sorted(purposes.items())),
        "keys_by_protection_level": dict(sorted(protection.items())),
        "hsm_keys": sum(1 for k in keys if k["hardware_backed"]),
        "external_keys": sum(1 for k in keys if k["external_key"]),
        "rotation_eligible_keys": len(eligible),
        "rotation_enabled_keys": sum(1 for k in keys if k["rotation_enabled"]),
        "keys_without_rotation_period": sum(
            1 for k in eligible if not k["rotation_enabled"]
        ),
        "keys_meeting_rotation_interval": len(compliant),
        "rotation_interval_days": _MAX_ROTATION_DAYS,
        "rotation_compliance_percentage": coverage_percentage(len(compliant), len(eligible)),
        "shortest_rotation_period_days": min(rotation_days) if rotation_days else None,
        "longest_rotation_period_days": max(rotation_days) if rotation_days else None,
        "keys_with_overdue_next_rotation": sum(
            1
            for k in keys
            if k["days_until_next_rotation"] is not None and k["days_until_next_rotation"] < 0
        ),
        "primary_version_states": dict(sorted(states.items())),
        "keys_with_disabled_primary_version": sum(
            1
            for k in keys
            if k["primary_version_state"] and not k["primary_version_enabled"]
        ),
        "shortest_destroy_scheduled_days": min(destroy_days) if destroy_days else None,
        "publicly_accessible": any(
            r["publicly_accessible"] for r in rings + keys
        ),
        "publicly_accessible_keys": sum(1 for k in keys if k["publicly_accessible"]),
        "publicly_accessible_key_rings": sum(1 for r in rings if r["publicly_accessible"]),
        "keys_with_iam_bindings": sum(1 for k in keys if k["iam_bindings"]),
        "key_rings_with_iam_bindings": sum(1 for r in rings if r["iam_bindings"]),
        "keys_violating_separation_of_duties": sum(
            1 for k in keys if k["separation_of_duties_violated"]
        ),
    }


# --- collection ---

def policy_bindings(policy) -> list[dict]:
    """google.iam.v1.Policy → {role, members} dicts. Raw protobuf, not proto-plus:
    no to_dict(), and reading the two fields that matter beats json_format.
    """
    return [{"role": b.role, "members": list(b.members)} for b in policy.bindings]


def _client(creds):
    from google.cloud import kms

    return kms.KeyManagementServiceClient(credentials=creds)


def collect_locations(project, creds, collector: Collector) -> tuple[list[str], bool]:
    """Every KMS location the project can hold key rings in.

    keyRings.list has no wildcard location, so locations are enumerated first and
    the ring listing repeated per location — Prowler's walk. A project that never
    enabled cloudkms.googleapis.com 403s here with SERVICE_DISABLED, itself
    evidence, so it is tolerated and reported as an unreadable API.
    """
    def _list():
        client = _client(creds)
        # list_locations comes from the generic Locations mixin, not the KMS
        # surface: it returns a bare ListLocationsResponse, not a pager. Iterating
        # the response raises TypeError, so the page token is walked by hand.
        found, token = [], ""
        while True:
            response = client.list_locations(
                request={"name": f"projects/{project}", "page_token": token}
            )
            found.extend(
                loc.location_id or basename(loc.name) for loc in response.locations
            )
            token = response.next_page_token
            if not token:
                return sorted(found)

    locations = collector.guard(
        "cloudkms.projects.locations.list", _list, default=None, tolerate=service_disabled
    )
    return (locations or []), locations is not None


def collect_key_rings(
    project, creds, collector: Collector, locations: list[str], now: datetime
) -> tuple[list[dict], list[dict]]:
    """Key rings and crypto keys across every location, with their IAM policies."""
    from google.cloud import kms

    client = collector.guard("cloudkms.client", lambda: _client(creds))
    if client is None:
        return [], []

    ring_records: list[dict] = []
    key_records: list[dict] = []

    for location in locations:
        parent = f"projects/{project}/locations/{location}"

        def _rings(parent=parent):
            return [
                kms.KeyRing.to_dict(r, use_integers_for_enums=False)
                for r in client.list_key_rings(parent=parent)
            ]

        rings = collector.guard(f"cloudkms.keyRings.list ({location})", _rings, default=[])

        for ring in rings:
            ring_name = dig_any(ring, "name")

            def _keys(ring_name=ring_name):
                return [
                    kms.CryptoKey.to_dict(k, use_integers_for_enums=False)
                    for k in client.list_crypto_keys(parent=ring_name)
                ]

            # A RING binding inherits to every key in it — a public ring is a public key.
            def _ring_policy(ring_name=ring_name):
                return policy_bindings(client.get_iam_policy(request={"resource": ring_name}))

            raw_keys = collector.guard(
                f"cloudkms.cryptoKeys.list ({ring_name})", _keys, default=[]
            )
            ring_bindings = collector.guard(
                f"cloudkms.keyRings.getIamPolicy ({ring_name})", _ring_policy, default=[]
            )

            ring_keys = []
            for raw_key in raw_keys:
                key_name = dig_any(raw_key, "name")

                def _key_policy(key_name=key_name):
                    return policy_bindings(
                        client.get_iam_policy(request={"resource": key_name})
                    )

                key_bindings = collector.guard(
                    f"cloudkms.cryptoKeys.getIamPolicy ({key_name})", _key_policy, default=[]
                )
                ring_keys.append(crypto_key_record(raw_key, key_bindings, now))

            key_records += ring_keys
            ring_records.append(key_ring_record(ring, ring_keys, ring_bindings))

    ring_records.sort(key=lambda r: (r["location"] or "", r["key_ring_id"] or ""))
    key_records.sort(
        key=lambda k: (k["location"] or "", k["key_ring"] or "", k["key_id"] or "")
    )
    return ring_records, key_records


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    now = datetime.now(timezone.utc)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    locations: list[str] = []
    rings: list[dict] = []
    keys: list[dict] = []
    api_readable = False
    if project and creds is not None:
        locations, api_readable = collect_locations(project, creds, collector)
        if locations:
            rings, keys = collect_key_rings(project, creds, collector, locations, now)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={
            "locations": locations,
            "key_rings": rings,
            "crypto_keys": keys,
        },
        summary=summarize(rings, keys, locations, api_readable=api_readable),
    )

    filename = f"gcp_kms_key_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
