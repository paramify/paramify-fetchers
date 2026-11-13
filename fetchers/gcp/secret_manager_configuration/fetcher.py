#!/usr/bin/env python3
"""
GCP Secret Manager Configuration

For each secret in one project: its replication policy (automatic vs
user-managed, and which locations), whether the replicas are wrapped with a CMEK,
whether a rotation schedule exists and when it next fires, whether the secret
expires, its labels, who can read it, and how many versions it has in each state.
No secret payload ever enters this evidence — AccessSecretVersion, the only call
that returns a value, is never made. Rotation is reported, not scored.

Ported from Prowler's GCP Secret Manager service (Apache-2.0).
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

logger = logging.getLogger("gcp_secret_manager_configuration")

# Prowler's default secretmanager_max_rotation_days, a reference the summary counts
# against — a validator can pick its own from each secret's rotation_period_days.
_MAX_ROTATION_PERIOD_DAYS = 90

# The two principals that make a secret readable outside the organization.
_PUBLIC_PRINCIPALS = frozenset({"allusers", "allauthenticatedusers"})

# IAM member prefixes that identify a person or a mailing list. Counted, not named.
_PERSONAL_MEMBER_PREFIXES = ("user:", "group:", "principal:", "principalset:")

# Enumerated so a secret with none of a given state still reports zero rather than
# omitting the key, which keeps the payload byte-stable across runs.
_VERSION_STATES = ("ENABLED", "DISABLED", "DESTROYED", "STATE_UNSPECIFIED")

_SECONDS_PER_DAY = 86_400


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


def parse_duration_seconds(value) -> int | None:
    """A protobuf Duration as rendered by to_dict ("7776000s") → int seconds."""
    if value is None:
        return None
    text = str(value).strip().rstrip("s")
    try:
        return int(float(text))
    except ValueError:
        return None


def secret_location(resource_name) -> str:
    """"global", or the region in `projects/p/locations/us-east1/secrets/x`.

    Prowler hardcodes "global" because it only lists the global parent.
    """
    parts = str(resource_name or "").split("/")
    if "locations" in parts:
        index = parts.index("locations")
        if index + 1 < len(parts):
            return parts[index + 1]
    return "global"


def is_public_member(member) -> bool:
    """Exact match against allUsers / allAuthenticatedUsers, prefix tolerated."""
    value = str(member or "").strip().lower()
    return value in _PUBLIC_PRINCIPALS or value.split(":")[-1] in _PUBLIC_PRINCIPALS


def replica_records(replication: dict) -> tuple[str | None, list[dict]]:
    """The replication policy name and one record per replica.

    Automatic policies carry no location list — Google picks the regions — so they
    become one replica with location None. CMEK is the PRESENCE of a
    customerManagedEncryption block, as in the other GCP encryption fetchers.
    """
    automatic = dig_any(replication, "automatic")
    user_managed = dig_any(replication, "user_managed")

    if isinstance(user_managed, dict):
        replicas = [
            {
                "location": dig_any(r, "location") or None,
                "kms_key_name": dig_any(r, "customer_managed_encryption", "kms_key_name"),
            }
            for r in (dig_any(user_managed, "replicas") or [])
        ]
        for replica in replicas:
            replica["cmek"] = replica["kms_key_name"] is not None
        return "user_managed", sorted(replicas, key=lambda r: r["location"] or "")

    if isinstance(automatic, dict):
        kms = dig_any(automatic, "customer_managed_encryption", "kms_key_name")
        return "automatic", [{"location": None, "kms_key_name": kms, "cmek": kms is not None}]

    return None, []


def version_record(version: dict) -> dict:
    """One SecretVersion: identity, state and timestamps. Never any payload data."""
    return {
        "id": basename(dig_any(version, "name")),
        "state": dig_any(version, "state") or None,
        "create_time": dig_any(version, "create_time") or None,
        "destroy_time": dig_any(version, "destroy_time") or None,
        "scheduled_destroy_time": dig_any(version, "scheduled_destroy_time") or None,
        "kms_key_version": dig_any(
            version, "customer_managed_encryption", "kms_key_version_name"
        ),
    }


def binding_record(binding: dict) -> dict:
    """One IAM binding on the secret: public and service-account members named.

    Everyone else is counted only, so the policy cannot become an identity inventory.
    """
    members = binding.get("members") or []
    public = sorted(m for m in members if is_public_member(m))
    service_accounts = sorted(m for m in members if str(m).startswith("serviceAccount:"))
    return {
        "role": binding.get("role"),
        "member_count": len(members),
        "public_members": public,
        "service_account_members": service_accounts,
        "other_member_count": len(members) - len(public) - len(service_accounts),
        "personal_member_count": sum(
            1 for m in members if str(m).lower().startswith(_PERSONAL_MEMBER_PREFIXES)
        ),
    }


def secret_record(
    secret: dict, versions: list[dict], bindings: list[dict], now: datetime
) -> dict:
    resource_name = dig_any(secret, "name")
    rotation = dig_any(secret, "rotation") or {}
    policy_name, replicas = replica_records(dig_any(secret, "replication") or {})

    rotation_period_seconds = parse_duration_seconds(dig_any(rotation, "rotation_period"))
    next_rotation = dig_any(rotation, "next_rotation_time") or None
    next_rotation_at = parse_timestamp(next_rotation)
    expire_time = dig_any(secret, "expire_time") or None
    expires_at = parse_timestamp(expire_time)

    version_records = sorted(
        (version_record(v) for v in versions),
        key=lambda v: (v["create_time"] or "", v["id"] or ""),
    )
    state_counts = {
        state: sum(1 for v in version_records if v["state"] == state)
        for state in _VERSION_STATES
    }
    enabled = [v for v in version_records if v["state"] == "ENABLED"]
    binding_records = sorted(
        (binding_record(b) for b in bindings), key=lambda b: b["role"] or ""
    )
    public_members = sorted({m for b in binding_records for m in b["public_members"]})

    return {
        "name": basename(resource_name),
        "resource_name": resource_name,
        "location": secret_location(resource_name),
        "create_time": dig_any(secret, "create_time") or None,
        "labels": dig_any(secret, "labels") or {},
        # --- replication + encryption at rest ---
        "replication_policy": policy_name,
        "replicas": replicas,
        "replica_count": len(replicas),
        "replica_locations": sorted(r["location"] for r in replicas if r["location"]),
        # CMEK only counts when EVERY replica has one — one Google-managed replica
        # makes the secret Google-managed in the region that matters.
        "cmek": bool(replicas) and all(r["cmek"] for r in replicas),
        "replicas_with_cmek": sum(1 for r in replicas if r["cmek"]),
        "kms_key_names": sorted({r["kms_key_name"] for r in replicas if r["kms_key_name"]}),
        # --- rotation ---
        "rotation_configured": rotation_period_seconds is not None or next_rotation is not None,
        "rotation_period": dig_any(rotation, "rotation_period") or None,
        "rotation_period_days": (
            rotation_period_seconds // _SECONDS_PER_DAY
            if rotation_period_seconds is not None
            else None
        ),
        "next_rotation_time": next_rotation,
        # A scheduled rotation whose time has passed means the schedule is not
        # actually firing — "configured" alone would report that as healthy.
        "rotation_overdue": bool(next_rotation_at and next_rotation_at < now),
        "notification_topic_count": len(dig_any(secret, "topics") or []),
        "version_destroy_ttl": dig_any(secret, "version_destroy_ttl") or None,
        # --- lifecycle ---
        "expire_time": expire_time,
        "has_expiry": expire_time is not None,
        "expired": bool(expires_at and expires_at < now),
        # --- versions (state only, never data) ---
        "version_count": len(version_records),
        "version_states": state_counts,
        "enabled_version_count": len(enabled),
        "latest_enabled_version_create_time": enabled[-1]["create_time"] if enabled else None,
        "versions": version_records,
        # --- access ---
        "iam_policy_bindings": binding_records,
        "publicly_accessible": bool(public_members),
        "public_access_members": public_members,
    }


def summarize(secrets: list[dict], *, api_readable: bool = True) -> dict:
    rotating = [s for s in secrets if s["rotation_configured"]]
    cmek = sum(1 for s in secrets if s["cmek"])
    within_max = sum(
        1
        for s in rotating
        if s["rotation_period_days"] is not None
        and s["rotation_period_days"] <= _MAX_ROTATION_PERIOD_DAYS
    )
    periods = [s["rotation_period_days"] for s in rotating if s["rotation_period_days"] is not None]
    versions = [v for s in secrets for v in s["versions"]]
    return {
        # False when secretmanager.googleapis.com is not enabled (recorded in
        # metadata.skipped_calls) — "no secrets" and "could not look" are different.
        "secret_manager_api_readable": api_readable,
        "total_secrets": len(secrets),
        "secrets_with_rotation": len(rotating),
        "rotation_percentage": coverage_percentage(len(rotating), len(secrets)),
        "max_rotation_period_days": _MAX_ROTATION_PERIOD_DAYS,
        "secrets_rotating_within_max_period": within_max,
        "secrets_with_overdue_rotation": sum(1 for s in secrets if s["rotation_overdue"]),
        "longest_rotation_period_days": max(periods) if periods else None,
        "cmek_secrets": cmek,
        "google_managed_secrets": len(secrets) - cmek,
        "cmek_percentage": coverage_percentage(cmek, len(secrets)),
        "automatic_replication_secrets": sum(
            1 for s in secrets if s["replication_policy"] == "automatic"
        ),
        "user_managed_replication_secrets": sum(
            1 for s in secrets if s["replication_policy"] == "user_managed"
        ),
        "replica_locations": sorted({loc for s in secrets for loc in s["replica_locations"]}),
        "publicly_accessible_secrets": sum(1 for s in secrets if s["publicly_accessible"]),
        "non_public_secret_percentage": coverage_percentage(
            len(secrets) - sum(1 for s in secrets if s["publicly_accessible"]), len(secrets)
        ),
        "secrets_with_expiry": sum(1 for s in secrets if s["has_expiry"]),
        "secrets_with_no_enabled_version": sum(
            1 for s in secrets if s["enabled_version_count"] == 0
        ),
        "total_versions": len(versions),
        "enabled_versions": sum(1 for v in versions if v["state"] == "ENABLED"),
        "disabled_versions": sum(1 for v in versions if v["state"] == "DISABLED"),
        "destroyed_versions": sum(1 for v in versions if v["state"] == "DESTROYED"),
    }


# --- collection ---

def policy_bindings(policy) -> list[dict]:
    """google.iam.v1.Policy → sorted {role, members} dicts.

    An IAM policy comes back as a raw protobuf, not a proto-plus message, so it has
    no to_dict(); reading the two fields that matter beats pulling in json_format.
    Duplicated in the IAM service-accounts fetcher: fetchers do not import each other.
    """
    return sorted(
        ({"role": b.role, "members": sorted(b.members)} for b in policy.bindings),
        key=lambda b: b["role"] or "",
    )


def collect_secrets(project, creds, collector: Collector, now: datetime) -> list[dict] | None:
    """Every secret in the project, or None when Secret Manager could not be read.

    Never AccessSecretVersion: ListSecrets, then ListSecretVersions and GetIamPolicy.
    """
    from google.cloud import secretmanager

    # One client for the whole run: a fresh one per call opens a new gRPC channel.
    client = collector.guard(
        "secretmanager.client",
        lambda: secretmanager.SecretManagerServiceClient(credentials=creds),
    )
    if client is None:
        return None

    def _list():
        # The GAPIC pager iterates every page; no manual page-token loop.
        return [
            secretmanager.Secret.to_dict(s, use_integers_for_enums=False)
            for s in client.list_secrets(request={"parent": f"projects/{project}"})
        ]

    # A project that has never used Secret Manager has the API disabled and the
    # call 403s rather than returning an empty list — evidence, not a failure.
    secrets = collector.guard(
        "secretmanager.secrets.list", _list, tolerate=service_disabled
    )
    if secrets is None:
        return None

    records = []
    for secret in secrets:
        resource = dig_any(secret, "name")
        name = basename(resource)

        def _versions(resource=resource):
            return [
                secretmanager.SecretVersion.to_dict(v, use_integers_for_enums=False)
                for v in client.list_secret_versions(request={"parent": resource})
            ]

        def _policy(resource=resource):
            return policy_bindings(client.get_iam_policy(request={"resource": resource}))

        versions = collector.guard(
            f"secretmanager.secrets.versions.list ({name})", _versions, default=[]
        )
        bindings = collector.guard(
            f"secretmanager.secrets.getIamPolicy ({name})", _policy, default=[]
        )
        records.append(secret_record(secret, versions, bindings, now))
    return sorted(records, key=lambda r: r.get("name") or "")


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

    secrets: list[dict] | None = None
    if project and creds is not None:
        secrets = collect_secrets(project, creds, collector, now)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"secrets": secrets or []},
        summary=summarize(secrets or [], api_readable=secrets is not None),
    )

    filename = (
        f"gcp_secret_manager_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
