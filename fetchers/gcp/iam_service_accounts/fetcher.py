#!/usr/bin/env python3
"""
KSI-IAM-SNU / KSI-IAM-ELP / KSI-SVC-ASM: GCP IAM Service Accounts & Keys

For each service account in one project: its key inventory split by key type, the
project-level roles it holds, and who can impersonate it. The finding it exists to
surface is the user-managed key that never rotates — a downloaded private key with
a ~10-year validity, where a system-managed key is rotated by Google. Key material
is never copied (`list_service_account_keys` can carry public_key_data), and human
members are counted rather than enumerated, so this file does not quietly become a
user inventory.

Ported from Prowler's GCP IAM service (Apache-2.0).
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
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_iam_service_accounts")

# The CIS rotation interval for a user-managed key, and the age the summary counts
# against. A validator can pick a different threshold from the per-key age_days.
_ROTATION_AGE_DAYS = 90

# Primitive (pre-IAM) roles; owner and editor are write-capable project-wide.
_PRIMITIVE_ROLES = frozenset({"roles/owner", "roles/editor", "roles/viewer"})
_WRITE_PRIMITIVE_ROLES = frozenset({"roles/owner", "roles/editor"})

# Granting these project-wide lets any holder act as (or mint tokens for) every
# service account in the project — Prowler's iam_no_service_roles_at_project_level.
_IMPERSONATION_ROLES = frozenset(
    {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"}
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


def is_over_broad_role(role: str) -> bool:
    """Prowler's administrative-privilege rule: owner/editor, or any *admin* role."""
    return role in _WRITE_PRIMITIVE_ROLES or "admin" in role.lower()


def key_record(key: dict, now: datetime) -> dict:
    """Normalize one service-account key into an evidence record.

    A `valid_before_time` in the year 9999 is the API's way of saying the key
    never expires.
    """
    valid_after = parse_timestamp(dig_any(key, "valid_after_time"))
    valid_before = parse_timestamp(dig_any(key, "valid_before_time"))
    key_type = dig_any(key, "key_type") or None
    return {
        "id": basename(dig_any(key, "name")),
        "key_type": key_type,
        "user_managed": key_type == "USER_MANAGED",
        "key_origin": dig_any(key, "key_origin") or None,
        "key_algorithm": dig_any(key, "key_algorithm") or None,
        "disabled": bool(dig_any(key, "disabled")),
        "valid_after_time": dig_any(key, "valid_after_time") or None,
        "valid_before_time": dig_any(key, "valid_before_time") or None,
        "age_days": (now - valid_after).days if valid_after else None,
        "expires_in_days": (valid_before - now).days if valid_before else None,
        "never_expires": bool(valid_before and valid_before.year >= 9999),
    }


def service_account_record(
    account: dict,
    keys: list[dict],
    sa_bindings: list[dict],
    project_bindings: list[dict],
    now: datetime,
) -> dict:
    """Normalize one service account, its keys, and its privilege posture."""
    email = dig_any(account, "email")
    member = f"serviceAccount:{email}"

    project_roles = sorted(b["role"] for b in project_bindings if member in b["members"])
    key_records = sorted(
        (key_record(k, now) for k in keys),
        key=lambda k: (k["valid_after_time"] or "", k["id"] or ""),
    )
    user_managed = [k for k in key_records if k["user_managed"]]
    ages = [k["age_days"] for k in user_managed if k["age_days"] is not None]
    impersonators = sorted(
        {m for b in sa_bindings if b["role"] in _IMPERSONATION_ROLES for m in b["members"]}
    )

    return {
        "email": email,
        "display_name": dig_any(account, "display_name") or None,
        "description": dig_any(account, "description") or None,
        "unique_id": dig_any(account, "unique_id") or None,
        "disabled": bool(dig_any(account, "disabled")),
        "keys": key_records,
        "user_managed_key_count": len(user_managed),
        "system_managed_key_count": len(key_records) - len(user_managed),
        "oldest_user_managed_key_age_days": max(ages) if ages else None,
        "user_managed_keys_past_rotation_age": sum(
            1 for age in ages if age > _ROTATION_AGE_DAYS
        ),
        "project_roles": project_roles,
        "primitive_project_roles": [r for r in project_roles if r in _PRIMITIVE_ROLES],
        "over_broad_project_roles": [r for r in project_roles if is_over_broad_role(r)],
        "has_over_broad_project_role": any(is_over_broad_role(r) for r in project_roles),
        "iam_policy_bindings": sa_bindings,
        "impersonation_members": impersonators,
        "impersonable": bool(impersonators),
    }


def project_binding_record(binding: dict) -> dict:
    """One project-level IAM binding, service accounts named and users counted."""
    members = binding.get("members") or []
    service_accounts = sorted(m for m in members if m.startswith("serviceAccount:"))
    return {
        "role": binding.get("role"),
        "member_count": len(members),
        "service_account_members": service_accounts,
        "other_member_count": len(members) - len(service_accounts),
        "primitive_role": binding.get("role") in _PRIMITIVE_ROLES,
        "over_broad_role": is_over_broad_role(binding.get("role") or ""),
        "impersonation_role": binding.get("role") in _IMPERSONATION_ROLES,
    }


def summarize(accounts: list[dict], project_bindings: list[dict]) -> dict:
    with_user_keys = sum(1 for a in accounts if a["user_managed_key_count"])
    without_user_keys = len(accounts) - with_user_keys
    all_keys = [k for a in accounts for k in a["keys"]]
    user_keys = [k for k in all_keys if k["user_managed"]]
    key_ages = [k["age_days"] for k in user_keys if k["age_days"] is not None]
    return {
        "total_service_accounts": len(accounts),
        "disabled_service_accounts": sum(1 for a in accounts if a["disabled"]),
        "service_accounts_with_user_managed_keys": with_user_keys,
        "service_accounts_without_user_managed_keys": without_user_keys,
        # The posture to evidence: no downloaded private keys anywhere.
        "no_user_managed_key_percentage": coverage_percentage(
            without_user_keys, len(accounts)
        ),
        "user_managed_key_count": len(user_keys),
        "system_managed_key_count": len(all_keys) - len(user_keys),
        "user_managed_keys_past_rotation_age": sum(
            1 for age in key_ages if age > _ROTATION_AGE_DAYS
        ),
        "rotation_age_days": _ROTATION_AGE_DAYS,
        "oldest_user_managed_key_age_days": max(key_ages) if key_ages else None,
        "never_expiring_user_managed_keys": sum(1 for k in user_keys if k["never_expires"]),
        "disabled_user_managed_keys": sum(1 for k in user_keys if k["disabled"]),
        "service_accounts_with_over_broad_roles": sum(
            1 for a in accounts if a["has_over_broad_project_role"]
        ),
        "service_accounts_with_primitive_roles": sum(
            1 for a in accounts if a["primitive_project_roles"]
        ),
        "impersonable_service_accounts": sum(1 for a in accounts if a["impersonable"]),
        "total_project_role_bindings": len(project_bindings),
        "over_broad_project_role_bindings": sum(
            1 for b in project_bindings if is_over_broad_role(b.get("role") or "")
        ),
        "project_wide_impersonation_bindings": sum(
            1 for b in project_bindings if b.get("role") in _IMPERSONATION_ROLES
        ),
    }


# --- collection ---

def policy_bindings(policy) -> list[dict]:
    """google.iam.v1.Policy → sorted {role, members} dicts.

    An IAM policy comes back as a raw protobuf, not a proto-plus message, so it
    has no to_dict(). Conditional bindings collapse to their role — the condition
    expression is not part of this evidence set.
    """
    return sorted(
        ({"role": b.role, "members": sorted(b.members)} for b in policy.bindings),
        key=lambda b: b["role"] or "",
    )


def collect_project_bindings(project, creds, collector: Collector) -> list[dict]:
    from google.cloud import resourcemanager_v3

    def _get():
        client = resourcemanager_v3.ProjectsClient(credentials=creds)
        return policy_bindings(client.get_iam_policy(resource=f"projects/{project}"))

    return collector.guard("cloudresourcemanager.projects.getIamPolicy", _get, default=[])


def collect_service_accounts(
    project, creds, collector: Collector, project_bindings: list[dict], now: datetime
) -> list[dict]:
    from google.cloud import iam_admin_v1

    # One client for the whole run: keys and the policy are read per service
    # account, and a fresh client would open a gRPC channel per call.
    client = collector.guard(
        "iam.client", lambda: iam_admin_v1.IAMClient(credentials=creds)
    )
    if client is None:
        return []

    def _list():
        # The GAPIC pager iterates every page; no manual page-token loop.
        return [
            iam_admin_v1.ServiceAccount.to_dict(sa, use_integers_for_enums=False)
            for sa in client.list_service_accounts(name=f"projects/{project}")
        ]

    accounts = collector.guard("iam.serviceAccounts.list", _list, default=[])

    records = []
    for account in accounts:
        resource = dig_any(account, "name")
        email = dig_any(account, "email")

        def _keys(resource=resource):
            response = client.list_service_account_keys(name=resource)
            return [
                iam_admin_v1.ServiceAccountKey.to_dict(k, use_integers_for_enums=False)
                for k in response.keys
            ]

        # The "act as this service account" binding lives on the SA, not the project policy.
        def _policy(resource=resource):
            return policy_bindings(client.get_iam_policy(resource=resource))

        keys = collector.guard(f"iam.serviceAccounts.keys.list ({email})", _keys, default=[])
        sa_bindings = collector.guard(
            f"iam.serviceAccounts.getIamPolicy ({email})", _policy, default=[]
        )
        records.append(
            service_account_record(account, keys, sa_bindings, project_bindings, now)
        )
    return sorted(records, key=lambda r: r.get("email") or "")


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

    accounts: list[dict] = []
    project_bindings: list[dict] = []
    if project and creds is not None:
        # Project bindings first: each service account's roles are derived from them.
        project_bindings = collect_project_bindings(project, creds, collector)
        accounts = collect_service_accounts(project, creds, collector, project_bindings, now)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={
            "service_accounts": accounts,
            "project_role_bindings": [project_binding_record(b) for b in project_bindings],
        },
        summary=summarize(accounts, project_bindings),
    )

    filename = f"gcp_iam_service_accounts_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
