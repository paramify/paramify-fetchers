#!/usr/bin/env python3
"""
KSI-IAM-02 / KSI-IAM-04 / KSI-SVC-04: GitHub organization security settings.

Reports the organization-level posture that every repository inherits: whether
two-factor authentication is required of all members, the default (base)
repository permission, member and outside-collaborator counts, who may create
and delete repositories, private-repository forking, SAML SSO state where the
token can see it, and the code-security defaults applied to newly created
repositories (Advanced Security, secret scanning, push protection, Dependabot).

These settings are the ceiling on every repository's posture — a repo cannot be
safer than an org that lets any member create public repositories with write
access as the base permission.

Field projection ported from Prowler (Apache-2.0), master:
  prowler/providers/github/services/organization/organization_service.py
    -> the `Org` model: mfa_required, base_permission, members_can_create_*,
       members_allowed_repository_creation_type, members_can_delete_repositories,
       is_verified.
  prowler/providers/github/services/organization/organization_*/ (5 checks:
    members_mfa_required, default_repository_permission_strict,
    repository_creation_limited, repository_deletion_limited, verified_badge)
Extends that projection with the fields Prowler's model omits but the control
story needs: member / outside-collaborator counts, private-repo forking, SAML
SSO state, and the new-repository code-security defaults.

Single-organization per invocation; fanout across organizations happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from github_common import (  # noqa: E402
    Collector,
    ConfigError,
    GitHubAPIError,
    build_payload,
    get_env,
    github_get,
    register_redaction,
    resolve_organization,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("github_organization_security_settings")

# Fields copied straight through from GET /orgs/{org}. Every one of them needs
# organization Administration:Read (or org-owner) — with a weaker token GitHub
# returns the public subset and simply omits these keys, which is why absence is
# reported as null plus settings_visible: false, never as "disabled".
MEMBER_POLICY_FIELDS = (
    "default_repository_permission",
    "members_can_create_repositories",
    "members_can_create_public_repositories",
    "members_can_create_private_repositories",
    "members_can_create_internal_repositories",
    "members_allowed_repository_creation_type",
    "members_can_create_pages",
    "members_can_create_public_pages",
    "members_can_create_private_pages",
    "members_can_delete_repositories",
    "members_can_fork_private_repositories",
    "web_commit_signoff_required",
)

# Defaults GitHub applies to NEWLY created repositories in this org — the
# central-configuration lever (KSI-SVC-04): turning these on means every future
# repo starts compliant instead of being fixed one at a time.
NEW_REPOSITORY_DEFAULT_FIELDS = (
    "advanced_security_enabled_for_new_repositories",
    "dependabot_alerts_enabled_for_new_repositories",
    "dependabot_security_updates_enabled_for_new_repositories",
    "dependency_graph_enabled_for_new_repositories",
    "secret_scanning_enabled_for_new_repositories",
    "secret_scanning_push_protection_enabled_for_new_repositories",
    "secret_scanning_push_protection_custom_link_enabled",
    "secret_scanning_validity_checks_enabled",
)

# Base repository permissions, weakest to strongest. "read" or "none" is the
# least-privilege end; "write" or "admin" as an org-wide default means every
# member can push to every repository.
PERMISSION_RANK = {"none": 0, "read": 1, "triage": 2, "write": 3, "maintain": 4, "admin": 5}
STRICT_BASE_PERMISSIONS = {"none", "read"}


# --- pure transforms (operate on REST response dicts; unit-tested from fixtures) ---

def organization_record(org: Dict[str, Any]) -> Dict[str, Any]:
    """Project GET /orgs/{org} into the evidence record."""
    record: Dict[str, Any] = {
        "login": org.get("login"),
        "id": org.get("id"),
        "name": org.get("name"),
        "created_at": org.get("created_at"),
        "is_verified": org.get("is_verified"),
        "two_factor_requirement_enabled": org.get("two_factor_requirement_enabled"),
        "public_repositories": org.get("public_repos"),
        "total_private_repositories": org.get("total_private_repos"),
        "owned_private_repositories": org.get("owned_private_repos"),
        "plan": (org.get("plan") or {}).get("name"),
        "plan_seats": (org.get("plan") or {}).get("seats"),
        "plan_filled_seats": (org.get("plan") or {}).get("filled_seats"),
    }
    for field in MEMBER_POLICY_FIELDS + NEW_REPOSITORY_DEFAULT_FIELDS:
        record[field] = org.get(field)

    # Normalized lowercase copy: GitHub has returned this both cased and
    # uncased over time, and Prowler lowercases it before comparing.
    base = record.get("default_repository_permission")
    record["default_repository_permission"] = base.lower() if isinstance(base, str) else base

    # `two_factor_requirement_enabled` is the sentinel for "did the token get the
    # admin view?" — it is the field that vanishes first without Administration:Read.
    record["settings_visible"] = org.get("two_factor_requirement_enabled") is not None
    return record


def repository_creation_restricted(record: Dict[str, Any]) -> Optional[bool]:
    """True when members cannot freely create repositories.

    Two spellings coexist: the boolean `members_can_create_repositories` and the
    older `members_allowed_repository_creation_type` ("all" / "private" / "none").
    Prowler's repository_creation_limited check reads the booleans; both are
    honored here so an org on either shape reports the same posture.
    """
    creation_type = record.get("members_allowed_repository_creation_type")
    if isinstance(creation_type, str):
        return creation_type.lower() == "none"
    can_create = record.get("members_can_create_repositories")
    if can_create is None:
        return None
    return not can_create


def summarize(
    record: Dict[str, Any],
    *,
    member_count: Optional[int],
    outside_collaborator_count: Optional[int],
    members_without_2fa: Optional[int],
    sso: Dict[str, Any],
) -> Dict[str, Any]:
    base = record.get("default_repository_permission")
    return {
        # --- KSI-IAM-02: MFA required of every member -----------------------
        "two_factor_required_for_all_members": record.get("two_factor_requirement_enabled"),
        "members_without_two_factor": members_without_2fa,
        # --- KSI-IAM-04: least privilege ------------------------------------
        "default_repository_permission": base,
        "default_repository_permission_is_strict": (
            base in STRICT_BASE_PERMISSIONS if isinstance(base, str) else None
        ),
        "repository_creation_restricted": repository_creation_restricted(record),
        "repository_deletion_restricted": (
            None
            if record.get("members_can_delete_repositories") is None
            else not record["members_can_delete_repositories"]
        ),
        "public_repository_creation_allowed": record.get("members_can_create_public_repositories"),
        "private_repository_forking_allowed": record.get("members_can_fork_private_repositories"),
        "member_count": member_count,
        "outside_collaborator_count": outside_collaborator_count,
        "sso_state": sso.get("state"),
        "sso_authorized_credentials": sso.get("authorized_credentials"),
        # --- KSI-SVC-04: centrally enforced configuration -------------------
        "advanced_security_default_enabled": record.get(
            "advanced_security_enabled_for_new_repositories"
        ),
        "secret_scanning_default_enabled": record.get(
            "secret_scanning_enabled_for_new_repositories"
        ),
        "push_protection_default_enabled": record.get(
            "secret_scanning_push_protection_enabled_for_new_repositories"
        ),
        "dependabot_alerts_default_enabled": record.get(
            "dependabot_alerts_enabled_for_new_repositories"
        ),
        "web_commit_signoff_required": record.get("web_commit_signoff_required"),
        "organization_verified": record.get("is_verified"),
        "settings_visible": record.get("settings_visible"),
    }


# --- collection ------------------------------------------------------------ #

def count_collection(path: str, token: str, collector: Collector) -> Optional[int]:
    """Total entries in a paginated collection, counting only.

    Member and collaborator LOGINS are deliberately not written into evidence —
    the control question is "how many", and a roster of usernames is personal
    data this evidence set has no reason to carry.
    """
    def _get() -> int:
        return len(github_get(path, token=token) or [])

    return collector.guard(f"GET {path}", _get, default=None)


def count_members_without_2fa(org: str, token: str, collector: Collector) -> Optional[int]:
    """Members with 2FA disabled — org-owner-only visibility.

    `filter=2fa_disabled` is rejected (403/422) for a token that is not an owner,
    and GitHub also rejects it while the org enforces 2FA in some
    configurations. Those are "not visible", not collection failures, so they
    return None instead of failing the run.
    """
    path = f"/orgs/{org}/members"

    def _get() -> Optional[int]:
        try:
            return len(github_get(path, token=token, params={"filter": "2fa_disabled"}) or [])
        except GitHubAPIError as exc:
            if exc.status in (403, 404, 422):
                logger.info(
                    "2FA-disabled member count not visible to this token (HTTP %s); reporting null",
                    exc.status,
                )
                return None
            raise

    return collector.guard(f"GET {path}?filter=2fa_disabled", _get, default=None)


def fetch_sso_state(org: str, token: str, collector: Collector) -> Dict[str, Any]:
    """SAML SSO state, as far as the REST API exposes it.

    There is no `saml_enabled` field on GET /orgs/{org}: the only read-only REST
    signal is the SAML SSO credential-authorization list, which exists (200) when
    SAML SSO is configured and 404s when it is not. Whether SSO is *enforced*
    versus merely configured is visible only via GraphQL, so this reports what it
    can and labels the rest honestly rather than guessing:

      configured     - SAML SSO is set up (200, with the authorized-credential count)
      not_configured - 404: no SAML SSO on this organization
      not_visible    - 403: the token is not an org owner, so state is unknown
    """
    path = f"/orgs/{org}/credential-authorizations"

    def _get() -> Dict[str, Any]:
        try:
            credentials = github_get(path, token=token) or []
            return {"state": "configured", "authorized_credentials": len(credentials)}
        except GitHubAPIError as exc:
            if exc.status == 404:
                return {"state": "not_configured", "authorized_credentials": None}
            if exc.status == 403:
                return {"state": "not_visible", "authorized_credentials": None}
            raise

    return collector.guard(
        f"GET {path}", _get, default={"state": "unknown", "authorized_credentials": None}
    )


def collect(org: str, token: str, collector: Collector) -> Dict[str, Any]:
    path = f"/orgs/{org}"
    org_data = collector.guard(f"GET {path}", lambda: github_get(path, token=token), default=None)

    record = organization_record(org_data if isinstance(org_data, dict) else {"login": org})
    member_count = count_collection(f"/orgs/{org}/members", token, collector)
    outside = count_collection(f"/orgs/{org}/outside_collaborators", token, collector)
    without_2fa = count_members_without_2fa(org, token, collector)
    sso = fetch_sso_state(org, token, collector) or {"state": "unknown"}

    record["member_count"] = member_count
    record["outside_collaborator_count"] = outside
    record["members_without_two_factor"] = without_2fa
    record["saml_sso"] = sso

    return {
        "results": {"organization": record},
        "summary": summarize(
            record,
            member_count=member_count,
            outside_collaborator_count=outside,
            members_without_2fa=without_2fa,
            sso=sso,
        ),
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner + secret
    # resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    org_info = resolve_organization(collector)
    organization = org_info["organization"]

    token = None
    try:
        token = get_env("GITHUB_TOKEN")
        register_redaction(token)
    except ConfigError as exc:
        collector.record("resolve_github_token", exc)

    if organization and token:
        collected = collect(organization, token, collector)
    else:
        empty = organization_record({"login": organization} if organization else {})
        collected = {
            "results": {"organization": empty},
            "summary": summarize(
                empty,
                member_count=None,
                outside_collaborator_count=None,
                members_without_2fa=None,
                sso={"state": "unknown", "authorized_credentials": None},
            ),
        }

    evidence = build_payload(
        organization=organization,
        organization_source=org_info["organization_source"],
        collector=collector,
        results=collected["results"],
        summary=collected["summary"],
    )

    filename = (
        f"github_organization_security_settings_{sanitize_for_filename(organization or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        logger.error(
            "Encountered %d GitHub API failure(s) during collection; partial evidence written to %s",
            len(collector.failures),
            path,
        )
        write_status(collector.status_error, collector.status_code)
        return 1

    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
