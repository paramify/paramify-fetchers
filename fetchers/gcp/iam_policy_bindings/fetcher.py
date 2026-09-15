#!/usr/bin/env python3
"""
GCP Project IAM Policy Bindings

The "who has what access" evidence set for one GCP project: every binding in the
project's IAM policy with its role and members, rolled up a second time per
principal so the policy can be read either way, plus whether Cloud Audit Logging
is configured and who is exempted from it.

Ported from Prowler's GCP Cloud Resource Manager service (Apache-2.0).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    access_denied,
    build_payload,
    coverage_percentage,
    credentials,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_iam_policy_bindings")

# GCP allows at most 10 folder levels between a project and its organization, so the
# ancestry walk is bounded by the platform rather than by a guess.
_MAX_ANCESTRY_DEPTH = 10

# allUsers is the entire internet; allAuthenticatedUsers is every Google account.
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})

# Primitive (pre-IAM) roles. Broad by construction — owner and editor are
# write-capable across every service in the project.
_PRIMITIVE_ROLES = frozenset({"roles/owner", "roles/editor", "roles/viewer"})
_WRITE_PRIMITIVE_ROLES = frozenset({"roles/owner", "roles/editor"})

# Consumer Google accounts. CIS GCP 1.1 wants corporate credentials only, so a
# personal account holding a project role is a finding whether or not the
# organization domain resolved.
_CONSUMER_DOMAINS = frozenset({"gmail.com", "googlemail.com"})

# The member prefixes IAM defines. Anything else buckets to "other", so a new
# principal type shows up as unclassified rather than silently mis-typed.
_MEMBER_TYPES = frozenset(
    {
        "user",
        "serviceAccount",
        "group",
        "domain",
        "projectOwner",
        "projectEditor",
        "projectViewer",
        "principal",
        "principalSet",
        "principalHierarchy",
        "federatedIdentity",
    }
)

# Service-account email domains that belong to Google, not to a customer project:
# a service agent is created by ENABLING AN API, so counting it as an external or
# cross-project grant would bury the real findings in noise.
_GOOGLE_SERVICE_AGENT_DOMAIN_MARKERS = (
    # service-<projectnumber>@gcp-sa-<api>.iam.gserviceaccount.com
    "gcp-sa-",
    "cloudservices.gserviceaccount.com",
    "system.gserviceaccount.com",
    "containerregistry.iam.gserviceaccount.com",
    "container-engine-robot.iam.gserviceaccount.com",
)

_SERVICE_ACCOUNT_DOMAIN_SUFFIXES = (
    ".iam.gserviceaccount.com",
    ".appspot.gserviceaccount.com",
    ".developer.gserviceaccount.com",
)

# The log types CIS GCP 2.1 wants on `allServices` for project-wide audit logging.
_FULL_AUDIT_LOG_TYPES = frozenset({"ADMIN_READ", "DATA_READ", "DATA_WRITE"})

# google.iam.v1.AuditLogConfig.LogType — the fallback in `audit_log_type_name`.
_AUDIT_LOG_TYPE_NAMES = {
    0: "LOG_TYPE_UNSPECIFIED",
    1: "ADMIN_READ",
    2: "DATA_WRITE",
    3: "DATA_READ",
}


# --- pure transforms ---

def is_over_broad_role(role: str) -> bool:
    """Prowler's administrative-privilege rule: owner/editor, or any *admin* role.

    Identical to the sibling gcp_iam_service_accounts rule, so both evidence sets
    classify a given role the same way.
    """
    return role in _WRITE_PRIMITIVE_ROLES or "admin" in role.lower()


def member_type(member: str) -> str:
    """The IAM principal type of a member string.

    `deleted:user:a@b.com?uid=1` reports as `deleted_user`: a binding left pointing
    at a deleted identity is worth seeing, but it is not a live grant.
    """
    if member in _PUBLIC_MEMBERS:
        return "public"
    deleted = member.startswith("deleted:")
    body = member[len("deleted:"):] if deleted else member
    prefix = body.split(":", 1)[0] if ":" in body else "unknown"
    kind = prefix if prefix in _MEMBER_TYPES else "other"
    return f"deleted_{kind}" if deleted else kind


def member_domain(member: str) -> str | None:
    """The email/domain part of a member, or None when it doesn't carry one.

    `domain:example.com` IS its domain; a `principalSet://` workload identity has none.
    """
    if member in _PUBLIC_MEMBERS:
        return None
    body = member[len("deleted:"):] if member.startswith("deleted:") else member
    prefix, _, identity = body.partition(":")
    if not identity:
        return None
    # A deleted member carries a ?uid= suffix that is not part of the domain.
    identity = identity.split("?", 1)[0].lower()
    if prefix == "domain":
        return identity or None
    if "@" in identity:
        return identity.rsplit("@", 1)[-1] or None
    return None


def is_google_service_agent(member: str) -> bool:
    """True for one of Google's own service agents (not a customer identity)."""
    domain = member_domain(member) or ""
    return any(marker in domain for marker in _GOOGLE_SERVICE_AGENT_DOMAIN_MARKERS)


def service_account_project(member: str) -> str | None:
    """The project that owns a `serviceAccount:` member, from its email domain."""
    domain = member_domain(member) or ""
    for suffix in _SERVICE_ACCOUNT_DOMAIN_SUFFIXES:
        if domain.endswith(suffix):
            return domain[: -len(suffix)] or None
    return None


def is_consumer_account(member: str) -> bool:
    """CIS GCP 1.1: a personal Google account holding a role in the project."""
    return (member_domain(member) or "") in _CONSUMER_DOMAINS


def is_external(member: str, org_domain: str | None) -> bool:
    """True for a human/group/domain identity outside the organization's domain.

    With no org domain to compare against, everything reports False and the summary
    says the evaluation didn't happen rather than implying "no external members".
    Service accounts never live on the org domain, so
    `is_cross_project_service_account` is their question instead.
    """
    if not org_domain or member in _PUBLIC_MEMBERS:
        return False
    if member_type(member) not in ("user", "group", "domain", "deleted_user", "deleted_group"):
        return False
    domain = member_domain(member)
    if not domain:
        return False
    org_domain = org_domain.lower().lstrip(".")
    return not (domain == org_domain or domain.endswith(f".{org_domain}"))


def is_cross_project_service_account(member: str, project: str | None) -> bool:
    """True for a service account owned by some other project.

    A cross-project grant is both a legitimate pattern (a shared CI account) and a
    real finding (an account nobody here controls), so it is reported rather than
    judged. Google's own service agents are excluded.
    """
    if member_type(member) not in ("serviceAccount", "deleted_serviceAccount"):
        return False
    if is_google_service_agent(member):
        return False
    owner = service_account_project(member)
    return bool(owner and project and owner != project)


def condition_record(condition: dict | None) -> dict | None:
    """An IAM condition, verbatim. None when the binding is unconditional."""
    if not condition:
        return None
    return {
        "title": condition.get("title") or None,
        "description": condition.get("description") or None,
        "expression": condition.get("expression") or None,
    }


def binding_record(binding: dict, org_domain: str | None, project: str | None) -> dict:
    """Normalize one project IAM policy binding into an evidence record."""
    role = binding.get("role") or ""
    members = sorted(set(binding.get("members") or []))
    types: dict[str, int] = {}
    for member in members:
        kind = member_type(member)
        types[kind] = types.get(kind, 0) + 1

    service_accounts = [m for m in members if member_type(m).endswith("serviceAccount")]
    public = [m for m in members if m in _PUBLIC_MEMBERS]
    over_broad = is_over_broad_role(role)

    return {
        "role": role,
        "primitive_role": role in _PRIMITIVE_ROLES,
        "over_broad_role": over_broad,
        "member_count": len(members),
        "members": members,
        "member_types": dict(sorted(types.items())),
        "public_members": public,
        "publicly_granted": bool(public),
        "service_account_members": service_accounts,
        # Prowler's iam_sa_no_administrative_privileges, at the binding level.
        "service_account_granted_over_broad_role": bool(over_broad and service_accounts),
        "external_members": [m for m in members if is_external(m, org_domain)],
        "consumer_account_members": [m for m in members if is_consumer_account(m)],
        "cross_project_service_account_members": [
            m for m in members if is_cross_project_service_account(m, project)
        ],
        "conditional": bool(binding.get("condition")),
        "condition": condition_record(binding.get("condition")),
    }


def principal_record(
    member: str, bindings: list[dict], org_domain: str | None, project: str | None
) -> dict:
    """The same policy read by principal: every role one member holds."""
    held = [b for b in bindings if member in b["members"]]
    roles = sorted({b["role"] for b in held})
    return {
        "member": member,
        "member_type": member_type(member),
        "domain": member_domain(member),
        "service_account_project": service_account_project(member),
        "role_count": len(roles),
        "roles": roles,
        "primitive_roles": [r for r in roles if r in _PRIMITIVE_ROLES],
        "over_broad_roles": [r for r in roles if is_over_broad_role(r)],
        "has_over_broad_role": any(is_over_broad_role(r) for r in roles),
        "public": member in _PUBLIC_MEMBERS,
        "external": is_external(member, org_domain),
        "consumer_account": is_consumer_account(member),
        "cross_project_service_account": is_cross_project_service_account(member, project),
        "google_service_agent": is_google_service_agent(member),
        "conditional_role_count": sum(1 for b in held if b["conditional"]),
    }


def principal_records(
    bindings: list[dict], org_domain: str | None, project: str | None
) -> list[dict]:
    members = sorted({m for b in bindings for m in b["members"]})
    return [principal_record(m, bindings, org_domain, project) for m in members]


def audit_config_record(config: dict) -> dict:
    """One auditConfig: which service is logged, at what log types, minus whom."""
    log_configs = []
    exempted: set[str] = set()
    for entry in config.get("audit_log_configs") or []:
        members = sorted(set(entry.get("exempted_members") or []))
        exempted.update(members)
        log_configs.append(
            {
                "log_type": entry.get("log_type") or None,
                "exempted_members": members,
            }
        )
    log_configs.sort(key=lambda c: c["log_type"] or "")
    return {
        "service": config.get("service") or None,
        "log_types": sorted({c["log_type"] for c in log_configs if c["log_type"]}),
        "log_configs": log_configs,
        "exempted_members": sorted(exempted),
        "exempted_member_count": len(exempted),
    }


def project_record(project_details: dict | None, project_id: str | None) -> dict:
    """The project the policy belongs to. Empty-but-present when the read failed."""
    details = project_details or {}
    name = details.get("name") or ""
    return {
        "project_id": details.get("project_id") or project_id,
        # resourcemanager v3 names a project `projects/<number>`; Prowler reads the
        # same number out of v1's `projectNumber`.
        "project_number": name.split("/")[-1] if name.startswith("projects/") else None,
        "display_name": details.get("display_name") or None,
        "parent": details.get("parent") or None,
        "state": details.get("state") or None,
        "labels": dict(sorted((details.get("labels") or {}).items())) or None,
    }


def summarize(
    bindings: list[dict],
    principals: list[dict],
    audit_configs: list[dict],
    org_domain: str | None,
    domain_source: str,
) -> dict:
    all_services = next((c for c in audit_configs if c["service"] == "allServices"), None)
    all_service_log_types = set(all_services["log_types"]) if all_services else set()
    non_primitive = sum(1 for b in bindings if not b["primitive_role"])

    def holders(role: str) -> int:
        return sum(1 for p in principals if role in p["roles"])

    return {
        "total_bindings": len(bindings),
        "total_roles_granted": len({b["role"] for b in bindings}),
        "total_principals": len(principals),
        "non_primitive_binding_percentage": coverage_percentage(non_primitive, len(bindings)),
        "primitive_role_bindings": len(bindings) - non_primitive,
        "over_broad_role_bindings": sum(1 for b in bindings if b["over_broad_role"]),
        "owner_principals": holders("roles/owner"),
        "editor_principals": holders("roles/editor"),
        "viewer_principals": holders("roles/viewer"),
        "principals_with_over_broad_roles": sum(1 for p in principals if p["has_over_broad_role"]),
        "publicly_granted": any(b["publicly_granted"] for b in bindings),
        "public_bindings": sum(1 for b in bindings if b["publicly_granted"]),
        "public_members": sorted({m for b in bindings for m in b["public_members"]}),
        "service_account_principals": sum(
            1 for p in principals if p["member_type"].endswith("serviceAccount")
        ),
        "service_account_bindings_with_over_broad_roles": sum(
            1 for b in bindings if b["service_account_granted_over_broad_role"]
        ),
        "cross_project_service_account_principals": sum(
            1 for p in principals if p["cross_project_service_account"]
        ),
        "deleted_principals": sum(1 for p in principals if p["member_type"].startswith("deleted_")),
        "organization_domain": org_domain,
        "organization_domain_source": domain_source,
        # False means "not asked", not "none found" — the org read sits outside a
        # project-scoped role.
        "external_members_evaluated": bool(org_domain),
        "external_principals": sum(1 for p in principals if p["external"]),
        "consumer_account_principals": sum(1 for p in principals if p["consumer_account"]),
        "conditional_bindings": sum(1 for b in bindings if b["conditional"]),
        # Prowler's iam_audit_logs_enabled: auditConfigs present on the policy.
        "audit_logging_configured": bool(audit_configs),
        "audit_config_services": sorted(c["service"] for c in audit_configs if c["service"]),
        "audit_all_services_configured": all_services is not None,
        "audit_all_services_log_types": sorted(all_service_log_types),
        "audit_full_log_types_on_all_services": _FULL_AUDIT_LOG_TYPES.issubset(
            all_service_log_types
        ),
        "audit_exempted_member_count": len(
            {m for c in audit_configs for m in c["exempted_members"]}
        ),
    }


# --- collection ---

def _outside_project_scope(exc: BaseException) -> bool:
    """`guard(tolerate=...)` predicate for reads above the project.

    The organization/folder reads that resolve the org domain are not in a
    project-scoped read-only role's grant, and Resource Manager may not be enabled
    at all. The project's policy is complete evidence either way, so these are
    recorded as skipped rather than failing the collection.
    """
    return access_denied(exc) or service_disabled(exc)


def audit_log_type_name(config) -> str | None:
    """Enum name for a google.iam.v1.AuditLogConfig.log_type value.

    An IAM policy comes back as a raw protobuf rather than a proto-plus message, so
    the enum arrives as an int. The message's own enum wrapper knows the names.
    """
    raw = getattr(config, "log_type", None)
    if raw is None:
        return None
    try:
        return config.LogType.Name(raw)
    except Exception:  # noqa: BLE001 — enum lookup is best-effort, never fatal
        return _AUDIT_LOG_TYPE_NAMES.get(int(raw), str(raw))


def policy_dicts(policy) -> tuple[list[dict], list[dict]]:
    """google.iam.v1.Policy → (binding dicts, audit-config dicts).

    Raw protobuf, so there is no to_dict(); reading the handful of fields that matter
    beats pulling in json_format. Conditions are preserved here (the sibling
    service-account fetcher drops them): a conditional binding grants something else.
    """
    bindings = [
        {
            "role": b.role,
            "members": list(b.members),
            "condition": (
                {
                    "title": b.condition.title,
                    "description": b.condition.description,
                    "expression": b.condition.expression,
                }
                if b.HasField("condition")
                else None
            ),
        }
        for b in policy.bindings
    ]
    audit_configs = [
        {
            "service": c.service,
            "audit_log_configs": [
                {
                    "log_type": audit_log_type_name(entry),
                    "exempted_members": list(entry.exempted_members),
                }
                for entry in c.audit_log_configs
            ],
        }
        for c in policy.audit_configs
    ]
    return bindings, audit_configs


def collect_policy(project, creds, collector: Collector) -> tuple[list[dict], list[dict]]:
    """The project's IAM policy at version 3, so conditions come back."""
    from google.cloud import resourcemanager_v3
    from google.iam.v1 import iam_policy_pb2, options_pb2

    def _get():
        client = resourcemanager_v3.ProjectsClient(credentials=creds)
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project}",
            options=options_pb2.GetPolicyOptions(requested_policy_version=3),
        )
        return policy_dicts(client.get_iam_policy(request=request))

    return collector.guard(
        "cloudresourcemanager.projects.getIamPolicy", _get, default=([], [])
    )


def collect_project_details(project, creds, collector: Collector) -> dict:
    from google.cloud import resourcemanager_v3

    def _get():
        client = resourcemanager_v3.ProjectsClient(credentials=creds)
        return resourcemanager_v3.Project.to_dict(
            client.get_project(name=f"projects/{project}"), use_integers_for_enums=False
        )

    return collector.guard("cloudresourcemanager.projects.get", _get, default={}) or {}


def collect_organization_domain(
    parent: str | None, creds, collector: Collector
) -> tuple[str | None, str | None]:
    """Walk up from the project to its organization and read its primary domain.

    An organization's `display_name` IS its primary domain (that is how the resource
    is created), which is what makes "member outside the org" answerable at all.
    """
    from google.cloud import resourcemanager_v3

    depth = 0
    while parent and parent.startswith("folders/") and depth < _MAX_ANCESTRY_DEPTH:
        depth += 1

        def _parent_of_folder(folder=parent):
            client = resourcemanager_v3.FoldersClient(credentials=creds)
            return client.get_folder(name=folder).parent or ""

        parent = collector.guard(
            f"cloudresourcemanager.folders.get ({parent})",
            _parent_of_folder,
            default="",
            tolerate=_outside_project_scope,
        )

    if not parent or not parent.startswith("organizations/"):
        return None, None

    def _org_domain():
        client = resourcemanager_v3.OrganizationsClient(credentials=creds)
        return client.get_organization(name=parent).display_name or ""

    domain = collector.guard(
        f"cloudresourcemanager.organizations.get ({parent})",
        _org_domain,
        default="",
        tolerate=_outside_project_scope,
    )
    return parent, (domain or None)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    # An operator-supplied domain wins: the org lookup needs a permission above the
    # project that a read-only project role doesn't have.
    configured_domain = (os.environ.get("GCP_ORGANIZATION_DOMAIN") or "").strip().lower()

    raw_bindings: list[dict] = []
    raw_audit_configs: list[dict] = []
    details: dict = {}
    organization: str | None = None
    org_domain: str | None = configured_domain or None
    domain_source = "config" if configured_domain else "unresolved"

    if project and creds is not None:
        details = collect_project_details(project, creds, collector)
        raw_bindings, raw_audit_configs = collect_policy(project, creds, collector)
        if not configured_domain:
            organization, resolved = collect_organization_domain(
                details.get("parent"), creds, collector
            )
            if resolved:
                org_domain, domain_source = resolved.lower(), "organization"
        else:
            organization = details.get("parent") or None
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    bindings = sorted(
        (binding_record(b, org_domain, project) for b in raw_bindings),
        key=lambda b: (b["role"], b["condition"]["title"] if b["condition"] else ""),
    )
    principals = principal_records(bindings, org_domain, project)
    audit_configs = sorted(
        (audit_config_record(c) for c in raw_audit_configs),
        key=lambda c: c["service"] or "",
    )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={
            "project": project_record(details, project),
            "organization": {
                "name": organization,
                "domain": org_domain,
                "domain_source": domain_source,
            },
            "bindings": bindings,
            "principals": principals,
            "audit_configs": audit_configs,
        },
        summary=summarize(bindings, principals, audit_configs, org_domain, domain_source),
    )

    filename = f"gcp_iam_policy_bindings_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
