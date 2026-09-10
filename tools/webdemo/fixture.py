"""Synthetic demo workspace for the web demo capture.

The web demo must not ship real evidence: our own runs carry live tenant
identifiers (subscription/tenant/correlation ids, project names, resource
ARNs). So the capture drives the *real* TUI against a *fabricated* workspace —
a throwaway directory that looks exactly like a repo checkout to
`api.find_repo_root` (sibling fetchers/ + framework/) but whose manifests and
evidence describe a fictional "Acme" tenant.

fetchers/ and framework/ are symlinked to the real repo, so the catalog tab
shows the genuine 183-fetcher tree — that is product surface, not tenant data.
Only manifests/ and evidence/ are invented.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

# ── the fictional tenant ─────────────────────────────────────────────────── #

WEST = "prod-us-gov-west"
EAST = "prod-us-gov-east"

AWS_FETCHERS = [
    "aws_iam_mfa_status",
    "aws_iam_password_policy",
    "aws_iam_roles",
    "aws_cloudtrail_configuration",
    "aws_config_monitoring",
    "aws_guard_duty",
    "aws_block_storage_encryption_status",
    "aws_s3_encryption_status",
    "aws_load_balancer_encryption_status",
    "aws_kms_key_rotation",
    "aws_network_acls",
    "aws_security_groups",
]

OKTA_FETCHERS = [
    "okta_phishing_resistant_mfa",
    "okta_authenticators",
    "okta_least_privilege",
    "okta_automated_account_management",
    "okta_suspicious_activity_management",
    "okta_passwordless_authentication",
]

GCP_FETCHERS = [
    "gcp_iam_service_accounts",
    "gcp_cloud_storage_encryption_status",
    "gcp_firewall_rules",
    "gcp_cloud_logging_configuration",
    "gcp_kms_key_configuration",
]

K8S_FETCHERS = ["k8s_eks_pod_inventory", "k8s_kubectl_security"]

AWS_SECRETS = {
    "access_key_id": "${env:AWS_ACCESS_KEY_ID}",
    "secret_access_key": "${env:AWS_SECRET_ACCESS_KEY}",
    "session_token": "${env:AWS_SESSION_TOKEN}",
}


def _aws_entry(use: str, fanout: bool) -> dict:
    entry: dict = {"use": use, "secrets": dict(AWS_SECRETS)}
    if fanout:
        entry["targets"] = [
            {"profile": WEST, "region": "us-gov-west-1"},
            {"profile": EAST, "region": "us-gov-east-1"},
        ]
    return entry


def _manifests(known: set[str]) -> dict[str, dict]:
    """The four manifests the welcome picker lists.

    `known` is the set of fetcher names that actually exist in the catalog, so a
    renamed or removed fetcher shows up as a capture-time error instead of a
    silently invalid demo manifest.
    """

    def keep(names: list[str]) -> list[str]:
        missing = [n for n in names if n not in known]
        if missing:
            raise SystemExit(
                "demo manifests name fetchers that are not in the catalog: "
                + ", ".join(missing)
                + "\nupdate tools/webdemo/fixture.py to the current fetcher names."
            )
        return names

    # The first four AWS entries fan out across both accounts; the rest collect
    # once with the ambient identity. That mix is the point of the run tab —
    # "single" and "fanout" rows side by side.
    aws = [_aws_entry(u, fanout=i < 4) for i, u in enumerate(keep(AWS_FETCHERS))]

    okta = [
        {
            "use": u,
            "secrets": {
                "api_token": "${env:OKTA_API_TOKEN}",
                "org_url": "${env:OKTA_ORG_URL}",
            },
        }
        for u in keep(OKTA_FETCHERS)
    ]

    gcp = [
        {
            "use": u,
            "targets": [
                {"project": "acme-platform-prod", "environment": "prod"},
                {"project": "acme-platform-stage", "environment": "stage"},
            ],
        }
        for u in keep(GCP_FETCHERS)
    ]

    # Deliberately broken: k8s fetchers don't support targets, so `validate`
    # reports one error per entry. The welcome picker needs a manifest that is
    # NOT runnable, or the "âš  N issues" state never appears in the demo.
    k8s = [
        {"use": u, "targets": [{"cluster": "acme-prod-eks"}]}
        for u in keep(K8S_FETCHERS)
    ]

    return {
        "aws-prod.yaml": {"run": {"output_dir": "./evidence", "fetchers": aws}},
        "okta-quarterly.yaml": {"run": {"output_dir": "./evidence", "fetchers": okta}},
        "gcp-baseline.yaml": {"run": {"output_dir": "./evidence", "fetchers": gcp}},
        "k8s-cluster.yaml": {"run": {"output_dir": "./evidence", "fetchers": k8s}},
    }


# ── synthetic evidence ───────────────────────────────────────────────────── #

def _envelope(fetcher: str, run_id: str, target: dict | None, payload,
              exit_code: int = 0, evidence_set: dict | None = None,
              error: str | None = None) -> dict:
    """One evidence file in the standard envelope shape (framework/envelope.py)."""
    md = {
        "fetcher_name": fetcher,
        "fetcher_version": "0.1.0",
        "category": fetcher.split("_")[0],
        "run_id": run_id,
        "target": target or {},
        "collected_at": run_id[:10] + "T" + run_id[11:19].replace("-", ":") + "Z",
        "status": "success" if exit_code == 0 else "error",
        "exit_code": exit_code,
    }
    if evidence_set:
        md["evidence_set"] = evidence_set
    if error:
        md["error"] = error
    return {"schema_version": "1.0", "metadata": md, "payload": payload}


# Two accounts, so the payload is a function of the target rather than a
# constant: the east file must not report west's account id and region.
ACCOUNTS = {"prod-us-gov-west": "210987654321", "prod-us-gov-east": "345678901234"}

_MFA_USERS = [
    ("svc-evidence-collector", "2025-11-04T18:22:09Z", False, 1, "virtual", "2025-11-04T18:24:41Z"),
    ("a.okonkwo", "2025-06-19T14:03:55Z", True, 0, "hardware-fido", "2025-06-19T14:31:02Z"),
    ("r.delacroix", "2025-02-27T09:47:12Z", True, 0, "hardware-fido", "2025-02-27T10:02:38Z"),
    ("j.haverford", "2024-08-15T21:10:44Z", True, 1, "virtual", "2024-08-15T21:26:19Z"),
]


def mfa_payload(account_id: str, region: str) -> dict:
    arn = f"arn:aws-us-gov:iam::{account_id}"
    return {
        "account_id": account_id,
        "collected_region": region,
        "summary": {
            "users_total": 14,
            "users_with_mfa": 14,
            "users_without_mfa": 0,
            "root_mfa_enabled": True,
            "hardware_mfa_root": True,
        },
        "users": [
            {
                "user_name": name,
                "arn": f"{arn}:user/{name}",
                "created": created,
                "password_enabled": console,
                "access_keys": keys,
                "mfa_devices": [
                    {"type": kind, "serial": f"{arn}:mfa/{name}", "enabled_date": enrolled}
                ],
            }
            for name, created, console, keys, kind, enrolled in _MFA_USERS
        ],
        "root_account": {
            "mfa_active": True,
            "mfa_device_type": "hardware-fido",
            "last_used": "2026-07-11T02:14:00Z",
            "access_keys_present": False,
        },
    }


MFA_SET = {
    "reference_id": "EVD-AWS-IAM-MFA",
    "name": "Multi-Factor Authentication Enforcement (IAM)",
    "instructions": (
        "Script: fetcher.sh. AWS CLI calls: iam list-users, iam list-mfa-devices per user, and "
        "iam get-account-summary for the root account. Per user this reports the user name, ARN, "
        "creation date, whether console access is enabled, the number of active access keys, and "
        "every registered MFA device with its type and enrollment date. The root account is "
        "reported separately with its MFA device type and whether long-lived access keys exist. "
        "Zero users without MFA and root_mfa_enabled true is the passing shape."
    ),
}

def cloudtrail_payload(account_id: str) -> dict:
    return {
        "account_id": account_id,
        "trails": [
            {"name": "acme-org-trail", "is_multi_region": True, "is_organization_trail": True,
             "log_file_validation_enabled": True,
             "kms_key_id": f"arn:aws-us-gov:kms:us-gov-west-1:{account_id}:key/"
                           "8f3c1a20-77bd-4e19-9a44-2c0e5d8b6f31",
             "s3_bucket": "acme-audit-logs-usgw1",
             "cloudwatch_logs_group": f"arn:aws-us-gov:logs:us-gov-west-1:{account_id}:"
                                      "log-group:acme-cloudtrail:*",
             "status": {"is_logging": True, "latest_delivery": "2026-09-02T09:13:52Z",
                        "delivery_error": None},
             "event_selectors": [{"read_write_type": "All", "include_management_events": True,
                                  "data_resources": [{"type": "AWS::S3::Object",
                                                      "values": ["arn:aws-us-gov:s3"]}]}]},
        ],
        "summary": {"trails_total": 1, "multi_region_trails": 1, "validated_trails": 1,
                    "encrypted_trails": 1, "logging_trails": 1},
    }


GUARD_DUTY_ERROR_PAYLOAD = {
    "account_id": "345678901234",
    "collected_region": "us-gov-east-1",
    "detectors": [],
    "note": "GuardDuty has never been enabled in this region.",
}


def _run(run_id: str, manifest: str, started: str, completed: str,
         invocations: list[dict]) -> dict:
    return {
        "run_id": run_id,
        "manifest": manifest,
        "started_at": started,
        "completed_at": completed,
        "invocations": invocations,
    }


def _inv(fetcher: str, outputs: list[str], exit_code: int = 0,
         target: dict | None = None, duration: float = 3.4,
         started: str = "", completed: str = "", stderr_tail: str = "") -> dict:
    return {
        "fetcher_name": fetcher,
        "fetcher_version": "0.1.0",
        "target": target,
        "started_at": started,
        "completed_at": completed,
        "duration_sec": duration,
        "exit_code": exit_code,
        "outputs": outputs,
        "stderr_tail": stderr_tail,
    }


# Output filenames follow the fetchers' own convention (fetchers/aws/_shared/aws.sh
# aws_target_id): "<fetcher>_<profile>.json", or "<fetcher>_ambient.json" when a
# target sets no profile.
def _out(fetcher: str, profile: str | None) -> str:
    return f"{fetcher}_{profile or 'ambient'}.json"


def _aws_run(run_id: str, started: str, completed: str, *, fail_guard_duty: bool):
    """One aws-prod run: the first four fetchers fanned out over both accounts,
    the rest collected once against the ambient identity."""
    invocations: list[dict] = []
    files: dict[str, dict] = {}
    clock = 0.0

    def stamp(offset: float) -> str:
        # started_at is "…T09:14:05Z"; keep the demo readable rather than exact.
        return started[:-4] + f"{int(offset) % 60:02d}Z"

    for i, use in enumerate(AWS_FETCHERS):
        fanout = i < 4
        profiles = [WEST, EAST] if fanout else [None]
        for profile in profiles:
            code = 1 if (fail_guard_duty and use == "aws_guard_duty") else 0
            name = _out(use, profile)
            target = {"profile": profile, "region":
                      "us-gov-west-1" if profile == WEST else "us-gov-east-1"} if profile else None
            clock += 2.7
            invocations.append(_inv(
                use, [] if code else [name], exit_code=code, target=target,
                duration=round(2.1 + (i % 4) * 0.8, 2),
                started=stamp(clock), completed=stamp(clock + 2.4),
                stderr_tail=("aws_guard_duty: guardduty list-detectors returned no detectors for "
                             "us-gov-east-1; treating as a collection failure because "
                             "DETECTOR_REQUIRED=true.\n" if code else ""),
            ))
            if code:
                continue
            account = ACCOUNTS.get(profile or "", ACCOUNTS[WEST])
            region = (target or {}).get("region", "us-gov-west-1")
            if use == "aws_iam_mfa_status":
                payload, es = mfa_payload(account, region), MFA_SET
            elif use == "aws_cloudtrail_configuration":
                payload, es = cloudtrail_payload(account), {
                    "reference_id": "EVD-AWS-CLOUDTRAIL",
                    "name": "Audit Log Collection and Integrity (CloudTrail)",
                    "instructions": (
                        "Script: fetcher.sh. AWS CLI calls: cloudtrail describe-trails, "
                        "get-trail-status and get-event-selectors per trail. Reports each trail's "
                        "multi-region and organization flags, log-file validation, the KMS key "
                        "encrypting the log files, the destination bucket and CloudWatch group, "
                        "live delivery status, and the management/data event selectors."
                    ),
                }
            else:
                payload, es = {
                    "account_id": account,
                    "collected_region": region,
                    "summary": {"resources_checked": 26 + i * 3, "compliant": 26 + i * 3,
                                "non_compliant": 0},
                    "note": f"Collected by {use} against the {profile or 'ambient'} identity.",
                }, None
            files[name] = _envelope(use, run_id, target, payload, evidence_set=es)

    if fail_guard_duty:
        files[_out("aws_guard_duty", None)] = _envelope(
            "aws_guard_duty", run_id, None, GUARD_DUTY_ERROR_PAYLOAD, exit_code=1,
            error="guardduty list-detectors returned no detectors for us-gov-east-1",
        )
        # The failing invocation records no output; the error envelope above is
        # written by the fetcher itself, so list_runs picks it up as a loose file.
    return _run(run_id, "manifests/aws-prod.yaml", started, completed, invocations), files


def _okta_run(run_id: str, started: str, completed: str):
    invocations, files = [], {}
    for i, use in enumerate(OKTA_FETCHERS):
        name = f"{use}.json"
        invocations.append(_inv(use, [name], duration=round(1.4 + i * 0.3, 2),
                                started=started, completed=completed))
        files[name] = _envelope(use, run_id, None, {
            "org_url": "https://acme.okta.com",
            "summary": {"policies": 4 + i, "users_in_scope": 812, "non_compliant": 0},
            "note": f"Collected by {use} against the Acme Okta org.",
        })
    return _run(run_id, "manifests/okta-quarterly.yaml", started, completed, invocations), files


def build(workspace: Path, repo_root: Path, known_fetchers: set[str]) -> Path:
    """Create the throwaway demo workspace and return its path."""
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)

    # Symlink the real product surface; invent only the tenant-shaped parts.
    for shared in ("fetchers", "framework", "uploaders", "comparators", "catalog"):
        src = repo_root / shared
        if src.exists():
            (workspace / shared).symlink_to(src)

    import yaml  # local import: only the fixture needs it

    (workspace / "manifests").mkdir()
    for name, body in _manifests(known_fetchers).items():
        (workspace / "manifests" / name).write_text(
            yaml.safe_dump(body, sort_keys=False, default_flow_style=False)
        )

    evidence = workspace / "evidence"
    evidence.mkdir()
    runs = [
        _aws_run("2026-09-02T09-14-05Z", "2026-09-02T09:14:05Z", "2026-09-02T09:15:48Z",
                 fail_guard_duty=True),
        _aws_run("2026-08-28T09-12-44Z", "2026-08-28T09:12:44Z", "2026-08-28T09:14:19Z",
                 fail_guard_duty=False),
        _okta_run("2026-08-21T16-03-11Z", "2026-08-21T16:03:11Z", "2026-08-21T16:03:59Z"),
    ]
    for meta, files in runs:
        run_dir = evidence / f"run-{meta['run_id']}"
        run_dir.mkdir()
        (run_dir / "_run_metadata.json").write_text(json.dumps(meta, indent=2))
        for name, body in files.items():
            (run_dir / name).write_text(json.dumps(body, indent=2))

    return workspace


# ── evidence for an arbitrary fetcher (the live sandbox) ─────────────────── #

# The static capture only ever runs the four manifests above, but the Fly
# sandbox lets a visitor add any fetcher in the catalog and run it. That needs a
# plausible envelope for a fetcher this module has never heard of.

_SPECIFIC = {"aws_iam_mfa_status", "aws_cloudtrail_configuration"}

_TENANT_LABEL = {
    "aws": "account", "azure": "subscription", "gcp": "project",
    "okta": "org", "k8s": "cluster", "gitlab": "group", "datadog": "org",
    "crowdstrike": "tenant", "sentinelone": "site", "knowbe4": "account",
    "rippling": "company", "checkov": "repository", "paramify": "workspace",
    "demo": "workspace",
}


def synthetic_envelope(fetcher: str, category: str, run_id: str,
                       target: dict | None, evidence_set: dict | None = None) -> dict:
    """A plausible evidence envelope for any fetcher in the catalog.

    The two fetchers with hand-written payloads keep them (they are what the
    evidence viewer opens in the tour); everything else gets a summary-shaped
    payload built from its own name, so the file reads as that fetcher's output
    rather than as filler.
    """
    profile = (target or {}).get("profile")
    account = ACCOUNTS.get(profile or "", ACCOUNTS[WEST])
    region = (target or {}).get("region", "us-gov-west-1")

    if fetcher == "aws_iam_mfa_status":
        return _envelope(fetcher, run_id, target, mfa_payload(account, region),
                         evidence_set=evidence_set or MFA_SET)
    if fetcher == "aws_cloudtrail_configuration":
        return _envelope(fetcher, run_id, target, cloudtrail_payload(account),
                         evidence_set=evidence_set)

    # The check this fetcher performs, read off its own name: everything after
    # the category prefix, which is how the fetchers are named.
    subject = fetcher.split("_", 1)[-1].replace("_", " ")
    scope = _TENANT_LABEL.get(category, "tenant")
    checked = 8 + (sum(ord(c) for c in fetcher) % 37)
    payload = {
        f"{scope}_id": _scope_id(category, target, account),
        "collected_region": region if category == "aws" else None,
        "check": subject,
        "summary": {
            "resources_checked": checked,
            "compliant": checked,
            "non_compliant": 0,
        },
        "findings": [],
        "note": (
            f"Sandbox evidence for {fetcher}. A real run shells out to the "
            f"{category} API and reports the {subject} of every resource it finds."
        ),
    }
    return _envelope(fetcher, run_id, target, payload, evidence_set=evidence_set)


def _scope_id(category: str, target: dict | None, account: str) -> str:
    t = target or {}
    # Not "profile": an AWS target names a credential profile, and the scope an
    # AWS payload reports is the numeric account behind it.
    for key in ("project", "subscription_id", "cluster", "group"):
        if t.get(key):
            return str(t[key])
    return {
        "aws": account,
        "azure": "b7c41d38-2f5a-4e61-9c0d-8ab3e5f27d14",
        "gcp": "acme-platform-prod",
        "okta": "https://acme.okta.com",
    }.get(category, "acme")


def output_name(fetcher: str, category: str, target: dict | None) -> str:
    """The filename a fetcher writes, following each category's own convention."""
    t = target or {}
    if category == "aws":
        return _out(fetcher, t.get("profile"))
    for key in ("project", "subscription_id", "cluster"):
        if t.get(key):
            slug = str(t[key]).replace("/", "_")
            return f"{fetcher}_{slug}.json"
    return f"{fetcher}.json"
