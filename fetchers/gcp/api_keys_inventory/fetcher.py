#!/usr/bin/env python3
"""
GCP API Keys Inventory

Every API key in one project: creation and last-update time, age against the
90-day rotation interval, and both restriction axes — which API services the key
may call, and which referrers, IP ranges, Android packages or iOS bundle ids may
present it. No key string is ever read: key material comes only from the
separate GetKeyString method, which this fetcher never calls.

Ported from Prowler's GCP API Keys service (Apache-2.0).
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

logger = logging.getLogger("gcp_api_keys_inventory")

# The interval Prowler's apikeys_key_rotated_in_90_days measures against. An API
# key has no expiry, so age is the whole of the rotation evidence.
_ROTATION_AGE_DAYS = 90

# A key "restricted" to this wildcard target can still call every Cloud API.
_WILDCARD_API_TARGET = "cloudapis.googleapis.com"

# API keys only exist in the `global` location.
_KEY_LOCATION = "global"


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


def api_target_records(restrictions: dict) -> list[dict]:
    """Which API services the key may call, and how narrowly within each.

    `methods` narrows a target to specific RPCs; empty means the whole service.
    """
    targets = []
    for target in dig_any(restrictions, "api_targets") or []:
        methods = sorted(dig_any(target, "methods") or [])
        service = dig_any(target, "service") or None
        targets.append(
            {
                "service": service,
                "method_count": len(methods),
                "methods": methods,
                "wildcard_service": service == _WILDCARD_API_TARGET,
            }
        )
    return sorted(targets, key=lambda t: t["service"] or "")


def client_restrictions(restrictions: dict) -> dict:
    """The four client-side restriction axes, whichever one the key uses.

    A key carries at most one — browser, server, Android or iOS — since they
    describe mutually exclusive call sites. Android entries also carry an APK
    signing-certificate fingerprint, dropped here: it is not a control fact.
    """
    android = dig_any(restrictions, "android_key_restrictions", "allowed_applications") or []
    return {
        "allowed_referrers": sorted(
            dig_any(restrictions, "browser_key_restrictions", "allowed_referrers") or []
        ),
        "allowed_ips": sorted(
            dig_any(restrictions, "server_key_restrictions", "allowed_ips") or []
        ),
        "allowed_android_packages": sorted(
            dig_any(app, "package_name") or "" for app in android
        ),
        "allowed_ios_bundle_ids": sorted(
            dig_any(restrictions, "ios_key_restrictions", "allowed_bundle_ids") or []
        ),
    }


def key_record(key: dict, now: datetime) -> dict:
    """Normalize one API key into an evidence record. Never reads key material."""
    restrictions = dig_any(key, "restrictions") or {}
    targets = api_target_records(restrictions)
    clients = client_restrictions(restrictions)

    created = parse_timestamp(dig_any(key, "create_time"))
    updated = parse_timestamp(dig_any(key, "update_time"))

    # Prowler's rule: a key whose only target is the cloudapis.googleapis.com
    # wildcard is as unrestricted as one with no targets at all.
    real_targets = [t for t in targets if not t["wildcard_service"]]
    api_restricted = bool(real_targets)
    client_restricted = any(
        clients[axis]
        for axis in (
            "allowed_referrers",
            "allowed_ips",
            "allowed_android_packages",
            "allowed_ios_bundle_ids",
        )
    )

    record = {
        "uid": dig_any(key, "uid") or None,
        "name": dig_any(key, "name") or None,
        "display_name": dig_any(key, "display_name") or None,
        "create_time": dig_any(key, "create_time") or None,
        "update_time": dig_any(key, "update_time") or None,
        "delete_time": dig_any(key, "delete_time") or None,
        "age_days": (now - created).days if created else None,
        "days_since_update": (now - updated).days if updated else None,
        "never_updated": bool(created and updated and created == updated),
        "past_rotation_age": bool(created and (now - created).days > _ROTATION_AGE_DAYS),
        "api_targets": targets,
        "api_target_services": sorted({t["service"] for t in targets if t["service"]}),
        "targets_all_cloud_apis": any(t["wildcard_service"] for t in targets),
        "api_restrictions_configured": api_restricted,
        "client_restrictions_configured": client_restricted,
        "unrestricted": not api_restricted and not client_restricted,
        "fully_restricted": api_restricted and client_restricted,
        # Never collected: GetKeyString is the only source, and it is never called.
        "key_material_collected": False,
    }
    record.update(clients)
    return record


def summarize(keys: list[dict], api_readable: bool = True) -> dict:
    restricted = [k for k in keys if not k["unrestricted"]]
    ages = [k["age_days"] for k in keys if k["age_days"] is not None]
    services: dict[str, int] = {}
    for key in keys:
        for service in key["api_target_services"]:
            services[service] = services.get(service, 0) + 1

    return {
        # False means the API Keys API is disabled or unreadable on this project,
        # not that the project has no keys.
        "api_keys_api_readable": api_readable,
        "total_api_keys": len(keys),
        # Prowler's apikeys_key_exists: the defensible posture for most projects.
        "no_api_keys": api_readable and not keys,
        "unrestricted_keys": sum(1 for k in keys if k["unrestricted"]),
        "api_restricted_keys": sum(1 for k in keys if k["api_restrictions_configured"]),
        "client_restricted_keys": sum(1 for k in keys if k["client_restrictions_configured"]),
        "fully_restricted_keys": sum(1 for k in keys if k["fully_restricted"]),
        "restricted_key_percentage": coverage_percentage(len(restricted), len(keys)),
        "keys_targeting_all_cloud_apis": sum(1 for k in keys if k["targets_all_cloud_apis"]),
        "api_target_service_counts": dict(sorted(services.items())),
        "keys_past_rotation_age": sum(1 for k in keys if k["past_rotation_age"]),
        "rotation_age_days": _ROTATION_AGE_DAYS,
        "oldest_key_age_days": max(ages) if ages else None,
        "keys_never_updated": sum(1 for k in keys if k["never_updated"]),
        # Auditable statement about this evidence set, not a fact about the project.
        "key_material_collected": False,
    }


# --- collection ---

def collect_keys(project, creds, collector: Collector, now: datetime) -> tuple[list[dict], bool]:
    """Every API key in the project's `global` location.

    A project that never enabled apikeys.googleapis.com 403s with
    SERVICE_DISABLED — itself evidence, so it is tolerated and reported as an
    unreadable API rather than as a collection failure.
    """
    from google.cloud import api_keys_v2

    def _list():
        client = api_keys_v2.ApiKeysClient(credentials=creds)
        # The response carries no key string: GetKeyString is a separate method,
        # and it is never called.
        return [
            key_record(api_keys_v2.Key.to_dict(k, use_integers_for_enums=False), now)
            for k in client.list_keys(
                parent=f"projects/{project}/locations/{_KEY_LOCATION}"
            )
        ]

    keys = collector.guard(
        "apikeys.projects.locations.keys.list",
        _list,
        default=None,
        tolerate=service_disabled,
    )
    records = sorted(keys or [], key=lambda k: (k.get("create_time") or "", k.get("uid") or ""))
    return records, keys is not None


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

    keys: list[dict] = []
    api_readable = False
    if project and creds is not None:
        keys, api_readable = collect_keys(project, creds, collector, now)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"api_keys": keys},
        summary=summarize(keys, api_readable=api_readable),
    )

    filename = f"gcp_api_keys_inventory_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
