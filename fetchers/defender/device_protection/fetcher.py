#!/usr/bin/env python3
"""
KSI-PIY-GIV / KSI-CNA-EIS: Defender for Endpoint device protection

Collects every device Microsoft Defender for Endpoint knows about and reduces
the fleet to the counters that show endpoint protection is operating: devices
that could be onboarded but are not, sensors that have stopped reporting,
antivirus signatures that are out of date, and devices unseen for longer than
the configured window.

The counters are all "should be zero" assertions, which makes an empty fleet
indistinguishable from a healthy one. `fleet_empty` exists to break that tie and
is reported first for that reason.
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

logger = logging.getLogger("defender_device_protection")

DEFAULT_API_BASE_URL = "https://api.securitycenter.microsoft.com"
DEFAULT_STALE_AFTER_DAYS = 30
REQUEST_TIMEOUT = 60
MAX_RETRIES = 3
RETRY_STATUSES = (429, 503)
# MDE returns the fleet in pages of ~10k. The cap is a runaway guard, not a
# limit anyone should reach; hitting it is reported as a partial collection
# rather than silently truncating the evidence.
MAX_PAGES = 200

# Fields projected from each machine record, as returned by the API. Everything
# else MDE reports (IP addresses, exposure detail, health remediation hints) is
# left out: it is not what the evidence has to prove and it enlarges the
# per-device footprint of a file that already carries one row per endpoint.
MACHINE_FIELDS = {
    "id": "id",
    "computerDnsName": "computer_dns_name",
    "osPlatform": "os_platform",
    "osVersion": "os_version",
    "version": "os_build",
    "onboardingStatus": "onboarding_status",
    "healthStatus": "health_status",
    "defenderAvStatus": "defender_av_status",
    "agentVersion": "agent_version",
    "lastSeen": "last_seen",
    "riskScore": "risk_score",
    "exposureLevel": "exposure_level",
    "rbacGroupName": "rbac_group_name",
    "isAadJoined": "is_aad_joined",
    "machineTags": "machine_tags",
}


class CollectionError(Exception):
    """A failure that ends collection, carrying the runner's machine-readable code."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def report_failure(reason: str, code: str | None = None) -> None:
    """Report why this run failed; the runner puts it in the envelope's metadata.error.

    Call this on every path that returns non-zero. Without it the runner falls back
    to the tail of stderr, which is whatever you logged last — and for most fetchers
    that is the "Evidence saved" line, i.e. a success message reported as the reason
    for a failure. `code` is a machine-readable category (auth_failed,
    not_authorized, not_enabled, target_unreachable, rate_limited, bad_config,
    partial_failure). See docs/fetcher_contract.md § Output.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(json.dumps({"error": reason} | ({"code": code} if code else {})))


def api_base_url() -> str:
    """The MDE endpoint for the tenant's cloud, without a trailing slash.

    Commercial by default; GCC and GCC High / DoD tenants answer on
    *.securitycenter.microsoft.us and must set DEFENDER_API_BASE_URL. The
    commercial endpoint does not error for a government tenant — it authenticates
    and reports an empty fleet, which is why this is worth getting right.
    """
    return os.environ.get("DEFENDER_API_BASE_URL", DEFAULT_API_BASE_URL).rstrip("/")


def stale_after_days() -> int:
    raw = os.environ.get("DEFENDER_STALE_AFTER_DAYS")
    if not raw:
        return DEFAULT_STALE_AFTER_DAYS
    try:
        return int(raw)
    except ValueError:
        raise CollectionError(
            f"DEFENDER_STALE_AFTER_DAYS must be an integer, got {raw!r}", "bad_config"
        )


def acquire_token(base_url: str) -> str:
    """Exchange the ambient Azure credential for a token scoped to the MDE resource.

    The scope is derived from the endpoint so a sovereign-cloud base URL needs no
    second setting. Lazy import keeps the SDK off the import path for anything
    that only wants to read this module.
    """
    from azure.identity import DefaultAzureCredential  # lazy

    try:
        credential = DefaultAzureCredential()
        return credential.get_token(f"{base_url}/.default").token
    except Exception as exc:  # azure-identity raises a family of these
        raise CollectionError(
            f"could not acquire a Defender for Endpoint token for {base_url}: {exc}",
            "auth_failed",
        ) from exc


def _get(session: requests.Session, url: str) -> Dict[str, Any]:
    """One GET, with the MDE error taxonomy mapped onto runner status codes."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT)
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise CollectionError(f"could not reach {url}: {exc}", "target_unreachable") from exc

        if response.status_code == 401:
            raise CollectionError(
                "Defender for Endpoint rejected the token (401) — the credential is not "
                "valid for this tenant",
                "auth_failed",
            )
        if response.status_code == 403:
            raise CollectionError(
                "Defender for Endpoint returned 403 — the principal authenticated but "
                "lacks the Machine.Read.All application permission, or it was never "
                "admin-consented",
                "not_authorized",
            )
        if response.status_code in RETRY_STATUSES and attempt < MAX_RETRIES:
            delay = _retry_delay(response, attempt)
            logger.warning(
                "%s from Defender (attempt %d/%d), retrying in %ss",
                response.status_code,
                attempt,
                MAX_RETRIES,
                delay,
            )
            time.sleep(delay)
            continue
        if response.status_code in RETRY_STATUSES:
            raise CollectionError(
                f"Defender for Endpoint throttled the run ({response.status_code}) and did "
                f"not recover after {MAX_RETRIES} attempts",
                "rate_limited",
            )
        if not response.ok:
            raise CollectionError(
                f"Defender for Endpoint returned {response.status_code} for {url}: "
                f"{response.text[:300]}",
                "partial_failure",
            )
        try:
            return response.json()
        except ValueError as exc:
            raise CollectionError(
                f"Defender for Endpoint returned a non-JSON body for {url}", "partial_failure"
            ) from exc
    raise CollectionError(f"exhausted retries for {url}", "rate_limited")


def _retry_delay(response: requests.Response, attempt: int) -> int:
    """Honour Retry-After when MDE sends one; otherwise back off."""
    header = response.headers.get("Retry-After")
    if header:
        try:
            return max(1, int(float(header)))
        except ValueError:
            pass
    return 2**attempt


def fetch_machines(base_url: str, token: str, api_failures: List[str]) -> List[Dict[str, Any]]:
    """Every machine record, following @odata.nextLink to the end of the fleet."""
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    machines: List[Dict[str, Any]] = []
    url: Optional[str] = f"{base_url}/api/machines"
    pages = 0
    while url and pages < MAX_PAGES:
        body = _get(session, url)
        machines.extend(body.get("value") or [])
        url = body.get("@odata.nextLink")
        pages += 1

    if url:
        api_failures.append(
            f"stopped after {MAX_PAGES} pages with more results pending — the device list is incomplete"
        )
    return machines


_OVERLONG_FRACTION = re.compile(r"(\.\d{6})\d+")


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse an MDE timestamp. Returns None for anything unparseable.

    MDE serialises seven fractional digits ("...T12:00:00.0000000Z"), one more
    than fromisoformat accepts before 3.11, so the tail is trimmed rather than
    the whole timestamp discarded.
    """
    if not value:
        return None
    text = _OVERLONG_FRACTION.sub(r"\1", value.replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _project(machine: Dict[str, Any]) -> Dict[str, Any]:
    return {out: machine.get(src) for src, out in MACHINE_FIELDS.items()}


def _tally(values: List[Optional[str]]) -> Dict[str, int]:
    """Count every distinct value, so states the counters do not name stay visible."""
    counts: Dict[str, int] = {}
    for value in values:
        key = value if value else "Unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def summarize(devices: List[Dict[str, Any]], stale_days: int, now: datetime) -> Dict[str, Any]:
    """Reduce the fleet to the counters the validators assert on.

    Health, antivirus and staleness are computed over *onboarded* devices only. A
    device that was never onboarded has no sensor to be unhealthy and no
    signatures to be stale; counting it in all three would report one gap three
    times and make the onboarding counter the only honest number in the summary.
    """
    onboarded = [d for d in devices if d.get("onboarding_status") == "Onboarded"]
    cutoff = now - timedelta(days=stale_days)

    stale = 0
    unknown_last_seen = 0
    for device in onboarded:
        last_seen = _parse_timestamp(device.get("last_seen"))
        if last_seen is None:
            unknown_last_seen += 1
        elif last_seen < cutoff:
            stale += 1

    health = [d.get("health_status") for d in onboarded]
    av = [d.get("defender_av_status") for d in onboarded]

    return {
        # Read this first: every counter below is a should-be-zero assertion, and
        # an empty fleet satisfies all of them.
        "fleet_empty": len(devices) == 0,
        "device_count": len(devices),
        "onboarded_count": len(onboarded),
        # Devices MDE says it could onboard and has not. Unsupported platforms and
        # records too sparse to classify are counted separately rather than folded
        # in here, because they are not the same finding and not the same fix.
        "not_onboarded_count": sum(
            1 for d in devices if d.get("onboarding_status") == "CanBeOnboarded"
        ),
        "unsupported_count": sum(
            1 for d in devices if d.get("onboarding_status") == "Unsupported"
        ),
        "insufficient_info_count": sum(
            1 for d in devices if d.get("onboarding_status") == "InsufficientInfo"
        ),
        "onboarding_coverage_pct": (
            round(100.0 * len(onboarded) / len(devices), 2) if devices else 0.0
        ),
        "health_active_count": sum(1 for s in health if s == "Active"),
        "health_inactive_count": sum(1 for s in health if s == "Inactive"),
        "health_impaired_count": sum(
            1 for s in health if s and s != "Active" and s != "Inactive"
        ),
        "av_signature_updated_count": sum(1 for s in av if s == "Updated"),
        "av_signature_not_updated_count": sum(1 for s in av if s == "NotUpdated"),
        "av_status_unknown_count": sum(1 for s in av if not s or s == "Unknown"),
        "av_not_supported_count": sum(1 for s in av if s == "NotSupported"),
        "stale_after_days": stale_days,
        "stale_device_count": stale,
        "unknown_last_seen_count": unknown_last_seen,
        "onboarding_status_breakdown": _tally([d.get("onboarding_status") for d in devices]),
        "health_status_breakdown": _tally(health),
        "defender_av_status_breakdown": _tally(av),
        "os_platform_breakdown": _tally([d.get("os_platform") for d in devices]),
    }


def collect() -> Dict[str, Any]:
    base_url = api_base_url()
    stale_days = stale_after_days()
    api_failures: List[str] = []
    now = datetime.now(timezone.utc)

    token = acquire_token(base_url)
    devices = [_project(m) for m in fetch_machines(base_url, token, api_failures)]

    return {
        "collected_at": now.isoformat(),
        "source": {
            "product": "Microsoft Defender for Endpoint",
            "api_base_url": base_url,
            "endpoint": f"{base_url}/api/machines",
            "cloud": "commercial" if base_url == DEFAULT_API_BASE_URL else "sovereign",
        },
        "summary": summarize(devices, stale_days, now),
        "devices": devices,
        "collection": {"api_failures": api_failures},
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself and reads env directly.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "defender_device_protection.json"

    evidence: Dict[str, Any] = {}
    failure: Optional[CollectionError] = None
    try:
        evidence = collect()
    except CollectionError as exc:
        failure = exc
        evidence = {"error": str(exc), "code": exc.code}

    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Evidence saved to %s", output_path)

    # Everything below runs after the success line on purpose: the runner's
    # fallback reads the tail of stderr, so an error logged before it would be
    # overwritten by "Evidence saved to …" as the reported reason.
    if failure is not None:
        report_failure(str(failure), failure.code)
        logger.error("%s", failure)
        return 1

    api_failures = evidence["collection"]["api_failures"]
    if api_failures:
        reason = f"{len(api_failures)} API calls failed: {'; '.join(api_failures)}"
        report_failure(reason, "partial_failure")
        logger.error("%s", reason)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
