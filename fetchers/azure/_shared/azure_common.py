"""Shared helpers for the Azure evidence fetchers.

Azure SDK imports are lazy so the pure transforms and their tests import with only
the standard library. `environment` comes from AZURE_ENVIRONMENT into the payload
metadata because the runner-built envelope carries no `environment` field.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# One implementation per runtime lives in fetchers/_lib; a category-shared module
# may RE-EXPORT it and must not reimplement it (docs/fetcher_contract.md § Output).
# Same mechanism a fetcher uses, one directory further up: this file is
# fetchers/azure/_shared/, so fetchers/_lib is parents[2] / "_lib".
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import STATUS_CODES, report_failure  # noqa: E402,F401

_LOGGER = logging.getLogger("azure_common")


def current_timestamp() -> str:
    """UTC, second-resolution, Z-suffixed — matches the AWS/GCP fetchers' format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    """Make a target identifier safe for a per-target output filename."""
    sanitized = (value or "").replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized) or "unknown"


def basename(resource_id: Optional[str]) -> Optional[str]:
    """Last segment of an ARM resource ID — the human-meaningful part."""
    if not resource_id:
        return resource_id
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


def resource_group_from_id(resource_id: Optional[str]) -> Optional[str]:
    """Resource group from an ARM resource ID, or None for subscription-scoped IDs.

    Matched case-insensitively: ARM is inconsistent about `resourceGroups` vs
    `resourcegroups` across services and API versions.
    """
    if not resource_id:
        return None
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1] or None
    return None


def dig(obj: Any, *path: str) -> Any:
    """Walk a nested dict by keys, tolerating a missing link at any level."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


# --------------------------------------------------------------------------- #
# The SDK boundary: reading azure-mgmt model objects
# --------------------------------------------------------------------------- #

def model_attr(model: Any, name: str) -> Any:
    """Read ONE attribute off an azure-mgmt model, normalized to a plain value.

    Attributes, never `as_dict()`: on the `_model_base` SDKs (azure-mgmt-storage 25.x,
    azure-mgmt-network 31.x) `as_dict()` emits the camelCase WIRE shape nested under
    "properties", while msrest ones (azure-mgmt-security 7.0.0) emit flat snake_case.
    Attribute access is flat snake_case on both — which is why Prowler reads models so.

    Absent reads as None, so a nested model the API omitted (`encryption`,
    `key_policy`, `protocol_settings`) doesn't raise partway down a projection. Enums
    unwrap to their wire string: azure-mgmt types many fields as `str` enums whose
    `str()` renders "KeySource.MICROSOFT_KEYVAULT", not "Microsoft.Keyvault", which
    would break a downstream `.lower()` comparison and put a repr in the evidence.
    """
    value = getattr(model, name, None)
    return value.value if isinstance(value, Enum) else value


class Collector:
    """Tracks per-call API failures so a partial failure surfaces as exit 1.

    One inaccessible subscription of five must not exit 0 with quietly-empty data.
    Failures drive the exit code, the payload's `partial_failure` flag, and the
    `$FETCHER_STATUS_FILE` reason.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.failures: List[Dict[str, str]] = []

    def record(self, operation: str, exc: BaseException) -> None:
        self.failures.append(
            {"operation": operation, "type": type(exc).__name__, "message": str(exc)}
        )
        self.logger.error("API call failed: %s (%s: %s)", operation, type(exc).__name__, exc)

    def guard(self, operation: str, fn: Callable[[], Any], default: Any = None) -> Any:
        """Run `fn()`, recording (not raising) any exception; returns `default`."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
            self.record(operation, exc)
            return default

    @property
    def ok(self) -> bool:
        return not self.failures


# --------------------------------------------------------------------------- #
# Failure classification for $FETCHER_STATUS_FILE's `code`
# --------------------------------------------------------------------------- #

# Matched on the recorded exception type name, then its message. Ordered
# most-specific-first: the first match wins across ALL failures, so a run whose real
# problem is an unresolved credential isn't reported as a generic partial_failure.
_CODE_RULES = (
    (
        "auth_failed",
        ("clientauthenticationerror", "credentialunavailableerror", "chainedtokencredential"),
        ("authenticationfailed", "aadsts", "defaultazurecredential failed", "invalid_client",
         "no credential", "unable to get authority", "token request failed"),
    ),
    (
        "not_authorized",
        ("permissionerror",),
        ("authorizationfailed", "does not have authorization", "forbidden", "(403)",
         "insufficient privileges", "not authorized"),
    ),
    (
        "rate_limited",
        (),
        ("toomanyrequests", "(429)", "rate limit", "throttl"),
    ),
    (
        "target_unreachable",
        ("servicerequesterror", "servicerequesttimeouterror", "connectionerror",
         "timeouterror", "sslerror"),
        ("failed to establish a new connection", "name or service not known",
         "temporary failure in name resolution", "connection aborted", "timed out",
         "getaddrinfo", "max retries exceeded", "(503)", "(504)"),
    ),
    (
        "bad_config",
        (),
        ("subscriptionnotfound", "invalidsubscriptionid", "invalid subscription",
         "is not a valid subscription", "no subscription"),
    ),
    (
        # A missing azure-mgmt-* dependency is our fault, not the customer's
        # config — it must not masquerade as bad_config.
        "internal_error",
        ("modulenotfounderror", "importerror"),
        (),
    ),
)


def classify_failure_code(failures: List[Dict[str, str]]) -> str:
    """Map recorded failures onto the contract's `code` enum, else partial_failure."""
    if not failures:
        return "partial_failure"
    types = {(f.get("type") or "").lower() for f in failures}
    messages = " ".join((f.get("message") or "").lower() for f in failures)
    for code, type_markers, message_markers in _CODE_RULES:
        if any(marker in t for t in types for marker in type_markers):
            return code
        if any(marker in messages for marker in message_markers):
            return code
    return "partial_failure"


def failure_reason(failures: List[Dict[str, str]], limit: int = 300) -> str:
    """One-line reason for `report_failure`, from the first recorded failure.

    The full set stays in the payload's `metadata.api_failures`. Truncation is marked
    so a clipped Azure error (they run to many lines) can't be read as the whole one.
    """
    if not failures:
        return "collection failed"
    worst = failures[0]
    detail = " ".join((worst.get("message") or "").split())
    if len(detail) > limit:
        detail = detail[:limit].rstrip() + " ..."
    return (
        f"{len(failures)} Azure API failure(s); first: "
        f"{worst.get('operation')}: {worst.get('type')}: {detail}"
    )


# --------------------------------------------------------------------------- #
# Auth / subscription resolution
# --------------------------------------------------------------------------- #

def credential():
    """DefaultAzureCredential. Lazy import so tests don't need the Azure SDK."""
    from azure.identity import DefaultAzureCredential  # lazy

    return DefaultAzureCredential()


# --------------------------------------------------------------------------- #
# Which ARM cloud to talk to
# --------------------------------------------------------------------------- #
#
# Derived from AZURE_AUTHORITY_HOST exactly as entra_graph.graph_host() derives the
# Graph host: that variable is the one declared sovereign-cloud selector, and a
# second knob could disagree with the credential's own authority.
#
# Without this the azure.mgmt clients default to commercial Azure. A Gov Cloud
# subscription then comes back as `SubscriptionNotFound` — the collection does fail
# rather than silently returning empty evidence, but it fails naming the
# subscription, so it reads as a bad id or a permissions problem rather than as a
# request sent to the wrong cloud.
ARM_ENDPOINT_PUBLIC = "https://management.azure.com"

_AUTHORITY_TO_ARM_ENDPOINT = {
    "login.microsoftonline.com": ARM_ENDPOINT_PUBLIC,
    "login.microsoftonline.us": "https://management.usgovcloudapi.net",
    "login.microsoftonline.de": "https://management.microsoftazure.de",
    "login.chinacloudapi.cn": "https://management.chinacloudapi.cn",
    "login.partner.microsoftonline.cn": "https://management.chinacloudapi.cn",
}


def arm_endpoint() -> str:
    """ARM management endpoint for the cloud the credential's authority points at."""
    authority = (os.environ.get("AZURE_AUTHORITY_HOST") or "").strip()
    if not authority:
        return ARM_ENDPOINT_PUBLIC
    host = authority.replace("https://", "").replace("http://", "").strip("/").lower()
    mapped = _AUTHORITY_TO_ARM_ENDPOINT.get(host)
    if mapped is None:
        _LOGGER.warning(
            "AZURE_AUTHORITY_HOST %r is not a recognized sovereign authority; "
            "collecting against the public management endpoint %s",
            authority,
            ARM_ENDPOINT_PUBLIC,
        )
        return ARM_ENDPOINT_PUBLIC
    return mapped


def arm_client_kwargs() -> Dict[str, Any]:
    """`base_url` + `credential_scopes` for an azure.mgmt client, keyed to the cloud.

    Spread into every management client constructor:

        Client(credential=cred, subscription_id=sub, **arm_client_kwargs())

    Both keys are required together. `base_url` alone sends a token minted for the
    commercial audience to the sovereign endpoint, which rejects it — so setting
    only the endpoint trades SubscriptionNotFound for an auth error.
    """
    endpoint = arm_endpoint()
    return {"base_url": endpoint, "credential_scopes": [f"{endpoint}/.default"]}


def resolve_subscription(collector: Collector) -> Dict[str, Optional[str]]:
    """Resolve the subscription to collect from.

    Explicit AZURE_SUBSCRIPTION_ID (set by the runner from a target) wins; else the
    first *enabled* subscription the ambient credential can see.
    """
    explicit = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if explicit:
        return {"subscription_id": explicit, "subscription_source": "target"}

    def _discover() -> Optional[str]:
        from azure.mgmt.subscription import SubscriptionClient  # lazy

        client = SubscriptionClient(credential(), **arm_client_kwargs())
        for sub in client.subscriptions.list():
            # SubscriptionState serializes as "Enabled", its repr as
            # "SubscriptionState.ENABLED"; both contain "enabled", while "Disabled",
            # "Warned", "PastDue" and "Deleted" do not.
            if "enabled" in str(getattr(sub, "state", "")).lower():
                return getattr(sub, "subscription_id", None)
        return None

    subscription_id = collector.guard("subscription.subscriptions.list", _discover)
    return {
        "subscription_id": subscription_id,
        "subscription_source": "ambient_default" if subscription_id else "unresolved",
    }


# --------------------------------------------------------------------------- #
# Resource-provider registration — "service not in use" vs "in use but empty"
# --------------------------------------------------------------------------- #

REGISTERED = "registered"
NOT_REGISTERED = "not_registered"
REGISTRATION_UNKNOWN = "unknown"


def provider_registration_status(
    collector: Collector, subscription_id: str, cred, namespace: str
) -> str:
    """Registration state of an ARM resource provider, as evidence.

    For most namespaces Azure returns an EMPTY LIST rather than an error when the
    provider is not registered — confirmed live: with Microsoft.Storage unregistered,
    `storage_accounts.list()` yields zero accounts and raises nothing. So without this
    field `total_storage_accounts: 0` reads identically whether the service is not in
    use or in use and genuinely empty. Microsoft.Security *does* raise "Subscription
    Not Registered", so Defender needs no such call and reuses the field name.

    A not-registered provider is valid evidence, NOT a collection failure — the same
    convention as AWS's SubscriptionRequiredException handling. "unknown" means the
    lookup itself failed, which `guard` does record.
    """

    def _get() -> Optional[str]:
        # azure-mgmt-resource moved this class: re-exported at the package root
        # through 24.x (what Prowler pins), GONE by 26.0.0 where it lives under
        # `.resources` (verified live). New home first, fall back to the old one.
        try:
            from azure.mgmt.resource.resources import ResourceManagementClient  # lazy
        except ImportError:  # pragma: no cover - depends on installed SDK version
            from azure.mgmt.resource import ResourceManagementClient  # lazy

        client = ResourceManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )
        return model_attr(client.providers.get(namespace), "registration_state")

    state = collector.guard(f"resource.providers.get({namespace})", _get)
    if state is None:
        return REGISTRATION_UNKNOWN
    return REGISTERED if str(state).lower() == "registered" else NOT_REGISTERED


# --------------------------------------------------------------------------- #
# Payload assembly / output
# --------------------------------------------------------------------------- #

def build_payload(
    *,
    subscription_id: Optional[str],
    subscription_source: str,
    collector: Collector,
    results: Dict[str, Any],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble the raw evidence dict the runner will wrap in an envelope."""
    return {
        "metadata": {
            "subscription_id": subscription_id,
            "subscription_source": subscription_source,
            "environment": os.environ.get("AZURE_ENVIRONMENT"),
            "datetime": current_timestamp(),
            # Explicit so a validator can assert on it without the envelope.
            "partial_failure": not collector.ok,
            "api_failures": collector.failures,
        },
        "results": results,
        "summary": summary,
    }


def write_evidence(output_dir: Path, filename: str, evidence: Dict[str, Any]) -> Path:
    """Write the evidence dict deterministically (sorted keys, stable ordering)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True, default=str)
    return path


def coverage_percentage(covered: int, total: int) -> int:
    """Integer percentage, matching the AWS/GCP fetchers' summary math (0 when empty)."""
    return (covered * 100) // total if total > 0 else 0
