"""Shared helpers for the GCP evidence fetchers.

Every GCP fetcher resolves its target project from ADC, collects one evidence
set, and exits non-zero if any API call failed, so a partial failure never
looks like success.

Nothing here imports a Google client library — the `google.*` imports stay lazy
inside each fetcher's `collect_*()`, so the pure transforms (and their tests)
import with only the standard library present.

Resource lists are sorted by a stable identifier and written with
sort_keys=True, so a re-run against unchanged infrastructure is byte-stable and
regex validators stay quiet.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# One implementation per runtime lives in fetchers/_lib; a category-shared module
# may RE-EXPORT it and must not reimplement it (docs/fetcher_contract.md § Output).
# Same mechanism a fetcher uses, one directory further up: this file is
# fetchers/gcp/_shared/, so fetchers/_lib is parents[2] / "_lib".
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import STATUS_CODES, report_failure  # noqa: E402,F401

# Least privilege at the token level, on top of the read-only IAM role.
READ_ONLY_SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]


def current_timestamp() -> str:
    """UTC, second-resolution, Z-suffixed — matches the AWS fetchers' format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    """Make a target identifier safe for a per-target output filename."""
    sanitized = (value or "").replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized) or "unknown"


def basename(resource_url: Optional[str]) -> Optional[str]:
    """Last path segment of a GCP self-link / partial URL.

    Compute returns fully-qualified URLs for `zone`, `type`, `sourceDisk`; KMS
    `name` values are already relative paths, so callers wanting the whole path
    skip this.
    """
    if not resource_url:
        return resource_url
    return resource_url.rstrip("/").rsplit("/", 1)[-1]


def first(obj: Optional[Dict[str, Any]], *keys: str) -> Any:
    """First present, non-None value among `keys` — the REST/Compute/KMS
    serializers disagree on camelCase vs snake_case spelling.
    """
    if not isinstance(obj, dict):
        return None
    for key in keys:
        val = obj.get(key)
        if val is not None:
            return val
    return None


def dig(obj: Any, *path: str) -> Any:
    """Walk a nested dict by keys, tolerating a missing link at any level."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _spellings(key: str) -> Tuple[str, ...]:
    """`key` plus its camelCase and snake_case counterparts, deduplicated."""
    parts = key.split("_")
    camel = parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()
    return tuple(dict.fromkeys((key, camel, snake)))


def dig_any(obj: Any, *path: str) -> Any:
    """`dig()` tolerating camelCase or snake_case at every level.

    GAPIC `to_dict()` emits snake_case, the REST/discovery APIs camelCase; only
    the deeply-nested GKE and logging shapes need this over spelling both by hand.
    """
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        for variant in _spellings(key):
            if variant in cur:
                cur = cur[variant]
                break
        else:
            return None
    return cur


def _one_line(text: Any, limit: int = 800) -> str:
    """Collapse to a single bounded line: Google API errors run multi-line (gRPC
    status blocks, enable-this-API URLs) and the status file's `error` does not.
    """
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


# Substrings mapping a recorded failure onto a STATUS_CODES category, matched
# against "<exception type> <message>" lowercased. First hit wins, so the order
# is deliberate: a 403 while refreshing a token is auth, not a missing IAM role.
_FAILURE_SIGNATURES = (
    ("auth_failed", (
        "defaultcredentialserror", "refresherror", "invalid_grant", "invalid_client",
        "unauthorized_client", "reauthentication", "unauthenticated",
        "could not automatically determine credentials",
        "invalid authentication credentials",
        # gRPC wraps a credential refresh failure as an UNAVAILABLE from the auth
        # plugin, so the 503 has to be read past to reach the real cause.
        "getting metadata from plugin failed",
        "401",
    )),
    ("not_authorized", (
        "permissiondenied", "forbidden", "403", "does not have permission",
        "caller does not have", "iam_permission_denied",
    )),
    ("rate_limited", (
        "resourceexhausted", "toomanyrequests", "429", "quota exceeded", "ratelimitexceeded",
    )),
    ("target_unreachable", (
        "serviceunavailable", "deadlineexceeded", "connectionerror", "timeout", "timed out",
        "name resolution", "getaddrinfo", "503", "504",
    )),
    ("bad_config", ("invalidargument", "badrequest", "notfound", "no project id", "400")),
)

# Keeps the one-line reason legible in a UI cell; api_failures has the full ledger.
_MAX_REPORTED_FAILURES = 3
_MAX_REPORTED_MESSAGE_CHARS = 200


def _failure_code(failure: Dict[str, str]) -> str:
    blob = f"{failure.get('type', '')} {failure.get('message', '')}".lower()
    for code, signatures in _FAILURE_SIGNATURES:
        if any(sig in blob for sig in signatures):
            return code
    return "internal_error"


def service_disabled(exc: BaseException) -> bool:
    """True when the API itself was never enabled on this project.

    GCP 403s with SERVICE_DISABLED rather than answering "no such resources", so
    a project with container.googleapis.com off reads as a failure when it is
    evidence: this project runs no GKE. Pass as `guard(tolerate=...)`.
    """
    text = f"{type(exc).__name__} {exc}".lower()
    return any(
        marker in text
        for marker in (
            "service_disabled",
            "accessnotconfigured",
            "has not been used in project",
            "api is not enabled",
        )
    )


def access_denied(exc: BaseException) -> bool:
    """True for a 403 / permission error.

    Tolerable only for reads *above* the project, which a project-scoped role is
    not granted; project-scoped it is a missing permission the operator must fix.
    """
    text = f"{type(exc).__name__} {exc}".lower()
    return any(marker in text for marker in ("permissiondenied", "forbidden", "403"))


class Collector:
    """Tracks per-call API failures so a partial failure surfaces as exit 1.

    One inaccessible project of five must not exit 0 with quietly-empty data;
    failures drive the exit code, the `partial_failure` flag, and the runner reason.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.failures: List[Dict[str, str]] = []
        self.skipped: List[Dict[str, str]] = []

    def record(self, operation: str, exc: BaseException) -> None:
        self.failures.append(
            {"operation": operation, "type": type(exc).__name__, "message": str(exc)}
        )
        self.logger.error("API call failed: %s (%s: %s)", operation, type(exc).__name__, exc)

    def skip(self, operation: str, exc: BaseException) -> None:
        """Record a call whose failure is itself evidence.

        Kept out of `failures` so it sets neither partial_failure nor the exit
        code, but still written to metadata.skipped_calls — a silently absent
        result is the failure mode this module exists to avoid.
        """
        self.skipped.append(
            {"operation": operation, "type": type(exc).__name__, "message": _one_line(exc)}
        )
        self.logger.warning(
            "Skipping %s — not a collection failure (%s: %s)",
            operation, type(exc).__name__, _one_line(exc, 200),
        )

    def guard(
        self,
        operation: str,
        fn: Callable[[], Any],
        default: Any = None,
        tolerate: Optional[Callable[[BaseException], bool]] = None,
    ) -> Any:
        """Run `fn()`, recording (not raising) any exception; returns `default`.

        A matching `tolerate` (`service_disabled`, `access_denied`) routes to `skip()`.
        """
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
            if tolerate is not None and tolerate(exc):
                self.skip(operation, exc)
            else:
                self.record(operation, exc)
            return default

    @property
    def ok(self) -> bool:
        return not self.failures

    def failure_report(self) -> Tuple[str, str]:
        """The one-line reason + STATUS_CODES category for `report_failure()`.

        A unanimous cause is reported as itself — expired ADC takes down every call,
        and `auth_failed` says more than `partial_failure`. Mixed causes report
        `partial_failure` and leave the detail to the api_failures ledger.
        """
        codes = {_failure_code(f) for f in self.failures}
        code = codes.pop() if len(codes) == 1 else "partial_failure"

        detail = "; ".join(
            f"{f['operation']} ({f['type']}: {f['message'][:_MAX_REPORTED_MESSAGE_CHARS]})"
            for f in self.failures[:_MAX_REPORTED_FAILURES]
        )
        noun = "call" if len(self.failures) == 1 else "calls"
        return _one_line(f"{len(self.failures)} GCP API {noun} failed: {detail}"), code


def resolve_project(collector: Collector) -> Dict[str, Optional[str]]:
    """Resolve the project to collect from.

    Explicit GOOGLE_CLOUD_PROJECT (runner-set from a target) wins; otherwise the
    ADC default project — "collect where deployed".
    """
    explicit = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT")
    if explicit:
        return {"project": explicit, "project_source": "target"}

    def _adc_project() -> Optional[str]:
        import google.auth  # lazy

        _creds, project = google.auth.default(scopes=READ_ONLY_SCOPES)
        return project

    project = collector.guard("google.auth.default (resolve project)", _adc_project)
    return {"project": project, "project_source": "adc_default" if project else "unresolved"}


def credentials():
    """ADC credentials scoped read-only. Lazy import so tests don't need google."""
    import google.auth  # lazy

    creds, _project = google.auth.default(scopes=READ_ONLY_SCOPES)
    return creds


def build_payload(
    *,
    project: Optional[str],
    project_source: str,
    collector: Collector,
    results: Dict[str, Any],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble the raw evidence dict the runner will wrap in an envelope.

    The envelope carries no `environment` field, so GCP_ENVIRONMENT goes here.
    """
    metadata: Dict[str, Any] = {
        "project": project,
        "project_source": project_source,
        "environment": os.environ.get("GCP_ENVIRONMENT"),
        "datetime": current_timestamp(),
        # Explicit so a validator can assert on it, not only the envelope status.
        "partial_failure": not collector.ok,
        "api_failures": collector.failures,
    }
    # Absent unless something was tolerated, keeping other payloads byte-for-byte.
    if collector.skipped:
        metadata["skipped_calls"] = collector.skipped
    return {"metadata": metadata, "results": results, "summary": summary}


def write_evidence(output_dir: Path, filename: str, evidence: Dict[str, Any]) -> Path:
    """Write the evidence dict deterministically (sorted keys, stable ordering)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    with open(path, "w") as f:
        json.dump(evidence, f, indent=2, sort_keys=True, default=str)
    return path


def coverage_percentage(covered: int, total: int) -> int:
    """Integer percentage, matching the AWS fetchers' summary math (0 when empty)."""
    return (covered * 100) // total if total > 0 else 0
