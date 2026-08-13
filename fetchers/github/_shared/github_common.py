"""Shared helpers for the GitHub evidence fetchers.

Every GitHub fetcher follows the same shape (mirroring the GCP category's
`_shared/gcp_common.py`): resolve the target organization, collect one evidence
set over the REST API, wrap it in a deterministic payload with a small metadata
block, and exit non-zero if any API call failed so a partial failure never looks
like success.

Design notes:
- **Auth is a declared secret, not an ambient credential.** GitHub has no
  instance-role / ADC equivalent — every call carries `Authorization: Bearer`.
  The runner resolves `github_token` and sets GITHUB_TOKEN for the child; see
  fetchers/_categories/github.yaml for the token types and read-only scopes.
- **Transport is `requests`.** Already a top-level dependency; no SDK is added.
  Pagination follows the `Link: <…>; rel="next"` header (parsed here, not by a
  client library), because the contract makes pagination the fetcher's job.
- **No retry logic.** The contract forbids it: a rate limit is reported as a
  failure with code `rate_limited`, never slept through. The runner owns
  scheduling; a fetcher that sleeps 15 minutes just gets killed at its timeout.
- **403 is two different things.** GitHub returns 403 both for "you are rate
  limited" (X-RateLimit-Remaining: 0 / Retry-After present) and for "your token
  may not read this". Those map to `rate_limited` and `not_authorized`
  respectively, and getting it wrong sends an operator chasing a permission bug
  during a rate-limit window.
- **Determinism.** Resource lists are sorted by a stable identifier and the file
  is written with sort_keys=True, so a re-run with unchanged configuration is
  byte-stable and regex validators stay quiet.
- **Secrets are never values.** Nothing here copies a secret value into
  evidence; the Actions fetcher projects secret *names* through an explicit
  allowlist. The resolved token is registered for redaction so it cannot appear
  in a recorded error message either.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import requests

# github.com by default; GHES/GHE.com override with GITHUB_API_URL (declared as
# a category passthrough_env so the runner's env whitelist lets it through).
DEFAULT_API_URL = "https://api.github.com"

# Pinned so a future default-version bump on GitHub's side cannot silently
# reshape captured evidence. Bump deliberately, with a re-verified run.
API_VERSION = "2022-11-28"

DEFAULT_HTTP_TIMEOUT = 30
PER_PAGE = 100

# Guard against a pathological pagination loop (a proxy echoing the same `next`
# link forever). 100 pages x 100 items is far beyond any real org.
MAX_PAGES = 100

# The ONLY codes the fetcher contract allows in $FETCHER_STATUS_FILE. Inventing
# a new one is a contract violation, so anything else degrades to internal_error.
STATUS_CODES = frozenset(
    {
        "auth_failed",
        "not_authorized",
        "target_unreachable",
        "rate_limited",
        "bad_config",
        "partial_failure",
        "internal_error",
    }
)

# Precedence when several calls failed with different codes and we must pick one
# reason for the status file. A misconfiguration or a dead credential explains
# every downstream failure, so it outranks them.
_CODE_PRECEDENCE = (
    "bad_config",
    "auth_failed",
    "rate_limited",
    "not_authorized",
    "target_unreachable",
    "internal_error",
)

# One line, and short enough to sit in envelope metadata without swallowing it.
_MAX_STATUS_ERROR_CHARS = 500

logger = logging.getLogger("github_common")


# --------------------------------------------------------------------------- #
# Redaction — belt and braces over the runner's own output redaction
# --------------------------------------------------------------------------- #

_REDACTIONS: Set[str] = set()


def register_redaction(value: Optional[str]) -> None:
    """Register a secret value to scrub from recorded messages and status files.

    The runner already redacts declared secrets from *captured output*, but an
    evidence file and $FETCHER_STATUS_FILE are written by us, not captured from
    us. Call this immediately after reading the token.
    """
    if value and len(value) >= 8:
        _REDACTIONS.add(value)


def redact(text: str) -> str:
    out = str(text)
    for secret in _REDACTIONS:
        out = out.replace(secret, "***")
    return out


# --------------------------------------------------------------------------- #
# Small shared primitives
# --------------------------------------------------------------------------- #

def current_timestamp() -> str:
    """UTC, second-resolution, Z-suffixed — matches every other category."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    """Make a target identifier safe for a per-target output filename.

    Fanout writes one file per organization; the runner discovers outputs by
    diffing the evidence dir, so each invocation MUST write a distinct name.
    """
    sanitized = (value or "").replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized) or "unknown"


def http_timeout() -> int:
    """Per-request timeout, resolved at call time.

    Read lazily (not as an import-time constant) so a malformed value degrades
    to the default with a warning instead of aborting with a bare int()
    ValueError before main() can log anything useful.
    """
    raw = os.environ.get("GITHUB_HTTP_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_HTTP_TIMEOUT
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "GITHUB_HTTP_TIMEOUT=%r is not an integer; using the %ds default",
            raw,
            DEFAULT_HTTP_TIMEOUT,
        )
        return DEFAULT_HTTP_TIMEOUT


class ConfigError(RuntimeError):
    """A precondition the operator must fix (missing env, unset target field).

    Carries `code = "bad_config"` so it lands in the status file as a
    configuration problem rather than an opaque internal error.
    """

    code = "bad_config"


def get_env(name: str) -> str:
    """Required env var, or ConfigError naming it."""
    value = os.environ.get(name, "")
    if not value:
        raise ConfigError(f"Missing required env var: {name}")
    return value


def api_base_url() -> str:
    """REST API root: github.com by default, GHES/GHE.com via GITHUB_API_URL."""
    return (os.environ.get("GITHUB_API_URL") or DEFAULT_API_URL).rstrip("/")


def int_env(name: str, default: int = 0) -> int:
    """Optional integer knob; a malformed value degrades to `default`."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default


def bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------- #
# Failure accumulation
# --------------------------------------------------------------------------- #

class Collector:
    """Tracks per-call API failures so a partial failure surfaces as exit 1.

    One repository of five being inaccessible must not exit 0 with quietly-empty
    data (the worst failure mode for a compliance tool). Call `guard()` around
    each API interaction; failures accumulate and drive the exit code, a
    `partial_failure` flag in the payload, and the $FETCHER_STATUS_FILE reason.

    Successes are counted too, only so `status_code` can tell "the credential is
    dead" (nothing worked -> auth_failed) apart from "we got most of it"
    (something worked -> partial_failure).
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.failures: List[Dict[str, Any]] = []
        self.successes = 0

    def record(self, operation: str, exc: BaseException) -> None:
        entry: Dict[str, Any] = {
            "operation": operation,
            "type": type(exc).__name__,
            "message": redact(str(exc)),
        }
        code = getattr(exc, "code", None)
        if code in STATUS_CODES:
            entry["code"] = code
        status = getattr(exc, "status", None)
        if isinstance(status, int):
            entry["http_status"] = status
        self.failures.append(entry)
        self.logger.error(
            "API call failed: %s (%s: %s)", operation, type(exc).__name__, redact(str(exc))
        )

    def guard(self, operation: str, fn: Callable[[], Any], default: Any = None) -> Any:
        """Run `fn()`, recording (not raising) any exception; returns `default`."""
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
            self.record(operation, exc)
            return default
        self.successes += 1
        return result

    @property
    def ok(self) -> bool:
        return not self.failures

    @property
    def status_code(self) -> str:
        """The single contract code that best explains this run's failure.

        Only the seven allowed codes are ever returned.
        """
        codes = [f.get("code") for f in self.failures if f.get("code")]
        if not codes:
            return "internal_error"
        if "bad_config" in codes:
            return "bad_config"
        # A dead credential explains everything; if some calls DID work the token
        # is fine and this is a genuine partial run.
        if "auth_failed" in codes and not self.successes:
            return "auth_failed"
        # Rate limiting outranks partial_failure: "wait and re-run" is the action,
        # and a bare partial_failure would hide it.
        if "rate_limited" in codes:
            return "rate_limited"
        if self.successes:
            return "partial_failure"
        return next(c for c in _CODE_PRECEDENCE if c in codes)

    @property
    def status_error(self) -> str:
        """One-line human-readable reason for $FETCHER_STATUS_FILE."""
        if not self.failures:
            return "collection failed"
        first = self.failures[0]
        operation, message = first["operation"], first["message"]
        # A GitHubAPIError message already opens with "GET <path>: …", so naming
        # the operation again would read "GET /orgs/x: GET /orgs/x: 401 …".
        # Compare without the query string, since the operation label carries it
        # ("GET /orgs/x/members?filter=2fa_disabled") and the message does not.
        reason = (
            message
            if message.startswith(operation.split("?")[0])
            else f"{operation}: {message}"
        )
        extra = len(self.failures) - 1
        if extra:
            reason = f"{reason} (+{extra} more failure{'s' if extra > 1 else ''})"
        return reason


# --------------------------------------------------------------------------- #
# The failure channel added by the fetcher contract (PR #26)
# --------------------------------------------------------------------------- #

def _one_line(text: str) -> str:
    collapsed = " ".join(str(text).split())
    if len(collapsed) > _MAX_STATUS_ERROR_CHARS:
        collapsed = collapsed[: _MAX_STATUS_ERROR_CHARS - 1] + "…"
    return collapsed or "collection failed"


def write_status(error: str, code: Optional[str] = None) -> Optional[Path]:
    """Write the failure reason to $FETCHER_STATUS_FILE.

    Required whenever a fetcher exits non-zero. Without it `metadata.error`
    falls back to the tail of stderr, so a closing "Evidence saved to …" INFO
    line becomes the reported failure reason — technically a log line, in
    practice a lie in the compliance record.

    Shape: {"error": "<one line>", "code": "<one of STATUS_CODES>"}. `code` is
    optional; an unrecognized one degrades to internal_error rather than
    inventing a code the runner does not know.

    Backward-compatible by design: with the env var unset this is a silent
    no-op, so the fetchers run unchanged against a runner that predates the
    clause. Best-effort — it never raises, because failing to write the reason
    for a failure must not replace the real failure.
    """
    path_str = os.environ.get("FETCHER_STATUS_FILE")
    if not path_str:
        return None

    payload: Dict[str, str] = {"error": _one_line(redact(error))}
    if code:
        if code in STATUS_CODES:
            payload["code"] = code
        else:
            logger.warning("status code %r is not in the contract; using internal_error", code)
            payload["code"] = "internal_error"

    try:
        path = Path(path_str)
        if path.parent and str(path.parent):
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True) + "\n")
        return path
    except OSError as exc:
        logger.warning("could not write FETCHER_STATUS_FILE %s: %s", path_str, exc)
        return None


# --------------------------------------------------------------------------- #
# REST transport
# --------------------------------------------------------------------------- #

class GitHubAPIError(RuntimeError):
    """A GitHub API call that failed, classified into a contract status code.

    `status` is the HTTP status (None for a transport-level failure) so callers
    can branch on the *expected* ones — a 404 from a branch-protection endpoint
    means "not protected", not "collection failed" — without treating them as
    failures.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: Optional[str] = None,
        resets_in: Optional[int] = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.resets_in = resets_in


def parse_next_link(link_header: Optional[str]) -> Optional[str]:
    """Extract the `rel="next"` URL from a GitHub `Link` response header.

    Parsed here rather than leaning on requests' `.links` so the pagination rule
    the contract makes ours is explicit and directly unit-testable.

        <https://api.github.com/orgs/x/repos?page=2>; rel="next",
        <https://api.github.com/orgs/x/repos?page=5>; rel="last"
    """
    if not link_header:
        return None
    for part in link_header.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url = segments[0].strip()
        if not (url.startswith("<") and url.endswith(">")):
            continue
        for attr in segments[1:]:
            key, _, value = attr.strip().partition("=")
            if key.strip().lower() == "rel" and value.strip().strip('"\'') == "next":
                return url[1:-1]
    return None


def _header_int(response: Any, name: str) -> Optional[int]:
    raw = (getattr(response, "headers", {}) or {}).get(name)
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


def _rate_limit_resets_in(response: Any) -> Optional[int]:
    """Seconds until the limit resets: Retry-After, else X-RateLimit-Reset."""
    retry_after = _header_int(response, "Retry-After")
    if retry_after is not None:
        return max(0, retry_after)
    reset_at = _header_int(response, "X-RateLimit-Reset")
    if reset_at is not None:
        return max(0, reset_at - int(time.time()))
    return None


def _body_message(response: Any) -> str:
    """GitHub's JSON `message`, falling back to a trimmed body."""
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 — HTML error page / empty body
        body = None
    if isinstance(body, dict):
        message = body.get("message")
        if message:
            return str(message)
    text = (getattr(response, "text", "") or "").strip()
    return text[:200]


def _is_rate_limited(response: Any, message: str) -> bool:
    """Distinguish a rate-limit 403 from a permission 403.

    GitHub overloads 403. Primary limits zero out X-RateLimit-Remaining;
    secondary limits send Retry-After and say so in the body. A permission
    denial has neither, and mislabelling it sends an operator hunting for a
    scope problem that does not exist (or vice versa).
    """
    if getattr(response, "status_code", None) == 429:
        return True
    if _header_int(response, "X-RateLimit-Remaining") == 0:
        return True
    if _header_int(response, "Retry-After") is not None:
        return True
    lowered = (message or "").lower()
    return "rate limit" in lowered or "abuse detection" in lowered


def _error_for(response: Any, path: str) -> GitHubAPIError:
    status = getattr(response, "status_code", None)
    message = _body_message(response)

    if status == 401:
        return GitHubAPIError(
            f"GET {path}: GitHub authentication failed (401: {message or 'Bad credentials'}) "
            "— check the token value, its expiry, and that it is scoped to this organization",
            status=status,
            code="auth_failed",
        )

    if status in (403, 429):
        if _is_rate_limited(response, message):
            resets_in = _rate_limit_resets_in(response)
            when = f", resets in {resets_in}s" if resets_in is not None else ""
            return GitHubAPIError(
                f"GitHub API rate limit exceeded{when} (GET {path})",
                status=status,
                code="rate_limited",
                resets_in=resets_in,
            )
        return GitHubAPIError(
            f"GET {path}: not authorized (403: {message or 'Forbidden'}) "
            "— the token is valid but lacks the read permission for this resource",
            status=status,
            code="not_authorized",
        )

    if status == 404:
        return GitHubAPIError(
            f"GET {path}: not found (404: {message or 'Not Found'}) — the resource does not "
            "exist, or the token cannot see it (GitHub returns 404 rather than 403 to avoid "
            "confirming private resources)",
            status=status,
            code="target_unreachable",
        )

    if isinstance(status, int) and status >= 500:
        return GitHubAPIError(
            f"GET {path}: GitHub API server error ({status}: {message})",
            status=status,
            code="target_unreachable",
        )

    return GitHubAPIError(
        f"GET {path}: unexpected GitHub API response ({status}: {message})",
        status=status,
        code="internal_error",
    )


def _warn_if_rate_limit_low(response: Any, path: str) -> None:
    remaining = _header_int(response, "X-RateLimit-Remaining")
    if remaining is not None and remaining <= 50:
        resets_in = _rate_limit_resets_in(response)
        logger.warning(
            "GitHub rate limit low: %s request(s) remaining%s (after GET %s)",
            remaining,
            f", resets in {resets_in}s" if resets_in is not None else "",
            path,
        )


def github_get(
    path: str,
    *,
    token: str,
    params: Optional[Dict[str, Any]] = None,
    items_key: Optional[str] = None,
) -> Any:
    """GET one GitHub REST resource, following `rel="next"` to the last page.

    - `path` is API-root-relative ("/orgs/acme/repos"); an absolute URL is used
      as given (that is how `next` links come back).
    - A JSON **array** response is paginated and returned concatenated.
    - A JSON **object** response is returned as-is (single resource).
    - `items_key` handles GitHub's counted-collection shape
      (`{"total_count": N, "secrets": [...]}`): pages are followed and the named
      list concatenated across them.

    Raises GitHubAPIError classified into a contract status code. Never retries
    and never sleeps — a rate limit is reported, not waited out.
    """
    url = path if path.startswith("http://") or path.startswith("https://") else f"{api_base_url()}{path}"
    query: Optional[Dict[str, Any]] = dict(params or {})
    query.setdefault("per_page", PER_PAGE)

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "Authorization": f"Bearer {token}",
        "User-Agent": "paramify-fetchers",
    }

    items: List[Any] = []
    paginating = False

    for page in range(1, MAX_PAGES + 1):
        try:
            response = requests.get(url, headers=headers, params=query, timeout=http_timeout())
        except requests.RequestException as exc:
            raise GitHubAPIError(
                f"GET {path}: could not reach the GitHub API ({type(exc).__name__}: {redact(str(exc))})",
                code="target_unreachable",
            ) from exc

        _warn_if_rate_limit_low(response, path)

        if response.status_code >= 400:
            raise _error_for(response, path)

        if response.status_code == 204 or not (response.content or b"").strip():
            data: Any = [] if (items_key or paginating) else {}
        else:
            try:
                data = response.json()
            except ValueError as exc:
                raise GitHubAPIError(
                    f"GET {path}: response was not JSON ({exc})",
                    status=response.status_code,
                    code="internal_error",
                ) from exc

        if items_key is not None:
            page_items = data.get(items_key) if isinstance(data, dict) else data
            items.extend(page_items or [])
            paginating = True
        elif isinstance(data, list):
            items.extend(data)
            paginating = True
        else:
            # Single object: no pagination to do.
            return data

        next_url = parse_next_link((getattr(response, "headers", {}) or {}).get("Link"))
        if not next_url:
            return items
        # The `next` link already carries page/per_page; re-sending params would
        # fight it (and requests would append duplicate query keys).
        url, query = next_url, None
        if page == MAX_PAGES:
            logger.warning(
                "GET %s: stopped after %d pages (%d items); a `next` link was still present",
                path,
                MAX_PAGES,
                len(items),
            )

    return items


# --------------------------------------------------------------------------- #
# Target resolution and payload assembly
# --------------------------------------------------------------------------- #

def resolve_organization(collector: Collector) -> Dict[str, Optional[str]]:
    """Resolve the organization to collect from.

    GITHUB_ORG is set by the runner from the manifest target. It is REQUIRED —
    there is no ambient "current organization". A token (fine-grained PAT or App
    installation token) can see several orgs plus personal repos and the API
    resolves no default, so inferring one would make the evidence set's contents
    change the day someone's token gains access to another org. Compliance
    evidence has to state which organization it describes.

    GITHUB_ORGANIZATION is accepted as an alias for operators who set the longer
    name by hand.
    """
    org = (os.environ.get("GITHUB_ORG") or os.environ.get("GITHUB_ORGANIZATION") or "").strip()
    if org:
        return {"organization": org, "organization_source": "target"}
    collector.record(
        "resolve_organization",
        ConfigError(
            "GITHUB_ORG is not set — add an `organization` target to the manifest entry "
            "(GitHub has no ambient default organization)"
        ),
    )
    return {"organization": None, "organization_source": "unresolved"}


def build_payload(
    *,
    organization: Optional[str],
    organization_source: str,
    collector: Collector,
    results: Dict[str, Any],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble the raw evidence dict the runner will wrap in an envelope.

    The envelope adds fetcher_name/version/status/target; this metadata block
    adds the GitHub-specific context. `api_url` is included because the same
    fetcher against github.com and against a GHES instance produces evidence
    about two different systems, and an auditor cannot tell them apart from the
    envelope alone.
    """
    return {
        "metadata": {
            "organization": organization,
            "organization_source": organization_source,
            "api_url": api_base_url(),
            "datetime": current_timestamp(),
            # Explicit so a validator can assert on it, and so a partially-failed
            # run is legible from the payload alone, not only the envelope status.
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
    """Integer percentage, matching the other categories' summary math."""
    return (covered * 100) // total if total > 0 else 0


def enabled(block: Any) -> Optional[bool]:
    """GitHub's `{"enabled": bool}` wrapper, tolerating a bare bool or absence.

    Branch-protection endpoints return every toggle as such an object; some
    fields come back as a bare boolean.
    """
    if isinstance(block, dict):
        value = block.get("enabled")
        return bool(value) if value is not None else None
    if isinstance(block, bool):
        return block
    return None
