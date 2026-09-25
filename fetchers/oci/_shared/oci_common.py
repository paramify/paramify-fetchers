"""Shared helpers for the Oracle Cloud Infrastructure evidence fetchers.

Every OCI fetcher resolves one tenancy, walks the compartment tree beneath a
chosen root, collects one evidence set, and exits non-zero if any API call
failed, so a partial failure never looks like success.

Nothing here imports the `oci` SDK at module scope — the imports stay lazy
inside the functions that need them, so the pure transforms (and their tests)
import with only the standard library present.

Resource lists are sorted by a stable identifier and written with
sort_keys=True, so a re-run against unchanged infrastructure is byte-stable and
regex validators stay quiet.

TWO THINGS THAT ARE OCI-SPECIFIC and bite immediately:

  * Everything is compartment-scoped. Almost every list call takes a
    `compartment_id` and returns only that compartment's resources — there is no
    tenancy-wide list. A fetcher that reads the tenancy root alone reports an
    empty estate for nearly every real tenancy, because the root is where nobody
    puts anything. `walk_compartments()` is the answer, and it is why these
    fetchers fan out over compartments rather than over regions.

  * `OCI_CLI_PROFILE` is read by the CLI, never by the Python SDK. Verified in
    the SDK source: `oci.config.from_file()` defaults to the literal "DEFAULT"
    and takes the profile as an argument. Setting the env var and expecting the
    SDK to honour it silently collects from the wrong profile, so
    `load_config()` reads it here and passes it through.
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
# This file is fetchers/oci/_shared/, so fetchers/_lib is parents[2] / "_lib".
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import STATUS_CODES, report_failure  # noqa: E402,F401

# The five config keys the API-key path needs, and the env var each is read
# from. `key_content` is the PEM itself: the SDK accepts it in a config DICT and
# refuses it in a config FILE, which is exactly the property that lets the runner
# inject it as a secret without anything touching disk.
API_KEY_ENV = {
    "user": "OCI_USER_OCID",
    "tenancy": "OCI_TENANCY_OCID",
    "fingerprint": "OCI_FINGERPRINT",
    "key_content": "OCI_PRIVATE_KEY",
    "region": "OCI_REGION",
}

# How the tenancy was authenticated, recorded in the evidence metadata. An
# assessor reading the file should not have to guess whether a human's laptop
# key or a workload identity produced it.
AUTH_API_KEY = "api_key"
AUTH_INSTANCE_PRINCIPAL = "instance_principal"
AUTH_RESOURCE_PRINCIPAL = "resource_principal"
AUTH_CONFIG_FILE = "config_file"


def current_timestamp() -> str:
    """UTC, second-resolution, Z-suffixed — matches the AWS/Azure/GCP format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    """Make a target identifier safe for a per-target output filename."""
    sanitized = (value or "").replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized) or "unknown"


def as_bool(value: Any, default: bool = False) -> bool:
    """Parse a runner-injected boolean.

    `framework/runner/executor.py::_coerce_env` renders booleans as lowercase
    "true"/"false", but a hand-written manifest may carry "True", "1" or "yes",
    so all of them are accepted.
    """
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


def short_ocid(ocid: Optional[str], keep: int = 8) -> Optional[str]:
    """Last `keep` characters of an OCID, for a human-readable summary line.

    OCIDs are ~100 characters and identical for their first sixty, so a summary
    listing them in full is unreadable. The full OCID always stays in the record.
    """
    if not ocid:
        return ocid
    return ocid[-keep:] if len(ocid) > keep else ocid


def to_plain(model: Any) -> Any:
    """An SDK model as a plain dict, with datetimes already stringified.

    `oci.util.to_dict` walks the model's swagger_types and renders datetimes as
    ISO-8601, which is what keeps the evidence JSON-serializable and stable.
    """
    from oci.util import to_dict  # lazy

    return to_dict(model)


def iso(value: Any) -> Optional[str]:
    """A model datetime as an ISO-8601 string, tolerating an already-string value."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def age_in_days(value: Any, *, now: Optional[datetime] = None) -> Optional[int]:
    """Whole days between `value` and now, or None when unparseable.

    Deliberately whole days: several fetchers report "how stale is this", and a
    float there makes two runs against unchanged infrastructure differ, which is
    the intermittent-test trap the Splunk work hit with "hours ago".
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return (reference - value).days


def _one_line(text: Any, limit: int = 800) -> str:
    """Collapse to a single bounded line: an OCI ServiceError carries an opc-request-id
    and a docs URL on their own lines, and the status file's `error` does not.
    """
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


# Substrings mapping a recorded failure onto a STATUS_CODES category, matched
# against "<exception type> <status> <code> <message>" lowercased. First hit
# wins, so the order is deliberate: a signing failure is auth, not a bad request.
_FAILURE_SIGNATURES = (
    ("auth_failed", (
        "invalidconfig", "configfilenotfound", "profilenotfound", "invalidkeyfilepath",
        "missingprivatekeypassphrase", "invalidprivatekey", "notauthenticated",
        "could not find config file", "no such file or directory: '~/.oci",
        "the required information to complete authentication was not provided",
        "401",
    )),
    ("not_authorized", (
        "notauthorizedorunauthorized", "notauthorized", "forbidden", "403",
        "notallowed", "cannotparserequest.*policy",
    )),
    ("rate_limited", ("toomanyrequests", "429", "ratelimit", "quotaexceeded")),
    ("target_unreachable", (
        "requestexception", "connectionerror", "connecttimeout", "readtimeout",
        "timeout", "timed out", "name resolution", "getaddrinfo", "502", "503", "504",
    )),
    # 404 is OCI's answer for "no permission on this compartment" as well as a
    # genuinely absent resource, so it lands in bad_config rather than
    # not_authorized — the ledger carries the detail either way.
    ("bad_config", (
        "invalidparameter", "badrequest", "notfound", "limitexceeded",
        "missingparameter", "400", "404", "409",
    )),
)

# Keeps the one-line reason legible in a UI cell; api_failures has the full ledger.
_MAX_REPORTED_FAILURES = 3
_MAX_REPORTED_MESSAGE_CHARS = 200


def _failure_code(failure: Dict[str, str]) -> str:
    blob = " ".join(
        str(failure.get(k, "")) for k in ("type", "status", "code", "message")
    ).lower()
    for code, signatures in _FAILURE_SIGNATURES:
        if any(sig in blob for sig in signatures):
            return code
    return "internal_error"


def _service_error_parts(exc: BaseException) -> Dict[str, str]:
    """status / code / opc-request-id off an oci.exceptions.ServiceError.

    Read by attribute rather than isinstance so this module stays importable
    without the SDK, and so a wrapped or re-raised error still yields its parts.
    """
    parts: Dict[str, str] = {}
    for attr in ("status", "code", "request_id"):
        value = getattr(exc, attr, None)
        if value is not None:
            parts["opc_request_id" if attr == "request_id" else attr] = str(value)
    return parts


def not_found_or_not_subscribed(exc: BaseException) -> bool:
    """service_not_subscribed, plus a bare 404 NotAuthorizedOrNotFound.

    ONLY for a call whose 404 is known to mean "never enabled" AND whose caller
    tells that apart from a denial by other means — ZPR's configuration, which
    404s until ZPR is switched on (seen live), and which zpr_policies weighs
    against whether any policy came back; and ZPR's listings, only once that
    configuration has 404'd too. Anywhere else a 404 is a missing grant.
    """
    text = f"{type(exc).__name__} {getattr(exc, 'code', '')} {exc}".lower()
    if "notauthorizedornotfound" in text or "authorization failed or requested resource not found" in text:
        return True
    return service_not_subscribed(exc)


def service_not_subscribed(exc: BaseException) -> bool:
    """True when OCI says in so many words that the service is not subscribed.

    A bare 404 NotAuthorizedOrNotFound is NOT enough: it is also exactly what a
    missing policy grant returns, so reading it as "not subscribed" would let a
    collector without `read bastion` exit 0 reporting Bastion as unavailable.
    On a bare trial tenancy every service these fetchers call answered an empty list, never a
    404. Pass as `guard(tolerate=…)`.
    """
    text = f"{type(exc).__name__} {getattr(exc, 'code', '')} {exc}".lower()
    return any(
        marker in text
        for marker in (
            "servicenotsubscribed",
            "not subscribed",
            "tenant is not subscribed",
            "service is not enabled",
            "is not enabled for this tenancy",
        )
    )


def access_denied(exc: BaseException) -> bool:
    """True for a 403 / policy-denied error.

    Tolerable only for reads the collecting user is not expected to hold a policy
    for — a tenancy-wide read from a compartment-scoped principal. Anywhere else
    it is a missing policy statement the operator must fix, not evidence.
    """
    text = f"{type(exc).__name__} {getattr(exc, 'code', '')} {exc}".lower()
    if getattr(exc, "status", None) == 403:
        return True
    return any(marker in text for marker in ("notauthorized", "forbidden", "403"))


class Collector:
    """Tracks per-call API failures so a partial failure surfaces as exit 1.

    One unreadable compartment of forty must not exit 0 with quietly-empty data;
    failures drive the exit code, the `partial_failure` flag, and the runner reason.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.failures: List[Dict[str, str]] = []
        self.skipped: List[Dict[str, str]] = []

    def record(self, operation: str, exc: BaseException) -> None:
        failure = {"operation": operation, "type": type(exc).__name__, "message": _one_line(exc)}
        failure.update(_service_error_parts(exc))
        self.failures.append(failure)
        self.logger.error(
            "API call failed: %s (%s: %s)", operation, type(exc).__name__, _one_line(exc, 200)
        )

    def skip(self, operation: str, exc: BaseException) -> None:
        """Record a call whose failure is itself evidence.

        Kept out of `failures` so it sets neither partial_failure nor the exit
        code, but still written to metadata.skipped_calls — a silently absent
        result is the failure mode this module exists to avoid.
        """
        skipped = {"operation": operation, "type": type(exc).__name__, "message": _one_line(exc)}
        skipped.update(_service_error_parts(exc))
        self.skipped.append(skipped)
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

        A matching `tolerate` (`service_not_subscribed`, `access_denied`) routes
        to `skip()`.
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

        A unanimous cause is reported as itself — an expired signing key takes
        down every call, and `auth_failed` says more than `partial_failure`.
        Mixed causes report `partial_failure` and leave the detail to the ledger.
        """
        codes = {_failure_code(f) for f in self.failures}
        code = codes.pop() if len(codes) == 1 else "partial_failure"

        detail = "; ".join(
            f"{f['operation']} ({f['type']}: {f['message'][:_MAX_REPORTED_MESSAGE_CHARS]})"
            for f in self.failures[:_MAX_REPORTED_FAILURES]
        )
        noun = "call" if len(self.failures) == 1 else "calls"
        return _one_line(f"{len(self.failures)} OCI API {noun} failed: {detail}"), code


# --- auth ---

def _api_key_config() -> Optional[Dict[str, str]]:
    """A config dict from the five API-key env vars, or None if any is missing.

    All five or none: a partially-set environment is an operator mistake, and
    falling through to the config file would collect from the wrong tenancy
    while looking like it worked.
    """
    values = {key: os.environ.get(env) for key, env in API_KEY_ENV.items()}
    if not all(values.values()):
        return None
    config = {k: v for k, v in values.items() if v is not None}
    passphrase = os.environ.get("OCI_PRIVATE_KEY_PASSPHRASE")
    if passphrase:
        config["pass_phrase"] = passphrase
    return config


def load_config(collector: Collector) -> Dict[str, Any]:
    """Resolve credentials, returning {config, signer, auth_method, tenancy}.

    Order: explicit API-key env vars, then an explicitly requested principal,
    then resource principal (which announces itself via the env), then the
    config file. `signer` is None on the API-key and config-file paths, where the
    config dict alone is enough to build a client.
    """
    import oci  # lazy

    requested = (os.environ.get("OCI_CLI_AUTH") or "").strip().lower()

    api_key = _api_key_config()
    if api_key and requested in ("", "api_key"):
        oci.config.validate_config(api_key)
        return {
            "config": api_key,
            "signer": None,
            "auth_method": AUTH_API_KEY,
            "tenancy": api_key["tenancy"],
        }

    if requested == AUTH_INSTANCE_PRINCIPAL:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        return {
            "config": {"region": os.environ.get("OCI_REGION") or signer.region},
            "signer": signer,
            "auth_method": AUTH_INSTANCE_PRINCIPAL,
            "tenancy": signer.tenancy_id,
        }

    if requested == AUTH_RESOURCE_PRINCIPAL or os.environ.get("OCI_RESOURCE_PRINCIPAL_VERSION"):
        signer = oci.auth.signers.get_resource_principals_signer()
        return {
            "config": {"region": os.environ.get("OCI_REGION") or getattr(signer, "region", None)},
            "signer": signer,
            "auth_method": AUTH_RESOURCE_PRINCIPAL,
            "tenancy": getattr(signer, "tenancy_id", None),
        }

    # OCI_CLI_PROFILE is the CLI's spelling and the SDK ignores it — see the
    # module docstring. Read it here so the documented env var actually works.
    profile = os.environ.get("OCI_CLI_PROFILE") or oci.config.DEFAULT_PROFILE
    # Passed explicitly: the SDK reads OCI_CONFIG_FILE only when ~/.oci/config
    # does NOT exist, so on a host with both, a deployment pointed at a
    # restricted collector's config silently collected with ~/.oci/config.
    location = os.environ.get("OCI_CONFIG_FILE") or oci.config.DEFAULT_LOCATION
    config = oci.config.from_file(file_location=location, profile_name=profile)
    # A target's `region` arrives as OCI_REGION and must win over the profile's,
    # as it already does on the principal paths — otherwise a per-region fanout
    # target silently collects the profile's region every time.
    if os.environ.get("OCI_REGION"):
        config["region"] = os.environ["OCI_REGION"]
    oci.config.validate_config(config)
    return {
        "config": config,
        "signer": None,
        "auth_method": AUTH_CONFIG_FILE,
        "tenancy": config["tenancy"],
    }


def make_client(client_class: Any, auth: Dict[str, Any], **kwargs: Any) -> Any:
    """Build an SDK client from a `load_config()` result.

    One place, because the signer paths take `signer=` and the config paths must
    not — passing signer=None to a client that expects a config is a TypeError
    at the worst possible moment, inside a collection.

    Every client retries. The SDK's global retry strategy is None unless set,
    so without this a single 429 or 5xx on a large tenancy failed the whole
    collection. DEFAULT_RETRY_STRATEGY backs off with jitter on throttling,
    5xx, timeouts and connection errors, and never on a 404 — so a missing
    permission still fails fast.
    """
    import oci  # lazy

    kwargs.setdefault("retry_strategy", oci.retry.DEFAULT_RETRY_STRATEGY)
    if auth.get("signer") is not None:
        return client_class(auth["config"], signer=auth["signer"], **kwargs)
    return client_class(auth["config"], **kwargs)


# --- compartments ---

def list_all(list_fn: Callable[..., Any], *args: Any, **kwargs: Any) -> List[Any]:
    """Every page of a list call, as a flat list of models.

    `oci.pagination.list_call_get_all_results` follows `opc-next-page` for both
    of the SDK's list shapes — a bare list in `.data` and a `.data.items`
    collection — so no fetcher has to know which one an endpoint returns.
    """
    from oci.pagination import list_call_get_all_results  # lazy

    return list_call_get_all_results(list_fn, *args, **kwargs).data


# Above OCI's own maximum compartment nesting depth, so the manual walk below
# never truncates a real tenancy — it only bounds a cycle.
_MAX_COMPARTMENT_DEPTH = 25


def walk_compartments(
    identity_client: Any,
    root: str,
    collector: Collector,
    *,
    include_subcompartments: bool = True,
    tenancy: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """The root compartment plus, optionally, every ACTIVE compartment beneath it.

    TWO WALKS, because OCI only supports the fast one from the tenancy root.
    `compartment_id_in_subtree=True` is rejected with

        400 InvalidParameter: compartmentId must be tenancy ocid when list all
        compartments under tenancy is used

    for any child compartment — verified against the live API, not the docs. So
    a run scoped to the tenancy uses the one-call subtree listing, and a run
    scoped to a child compartment walks the tree breadth-first by hand. Getting
    this wrong is not subtle but it is invisible without a child compartment to
    test against: every fanout target would have recorded a 400 and reported a
    partial failure while collecting nothing.

    `access_level="ACCESSIBLE"` asks OCI to return only compartments this
    principal can actually read, which keeps a narrowly-scoped collector from
    recording a 404 per inaccessible compartment. It is only accepted alongside
    the subtree listing, so the manual walk cannot use it and tolerates the
    resulting per-compartment denial instead.

    The root is included explicitly because `list_compartments` never returns the
    compartment it was asked about — a fetcher that used the call's output alone
    would silently skip every resource in the compartment it was pointed at.
    """
    compartments = [{"id": root, "name": "root", "is_root": True}]

    # The target itself must be readable. Below it, a denied child is scoping
    # and is tolerated; but tolerating the TARGET turned a mistyped compartment
    # OCID into a clean run: the walk skipped it, the service call's 404 read as
    # "not subscribed", and the evidence said success with nothing found.
    if not (tenancy and root == tenancy):
        target = collector.guard(
            f"identity.get_compartment ({short_ocid(root)})",
            lambda: identity_client.get_compartment(root).data,
        )
        if target is None:
            return []
        if getattr(target, "lifecycle_state", "ACTIVE") != "ACTIVE":
            collector.record(
                f"identity.get_compartment ({short_ocid(root)})",
                RuntimeError(f"target compartment is {target.lifecycle_state}, not ACTIVE"),
            )
            return []

    if not include_subcompartments:
        return compartments

    def _record(comp: Any) -> None:
        compartments.append(
            {
                "id": comp.id,
                "name": comp.name,
                "description": getattr(comp, "description", None),
                "is_root": False,
            }
        )

    if tenancy and root == tenancy:
        def _subtree() -> List[Any]:
            return list_all(
                identity_client.list_compartments,
                root,
                compartment_id_in_subtree=True,
                access_level="ACCESSIBLE",
                lifecycle_state="ACTIVE",
            )

        for comp in collector.guard("identity.list_compartments", _subtree, default=[]) or []:
            _record(comp)
        return compartments

    # Breadth-first, one level per call. Bounded by _MAX_COMPARTMENT_DEPTH
    # because OCI allows nesting and a cycle would otherwise hang the run;
    # the limit is above OCI's own maximum nesting depth, so it never truncates
    # a real tenancy.
    frontier = [root]
    seen = {root}
    for _ in range(_MAX_COMPARTMENT_DEPTH):
        if not frontier:
            break
        next_frontier: List[str] = []
        for parent in frontier:
            def _children(p=parent) -> List[Any]:
                return list_all(identity_client.list_compartments, p, lifecycle_state="ACTIVE")

            for comp in collector.guard(
                f"identity.list_compartments ({short_ocid(parent)})",
                _children,
                default=[],
                # A compartment this principal cannot read is evidence of scoping,
                # not a collection failure — the subtree listing would simply have
                # omitted it via access_level=ACCESSIBLE.
                tolerate=access_denied,
            ) or []:
                if comp.id in seen:
                    continue
                seen.add(comp.id)
                _record(comp)
                next_frontier.append(comp.id)
        frontier = next_frontier
    return compartments


def resolve_scope(auth: Dict[str, Any]) -> Dict[str, Any]:
    """The compartment this run collects from, and where that choice came from."""
    explicit = os.environ.get("OCI_COMPARTMENT_ID")
    if explicit:
        return {"compartment_id": explicit, "compartment_source": "target"}
    return {"compartment_id": auth.get("tenancy"), "compartment_source": "tenancy_root"}


# --- output ---

def build_payload(
    *,
    auth: Dict[str, Any],
    scope: Dict[str, Any],
    collector: Collector,
    results: Dict[str, Any],
    summary: Dict[str, Any],
    compartments_scanned: Optional[int] = None,
    regional: bool = True,
) -> Dict[str, Any]:
    """Assemble the raw evidence dict the runner will wrap in an envelope.

    `auth_method` and `region` are here because they are the two facts an
    assessor cannot recover from the payload otherwise: which identity produced
    this file, and which region answered.
    """
    metadata: Dict[str, Any] = {
        "tenancy_id": auth.get("tenancy"),
        "region": (auth.get("config") or {}).get("region"),
        "auth_method": auth.get("auth_method"),
        "compartment_id": scope.get("compartment_id"),
        "compartment_source": scope.get("compartment_source"),
        "environment": os.environ.get("OCI_ENVIRONMENT"),
        "datetime": current_timestamp(),
        # Explicit so a validator can assert on it, not only the envelope status.
        "partial_failure": not collector.ok,
        "api_failures": collector.failures,
    }
    if compartments_scanned is not None:
        metadata["compartments_scanned"] = compartments_scanned
    if regional and auth.get("tenancy"):
        metadata.update(region_coverage(auth, collector))
    # Absent unless something was tolerated, keeping other payloads byte-for-byte.
    if collector.skipped:
        metadata["skipped_calls"] = collector.skipped
    return {"metadata": metadata, "results": results, "summary": summary}


def region_coverage(auth: Dict[str, Any], collector: Collector) -> Dict[str, Any]:
    """Which subscribed regions this run did NOT collect.

    Every regional list call answers for one region, so a tenancy subscribed to
    two regions produces evidence covering half of it with nothing failing.
    Stated in the metadata so "no public buckets" can be read as "no public
    buckets in us-phoenix-1". Fan out one target per region to cover them all.
    A failed lookup is skipped, not failed: it is context, not evidence.
    """
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    subscriptions = collector.guard(
        "identity.list_region_subscriptions",
        lambda: identity.list_region_subscriptions(auth["tenancy"]).data,
        tolerate=lambda exc: True,
    )
    if subscriptions is None:
        return {}
    subscribed = sorted(r.region_name for r in subscriptions if r.status == "READY")
    collected = (auth.get("config") or {}).get("region")
    return {
        "regions_subscribed": subscribed,
        "regions_not_collected": [r for r in subscribed if r != collected],
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


def finish(
    collector: Collector,
    logger: logging.Logger,
    path: Path,
) -> int:
    """The shared epilogue: exit code, failure reason, and the one success line.

    Mirrors `aws_finish` (upstream commit a75ea20). The order matters — the
    runner's fallback reads the TAIL of stderr, so the "Evidence saved" INFO line
    must never be the last thing a failed run logs.
    """
    if not collector.ok:
        reason, code = collector.failure_report()
        logger.error("%s", reason)
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0
