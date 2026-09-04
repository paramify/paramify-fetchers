#!/usr/bin/env python3
"""
Shared Splunk management-API client for the splunk fetcher category.

Splunk's management API listens on port 8089 (separate from the 8000 web UI)
and speaks Atom XML by default; `output_mode=json` switches it to JSON, which
every call here does. Collections answer:

    {"entry": [{"name": ..., "content": {...}, "acl": {...}}, ...],
     "paging": {"total": N, "perPage": M, "offset": O},
     "messages": []}

Endpoint paths, the auth header forms and the `count`/`offset` paging
parameters are taken from Splunk's own SDK (github.com/splunk/splunk-sdk-python,
`splunklib/client.py` and `splunklib/binding.py`), not from prose docs.

Three things about this API are worth knowing before reading anything else,
because each is a silent-wrong-answer trap rather than an error:

1. **Value types are inconsistent, per field and per rendering.** Verified
   against a real Splunk Enterprise 10.4.2 (see the correction note below):
   under `output_mode=json`, `disabled` and `enableDataIntegrityControl` are
   native JSON booleans, `totalEventCount` and `frozenTimePeriodInSecs` are
   native integers — but `currentDBSizeMB` is a **string** in the same
   response. Splunk's Atom rendering, which is the default and what the SDK
   parses, makes every one of them a string, which is why the SDK's own
   integration tests assert `index["disabled"] == "0"`.

   So there is no single rule to rely on, and `"0"` is truthy in Python.
   Nothing here reads a raw value in a boolean or arithmetic context — it goes
   through `as_bool` / `as_int`, which accept both renderings.

2. **`count` defaults to 30.** Not to "all". Confirmed against 10.4.2 with 46
   indexes present: a bare request returns 30 of them, with `paging.perPage`
   30 and `paging.total` 46. A collection read without an explicit count
   silently returns the first page and looks complete.

3. **A 200 can carry `messages[]`**, which is where Splunk puts partial
   failures and warnings. `raise_for_status()` sees nothing wrong. On a
   healthy single instance it is always `[]`; the handling is defensive and is
   the one behaviour here NOT observed on a real server.

A correction, kept because it is the finding
--------------------------------------------
This module was first written asserting that every Splunk value is a string,
inferred from the SDK's integration tests. Running it against a real 10.4.2
showed that is true of the Atom rendering and only partly true of the JSON one.
The coercion was right; the stated reason was wrong, and the real rule (types
vary by field) is a stronger argument for coercing than the one it replaced.

Similarly, the capability table in the README used to claim `list_indexes`
gates `GET /services/data/indexes`. It does not — a user whose role holds none
of it reads all 46 indexes. `indexes_edit` gates writes. See the README.

Collection-failure convention (see docs/authoring_a_fetcher.md): a failed call
appends to `api_failures` and returns None rather than raising, so one bad
endpoint does not lose the evidence already collected. The caller exits
non-zero when `api_failures` is non-empty. Authentication failure is the one
exception — no call can succeed without a session, so it raises.

How this category is put together
---------------------------------
Read this first if you are picking the category up.

    fetchers/splunk/
      _shared/splunk_client.py     <- you are here: API client + the shared entry point
      <evidence_set>/
        fetcher.py         <- collect() + summarize(), one evidence set each
        fetcher.yaml       <- the manifest the runner reads

Every fetcher is the same three pieces, and only the middle one is interesting:

1. **collect()** — build the client, call the endpoints, hand the records to
   summarize(), return `evidence(...)`. Usually under 30 lines, because
   everything generic lives here in _shared.
2. **summarize()** — turn raw API records into the numbers an assessor reads.
   This is where the judgement is, and where every bug this category has ever
   had was found.
3. **`sys.exit(run_fetcher(collect, "<name>.json", logger))`** — the whole entry
   point. Logging, .env, the output directory, the catch-all and the exit code
   are all in `run_fetcher` below.

Two rules that are not obvious and are load-bearing:

- **No fetcher decides pass or fail.** These report what is configured and name
  what a reviewer should look at. The verdict is Paramify's, downstream. If you
  find yourself writing `compliant: True`, stop.
- **An empty result and a broken collection must never look alike.** `status` is
  `success` or `partial_or_empty` — both are healthy, exit 0. A *fault* is
  `api_failures` being non-empty, which exits non-zero even if records came
  back. Most of the bugs found here were a partial collection reporting success,
  so this distinction is the thing to preserve when changing anything.

Adding a fetcher to this category: copy the smallest existing one, keep
collect() thin, put the thinking in summarize(), and add a test that fails if
your summary is wrong. Then break your own fix on purpose and check the test
actually catches it — that pass has caught three tests here that asserted
nothing.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

logger = logging.getLogger("splunk._shared")

DEFAULT_BASE_URL = "https://localhost:8089"
DEFAULT_TIMEOUT = 30

# Splunk's default page size is 30. Every collection read here sets one
# explicitly; a bare request looks like a complete answer and is not.
PAGE_SIZE = 100

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 2
MAX_BACKOFF_SECONDS = 60

# A cursor that does not advance would otherwise loop forever.
MAX_PAGES = 1000

# The string spellings of a boolean. "0"/"1" is what the Atom rendering sends
# and what several JSON fields still use; the .conf files behind the API also
# accept the long spellings and some endpoints echo those back, so both are
# handled. Native JSON booleans are handled ahead of these, in as_bool.
TRUE_STRINGS = {"1", "true", "t", "yes", "y", "on"}
FALSE_STRINGS = {"0", "false", "f", "no", "n", "off"}


class SplunkAuthError(RuntimeError):
    """Raised when authentication fails. Fatal — nothing can proceed."""


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def as_bool(value: Any) -> Optional[bool]:
    """
    Splunk's booleans, in whichever rendering arrived.

    Returns None for anything unrecognized rather than guessing. A field whose
    value we cannot read is not the same as a field that is off, and in evidence
    the difference matters: reporting "integrity control disabled" because a
    value was spelled unexpectedly is a finding the tenant did not earn, and
    reporting it enabled would be worse.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        folded = value.strip().lower()
        if folded in TRUE_STRINGS:
            return True
        if folded in FALSE_STRINGS:
            return False
    return None


def as_int(value: Any) -> Optional[int]:
    """
    A Splunk number, whether it arrived as an int or a string.

    Both happen in the same response: on 10.4.2 `totalEventCount` is an int and
    `currentDBSizeMB` is a string. None when it is not a number at all.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def resolve_base_url() -> str:
    return os.environ.get("SPLUNK_BASE_URL", "").strip().rstrip("/") or DEFAULT_BASE_URL


def resolve_verify() -> Tuple[Any, Optional[str]]:
    """
    TLS verification setting, and the reason if it is off.

    Splunk ships a self-signed certificate on 8089, so turning verification off
    is the well-trodden path and most integration guides say to. It is still a
    choice an assessor needs to see: evidence collected over an unauthenticated
    channel cannot rule out an interposed host. So it is opt-in by name, and
    whichever way it resolves travels in the evidence file.

    SPLUNK_CA_BUNDLE points at the CA that signed the Splunk certificate and is
    the right answer. SPLUNK_VERIFY_SSL=false is the escape hatch.
    """
    bundle = os.environ.get("SPLUNK_CA_BUNDLE", "").strip()
    if bundle:
        return bundle, None

    raw = os.environ.get("SPLUNK_VERIFY_SSL", "").strip()
    if raw and as_bool(raw) is False:
        return False, "SPLUNK_VERIFY_SSL was set false"
    return True, None


class SplunkClient:
    """Minimal read-only Splunk management-API client with failure tracking."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        verify: Any = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify = verify
        self.api_failures: List[Dict[str, Any]] = []
        # How the session was established. An assessor reading the evidence
        # should be able to tell a scoped API token from a password login.
        self.auth_method: Optional[str] = None
        self.server_info: Dict[str, Any] = {}
        self._token = token
        self._username = username
        self._password = password
        self._session_key: Optional[str] = None

    # --- auth -------------------------------------------------------------

    def authenticate(self) -> None:
        """
        A bearer token when one is configured, otherwise a session login.

        Splunk authentication tokens (Settings > Tokens) are the right
        credential for this: they carry the creating user's roles, can be given
        an expiry, and are revocable without changing a password. The
        username/password path exists because a fresh trial instance has no
        tokens enabled yet, which is exactly when someone first runs this.
        """
        if self._token:
            self.auth_method = "bearer_token"
            logger.info("Using a Splunk bearer token against %s", self.base_url)
            return

        if not (self._username and self._password):
            raise SplunkAuthError(
                "No credentials: set SPLUNK_TOKEN, or SPLUNK_USERNAME and SPLUNK_PASSWORD"
            )

        endpoint = f"{self.base_url}/services/auth/login"
        try:
            response = requests.post(
                endpoint,
                data={
                    "username": self._username,
                    "password": self._password,
                    "output_mode": "json",
                },
                timeout=self.timeout,
                verify=self.verify,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as e:
            raise SplunkAuthError(f"Session login to {endpoint} failed: {e}") from e
        except ValueError as e:
            raise SplunkAuthError(f"Session login response from {endpoint} was not JSON: {e}") from e

        session_key = payload.get("sessionKey")
        if not session_key:
            raise SplunkAuthError(f"Session login response from {endpoint} contained no sessionKey")

        self._session_key = session_key
        self.auth_method = "session_key"
        logger.info("Authenticated to %s as %s", self.base_url, self._username)

    def _headers(self) -> Dict[str, str]:
        if self._token:
            # Splunk accepts a JWT as a standard bearer token.
            return {"Authorization": f"Bearer {self._token}"}
        if self._session_key:
            # A session key uses Splunk's own scheme, not Bearer.
            return {"Authorization": f"Splunk {self._session_key}"}
        raise SplunkAuthError("Not authenticated")

    # --- requests ---------------------------------------------------------

    def _retry_delay(self, response: Any, attempt: int) -> float:
        retry_after = None
        if response is not None:
            retry_after = (getattr(response, "headers", {}) or {}).get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), MAX_BACKOFF_SECONDS)
            except (TypeError, ValueError):
                pass
        return min(BACKOFF_BASE_SECONDS**attempt, MAX_BACKOFF_SECONDS)

    def request(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        One GET, with bounded retry. Returns the decoded body, or None after
        recording the failure.

        Read-only by construction: there is no method parameter. Nothing in this
        category has any business writing to a customer's Splunk, and a client
        that cannot express a write cannot be talked into one.
        """
        endpoint = f"{self.base_url}{path}"
        query = dict(params or {})
        query["output_mode"] = "json"

        last_error: Optional[Exception] = None
        last_response: Any = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = requests.get(
                    endpoint,
                    headers=self._headers(),
                    params=query,
                    timeout=self.timeout,
                    verify=self.verify,
                )
            except requests.exceptions.RequestException as e:
                last_error, last_response = e, None
                if attempt < MAX_RETRIES:
                    time.sleep(self._retry_delay(None, attempt))
                    continue
                break

            if response.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                delay = self._retry_delay(response, attempt)
                logger.warning(
                    "GET %s returned %s; retrying in %.1fs (attempt %d/%d)",
                    path,
                    response.status_code,
                    delay,
                    attempt + 1,
                    MAX_RETRIES,
                )
                time.sleep(delay)
                continue

            try:
                response.raise_for_status()
                body = response.json()
                self._record_messages(endpoint, body)
                return body
            except requests.exceptions.RequestException as e:
                last_error, last_response = e, response
                break
            except ValueError as e:
                last_error, last_response = e, response
                break

        if last_error is not None:
            self._record_failure(endpoint, last_error, last_response)
        return None

    def _record_messages(self, endpoint: str, body: Any) -> None:
        """
        Surface `messages[]` returned alongside a successful response.

        Splunk reports partial failures and warnings this way — a search peer
        that did not answer, a knowledge object that could not be read — with a
        200 and the reason in the body. Without this the run reports success
        over evidence that is quietly incomplete, which for a compliance fetcher
        is the worst shape an error can take: fewer records than the deployment
        actually has, presented as a clean result.

        Splunk also uses `messages` for INFO-level chatter, so only WARN and
        above is treated as a failure. The rest is logged and dropped.
        """
        if not isinstance(body, dict):
            return
        messages = body.get("messages")
        if not messages or not isinstance(messages, list):
            return

        serious = [
            m
            for m in messages
            if isinstance(m, dict)
            and str(m.get("type", "")).upper() not in {"INFO", "DEBUG", "HTTP"}
        ]
        for message in messages:
            logger.info("%s message: %s", endpoint, message)

        if serious:
            logger.error("%s returned %d warning(s): %s", endpoint, len(serious), serious)
            self.api_failures.append(
                {
                    "endpoint": endpoint,
                    "error": "response returned messages alongside its entries",
                    "api_messages": serious,
                    "partial": True,
                }
            )

    def _record_failure(self, endpoint: str, error: Exception, response: Any) -> None:
        failure: Dict[str, Any] = {
            "endpoint": endpoint,
            "type": type(error).__name__,
            "message": str(error),
        }
        if response is not None:
            failure["status_code"] = getattr(response, "status_code", None)
            try:
                body = response.json()
                if isinstance(body, dict) and body.get("messages"):
                    # Splunk names the missing capability here, which is the
                    # difference between "wrong password" and "this role cannot
                    # read indexes".
                    failure["api_messages"] = body["messages"]
            except Exception:  # noqa: BLE001 - a non-JSON error body is not itself a failure
                pass
        self.api_failures.append(failure)
        logger.warning("API call to %s failed: %s", endpoint, error)

    # --- pagination -------------------------------------------------------

    def _pagination_stalled(self, path: str, collected: int) -> None:
        """
        A page that returned entries, none of which were new.

        Offset paging assumes the server honours `offset`. One that does not
        hands back page one every time, and the client's own offset counter
        still advances — so the walk terminates against `paging.total` looking
        perfectly healthy while the evidence is the first page repeated and
        every later record is **missing**.

        That is the same failure the crowdstrike client hit as a repeating
        cursor, arriving through integer offsets instead. Stopping is right;
        being quiet about it is not, because a truncated collection that reports
        success is indistinguishable from a small deployment.
        """
        self.api_failures.append(
            {
                "endpoint": f"{self.base_url}{path}",
                "type": "PaginationNotAdvancing",
                "message": (
                    f"A page returned only entries already collected, after {collected} "
                    "unique records. The server is not honouring `offset`. Evidence is "
                    "incomplete."
                ),
            }
        )
        logger.error("Pagination stopped advancing on %s after %d records", path, collected)

    def _page_cap_reached(self, path: str, collected: int) -> None:
        self.api_failures.append(
            {
                "endpoint": f"{self.base_url}{path}",
                "type": "PaginationLimitExceeded",
                "message": (
                    f"Stopped after {MAX_PAGES} pages with {collected} entries collected; "
                    "the offset did not terminate. Evidence may be incomplete."
                ),
            }
        )
        logger.error("Pagination cap hit on %s after %d entries", path, collected)

    def collect(
        self, path: str, params: Optional[Dict[str, Any]] = None, page_size: int = PAGE_SIZE
    ) -> List[Dict[str, Any]]:
        """
        Every entry in a collection, following `count`/`offset` to the end.

        Terminates on an empty page, not on `paging.total`. `total` is a useful
        corroboration and a poor terminator: it is absent on some endpoints, and
        on a deployment being written to underneath the walk it can be stale in
        either direction. An empty page is unambiguous. A short page is *not*
        the end — Splunk can return fewer entries than asked for and still have
        more, and treating that as the end is how a paginator quietly collects
        a fraction of a deployment and reports success.
        """
        collected: List[Dict[str, Any]] = []
        seen: set = set()
        duplicates = 0
        offset = 0

        for _ in range(MAX_PAGES):
            page_params = dict(params or {})
            page_params["count"] = page_size
            page_params["offset"] = offset

            body = self.request(path, params=page_params)
            if body is None:
                return collected

            entries = body.get("entry") or []
            if not isinstance(entries, list):
                # Splunk's Atom rendering collapses a lone entry into a single
                # object; the JSON rendering should not, but the SDK defends
                # against it, so neither is this going to trust it blindly.
                entries = [entries]

            # Identity is the entry `id` — a fully namespaced URL, which is the
            # only field that is unique across the whole collection. `name` is
            # not: `/servicesNS/-/-/` spans every app, and two apps may each
            # hold a saved search of the same name.
            new_on_this_page = 0
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                key = entry.get("id") or (entry.get("name"), (entry.get("acl") or {}).get("app"))
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                collected.append(entry)
                new_on_this_page += 1

            offset += len(entries)

            if not entries:
                break

            # A page of entries that were all already collected means the walk
            # is not advancing. Continuing would loop; returning quietly would
            # present the first page, repeated, as a complete collection.
            if new_on_this_page == 0:
                self._pagination_stalled(path, len(collected))
                return collected

            total = as_int((body.get("paging") or {}).get("total"))
            if total is not None and offset >= total:
                break
        else:
            self._page_cap_reached(path, len(collected))

        if duplicates:
            # Not a failure on its own: an offset walk over a collection being
            # written to will re-see rows, and Splunk offers no snapshot. Worth
            # saying out loud, because the same shift that repeats one row can
            # skip another.
            logger.warning(
                "%s returned %d duplicate entries across pages; collected %d unique",
                path,
                duplicates,
                len(collected),
            )
        return collected


def flatten(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    One Splunk entry as a flat record: its name plus its `content` block.

    Splunk nests every actual setting under `content` and keeps identity at the
    top level, so neither half is usable alone.
    """
    content = entry.get("content")
    record: Dict[str, Any] = dict(content) if isinstance(content, dict) else {}
    record["name"] = entry.get("name")
    acl = entry.get("acl")
    if isinstance(acl, dict):
        record["acl_app"] = acl.get("app")
        record["acl_owner"] = acl.get("owner")
        record["acl_sharing"] = acl.get("sharing")
    return record


def build_client() -> SplunkClient:
    """Construct a client from the declared env vars and authenticate it."""
    verify, verify_reason = resolve_verify()
    if verify_reason:
        logger.warning(
            "TLS certificate verification is OFF (%s). Splunk's default "
            "certificate is self-signed; point SPLUNK_CA_BUNDLE at the signing "
            "CA to verify it properly.",
            verify_reason,
        )

    client = SplunkClient(
        base_url=resolve_base_url(),
        token=os.environ.get("SPLUNK_TOKEN", "").strip() or None,
        username=os.environ.get("SPLUNK_USERNAME", "").strip() or None,
        password=os.environ.get("SPLUNK_PASSWORD", "").strip() or None,
        timeout=int(os.environ.get("SPLUNK_HTTP_TIMEOUT", DEFAULT_TIMEOUT)),
        verify=verify,
    )
    client.authenticate()
    return client


def collection_provenance(client: "SplunkClient") -> Dict[str, Any]:
    """
    Where this evidence came from and how much the transport can be trusted.

    `tls_verified` is the one field here that is not a restatement of the
    manifest. Splunk's stock certificate is self-signed, so a deployment where
    verification is off is common and not by itself a finding — but an assessor
    reading a FedRAMP package should not have to guess whether the collection
    authenticated the server it was talking to.
    """
    return {
        "base_url": client.base_url,
        "auth_method": client.auth_method,
        "tls_verified": client.verify is not False,
        "server": client.server_info or None,
    }


def read_server_info(client: "SplunkClient") -> Dict[str, Any]:
    """
    Version and role of the instance, from `/services/server/info`.

    Worth a call of its own: `server_roles` is what says whether this evidence
    describes a single instance, a search head, or one indexer out of a cluster
    — and the same index list means very different things in each case.
    """
    body = client.request("/services/server/info")
    if body is None:
        return {}

    entries = body.get("entry") or []
    if not entries:
        return {}

    content = flatten(entries[0])
    info = {
        "version": content.get("version"),
        "build": content.get("build"),
        "server_name": content.get("serverName"),
        "guid": content.get("guid"),
        "server_roles": content.get("server_roles"),
        "product_type": content.get("product_type"),
        "license_state": content.get("licenseState"),
    }
    client.server_info = {k: v for k, v in info.items() if v is not None}
    return client.server_info


def evidence_error(message: str, api_failures: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Evidence body for a run that could not collect. Still written to disk — an
    empty file is indistinguishable from a fetcher that never ran.
    """
    return {
        "status": "error",
        "message": message,
        "api_failures": api_failures or [],
        "retrieved_at": current_timestamp(),
    }

# --- the fetcher entry point, shared -----------------------------------------
#
# Every fetcher in this category ended with the same ~34 lines: configure
# logging, load .env, make the output directory, call collect() inside a
# catch-all, write the JSON, decide an exit code. They differed by one string —
# the output filename. That is now here, so a change to the failure contract is
# made once rather than in every fetcher and in every fetcher added later.
#
# Precedent for putting it in _shared: okta/_shared/okta_iam_core.py does the
# same for its category.


def evidence(
    *,
    client: "SplunkClient",
    endpoint: str,
    records: List[Dict[str, Any]],
    analysis: Dict[str, Any],
    empty_message: str,
    data: Optional[List[Dict[str, Any]]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    """
    Build the evidence body every fetcher in this category returns.

    One shape, one place. `status` is `success` when anything was collected and
    `partial_or_empty` when nothing was — both are exit-code 0 states; a *fault*
    is signalled by `api_failures` being non-empty, not by the status. That
    separation matters: an empty deployment and a broken collection must not
    look the same, and neither should be confused with a crash.

    `**extra` carries fetcher-specific top-level keys (the firewall fetcher adds
    its containers, rule groups and rules) without every fetcher restating the
    common ones.

    `data` is the allowlisted view of `records` — what each fetcher's
    `describe()` keeps. It is a separate argument because `record_count` must
    still count what was collected, not what survived the allowlist. Passing
    the raw records straight through would ship Splunk's whole `content` block,
    including the account password hash and every UI preference.
    """
    body: Dict[str, Any] = {
        "status": "success" if records else "partial_or_empty",
        "api_endpoint": f"{client.base_url}{endpoint}",
        "record_count": len(records),
        "api_failures": client.api_failures,
        "data": records if data is None else data,
        "analysis": analysis,
        "collection": collection_provenance(client),
        "retrieved_at": current_timestamp(),
    }
    if not records:
        body["message"] = empty_message
    body.update(extra)
    return body


def report_failure(message: str, code: Optional[str] = None) -> None:
    """
    Tell the runner why this run failed. See docs/fetcher_contract.md.

    Without this the runner falls back to the **tail of stderr**, so the last
    thing logged becomes the reported reason — and since a fetcher logs
    "Evidence saved to ..." on its way out, a failed run would report a success
    message as its error (upstream issue #24). Stdlib only, no framework import.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    body: Dict[str, Any] = {"error": message}
    if code:
        body["code"] = code
    try:
        Path(path).write_text(json.dumps(body))
    except OSError as e:  # never let status reporting break the run
        logger.warning("Could not write FETCHER_STATUS_FILE: %s", e)


def run_fetcher(
    collect: Callable[[], Dict[str, Any]],
    output_name: str,
    logger: logging.Logger,
) -> int:
    """
    Run one fetcher and write its evidence. Returns the process exit code.

    The failure contract, in one place:

    - **The evidence file is always written**, including on a fault. A missing
      file is indistinguishable from a fetcher that never ran, which is the
      difference between "we have no evidence" and "we collected nothing".
    - **Any entry in `api_failures` exits non-zero**, even when records were
      collected. A partial collection presented as success is the failure this
      category guards against hardest.
    - An unexpected exception is caught and written as an error body rather than
      escaping as a traceback, so the runner still gets a readable artifact.

    Usage, at the bottom of a fetcher:

        if __name__ == "__main__":
            sys.exit(run_fetcher(collect, "splunk_indexes.json", logger))
    """
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: the fetcher loads .env itself. Once the framework's runner
    # and secret resolver pass resolved values in, this goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = collect()
    except Exception as e:  # noqa: BLE001 - evidence must be written even on an unexpected fault
        logger.error("Collection failed: %s", e)
        result = evidence_error(str(e))

    output_path = output_dir / output_name
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)

    # The reason must be logged AFTER the "Evidence saved" line above, because
    # the runner's fallback takes the tail of stderr.
    failures = result.get("api_failures") or []
    if failures:
        first = failures[0]
        detail = first.get("message") or first.get("error") or "see api_failures"
        message = (
            f"{len(failures)} API failure(s) during collection; first: "
            f"{first.get('endpoint', 'unknown endpoint')}: {detail}"
        )
        logger.error(message)
        report_failure(message, code=str(first.get("type") or first.get("status_code") or ""))
        return 1

    if result.get("status") not in {"success", "partial_or_empty"}:
        message = str(result.get("message") or "collection did not complete")
        logger.error(message)
        report_failure(message, code="collection_error")
        return 1

    return 0
