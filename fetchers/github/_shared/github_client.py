"""The shared client and entry point for every GitHub fetcher.

A fetcher is a `collect(client, org, repos, config)` function handed to `run`, which reads the target, lists the
repositories, writes the evidence and reports failure. A failed call returns None and is recorded on the client; any
recorded failure makes the run exit non-zero. What GitHub gets wrong, and how this handles it, is in the README.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("github")

DEFAULT_API_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
TIMEOUT_SECONDS = 60
PER_PAGE = 100
MAX_PAGES = 1000
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
MAX_WAIT_SECONDS = 60
GRAPHQL_PAGE = 50
GRAPHQL_MIN_PAGE = 5
GRAPHQL_REPO_BATCH = 10
GRAPHQL_TIMEOUT = {502, 504}
GRAPHQL_CODES = {"FORBIDDEN": "not_authorized", "NOT_FOUND": "not_authorized", "RATE_LIMITED": "rate_limited"}
HTTP_CODES = {401: "auth_failed", 403: "not_authorized", 404: "not_authorized", 429: "rate_limited"}

# Responses that describe the target rather than the token. Matched on GitHub's
# message, because the same status also means "you may not read this".
FEATURE_OFF = "disabled"
NOT_PROTECTED = "not_protected"
PLAN_UNAVAILABLE = "plan_unavailable"
NOT_SET_UP = "not_set_up"
NO_BRANCH = "no_branch"
KNOWN_STATES: List[Tuple[int, str, str]] = [
    (404, "branch not protected", NOT_PROTECTED),
    (404, "branch not found", NO_BRANCH),
    (403, "upgrade to github", PLAN_UNAVAILABLE),
    (404, "upgrade to github", PLAN_UNAVAILABLE),
    (403, "dependabot alerts are disabled", FEATURE_OFF),
    (404, "vulnerability alerts are disabled", FEATURE_OFF),
    (404, "secret scanning is disabled", FEATURE_OFF),
    (404, "no analysis found", NOT_SET_UP),
    (403, "advanced security must be enabled", FEATURE_OFF),
    (403, "code scanning is not enabled", FEATURE_OFF),
]

# A fetcher's CONFIG: {metadata key: (env var, default)}. Defaults are int, bool or str and are recorded in metadata.
Config = Dict[str, Tuple[str, Any]]


# --- values ------------------------------------------------------------------

def now_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


def iso(epoch: Optional[float]) -> Optional[str]:
    try:
        return None if epoch is None else datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def to_epoch(value: Any) -> Optional[float]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def days_between(start: Optional[float], end: Optional[float]) -> Optional[float]:
    return None if start is None or end is None else round((end - start) / 86400, 1)


SEVERITIES = ("critical", "high", "medium", "low")
AGE_BUCKETS = (7, 30, 90, 180)


def by_severity(alerts: List[dict], field: str) -> Dict[str, int]:
    return {s: len([a for a in alerts if a[field] == s]) for s in SEVERITIES}


def open_older_than(alerts: List[dict], field: str) -> Dict[str, Dict[str, int]]:
    """Open alerts per severity older than each of AGE_BUCKETS days."""
    return {str(d): by_severity([a for a in alerts if (a["age_days"] or 0) > d], field) for d in AGE_BUCKETS}


def median_days(alerts: List[dict], field: str) -> Optional[float]:
    values = sorted(a[field] for a in alerts)
    return values[len(values) // 2] if values else None


def as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    folded = value.strip().lower() if isinstance(value, str) else None
    if folded in ("1", "true", "yes", "on"):
        return True
    if folded in ("0", "false", "no", "off"):
        return False
    return None


def split_list(value: Optional[str]) -> List[str]:
    return [v for v in re.split(r"[,\s]+", value or "") if v]


def glob_regex(pattern: str) -> "re.Pattern[str]":
    """GitHub's ruleset glob, which is Ruby's File.fnmatch with FNM_PATHNAME (fuzzed against Ruby, measured on GitHub).

    `*`, `?` and `[...]` never match "/"; `**/` matches any number of directories only when `**` is a whole
    segment; anywhere else `**` is `*`. `\\x` is a literal x.
    """
    out, i, n = [], 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            j = i
            while j < n and pattern[j] == "*":
                j += 1
            if j - i == 2 and (i == 0 or pattern[i - 1] == "/") and j < n and pattern[j] == "/":
                out.append("(?:[^/]+/)*")
                i = j + 1
            else:
                out.append("[^/]*")
                i = j
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j, negate = i + 1, False
            if j < n and pattern[j] in "!^":
                negate, j = True, j + 1
            k = j  # unlike POSIX, a "]" right after "[" or "[!" closes the class (Ruby, measured)
            while k < n and pattern[k] != "]":
                k += 2 if pattern[k] == "\\" else 1
            if k >= n:
                return re.compile("(?!)")  # an unclosed "[" matches nothing at all (Ruby, measured)
            out.append(_bracket(pattern[j:k], negate))
            i = k + 1
        elif c == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
        elif c == "\\":
            i += 1  # a trailing lone backslash is dropped, not matched (Ruby, measured)
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"\Z")


def _bracket(body: str, negate: bool) -> str:
    """A [...] class item by item, every character escaped; an empty class matches nothing, or anything if negated."""
    items, i = [], 0
    while i < len(body):
        c = body[i + 1] if body[i] == "\\" and i + 1 < len(body) else body[i]
        i += 2 if body[i] == "\\" and i + 1 < len(body) else 1
        if i + 1 < len(body) and body[i] == "-":
            end = body[i + 2] if body[i + 1] == "\\" and i + 2 < len(body) else body[i + 1]
            i += 3 if body[i + 1] == "\\" and i + 2 < len(body) else 2
            # A reversed range matches only its two endpoints (Ruby, measured).
            items.append(f"{re.escape(c)}-{re.escape(end)}" if c <= end else f"{re.escape(c)}{re.escape(end)}")
            continue
        items.append(re.escape(c))
    if not items:
        return "[^/]" if negate else "(?!)"
    return f"(?!/)[{'^' if negate else ''}{''.join(items)}]"


def ref_matches(pattern: str, ref: str, default_branch: str) -> Optional[bool]:
    """One ruleset condition against a fully qualified ref (refs/heads/main) or a repository name."""
    if pattern == "~ALL":
        return True
    if pattern == "~DEFAULT_BRANCH":
        return ref == f"refs/heads/{default_branch}"
    try:
        return bool(glob_regex(pattern).match(ref))
    except re.error:
        return None  # a pattern this matcher cannot read is unknown, never a crash or a guess


def ruleset_targets_ref(ruleset: dict, repo_name: str, ref: str, default_branch: str,
                        target: str = "branch") -> Optional[bool]:
    """Whether a ruleset applies to a fully qualified ref (refs/heads/x, refs/tags/v1) in one repository.

    True/False when its conditions can be evaluated here; None when they depend on repository properties or ids,
    are missing, or hold a pattern the matcher cannot read: unknown is never "elsewhere".
    """
    if (ruleset.get("target") or "branch") != target:
        return False
    conditions = ruleset.get("conditions")
    if not conditions or "repository_property" in conditions or "repository_id" in conditions:
        return None
    names = conditions.get("repository_name")
    if names:
        include = _any(ref_matches(p, repo_name, "") for p in names.get("include") or [])
        exclude = _any(ref_matches(p, repo_name, "") for p in names.get("exclude") or [])
        if include is None or exclude is None:
            return None
        if not include or exclude:
            return False
    refs = conditions.get("ref_name") or {}
    if not refs.get("include"):
        return None
    include = _any(ref_matches(p, ref, default_branch) for p in refs.get("include") or [])
    exclude = _any(ref_matches(p, ref, default_branch) for p in refs.get("exclude") or [])
    if include is None or exclude is None:
        return None
    return include and not exclude


def _any(results: Any) -> Optional[bool]:
    """True if any match; None if none matched but one pattern could not be read; else False."""
    seen = list(results)
    return True if True in seen else None if None in seen else False


# --- the client --------------------------------------------------------------

class GitHubClient:
    """Read-only access to one GitHub API host (github.com, GHE.com or GHES)."""

    def __init__(self, api_url: str, token: str):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "paramify-fetchers",
        })
        self.failures: List[Dict[str, str]] = []
        self.codes: List[str] = []
        self.rate: Dict[str, Any] = {}
        self.graphql_rate: Dict[str, Any] = {}
        self.last_message = ""  # GitHub's message for the last non-2xx; bodies of non-2xx are never returned
        # Fine-grained and classic personal tokens; an App installation token is ghs_. Some endpoints serve Apps only.
        self.personal_token = token.startswith(("github_pat_", "ghp_"))

    def fail(self, operation: str, type_: str, message: str, code: str) -> None:
        self.failures.append({"operation": operation, "type": type_, "message": message})
        self.codes.append(code)

    def failure_code(self) -> str:
        return self.codes[0] if len(set(self.codes)) == 1 else "partial_failure"

    def _url(self, path: str) -> str:
        if not path.startswith("http"):
            return f"{self.api_url}/{path.lstrip('/')}"
        # The session carries the token: never send it anywhere but the configured API host.
        if not path.startswith(self.api_url + "/"):
            raise ValueError(f"refusing a URL off the API host {self.api_url}: {path}")
        return path

    def _send(self, url: str, params: Optional[dict] = None,
              body: Optional[dict] = None) -> Tuple[Optional[requests.Response], Optional[str]]:
        """One GET, or a POST of `body`. Retries 429, 5xx and rate-limit 403s within MAX_WAIT_SECONDS.

        Returns (response, transport error). A GraphQL timeout is returned at once: retrying the same page fails again.
        """
        for attempt in range(MAX_RETRIES + 1):
            try:
                if body is None:
                    resp = self.session.get(url, params=params, timeout=TIMEOUT_SECONDS)
                else:
                    resp = self.session.post(url, json=body, timeout=TIMEOUT_SECONDS)
            except requests.exceptions.RequestException as exc:
                if isinstance(exc, requests.exceptions.ConnectionError) and attempt < MAX_RETRIES:
                    time.sleep(min(2 ** attempt, MAX_WAIT_SECONDS))
                    continue
                return None, f"{type(exc).__name__}: {exc}"
            self._note_rate(resp)
            if body is not None and resp.status_code in GRAPHQL_TIMEOUT:
                return resp, None
            wait = _retry_wait(resp, attempt)
            if wait is not None and attempt < MAX_RETRIES:
                time.sleep(wait)
                continue
            return resp, None
        return None, "retries exhausted"

    def _note_rate(self, resp: requests.Response) -> None:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            rate = {"limit": _int(resp.headers.get("X-RateLimit-Limit")), "remaining": _int(remaining),
                         "reset": iso(_int(resp.headers.get("X-RateLimit-Reset")))}
            if resp.headers.get("X-RateLimit-Resource") == "graphql":
                self.graphql_rate = rate
            else:
                self.rate = rate

    def read(self, path: str, params: Optional[dict] = None) -> Tuple[Optional[str], Any]:
        """(state, body). body only when state is None; else a KNOWN_STATES label, or "failed" (already recorded)."""
        operation = f"GET {path}"
        resp, error = self._send(self._url(path), params)
        if resp is None:
            self.fail(operation, "RequestError", error or "", "target_unreachable")
            return "failed", None
        if resp.status_code < 300:
            if resp.status_code == 204 or not resp.content:
                return None, None
            try:
                return None, resp.json()
            except ValueError:
                self.fail(operation, "InvalidJSON", resp.text[:300], "internal_error")
                return "failed", None
        state, self.last_message = self._classify(path, resp)
        return state, None

    def lookup(self, path: str, params: Optional[dict] = None) -> Tuple[bool, Any]:
        """(found, body) for a single object. A 404 is not found, not a failure; anything else fails as usual."""
        resp, error = self._send(self._url(path), params)
        if resp is not None and resp.status_code == 404:
            return False, None
        if resp is None:
            self.fail(f"GET {path}", "RequestError", error or "", "target_unreachable")
            return False, None
        if resp.status_code >= 300:
            self._classify(path, resp)
            return False, None
        return True, resp.json()

    def get(self, path: str, params: Optional[dict] = None) -> Any:
        """A single object. Any non-2xx is a failure, known state or not."""
        state, body = self.read(path, params)
        if state is None:
            return body
        if state != "failed":
            self.fail(f"GET {path}", "UnexpectedState", f"{state}: {self.last_message}", "not_authorized")
        return None

    def paginate(self, path: str, params: Optional[dict] = None, key: Optional[str] = None,
                 until: Optional[Callable[[Any], bool]] = None) -> Tuple[Optional[str], Optional[List[Any]]]:
        """(state, items) over every page. state as in read(); items is None unless state is None.

        `until` ends the walk at the first item it accepts, which is left out: for a list sorted newest first.
        """
        url: str = self._url(path)
        query: Optional[dict] = {**(params or {}), "per_page": PER_PAGE}
        items: List[Any] = []
        seen = set()
        for _ in range(MAX_PAGES):
            if url in seen:
                self.fail(f"GET {path}", "PaginationNotAdvancing", f"page repeated: {url}", "partial_failure")
                return "failed", None
            seen.add(url)
            resp, error = self._send(url, query)
            if resp is None:
                self.fail(f"GET {path}", "RequestError", error or "", "target_unreachable")
                return "failed", None
            if resp.status_code >= 300:
                state, self.last_message = self._classify(path, resp)
                return state, None
            try:
                body = resp.json()
            except ValueError:
                self.fail(f"GET {path}", "InvalidJSON", resp.text[:300], "internal_error")
                return "failed", None
            page = body.get(key) if key else body
            if not isinstance(page, list):
                self.fail(f"GET {path}", "UnexpectedShape",
                          f"expected a list{f' under {key!r}' if key else ''}", "internal_error")
                return "failed", None
            if until is not None:
                for n, item in enumerate(page):
                    if until(item):
                        return None, items + page[:n]
            items += page
            next_url = resp.links.get("next", {}).get("url")
            if not next_url:
                return None, items
            if not next_url.startswith(self.api_url + "/"):
                self.fail(f"GET {path}", "PaginationOffHost", f"next page is off the API host: {next_url}", "internal_error")
                return "failed", None
            url, query = next_url, None
        self.fail(f"GET {path}", "PageCapReached", f"more than {MAX_PAGES} pages", "partial_failure")
        return "failed", None

    def paginate_required(self, path: str, params: Optional[dict] = None, key: Optional[str] = None,
                          until: Optional[Callable[[Any], bool]] = None) -> Optional[List[Any]]:
        """paginate() where a known state is also a failure."""
        state, items = self.paginate(path, params, key, until)
        if state is None:
            return items
        if state != "failed":
            self.fail(f"GET {path}", "UnexpectedState", f"{state}: {self.last_message}", "not_authorized")
        return None

    def _classify(self, path: str, resp: requests.Response) -> Tuple[str, str]:
        message = _message(resp)
        folded = message.lower()
        for status, fragment, state in KNOWN_STATES:
            if resp.status_code == status and fragment in folded:
                return state, message
        self.fail(f"GET {path}", f"HTTP {resp.status_code}", _explain(resp, message), _failure_code(resp))
        return "failed", message

    def graphql_url(self) -> str:
        """github.com and GHE.com serve GraphQL at <api>/graphql; GHES at /api/graphql beside /api/v3."""
        return self.api_url[:-2] + "graphql" if self.api_url.endswith("/api/v3") else f"{self.api_url}/graphql"

    def graphql(self, operation: str, query: str, variables: dict) -> Tuple[str, Any]:
        """One query. ("ok", data), ("timeout", None) for a page too heavy to answer, or ("failed", None), recorded."""
        if re.search(r"\b(mutation|subscription)\b", query):
            raise ValueError("graphql() runs queries only")
        resp, error = self._send(self.graphql_url(), body={"query": query, "variables": variables})
        if resp is None:
            self.fail(operation, "RequestError", error or "", "target_unreachable")
            return "failed", None
        if resp.status_code in GRAPHQL_TIMEOUT:
            return "timeout", None
        if resp.status_code >= 300:
            self.fail(operation, f"HTTP {resp.status_code}", _explain(resp, _message(resp)), _failure_code(resp))
            return "failed", None
        if not resp.content.strip():
            # Measured on microsoft/vscode: a heavy page can come back as an empty 200 instead of a 502.
            return "timeout", None
        try:
            body = resp.json()
        except ValueError:
            self.fail(operation, "InvalidJSON", f"HTTP {resp.status_code}, not JSON: {resp.text[:300]}", "internal_error")
            return "failed", None
        errors = body.get("errors") if isinstance(body, dict) else None
        if errors:
            first = errors[0] if isinstance(errors[0], dict) else {}
            message = str(first.get("message") or "")
            if "timeout" in message.lower():
                return "timeout", None
            self.fail(operation, f"GraphQL {first.get('type') or 'error'}", _explain(resp, message),
                      GRAPHQL_CODES.get(str(first.get("type")), "internal_error"))
            return "failed", None
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            self.fail(operation, "UnexpectedShape", "no data in the GraphQL response", "internal_error")
            return "failed", None
        return "ok", data

    def graphql_nodes(self, operation: str, query: str, variables: dict, connection: Callable[[dict], Any],
                      until: Optional[Callable[[Any], bool]] = None, page: int = GRAPHQL_PAGE) -> Optional[List[Any]]:
        """Every node of the connection `connection(data)` picks out, paging with $first and $after.

        A timeout halves $first down to GRAPHQL_MIN_PAGE. `until` ends the walk as in paginate().
        """
        nodes: List[Any] = []
        after: Optional[str] = None
        seen = set()
        for _ in range(MAX_PAGES):
            state, data = self.graphql(operation, query, {**variables, "first": page, "after": after})
            if state == "timeout":
                if page <= GRAPHQL_MIN_PAGE:
                    self.fail(operation, "GraphQLTimeout", f"timed out at {page} items a page", "target_unreachable")
                    return None
                page = max(GRAPHQL_MIN_PAGE, page // 2)
                continue
            if state != "ok":
                return None
            conn = connection(data)
            if not isinstance(conn, dict) or not isinstance(conn.get("nodes"), list):
                self.fail(operation, "UnexpectedShape", "the GraphQL connection is missing", "internal_error")
                return None
            if until is not None:
                for n, node in enumerate(conn["nodes"]):
                    if until(node):
                        return nodes + conn["nodes"][:n]
            nodes += conn["nodes"]
            info = conn.get("pageInfo") or {}
            if not info.get("hasNextPage"):
                return nodes
            after = info.get("endCursor")
            if not after or after in seen:
                self.fail(operation, "PaginationNotAdvancing", f"cursor repeated: {after}", "partial_failure")
                return None
            seen.add(after)
        self.fail(operation, "PageCapReached", f"more than {MAX_PAGES} pages", "partial_failure")
        return None

    def graphql_repos(self, operation: str, owner: str, names: List[str], fields: str,
                      batch: int = GRAPHQL_REPO_BATCH) -> Optional[Dict[str, Any]]:
        """{name: the repository's `fields`} for many repositories, `batch` to a query as aliases.

        A timeout halves the batch down to one repository; one repository that still times out fails.
        """
        out: Dict[str, Any] = {}
        i = 0
        while i < len(names):
            chunk = names[i:i + batch]
            params = ", ".join(f"$n{k}: String!" for k in range(len(chunk)))
            body = " ".join(f"r{k}: repository(owner: $owner, name: $n{k}) {{ {fields} }}" for k in range(len(chunk)))
            state, data = self.graphql(operation, f"query($owner: String!, {params}) {{ {body} }}",
                                       {"owner": owner, **{f"n{k}": n for k, n in enumerate(chunk)}})
            if state == "timeout":
                if batch == 1:
                    self.fail(operation, "GraphQLTimeout", f"timed out on {chunk[0]} alone", "target_unreachable")
                    return None
                batch = max(1, batch // 2)
                continue
            if state != "ok":
                return None
            for k, name in enumerate(chunk):
                if not isinstance(data.get(f"r{k}"), dict):
                    self.fail(operation, "UnexpectedShape", f"no repository {name} in the GraphQL response",
                              "internal_error")
                    return None
                out[name] = data[f"r{k}"]
            i += len(chunk)
        return out

    def expect(self, what: str, collected: int, expected: Optional[int]) -> None:
        """Record a failure when a collection is smaller than an independent count of it."""
        if expected is not None and collected < expected:
            self.fail(f"count {what}", "IncompleteCollection",
                      f"collected {collected} {what}, the organization reports {expected}", "partial_failure")


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rate_limited(resp: requests.Response) -> bool:
    return resp.status_code == 429 or (
        resp.status_code == 403 and bool(resp.headers.get("Retry-After") or resp.headers.get("X-RateLimit-Remaining") == "0"
                                         or "rate limit" in _message(resp).lower()))


def _failure_code(resp: requests.Response) -> str:
    """A 403 is a missing permission unless GitHub says it is a rate limit."""
    return "rate_limited" if _rate_limited(resp) else HTTP_CODES.get(resp.status_code, "internal_error")


def _retry_wait(resp: requests.Response, attempt: int) -> Optional[float]:
    """Seconds before a retry, or None when final. Waits beyond MAX_WAIT_SECONDS fail as rate_limited instead."""
    if _rate_limited(resp):
        retry_after = _int(resp.headers.get("Retry-After"))
        if retry_after is None and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = _int(resp.headers.get("X-RateLimit-Reset"))
            retry_after = max(0, reset - int(time.time())) if reset else None
        wait = retry_after if retry_after is not None else 2 ** attempt * 5
        return wait if wait <= MAX_WAIT_SECONDS else None
    if resp.status_code in RETRY_STATUS and resp.status_code != 429:
        return min(2 ** attempt, MAX_WAIT_SECONDS)
    return None


def _message(resp: requests.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300] or resp.reason or ""
    return str(body.get("message") or resp.reason or "") if isinstance(body, dict) else resp.reason or ""


def _explain(resp: requests.Response, message: str) -> str:
    """GitHub names the fine-grained permission an endpoint needs in X-Accepted-GitHub-Permissions."""
    needed = resp.headers.get("X-Accepted-GitHub-Permissions")
    return f"{message} (needs: {needed})" if needed else message


# --- repositories ------------------------------------------------------------

def list_repos(client: GitHubClient, org: dict, allowlist: List[str], include_archived: bool) -> Optional[List[dict]]:
    """The organization's repositories, filtered by allowlist and archive state, checked against the org's counts."""
    login = org["login"]
    repos: Optional[List[dict]]
    if allowlist:
        # Fetched one by one: listing a large organization to keep three repositories costs dozens of pages.
        repos, missing = [], []
        for name in dict.fromkeys(allowlist):
            failures = len(client.failures)
            found, body = client.lookup(f"repos/{login}/{name}")
            if found:
                repos.append(body)
            elif len(client.failures) == failures:
                missing.append(name)
        if missing:
            client.fail(f"GET repos/{login}/...", "RepositoryNotFound",
                        f"listed in repositories but not visible to the token: {', '.join(missing)}", "bad_config")
    else:
        repos = client.paginate_required(f"orgs/{login}/repos", {"type": "all", "sort": "full_name"})
        if repos is None:
            return None
        # public_repos is visible to anyone; total_private_repos only to members who can see them.
        expected = (org.get("public_repos") or 0) + (org.get("total_private_repos") or 0)
        client.expect("repositories", len(repos), expected if org.get("public_repos") is not None else None)
    if not include_archived:
        repos = [r for r in repos if not r.get("archived")]
    return sorted(repos, key=lambda r: r["name"].lower())


# --- the entry point ---------------------------------------------------------

def run(name: str, collect: Callable[[GitHubClient, dict, List[dict], Dict[str, Any]], Optional[dict]],
        config: Optional[Config] = None, inventory: bool = False) -> int:
    """Run one fetcher against the organization in the environment and write its evidence. Returns the exit code.

    An inventory's `collect` returns its records under "data". Any failure withholds every record (`data: []`,
    `records_included: false`, the count kept): a pipeline reads the file as the whole estate.
    """
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = _target_from_env()
        settings = {key: _env_value(env, default) for key, (env, default) in (config or {}).items()}
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = GitHubClient(target["api_url"], target["token"])
    result: Dict[str, Any] = {}
    org: Dict[str, Any] = {}
    try:
        org = client.get(f"orgs/{target['org']}") or {}
        repos = list_repos(client, org, target["repositories"], target["include_archived"]) if org else None
        if repos is not None:
            result = collect(client, org, repos, settings) or {}
    except Exception as exc:  # noqa: BLE001 - an unexpected response must still leave evidence and a reason
        logger.exception("collection failed")
        client.fail("collect", type(exc).__name__, str(exc), "internal_error")
        result = {}

    evidence = {
        "metadata": {
            "collected_at": iso(now_epoch()),
            "organization": target["org"],
            "api_url": target["api_url"],
            "plan": (org.get("plan") or {}).get("name"),
            "repositories_filter": target["repositories"] or None,
            "include_archived": target["include_archived"],
            **settings,
            **result.pop("metadata", {}),
            "rate_limit": client.rate or None,
            **({"graphql_rate_limit": client.graphql_rate} if client.graphql_rate else {}),
            "partial_failure": bool(client.failures),
            "api_failures": client.failures,
        },
        "summary": result.pop("summary", {}),
        **result,
    }
    if inventory:
        records = evidence.get("data") or []
        evidence.update({"record_count": len(records), "records_included": not client.failures,
                         "data": [] if client.failures else records})
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    host = urlparse(target["api_url"]).hostname or "github"
    suffix = re.sub(r"[^a-zA-Z0-9_-]", "_", target["org"] if host == "api.github.com" else f"{host}_{target['org']}")
    path = output_dir / f"{name}_{suffix}.json"
    path.write_text(json.dumps(evidence, indent=2))
    logger.info("Evidence saved to %s", path)

    if client.failures:
        reason = "; ".join(f"{f['operation']}: {f['message']}" for f in client.failures[:10])
        more = f" (+{len(client.failures) - 10} more)" if len(client.failures) > 10 else ""
        report_failure(f"{len(client.failures)} collection failure(s): {reason}{more}", client.failure_code())
        return 1
    return 0


def _target_from_env() -> Dict[str, Any]:
    missing = [v for v in ("GITHUB_ORG", "GITHUB_TOKEN") if not os.environ.get(v, "").strip()]
    if missing:
        raise ValueError(f"missing required env var(s): {', '.join(missing)}")
    api_url = os.environ.get("GITHUB_API_URL", "").strip() or DEFAULT_API_URL
    if not api_url.startswith("https://"):
        raise ValueError(f"GITHUB_API_URL must be an https:// URL, got {api_url!r}")
    include_archived = as_bool(os.environ.get("GITHUB_INCLUDE_ARCHIVED") or "false")
    if include_archived is None:
        raise ValueError("GITHUB_INCLUDE_ARCHIVED must be true or false")
    return {
        "org": os.environ["GITHUB_ORG"].strip(),
        "api_url": api_url.rstrip("/"),
        "token": os.environ["GITHUB_TOKEN"].strip(),
        "repositories": split_list(os.environ.get("GITHUB_REPOSITORIES")),
        "include_archived": include_archived,
    }


def _env_value(name: str, default: Any) -> Any:
    raw = os.environ.get(name, "").strip()
    if not raw or isinstance(default, str):
        return raw or default
    if isinstance(default, bool):
        value = as_bool(raw)
        if value is None:
            raise ValueError(f"{name} must be true or false, got {raw!r}")
        return value
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
