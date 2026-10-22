"""Shared Jira Cloud REST client and run plumbing for the jira fetchers."""

import json
import logging
import math
import os
import re
import statistics
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("jira_common")

PAGE_SIZE = 100
TIMEOUT = 60
# Jira Cloud rate-limits (429) and has transient 5xx answers; a run of a thousand
# calls will see some. Retry with the Retry-After header when present, else an
# increasing wait, and give up after MAX_RETRIES extra attempts.
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
# A request that raises (timeout, connection reset) is retried fewer times: each
# attempt can already take the full TIMEOUT, and a run has a fixed time budget.
MAX_EXCEPTION_RETRIES = 2
BACKOFF_BASE_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 60.0
NONE_LABEL = "(none)"
NOT_FOUND = object()
# POST /rest/api/3/changelog/bulkfetch accepts at most 1000 issues and 10 field ids.
CHANGELOG_ISSUE_BATCH = 1000
CHANGELOG_FIELD_BATCH = 10


class Abort(Exception):
    """A failure no further call can get past (bad credential, host unreachable)."""


class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str) -> None:
        self.base_url = base_url
        self.session = requests.Session()
        self.session.auth = (email, api_token)
        self.session.headers.update({"Accept": "application/json"})
        self.api_failures: list[dict] = []
        self.failure_codes: list[str] = []
        self.authenticated = False

    def fail(self, operation: str, type_: str, message: str, code: str) -> None:
        self.api_failures.append(
            {"operation": operation, "type": type_, "message": message[:500]}
        )
        self.failure_codes.append(code)

    @staticmethod
    def _retry_delay(resp, attempt: int) -> float:
        retry_after = (getattr(resp, "headers", None) or {}).get("Retry-After") if resp is not None else None
        if retry_after:
            try:
                delay = float(retry_after)
            except (TypeError, ValueError):
                delay = None
            if delay is not None and math.isfinite(delay):
                return max(0.0, min(delay, MAX_BACKOFF_SECONDS))
        return min(BACKOFF_BASE_SECONDS ** (attempt + 1), MAX_BACKOFF_SECONDS)

    def _send(self, method, path, operation, params, body):
        """One request with retries. Returns the response, or None after recording the failure."""
        last_error = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                # Redirects are not followed: a redirected request could carry the
                # credential or a POST body to a path or host it was never meant for.
                resp = self.session.request(
                    method,
                    f"{self.base_url}{path}",
                    params=params,
                    json=body,
                    timeout=TIMEOUT,
                    allow_redirects=False,
                )
            except requests.RequestException as e:
                # Only the exception type: some requests errors quote the request.
                last_error = type(e).__name__
                if attempt < MAX_EXCEPTION_RETRIES:
                    delay = self._retry_delay(None, attempt)
                    logger.warning("%s: %s; retrying in %.0fs", operation, last_error, delay)
                    time.sleep(delay)
                    continue
                break
            if resp.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                delay = self._retry_delay(resp, attempt)
                logger.warning("%s returned HTTP %s; retrying in %.0fs", operation, resp.status_code, delay)
                time.sleep(delay)
                continue
            return resp

        # Every attempt raised. Before any call has succeeded the host is simply not
        # reachable and nothing later can work; after one, this is one failed call
        # and the run goes on with the failure recorded.
        if not self.authenticated:
            self.fail(operation, last_error or "RequestException", "no response after retries", "target_unreachable")
            raise Abort
        self.fail(operation, last_error or "RequestException", "no response after retries", "partial_failure")
        return None

    def request(self, method, path, operation, *, params=None, body=None, allow_404=False, quiet_400=False):
        """Return the decoded JSON body, NOT_FOUND (when allowed), or None on failure."""
        resp = self._send(method, path, operation, params, body)
        if resp is None:
            return None

        if resp.status_code == 200:
            self.authenticated = True
            try:
                return resp.json()
            except ValueError:
                self.fail(
                    operation, "InvalidJSON", f"response was not JSON ({len(resp.content)} bytes)",
                    "partial_failure",
                )
                return None
        if resp.status_code == 404 and allow_404:
            return NOT_FOUND
        if resp.status_code == 400 and quiet_400:
            return NOT_FOUND

        if 300 <= resp.status_code < 400:
            self.fail(
                operation,
                f"HTTP{resp.status_code}",
                "redirect not followed; JIRA_BASE_URL must be the site or API gateway URL itself",
                "bad_config",
            )
            return None

        message = error_message(resp)
        if resp.status_code == 401:
            # Jira also answers 401 for a missing project permission (measured on
            # /project/{key}/role), so only a 401 before any success is a bad credential.
            if self.authenticated:
                self.fail(operation, "HTTP401", message, "not_authorized")
                return None
            self.fail(operation, "HTTP401", message, "auth_failed")
            raise Abort
        code = {403: "not_authorized", 429: "rate_limited", 400: "bad_config"}.get(
            resp.status_code, "partial_failure"
        )
        self.fail(operation, f"HTTP{resp.status_code}", message, code)
        return None

    def paged_values(self, path, operation, params=None, page_size=50, **request_kw):
        """Page a `startAt`/`isLast` list endpoint. Returns (values, complete).

        With allow_404 or quiet_400, a refused first page counts as an empty, complete list.
        """
        values: list = []
        start_at = 0
        while True:
            page = self.request(
                "GET",
                path,
                operation,
                params={**(params or {}), "startAt": start_at, "maxResults": page_size},
                **request_kw,
            )
            if page is NOT_FOUND:
                # Only a refused first page means "nothing here"; a later one is a failure.
                return values, start_at == 0
            if page is None:
                return values, False
            batch = page.get("values") or []
            values.extend(batch)
            start_at += len(batch)
            if page.get("isLast", True) or not batch:
                return values, True

    def service_desks(self):
        """Page the JSM service-desk list (`start`/`limit`/`isLastPage` paging).

        Returns the list, NOT_FOUND when the site has no Jira Service Management,
        or None after a recorded failure.
        """
        desks: list = []
        start = 0
        while True:
            page = self.request(
                "GET",
                "/rest/servicedeskapi/servicedesk",
                "GET /rest/servicedeskapi/servicedesk",
                params={"start": start, "limit": 50},
                allow_404=True,
            )
            if page is NOT_FOUND:
                return NOT_FOUND
            if page is None:
                return None
            batch = page.get("values") or []
            desks.extend(batch)
            start += len(batch)
            if page.get("isLastPage", True) or not batch:
                return desks

    def search_issues(self, jql: str, fields: list, max_issues: int):
        """Page POST /rest/api/3/search/jql. Returns (issues, truncated, complete)."""
        issues: list = []
        token = None
        tokens_seen: set = set()
        while True:
            body = {
                "jql": jql,
                "fields": fields,
                "maxResults": min(PAGE_SIZE, max_issues - len(issues)),
            }
            if token:
                body["nextPageToken"] = token
            page = self.request(
                "POST", "/rest/api/3/search/jql", "POST /rest/api/3/search/jql", body=body
            )
            if page is None:
                return issues, False, False
            batch = page.get("issues") or []
            issues.extend(batch)
            token = page.get("nextPageToken")
            more = bool(token) and not page.get("isLast", False)
            if more and (token in tokens_seen or not batch):
                # A repeated token, or an empty page that still points onward, would
                # loop forever; stop and say the result is not complete.
                self.fail(
                    "POST /rest/api/3/search/jql", "BadPaging",
                    "the server repeated a nextPageToken or sent an empty page with one", "partial_failure",
                )
                return issues[:max_issues], len(issues) > max_issues, False
            tokens_seen.add(token)
            if len(issues) > max_issues:
                # The server returned more than maxResults asked for.
                return issues[:max_issues], True, True
            if not more:
                return issues, False, True
            if len(issues) >= max_issues:
                return issues, True, True

    def bulk_changelogs(self, issue_ids: list, field_ids: list):
        """Full change history per issue id via POST /rest/api/3/changelog/bulkfetch.

        Returns ({issue_id: [history, ...]}, complete). Histories are de-duplicated
        by id because the endpoint has repeated entries across pages before.
        """
        out: dict = {}
        seen: set = set()
        complete = True
        # The endpoint takes at most 10 field ids, so more are fetched in groups and
        # the items of a history that several groups return are merged.
        field_groups = [field_ids[i : i + CHANGELOG_FIELD_BATCH] for i in range(0, len(field_ids), CHANGELOG_FIELD_BATCH)]
        histories: dict = {}
        for i in range(0, len(issue_ids), CHANGELOG_ISSUE_BATCH):
            chunk = issue_ids[i : i + CHANGELOG_ISSUE_BATCH]
            for group in field_groups or [[]]:
                token = None
                tokens_seen: set = set()
                while True:
                    body = {"issueIdsOrKeys": chunk, "fieldIds": group, "maxResults": 1000}
                    if token:
                        body["nextPageToken"] = token
                    page = self.request(
                        "POST",
                        "/rest/api/3/changelog/bulkfetch",
                        "POST /rest/api/3/changelog/bulkfetch",
                        body=body,
                    )
                    if page is None:
                        complete = False
                        break
                    for log in page.get("issueChangeLogs") or []:
                        issue_id = str(log.get("issueId"))
                        for h in log.get("changeHistories") or []:
                            hid = (issue_id, h.get("id"))
                            if hid not in seen:
                                seen.add(hid)
                                # bulkfetch returns `created` as epoch milliseconds, not ISO text.
                                histories[hid] = {**h, "created": iso_ts(h.get("created")), "items": []}
                                out.setdefault(issue_id, []).append(histories[hid])
                            known = histories[hid]["items"]
                            for item in h.get("items") or []:
                                if item not in known:
                                    known.append(item)
                    token = page.get("nextPageToken")
                    if not token:
                        break
                    if token in tokens_seen:
                        # The endpoint has repeated pages before; a repeated token would loop forever.
                        self.fail(
                            "POST /rest/api/3/changelog/bulkfetch", "RepeatedPageToken",
                            "the server repeated a nextPageToken; history may be incomplete", "partial_failure",
                        )
                        complete = False
                        break
                    tokens_seen.add(token)
        return out, complete


def error_message(resp: requests.Response) -> str:
    if "html" in resp.headers.get("Content-Type", "").lower():
        return f"{resp.reason or 'error'} (HTML error page, not a Jira API response)"
    try:
        data = resp.json()
    except ValueError:
        return resp.text[:300] or resp.reason or ""
    if not isinstance(data, dict):
        return resp.text[:300]
    parts = list(data.get("errorMessages") or [])
    parts += [f"{k}: {v}" for k, v in (data.get("errors") or {}).items()]
    if data.get("errorMessage"):
        parts.append(data["errorMessage"])
    return "; ".join(parts) or resp.text[:300]


def name_of(obj, key="name"):
    return obj.get(key) if isinstance(obj, dict) else None


def iso_ts(value):
    """ISO 8601 UTC text for an epoch-millisecond number; other values pass through."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat(timespec="milliseconds")
    return value


def parse_ts(value):
    """Timezone-aware datetime from a Jira timestamp or YYYY-MM-DD date (as UTC midnight)."""
    if not isinstance(value, str) or not value:
        return None
    if len(value) == 10:
        try:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


class Counts(dict):
    """A {value: count} rollup with data-driven keys (see null_summary)."""


def counts(values) -> dict:
    return Counts(Counter(NONE_LABEL if v is None else v for v in values).most_common())


def number_stats(values: list) -> dict:
    if not values:
        return {"count": 0, "median": None, "mean": None, "max": None}
    return {
        "count": len(values),
        "median": round(statistics.median(values), 2),
        "mean": round(statistics.fmean(values), 2),
        "max": round(max(values), 2),
    }


ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,254}-[0-9]{1,12}$")


_FIELD_ID = re.compile(r"customfield_[0-9]{1,10}")


def _id_list(value):
    """The customfield_ ids in a config value (a string, comma-separated string or list), or None."""
    parts = value if isinstance(value, list) else str(value).split(",")
    cleaned = [str(p).strip() for p in parts if str(p).strip()]
    if cleaned and all(_FIELD_ID.fullmatch(p) for p in cleaned):
        return list(dict.fromkeys(cleaned))
    return None


def role_state(value):
    """Classify one JIRA_*_FIELDS value: "disabled" (empty), "ids" (customfield_ ids),
    "name" (a field name to look up) or "invalid" (anything else, e.g. a number or a
    list that is not all ids). Shared by _config and resolve_fields so both agree."""
    if value is None or (isinstance(value, str) and not value.strip()) or value == []:
        return "disabled"
    if isinstance(value, (str, list)) and _id_list(value):
        return "ids"
    if isinstance(value, str):
        return "name"
    return "invalid"


def disabled_roles(merged: dict) -> set:
    return {role for role, value in merged.items() if role_state(value) == "disabled"}


def invalid_roles(merged: dict) -> list:
    return sorted(role for role, value in merged.items() if role_state(value) == "invalid")


def resolve_fields(client: JiraClient, wanted: dict):
    """Map {role: field name, customfield_ id or list of ids} to {role: [field ids]}.

    Names are looked up (case-insensitively) via GET /rest/api/3/field, and pinned
    ids are checked against the same list so a mistyped id is not silently read as
    an always-empty field. A role may be pinned to several ids because team-managed
    projects each create their own copy of a field; a ticket is read from whichever
    of them holds a value. Returns (ids, problems, candidates) where problems maps
    role to "unresolved" (no such field or id), "ambiguous" (several fields share
    the name), "invalid" (not a name, id or list of ids) or "disabled" (empty), and
    candidates maps each ambiguous role to the matching fields so the operator can
    pin one or more by customfield_ id.
    """
    ids, problems, candidates = {}, {}, {}
    names, pinned = {}, {}
    for role, value in wanted.items():
        state = role_state(value)
        if state == "disabled" or state == "invalid":
            problems[role] = state
        elif state == "ids":
            pinned[role] = _id_list(value)
        else:
            names[role] = value.strip().lower()
    if not names and not pinned:
        return ids, problems, candidates
    fields = client.request("GET", "/rest/api/3/field", "GET /rest/api/3/field")
    if not isinstance(fields, list):
        problems.update({role: "unresolved" for role in list(names) + list(pinned)})
        return ids, problems, candidates
    by_name: dict = {}
    known_ids: set = set()
    for f in fields:
        if isinstance(f, dict) and isinstance(f.get("name"), str) and isinstance(f.get("id"), str):
            schema = f.get("schema") if isinstance(f.get("schema"), dict) else {}
            known_ids.add(f["id"])
            by_name.setdefault(f["name"].strip().lower(), []).append(
                {
                    "id": f["id"],
                    "name": f["name"],
                    "type": schema.get("custom") or schema.get("type"),
                }
            )
    for role, fids in pinned.items():
        unknown = [fid for fid in fids if fid not in known_ids]
        if unknown:
            problems[role] = "unresolved"
            candidates[role] = [{"id": fid, "name": None, "type": "not a field on this site"} for fid in unknown]
        else:
            ids[role] = fids
    for role, name in names.items():
        found = by_name.get(name, [])
        if len(found) == 1:
            ids[role] = [found[0]["id"]]
        elif found:
            problems[role] = "ambiguous"
            candidates[role] = found[:10]
        else:
            problems[role] = "unresolved"
    return ids, problems, candidates


def all_field_ids(ids: dict) -> list:
    """Every resolved field id, sorted and de-duplicated."""
    return sorted({fid for fids in ids.values() for fid in fids})


def role_values(fields: dict, ids: dict) -> dict:
    """{role: plain value} reading each role from the first of its ids that holds a value."""
    out = {}
    for role, fids in ids.items():
        # An empty string is "no value" too: keep looking in the role's other ids.
        out[role] = next((v for v in (field_value(fields.get(fid)) for fid in fids) if v not in (None, "")), None)
    return out


def field_problem_reason(problems: dict, env_name: str) -> str:
    """Explain unresolved or ambiguous field roles, or return "" when every enabled role resolved."""
    bad = sorted(f"{role} ({p})" for role, p in problems.items() if p in ("unresolved", "ambiguous", "invalid"))
    if not bad:
        return ""
    return (
        f"fields not resolved: {', '.join(bad)}; findings that depend on them are not reliable. "
        f"Set {env_name} to the field's name, a customfield_ id from metadata.field_candidates "
        f"(a list must hold customfield_ ids only), or an empty value to turn that check off"
    )


def _adf_text(node) -> str:
    if isinstance(node, dict):
        if node.get("type") == "text" and isinstance(node.get("text"), str):
            return node["text"]
        return " ".join(t for t in (_adf_text(c) for c in node.get("content") or []) if t)
    if isinstance(node, list):
        return " ".join(t for t in (_adf_text(c) for c in node) if t)
    return ""


def field_value(raw):
    """Plain value of a Jira field: option value, user display name, or the scalar itself."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, dict):
        if raw.get("type") == "doc":
            return _adf_text(raw).strip() or None
        for key in ("value", "displayName", "name", "key"):
            if raw.get(key) is not None and not isinstance(raw.get(key), (dict, list)):
                return str(raw[key])
        return None
    if isinstance(raw, list):
        vals = [field_value(v) for v in raw]
        return ", ".join(v for v in vals if v) or None
    return str(raw)


def fetch_issues(client: JiraClient, keys, fields: list):
    """Fetch issues by key via POST /rest/api/3/issue/bulkfetch, 100 per call.

    Unknown or hidden keys come back as issueErrors rather than failing the call.
    Returns (issues, missing_keys, complete). Keys that do not look like issue keys are skipped.
    """
    safe = sorted({k for k in keys if isinstance(k, str) and ISSUE_KEY.fullmatch(k)})
    found: list = []
    missing: list = []
    complete = True
    for i in range(0, len(safe), 100):
        chunk = safe[i : i + 100]
        page = client.request(
            "POST",
            "/rest/api/3/issue/bulkfetch",
            "POST /rest/api/3/issue/bulkfetch",
            body={"issueIdsOrKeys": chunk, "fields": fields},
        )
        if not isinstance(page, dict):
            # The call failed, so nothing in this chunk was read: report every key
            # as not visible rather than letting a caller treat it as absent.
            complete = False
            missing.extend(chunk)
            continue
        got = [i for i in page.get("issues") or [] if isinstance(i, dict)]
        found.extend(got)
        seen = {i.get("key") for i in got}
        missing.extend(k for k in chunk if k not in seen)
    return found, sorted(missing), complete


def json_env(name: str, default):
    """Parse a JSON object from an env var. Returns (value, error)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default, None
    try:
        value = json.loads(raw)
    except ValueError:
        return None, f"{name} must be a JSON object"
    if not isinstance(value, dict):
        return None, f"{name} must be a JSON object"
    return value, None


def int_env(name: str, default: int):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def list_env(name: str) -> list:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


# Jira Cloud hosts the API token may be sent to: a site, or the API gateway
# (required for scoped tokens). Government Cloud has its own domains.
# One DNS label under the Atlassian domain, ASCII only: a looser check let
# "evil.com\.atlassian.net" through, which requests sends to evil.com.
_SITE_HOST = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:atlassian\.net|atlassian-us-gov-mod\.net)$"
)
_GATEWAY_HOSTS = ("api.atlassian.com", "api.atlassian-us-gov-mod.com")
_URL_CHARS = re.compile(r"^[A-Za-z0-9:/._-]+$")
_GATEWAY_PATH = re.compile(r"^/ex/jira/[0-9A-Za-z-]{8,64}$")


def validate_base_url(raw: str):
    """Return (normalized_url, None) or (None, error). The error never echoes the raw value."""
    if not _URL_CHARS.fullmatch(raw):
        return None, "JIRA_BASE_URL contains characters a Jira Cloud URL never has"
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None, "JIRA_BASE_URL is not a valid URL"
    if parts.scheme != "https":
        return None, "JIRA_BASE_URL must use https://"
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return None, "JIRA_BASE_URL must not contain a username or password"
    if parts.query or parts.fragment:
        return None, "JIRA_BASE_URL must not contain a query string or fragment"
    if port not in (None, 443):
        return None, "JIRA_BASE_URL must not set a port"
    path = parts.path.rstrip("/")
    if _SITE_HOST.fullmatch(host) and not path:
        return f"https://{host}", None
    if host in _GATEWAY_HOSTS and _GATEWAY_PATH.fullmatch(path):
        return f"https://{host}{path}", None
    return None, (
        "JIRA_BASE_URL must be a Jira Cloud site (https://<site>.atlassian.net) or the "
        "API gateway for a scoped token (https://api.atlassian.com/ex/jira/<cloudId>); "
        f"got host {host or '(none)'!r}"
    )


def connection_settings():
    """Read the category settings. Returns (base_url, email, token), or an error string."""
    raw_url = os.environ.get("JIRA_BASE_URL", "").strip()
    email = os.environ.get("JIRA_EMAIL", "").strip()
    api_token = os.environ.get("JIRA_API_TOKEN", "").strip()
    for var, value in (
        ("JIRA_BASE_URL", raw_url),
        ("JIRA_EMAIL", email),
        ("JIRA_API_TOKEN", api_token),
    ):
        if not value:
            return f"{var} is not set"
    base_url, error = validate_base_url(raw_url)
    if error:
        return error
    return base_url, email, api_token


def collector_info(client: JiraClient):
    me = client.request("GET", "/rest/api/3/myself", "GET /rest/api/3/myself")
    if not me:
        return None
    return {
        "account_id": me.get("accountId"),
        "display_name": me.get("displayName"),
        "account_type": me.get("accountType"),
        "active": me.get("active"),
    }


def null_summary(summary):
    """The same shape as `summary` with every value null: for a section whose fetch failed,
    so a reader sees "not measured", never a zero that looks like "none found".
    Fixed-shape dicts keep their keys; a rollup keyed by data (Counts) becomes null."""
    if isinstance(summary, dict) and not isinstance(summary, Counts):
        return {k: null_summary(v) for k, v in summary.items()}
    return None


def is_date_only(value) -> bool:
    return isinstance(value, str) and len(value.strip()) == 10


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def write_and_finish(logger: logging.Logger, client: JiraClient, evidence: dict, filename: str, extra_failure: str = "") -> int:
    """Write the evidence file, then report the run's outcome. Returns the exit code."""
    meta = evidence.setdefault("metadata", {})
    meta["complete"] = not (extra_failure or client.api_failures)
    # The contract's signal for a validator is partial_failure, so it must follow
    # complete, not only api_failures: a hit cap or an unresolved field is partial too.
    meta["partial_failure"] = not meta["complete"]
    meta["incomplete_reason"] = extra_failure or None
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename
    try:
        output_path.write_text(json.dumps(evidence, indent=2))
    except OSError as e:
        report_failure(f"could not write evidence file: {e}", "internal_error")
        return 1

    logger.info("Evidence saved to %s", output_path)

    if client.api_failures:
        codes = client.failure_codes
        if "auth_failed" in codes:
            code = "auth_failed"
        elif len(set(codes)) == 1:
            code = codes[0]
        else:
            code = "partial_failure"
        detail = "; ".join(
            f"{f['operation']}: {f['type']} {f['message']}".strip()
            for f in client.api_failures[:3]
        )
        reason = f"{len(client.api_failures)} Jira API call(s) failed during collection - {detail}"
        if extra_failure:
            reason = f"{extra_failure}; {reason}"
        report_failure(reason, code)
        return 1
    if extra_failure:
        report_failure(extra_failure, "partial_failure")
        return 1
    return 0
