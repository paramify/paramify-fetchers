"""Qualys VM/PC API client: Basic auth, hardened XML parsing, retries and WARNING/URL paging."""

from __future__ import annotations

import io
import ipaddress
import os
import random
import time
from typing import Any, Callable, Iterator, Optional
from urllib.parse import parse_qs, urlsplit
from xml.etree.ElementTree import Element, ParseError

import requests

try:
    from defusedxml import DefusedXmlException
    from defusedxml import ElementTree as SafeET
except ImportError:  # reported as bad_config when the client is built
    SafeET = None
    DefusedXmlException = Exception  # type: ignore[assignment,misc]

TIMEOUT = (30, 600)
MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 2.0
BACKOFF_CAP_S = 60.0
MAX_WAIT_S = 300
MAX_PAGES = 10_000
REQUESTED_WITH = "paramify-fetchers"

PLATFORMS = {
    "qualysapi.qualys.com": "US1",
    "qualysapi.qg2.apps.qualys.com": "US2",
    "qualysapi.qg3.apps.qualys.com": "US3",
    "qualysapi.qg4.apps.qualys.com": "US4",
    "qualysapi.gov1.qualys.us": "GOV1",
    "qualysapi.qualys.eu": "EU1",
    "qualysapi.qg2.apps.qualys.eu": "EU2",
    "qualysapi.qg3.apps.qualys.it": "EU3",
    "qualysapi.qg1.apps.qualys.in": "IN1",
    "qualysapi.qg1.apps.qualys.ca": "CA1",
    "qualysapi.qg1.apps.qualys.ae": "AE1",
    "qualysapi.qg1.apps.qualys.co.uk": "UK1",
    "qualysapi.qg1.apps.qualys.com.au": "AU1",
    "qualysapi.qg1.apps.qualysksa.com": "KSA1",
}

RETRY_CODES = {"1920", "1960", "1965", "1981", "1999"}
HINTS = {
    "2000": "check QUALYS_USERNAME and QUALYS_PASSWORD; SSO users cannot use the API with a password",
    "2002": "the Qualys user account is inactive",
    "2003": "the subscription's registration is not complete; log in to the Qualys UI once with this user",
    "2011": "the user needs SecureID, which blocks API access",
    "2012": "the subscription's licence does not allow this API",
}


class QualysError(Exception):
    """A failed Qualys call. `code` is one of fetcher_status.STATUS_CODES."""

    def __init__(self, message: str, code: str = "partial_failure", operation: str = "",
                 qualys_code: Optional[str] = None) -> None:
        super().__init__(message)
        self.code = code
        self.operation = operation
        self.qualys_code = qualys_code


def text(elem: Optional[Element], path: str) -> Optional[str]:
    """Stripped text at `path` under `elem`, or None when absent or empty."""
    if elem is None:
        return None
    found = elem.find(path)
    if found is None or found.text is None:
        return None
    value = found.text.strip()
    return value or None


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_api_url(raw: str) -> str:
    """scheme://host[:port] of the Qualys API server; https only, except a loopback test double."""
    parts = urlsplit(raw.strip())
    host = (parts.hostname or "").lower()
    if not host:
        raise QualysError(f"QUALYS_API_URL {raw!r} is not a URL", "bad_config", "configuration")
    if parts.username or parts.password:
        raise QualysError("QUALYS_API_URL must not carry credentials", "bad_config", "configuration")
    if parts.scheme != "https" and not (parts.scheme == "http" and _loopback(host)):
        raise QualysError("QUALYS_API_URL must use https", "bad_config", "configuration")
    if host.startswith("qualysguard."):
        raise QualysError(
            f"QUALYS_API_URL {host} is the Qualys web UI; use the API server URL "
            "(qualysapi.…, shown under Help > About in the Qualys UI)", "bad_config", "configuration")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    default = {"https": 443, "http": 80}
    return (pa.scheme, pa.hostname, pa.port or default.get(pa.scheme)) == \
        (pb.scheme, pb.hostname, pb.port or default.get(pb.scheme))


class QualysClient:
    def __init__(self, base_url: str, username: str, password: str,
                 session: Optional[requests.Session] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if SafeET is None:
            raise QualysError("defusedxml is not installed (pip install defusedxml)", "bad_config", "configuration")
        self.base_url = normalize_api_url(base_url)
        self.username = username
        self.password = password
        self.session = session or requests.Session()
        self.sleep = sleep
        self.pages = 0

    @classmethod
    def from_env(cls) -> "QualysClient":
        url = os.environ.get("QUALYS_API_URL", "").strip()
        username = os.environ.get("QUALYS_USERNAME", "").strip()
        password = os.environ.get("QUALYS_PASSWORD", "")
        missing = [n for n, v in (("QUALYS_API_URL", url), ("QUALYS_USERNAME", username),
                                  ("QUALYS_PASSWORD", password)) if not v]
        if missing:
            raise QualysError(f"{', '.join(missing)} not set", "bad_config", "configuration")
        return cls(url, username, password)

    @property
    def platform(self) -> str:
        host = urlsplit(self.base_url).hostname or ""
        return PLATFORMS.get(host, "private_or_unlisted")

    @staticmethod
    def _seconds(value: Optional[str]) -> Optional[float]:
        try:
            return float(value) if value else None
        except ValueError:
            return None

    def _error_detail(self, body: bytes, headers: Any) -> tuple[Optional[str], str, Optional[float]]:
        code, message, wait = None, "", None
        try:
            root = SafeET.fromstring(body, forbid_dtd=False)
            code = text(root, ".//CODE")
            message = text(root, ".//TEXT") or ""
            for item in root.iter("ITEM"):
                if text(item, "KEY") == "SECONDS_TO_WAIT":
                    wait = self._seconds(text(item, "VALUE"))
        except (ParseError, DefusedXmlException):
            message = body[:200].decode("utf-8", "replace")
        if wait is None:
            wait = self._seconds(headers.get("X-RateLimit-ToWait-Sec"))
        return code, " ".join(message.split()), wait

    @staticmethod
    def _classify(status: int, code: Optional[str]) -> tuple[bool, str]:
        if code in RETRY_CODES or status in (202, 429, 500, 502, 503, 504):
            return True, "rate_limited" if code in {"1920", "1960", "1965"} or status == 429 else "target_unreachable"
        if status == 401 or code in {"2000", "2002", "2011"}:
            return False, "auth_failed"
        if code == "2003" or status == 400:
            return False, "bad_config"
        if status == 403 or code == "2012":
            return False, "not_authorized"
        return False, "internal_error"

    def _backoff(self, attempt: int) -> float:
        return min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2 ** (attempt - 1)) + random.uniform(0, 1)

    def get(self, url: str, params: Optional[dict], operation: str) -> bytes:
        """GET one page; retries throttling and transient errors; raises QualysError otherwise."""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resp = self.session.get(
                    url, params=params, auth=(self.username, self.password),
                    headers={"X-Requested-With": REQUESTED_WITH}, timeout=TIMEOUT, allow_redirects=False)
            except (requests.ConnectionError, requests.Timeout) as e:
                if attempt == MAX_ATTEMPTS:
                    raise QualysError(f"{operation}: could not reach {self.base_url}: {type(e).__name__}",
                                      "target_unreachable", operation) from e
                self.sleep(self._backoff(attempt))
                continue
            if resp.status_code == 200:
                return resp.content
            if 300 <= resp.status_code < 400:
                raise QualysError(
                    f"{operation}: HTTP {resp.status_code} redirect; QUALYS_API_URL should be the API server URL",
                    "bad_config", operation)
            code, message, wait = self._error_detail(resp.content, resp.headers)
            retry, status_code = self._classify(resp.status_code, code)
            if retry and attempt < MAX_ATTEMPTS:
                delay = wait if wait is not None else self._backoff(attempt)
                if delay > MAX_WAIT_S:
                    raise QualysError(f"{operation}: Qualys asks to wait {delay:.0f}s (limit {MAX_WAIT_S}s): {message}",
                                      "rate_limited", operation, code)
                self.sleep(delay)
                continue
            hint = f" ({HINTS[code]})" if code in HINTS else ""
            raise QualysError(f"{operation}: HTTP {resp.status_code}, Qualys code {code}: {message}{hint}",
                              status_code, operation, code)
        raise QualysError(f"{operation}: no response after {MAX_ATTEMPTS} attempts", "target_unreachable", operation)

    def records(self, path: str, params: dict[str, Any], record_tag: str | tuple[str, ...],
                operation: str) -> Iterator[Element]:
        """Every `record_tag` element across all pages, to the last RESPONSE/WARNING/URL.

        Each next page re-sends `params` with the id_min from WARNING/URL, so a next-page URL that drops a
        filter never widens or narrows the list. Read each element before the next iteration; it is cleared.
        """
        tags = (record_tag,) if isinstance(record_tag, str) else record_tag
        url = f"{self.base_url}{path}"
        query = dict(params)
        seen: set[str] = set()
        pages = 0
        while True:
            pages += 1
            if pages > MAX_PAGES:
                raise QualysError(f"{operation}: paging did not end after {MAX_PAGES} pages", "internal_error", operation)
            body = self.get(url, query, operation)
            self.pages += 1
            if b"<SIMPLE_RETURN" in body[:4096]:
                code, message, _ = self._error_detail(body, {})
                raise QualysError(f"{operation}: Qualys returned code {code}: {message}",
                                  self._classify(200, code)[1], operation, code)
            next_url: Optional[str] = None
            truncated = False
            try:
                for _, elem in SafeET.iterparse(io.BytesIO(body), events=("end",), forbid_dtd=False):
                    if elem.tag in tags:
                        yield elem
                        elem.clear()
                    elif elem.tag == "WARNING":
                        truncated = text(elem, "CODE") == "1980" or text(elem, "URL") is not None
                        next_url = text(elem, "URL")
            except (ParseError, DefusedXmlException) as e:
                raise QualysError(f"{operation}: response could not be parsed safely: {e}", "internal_error",
                                  operation) from e
            if truncated and not next_url:
                raise QualysError(f"{operation}: Qualys truncated the list without a next-page URL",
                                  "partial_failure", operation)
            if not next_url:
                return
            if not (_same_origin(next_url, self.base_url) and urlsplit(next_url).path.rstrip("/") == path.rstrip("/")):
                raise QualysError(f"{operation}: next-page URL points outside {self.base_url}{path}; not followed",
                                  "internal_error", operation)
            id_min = (parse_qs(urlsplit(next_url).query).get("id_min") or [""])[0]
            if not id_min or id_min in seen:
                raise QualysError(f"{operation}: next-page URL has no new id_min; paging stopped",
                                  "partial_failure", operation)
            seen.add(id_min)
            query = {**params, "id_min": id_min}
