"""Read-only Qualys FO API client. Never returns a successful partial collection."""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from typing import TYPE_CHECKING

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as SafeET
from defusedxml.ElementTree import ParseError

if TYPE_CHECKING:
    from xml.etree import ElementTree as ET
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402, F401

DETECTIONS = "/api/2.0/fo/asset/host/vm/detection/"
KNOWLEDGE_BASE = "/api/2.0/fo/knowledge_base/vuln/"
QVS = "/api/2.0/fo/knowledge_base/qvs/"
POLICIES = "/api/2.0/fo/compliance/policy/"
POSTURE = "/api/2.0/fo/compliance/posture/info/"
ENDPOINTS = {DETECTIONS, KNOWLEDGE_BASE, QVS, POLICIES, POSTURE}


# Adapted from Connor Dalton (@Controgon), paramify/paramify-fetchers#289,
# commit 5ce1171d097e130bf8f433894332191cb3934f56 (GPL-3.0-only).
# Retain bounded responses and sanitized diagnostics for assessment reports.
QUALYS_DOMAINS = (
    "qualys.com",
    "qualys.us",
    "qualys.eu",
    "qualys.it",
    "qualys.in",
    "qualys.ca",
    "qualys.ae",
    "qualys.co.uk",
    "qualys.com.au",
    "qualysksa.com",
)
RETRY_CODES = {"1920", "1960", "1965", "1981", "1999"}


def platform_host(host: str) -> bool:
    rest = host.removeprefix("qualysapi.")
    return rest != host and any(
        rest == d or rest.endswith(f".{d}") for d in QUALYS_DOMAINS
    )


def error_category(status: int, code: str) -> str:
    if status == 401 or code in {"2000", "2002", "2011"}:
        return "auth_failed"
    if code == "2003" or status == 400:
        return "bad_config"
    if status == 403 or code == "2012":
        return "not_authorized"
    return "partial_failure"


class QualysError(Exception):
    def __init__(self, message: str, code: str = "partial_failure"):
        super().__init__(message)
        self.code = code


def value(node: ET.Element, path: str, required: bool = False) -> str:
    result = (node.findtext(path) or "").strip()
    if required and not result:
        raise QualysError(f"Qualys response is missing required field {path}")
    return result


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        result = int(os.environ.get(name, str(default)))
    except ValueError:
        raise QualysError(f"{name} must be an integer", "bad_config") from None
    if not minimum <= result <= maximum:
        raise QualysError(
            f"{name} must be between {minimum} and {maximum}", "bad_config"
        )
    return result


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, str(default)).lower().strip()
    if raw not in {"true", "false"}:
        raise QualysError(f"{name} must be true or false", "bad_config")
    return raw == "true"


def id_list(raw: str) -> str:
    if raw and not re.fullmatch(
        r"[1-9]\d*(?:-[1-9]\d*)?(?:,[1-9]\d*(?:-[1-9]\d*)?)*", raw
    ):
        raise QualysError(
            "IDs must be comma-separated positive integers or ranges", "bad_config"
        )
    for item in raw.split(",") if raw else []:
        if "-" in item and int(item.split("-")[0]) > int(item.split("-")[1]):
            raise QualysError("ID ranges must be ascending", "bad_config")
    return raw


def parse_xml(body: bytes) -> ET.Element:
    # Qualys uses an external DOCTYPE; ElementTree never fetches it. Reject
    # internal entities and non-UTF-8 XML before parsing untrusted responses.
    try:
        decoded = body.decode("utf-8-sig")
        if "\x00" in decoded or "<!ENTITY" in decoded:
            raise ValueError
        return SafeET.fromstring(decoded, forbid_dtd=False)
    except (UnicodeError, ParseError, DefusedXmlException, ValueError):
        raise QualysError("Qualys returned invalid or unsafe XML") from None


class QualysClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        private_host: str = "",
        page_size: int = 1000,
        max_pages: int = 10000,
        max_records: int = 500000,
        retries: int = 3,
        interval: int = 1,
        session=None,
        sleep=time.sleep,
    ):
        parts = urlsplit(base_url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
        ):
            raise QualysError(
                "QUALYS_API_URL must be an HTTPS origin without credentials or a path",
                "bad_config",
            )
        host = parts.hostname.lower()
        if host.startswith("qualysguard.") or not (
            platform_host(host) or host == private_host.strip().lower()
        ):
            raise QualysError(
                "QUALYS_API_URL must name a Qualys API host; explicitly configure "
                "QUALYS_PRIVATE_CLOUD_HOST for a private cloud endpoint",
                "bad_config",
            )
        if not username or not password:
            raise QualysError(
                "QUALYS_USERNAME and QUALYS_PASSWORD are required", "bad_config"
            )
        self.base_url = base_url.rstrip("/")
        self.page_size = page_size
        self.max_pages = max_pages
        self.max_records = max_records
        self.retries = retries
        self.interval = interval
        self.session = session or requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({"X-Requested-With": "paramify-fetchers"})
        self.sleep = sleep
        self._last_request = None

    def close(self):
        self.session.close()

    def request(self, path: str, params: dict) -> bytes:
        if path not in ENDPOINTS or params.get("action") != "list":
            raise QualysError(
                "Only supported Qualys list operations are allowed", "bad_config"
            )
        for attempt in range(self.retries + 1):
            if self._last_request is not None:
                self.sleep(
                    max(0, self.interval - (time.monotonic() - self._last_request))
                )
            self._last_request = time.monotonic()
            retry_code = "partial_failure"
            headers = {}
            try:
                with self.session.get(
                    self.base_url + path,
                    params=params,
                    timeout=(10, 120),
                    allow_redirects=False,
                    stream=True,
                ) as response:
                    status = response.status_code
                    headers = response.headers
                    chunks, size = [], 0
                    for chunk in response.iter_content(1024 * 1024):
                        size += len(chunk)
                        if size > 64 * 1024 * 1024:
                            raise QualysError(
                                "Qualys page exceeds 64 MiB; reduce page_size"
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    code, wait_hint = "", None
                    if body.lstrip().startswith(b"<"):
                        try:
                            root = parse_xml(body)
                        except QualysError:
                            if status == 200:
                                raise
                        else:
                            if root.tag == "SIMPLE_RETURN":
                                code = value(root, "RESPONSE/CODE")
                                for item in root.iter("ITEM"):
                                    if value(item, "KEY") == "SECONDS_TO_WAIT":
                                        wait_hint = value(item, "VALUE")
                                if not code:
                                    raise QualysError(
                                        "Qualys returned an error without a code"
                                    )
                    # Qualys overloads HTTP 409; inspect its API code before
                    # deciding whether this is throttling or a permanent error.
                    if code in RETRY_CODES or status in {202, 429, 500, 502, 503, 504}:
                        retry_code = (
                            "rate_limited"
                            if code in {"1920", "1960", "1965"} or status == 429
                            else "partial_failure"
                        )
                        if wait_hint is not None:
                            headers = {**headers, "X-RateLimit-ToWait-Sec": wait_hint}
                    elif code or status != 200:
                        # Never include the server's TEXT/body: it may contain
                        # credentials or scanner evidence.
                        raise QualysError(
                            f"Qualys request failed at {path} (HTTP {status}, code {code or 'none'})",
                            error_category(status, code),
                        )
                    else:
                        if not body.strip():
                            raise QualysError("Qualys returned an empty response")
                        return body
            except requests.RequestException:
                # Exception strings can include credentials, URLs, or response data.
                retry_code = "target_unreachable"
            if attempt == self.retries:
                raise QualysError(
                    f"Qualys request failed after {attempt + 1} attempts at {path}",
                    retry_code,
                )
            wait = 2**attempt
            for header in ("Retry-After", "X-RateLimit-ToWait-Sec"):
                raw = headers.get(header, "0")
                try:
                    delay = int(raw)
                except (TypeError, ValueError):
                    try:
                        delay = parsedate_to_datetime(raw).timestamp() - time.time()
                    except (TypeError, ValueError, OverflowError):
                        delay = 0
                wait = max(wait, delay)
            if wait > 60:
                raise QualysError(
                    "Qualys retry delay exceeds 60 seconds; retry the run later",
                    retry_code,
                )
            logging.warning(
                "Retrying Qualys %s request in %.1f seconds", retry_code, wait
            )
            self.sleep(wait)
        raise AssertionError("unreachable")

    def xml(self, path: str, params: dict, root_name: str) -> ET.Element:
        root = parse_xml(self.request(path, params))
        response = root.find("RESPONSE")
        if root.tag != root_name or response is None or not value(response, "DATETIME"):
            raise QualysError(f"Unexpected Qualys response structure at {path}")
        return response

    def next_params(
        self, response: ET.Element, path: str, original: dict
    ) -> dict | None:
        warnings = response.findall(".//WARNING")
        if not warnings:
            return None
        if len(warnings) != 1 or value(warnings[0], "CODE") != "1980":
            raise QualysError(
                "Qualys returned an unhandled warning; collection may be incomplete"
            )
        url = value(warnings[0], "URL", required=True)
        parts = urlsplit(urljoin(self.base_url + path, url))
        base = urlsplit(self.base_url)
        if (
            parts.scheme != base.scheme
            or parts.netloc != base.netloc
            or parts.path != path
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise QualysError("Qualys pagination URL changed origin or endpoint")
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        query = dict(pairs)
        if len(query) != len(pairs) or not re.fullmatch(
            r"[1-9]\d*", query.get("id_min", "")
        ):
            raise QualysError("Qualys pagination URL has an invalid cursor")
        # Only the cursor can change. Reapply all original scope/status fields,
        # including ones absent from the server's continuation URL.
        for key, val in query.items():
            if key != "id_min" and (key not in original or str(original[key]) != val):
                raise QualysError("Qualys pagination URL changed the requested scope")
        return {**original, "id_min": query["id_min"]}

    def pages(self, path: str, params: dict, root_name: str):
        original = {"action": "list", **params}
        current = original
        previous_cursor = 0
        for _ in range(self.max_pages):
            response = self.xml(path, current, root_name)
            following = self.next_params(response, path, original)
            yield response
            if following is None:
                return
            cursor = int(following["id_min"])
            if cursor <= previous_cursor:
                raise QualysError("Qualys pagination cursor did not advance")
            previous_cursor = cursor
            current = following
        raise QualysError("Qualys page limit reached; no complete report available")


def build_client() -> QualysClient:
    return QualysClient(
        os.environ.get("QUALYS_API_URL", ""),
        os.environ.get("QUALYS_USERNAME", ""),
        os.environ.get("QUALYS_PASSWORD", ""),
        private_host=os.environ.get("QUALYS_PRIVATE_CLOUD_HOST", ""),
        page_size=env_int("QUALYS_PAGE_SIZE", 1000, 1, 10000),
        max_pages=env_int("QUALYS_MAX_PAGES", 10000, 1, 100000),
        max_records=env_int("QUALYS_MAX_RECORDS", 500000, 1, 10000000),
        retries=env_int("QUALYS_RETRIES", 3, 0, 10),
        interval=env_int("QUALYS_MIN_REQUEST_INTERVAL", 1, 0, 60),
    )
