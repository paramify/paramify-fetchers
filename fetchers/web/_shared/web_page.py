"""Shared by the web fetchers: one bounded GET, content-type handling and the run wrapper (HTML to text is in _lib)."""

import codecs
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, NamedTuple, Optional, Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402
from html_text import find_last_updated, html_to_text  # noqa: E402,F401  (re-exported for the web fetchers)

REQUEST_TIMEOUT = 30
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 5 * 1024 * 1024
ACCEPT = "text/html, application/json;q=0.9, text/plain;q=0.8"
HTML_TYPES = {"text/html", "application/xhtml+xml"}
HTTP_CODES = {401: "auth_failed", 403: "not_authorized", 429: "rate_limited"}

META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?([A-Za-z0-9_.:-]+)""", re.IGNORECASE)


class CollectionError(Exception):
    """A failure that ends the invocation: `kind` for the ledger, `code` for the contract."""

    def __init__(self, message: str, kind: str, code: str = "target_unreachable") -> None:
        super().__init__(message)
        self.kind = kind
        self.code = code


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise CollectionError(f"Missing required env var: {name}", "missing_config", "bad_config")
    return value


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def check_url(url: str, env: str = "WEB_PAGE_URL") -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise CollectionError(f"{env} is not an http(s) URL: {url!r}", "bad_url", "bad_config")
    return url


def sanitize_for_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", value)


def media_type(content_type: str) -> Tuple[str, Optional[str]]:
    media, _, params = content_type.partition(";")
    charset = None
    for param in params.split(";"):
        key, _, value = param.partition("=")
        if key.strip().lower() == "charset" and value.strip():
            charset = value.strip().strip("\"'")
    return media.strip().lower(), charset


def _codec(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    try:
        return codecs.lookup(name).name
    except LookupError:
        return None


def decode_body(body: bytes, charset: Optional[str], is_html: bool) -> str:
    """Header charset, else an HTML <meta charset>, else UTF-8 (replacing bad bytes)."""
    meta = META_CHARSET.search(body[:4096]) if is_html else None
    for candidate in (charset, meta.group(1).decode("ascii") if meta else None):
        codec = _codec(candidate)
        if codec:
            return body.decode(codec, errors="replace")
    return body.decode("utf-8", errors="replace")


def fetch(
    url: str, verify_ssl: bool, record: Dict[str, Any], user_agent: str, accept: str = ACCEPT
) -> Tuple[bytes, str]:
    """GET the page; fills `record` with what the response said, even when it fails."""
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    try:
        response = session.get(
            url,
            headers={"User-Agent": user_agent, "Accept": accept},
            timeout=REQUEST_TIMEOUT,
            verify=verify_ssl,
            stream=True,
        )
    except requests.exceptions.TooManyRedirects as exc:
        raise CollectionError(f"GET {url} redirected more than {MAX_REDIRECTS} times", "too_many_redirects") from exc
    except requests.exceptions.SSLError as exc:
        raise CollectionError(f"GET {url} failed TLS verification: {exc}", "tls_error") from exc
    except requests.exceptions.RequestException as exc:
        raise CollectionError(
            f"GET {url} failed at the network layer: {type(exc).__name__}: {exc}", "network_error"
        ) from exc

    with response:
        record["final_url"] = response.url
        record["redirects"] = [
            {"url": hop.url, "status": hop.status_code, "location": hop.headers.get("Location")}
            for hop in response.history
        ]
        record["http_status"] = response.status_code
        content_type = response.headers.get("Content-Type", "")
        record["content_type"] = content_type or None

        if response.status_code != 200:
            try:
                start = next(response.iter_content(200), b"")
            except requests.exceptions.RequestException:
                start = b""
            raise CollectionError(
                f"GET {url} returned HTTP {response.status_code} (expected 200); "
                f"body starts: {start[:200].decode('utf-8', errors='replace')!r}",
                "http_error",
                HTTP_CODES.get(response.status_code, "target_unreachable"),
            )

        declared = response.headers.get("Content-Length", "")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            raise CollectionError(
                f"GET {url} declared a {declared}-byte body, over the {MAX_BODY_BYTES}-byte limit", "body_too_large"
            )
        chunks, size = [], 0
        try:
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > MAX_BODY_BYTES:
                    raise CollectionError(f"GET {url} body exceeds the {MAX_BODY_BYTES}-byte limit", "body_too_large")
                chunks.append(chunk)
        except requests.exceptions.RequestException as exc:
            raise CollectionError(
                f"GET {url} failed while reading the body: {type(exc).__name__}: {exc}", "network_error"
            ) from exc
    return b"".join(chunks), content_type


def fetch_recorded(
    url: str, verify_ssl: bool, user_agent: str, accept: str = ACCEPT
) -> Tuple[Dict[str, Any], Optional[bytes], str]:
    """fetch() for a linked URL: a failure is recorded in `error`, not raised."""
    record: Dict[str, Any] = {
        "url": url, "final_url": None, "redirects": [], "http_status": 0, "content_type": None, "error": None,
    }
    try:
        check_url(url, "linked URL")
        body, content_type = fetch(url, verify_ssl, record, user_agent, accept)
    except CollectionError as exc:
        record["error"] = {"type": exc.kind, "message": str(exc)}
        return record, None, record["content_type"] or ""
    return record, body, content_type


class PageContent(NamedTuple):
    text: str
    title: Optional[str]
    is_json: bool
    document: Any


def read_content(body: bytes, content_type: str, url: str) -> PageContent:
    """Decode the body by media type. Unsupported types, bad JSON and empty text all fail."""
    media, charset = media_type(content_type)
    is_json = media == "application/json" or media.endswith("+json")
    title, document = None, None
    if media in HTML_TYPES:
        text, title = html_to_text(decode_body(body, charset, is_html=True))
    elif is_json:
        # RFC 8259: JSON exchanged between systems is UTF-8.
        text = decode_body(body, charset or "utf-8", is_html=False)
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise CollectionError(f"GET {url} served {media} that is not valid JSON: {exc}", "invalid_json") from exc
    elif media == "text/plain":
        text = decode_body(body, charset, is_html=False)
    else:
        raise CollectionError(
            f"GET {url} served content type {content_type or '(none)'!r}; "
            "only HTML, JSON and plain text are supported",
            "unsupported_content_type",
        )
    if not text.strip():
        raise CollectionError(
            f"GET {url} returned no text. A page that renders its text with JavaScript "
            "looks like this, and is out of scope for this fetcher",
            "empty_text",
        )
    return PageContent(text, title, is_json, document)


def write_evidence(output_dir: Path, name: str, target_name: str, evidence: Dict[str, Any]) -> Path:
    path = output_dir / f"{name}_{sanitize_for_filename(target_name)}.json"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, ensure_ascii=False)
    return path


def run(
    name: str,
    collect: Callable[[str, bool, Dict[str, Any]], Dict[str, Any]],
    failure_fields: Dict[str, Any],
    url_env: str = "WEB_PAGE_URL",
    resolve_url: Callable[[str], str] = lambda url: url,
) -> int:
    """Run one web fetcher for the target in the environment. Returns the exit code.

    The URL comes from `url_env`, is checked to be http(s), then passed through
    `resolve_url`. `collect(url, verify_ssl, record)` returns the evidence dict; `record` holds the
    request fields and is filled in by fetch() as the response arrives. On failure the
    file gets `record`, then `failure_fields`, then the contract's failure ledger.
    """
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()
    logger = logging.getLogger(name)

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    target_name = os.environ.get("WEB_TARGET_NAME", "").strip() or "page"
    record: Dict[str, Any] = {
        "collected_at": current_timestamp(),
        "target_name": target_name,
        "url": os.environ.get(url_env, "").strip(),
        "final_url": None,
        "redirects": [],
        "http_status": 0,
        "content_type": None,
    }

    try:
        target_name = record["target_name"] = get_env("WEB_TARGET_NAME")
        url = record["url"] = resolve_url(check_url(get_env(url_env), url_env))
        evidence = collect(url, env_bool("WEB_VERIFY_SSL", True), record)
        path = write_evidence(output_dir, name, target_name, evidence)
    except CollectionError as exc:
        reason, kind, code = str(exc), exc.kind, exc.code
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still reportable
        reason = f"Unexpected error collecting {record['url']}: {type(exc).__name__}: {exc}"
        kind, code = "internal_error", "internal_error"
    else:
        logger.info("Evidence saved to %s", path)
        return 0

    failure = {
        **record,
        **failure_fields,
        "metadata": {
            "partial_failure": True,
            "api_failures": [{"operation": f"GET {record['url']}", "type": kind, "message": reason}],
        },
    }
    try:
        path = write_evidence(output_dir, name, target_name, failure)
        logger.info("Evidence saved to %s", path)
    except OSError as exc:
        logger.info("Could not write the failure evidence file: %s", exc)
    report_failure(reason, code)
    return 1
