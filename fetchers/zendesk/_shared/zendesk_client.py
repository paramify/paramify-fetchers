"""HTTP, URL and run-wrapper helpers shared by the zendesk fetchers."""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

import requests

# A category-shared module sits one level deeper than a fetcher, so fetchers/_lib is parents[2] / "_lib".
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

REQUEST_TIMEOUT = 30
MAX_REDIRECTS = 5
HTTP_CODES = {401: "auth_failed", 403: "not_authorized", 429: "rate_limited"}
SIGN_IN = re.compile(r"/signin|/access/", re.IGNORECASE)


class CollectionError(Exception):
    """A failure that ends the invocation: `kind` for the ledger, `code` for the contract."""

    def __init__(self, message: str, kind: str, code: str = "target_unreachable") -> None:
        super().__init__(message)
        self.kind = kind
        self.code = code


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def verify_ssl_enabled() -> bool:
    return env("ZENDESK_VERIFY_SSL").lower() not in {"0", "false", "no", "off"}


def require_env(*names: str) -> None:
    for name in names:
        if not env(name):
            raise CollectionError(f"Missing required env var: {name}", "missing_config", "bad_config")


def parse_origin(url: str, env_name: str, why: str = "") -> str:
    """scheme://host[:port] of an http(s) URL, or bad_config naming the env var."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise CollectionError(f"{why}{env_name} must be an http(s) URL; got {url!r}", "bad_url", "bad_config")
    return f"{parsed.scheme}://{parsed.netloc}"


def http_session(user_agent: str) -> requests.Session:
    http = requests.Session()
    http.max_redirects = MAX_REDIRECTS
    http.headers["User-Agent"] = user_agent
    return http


def get_json(http: requests.Session, url: str, verify: bool,
             auth: Optional[Tuple[str, str]] = None) -> Dict[str, Any]:
    try:
        response = http.get(url, headers={"Accept": "application/json"}, timeout=REQUEST_TIMEOUT, verify=verify,
                            auth=auth)
    except requests.exceptions.RequestException as exc:
        raise CollectionError(f"GET {url} failed: {type(exc).__name__}: {exc}", "network_error") from exc
    if response.status_code != 200:
        raise CollectionError(
            f"GET {url} returned HTTP {response.status_code} (expected 200); body starts: {response.text[:200]!r}",
            "http_error", HTTP_CODES.get(response.status_code, "target_unreachable"))
    try:
        document = response.json()
    except ValueError as exc:
        raise CollectionError(f"GET {url} did not return JSON", "invalid_json") from exc
    if not isinstance(document, dict):
        raise CollectionError(f"GET {url} returned JSON that is not an object", "unexpected_shape")
    return document


def public_page_status(http: requests.Session, url: Any, verify: bool) -> Dict[str, Any]:
    """An anonymous GET of a Help Center page. Recorded, never raised."""
    status: Dict[str, Any] = {"http_status": 0, "final_url": None, "redirected_to_signin": None,
                              "bot_challenge": None, "error": None}
    if not isinstance(url, str) or urlparse(url).scheme not in {"http", "https"}:
        status["error"] = {"type": "bad_url", "message": f"html_url is not an http(s) URL: {url!r}"}
        return status
    try:
        with http.get(url, headers={"Accept": "text/html"}, timeout=REQUEST_TIMEOUT, verify=verify,
                      stream=True) as response:
            status.update(http_status=response.status_code, final_url=response.url)
            status["redirected_to_signin"] = bool(SIGN_IN.search(urlparse(response.url).path))
            # Measured on support.paramify.com: Cloudflare answers every non-browser client 403 with this header.
            status["bot_challenge"] = response.headers.get("cf-mitigated", "").lower() == "challenge"
    except requests.exceptions.RequestException as exc:
        status["error"] = {"type": "network_error", "message": f"GET {url} failed: {type(exc).__name__}: {exc}"}
    return status


def write_evidence(output_dir: Path, name: str, target_name: str, evidence: Dict[str, Any]) -> Path:
    path = output_dir / f"{name}_{re.sub(r'[^A-Za-z0-9_-]', '_', target_name)}.json"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, ensure_ascii=False)
    return path


def _redact(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def run(name: str, target_name: str, record: Dict[str, Any], work: Callable[[], Dict[str, Any]],
        failure_fields: Dict[str, Any], operation: str, redact: Iterable[str] = ()) -> int:
    """Write work()'s evidence and return 0, or write a failure file, report why, and return 1.

    `work` may update `record` before it fails; the failure file carries those updates.
    """
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger = logging.getLogger(name)
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    secrets = list(redact)
    try:
        path = write_evidence(output_dir, name, target_name, work())
    except CollectionError as exc:
        reason, kind, code = str(exc), exc.kind, exc.code
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still reportable
        reason, kind, code = f"Unexpected error: {type(exc).__name__}: {exc}", "internal_error", "internal_error"
    else:
        logger.info("Evidence saved to %s", path)
        return 0

    reason = _redact(reason, secrets)
    failure = {
        **record, **failure_fields,
        "metadata": {"partial_failure": True,
                     "api_failures": [{"operation": operation, "type": kind, "message": reason}]},
    }
    try:
        path = write_evidence(output_dir, name, target_name, failure)
        logger.info("Evidence saved to %s", path)
    except OSError as exc:
        logger.info("Could not write the failure evidence file: %s", exc)
    report_failure(reason, code)
    return 1
