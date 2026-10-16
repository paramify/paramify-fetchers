#!/usr/bin/env python3
"""The public articles in one Zendesk Help Center section, read anonymously, as evidence."""

import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402
from html_text import find_last_updated, html_to_text  # noqa: E402

NAME = "zendesk_help_center_section"
VERSION = "0.1.0"
logger = logging.getLogger(NAME)

REQUEST_TIMEOUT = 30
MAX_REDIRECTS = 5
PER_PAGE = 100
MAX_PAGES = 100
USER_AGENT = f"paramify-fetchers {NAME}/{VERSION}"
HTTP_CODES = {401: "auth_failed", 403: "not_authorized", 429: "rate_limited"}
SECTION_PATH = re.compile(r"^/hc/(?P<locale>[A-Za-z]{2,3}(?:-[A-Za-z0-9]+)*)/sections/(?P<id>\d+)")
SIGN_IN = re.compile(r"/signin|/access/", re.IGNORECASE)

ARTICLE_FIELDS = ["id", "title", "html_url", "created_at", "updated_at", "edited_at", "draft", "promoted",
                  "position", "label_names", "locale", "outdated", "author_id", "section_id", "user_segment_id"]
SECTION_FIELDS = ["id", "name", "html_url", "updated_at"]

# Paramify-specific keyword heuristics for a Secure Configuration Guide; see evidence_set.instructions.
ADMIN = re.compile(r"\badmin(?:istrator)?s?\b|\btop[- ]level\b", re.IGNORECASE)
TOP_LEVEL_ADMIN = re.compile(r"\btop[- ]level\s+(?:admin(?:istrator)?s?|account)", re.IGNORECASE)
SCG_TERMS = {
    "access": re.compile(r"\baccess", re.IGNORECASE),
    "configure": re.compile(r"\bconfigur", re.IGNORECASE),
    "operate": re.compile(r"\boperat", re.IGNORECASE),
    "decommission": re.compile(r"\bdecommission", re.IGNORECASE),
}

FAILURE_FIELDS: Dict[str, Any] = {
    "section": None, "article_count": None, "reported_count": None, "articles_updated_max": None,
    "articles_updated_min": None, "days_since_last_update": None, "all_articles_public": None,
    "public_page_challenges": None, "all_user_segments_everyone": None,
    "mentions_top_level_admin": None, "scg_terms": None, "articles": [],
}


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


def resolve_section(section_url: str, base_url: str, locale: str) -> Tuple[str, str, str]:
    """(origin, locale, section id) from a section URL, or from a bare id plus base_url."""
    if section_url.isdigit():
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CollectionError(
                "ZENDESK_SECTION_URL is a bare section id, so ZENDESK_BASE_URL must be an http(s) URL; "
                f"got {base_url!r}", "bad_url", "bad_config")
        return f"{parsed.scheme}://{parsed.netloc}", locale or "en-us", section_url
    parsed = urlparse(section_url)
    match = SECTION_PATH.match(parsed.path)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not match:
        raise CollectionError(
            "ZENDESK_SECTION_URL is not a Help Center section URL (https://<host>/hc/<locale>/sections/<id>…) "
            f"or a bare section id: {section_url!r}", "bad_url", "bad_config")
    return f"{parsed.scheme}://{parsed.netloc}", match.group("locale").lower(), match.group("id")


def _session() -> requests.Session:
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    session.headers["User-Agent"] = USER_AGENT
    return session


def get_json(session: requests.Session, url: str, verify_ssl: bool) -> Dict[str, Any]:
    try:
        response = session.get(url, headers={"Accept": "application/json"}, timeout=REQUEST_TIMEOUT, verify=verify_ssl)
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


def list_articles(session: requests.Session, url: str, origin: str, verify_ssl: bool) -> Tuple[List[Dict], int]:
    """Every page via next_page. Fails unless the collected count equals the API's own `count`."""
    articles: List[Dict[str, Any]] = []
    reported: Optional[int] = None
    seen = set()
    next_url: Optional[str] = url
    while next_url:
        if next_url in seen or len(seen) >= MAX_PAGES:
            raise CollectionError(f"pagination did not end after {len(seen)} page(s) at {next_url}", "pagination")
        if not next_url.startswith(origin + "/"):
            raise CollectionError(f"next_page points off the help center: {next_url!r}", "pagination")
        seen.add(next_url)
        page = get_json(session, next_url, verify_ssl)
        if not isinstance(page.get("articles"), list) or not isinstance(page.get("count"), int):
            raise CollectionError(f"GET {next_url} has no `articles` list and integer `count`", "unexpected_shape")
        articles += page["articles"]
        reported = page["count"]
        next_url = page.get("next_page")
    if reported is None or len(articles) != reported:
        raise CollectionError(
            f"collected {len(articles)} article(s) but the API reported count={reported}", "count_mismatch")
    return articles, reported


def public_page_status(session: requests.Session, url: Any, verify_ssl: bool) -> Dict[str, Any]:
    status: Dict[str, Any] = {"http_status": 0, "final_url": None, "redirected_to_signin": None,
                              "bot_challenge": None, "error": None}
    if not isinstance(url, str) or urlparse(url).scheme not in {"http", "https"}:
        status["error"] = {"type": "bad_url", "message": f"html_url is not an http(s) URL: {url!r}"}
        return status
    try:
        with session.get(url, headers={"Accept": "text/html"}, timeout=REQUEST_TIMEOUT, verify=verify_ssl,
                         stream=True) as response:
            status.update(http_status=response.status_code, final_url=response.url)
            status["redirected_to_signin"] = bool(SIGN_IN.search(urlparse(response.url).path))
            # Measured on support.paramify.com: Cloudflare answers every non-browser client 403 with this header.
            status["bot_challenge"] = response.headers.get("cf-mitigated", "").lower() == "challenge"
    except requests.exceptions.RequestException as exc:
        status["error"] = {"type": "network_error", "message": f"GET {url} failed: {type(exc).__name__}: {exc}"}
    return status


def article_record(session: requests.Session, article: Dict[str, Any], verify_ssl: bool) -> Dict[str, Any]:
    body = article.get("body") or ""
    text, _ = html_to_text(body) if body else ("", None)
    return {
        **{field: article.get(field) for field in ARTICLE_FIELDS},
        "public_page_status": public_page_status(session, article.get("html_url"), verify_ssl),
        "last_updated": find_last_updated(text),
        "text_length": len(text),
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "body": article.get("body"),
        "text": text,
    }


def _all_public(statuses: List[Dict[str, Any]]) -> Optional[bool]:
    """False if any page is plainly not public; None if a bot challenge left any unverified."""
    if not statuses:
        return None
    if any(s["redirected_to_signin"] or (s["http_status"] != 200 and not s["bot_challenge"]) for s in statuses):
        return False
    return None if any(s["bot_challenge"] for s in statuses) else True


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def collect(record: Dict[str, Any], origin: str, locale: str, section_id: str, verify_ssl: bool) -> Dict[str, Any]:
    session = _session()
    base = f"{origin}/api/v2/help_center/{locale}/sections/{section_id}"
    section = get_json(session, f"{base}.json", verify_ssl).get("section")
    if not isinstance(section, dict):
        raise CollectionError(f"GET {base}.json has no `section` object", "unexpected_shape")
    raw_articles, reported = list_articles(session, f"{base}/articles.json?per_page={PER_PAGE}", origin, verify_ssl)
    articles = [article_record(session, a, verify_ssl) for a in raw_articles]

    dated = sorted(a["updated_at"] for a in articles if _parse_time(a["updated_at"]))
    newest = _parse_time(dated[-1]) if dated else None
    collected = _parse_time(record["collected_at"])
    texts = [a["text"] for a in articles]
    with_admin = [t for t in texts if ADMIN.search(t)]
    return {
        **record,
        "section": {field: section.get(field) for field in SECTION_FIELDS},
        "article_count": len(articles),
        "reported_count": reported,
        "articles_updated_max": dated[-1] if dated else None,
        "articles_updated_min": dated[0] if dated else None,
        "days_since_last_update": int((collected - newest).total_seconds() // 86400) if newest else None,
        "all_articles_public": _all_public([a["public_page_status"] for a in articles]),
        "public_page_challenges": sum(bool(a["public_page_status"]["bot_challenge"]) for a in articles),
        "all_user_segments_everyone": all(a["user_segment_id"] is None for a in articles) if articles else None,
        "mentions_top_level_admin": any(TOP_LEVEL_ADMIN.search(t) for t in texts),
        "scg_terms": {term: any(pattern.search(t) for t in with_admin) for term, pattern in SCG_TERMS.items()},
        "articles": articles,
    }


def write_evidence(output_dir: Path, target_name: str, evidence: Dict[str, Any]) -> Path:
    path = output_dir / f"{NAME}_{re.sub(r'[^A-Za-z0-9_-]', '_', target_name)}.json"
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, ensure_ascii=False)
    return path


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    target_name = env("ZENDESK_TARGET_NAME") or "section"
    record: Dict[str, Any] = {
        "collected_at": current_timestamp(),
        "target_name": target_name,
        "section_url": env("ZENDESK_SECTION_URL"),
        "help_center": None,
        "locale": None,
        "anonymous": True,
    }
    try:
        for required in ("ZENDESK_TARGET_NAME", "ZENDESK_SECTION_URL"):
            if not env(required):
                raise CollectionError(f"Missing required env var: {required}", "missing_config", "bad_config")
        origin, locale, section_id = resolve_section(env("ZENDESK_SECTION_URL"), env("ZENDESK_BASE_URL"),
                                                     env("ZENDESK_LOCALE"))
        record.update(help_center=origin, locale=locale)
        verify_ssl = env("ZENDESK_VERIFY_SSL").lower() not in {"0", "false", "no", "off"}
        path = write_evidence(output_dir, target_name, collect(record, origin, locale, section_id, verify_ssl))
    except CollectionError as exc:
        reason, kind, code = str(exc), exc.kind, exc.code
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still reportable
        reason, kind, code = f"Unexpected error: {type(exc).__name__}: {exc}", "internal_error", "internal_error"
    else:
        logger.info("Evidence saved to %s", path)
        return 0

    failure = {
        **record, **FAILURE_FIELDS,
        "metadata": {"partial_failure": True,
                     "api_failures": [{"operation": f"list section {record['section_url']}", "type": kind,
                                       "message": reason}]},
    }
    try:
        path = write_evidence(output_dir, target_name, failure)
        logger.info("Evidence saved to %s", path)
    except OSError as exc:
        logger.info("Could not write the failure evidence file: %s", exc)
    report_failure(reason, code)
    return 1


if __name__ == "__main__":
    sys.exit(main())
