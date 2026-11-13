#!/usr/bin/env python3
"""NIST CMVP validation status for a configured list of cryptographic module certificate numbers."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

NAME = "nist_cmvp_module_validation_status"
VERSION = "0.1.0"
logger = logging.getLogger(NAME)

DEFAULT_BASE_URL = "https://csrc.nist.gov"
CERT_PATH = "/projects/cryptographic-module-validation-program/certificate/{number}"
USER_AGENT = f"paramify-fetchers {NAME}/{VERSION}"
REQUEST_TIMEOUT = 30
RETRIES = 2
RETRY_BACKOFF_SECONDS = 2.0

REASONS = (
    "historical", "revoked", "sunset_passed", "status_unknown", "not_found", "parse_error", "fetch_error",
)
# Reasons that mean the run could not check a certificate, rather than a verdict on it.
COLLECTION_FAILURES = ("parse_error", "fetch_error")
ACCEPTED_STANDARD = re.compile(r"^FIPS\s*140-[23]$", re.IGNORECASE)
US_DATE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})$")
CERT_HEADING = re.compile(r"^Certificate\s*#\s*(\d+)$", re.IGNORECASE)
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}

# Labels in the certificate page's Details panel. Rows are found by label text,
# not by id or class, so a change to the page's styling does not break them.
DETAIL_LABELS = {
    "module name": "module_name",
    "standard": "standard",
    "status": "status",
    "historical reason": "historical_reason",
    "sunset date": "sunset_date",
    "overall level": "overall_level",
    "caveat": "caveat",
    "security level exceptions": "security_level_exceptions",
    "module type": "module_type",
    "embodiment": "embodiment",
}


class ConfigError(Exception):
    pass


# -- a minimal DOM over html.parser ------------------------------------------

VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class Node:
    def __init__(self, tag: str, attrs: Dict[str, str], parent: Optional["Node"]) -> None:
        self.tag, self.attrs, self.parent = tag, attrs, parent
        self.children: List[Any] = []  # Node or str
        self._text: Optional[str] = None

    @property
    def elements(self) -> List["Node"]:
        return [c for c in self.children if isinstance(c, Node)]

    def text(self) -> str:
        """Whitespace-collapsed text, cached: a certificate page nests thousands of algorithm rows."""
        if self._text is None:
            parts = [c if isinstance(c, str) else c.text() for c in self.children if not (
                isinstance(c, Node) and c.tag in ("script", "style"))]
            self._text = " ".join(" ".join(parts).split())
        return self._text

    def walk(self) -> Iterator["Node"]:
        for child in self.elements:
            yield child
            yield from child.walk()

    def ancestors(self) -> Iterator["Node"]:
        node = self.parent
        while node is not None:
            yield node
            node = node.parent


class _TreeBuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("#document", {}, None)
        self.current = self.root

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        node = Node(tag, {k: v or "" for k, v in attrs}, self.current)
        self.current.children.append(node)
        if tag not in VOID_TAGS:
            self.current = node

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.current.children.append(Node(tag, {k: v or "" for k, v in attrs}, self.current))

    def handle_endtag(self, tag: str) -> None:
        # Close back to the nearest open element of this tag; ignore a stray end tag.
        for node in [self.current, *self.current.ancestors()]:
            if node.tag == tag:
                self.current = node.parent or self.root
                return

    def handle_data(self, data: str) -> None:
        self.current.children.append(data)


def parse_html(html: str) -> Node:
    builder = _TreeBuilder()
    builder.feed(html)
    builder.close()
    return builder.root


# -- certificate page ----------------------------------------------------------

def _label(text: str) -> str:
    return text.strip().rstrip(":").strip().lower()


def _section(root: Node, title: str, has_content) -> Optional[Node]:
    """The container of the section headed `title`: the nearest ancestor of the heading that holds its content."""
    for heading in root.walk():
        if heading.tag in HEADINGS and _label(heading.text()) == title.lower():
            for ancestor in heading.ancestors():
                if has_content(ancestor):
                    return ancestor
    return None


def _label_rows(container: Node) -> Dict[str, Node]:
    """Known label -> its value element: any element whose text is a label, followed by a sibling element."""
    rows: Dict[str, Node] = {}
    for node in [container, *container.walk()]:
        siblings = node.elements
        for i, cell in enumerate(siblings[:-1]):
            key = DETAIL_LABELS.get(_label(cell.text()))
            if key and key not in rows:
                rows[key] = siblings[i + 1]
    return rows


def us_date_to_iso(value: Optional[str]) -> Optional[str]:
    match = US_DATE.match((value or "").strip())
    if not match:
        return None
    month, day, year = (int(g) for g in match.groups())
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return None


def parse_certificate_page(html: str) -> Dict[str, Any]:
    """The page's certificate number, Details rows, vendor and validation history. Empty fields are None."""
    root = parse_html(html)
    heading = next(
        (m for n in root.walk() if n.tag in HEADINGS and (m := CERT_HEADING.match(n.text()))), None
    )
    details = _section(root, "Details", lambda n: bool({"status", "module_name"} & set(_label_rows(n))))
    rows = _label_rows(details) if details else {}
    page: Dict[str, Any] = {
        "page_certificate_number": int(heading.group(1)) if heading else None,
        "has_details": details is not None,
    }
    for key in DETAIL_LABELS.values():
        cell = rows.get(key)
        if key == "security_level_exceptions":
            items = [li.text() for li in cell.walk() if li.tag == "li"] if cell else []
            page[key] = [i for i in items if i] or ([cell.text()] if cell and cell.text() else [])
        else:
            page[key] = (cell.text() or None) if cell else None

    vendor = _section(root, "Vendor", lambda n: any(a.tag == "a" for a in n.walk()))
    link = next((a for a in vendor.walk() if a.tag == "a"), None) if vendor else None
    page["vendor"] = (link.text() or None) if link else None

    history_box = _section(root, "Validation History", lambda n: any(t.tag == "table" for t in n.walk()))
    history = []
    if history_box:
        for tr in (n for n in history_box.walk() if n.tag == "tr"):
            cells = [c.text() for c in tr.elements if c.tag == "td"]
            if len(cells) >= 3 and any(cells):
                history.append({"date": us_date_to_iso(cells[0]) or cells[0] or None,
                                "type": cells[1] or None, "lab": cells[2] or None})
    page["validation_history"] = history
    return page


def verdict(number: int, page: Dict[str, Any], today: date) -> Tuple[Optional[str], str]:
    """(reason, detail); reason is None when the certificate is currently validated."""
    if not page["has_details"]:
        if page["page_certificate_number"] == number:
            return "parse_error", "the page names the certificate but has no Details rows"
        return "not_found", "the page has no Details section for a certificate"
    if page["page_certificate_number"] is None:
        return "parse_error", "the page does not name its certificate number"
    if page["page_certificate_number"] != number:
        return "not_found", f"the page is for certificate {page['page_certificate_number']}"
    status = (page["status"] or "").strip().lower()
    if status == "revoked":
        return "revoked", "Status is Revoked"
    if status == "historical":
        return "historical", "Status is Historical"
    if status != "active":
        return "status_unknown", f"Status is {page['status']!r}, not Active"
    if not page["standard"]:
        return "parse_error", "the page shows no Standard"
    if not ACCEPTED_STANDARD.match(page["standard"]):
        return "status_unknown", f"Standard is {page['standard']!r}, not FIPS 140-2 or FIPS 140-3"
    sunset = us_date_to_iso(page["sunset_date"])
    if sunset is None:
        return "parse_error", f"Sunset Date {page['sunset_date']!r} is not a M/D/YYYY date"
    if date.fromisoformat(sunset) < today:
        return "sunset_passed", f"Status is Active but the sunset date {sunset} is before {today.isoformat()}"
    return None, f"Active {page['standard']} certificate, sunset {sunset}"


# -- collection ----------------------------------------------------------------

def parse_certificates(raw: str) -> List[Tuple[Optional[str], int]]:
    """'AWS-LC=4816, #4282' -> [('AWS-LC', 4816), (None, 4282)]."""
    entries: List[Tuple[Optional[str], int]] = []
    for chunk in re.split(r"[,;\n]", raw or ""):
        chunk = chunk.strip()
        if not chunk:
            continue
        label, _, number = chunk.rpartition("=")
        number = number.strip().lstrip("#").strip()
        if not number.isdigit():
            raise ConfigError(f"NIST_CMVP_CERTIFICATES: {chunk!r} is not a certificate number or 'Label=NUMBER'")
        entries.append((label.strip() or None, int(number)))
    if not entries:
        raise ConfigError("NIST_CMVP_CERTIFICATES is empty: list certificate numbers as '4816, 4282'")
    return entries


def fetch_page(session: requests.Session, url: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """(http_status, body, error). Retries timeouts, connection errors and 5xx; one request at a time."""
    error = None
    for attempt in range(RETRIES + 1):
        if attempt:
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            error = f"GET {url} failed: {type(exc).__name__}: {exc}"
            continue
        if response.status_code >= 500:
            error = f"GET {url} returned HTTP {response.status_code}"
            continue
        if response.status_code in (200, 404, 410):
            return response.status_code, response.text, None
        return response.status_code, None, f"GET {url} returned HTTP {response.status_code}"
    return None, None, error


def check_certificate(
    session: requests.Session, base_url: str, label: Optional[str], number: int, today: date
) -> Dict[str, Any]:
    url = base_url + CERT_PATH.format(number=number)
    record: Dict[str, Any] = {"certificate_number": number, "label": label, "url": url}
    status, body, error = fetch_page(session, url)
    record["http_status"] = status
    page: Dict[str, Any] = {}
    reason: Optional[str]
    if error:
        reason, detail = "fetch_error", error
    elif status != 200:
        reason, detail = "not_found", f"HTTP {status}"
    else:
        try:
            page = parse_certificate_page(body or "")
            reason, detail = verdict(number, page, today)
        except Exception as exc:  # noqa: BLE001 - one unreadable page must not stop the others
            reason, detail = "parse_error", f"{type(exc).__name__}: {exc}"
    history = page.get("validation_history") or []
    record.update({
        "validated": reason is None,
        "reason": reason,
        "reason_detail": detail,
        "module_name": page.get("module_name"),
        "vendor": page.get("vendor"),
        "standard": page.get("standard"),
        "status": page.get("status"),
        "historical_reason": page.get("historical_reason"),
        "sunset_date": us_date_to_iso(page.get("sunset_date")),
        "overall_level": page.get("overall_level"),
        "module_type": page.get("module_type"),
        "embodiment": page.get("embodiment"),
        "caveat": page.get("caveat"),
        "security_level_exceptions": page.get("security_level_exceptions") or [],
        "validation_dates": [h["date"] for h in history if h["date"]],
        "validation_history": history,
    })
    return record


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    validated = sum(1 for r in records if r["validated"])
    return {
        "certificates_total": len(records),
        "certificates_validated": validated,
        "certificates_not_validated": len(records) - validated,
        "not_validated_by_reason": {reason: sum(1 for r in records if r["reason"] == reason) for reason in REASONS},
    }


def collect(entries: List[Tuple[Optional[str], int]], base_url: str, now: datetime) -> Tuple[Dict[str, Any], List[str]]:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html"})
    records = [check_certificate(session, base_url, label, number, now.date()) for label, number in entries]
    failures = [f"certificate {r['certificate_number']}: {r['reason_detail']}"
                for r in records if r["reason"] in COLLECTION_FAILURES]
    # summary comes before the records: a validator reads the first match of each count.
    evidence: Dict[str, Any] = {
        "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base_url": base_url,
        "run_date": now.date().isoformat(),
        "summary": summarize(records),
        "certificates": records,
    }
    if failures:
        evidence["metadata"] = {
            "partial_failure": True,
            "api_failures": [
                {"operation": f"read CMVP certificate {r['certificate_number']}", "type": r["reason"],
                 "message": r["reason_detail"]}
                for r in records if r["reason"] in COLLECTION_FAILURES
            ],
        }
    return evidence, failures


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{NAME}.json"
    now = datetime.now(timezone.utc)
    base_url = (os.environ.get("NIST_CMVP_BASE_URL") or DEFAULT_BASE_URL).strip().rstrip("/")

    try:
        entries = parse_certificates(os.environ.get("NIST_CMVP_CERTIFICATES", ""))
    except ConfigError as exc:
        evidence = {
            "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "base_url": base_url,
            "certificates": [],
            "metadata": {"partial_failure": True,
                         "api_failures": [{"operation": "read config", "type": "bad_config", "message": str(exc)}]},
        }
        output_path.write_text(json.dumps(evidence, indent=2))
        report_failure(str(exc), "bad_config")
        return 1

    evidence, failures = collect(entries, base_url, now)
    output_path.write_text(json.dumps(evidence, indent=2))
    logger.info("Evidence saved to %s", output_path)
    if failures:
        code = "target_unreachable" if len(failures) == len(entries) else "partial_failure"
        report_failure(f"{len(failures)} of {len(entries)} certificates could not be checked: " + "; ".join(failures), code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
