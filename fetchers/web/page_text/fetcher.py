#!/usr/bin/env python3
"""The text one public web page served, as evidence."""

import hashlib
import sys
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
import web_page  # noqa: E402

NAME = "web_page_text"
VERSION = "0.1.0"

FAILURE_FIELDS = {
    "title": None, "last_updated": None, "text_length": 0, "sha256": None, "text_sha256": None, "text": None,
}


def collect(url: str, verify_ssl: bool, record: Dict[str, Any]) -> Dict[str, Any]:
    body, content_type = web_page.fetch(url, verify_ssl, record, f"paramify-fetchers {NAME}/{VERSION}")
    page = web_page.read_content(body, content_type, url)
    evidence = {
        **record,
        "title": page.title,
        "last_updated": web_page.find_last_updated(page.text),
        "text_length": len(page.text),
        "sha256": hashlib.sha256(body).hexdigest(),
        "text_sha256": hashlib.sha256(page.text.encode("utf-8")).hexdigest(),
    }
    if page.is_json:
        evidence["json"] = page.document
    evidence["text"] = page.text
    return evidence


if __name__ == "__main__":
    sys.exit(web_page.run(NAME, collect, FAILURE_FIELDS))
