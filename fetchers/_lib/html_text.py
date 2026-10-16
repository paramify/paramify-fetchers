"""HTML to readable text, and a best-effort "Last updated" date, for any fetcher. Stdlib only.

Import it the same way as fetcher_status:

    sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
    from html_text import html_to_text, find_last_updated   # noqa: E402
"""

import re
from html.parser import HTMLParser
from typing import Any, List, Optional, Tuple

__all__ = ["html_to_text", "find_last_updated"]

SKIPPED_TAGS = {"script", "style", "noscript", "template", "svg", "head"}
BLOCK_TAGS = {
    "address", "article", "aside", "blockquote", "body", "br", "caption", "dd",
    "details", "dialog", "div", "dl", "dt", "fieldset", "figcaption", "figure",
    "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "html",
    "legend", "li", "main", "nav", "ol", "p", "pre", "section", "summary",
    "table", "tbody", "tfoot", "thead", "tr", "ul",
}
CELL_TAGS = {"td", "th"}

_MONTH = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|"
    r"Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?"
)
_DATE = (
    rf"{_MONTH}\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?\s+{_MONTH},?\s+\d{{4}}"
    r"|\d{4}-\d{2}-\d{2}"
    r"|\d{1,2}/\d{1,2}/\d{2,4}"
    rf"|{_MONTH}\s+\d{{4}}"
)
_LABEL = r"\b(?:Last\s+(?:updated|modified|revised)|Effective\s+(?:date|as\s+of)|Updated)\b(?:\s+on)?\s*[:\-–—]?\s*"
LAST_UPDATED = re.compile(rf"{_LABEL}(?P<date>{_DATE})\b", re.IGNORECASE)
# The label alone on its line, with the date as the next line (two block elements).
LABEL_ONLY = re.compile(rf"^\s*{_LABEL}$", re.IGNORECASE)
DATE_FIRST = re.compile(rf"^\s*(?P<date>{_DATE})\b", re.IGNORECASE)


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.skipping: List[str] = []
        self.title_parts: Optional[List[str]] = None
        self.title: Optional[str] = None
        self.pre_depth = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag == "body" and "head" in self.skipping:
            # A <head> left open is closed by <body>, as a browser does.
            self.skipping = [t for t in self.skipping if t != "head"]
        if tag in SKIPPED_TAGS:
            self.skipping.append(tag)
        elif tag == "title" and self.title is None and "svg" not in self.skipping:
            self.title_parts = []
        elif tag == "pre":
            self.pre_depth += 1
        self._separate(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.skipping:
            while self.skipping and self.skipping.pop() != tag:
                pass
        elif tag == "title" and self.title_parts is not None:
            self.title = " ".join("".join(self.title_parts).split()) or None
            self.title_parts = None
        elif tag == "pre" and self.pre_depth:
            self.pre_depth -= 1
        self._separate(tag)

    def handle_data(self, data: str) -> None:
        if self.title_parts is not None:
            self.title_parts.append(data)
        elif not self.skipping:
            self.parts.append(data if self.pre_depth else data.replace("\r", " ").replace("\n", " "))

    def _separate(self, tag: str) -> None:
        if tag in BLOCK_TAGS:
            self.parts.append("\n")
        elif tag in CELL_TAGS:
            self.parts.append(" ")


def html_to_text(markup: str) -> Tuple[str, Optional[str]]:
    """(visible text, title). One line per block; whitespace within a line collapsed."""
    parser = _TextExtractor()
    parser.feed(markup)
    parser.close()
    lines = (" ".join(line.split()) for line in "".join(parser.parts).replace("\r\n", "\n").split("\n"))
    return "\n".join(line for line in lines if line), parser.title


def find_last_updated(text: str) -> Optional[str]:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        match = LAST_UPDATED.search(line)
        if match is None and LABEL_ONLY.match(line) and i + 1 < len(lines):
            match = DATE_FIRST.match(lines[i + 1])
        if match:
            return match.group("date")
    return None
