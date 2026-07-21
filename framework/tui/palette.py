"""Tokyo Night palette — the single source of color for the TUI.

Matches the Go evidence-tui-prototype's palette (and Textual's built-in
`tokyo-night` theme, which re-skins all the $variable-based CSS). These hex
constants are for the Rich Text styles built in Python (DataTable cells, detail
panes, etc.) which don't resolve Textual CSS $variables. Use the semantic roles
(OK/WARN/FAIL/ACCENT/INFO/MUTED) in screen code so intent stays readable.

Status cells in tables should go through pill()/status_pill() rather than
hand-picked colors, so every screen renders the same pass/warn/fail language.
"""

from rich.style import Style
from rich.text import Text

# raw palette
BG = "#1A1B26"
FG = "#C0CAF5"
SUBTLE = "#565F89"
BLUE = "#7AA2F7"
PURPLE = "#BB9AF7"
CYAN = "#7DCFFF"
GREEN = "#9ECE6A"
YELLOW = "#E0AF68"
RED = "#F7768E"
ORANGE = "#FF9E64"

# semantic roles
ACCENT = PURPLE    # keys, cursors, primary accents
INFO = CYAN       # identifiers, breadcrumb
MUTED = SUBTLE    # dim / secondary text
OK = GREEN
WARN = YELLOW
FAIL = RED

# Pill pairs: readable text on a muted swatch of the same hue. These are the
# text-*/*-muted values Textual derives for tokyo-night, frozen here for the
# same reason as the raw palette above (Rich can't resolve $variables).
OK_TEXT, OK_MUTED = "#BEDE9C", "#41503A"
WARN_TEXT, WARN_MUTED = "#EACA9B", "#554739"
FAIL_TEXT, FAIL_MUTED = "#F9A4B4", "#5C3645"

_TONES = {
    "ok": (OK_TEXT, OK_MUTED),
    "warn": (WARN_TEXT, WARN_MUTED),
    "fail": (FAIL_TEXT, FAIL_MUTED),
}

# Every status word the screens emit, mapped to a tone. None means "recede":
# plain muted text instead of a pill, so pending rows don't compete with results.
STATUS_TONE = {
    "queued": None,
    "running": "warn",
    "ok": "ok",
    "failed": "fail",
    "partial": "warn",
    "timeout": "fail",
    "skipped": "warn",
    "error": "fail",
}


def pill(label: str, tone: str) -> Text:
    """A status pill for table cells. Unknown tones fall back to muted text so
    a new status word can never crash a repaint."""
    spec = _TONES.get(tone)
    if spec is None:
        return Text(label, style=MUTED)
    fg, bg = spec
    return Text(f" {label} ", style=Style(color=fg, bgcolor=bg, bold=True))


def status_pill(status: str) -> Text:
    """The shared renderer for run/entry status cells across all screens."""
    tone = STATUS_TONE.get(status)
    if tone is None:
        return Text(status.upper(), style=MUTED)
    return pill(status.upper(), tone)
