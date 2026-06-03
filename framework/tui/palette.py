"""Tokyo Night palette — the single source of color for the TUI.

Matches the Go evidence-tui-prototype's palette (and Textual's built-in
`tokyo-night` theme, which re-skins all the $variable-based CSS). These hex
constants are for the Rich Text styles built in Python (DataTable cells, detail
panes, etc.) which don't resolve Textual CSS $variables. Use the semantic roles
(OK/WARN/FAIL/ACCENT/INFO/MUTED) in screen code so intent stays readable.
"""

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
INFO = CYAN        # identifiers, breadcrumb
MUTED = SUBTLE     # dim / secondary text
OK = GREEN
WARN = YELLOW
FAIL = RED
