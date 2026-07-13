"""Welcome / manifest-selector screen — the app's front door.

Lists the available run manifests and lets you pick one to drive the rest of
the session (view / edit / run). Tokyo Night palette + PARAMIFY logo under a
sweeping color-gradient sheen, with an animated verification readout of the
startup checks (repo root, catalog, manifests, uploader): each line types on,
spins, then settles to its answer — the results themselves come from the
discovery the app already ran. Preview it standalone with:

    python -m framework.tui.welcome_demo
"""

from __future__ import annotations

import colorsys
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Container, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import DataTable, Static

from framework import api
from framework.tui import palette
from framework.tui.modals import ConfirmModal, FormModal

# PARAMIFY block logo (from the Go prototype's app.LogoLines()).
LOGO = r"""
 ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗██╗███████╗██╗   ██╗
 ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██║██╔════╝╚██╗ ██╔╝
 ██████╔╝███████║██████╔╝███████║██╔████╔██║██║█████╗   ╚████╔╝
 ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██║██╔══╝    ╚██╔╝
 ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║██║██║        ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝        ╚═╝
""".strip("\n")
LOGO_LINES = LOGO.split("\n")

# Logo sheen — the hue ramps blue→purple across the logo while a bright
# gaussian band sweeps left→right (then off-edge, then again).
_LOGO_W = max(len(line) for line in LOGO_LINES)
_FPS = 30

# Verification readout — animated reveal of the startup checks.
# check states: 1 = ok, -1 = no answer (muted), -2 = failed (red)
_CHECKS = ["repo root", "fetcher catalog", "run manifests", "evidence uploader"]
_REVEAL0 = 0.45   # seconds before the first check line appears
_STAGGER = 0.32   # delay between successive lines
_TYPE_CPS = 70    # label typewriter speed, chars/second
_MIN_SPIN = 0.9   # a line spins at least this long, even though results are in
_COLLAPSE_AFTER = 0.8  # pause on the settled readout before collapsing to one line
_DOTS_TO = 24     # leaders pad the label out to this column
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_DOTS = "#3B4261"      # leader dots, dimmer than SUBTLE
_SPIN_FG = "#9AA5CE"   # spinner glyph

# Sample manifests for the standalone demo — same shape as api.list_manifests().
MOCK_MANIFESTS: List[dict] = [
    {"name": "aws-prod.yaml", "path": "manifests/aws-prod.yaml", "fetcher_count": 12,
     "issues": 0, "runnable": True, "readable": True, "last_run": "2026-06-02", "last_result": "11/12 ok"},
    {"name": "okta-quarterly.yaml", "path": "manifests/okta-quarterly.yaml", "fetcher_count": 8,
     "issues": 2, "runnable": False, "readable": True, "last_run": "2026-05-30", "last_result": "8/8 ok"},
    {"name": "k8s-baseline.yaml", "path": "manifests/k8s-baseline.yaml", "fetcher_count": 3,
     "issues": 0, "runnable": True, "readable": True, "last_run": None, "last_result": None},
    {"name": "gitlab-change-mgmt.yaml", "path": "manifests/gitlab-change-mgmt.yaml", "fetcher_count": 2,
     "issues": 0, "runnable": True, "readable": True, "last_run": "2026-05-27", "last_result": "0/2 ok"},
]


class ManifestSelected(Message):
    """Emitted when a manifest is chosen on the welcome screen (carries its path)."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__()


class WelcomeScreen(Screen):
    CSS = """
    WelcomeScreen { background: #1A1B26; align: center middle; }

    #welcome-root { width: 86; height: auto; }

    /* The logo widget is centered as a block (via Center) — never text-align
       it: per-line centering rstrips each row and shears the artwork. */
    #welcome-logo { width: auto; }
    #welcome-tagline { width: 100%; text-align: center; padding-top: 1; }

    #welcome-checks { width: 100%; height: 6; margin-top: 1; margin-bottom: 1; }

    #welcome-panel {
        width: 86;
        height: auto;
        border: round #565F89;
        border-title-color: #565F89;
        padding: 0 1;
        background: #1A1B26;
    }

    #welcome-manifests {
        height: auto;
        max-height: 12;
        background: #1A1B26;
        color: #C0CAF5;
        margin-top: 1;
    }
    #welcome-manifests > .datatable--header { color: #565F89; background: #1A1B26; text-style: none; }
    #welcome-manifests > .datatable--cursor { background: #283457; text-style: bold; }

    #welcome-hints { width: auto; color: #565F89; padding-top: 1; }
    """

    BINDINGS = [
        Binding("enter", "open", "open"),
        Binding("n", "new", "new"),
        Binding("d", "delete", "delete"),
        Binding("q", "app.quit", "quit"),  # app.* — a bare "quit" resolves in the screen namespace (no-op)
    ]

    def __init__(self, manifests: Optional[List[dict]] = None) -> None:
        super().__init__()
        self._manifests = manifests  # None -> fetched live via api.list_manifests in on_mount
        self.last_selected: Optional[str] = None
        # animation state
        self._t0 = 0.0
        self._check_results: Dict[int, Tuple[int, str]] = {}  # index -> (state, value)
        self._summary_parts: List[str] = []  # the readout collapses to these when all is well
        self._checks_done = False

    def compose(self) -> ComposeResult:
        with Vertical(id="welcome-root"):
            with Center():
                yield Static(LOGO, id="welcome-logo", markup=False)
            yield Static(self._tagline(), id="welcome-tagline")
            yield Static("", id="welcome-checks")
            with Container(id="welcome-panel"):
                yield DataTable(id="welcome-manifests")
            yield Static(self._hints(), id="welcome-hints")

    def on_mount(self) -> None:
        dt = self.query_one("#welcome-manifests", DataTable)
        dt.cursor_type = "row"
        dt.add_columns("manifest", "fetchers", "status", "last run")
        if self._manifests is None:
            self._manifests = api.list_manifests(self.app.root_path)
        for m in self._manifests:
            dt.add_row(
                Text(m["name"], style="#7DCFFF"),
                Text(str(m["fetcher_count"]), style="#BB9AF7", justify="right"),
                self._status_cell(m),
                self._last_run_cell(m),
                key=m["path"],
            )
        self.query_one("#welcome-panel", Container).border_title = self._panel_title()
        dt.focus()
        self._resolve_checks()
        self._t0 = time.monotonic()
        self._tick()
        self.set_interval(1 / _FPS, self._tick)

    # -- logo sheen + verification readout --------------------------------- #

    def _tick(self) -> None:
        t = time.monotonic() - self._t0
        self.query_one("#welcome-logo", Static).update(self._render_logo(t))
        if self._checks_done:
            return
        checks = self.query_one("#welcome-checks", Static)
        settle = _REVEAL0 + _STAGGER * (len(_CHECKS) - 1) + _MIN_SPIN
        if t <= settle + _COLLAPSE_AFTER:
            checks.update(self._render_checks(t))
            return
        self._checks_done = True  # readout is final; stop rebuilding it
        if all(state != -2 for state, _ in self._check_results.values()):
            # all is well -> reclaim the space: one muted summary line. Failures
            # keep the full readout on screen, where the detail matters.
            checks.update(self._summary_line())
            checks.styles.height = 1

    @staticmethod
    def _render_logo(t: float) -> Text:
        """Hue ramps blue→purple across the logo; a bright gaussian sheen band
        sweeps left→right. Consecutive same-color columns coalesce to one span."""
        shim = (t * 0.45) % 1.6 - 0.3  # band center in 0..1 column space
        cols = []
        for x in range(_LOGO_W):
            xn = x / _LOGO_W
            band = math.exp(-((xn - shim) ** 2) / 0.012)
            h = 0.61 + 0.115 * xn + 0.01 * math.sin(t * 1.3)
            s = max(0.52 - 0.24 * band, 0.0)
            v = min(0.70 + 0.30 * band, 1.0)
            r, g, b = colorsys.hsv_to_rgb(h % 1.0, s, v)
            cols.append(f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}")
        text = Text()
        for li, line in enumerate(LOGO_LINES):
            if li:
                text.append("\n")
            start = 0
            for i in range(1, len(line) + 1):
                if i == len(line) or cols[i] != cols[start]:
                    text.append(line[start:i], style=f"{cols[start]} bold")
                    start = i
        return text

    def _resolve_checks(self) -> None:
        """Fill in the verification answers from the discovery the app already
        ran (root/catalog on the app, manifests from this screen's own scan).
        The animation then reveals them on its own schedule."""
        root = getattr(self.app, "root_path", None)
        results: Dict[int, Tuple[int, str]] = {}
        if root is None:
            results[0] = (-2, "✗ not found")
            results[1] = (-1, "—")
            results[3] = (-1, "—")
        else:
            results[0] = (1, f"{Path(root).name}/")
            cat = getattr(self.app, "catalog_data", None)
            if cat:
                results[1] = (
                    1, f"✓ {cat['fetcher_count']} fetchers · {len(cat['categories'])} categories"
                )
            else:
                results[1] = (-2, "✗ load failed")
            uploader = Path(root) / "uploaders" / "paramify_evidence"
            results[3] = (1, "✓ paramify_evidence") if uploader.is_dir() else (-1, "not present")
        n = len(self._manifests or [])
        results[2] = (1, f"✓ {n} discovered") if n else (-1, "none yet")
        self._check_results = results
        cat = getattr(self.app, "catalog_data", None)
        self._summary_parts = [
            f"{cat['fetcher_count']} fetchers" if cat else "catalog unavailable",
            f"{n} manifest{'' if n == 1 else 's'}" if n else "no manifests yet",
            "uploader ready" if results[3][0] == 1 else "no uploader",
        ]

    def _summary_line(self) -> Text:
        text = Text()
        text.append("✓ ", style=palette.OK)
        text.append("workspace ok · " + " · ".join(self._summary_parts), style=palette.MUTED)
        return text

    def _render_checks(self, t: float) -> Text:
        text = Text()
        text.append("verifying your workspace", style=f"{palette.SUBTLE} italic")
        text.append("\n")
        for i, label in enumerate(_CHECKS):
            start = _REVEAL0 + _STAGGER * i
            if t < start:
                break
            text.append("\n  ")
            shown = int((t - start) * _TYPE_CPS)
            text.append(label[:shown], style=palette.SUBTLE)
            if shown < len(label):
                continue
            text.append(" " + "·" * (_DOTS_TO - len(label)) + " ", style=_DOTS)
            if t < start + _MIN_SPIN:
                text.append(_SPINNER[int(t * 12) % len(_SPINNER)], style=_SPIN_FG)
                continue
            state, value = self._check_results[i]
            if state == 1:
                text.append(value, style=palette.OK if value.startswith("✓") else palette.FG)
            elif state == -2:
                text.append(value, style=palette.FAIL)
            else:
                text.append(value, style=palette.MUTED)
        return text

    # -- cells ------------------------------------------------------------ #

    @staticmethod
    def _status_cell(m: dict) -> Text:
        if not m.get("readable", True):
            return Text("✗ unreadable", style="#F7768E")
        issues = m.get("issues")
        if issues is None:
            return Text("· unknown", style="#565F89")
        if issues:
            return Text(f"⚠ {issues} issue{'' if issues == 1 else 's'}", style="#E0AF68")
        return Text("✓ runnable", style="#9ECE6A")

    @staticmethod
    def _relative(ts: str) -> str:
        """Humanize a last-run stamp (run_id format or plain date); raw on mismatch."""
        for fmt in ("%Y-%m-%dT%H-%M-%SZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
            try:
                then = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        else:
            return ts
        seconds = int((datetime.now(timezone.utc) - then).total_seconds())
        if seconds < 60:
            return "just now"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"

    @staticmethod
    def _last_run_cell(m: dict) -> Text:
        if not m.get("last_run"):
            return Text("— never run", style="#565F89")
        result = m.get("last_result") or ""
        style = "#F7768E" if result.startswith("0/") else "#9ECE6A"
        t = Text(f"{WelcomeScreen._relative(m['last_run'])}  ", style="#565F89")
        t.append(result, style=style)
        return t

    def _tagline(self) -> Text:
        t = Text()
        t.append("fetcher", style="#BB9AF7 bold")
        t.append(" — collect compliance evidence from your stack", style="#565F89")
        return t

    def _panel_title(self) -> str:
        return (
            "select a run manifest" if self._manifests
            else "no manifests yet — add one under manifests/ or press n"
        )

    def _hints(self) -> Text:
        parts = [("enter", "open"), ("n", "new"), ("d", "delete"), ("q", "quit")]
        t = Text()
        for i, (key, desc) in enumerate(parts):
            if i:
                t.append("    ")
            t.append(key, style="#BB9AF7 bold")
            t.append(" ")
            t.append(desc, style="#565F89")
        return t

    # -- actions (mock: notify only) ------------------------------------- #

    def _selected(self) -> Optional[str]:
        dt = self.query_one("#welcome-manifests", DataTable)
        if dt.row_count == 0:
            return None
        row_key, _ = dt.coordinate_to_cell_key(dt.cursor_coordinate)
        return row_key.value

    def _open(self, path: Optional[str]) -> None:
        if path:
            self.last_selected = path
            self.post_message(ManifestSelected(path))  # app -> enter workspace

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # Enter on the focused table posts RowSelected (it shadows the screen's
        # enter binding) — open from here.
        self._open(event.row_key.value)

    def action_open(self) -> None:
        self._open(self._selected())

    def action_new(self) -> None:
        if not self.app.root_path:
            self.notify("Cannot create a manifest: repo root not found.", severity="error")
            return

        def done(result: Optional[dict]) -> None:
            name = (result or {}).get("new manifest", {}).get("name")
            if not name:
                return
            try:
                path = api.new_manifest_path(self.app.root_path, name)
            except FileExistsError:
                self.notify(f"{name} already exists.", severity="warning")
                return
            except (ValueError, OSError) as exc:
                self.notify(f"Could not create manifest: {exc}", severity="error")
                return
            self.post_message(ManifestSelected(str(path)))  # open the new one

        self.app.push_screen(
            FormModal(
                "New manifest",
                {"new manifest": [{
                    "key": "name", "label": "file name", "kind": "text",
                    "placeholder": "e.g. aws-prod", "required": True,
                    "help": "created empty under manifests/",
                }]},
                subtitle="Create a manifest and start editing it",
            ),
            done,
        )

    def action_delete(self) -> None:
        path = self._selected()
        if not path:
            return

        def done(ok: bool) -> None:
            if not ok:
                return
            try:
                Path(path).unlink()
            except OSError as exc:
                self.notify(f"Could not delete: {exc}", severity="error")
                return
            self.notify(f"Deleted {Path(path).name}.")
            self._reload_table()

        self.app.push_screen(ConfirmModal(f"Delete '{Path(path).name}' (the file on disk)?"), done)

    def _reload_table(self) -> None:
        self._manifests = api.list_manifests(self.app.root_path)
        dt = self.query_one("#welcome-manifests", DataTable)
        dt.clear()
        for m in self._manifests:
            dt.add_row(
                Text(m["name"], style="#7DCFFF"),
                Text(str(m["fetcher_count"]), style="#BB9AF7", justify="right"),
                self._status_cell(m),
                self._last_run_cell(m),
                key=m["path"],
            )
        self.query_one("#welcome-panel", Container).border_title = self._panel_title()
