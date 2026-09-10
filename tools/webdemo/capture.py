"""Capture the real TUI as a clickable web demo.

Runs the actual FetcherApp headless (Textual's `run_test` pilot) against the
synthetic workspace in fixture.py, grabs the composited screen at each point of
a scripted storyboard, and writes a single self-contained HTML page that
replays those frames — clickable tabs, arrow keys, a streaming run.

Every pixel comes from the app itself, so the demo cannot drift from the TUI's
real look: re-run this after a UI change and the page is current.

    python -m tools.webdemo.capture            # -> tools/webdemo/dist/demo.html
    python -m tools.webdemo.capture --out X.html

Design notes
------------
Frames are the composited character grid, not screenshots: each is a list of
(style-index, text) runs against one global style table, which is small enough
that a ~70-frame demo including animation stays well under a megabyte.

The two animated scenes are driven deterministically rather than by wall clock —
the welcome screen's logo sheen by rewinding its `_t0`, the run console by
feeding api.run's event dicts straight into RunPage._handle_event (which the run
module keeps worker-free precisely so synthetic events can drive it).
"""

from __future__ import annotations

import argparse
import asyncio
import io
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from framework import api  # noqa: E402
from framework.tui import app as app_module  # noqa: E402
from framework.tui.components import chrome  # noqa: E402
from tools.webdemo import fixture  # noqa: E402

WIDTH, HEIGHT = 160, 42

# The header clock is a live 1s timer. Left alone it changes between frames and
# makes every animated sequence flicker; freeze it at a plausible moment.
FROZEN_NOW = datetime(2026, 9, 2, 9, 14, 5)

# Obviously-fake credentials. The demo manifests name these as ${env:...} refs,
# and validate() checks the vars are present — without them every manifest
# reports issues and the welcome picker never shows a runnable one.
DEMO_ENV = {
    "AWS_ACCESS_KEY_ID": "ASIAEXAMPLEDEMOKEY01",
    "AWS_SECRET_ACCESS_KEY": "demo-secret-access-key-not-real",
    "AWS_SESSION_TOKEN": "demo-session-token-not-real",
    "OKTA_API_TOKEN": "00demo-okta-token-not-real",
    "OKTA_ORG_URL": "https://acme.okta.com",
    # Pinned so the Paramify tab renders the same regardless of what the
    # operator running the capture happens to have exported. upload_preflight
    # makes no API calls, so nothing is ever sent with these.
    "PARAMIFY_UPLOAD_API_TOKEN": "demo-upload-token-not-real",
    "PARAMIFY_API_TOKEN": "demo-read-token-not-real",
    "PARAMIFY_BASE_URL": "https://app.paramify.com/api/v0",
}


# ── frame grabbing ───────────────────────────────────────────────────────── #

class Frames:
    """Collects composited frames against a shared style table."""

    def __init__(self) -> None:
        self.styles: list[list] = []
        self._style_index: dict[tuple, int] = {}
        self.frames: list[list] = []
        self.texts: list[list[str]] = []  # plain-text grid per frame, for hotspots
        self.bg = "#1a1b26"  # replaced by drop_screen_background()

    def _style_id(self, style) -> int:
        if style is None:
            key: tuple = ("", "", 0)
        else:
            fg = style.color.get_truecolor().hex if style.color else ""
            bg = style.bgcolor.get_truecolor().hex if style.bgcolor else ""
            flags = (
                (1 if style.bold else 0)
                | (2 if style.italic else 0)
                | (4 if style.underline else 0)
                | (8 if style.dim else 0)
                | (16 if style.strike else 0)
                | (32 if style.reverse else 0)
            )
            key = (fg, bg, flags)
        if key not in self._style_index:
            self._style_index[key] = len(self.styles)
            self.styles.append(list(key))
        return self._style_index[key]

    def grab(self, app) -> int:
        """Composite the app's current screen into a frame; return its index."""
        console = Console(
            width=WIDTH, height=HEIGHT, file=io.StringIO(), force_terminal=True,
            color_system="truecolor", record=True, legacy_windows=False, safe_box=False,
        )
        console.print(app.screen._compositor.render_update(
            full=True, screen_stack=app._background_screens, simplify=True,
        ))

        lines: list[list] = [[]]
        for segment in console._record_buffer:
            if segment.control:
                continue
            style_id = self._style_id(segment.style)
            for i, part in enumerate(segment.text.split("\n")):
                if i:
                    lines.append([])
                if part:
                    row = lines[-1]
                    # Merge with the previous run when the style repeats — the
                    # compositor emits many adjacent same-style segments.
                    if row and row[-1][0] == style_id:
                        row[-1][1] += part
                    else:
                        row.append([style_id, part])
        while len(lines) > HEIGHT:
            lines.pop()

        self.frames.append(lines)
        self.texts.append(["".join(run[1] for run in line) for line in lines])
        return len(self.frames) - 1

    def drop_screen_background(self) -> None:
        """Stop painting the screen's own background on individual cells.

        The compositor gives every cell a background, and at a terminal-tight
        line height each row's background box overlaps the row above — hiding
        its descenders, which eats the underscore in every fetcher name. The
        screen background belongs on the container instead, so the overwhelming
        majority of cells paint no background at all and nothing is covered.
        Whatever background covers the most cells IS the screen background, so
        this keeps working if the TUI's theme changes.
        """
        weight: dict[str, int] = {}
        for frame in self.frames:
            for line in frame:
                for style_id, text in line:
                    bg = self.styles[style_id][1]
                    if bg:
                        weight[bg] = weight.get(bg, 0) + len(text)
        if not weight:
            return
        self.bg = max(weight, key=weight.__getitem__)
        for style in self.styles:
            if style[1] == self.bg:
                style[1] = ""


# ── hotspot resolution ───────────────────────────────────────────────────── #

def find_rect(text_grid: list[str], needle: str, occurrence: int = 0,
              pad: tuple[int, int, int, int] | str = (0, 0, 0, 0),
              only_row: int | None = None) -> list[int] | None:
    """Locate `needle` in the rendered grid as [row, col, width, height].

    pad is (top, right, bottom, left) in cells for an explicit box, or the
    string "row" to widen the hit to the panel borders (the `│` on either side)
    — which is what makes a table row clickable across its whole width without
    hard-coding column arithmetic that a layout change would silently break.

    only_row restricts the search to one line, so a label that also appears
    elsewhere on screen ("Run" in both the tab bar and the ▶ Run button) can be
    pinned to the one that is meant.
    """
    rows = range(len(text_grid)) if only_row is None else [only_row]
    hits = 0
    for row in rows:
        line = text_grid[row]
        start = 0
        while True:
            col = line.find(needle, start)
            if col < 0:
                break
            if hits == occurrence:
                if pad == "row":
                    left_border = line.rfind("\u2502", 0, col)
                    right_border = line.find("\u2502", col)
                    x0 = left_border + 1 if left_border >= 0 else 0
                    x1 = right_border if right_border >= 0 else len(line)
                    return [row, x0, max(1, x1 - x0), 1]
                top, right, bottom, left = pad
                return [row - top, col - left,
                        len(needle) + left + right, 1 + top + bottom]
            hits += 1
            start = col + 1
    return None


# ── the scripted run ─────────────────────────────────────────────────────── #

def run_events(entries: list[dict], run_id: str) -> list[dict]:
    """The event stream a real aws-prod run emits, rebuilt from the manifest.

    Shapes match api.run() exactly (run_start / fetcher_start / log_line /
    fetcher_result / run_complete) — RunPage can't tell these from the real thing.
    """
    run_dir = f"/Users/acme/evidence/run-{run_id}"
    events: list[dict] = [{
        "event": "run_start", "run_id": run_id, "run_dir": run_dir,
        "fetchers": [e["use"] for e in entries],
    }]
    clock = 5.0
    for entry in entries:
        use = entry["use"]
        targets = entry.get("targets") or [None]
        events.append({"event": "fetcher_start", "fetcher": use,
                       "targets": len(targets), "fanout": True})
        events.append({"event": "log_line", "fetcher": use,
                       "line": f"2026-09-02 09:14:{int(clock) % 60:02d} INFO {use} "
                               f"Resolving caller identity"})
        for target in targets:
            clock += 2.4
            failed = use == "aws_guard_duty"
            if failed:
                events.append({"event": "log_line", "fetcher": use,
                               "line": f"2026-09-02 09:14:{int(clock) % 60:02d} ERROR {use} "
                                       "guardduty list-detectors returned no detectors "
                                       "for us-gov-east-1"})
            else:
                events.append({"event": "log_line", "fetcher": use,
                               "line": f"2026-09-02 09:14:{int(clock) % 60:02d} INFO {use} "
                                       f"Evidence saved to {fixture._out(use, (target or {}).get('profile'))}"})
            events.append({
                "event": "fetcher_result", "fetcher": use,
                "exit_code": 1 if failed else 0,
                "duration_sec": round(1.8 + (len(use) % 5) * 0.6, 2),
                "target": target,
                "outputs": [] if failed else [fixture._out(use, (target or {}).get("profile"))],
            })
    events.append({"event": "run_complete", "run_id": run_id, "run_dir": run_dir,
                   "metadata_path": f"{run_dir}/_run_metadata.json", "ok": False})
    return events


# ── storyboard ───────────────────────────────────────────────────────────── #

# Welcome-screen timeline. The readout reveals four checks on a stagger and
# settles at ~2.3s, then collapses to one summary line at ~3.1s; the logo sheen
# has a 3.56s period, so the tail frames below span exactly one period and loop
# seamlessly.
INTRO_TIMES = [0.05, 0.35, 0.60, 0.85, 1.10, 1.35, 1.60, 1.90, 2.20, 2.45, 2.80]
SHEEN_PERIOD = 1.6 / 0.45
LOOP_FRAMES = 24
LOOP_TIMES = [3.30 + SHEEN_PERIOD * i / LOOP_FRAMES for i in range(LOOP_FRAMES)]


async def storyboard(app, pilot, frames: Frames) -> dict[str, Any]:
    """Drive the app through the demo and return the scene graph."""
    from framework.tui.screens.evidence import EvidencePage
    from framework.tui.screens.manifest import ManifestPage
    from framework.tui.screens.run import RunPage
    from framework.tui.screens.welcome import WelcomeScreen

    scenes: dict[str, Any] = {}

    def scene(name: str, ids: list[int], **kw) -> None:
        scenes[name] = {"frames": ids, **kw}

    def gaps(times: list[float], tail: float) -> list[int]:
        """Per-frame hold times (ms) from the timeline the frames were captured
        at, so the intro replays at the speed it was recorded."""
        out = [int((b - a) * 1000) for a, b in zip(times, times[1:])]
        return out + [int(tail * 1000)]

    # ── welcome: intro animation, then a looping sheen ──────────────────── #
    welcome = app.screen
    assert isinstance(welcome, WelcomeScreen), type(welcome)
    import time

    def at(t: float) -> int:
        welcome._t0 = time.monotonic() - t
        welcome._tick()
        return frames.grab(app)

    intro = [at(t) for t in INTRO_TIMES]
    loop = [at(t) for t in LOOP_TIMES]
    step = SHEEN_PERIOD / LOOP_FRAMES
    scene("welcome", intro + loop,
          durations=gaps(INTRO_TIMES, LOOP_TIMES[0] - INTRO_TIMES[-1])
                    + [int(step * 1000)] * LOOP_FRAMES,
          loop_from=len(intro),
          hint="a manifest is a run plan — pick one to open the workspace")

    # ── enter the workspace on aws-prod.yaml (the picker's first row) ───── #
    await pilot.press("enter")
    await pilot.pause()
    workspace = app.screen

    async def tab(n: str) -> None:
        # esc first: a focused Input eats every printable key, so the tab number
        # would land in the filter box instead of reaching the screen bindings.
        await pilot.press("escape")
        await pilot.press(n)
        await pilot.pause()

    # ── catalog ─────────────────────────────────────────────────────────── #
    from framework.tui.screens.catalog import CatalogPage
    catalog_page = workspace.query_one(CatalogPage)
    await pilot.press("down")           # highlight the aws category
    await pilot.press("enter")          # expand it
    await pilot.press("down")           # first fetcher -> contract in the detail
    await pilot.pause()
    scene("catalog", [frames.grab(app)],
          hint="183 fetchers across 14 categories — every contract is declared, not documented")

    # the same tree under a filter, landing on the MFA fetcher's contract
    catalog_page.focus_search()
    await pilot.press(*"mfa")
    await pilot.pause()
    await pilot.press("down", "down")
    await pilot.pause()
    scene("catalog.filter", [frames.grab(app)],
          hint="filter by name or description; the contract pane shows config, secrets and targets")

    # ── manifest ────────────────────────────────────────────────────────── #
    await tab("2")
    manifest_page = workspace.query_one(ManifestPage)
    scene("manifest", [frames.grab(app)],
          hint="the manifest is the run plan: which fetchers, which accounts, where the secrets come from")

    await pilot.press("down", "down", "down")
    await pilot.pause()
    scene("manifest.entry", [frames.grab(app)],
          hint="each entry shows its resolved config, secret refs and targets")

    manifest_page.action_preview()
    await pilot.pause()
    scene("manifest.preview", [frames.grab(app)], hint="p — preview the manifest as YAML")
    await pilot.press("escape")
    await pilot.pause()

    manifest_page.action_add_fetcher()
    await pilot.pause()
    scene("manifest.add", [frames.grab(app)],
          hint="a — add fetchers; already-added ones are greyed out")
    await pilot.press("escape")
    await pilot.pause()

    # ── run: idle, then the streaming console frame by frame ────────────── #
    await tab("3")
    run_page = workspace.query_one(RunPage)
    scene("run", [frames.grab(app)],
          hint="ctrl+r runs the manifest — press Run to watch a collection stream in")

    events = run_events(app.manifest["run"]["fetchers"], "2026-09-02T09-14-05Z")
    stream: list[int] = []
    # One frame per result (plus the opening and closing states) — enough to read
    # as live without a frame per log line.
    for i, event in enumerate(events):
        run_page._handle_event(event)
        if event["event"] in ("run_start", "fetcher_result", "run_complete"):
            await pilot.pause()
            stream.append(frames.grab(app))
    # Held a touch longer on the opening frame (the queue appearing) and at the
    # end, so the eye catches both ends of the sequence.
    holds = [700] + [190] * (len(stream) - 2) + [900]
    scene("run.stream", stream, durations=holds, next="run.done",
          hint="16 invocations across two accounts — status, live log and a pass/fail bar")
    scene("run.done", [stream[-1]],
          hint="one fetcher failed: GuardDuty was never enabled in us-gov-east-1")

    # ── evidence ────────────────────────────────────────────────────────── #
    await tab("4")
    evidence_page = workspace.query_one(EvidencePage)
    scene("evidence", [frames.grab(app)],
          hint="every past run, with the files it produced and the exit code of each invocation")

    # Open the MFA envelope from the run that is actually selected, so the modal
    # and the table behind it agree: metadata, evidence set and payload as the
    # uploader sees them.
    def mfa_file(run: dict) -> str:
        return next(f["path"] for f in run["files"]
                    if f["name"].startswith("aws_iam_mfa_status"))

    evidence_page._open_file(mfa_file(evidence_page._runs[0]))
    await pilot.pause()
    scene("evidence.file", [frames.grab(app)],
          hint="the envelope the uploader sends: metadata, evidence-set reference, payload")
    await pilot.press("escape")
    await pilot.pause()

    await pilot.press("down")
    await pilot.pause()
    scene("evidence.run", [frames.grab(app)],
          hint="the clean run from five days earlier — 16 of 16, nothing failed")

    # ── paramify ────────────────────────────────────────────────────────── #
    await tab("5")
    scene("upload", [frames.grab(app)],
          hint="push evidence, intake issue reports, and sync fetcher scripts to Paramify")

    return scenes


# ── navigation: what is clickable, and what the keys do ──────────────────── #

TAB_SCENES = ["catalog", "manifest", "run", "evidence", "upload"]
TAB_LABELS = ["Catalog", "Manifest", "Run", "Evidence", "Paramify"]
TAB_BAR_ROW = 2  # the TabbedContent tab strip, under the header rule

# Hotspots per scene: (needle, occurrence, pad, target scene). "row" widens the
# hit to the enclosing panel borders, so table rows are clickable end to end.
HOTSPOTS: dict[str, list[tuple]] = {
    "welcome": [
        ("aws-prod.yaml", 0, "row", "catalog"),
        ("gcp-baseline.yaml", 0, "row", "catalog"),
        ("k8s-cluster.yaml", 0, "row", "catalog"),
        ("okta-quarterly.yaml", 0, "row", "catalog"),
    ],
    "catalog": [
        ("/ filter fetchers", 0, (1, 14, 1, 2), "catalog.filter"),
        ("/ filter", 0, (0, 1, 0, 1), "catalog.filter"),   # footer hint
    ],
    "catalog.filter": [("esc leave field", 0, (0, 1, 0, 1), "catalog")],
    "manifest": [
        ("aws_iam_mfa_status", 0, "row", "manifest.entry"),
        ("aws_cloudtrail_configuration", 0, "row", "manifest.entry"),
        ("Add fetcher", 0, (0, 2, 0, 2), "manifest.add"),
        ("a add", 0, (0, 1, 0, 1), "manifest.add"),         # footer hint
        ("p preview", 0, (0, 1, 0, 1), "manifest.preview"),  # footer hint
    ],
    "manifest.entry": [
        ("aws_iam_mfa_status", 0, "row", "manifest"),
        ("Add fetcher", 0, (0, 2, 0, 2), "manifest.add"),
        ("a add", 0, (0, 1, 0, 1), "manifest.add"),
        ("p preview", 0, (0, 1, 0, 1), "manifest.preview"),
    ],
    "manifest.preview": [("esc", 0, (0, 6, 0, 1), "manifest.entry")],
    "manifest.add": [("esc", 0, (0, 6, 0, 1), "manifest")],
    "run": [
        ("\u25b6 Run", 0, (0, 3, 0, 3), "run.stream"),
        ("enter/ctrl+r run", 0, (0, 1, 0, 1), "run.stream"),  # footer hint
    ],
    "run.done": [
        ("\u25b6 Run", 0, (0, 3, 0, 3), "run.stream"),
        ("enter/ctrl+r run", 0, (0, 1, 0, 1), "run.stream"),
    ],
    "evidence": [
        ("2026-08-28T09-12-44Z", 0, "row", "evidence.run"),
        ("aws_iam_mfa_status_prod-us-gov-west.json", 0, "row", "evidence.file"),
        ("aws_iam_mfa_status_prod-us-gov-east.json", 0, "row", "evidence.file"),
    ],
    "evidence.run": [
        ("2026-09-02T09-14-05Z", 0, "row", "evidence"),
        ("aws_iam_mfa_status_prod-us-gov-west.json", 0, "row", "evidence.file"),
    ],
    "evidence.file": [("esc", 0, (0, 6, 0, 1), "evidence")],
}

# Extra key bindings the player honours, on top of 1-5 for the tabs.
SCENE_KEYS: dict[str, dict[str, str]] = {
    "welcome": {"Enter": "catalog"},
    "catalog": {"/": "catalog.filter"},
    "catalog.filter": {"Escape": "catalog"},
    "manifest": {"a": "manifest.add", "p": "manifest.preview", "ArrowDown": "manifest.entry"},
    "manifest.entry": {"a": "manifest.add", "p": "manifest.preview", "ArrowUp": "manifest"},
    "manifest.preview": {"Escape": "manifest.entry"},
    "manifest.add": {"Escape": "manifest"},
    "run": {"Control+r": "run.stream", "Enter": "run.stream"},
    "run.done": {"Control+r": "run.stream", "Enter": "run.stream"},
    "evidence": {"ArrowDown": "evidence.run", "Enter": "evidence.file"},
    "evidence.run": {"ArrowUp": "evidence", "Enter": "evidence.file"},
    "evidence.file": {"Escape": "evidence"},
}

# The tab each scene belongs to, so the number keys work from inside a modal and
# the player can mark the active tab.
SCENE_TAB = {
    "catalog": 0, "catalog.filter": 0,
    "manifest": 1, "manifest.entry": 1, "manifest.preview": 1, "manifest.add": 1,
    "run": 2, "run.stream": 2, "run.done": 2,
    "evidence": 3, "evidence.run": 3, "evidence.file": 3,
    "upload": 4,
}


def wire(scenes: dict[str, Any], frames: Frames) -> dict[str, Any]:
    """Attach resolved hotspots and key maps to each scene."""
    missing: list[str] = []
    for name, sc in scenes.items():
        grid = frames.texts[sc["frames"][0]]
        spots = []

        # The tab strip is clickable on every workspace scene.
        if name != "welcome":
            for i, label in enumerate(TAB_LABELS):
                rect = find_rect(grid, label, 0, (0, 1, 1, 1), only_row=TAB_BAR_ROW)
                if rect is None:
                    missing.append(f"{name}: tab {label!r} on row {TAB_BAR_ROW}")
                    continue
                spots.append({"rect": rect, "go": TAB_SCENES[i]})

        for needle, occurrence, pad, target in HOTSPOTS.get(name, []):
            rect = find_rect(grid, needle, occurrence, pad)
            if rect is None:
                missing.append(f"{name}: {needle!r}")
                continue
            spots.append({"rect": rect, "go": target})

        keys = dict(SCENE_KEYS.get(name, {}))
        if name != "welcome":
            for i, target in enumerate(TAB_SCENES):
                keys[str(i + 1)] = target
        sc["hotspots"] = spots
        sc["keys"] = keys
        if name in SCENE_TAB:
            sc["tab"] = SCENE_TAB[name]
    if missing:
        # A moved label silently drops a hotspot and the demo looks broken, so
        # fail the capture instead of shipping dead click targets.
        raise SystemExit("hotspot labels not found in the captured frames:\n  "
                         + "\n  ".join(missing))
    return scenes


# ── entry point ──────────────────────────────────────────────────────────── #

async def capture() -> tuple[Frames, dict[str, Any]]:
    frames = Frames()

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: D102
            return FROZEN_NOW

    chrome.datetime = FrozenDateTime  # freeze the header clock across frames

    app = app_module.FetcherApp(root_override=str(Path.cwd()))
    async with app.run_test(size=(WIDTH, HEIGHT)) as pilot:
        await pilot.pause()
        scenes = await storyboard(app, pilot, frames)
    frames.drop_screen_background()
    return frames, wire(scenes, frames)


def main() -> None:
    parser = argparse.ArgumentParser(prog="tools.webdemo.capture", description=__doc__)
    parser.add_argument("--out", default=str(Path(__file__).parent / "dist" / "demo.html"))
    parser.add_argument("--workspace", default="/tmp/paramify-webdemo-workspace",
                        help="where the throwaway demo workspace is built")
    args = parser.parse_args()

    catalog = api.catalog(REPO_ROOT)
    known = {f["name"] for cat in catalog["categories"] for f in cat["fetchers"]}
    workspace = fixture.build(Path(args.workspace), REPO_ROOT, known)

    os.environ.update(DEMO_ENV)
    os.chdir(workspace)  # relative output_dir in the manifests resolves from here

    frames, scenes = asyncio.run(capture())

    from tools.webdemo.page import render_page
    out = Path(args.out)
    if not out.is_absolute():
        out = REPO_ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    standalone, fragment = render_page(
        frames, scenes, WIDTH, HEIGHT, TAB_LABELS, TAB_SCENES,
    )
    out.write_text(standalone)
    frag = out.with_name(out.stem + ".fragment.html")
    frag.write_text(fragment)
    print(f"{len(frames.frames)} frames, {len(scenes)} scenes, "
          f"{len(frames.styles)} styles")
    print(f"  {out}  ({len(standalone) / 1024:.0f} KB)")
    print(f"  {frag}  ({len(fragment) / 1024:.0f} KB, for the Artifact publisher)")


if __name__ == "__main__":
    main()
