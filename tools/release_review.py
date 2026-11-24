"""Review a release notes file row by row, with each row shown as users see it.

    python tools/release_review.py [releases/<version>.yaml]

With no path it opens the one release file in ./releases that still has draft marks.
The file can live in another checkout (the release/next one you review in);
the checks then compare against that checkout's history.

Left: every row, grouped Breaking / New / Fetchers, with a mark for what still
needs you (○ not reviewed, TODO, … cut off, ! too long). Right: the row's text
fields and a preview drawn by framework/update_view.py, the code that draws
`paramify update` and the TUI update screen, so the preview cannot drift from
the real thing.

Keys: enter in a field (or ctrl+r) marks the row reviewed and moves on;
ctrl+n jumps to the next row that needs you; ctrl+d deletes a highlight row
(fetcher lines are kept and edited, never deleted); f changes the filter;
ctrl+s saves and lists what would still fail; q quits.

For maintainers. It edits only the file you open, and only on ctrl+s.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich.console import Group, RenderableType
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from framework import release_notes  # noqa: E402
from framework import update_view as view  # noqa: E402

TITLE_MAX = 72
TRY_MAX = 90
FIELDS = {  # kind: [(key, label, limit)]
    "breaking": [("title", "Title", TITLE_MAX), ("fix", "What the user does", release_notes.NOTE_MAX)],
    "new": [("title", "Title", TITLE_MAX), ("detail", "Second line (optional)", release_notes.NOTE_MAX),
            ("try", "Command to try (optional, starts with paramify)", TRY_MAX)],
    "fetcher": [("note", "What changed for the person running it", release_notes.NOTE_MAX)],
}
FILTERS = ("needs you", "not reviewed", "TODO", "cut off", "all")
SAMPLE_MANIFEST = "manifests/prod.yaml"


def _release_tool() -> Any:
    """tools/release.py, for the git facts `check` uses."""
    spec = importlib.util.spec_from_file_location("release_tool", Path(__file__).with_name("release.py"))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def git_facts(root: Path) -> Optional[dict]:
    """What the release checks compare against: fetcher versions at the last
    tag and now. None outside a clone with release tags."""
    try:
        tool = _release_tool()
        tag = tool.last_tag(root, "HEAD")
        changed, added = tool.changed_fetchers(root, tag, "HEAD")
        return {"tag": tag, "prev": tool._version_of(tag), "changed": changed, "added": added,
                "before": tool.fetcher_versions(root, tag)}
    except Exception:  # a scratch copy, no tags, no git: preview still works, checks are skipped
        return None


def repo_of(path: Path) -> Path:
    """The clone that holds `path` (the release/next checkout you review in), else this one."""
    try:
        import subprocess

        top = subprocess.run(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=True).stdout.strip()
        return Path(top).resolve() if top else REPO_ROOT
    except (OSError, subprocess.CalledProcessError):
        return REPO_ROOT


def default_file(root: Path) -> Optional[Path]:
    found = [p for p in sorted((root / "releases").glob("*.yaml"))
             if p.stem != "unreleased" and "draft: true" in p.read_text()]
    return found[0] if len(found) == 1 else None


# --------------------------------------------------------------------------- #
# Rows
# --------------------------------------------------------------------------- #

def rows(doc: dict) -> List[Tuple[str, dict]]:
    """[(kind, row dict)] in screen order: breaking, new, fetchers. The dicts are the doc's own."""
    hl = doc.get("highlights") or []
    return ([("breaking", r) for r in hl if r.get("tag") == "breaking"]
            + [("new", r) for r in hl if r.get("tag") != "breaking"]
            + [("fetcher", r) for r in doc.get("fetchers") or []])


def flags(kind: str, row: dict) -> List[str]:
    """What still needs a person: draft, todo, cut, long."""
    out = ["draft"] if row.get("draft") else []
    text = row.get("note", "") if kind == "fetcher" else row.get("title", "")
    if text.startswith("TODO"):
        out.append("todo")
    if any(str(row.get(k, "")).endswith("…") for k, _l, _m in FIELDS[kind]):
        out.append("cut")
    if any(len(str(row.get(k) or "")) > m for k, _l, m in FIELDS[kind]):
        out.append("long")
    return out


def shown(kind: str, row: dict, filt: str) -> bool:
    f = flags(kind, row)
    return {"needs you": bool(f), "not reviewed": "draft" in f, "TODO": "todo" in f,
            "cut off": "cut" in f, "all": True}[filt]


def label(kind: str, row: dict, width: int = 80) -> Text:
    """One line per row: state, kind, what needs you, then the text, cut to `width` with an ellipsis."""
    f = flags(kind, row)
    t = Text(no_wrap=True, overflow="ellipsis", end="")
    t.append("○ " if "draft" in f else "✓ ", style="yellow" if "draft" in f else "green")
    badge = {"breaking": "BRK", "new": row.get("tag", "new")[:3].upper(), "fetcher": ""}[kind]
    t.append(f"{badge:<4}", style="bold red" if kind == "breaking" else "dim")
    for mark, word, style in (("todo", "TODO", "bold red"), ("cut", "…", "yellow"), ("long", "LONG", "bold red")):
        if mark in f:
            t.append(word + " ", style=style)
    if kind == "fetcher":
        t.append(row.get("name", ""), style="cyan")
        if "todo" not in f:
            t.append("  " + row.get("note", ""), style="dim")
    else:
        t.append(row.get("title", ""))
    t.truncate(max(10, width))  # overflow="ellipsis" adds the …
    return t


# --------------------------------------------------------------------------- #
# The preview: the update screen's own functions, fed one row
# --------------------------------------------------------------------------- #

def preview(kind: str, row: dict, version: str, date: Optional[str], before: Dict[str, str]) -> RenderableType:
    releases = [{"version": version, "date": date}]
    if kind == "breaking":
        why = "fetchers" if row.get("fetchers") else "custom" if row.get("custom_fetchers") else "everyone"
        b = {**row, "touches": True, "why": why, "release": version,
             "manifests": [{"manifest": SAMPLE_MANIFEST, "fetchers": row.get("fetchers") or []}]}
        return Group(*view.breaking([b]))
    if kind == "new":
        parts: List[RenderableType] = list(view.whats_new([{**row, "release": version}], releases))
        if row.get("try"):
            parts += [Text(""), view.line(("try  ", "dim"), (row["try"], "bold"))]
        return Group(*parts)
    name = row.get("name", "")
    was = before.get(name)
    fetcher = {"name": name, "change": "changed" if was else "added", "from": was, "to": row.get("version"),
               "reason": None, "more": 0, "manifests": [SAMPLE_MANIFEST],
               "notes": [{"release": version, "version": row.get("version"), "note": row.get("note", "")}]}
    cli = view.your_fetchers({"yours": [fetcher]}, 1, [])
    tui = view.line(("TUI table: ", "dim"), (name + "  ", "cyan"), (view.versions(fetcher) + "  ", "dim"))
    tui.append_text(view.fetcher_note(fetcher, []))
    return Group(*cli, Text(""), tui)


def problems(doc: dict, facts: Optional[dict]) -> List[str]:
    """Everything that would keep the release PR red, as short lines."""
    out: List[str] = []
    try:
        from jsonschema import Draft202012Validator

        schema = json.loads((REPO_ROOT / "framework/schemas/release_highlights_schema.json").read_text())
        plain = json.loads(json.dumps(doc, default=str))
        out += [f"schema: {'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}"
                for e in Draft202012Validator(schema).iter_errors(plain)]
    except ImportError:
        pass
    every = rows(doc)
    marked = sum(1 for _k, r in every if r.get("draft"))
    todo = sum(1 for k, r in every if "todo" in flags(k, r))
    if marked:
        out.append(f"{marked} rows still have draft: true")
    if todo:
        out.append(f"{todo} notes still start with TODO")
    if facts:
        out += release_notes.check_release(doc, facts["changed"], facts["added"], facts["prev"])
    return out


# --------------------------------------------------------------------------- #
# The app
# --------------------------------------------------------------------------- #

class ReleaseReview(App):
    CSS = """
    #left { width: 46%; border-right: solid $panel; }
    #filter { padding: 0 1; color: $text-muted; }
    #rows { height: 1fr; border: none; }
    #right { padding: 0 1; }
    .field-label { color: $text-muted; margin-top: 1; }
    .count { color: $text-muted; height: 1; }
    .count.over { color: $error; }
    #preview { border: round $accent; padding: 0 1; height: auto; margin-top: 1; }
    #status { height: auto; max-height: 8; padding: 0 1; color: $text-muted; }
    """
    TITLE = "Release review"
    BINDINGS = [
        Binding("ctrl+s", "save", "Save", priority=True),
        Binding("ctrl+r", "reviewed", "Reviewed / not", priority=True),
        Binding("ctrl+n", "next_needed", "Next that needs you", priority=True),
        Binding("ctrl+d", "delete_row", "Delete highlight", priority=True),
        Binding("f", "cycle_filter", "Filter"),
        Binding("q", "quit_review", "Quit"),
    ]

    def __init__(self, path: Path, facts: Optional[dict] = None) -> None:
        super().__init__()
        self.path = path
        self.doc: dict = yaml.safe_load(path.read_text()) or {}
        self.version = str(self.doc.get("version", "?"))
        date = self.doc.get("date")
        self.date = date.isoformat() if isinstance(date, datetime.date) else (str(date) if date else None)
        self.facts = facts
        self.row_filter = FILTERS[0]
        self.listed: List[Tuple[str, dict]] = []
        self.current: Optional[Tuple[str, dict]] = None
        self.unsaved = False
        self.quit_armed = False

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="left"):
                yield Static("", id="filter")
                yield OptionList(id="rows")
            with VerticalScroll(id="right"):
                yield Static("", id="heading")
                for i in range(3):
                    yield Label("", classes="field-label", id=f"label{i}")
                    yield Input(id=f"field{i}")
                    yield Static("", classes="count", id=f"count{i}")
                yield Static("", id="preview")
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"{self.path.name} · v{self.version}"
        self.refill(keep=None)
        self.query_one("#rows", OptionList).focus()
        self.call_after_refresh(self.relabel)  # the list's width is known only after the first layout

    # -- the list -------------------------------------------------------- #

    def refill(self, keep: Optional[dict]) -> None:
        """Rebuild the list for the filter, keeping `keep` selected when it is still shown."""
        every = rows(self.doc)
        self.listed = [(k, r) for k, r in every if shown(k, r, self.row_filter)]
        ol = self.query_one("#rows", OptionList)
        ol.clear_options()
        ol.add_options([Option(label(k, r, self.label_width())) for k, r in self.listed])
        need = sum(1 for k, r in every if flags(k, r))
        self.query_one("#filter", Static).update(
            Text.assemble(("Filter: ", "dim"), (self.row_filter, "bold"), (f"   {len(self.listed)} shown · ", "dim"),
                          (f"{need} of {len(every)} need you", "yellow" if need else "green"),
                          ("   (f to change)", "dim")))
        index = next((i for i, (_k, r) in enumerate(self.listed) if r is keep), 0 if self.listed else None)
        if index is not None:
            ol.highlighted = index
            self.show(*self.listed[index])
        else:
            self.show(None, None)

    def label_width(self) -> int:
        w = self.query_one("#rows", OptionList).size.width
        return w - 3 if w > 20 else 78

    def relabel(self) -> None:
        ol = self.query_one("#rows", OptionList)
        for i, (k, r) in enumerate(self.listed):
            ol.replace_option_prompt_at_index(i, label(k, r, self.label_width()))

    def on_resize(self) -> None:
        self.call_after_refresh(self.relabel)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if 0 <= event.option_index < len(self.listed):
            self.show(*self.listed[event.option_index])

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.query_one("#field0", Input).focus()

    # -- the editor ------------------------------------------------------ #

    def show(self, kind: Optional[str], row: Optional[dict]) -> None:
        self.current = (kind, row) if kind and row is not None else None
        fields = FIELDS.get(kind or "", [])
        for i in range(3):
            lab, inp, cnt = (self.query_one(f"#label{i}", Label), self.query_one(f"#field{i}", Input),
                             self.query_one(f"#count{i}", Static))
            on = i < len(fields)
            for w in (lab, inp, cnt):
                w.display = on
            if on and row is not None:
                key, text, _limit = fields[i]
                lab.update(text)
                with inp.prevent(Input.Changed):
                    inp.value = str(row.get(key) or "")
                self.count(i)
        if row is None:
            self.query_one("#heading", Static).update(Text("Nothing here for this filter. Press f.", style="dim"))
            self.query_one("#preview", Static).update("")
            return
        what = {"breaking": "Breaking change", "new": f"New ({row.get('tag')})",
                "fetcher": f"Fetcher {row.get('name')} {row.get('version')}"}[kind or ""]
        state = Text(" not reviewed", style="yellow") if row.get("draft") else Text(" reviewed", style="green")
        self.query_one("#heading", Static).update(Text.assemble((what, "bold"), state))
        self.redraw_preview()

    def count(self, i: int) -> None:
        if not self.current:
            return
        kind, row = self.current
        key, _text, limit = FIELDS[kind][i]
        n = len(str(row.get(key) or ""))
        cnt = self.query_one(f"#count{i}", Static)
        cnt.update(f"{n}/{limit}")
        cnt.set_class(n > limit, "over")

    def redraw_preview(self) -> None:
        if not self.current:
            return
        kind, row = self.current
        before = (self.facts or {}).get("before", {})
        p = self.query_one("#preview", Static)
        p.border_title = "How users see it"
        p.update(preview(kind, row, self.version, self.date, before))

    def on_input_changed(self, event: Input.Changed) -> None:
        if not self.current or not event.input.id:
            return
        kind, row = self.current
        i = int(event.input.id.removeprefix("field"))
        key = FIELDS[kind][i][0]
        value = event.value.strip()
        if value or key in ("title", "note", "fix"):
            row[key] = value
        else:
            row.pop(key, None)  # an empty optional field is dropped, not written as ""
        self.unsaved = True
        self.count(i)
        self.redraw_preview()
        idx = next((i for i, (_k, r) in enumerate(self.listed) if r is row), None)
        if idx is not None:
            self.query_one("#rows", OptionList).replace_option_prompt_at_index(idx, label(kind, row, self.label_width()))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.action_reviewed(mark=True)

    # -- actions --------------------------------------------------------- #

    def action_reviewed(self, mark: Optional[bool] = None) -> None:
        if not self.current:
            return
        _kind, row = self.current
        if mark is None:
            mark = bool(row.get("draft"))
        if mark:
            row.pop("draft", None)
        else:
            row["draft"] = True
        self.unsaved = True
        if mark:
            self.action_next_needed(after=row)
        else:
            self.refill(keep=row)

    def action_next_needed(self, after: Optional[dict] = None) -> None:
        """Select the next row, after the current one and wrapping, that still needs you."""
        every = rows(self.doc)
        cur = after if after is not None else (self.current[1] if self.current else None)
        start = next((i + 1 for i, (_k, r) in enumerate(every) if r is cur), 0)
        nxt = next((r for k, r in every[start:] + every[:start] if r is not cur and flags(k, r)), None)
        if nxt is None:
            self.refill(keep=cur)
            self.notify("Nothing left that needs you. ctrl+s to save.")
            return
        if not shown(*next((k, r) for k, r in every if r is nxt), self.row_filter):
            self.row_filter = FILTERS[0]
        self.refill(keep=nxt)
        self.query_one("#field0", Input).focus()

    def action_delete_row(self) -> None:
        if not self.current:
            return
        kind, row = self.current
        if kind == "fetcher":
            self.notify("Fetcher lines are kept and edited, never deleted.", severity="warning")
            return
        hl = self.doc.get("highlights") or []
        i = next(i for i, r in enumerate(hl) if r is row)
        del hl[i]
        self.unsaved = True
        self.notify(f"Deleted: {row.get('title')}")
        self.refill(keep=None)

    def action_cycle_filter(self) -> None:
        self.row_filter = FILTERS[(FILTERS.index(self.row_filter) + 1) % len(FILTERS)]
        self.refill(keep=self.current[1] if self.current else None)

    def action_save(self) -> None:
        self.path.write_text(release_notes.dump_release(self.doc))
        self.unsaved = False
        left = problems(self.doc, self.facts)
        status = self.query_one("#status", Static)
        if left:
            status.update(Text.assemble((f"Saved {self.path.name}. Still to fix before the PR goes green:\n", "bold"),
                                        ("\n".join("  · " + p for p in left[:6]), "yellow"),
                                        (f"\n  · and {len(left) - 6} more" if len(left) > 6 else "", "yellow")))
        else:
            status.update(Text(f"Saved {self.path.name}. Nothing left to fix. Commit and push it to release/next.",
                               style="green"))

    def action_quit_review(self) -> None:
        if self.unsaved and not self.quit_armed:
            self.quit_armed = True
            self.notify("Unsaved changes. ctrl+s saves; q again quits without saving.", severity="warning")
            return
        self.exit()


def main(argv: Optional[List[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else default_file(Path.cwd())
    if path is None or not path.is_file():
        print("release_review: name the file, e.g. python tools/release_review.py releases/0.7.0-beta.yaml",
              file=sys.stderr)
        return 1
    path = path.resolve()
    ReleaseReview(path, git_facts(repo_of(path))).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
