"""Manifest editor (Phase 2).

Edits the App's in-memory manifest dict entirely through framework.api: a
DataTable of entries on the left, a live contract/values detail on the right,
and an issues bar (api.validate) at the bottom. Every mutation goes through a
modal -> api.* mutator -> rebuild, mirroring the Bagels write path.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import yaml
from rich.console import RenderableType
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Input, Static

from framework import api, patterns
from framework.contract import ManifestEntry
from framework.issue_reports import CLOSE_AFTER_RUN, CLOSE_NEVER
from framework.runner.manifest_loader import entry_keys
from framework.tui import kinds, palette, render
from framework.tui.components.detail import FocusCatalog, ManifestChanged, ShowDetail
from framework.tui.components.forms import env_name_from_ref
from framework.tui.components.keys import BUTTON_ROW_BINDINGS, ButtonRowNav
from framework.tui.components.table import DataTable
from framework.tui.modals import (
    ConfirmModal,
    FormModal,
    PickerModal,
    PreviewModal,
    TargetsModal,
)

APPROVALS = ("MANUAL", "SUBMISSION_WITH_PASSING_VALIDATORS", "SUBMISSION")
NO_REQUESTS = ("direct", "evidence", "refuse")
DELIVERIES = ("auto", "direct")


def _cell(value) -> str:
    """One target field as table text. An unset field reads as a dash rather than
    an empty cell, so a missing required value is visible at a glance."""
    if value is None or value == "":
        return "—"
    return str(value)


def _target_summary(target: dict) -> str:
    """A target on one line, for confirmations. Secrets are named, never valued —
    the manifest holds ${env:VAR} references, and printing them invites the habit
    of putting the credential itself there."""
    vals = {k: v for k, v in (target or {}).items() if k != "secrets"}
    return "  ".join(f"{k}={v}" for k, v in vals.items()) or "(empty)"


# The owner picker's "remove the owner" choice; no username can be empty.
_NO_OWNER = "\0none"

class ManifestPanel(ButtonRowNav, Vertical):
    """The manifest editor: settings row, entries table, and (with detail=True)
    the selected entry's detail beside the table.

    With detail=False the detail pane is left out and ShowDetail bubbles to the
    page that hosts the panel, which shows it in a shared pane.
    """

    HINTS = [
        ("a", "add"), ("e", "entry"), ("x", "remove"), ("t", "targets"),
        ("A", "assessment"), ("s", "save"), ("v", "validate"), ("p", "preview"),
    ]

    BINDINGS = [
        Binding("a", "add_fetcher", "Add"),
        Binding("e", "edit_entry", "Entry"),
        Binding("x", "remove_entry", "Remove"),
        Binding("t", "edit_targets", "Targets"),
        Binding("A", "pick_assessment", "Assessment"),
        Binding("s", "save", "Save"),
        Binding("v", "validate", "Validate"),
        Binding("p", "preview", "Preview"),
        *BUTTON_ROW_BINDINGS,
    ]

    def __init__(self, *, detail: bool = True, **kwargs) -> None:
        super().__init__(**kwargs)
        self._has_detail = detail
        if not detail:
            self.add_class("no-detail")

    def compose(self) -> ComposeResult:
        with Horizontal(id="manifest-top"):
            yield Static("output dir:", classes="inline-label")
            # select_on_focus off: Textual selects the whole value on focus, so
            # the first keystroke replaced the existing path wholesale.
            yield Input(placeholder="./evidence", id="manifest-output-dir", select_on_focus=False)
            yield Static("stack:", classes="inline-label")
            yield Button("—", id="manifest-stack")
            yield Static("owner:", classes="inline-label after-button")
            yield Button("—", id="manifest-owner")
            yield Button("Save", id="btn-save")
        with Horizontal(id="manifest-body"):
            with Vertical(id="manifest-entries-panel", classes="panel"):
                yield DataTable(id="manifest-entries")
                yield Static("", id="manifest-empty-hint", classes="empty-hint")
            if self._has_detail:
                with VerticalScroll(id="manifest-detail-scroll", classes="panel"):
                    yield Static(render.empty_detail("No fetcher selected."), id="manifest-detail")
        yield Static(id="manifest-issues")

    def on_mount(self) -> None:
        self._selected: Optional[str] = None  # the fetcher (use) of the selected row
        self._selected_key: Optional[str] = None  # its entry key: x, x#1
        self._key_use: Dict[str, str] = {}
        self._errors: List[str] = []
        # {entry key: merged config view}, rebuilt with the table (api.effective_config)
        self._config_view: Dict[str, List[dict]] = {}
        self.query_one("#manifest-entries-panel", Vertical).border_title = "fetchers"
        if self._has_detail:
            self.query_one("#manifest-detail-scroll", VerticalScroll).border_title = "detail"
        else:
            # On the Fetchers page an empty manifest hides its table; the hint takes
            # its place as the focus stop, so the manifest's keys stay in reach.
            self.query_one("#manifest-empty-hint", Static).can_focus = True
        dt = self.query_one("#manifest-entries", DataTable)
        dt.cursor_type = "row"
        dt.zebra_stripes = True
        # kind + sends to: the two kinds go to different places, and a scan
        # report goes nowhere until the manifest names its assessment. Sends to
        # is last because it is the widest: on a narrow terminal it is what runs
        # off the edge, not status (the detail pane shows it in full). No mode
        # column: targets already reads "—" for a fetcher that runs once.
        dt.add_columns("fetcher", "kind", "secrets", "config", "targets", "status", "sends to")
        self.rebuild()

    # -- state access ----------------------------------------------------- #

    @property
    def _manifest(self) -> Optional[dict]:
        return getattr(self.app, "manifest", None)

    def _run(self) -> dict:
        return (self._manifest or {}).get("run") or {}

    def _entries(self) -> List[dict]:
        return self._run().get("fetchers") or []

    def _entry(self, use: str) -> dict:
        return next((e for e in self._entries() if e.get("use") == use), {})

    def _selected_entry_key(self) -> Optional[str]:
        """The selected row's entry key (`x`, `x#1`), so a write reaches that entry, not the first."""
        use = self._selected
        if use is None:
            return None
        return self._selected_key if self._key_use.get(self._selected_key or "") == use else use

    def _keyed_entry(self, key: Optional[str]) -> dict:
        return next((e for k, e in self._keyed() if k == key), {})

    def _descriptors(self) -> Dict[str, dict]:
        cat = getattr(self.app, "catalog_data", None)
        out: Dict[str, dict] = {}
        if cat:
            for c in cat["categories"]:
                for f in c["fetchers"]:
                    out[f["name"]] = f
        return out

    # -- rebuild ---------------------------------------------------------- #

    def rebuild(self) -> None:
        dt = self.query_one("#manifest-entries", DataTable)
        if self._manifest is None:
            dt.clear()
            self._set_empty(f"no manifest loaded — press [bold {palette.ACCENT}]m[/] to pick one")
            self._set_issues(["(no manifest loaded)"])
            self.post_message(ManifestChanged(set()))
            return

        out = self._run().get("output_dir", "") or ""
        odi = self.query_one("#manifest-output-dir", Input)
        if odi.value != out:
            odi.value = out

        self.query_one("#manifest-stack", Button).label = self._stack_label()
        self.query_one("#manifest-owner", Button).label = (self._run().get("paramify") or {}).get("owner") or "—"

        descriptors = self._descriptors()
        entries = self._entries()
        # One discovery pass shared by validate + effective_config: each would
        # otherwise walk and schema-validate all ~125 fetcher.yaml files, and
        # rebuild() runs on every mutation and tab switch.
        try:
            discovered = api.discover(self.app.root_path)
        except Exception:  # never let a discovery failure kill the UI
            discovered = {"fetchers": {}, "platforms": {}}
        try:
            self._errors = api.validate(self._manifest, self.app.root_path, **discovered)
        except Exception as exc:  # never let a validation crash kill the UI
            self._errors = [f"validation error: {exc}"]
        # One row per entry, keyed by entry key (`x`, `x#1`): two entries of one
        # fetcher used to share a key, which the table refuses. Everything a row
        # shows is read by that key too, so each row shows its own entry.
        keys = entry_keys([ManifestEntry(use=str(e.get("use", "?"))) for e in entries])
        by_key = self._bucket_errors(self._errors, entries)
        try:
            self._config_view = api.effective_config(self._manifest, keys, self.app.root_path, **discovered)
        except Exception:  # never let a config-merge failure kill the UI
            self._config_view = {}

        dt.clear()
        row_keys: List[str] = []
        self._key_use = {}
        for e, ekey in zip(entries, keys):
            use = e.get("use", "?")
            self._key_use[ekey] = use
            d = descriptors.get(use)
            fanout = bool(d and d.get("supports_targets"))
            sset, stot = self._secret_counts(d, e)
            cset, ctot = self._config_counts(self._config_view.get(ekey))
            ntargets = len(e.get("targets") or [])
            errs = by_key.get(ekey, [])
            status = palette.pill("✓", "ok") if not errs else palette.pill(f"⚠ {len(errs)}", "warn")
            dt.add_row(
                use,
                render.kind_pill(kinds.kind_of(d)) if d else "—",
                f"{sset}/{stot}",
                f"{cset}/{ctot}",
                str(ntargets) if fanout else "—",
                status,
                render.destination_cell(d, self._config_view.get(ekey)) if d else "—",
                key=ekey,
            )
            row_keys.append(ekey)

        empty = (
            f"manifest is empty — press [bold {palette.ACCENT}]a[/] to add fetchers"
            if self._has_detail
            else f"press [bold {palette.ACCENT}]a[/] on a fetcher to add it"
        )
        self._set_empty(None if entries else empty)

        # preserve selection across rebuilds
        if row_keys:
            if self._selected_key in row_keys:
                target = self._selected_key
            else:
                target = next((k for k in row_keys if self._key_use[k] == self._selected), row_keys[0])
            self._selected_key = target
            self._selected = self._key_use[target]
            try:
                dt.move_cursor(row=dt.get_row_index(target))
            except Exception:
                pass
        else:
            self._selected = self._selected_key = None

        self._refresh_detail()
        self._set_issues(self._errors)
        if not self._has_detail:
            # Under the catalog, whose list is titled "fetchers", this one is the manifest.
            self.query_one("#manifest-entries-panel", Vertical).border_title = f"manifest ({len(entries)})"
        self.post_message(ManifestChanged(self.in_manifest()))

    def _set_empty(self, hint: Optional[str]) -> None:
        """Show the hatched placeholder (with the given message) instead of the
        entries table, or the table again when hint is None."""
        if hint:
            self.query_one("#manifest-empty-hint", Static).update(hint)
        self.query_one("#manifest-entries-panel", Vertical).set_class(bool(hint), "empty")

    def _refresh_detail(self) -> None:
        # A panel with its own pane writes it at once; otherwise the host shows it.
        if self._has_detail:
            self.query_one("#manifest-detail", Static).update(self.current_detail())
        else:
            self.post_message(ShowDetail(self.current_detail(), self))

    def current_detail(self) -> RenderableType:
        """What the detail pane shows for the selected entry."""
        use = self._selected
        if not use or self._manifest is None:
            return render.empty_detail("No fetcher selected — press 'a' to add one.")
        # The selected entry (`x#1`), not the first that uses this fetcher.
        key = self._selected_entry_key()
        entry = self._keyed_entry(key)
        d = self._descriptors().get(use)
        # Bucket against the full entry list so index-prefixed (entry[i]) errors
        # attribute correctly, then take this entry's slice.
        errs = self._bucket_errors(self._errors, self._entries()).get(key, [])
        return render.entry_detail(d, entry, errs, self._config_view.get(key))

    def _set_issues(self, errors: List[str]) -> None:
        issues = self.query_one("#manifest-issues", Static)
        if not errors:
            issues.update(Text("✓ manifest is runnable", style=palette.OK))
            return
        head = Text(f"{len(errors)} issue(s):  ", style=palette.WARN)
        head.append("   ·   ".join(errors[:3]), style="dim")
        if len(errors) > 3:
            head.append(f"   (+{len(errors) - 3} more — press p to preview)", style="dim")
        issues.update(head)

    # -- per-entry summaries --------------------------------------------- #

    @staticmethod
    def _secret_counts(d: Optional[dict], e: dict) -> tuple:
        if not d:
            return (0, 0)
        top = [s for s in d.get("secrets", []) if not s.get("per_target")]
        have = e.get("secrets") or {}
        return (sum(1 for s in top if s["name"] in have), len(top))

    @staticmethod
    def _config_counts(view: Optional[List[dict]]) -> tuple:
        """(explicitly set, total applicable) from api.effective_config()'s view.

        "Set" means a value was supplied — in the entry or at the category level.
        Counting only the entry's own block reported category config as unset.
        """
        if not view:
            return (0, 0)
        return (sum(1 for c in view if c.get("source") not in (None, "default")), len(view))

    @staticmethod
    def _bucket_errors(errors: List[str], entries: List[dict]) -> Dict[str, List[str]]:
        """{entry key: its errors}. api.validate() uses two prefix conventions:
        "<entry key>: ..." / "<entry key> ..." for known entries, and
        "entry[<i>] uses unknown fetcher: <use>" for undiscovered ones. Attribute
        both so an unknown-fetcher row never shows a misleading ✓, and so an
        error about `x#1` shows on that row only."""
        keys = entry_keys([ManifestEntry(use=str(e.get("use", "?"))) for e in entries])
        out: Dict[str, List[str]] = {}
        for msg in errors or []:
            target = None
            if msg.startswith("entry[") and "]" in msg:
                try:
                    idx = int(msg[6 : msg.index("]")])
                except ValueError:
                    idx = -1
                if 0 <= idx < len(keys):
                    target = keys[idx]
            if target is None:
                target = next((k for k in keys if msg.startswith(f"{k}:") or msg.startswith(f"{k} ")), None)
            if target:
                out.setdefault(target, []).append(msg)
        return out

    @staticmethod
    def _config_spec(field: dict, current) -> dict:
        t = field.get("type")
        kind = "bool" if t == "boolean" else "int" if t == "integer" else "text"
        default = field.get("default")
        if kind == "bool":
            value = current if current is not None else bool(default)
        else:
            value = current
        return {
            "key": field["name"],
            "label": field["name"],
            "kind": kind,
            "value": value,
            "placeholder": "" if default is None else f"default: {default}",
            "required": field.get("required", False),
            "help": field.get("description") or "",
        }

    @staticmethod
    def _patterns_spec(field: dict, cfg: dict, m: dict, category: Optional[str]) -> dict:
        """A pattern list opens on the entry's own list, or on the category's, which it inherits until edited."""
        name = field["name"]
        where = f"platforms.{category}"
        inherited = api.category_patterns(m, category, name)
        n = len(inherited)
        held = f"{n} pattern{'' if n == 1 else 's'}"
        if name in cfg:
            value = patterns.to_lines(cfg[name])
            note = "this entry's own list"
            if inherited:
                note = f"{note}; replaces {where}'s {held}" if value else f"empty here: {where}'s {held} don't apply"
        elif inherited:
            value = patterns.to_lines([it.as_manifest() for it in inherited])
            note = f"inherits {where} ({held}) until edited here"
        else:
            value, note = "", ""
        return {
            "key": name,
            "label": name,
            "kind": "patterns",
            "value": value,
            "placeholder": "one per line: pattern  # reason",
            "required": field.get("required", False),
            "help": api.grammar_text(field.get("prefixes") or (), field.get("bare", True)),
            "prefixes": tuple(field.get("prefixes") or ()),
            "bare": field.get("bare", True),
            "note": note,
        }

    # -- events ----------------------------------------------------------- #

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        key = event.row_key.value
        self._selected_key = key
        self._selected = self._key_use.get(key, key)
        self._refresh_detail()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # Enter on a row edits it — what a table row implies, and previously the
        # one key on this page that did nothing at all.
        self.action_edit_entry()

    @on(Input.Submitted, "#manifest-output-dir")
    def _on_output_dir(self, event: Input.Submitted) -> None:
        self._commit_output_dir(event.value.strip() or "./evidence")

    @on(Input.Blurred, "#manifest-output-dir")
    def _on_output_dir_blurred(self, event: Input.Blurred) -> None:
        # Commit on blur as well as enter: an edit that was never submitted got
        # silently reverted by the next rebuild(). A cleared field is left alone
        # (that's an empty field, not a request for the default).
        if event.value.strip():
            self._commit_output_dir(event.value.strip())

    def _commit_output_dir(self, value: str) -> None:
        if self._manifest is None or value == (self._run().get("output_dir") or ""):
            return  # blur fires on every focus change; only a real change commits
        api.set_output_dir(self._manifest, value)
        self._autosave()
        self.notify("Output dir updated.")
        self.rebuild()

    def _stack_label(self) -> str:
        block = self._run().get("paramify") or {}
        return str(block.get("stack_name") or block.get("stack") or "—")

    @on(Button.Pressed, "#manifest-stack")
    def _on_stack(self) -> None:
        self.action_pick_stack()

    def action_pick_stack(self) -> None:
        """Choose the Paramify stack uploads go to.

        With a token the choice is a list read from the workspace (id and name
        stored). Without one there is nothing to list, so the value is typed and
        stored as the stack alone.
        """
        m = self._manifest
        if m is None:
            return
        # upload_readiness loads `.env` first, as list_stacks does: a token kept
        # only there must not drop the picker to typed, unchecked text.
        if api.upload_readiness(self.app.root_path)["token_present"]:
            self._pick_stack_online(m)
        else:
            self._type_stack(m)

    @work(thread=True, exclusive=True, group="stacks")
    def _pick_stack_online(self, m: dict) -> None:
        try:
            stacks = api.list_stacks(self.app.root_path)
        except Exception as exc:
            self.app.call_from_thread(self.notify, f"Could not list stacks: {exc}", severity="error")
            return
        self.app.call_from_thread(self._show_stack_picker, m, stacks)

    def _show_stack_picker(self, m: dict, stacks: List[dict]) -> None:
        names = {s["id"]: s["name"] for s in stacks}

        def done(choice: Optional[str]) -> None:
            if choice is None:
                return
            api.set_stack(m, choice, names.get(choice))
            self._autosave()
            self.notify("Stack updated.")
            self.rebuild()

        self.app.push_screen(
            PickerModal("Paramify stack", [(s["id"], f"{s['name']}  ({s['id']})") for s in stacks]),
            done,
        )

    def _type_stack(self, m: dict) -> None:
        current = (self._run().get("paramify") or {}).get("stack") or ""
        spec = {"key": "stack", "label": "stack", "kind": "text", "value": current,
                "placeholder": "stack id or name", "required": False,
                "help": "no API token: the value is stored as typed"}

        def done(result: Optional[dict]) -> None:
            if result is None:
                return
            value = (result.get("stack") or {}).get("stack")
            if value and value != current:
                api.set_stack(m, value)
                self._autosave()
                self.notify("Stack updated.")
                self.rebuild()

        self.app.push_screen(
            FormModal("Paramify stack", {"stack": [spec]},
                      subtitle="Set a token to pick from the workspace's stacks."),
            done,
        )

    @on(Button.Pressed, "#manifest-owner")
    def _on_owner(self) -> None:
        self.action_pick_owner()

    def action_pick_owner(self) -> None:
        """Choose whose channel uploads use when a stack has one channel per owner.

        With a token the choice is a list of the owners of the workspace's
        channels. Without one the username is typed and stored as given.
        """
        m = self._manifest
        if m is None:
            return
        if api.upload_readiness(self.app.root_path)["token_present"]:
            self._pick_owner_online(m)
        else:
            self._type_owner(m)

    @work(thread=True, exclusive=True, group="owners")
    def _pick_owner_online(self, m: dict) -> None:
        try:
            owners = api.list_channel_owners(self.app.root_path)
        except Exception as exc:
            self.app.call_from_thread(self.notify, f"Could not list channel owners: {exc}", severity="error")
            return
        self.app.call_from_thread(self._show_owner_picker, m, owners)

    def _set_owner(self, m: dict, owner: Optional[str]) -> None:
        api.set_owner(m, owner)
        self._autosave()
        self.notify("Owner updated." if owner else "Owner removed.")
        self.rebuild()

    def _show_owner_picker(self, m: dict, owners: List[dict]) -> None:
        def done(choice: Optional[str]) -> None:
            if choice is not None:
                self._set_owner(m, None if choice == _NO_OWNER else choice)

        options = [(o["owner"], f"{o['owner']}  ({o['sets']} evidence set{'s' if o['sets'] != 1 else ''})")
                   for o in owners]
        if (self._run().get("paramify") or {}).get("owner"):
            options.append((_NO_OWNER, "(no owner)"))
        self.app.push_screen(
            PickerModal("Paramify channel owner", options,
                        subtitle="Used only where a stack has one channel per owner."),
            done,
        )

    def _type_owner(self, m: dict) -> None:
        current = (self._run().get("paramify") or {}).get("owner") or ""
        spec = {"key": "owner", "label": "owner", "kind": "text", "value": current,
                "placeholder": "Paramify username", "required": False,
                "help": "no API token: the value is stored as typed; blank removes it"}

        def done(result: Optional[dict]) -> None:
            if result is None:
                return
            value = ((result.get("owner") or {}).get("owner") or "").strip()
            if value != current:
                self._set_owner(m, value or None)

        self.app.push_screen(
            FormModal("Paramify channel owner", {"owner": [spec]},
                      subtitle="Set a token to pick from the workspace's channel owners."),
            done,
        )

    @on(Button.Pressed, "#btn-save")
    def _on_btn_save(self) -> None:
        self.action_save()

    # -- actions ---------------------------------------------------------- #

    def action_add_fetcher(self) -> None:
        # Fetchers are added from the catalog above, on the same page.
        self.post_message(FocusCatalog())

    def add_fetchers(self, names: List[str]) -> List[str]:
        """Add fetchers to the manifest and return the names added.

        A comparator brings its inputs with it. Each added fetcher's entry-level
        secrets are wired to their suggested env var names: the default is almost
        always correct, so the edit form is only needed where a name differs.
        (Per-target secrets are not wired: each target usually needs its own
        credential.) The table cursor moves to the last fetcher asked for.
        """
        m = self._manifest
        if m is None or not names:
            return []
        descriptors = self._descriptors()
        try:
            fetchers = api.discover(self.app.root_path)["fetchers"]
        except Exception:  # never let a discovery failure kill the UI
            fetchers = {}
        added = [a for name in names for a in api.add_entry(m, name, fetchers)]
        wired = False
        for name in added:
            d = descriptors.get(name)
            for s in (d or {}).get("secrets", []):
                if not s.get("per_target") and s.get("env"):
                    api.set_secret(m, name, s["name"], s["env"])
                    wired = True
        # Both: rebuild keeps the old row while _selected_key still names one.
        self._selected = self._selected_key = names[-1]
        self._autosave()
        self.rebuild()
        if added:
            asked = [n for n in names if n in added]
            inputs = len(added) - len(asked)
            message = f"Added {', '.join(asked) or ', '.join(added)}"
            if asked and inputs:
                message += f" + {inputs} input{'s' if inputs != 1 else ''}"
            if wired:
                message += " — secrets wired to default env vars (e to change)."
            self.notify(message)
        return added

    def in_manifest(self) -> set:
        """The fetchers the manifest uses."""
        return {str(e.get("use")) for e in self._entries() if e.get("use")}

    def select(self, use: str) -> None:
        """Move the table cursor to the entry for `use`."""
        dt = self.query_one("#manifest-entries", DataTable)
        try:
            row = dt.get_row_index(use)
        except Exception:
            return
        self._selected = self._selected_key = use
        dt.move_cursor(row=row)
        self._refresh_detail()

    def action_edit_entry(self) -> None:
        use, m = self._selected, self._manifest
        if not use or m is None:
            return
        d = self._descriptors().get(use)
        if d is None:
            self.notify("Unknown fetcher — cannot edit.", severity="warning")
            return
        # Every write below targets this exact entry, not the first with this fetcher.
        ekey = self._selected_entry_key()
        entry = next((e for k, e in self._keyed() if k == ekey), None) or self._entry(use)
        cfg = entry.get("config") or {}
        secs = entry.get("secrets") or {}
        category = d.get("category")
        config_specs = [self._patterns_spec(c, cfg, m, category) if c.get("type") == patterns.TYPE
                        else self._config_spec(c, cfg.get(c["name"])) for c in d.get("config", [])]
        lists = {c["name"] for c in d.get("config", []) if c.get("type") == patterns.TYPE}
        secret_specs = [
            {
                "key": s["name"], "label": s["name"], "kind": "secret",
                # Prefill with the current reference if set, else the fetcher's
                # suggested env var name (the documented default).
                "value": env_name_from_ref(secs.get(s["name"])) or (s.get("env") or ""),
                "placeholder": s.get("env") or "", "required": True, "help": "",
            }
            for s in d.get("secrets", []) if not s.get("per_target")
        ]
        pf = entry.get("paramify") or {}
        paramify_specs = [
            {"key": "stack", "label": "stack", "kind": "text", "value": pf.get("stack"),
             "placeholder": "inherit", "required": False, "help": "stack id or name; blank inherits"},
            {"key": "owner", "label": "owner", "kind": "text", "value": pf.get("owner"),
             "placeholder": "inherit", "required": False,
             "help": "Paramify username; picks the channel when a stack has one per owner; blank inherits"},
            {"key": "approval", "label": "approval", "kind": "select", "value": pf.get("approval") if pf.get("approval") in APPROVALS else None,
             "options": [(v, v) for v in APPROVALS], "required": False, "help": "blank inherits"},
            {"key": "no_request", "label": "no_request", "kind": "select", "value": pf.get("no_request") if pf.get("no_request") in NO_REQUESTS else None,
             "options": [(v, v) for v in NO_REQUESTS], "required": False, "help": "blank inherits"},
            {"key": "delivery", "label": "delivery", "kind": "select", "value": pf.get("delivery") if pf.get("delivery") in DELIVERIES else None,
             "options": [(v, v) for v in DELIVERIES], "required": False, "help": "blank inherits"},
        ]
        groups = {"config": config_specs, "secrets": secret_specs, "paramify": paramify_specs}

        def done(result: Optional[dict]) -> None:
            if result is None:
                return
            for k, v in (result.get("config") or {}).items():
                if k in lists:
                    api.set_pattern_list(m, use, k, patterns.parse(v)[0], category, entry_key=ekey)
                else:
                    api.set_fetcher_config(m, use, k, v, entry_key=ekey)
            for name, env in (result.get("secrets") or {}).items():
                api.set_secret(m, use, name, env, entry_key=ekey)
            self._set_entry_paramify(entry, result.get("paramify") or {})
            self._autosave()
            self.rebuild()
            self.notify(f"Updated {use}.")

        # Entry level only. 104 of the 138 fanout fetchers declare no entry
        # config, so for those this form is nothing but secrets — indistinguishable
        # from the target editor failing to open unless it says where targets live.
        # Short enough to survive the card width — a subtitle that clips takes the
        # targets pointer with it, which is the half that answers "why is this
        # form only secrets?". The ENV-VAR rule is also on the secrets group label.
        subtitle = "Secrets take the ENV VAR NAME, not the value."
        if d.get("supports_targets"):
            # Leads, and the secrets note is trimmed to fit beside it: the card
            # clips rather than wraps, and this is the half that answers "why is
            # this form only secrets?". The ENV-VAR rule is also on the group label.
            subtitle = "Targets: press 't'.   ·   Secrets take the ENV VAR NAME."
        self.app.push_screen(
            FormModal(f"Edit {use} — entry config and secrets", groups, subtitle=subtitle),
            done,
        )

    def _keyed(self) -> List[tuple]:
        entries = self._entries()
        return list(zip(entry_keys([ManifestEntry(use=str(e.get("use", "?"))) for e in entries]), entries))

    def _set_entry_paramify(self, entry: dict, values: dict) -> None:
        """Write the entry's `paramify` block from the form; a blank field removes its key."""
        block = dict(entry.get("paramify") or {})
        for key in ("stack", "owner", "approval", "no_request", "delivery"):
            if values.get(key):
                block[key] = values[key]
            else:
                block.pop(key, None)
        if block.get("stack") != (entry.get("paramify") or {}).get("stack"):
            block.pop("stack_name", None)  # a name belongs to the id it was stored with
        if block:
            entry["paramify"] = block
        else:
            entry.pop("paramify", None)

    def action_edit_targets(self) -> None:
        """Open the fanout targets of the selected fetcher as an editable table.

        A fanout fetcher runs once per target, so the targets are the run plan.
        The page only ever showed their count, and there was no way to change one
        — a typo meant removing the target and retyping every field.
        """
        use, m = self._selected, self._manifest
        if not use or m is None:
            return
        d = self._descriptors().get(use)
        if not d or not d.get("supports_targets"):
            self.notify("This fetcher does not support targets.", severity="warning")
            return
        key = self._selected_entry_key()  # the selected entry, not the first with this fetcher

        fields = [t["name"] for t in d.get("target_schema", [])]
        per_target_secrets = [s for s in d.get("secrets", []) if s.get("per_target")]

        def rows() -> List[List[str]]:
            out = []
            for t in (self._keyed_entry(key).get("targets") or []):
                row = [_cell(t.get(f)) for f in fields]
                if per_target_secrets:
                    wired = len(t.get("secrets") or {})
                    row.append(f"{wired}/{len(per_target_secrets)}" if wired else "—")
                out.append(row)
            return out

        columns = [*fields] + (["secrets"] if per_target_secrets else [])
        self.app.push_screen(
            TargetsModal(
                f"Targets — {use}",
                columns,
                rows,
                on_add=self.action_add_target,
                on_edit=lambda i: self._edit_target(use, i, key),
                on_remove=lambda i: self._remove_target_at(use, i, key),
                subtitle="the fetcher runs once per target",
            )
        )

    def _edit_target(self, use: str, index: int, key: Optional[str] = None) -> None:
        m = self._manifest
        d = self._descriptors().get(use) or {}
        targets = self._keyed_entry(key or use).get("targets") or []
        if m is None or not 0 <= index < len(targets):
            return
        current = targets[index]
        current_secrets = current.get("secrets") or {}
        value_specs = [
            self._config_spec(t, current.get(t["name"])) for t in d.get("target_schema", [])
        ]
        secret_specs = [
            {
                "key": s["name"], "label": s["name"], "kind": "secret",
                "value": env_name_from_ref(current_secrets.get(s["name"])) or (s.get("env") or ""),
                "placeholder": s.get("env") or "", "required": True, "help": "",
            }
            for s in d.get("secrets", []) if s.get("per_target")
        ]

        def done(result: Optional[dict]) -> None:
            if result is None:
                return
            api.set_target(
                m, use, index,
                result.get("values") or {},
                secret_env=(result.get("secrets") or None),
                entry_key=key,
            )
            self._autosave()
            self.rebuild()
            self.notify(f"Updated target {index} of {use}.")

        self.app.push_screen(
            FormModal(
                f"Edit target {index} — {use}",
                {"values": value_specs, "secrets": secret_specs},
                subtitle="target fields + per-target secrets",
            ),
            done,
        )

    def _remove_target_at(self, use: str, index: int, key: Optional[str] = None) -> None:
        m = self._manifest
        if m is None:
            return
        summary = _target_summary((self._keyed_entry(key or use).get("targets") or [])[index])

        def done(ok: bool) -> None:
            if ok:
                api.remove_target(m, use, index, entry_key=key)
                self._autosave()
                self.rebuild()
                self.notify(f"Removed target {index} from {use}.")

        self.app.push_screen(ConfirmModal(f"Remove target {index} ({summary}) from '{use}'?"), done)

    def action_add_target(self) -> None:
        use, m = self._selected, self._manifest
        if not use or m is None:
            return
        d = self._descriptors().get(use)
        if not d or not d.get("supports_targets"):
            self.notify("This fetcher does not support targets.", severity="warning")
            return
        value_specs = [self._config_spec(t, None) for t in d.get("target_schema", [])]
        secret_specs = [
            {
                "key": s["name"], "label": s["name"], "kind": "secret", "value": "",
                "placeholder": s.get("env") or "", "required": True, "help": "",
            }
            for s in d.get("secrets", []) if s.get("per_target")
        ]
        groups = {"values": value_specs, "secrets": secret_specs}

        def done(result: Optional[dict]) -> None:
            if result is None:
                return
            values = result.get("values") or {}
            api.add_target(m, use, values, secret_env=(result.get("secrets") or None),
                           entry_key=self._selected_entry_key())
            self._autosave()
            self.rebuild()
            # api.validate() does not check required target fields, so warn here:
            # an empty/invalid required field would otherwise be dropped silently.
            missing = [
                t["name"]
                for t in d.get("target_schema", [])
                if t.get("required") and t.get("default") is None and t["name"] not in values
            ]
            if missing:
                self.notify(
                    f"Target added — required field(s) still unset: {', '.join(missing)}",
                    severity="warning",
                )
            else:
                self.notify(f"Added target to {use}.")

        self.app.push_screen(
            FormModal(f"Add target to {use}", groups, subtitle="target fields + per-target secrets"),
            done,
        )

    def action_pick_assessment(self) -> None:
        """Point the selected issue-report entry at a Paramify assessment.

        The TUI equivalent of `paramify assessments select`, and the same reason
        the program picker exists: the manifest needs an assessment UUID, and
        nobody should be typing one. Filtered to the assessment type the fetcher
        declares, so a CSPM report is never offered a vulnerability assessment.

        This is the one manifest action that needs the network, so a workspace
        that cannot be reached reports why instead of opening an empty picker.
        """
        use, m = self._selected, self._manifest
        if not use or m is None:
            # Silence here read as a broken key on a new, empty manifest.
            self.notify("Add a scan report first (a), then select it.",
                        severity="warning")
            return
        d = self._descriptors().get(use)
        if not d or kinds.kind_of(d) != kinds.SCAN_REPORT:
            self.notify(
                "Only scan reports go to an assessment; evidence goes to the "
                "evidence set its fetcher names.", severity="warning"
            )
            return

        assessment_type = (d.get("issue_report") or {}).get("assessment_type")
        self.notify("Loading assessments…")
        self._assessments_worker(use, assessment_type)

    @work(thread=True, exclusive=True, group="assessments")
    def _assessments_worker(self, use: str, assessment_type: Optional[str]) -> None:
        # Off the UI thread: listing assessments is a network call, and a slow or
        # unreachable workspace froze the whole app while it ran.
        try:
            assessments = api.list_assessments(assessment_type)
        except (RuntimeError, ValueError) as exc:
            self.app.call_from_thread(
                self.notify, f"Cannot list assessments: {exc}", severity="error", timeout=12
            )
            return
        self.app.call_from_thread(self._show_assessment_picker, use, assessment_type, assessments)

    def _show_assessment_picker(
        self, use: str, assessment_type: Optional[str], assessments: List[dict]
    ) -> None:
        m = self._manifest
        if m is None:
            return
        if not assessments:
            scope = f" of type {assessment_type}" if assessment_type else ""
            self.notify(f"No assessments{scope} in this workspace.", severity="warning")
            return

        by_id = {a["id"]: a for a in assessments}
        options = []
        for a in assessments:
            bits = [b for b in (a.get("frequency"), a.get("mechanism_name")) if b]
            note = f"  ({', '.join(bits)})" if bits else ""
            options.append((a["id"], f"{api.assessment_display_name(a)}{note}"))

        def done(chosen_id: Optional[str]) -> None:
            if chosen_id is None:
                return
            chosen = by_id[chosen_id]
            api.set_assessment(m, use, chosen)
            self._autosave()
            self.rebuild()
            # Asked right after the assessment because it is a fact about how
            # that assessment's cycles are filled, and the uploader will not
            # guess it. Escape keeps the assessment and leaves the policy as it was.
            self._pick_close_cycle(use, api.assessment_display_name(chosen))

        self.app.push_screen(
            PickerModal(
                f"Assessment for {use}",
                options,
                subtitle=f"{assessment_type or 'any type'} — the scan report is sent to this assessment's pipeline",
            ),
            done,
        )

    def _pick_close_cycle(self, use: str, assessment_label: str) -> None:
        m = self._manifest
        if m is None:
            return
        options = [
            (CLOSE_AFTER_RUN,
             "after_run — one report per cycle: close after each complete run"),
            (CLOSE_NEVER,
             "never — several files per cycle: close in Paramify or with "
             "`paramify issues close`"),
        ]

        def done(policy: Optional[str]) -> None:
            if policy is None:
                self.notify(f"{use} → {assessment_label}")
                return
            api.set_close_cycle(m, use, policy)
            self._autosave()
            self.rebuild()
            self.notify(f"{use} → {assessment_label}, close_cycle={policy}")

        self.app.push_screen(
            PickerModal(
                f"How is {assessment_label}'s cycle closed?",
                options,
                subtitle="Closing auto-closes every open issue the cycle never saw",
            ),
            done,
        )

    def action_remove_entry(self) -> None:
        use, m = self._selected, self._manifest
        if not use or m is None:
            return
        # Only the selected entry; another entry of the same fetcher stays.
        key = self._selected_entry_key()

        def done(ok: bool) -> None:
            if ok:
                api.remove_entry(m, use, entry_key=key)
                self._selected = None
                self._autosave()
                self.rebuild()
                self.notify(f"Removed {use}.")

        self.app.push_screen(ConfirmModal(f"Remove '{use}' from the manifest?"), done)

    def _autosave(self) -> None:
        """Write the manifest through after a mutation.

        Edits used to live in memory until 's', so quitting — or a crash, or
        simply not knowing the key — discarded them with nothing on screen to say
        the file and the view had diverged. Saving on every mutation removes the
        divergence instead of trying to surface it.

        A save that cannot happen keeps the change in memory and says so: a
        manifest the schema refuses or a path that will not take a write is worth
        reporting, but not worth throwing away the edit that triggered it. 's'
        retries once the cause is fixed.
        """
        m = self._manifest
        if m is None:
            return
        try:
            api.dump_manifest(m, self.app.manifest_path, self.app.root_path)
        except Exception as exc:  # noqa: BLE001 — every failure keeps the edit
            self.notify(
                f"Change not saved: {exc} — fix, then press 's'.",
                severity="error",
                timeout=12,
            )

    def action_save(self) -> None:
        m = self._manifest
        if m is None:
            return
        try:
            api.dump_manifest(m, self.app.manifest_path, self.app.root_path)
        except ValueError as exc:
            self.notify(f"Cannot save: {exc}", severity="error", timeout=12)
            return
        except Exception as exc:
            self.notify(f"Save failed: {exc}", severity="error", timeout=12)
            return
        self.notify(f"Saved → {self.app.manifest_path}")

    def action_validate(self) -> None:
        self.rebuild()
        n = len(self._errors)
        self.notify("Manifest is runnable." if n == 0 else f"{n} issue(s) — see the detail pane.")

    def action_preview(self) -> None:
        if self._manifest is None:
            return
        text = yaml.safe_dump(self._manifest, sort_keys=False, default_flow_style=False)
        self.app.push_screen(PreviewModal(text, title=str(self.app.manifest_path)))

    # -- focus ------------------------------------------------------------ #

    def focus_default(self) -> None:
        self.query_one("#manifest-entries", DataTable).focus()
