"""Manifest editor (Phase 2).

Edits the App's in-memory manifest dict entirely through framework.api: a
DataTable of entries on the left, a live contract/values detail on the right,
and an issues bar (api.validate) at the bottom. Every mutation goes through a
modal -> api.* mutator -> rebuild, mirroring the Bagels write path.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import yaml
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Input, Static

from framework import api
from framework.tui import palette, render
from framework.tui.components.forms import env_name_from_ref
from framework.tui.modals import (
    ConfirmModal,
    FormModal,
    MultiPickerModal,
    PickerModal,
    PreviewModal,
)


class ManifestPage(Vertical):
    HINTS = [
        ("a", "add"), ("e", "edit"), ("x", "remove"), ("t", "target"),
        ("s", "save"), ("v", "validate"), ("p", "preview"),
    ]

    BINDINGS = [
        Binding("a", "add_fetcher", "Add"),
        Binding("e", "edit_entry", "Edit"),
        Binding("x", "remove_entry", "Remove"),
        Binding("t", "add_target", "Add target"),
        Binding("T", "remove_target", "Rm target", show=False),
        Binding("s", "save", "Save"),
        Binding("v", "validate", "Validate"),
        Binding("p", "preview", "Preview"),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(id="manifest-top"):
            yield Static("output dir:", classes="inline-label")
            yield Input(placeholder="./evidence", id="manifest-output-dir")
            yield Button("Add fetcher", variant="primary", id="btn-add")
            yield Button("Save", id="btn-save")
        with Horizontal(id="manifest-body"):
            with Vertical(id="manifest-entries-panel", classes="panel"):
                yield DataTable(id="manifest-entries")
                yield Static("", id="manifest-empty-hint", classes="empty-hint")
            with VerticalScroll(id="manifest-detail-scroll", classes="panel"):
                yield Static(render.empty_detail("No fetcher selected."), id="manifest-detail")
        yield Static(id="manifest-issues")

    def on_mount(self) -> None:
        self._selected: Optional[str] = None
        self._errors: List[str] = []
        self.query_one("#manifest-entries-panel", Vertical).border_title = "fetchers"
        self.query_one("#manifest-detail-scroll", VerticalScroll).border_title = "detail"
        dt = self.query_one("#manifest-entries", DataTable)
        dt.cursor_type = "row"
        dt.zebra_stripes = True
        dt.add_columns("fetcher", "mode", "secrets", "config", "targets", "status")
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
            return

        out = self._run().get("output_dir", "") or ""
        odi = self.query_one("#manifest-output-dir", Input)
        if odi.value != out:
            odi.value = out

        descriptors = self._descriptors()
        entries = self._entries()
        try:
            self._errors = api.validate(self._manifest, self.app.root_path)
        except Exception as exc:  # never let a validation crash kill the UI
            self._errors = [f"validation error: {exc}"]
        by_use = self._bucket_errors(self._errors, entries)

        dt.clear()
        row_keys: List[str] = []
        for e in entries:
            use = e.get("use", "?")
            d = descriptors.get(use)
            fanout = bool(d and d.get("supports_targets"))
            sset, stot = self._secret_counts(d, e)
            cset, ctot = self._config_counts(d, e)
            ntargets = len(e.get("targets") or [])
            errs = by_use.get(use, [])
            status = palette.pill("✓", "ok") if not errs else palette.pill(f"⚠ {len(errs)}", "warn")
            dt.add_row(
                use,
                "fanout" if fanout else "single",
                f"{sset}/{stot}",
                f"{cset}/{ctot}",
                str(ntargets) if fanout else "—",
                status,
                key=use,
            )
            row_keys.append(use)

        self._set_empty(
            None
            if entries
            else f"manifest is empty — press [bold {palette.ACCENT}]a[/] to add fetchers"
        )

        # preserve selection across rebuilds
        if row_keys:
            target = self._selected if self._selected in row_keys else row_keys[0]
            self._selected = target
            try:
                dt.move_cursor(row=dt.get_row_index(target))
            except Exception:
                pass
        else:
            self._selected = None

        self._refresh_detail()
        self._set_issues(self._errors)

    def _set_empty(self, hint: Optional[str]) -> None:
        """Show the hatched placeholder (with the given message) instead of the
        entries table, or the table again when hint is None."""
        if hint:
            self.query_one("#manifest-empty-hint", Static).update(hint)
        self.query_one("#manifest-entries-panel", Vertical).set_class(bool(hint), "empty")

    def _refresh_detail(self) -> None:
        detail = self.query_one("#manifest-detail", Static)
        use = self._selected
        if not use or self._manifest is None:
            detail.update(render.empty_detail("No fetcher selected — press 'a' to add one."))
            return
        entry = self._entry(use)
        d = self._descriptors().get(use)
        # Bucket against the full entry list so index-prefixed (entry[i]) errors
        # attribute correctly, then take this entry's slice.
        errs = self._bucket_errors(self._errors, self._entries()).get(use, [])
        detail.update(render.entry_detail(d, entry, errs))

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
    def _config_counts(d: Optional[dict], e: dict) -> tuple:
        if not d:
            return (0, 0)
        fields = d.get("config", [])
        have = e.get("config") or {}
        return (sum(1 for f in fields if f["name"] in have), len(fields))

    @staticmethod
    def _bucket_errors(errors: List[str], entries: List[dict]) -> Dict[str, List[str]]:
        # api.validate() uses two prefix conventions: "<use>: ..." / "<use> ..."
        # for known entries, and "entry[<i>] uses unknown fetcher: <use>" for
        # undiscovered ones. Attribute both so an unknown-fetcher row never shows
        # a misleading ✓.
        uses = [e.get("use") for e in entries]
        out: Dict[str, List[str]] = {}
        for msg in errors or []:
            target = None
            if msg.startswith("entry[") and "]" in msg:
                try:
                    idx = int(msg[6 : msg.index("]")])
                except ValueError:
                    idx = -1
                if 0 <= idx < len(uses):
                    target = uses[idx]
            if target is None:
                for u in uses:
                    if u and (msg.startswith(f"{u}:") or msg.startswith(f"{u} ")):
                        target = u
                        break
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

    # -- events ----------------------------------------------------------- #

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._selected = event.row_key.value
        self._refresh_detail()

    @on(Input.Submitted, "#manifest-output-dir")
    def _on_output_dir(self, event: Input.Submitted) -> None:
        if self._manifest is None:
            return
        api.set_output_dir(self._manifest, event.value.strip() or "./evidence")
        self.notify("Output dir updated.")
        self.rebuild()

    @on(Button.Pressed, "#btn-add")
    def _on_btn_add(self) -> None:
        self.action_add_fetcher()

    @on(Button.Pressed, "#btn-save")
    def _on_btn_save(self) -> None:
        self.action_save()

    # -- actions ---------------------------------------------------------- #

    def action_add_fetcher(self) -> None:
        m = self._manifest
        if m is None:
            return
        existing = {e.get("use") for e in self._entries()}
        cat = getattr(self.app, "catalog_data", None)
        groups = []
        if cat:
            for c in cat["categories"]:
                # Pass every fetcher (not just addable ones): the picker shows the
                # already-added ones greyed out so a fully-added category — e.g.
                # datadog once all 13 are in — still appears instead of vanishing.
                names = [f["name"] for f in c["fetchers"]]
                if names:
                    groups.append((c["name"], names))
        if not groups:
            self.notify("No fetchers discovered.")
            return

        def done(names: Optional[List[str]]) -> None:
            if not names:
                return
            # Auto-wire each added fetcher's entry-level secrets to their suggested
            # env var names: the default is almost always correct, so the edit form
            # is only needed for the edge case where a name differs. (Per-target
            # secrets are not wired here — each target usually needs its own cred.)
            descriptors = self._descriptors()
            wired = False
            for name in names:
                api.add_entry(m, name)
                d = descriptors.get(name)
                if d:
                    for s in d.get("secrets", []):
                        if not s.get("per_target") and s.get("env"):
                            api.set_secret(m, name, s["name"], s["env"])
                            wired = True
            self._selected = names[-1]
            self.rebuild()
            n = len(names)
            noun = "fetcher" if n == 1 else "fetchers"
            if wired:
                self.notify(f"Added {n} {noun} — secrets wired to default env vars (e to change).")
            else:
                self.notify(f"Added {n} {noun}.")

        self.app.push_screen(
            MultiPickerModal(
                "Add fetchers",
                groups,
                subtitle="enter/space opens a platform or toggles a fetcher · ✓ = already in manifest · type to filter",
                disabled=existing,
            ),
            done,
        )

    def action_edit_entry(self) -> None:
        use, m = self._selected, self._manifest
        if not use or m is None:
            return
        d = self._descriptors().get(use)
        if d is None:
            self.notify("Unknown fetcher — cannot edit.", severity="warning")
            return
        entry = self._entry(use)
        cfg = entry.get("config") or {}
        secs = entry.get("secrets") or {}
        config_specs = [self._config_spec(c, cfg.get(c["name"])) for c in d.get("config", [])]
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
        if not config_specs and not secret_specs:
            hint = " — press 't' to add targets" if d.get("supports_targets") else ""
            self.notify(f"{use} has no entry-level config or secrets to edit{hint}.")
            return
        groups = {"config": config_specs, "secrets": secret_specs}

        def done(result: Optional[dict]) -> None:
            if result is None:
                return
            for k, v in (result.get("config") or {}).items():
                api.set_fetcher_config(m, use, k, v)
            for name, env in (result.get("secrets") or {}).items():
                api.set_secret(m, use, name, env)
            self.rebuild()
            self.notify(f"Updated {use}.")

        self.app.push_screen(
            FormModal(
                f"Edit {use}",
                groups,
                subtitle="Secret fields take the env var NAME (e.g. KNOWBE4_API_KEY), not the credential.",
            ),
            done,
        )

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
            api.add_target(m, use, values, secret_env=(result.get("secrets") or None))
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

    def action_remove_target(self) -> None:
        use, m = self._selected, self._manifest
        if not use or m is None:
            return
        targets = self._entry(use).get("targets") or []
        if not targets:
            self.notify("No targets to remove.")
            return
        options = []
        for i, t in enumerate(targets):
            vals = {k: v for k, v in t.items() if k != "secrets"}
            summary = "  ".join(f"{k}={v}" for k, v in vals.items()) or "(empty)"
            options.append((str(i), f"[{i}] {summary}"))

        def done(idx: Optional[str]) -> None:
            if idx is not None:
                api.remove_target(m, use, int(idx))
                self.rebuild()
                self.notify("Target removed.")

        self.app.push_screen(
            PickerModal(f"Remove target from {use}", options, subtitle="Pick a target to remove"),
            done,
        )

    def action_remove_entry(self) -> None:
        use, m = self._selected, self._manifest
        if not use or m is None:
            return

        def done(ok: bool) -> None:
            if ok:
                api.remove_entry(m, use)
                self._selected = None
                self.rebuild()
                self.notify(f"Removed {use}.")

        self.app.push_screen(ConfirmModal(f"Remove '{use}' from the manifest?"), done)

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
