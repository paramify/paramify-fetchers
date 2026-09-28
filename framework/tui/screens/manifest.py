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
from framework.issue_reports import CLOSE_AFTER_RUN, CLOSE_NEVER
from framework.tui import palette, render
from framework.tui.components.forms import env_name_from_ref
from framework.tui.components.keys import BUTTON_ROW_BINDINGS, ButtonRowNav
from framework.tui.modals import (
    ConfirmModal,
    FormModal,
    MultiPickerModal,
    PickerModal,
    PreviewModal,
    TargetsModal,
)


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


class ManifestPage(ButtonRowNav, Vertical):
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

    def compose(self) -> ComposeResult:
        with Horizontal(id="manifest-top"):
            yield Static("output dir:", classes="inline-label")
            # select_on_focus off: Textual selects the whole value on focus, so
            # the first keystroke replaced the existing path wholesale.
            yield Input(placeholder="./evidence", id="manifest-output-dir", select_on_focus=False)
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
        # {use: merged config view}, rebuilt with the table (api.effective_config)
        self._config_view: Dict[str, List[dict]] = {}
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
        by_use = self._bucket_errors(self._errors, entries)
        try:
            self._config_view = api.effective_config(
                self._manifest, [e.get("use", "") for e in entries],
                self.app.root_path, **discovered,
            )
        except Exception:  # never let a config-merge failure kill the UI
            self._config_view = {}

        dt.clear()
        row_keys: List[str] = []
        for e in entries:
            use = e.get("use", "?")
            d = descriptors.get(use)
            fanout = bool(d and d.get("supports_targets"))
            sset, stot = self._secret_counts(d, e)
            cset, ctot = self._config_counts(self._config_view.get(use))
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
        detail.update(render.entry_detail(d, entry, errs, self._config_view.get(use)))

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
            self._autosave()
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
            hint = " — press 't' to edit its targets" if d.get("supports_targets") else ""
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

        fields = [t["name"] for t in d.get("target_schema", [])]
        per_target_secrets = [s for s in d.get("secrets", []) if s.get("per_target")]

        def rows() -> List[List[str]]:
            out = []
            for t in (self._entry(use).get("targets") or []):
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
                on_edit=lambda i: self._edit_target(use, i),
                on_remove=lambda i: self._remove_target_at(use, i),
                subtitle="the fetcher runs once per target",
            )
        )

    def _edit_target(self, use: str, index: int) -> None:
        m = self._manifest
        d = self._descriptors().get(use) or {}
        targets = self._entry(use).get("targets") or []
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

    def _remove_target_at(self, use: str, index: int) -> None:
        m = self._manifest
        if m is None:
            return
        summary = _target_summary((self._entry(use).get("targets") or [])[index])

        def done(ok: bool) -> None:
            if ok:
                api.remove_target(m, use, index)
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
            api.add_target(m, use, values, secret_env=(result.get("secrets") or None))
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
            return
        d = self._descriptors().get(use)
        if not d or d.get("kind") != "issue_report":
            self.notify(
                "Only issue-report fetchers go to an assessment.", severity="warning"
            )
            return

        assessment_type = (d.get("issue_report") or {}).get("assessment_type")
        try:
            assessments = api.list_assessments(assessment_type)
        except (RuntimeError, ValueError) as exc:
            self.notify(f"Cannot list assessments: {exc}", severity="error", timeout=12)
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
                subtitle=f"{assessment_type or 'any type'} — its reports are intaken here",
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

        def done(ok: bool) -> None:
            if ok:
                api.remove_entry(m, use)
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
