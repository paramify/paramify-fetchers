"""Modal dialogs for the manifest editor.

Each follows the Bagels write-path idiom (reimplemented, not copied): a
ModalScreen that collects input and returns a result via dismiss(), which the
caller's push_screen callback maps onto framework.api mutators.

  FormModal        -> dict of {group: {key: value}}   (edit entry / add target / platform)
  PickerModal      -> str (the chosen option id) or None
  ConfirmModal     -> bool
  PreviewModal     -> None (read-only YAML view)
  EnvironmentModal -> None (which variables a run reads have a value; never the values)
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, List, Tuple

from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, Static, Tree
from textual.widgets.option_list import Option

from framework.tui import palette, render
from framework.tui.components.forms import FieldRow
from framework.tui.components.keys import (
    BUTTON_ROW_BINDINGS,
    FILTER_NAV_BINDINGS,
    ButtonRowNav,
    FilterListNav,
)
from framework.tui.components.table import DataTable
from framework.tui.words import agree, plural


class FormModal(ButtonRowNav, ModalScreen[dict]):
    """Render grouped field specs; return {group: {key: typed value}} on save.

    Empty optional fields are omitted from the result (so we never write blanks);
    booleans are always included.
    """

    # Friendlier section headings; the dict key stays the result key.
    GROUP_LABELS = {
        "config": "config",
        "secrets": "secrets  ·  env var names, not the values",
        "values": "target fields",
    }

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        *BUTTON_ROW_BINDINGS,
    ]

    def __init__(self, title: str, groups: Dict[str, List[dict]], subtitle: str = "",
                 save_label: str = "Save") -> None:
        super().__init__()
        self._title = title
        self._subtitle = subtitle
        self._groups = groups
        # "Next" where another step follows, so the form does not promise a save it does not make.
        self._save_label = save_label

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card"):
            yield Label(self._title, id="modal-title")
            if self._subtitle:
                yield Label(self._subtitle, id="modal-subtitle")
            with VerticalScroll(id="modal-body"):
                any_fields = False
                shown = [g for g, fields in self._groups.items() if fields]
                for gname, fields in self._groups.items():
                    if not fields:
                        continue
                    any_fields = True
                    # One section: the title already says what it is (secrets keep theirs: it says
                    # the fields take env var names).
                    if len(shown) > 1 or gname == "secrets":
                        yield Label(self.GROUP_LABELS.get(gname, gname), classes="group-label")
                    for spec in fields:
                        yield FieldRow(spec, group=gname)
                if not any_fields:
                    yield Static("Nothing to configure for this fetcher.", classes="dim")
            with Horizontal(id="modal-buttons"):
                yield Button(self._save_label, variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        # .first() raises NoMatches on an empty query, so guard with the count —
        # a form can legitimately have no fields (nothing to configure).
        rows = self.query(FieldRow)
        if rows:
            rows.first().query_one("#field-input").focus()

    @on(Button.Pressed, "#save")
    def action_save(self) -> None:
        for row in self.query(FieldRow):
            problems = row.problems()
            if problems:
                key = row.spec.get("label") or row.spec["key"]
                self.notify(f"{key}: {problems[0]}", severity="error")
                row.query_one("#field-input").focus()
                return
        result: Dict[str, dict] = {}
        for row in self.query(FieldRow):
            value = row.get_value()
            if value is None:
                continue
            result.setdefault(row.group, {})[row.spec["key"]] = value
        self.dismiss(result)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class PickerModal(FilterListNav, ModalScreen[str]):
    """A filterable single-choice list. Returns the chosen option id, or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel"), *FILTER_NAV_BINDINGS]
    FILTER_NAV = ("#picker-filter", "#picker-list")

    def __init__(self, title: str, options: List[Tuple[str, str]], subtitle: str = "",
                 notice: str = "") -> None:
        # options: list of (id, label). notice: why the list is short or empty
        # (no token, an API error), shown as a warning above it.
        super().__init__()
        self._title = title
        self._subtitle = subtitle
        self._options = options
        self._notice = notice

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card"):
            yield Label(self._title, id="modal-title")
            if self._subtitle:
                yield Label(self._subtitle, id="modal-subtitle")
            if self._notice:
                # Plain text: it can carry an API error body, and a "[" there is not markup.
                yield Static(Text(self._notice), id="picker-notice")
            yield Input(placeholder="filter…", id="picker-filter")
            yield OptionList(id="picker-list")

    def on_mount(self) -> None:
        self._populate("")
        if not (self._notice and len(self._options) <= 1):
            self.query_one("#picker-filter", Input).focus()
            return
        # A notice with one fallback choice: nothing to filter, so hide the box
        # and put enter on the choice.
        self.query_one("#picker-filter", Input).display = False
        ol = self.query_one("#picker-list", OptionList)
        ol.add_class("fallback")
        ol.highlighted = 0
        ol.focus()

    def _populate(self, flt: str) -> None:
        ol = self.query_one("#picker-list", OptionList)
        ol.clear_options()
        flt = flt.strip().lower()
        matches = [(oid, label) for oid, label in self._options if not flt or flt in label.lower()]
        if matches:
            ol.add_options([Option(label, id=oid) for oid, label in matches])
        else:
            ol.add_option(Option("no matches", disabled=True))

    @on(Input.Changed, "#picker-filter")
    def _filter(self, event: Input.Changed) -> None:
        self._populate(event.value)

    @on(OptionList.OptionSelected, "#picker-list")
    def _choose(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option_id)

    @on(Input.Submitted, "#picker-filter")
    def _submit(self, event: Input.Submitted) -> None:
        """Enter in the filter picks the highlighted option — or the only one
        left. Without this, Enter in the box did nothing, and the cursor that
        up/down had just moved could only be taken by tabbing into the list."""
        ol = self.query_one("#picker-list", OptionList)
        index = ol.highlighted
        if index is None and ol.option_count == 1:
            index = 0
        if index is None:
            return
        option = ol.get_option_at_index(index)
        if not option.disabled:
            self.dismiss(option.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class TargetsModal(ModalScreen[None]):
    """The fanout targets of one fetcher, as rows you can add to, edit, or remove.

    A fanout fetcher runs once per target, so the targets ARE the run plan — and
    until this existed the page showed only how many there were. Editing in
    particular had no path at all: fixing a typo'd subscription id meant removing
    the target and retyping every field.

    The modal renders and routes keys; the page owns the manifest and performs the
    api calls, same as everywhere else. Each action pushes its own screen (a form,
    a confirm) on top of this one, so rows are re-read on resume rather than being
    passed back and forth.
    """

    BINDINGS = [
        Binding("escape", "done", "Done"),
        Binding("a", "add", "Add"),
        Binding("e", "edit", "Edit"),
        Binding("x", "remove", "Remove"),
    ]

    def __init__(
        self,
        title: str,
        columns: List[str],
        get_rows,
        on_add,
        on_edit,
        on_remove,
        subtitle: str = "",
    ) -> None:
        super().__init__()
        self._title = title
        self._columns = columns
        self._get_rows = get_rows          # () -> List[List[str]], one row per target
        self._on_add = on_add              # () -> None
        self._on_edit = on_edit            # (index) -> None
        self._on_remove = on_remove        # (index) -> None
        self._subtitle = subtitle

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card", classes="wide"):
            yield Label(self._title, id="modal-title")
            if self._subtitle:
                yield Label(self._subtitle, id="modal-subtitle")
            yield DataTable(id="targets-table", cursor_type="row", zebra_stripes=True)
            yield Static("", id="targets-count")
            yield Static("a add    e edit    x remove    esc done", id="targets-keys")

    def on_mount(self) -> None:
        table = self.query_one("#targets-table", DataTable)
        table.add_columns("#", *self._columns)
        self._populate()
        table.focus()

    def on_screen_resume(self) -> None:
        """Re-read after a form or confirm above this one closes.

        The rows live in the manifest, which the page mutates — so the table is
        rebuilt from the source rather than tracking edits of its own.
        """
        self._populate()

    def _populate(self) -> None:
        table = self.query_one("#targets-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        rows = self._get_rows()
        for i, row in enumerate(rows):
            table.add_row(str(i), *row, key=str(i))
        if rows:
            table.move_cursor(row=min(cursor, len(rows) - 1))
        self.query_one("#targets-count", Static).update(
            plural(len(rows), "target") if rows else "No targets yet. Press a to add one."
        )

    def _index(self) -> int:
        table = self.query_one("#targets-table", DataTable)
        return table.cursor_row if table.row_count else -1

    def action_add(self) -> None:
        self._on_add()

    def action_edit(self) -> None:
        i = self._index()
        if i >= 0:
            self._on_edit(i)

    def action_remove(self) -> None:
        i = self._index()
        if i >= 0:
            self._on_remove(i)

    def action_done(self) -> None:
        self.dismiss(None)


class _PickTree(Tree):
    """A Tree where space behaves like enter, so both route through NodeSelected
    and the modal's single handler can decide: toggle a leaf's checkbox or
    expand/collapse a category. auto_expand is left off (set on the instance) so
    the only thing that opens a platform is an explicit select/click."""

    BINDINGS = [Binding("space", "select_cursor", "Toggle", show=False)]


class ConfirmModal(ButtonRowNav, ModalScreen[bool]):
    """A yes/no confirmation. Returns True on confirm, False otherwise."""

    # Yes is composed first, so the default AUTO_FOCUS ("*") put enter on the
    # destructive answer — this dialog gates deleting a manifest file, removing
    # an entry, and uploading to Paramify. Focus No: enter and escape both mean
    # no, y means yes.
    AUTO_FOCUS = "#no"

    BINDINGS = [
        Binding("escape", "no", "No"),
        Binding("n", "no", "No"),
        Binding("y", "yes", "Yes"),
        *BUTTON_ROW_BINDINGS,
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card", classes="confirm"):
            # Plain text: a message carries file names and API bodies, and a "[" in
            # one must show as itself, not be read as Rich markup.
            yield Label(Text(self._message), id="modal-title")
            with Horizontal(id="modal-buttons"):
                yield Button("Yes", variant="error", id="yes")
                yield Button("No", variant="primary", id="no")

    @on(Button.Pressed, "#yes")
    def action_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def action_no(self) -> None:
        self.dismiss(False)


class ReportModal(ButtonRowNav, ModalScreen[bool]):
    """Exactly what will be sent, and one question (from the error card, branch
    feat/tui-error-card). Lands on Back: sending to an AI service is opt-in."""

    AUTO_FOCUS = "#report-no"

    BINDINGS = [
        Binding("escape", "no", "Back"),
        Binding("n", "no", "Back"),
        Binding("y", "yes", "Yes"),
        *BUTTON_ROW_BINDINGS,
    ]

    def __init__(self, report: str, title: str, subtitle: str, question: str, yes_label: str) -> None:
        super().__init__()
        self._report, self._title, self._subtitle = report, title, subtitle
        self._question, self._yes_label = question, yes_label

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card", classes="wide"):
            yield Label(self._title, id="modal-title")
            yield Label(self._subtitle, id="modal-subtitle")
            with VerticalScroll(id="modal-body"):
                yield Static(self._report, id="preview-text", markup=False)
            yield Label(Text(self._question), id="report-question")
            with Horizontal(id="modal-buttons"):
                yield Button(f"{self._yes_label} (y)", variant="primary", id="report-yes")
                yield Button("Back (n)", id="report-no")

    @on(Button.Pressed, "#report-yes")
    def action_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#report-no")
    def action_no(self) -> None:
        self.dismiss(False)


class PreviewModal(ModalScreen[None]):
    """Read-only scrollable view of the manifest YAML."""

    BINDINGS = [Binding("escape,q,p", "close", "Close")]

    def __init__(self, text: str, title: str = "manifest preview", close_keys: str = "escape,q,p") -> None:
        super().__init__()
        if close_keys != "escape,q,p":
            self._bindings = self._bindings.copy()
            self._bindings.bind(close_keys, "close", "Close")
        self._text = text
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card", classes="wide"):
            yield Label(self._title, id="modal-title")
            with VerticalScroll(id="modal-body"):
                # markup off: YAML / evidence JSON contains '[' which would
                # otherwise be parsed as console-markup tags.
                yield Static(self._text, id="preview-text", markup=False)

    def action_close(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        # Clicking outside the card returns to the page (in addition to esc/q/p).
        if not self.query_one("#modal-card").region.contains(event.screen_x, event.screen_y):
            self.dismiss(None)


class EnvironmentModal(ButtonRowNav, ModalScreen[None]):
    """What the manifest still needs from the environment: the required variables
    with no value, split by whether they block a run or an upload.

    One action, as a button that is always there: add the missing names to .env
    as blank lines, for the user to fill in. Once they are written, the line above
    the buttons says so. Close (or esc) re-checks, since the manifest page reads
    the environment again when the view closes.

    Presence only: `read` and `write` return api.generate_env()'s dict, which
    holds names and notes and never a value, so nothing here can show, log or
    take one. Like TargetsModal it renders; the caller owns the api calls.
    `notice` says why it opened on its own (a run that stopped).
    """

    BINDINGS = [Binding("escape", "done", "Close"), *BUTTON_ROW_BINDINGS]

    def __init__(self, title: str, read: Callable[[], dict], write: Callable[[], dict], notice: str = "") -> None:
        super().__init__()
        self._title = title
        self._read = read
        self._write = write
        self._notice = notice
        self._env: dict = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card", classes="env"):
            yield Label("", id="modal-title")
            if self._notice:
                yield Static(Text(self._notice), id="env-notice")
            with VerticalScroll(id="modal-body"):
                yield Static("", id="env-list")
            yield Static("", id="env-unmapped")
            yield Static("", id="env-others")
            with Horizontal(id="modal-buttons"):
                yield Button("Add blank lines to .env", variant="primary", id="env-write")
                yield Button("Close", id="env-close")

    def on_mount(self) -> None:
        self._load(self._read)
        self.query_one("#env-write", Button).focus()

    def _load(self, how: Callable[[], dict]) -> bool:
        try:
            self._env = how()
        except Exception as exc:  # an unreadable .env, a manifest discovery can't read
            self.notify(f"Couldn't read the environment: {exc}", severity="error")
            return False
        self._paint()
        return True

    def _paint(self) -> None:
        variables = self._env.get("variables") or []
        missing = render.env_missing(variables)
        title = self.query_one("#modal-title", Label)
        if missing:
            title.update(f"{plural(len(missing), 'variable')} {agree(len(missing), 'needs', 'need')} a value")
        else:
            title.update(Text("✓ Everything this manifest needs is set.", style=palette.OK))
        if self._notice and not render.env_missing(variables, run=True):
            # The run that stopped would start now: its reason no longer holds.
            self.query_one("#env-notice", Static).display = False

        self.query_one("#modal-body", VerticalScroll).display = bool(missing)
        self.query_one("#env-list", Static).update(render.env_needed(variables))

        n_set = sum(1 for v in variables if v["set"])
        lines = []
        if missing and n_set:
            lines.append(f"{plural(n_set, 'other')} {agree(n_set, 'is', 'are')} set. ")
        where = Path(self._env.get("path") or ".env").name
        if self._env.get("text"):
            lines.append(f"The button adds the names to {where} with blank values; fill them in there.")
        elif missing:
            lines.append(f"Already written to {where} with blank values: fill them in there, "
                         "then open this again.")
        else:
            lines.append("Values are never shown here.")
        self.query_one("#env-others", Static).update(Text("".join(lines), style=palette.MUTED))

        unmapped = self._env.get("unmapped") or []
        line = self.query_one("#env-unmapped", Static)
        line.display = bool(unmapped)
        if unmapped:
            names = [f"{u['fetcher']} {u['secret']}" + (" (each target)" if u["per_target"] else "")
                     for u in unmapped]
            text = Text("Not mapped in the manifest yet, so a run stops on them: ", style=palette.WARN)
            text.append(", ".join(names), style="dim")
            line.update(text)

    @on(Button.Pressed, "#env-write")
    def action_write(self) -> None:
        before = self._env.get("path")
        if not self._load(self._write):
            return
        added = self._env.get("added") or []
        where = Path(self._env.get("path") or before or ".env").name
        # The write's result says what it added; read again so the view shows the
        # file as it is now (nothing left to add, so no button).
        self._load(self._read)
        if added:
            self.notify(f"Added {plural(len(added), 'blank line')} to {where}. Fill in the values there.")
        else:
            self.notify(f"Already written to {where}: nothing new to add.")

    @on(Button.Pressed, "#env-close")
    def action_done(self) -> None:
        self.dismiss(None)
