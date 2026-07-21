"""Modal dialogs for the manifest editor.

Each follows the Bagels write-path idiom (reimplemented, not copied): a
ModalScreen that collects input and returns a result via dismiss(), which the
caller's push_screen callback maps onto framework.api mutators.

  FormModal        -> dict of {group: {key: value}}   (edit entry / add target / platform)
  PickerModal      -> str (the chosen option id) or None
  MultiPickerModal -> list[str] (the chosen option ids) or None
  ConfirmModal     -> bool
  PreviewModal     -> None (read-only YAML view)
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, Static, Tree
from textual.widgets.option_list import Option

from framework.tui.components.forms import FieldRow


class FormModal(ModalScreen[dict]):
    """Render grouped field specs; return {group: {key: typed value}} on save.

    Empty optional fields are omitted from the result (so we never write blanks);
    booleans are always included.
    """

    # Friendlier section headings; the dict key stays the result key.
    GROUP_LABELS = {
        "config": "config",
        "secrets": "secrets  ·  enter the ENV VAR NAME, not the value",
        "values": "target fields",
    }

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
    ]

    def __init__(self, title: str, groups: Dict[str, List[dict]], subtitle: str = "") -> None:
        super().__init__()
        self._title = title
        self._subtitle = subtitle
        self._groups = groups

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card"):
            yield Label(self._title, id="modal-title")
            if self._subtitle:
                yield Label(self._subtitle, id="modal-subtitle")
            with VerticalScroll(id="modal-body"):
                any_fields = False
                for gname, fields in self._groups.items():
                    if not fields:
                        continue
                    any_fields = True
                    yield Label(self.GROUP_LABELS.get(gname, gname), classes="group-label")
                    for spec in fields:
                        yield FieldRow(spec, group=gname)
                if not any_fields:
                    yield Static("Nothing to configure for this fetcher.", classes="dim")
            with Horizontal(id="modal-buttons"):
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        # .first() raises NoMatches on an empty query, so guard with the count —
        # a form can legitimately have no fields (nothing to configure).
        rows = self.query(FieldRow)
        if rows:
            rows.first().query_one("#field-input").focus()

    @on(Button.Pressed, "#save")
    def action_save(self) -> None:
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


class PickerModal(ModalScreen[str]):
    """A filterable single-choice list. Returns the chosen option id, or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, options: List[Tuple[str, str]], subtitle: str = "") -> None:
        # options: list of (id, label)
        super().__init__()
        self._title = title
        self._subtitle = subtitle
        self._options = options

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card"):
            yield Label(self._title, id="modal-title")
            if self._subtitle:
                yield Label(self._subtitle, id="modal-subtitle")
            yield Input(placeholder="filter…", id="picker-filter")
            yield OptionList(id="picker-list")

    def on_mount(self) -> None:
        self._populate("")
        self.query_one("#picker-filter", Input).focus()

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

    def action_cancel(self) -> None:
        self.dismiss(None)


class _PickTree(Tree):
    """A Tree where space behaves like enter, so both route through NodeSelected
    and the modal's single handler can decide: toggle a leaf's checkbox or
    expand/collapse a category. auto_expand is left off (set on the instance) so
    the only thing that opens a platform is an explicit select/click."""

    BINDINGS = [Binding("space", "select_cursor", "Toggle", show=False)]


class MultiPickerModal(ModalScreen[list]):
    """A filterable multi-select catalog: collapsible per-platform dropdowns of
    checkbox leaves on the left, a live list of everything checked on the right.
    Returns the chosen ids (platform-grouped order), or None.

    The checked set is the source of truth; leaf labels and the right pane are
    rendered from it, so filtering (which rebuilds the tree) never drops a pick.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "confirm", "Add"),
    ]

    def __init__(
        self, title: str, groups: List[Tuple[str, List[str]]], subtitle: str = ""
    ) -> None:
        # groups: ordered [(platform, [fetcher_name, ...]), ...] — categories as
        # the catalog sorts them; only non-already-added fetchers.
        super().__init__()
        self._title = title
        self._subtitle = subtitle
        self._groups = groups
        self._cat_of = {name: cat for cat, names in groups for name in names}
        self._all_ids = [name for _, names in groups for name in names]
        self._chosen: set = set()

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card", classes="multi-pick"):
            yield Label(self._title, id="modal-title")
            if self._subtitle:
                yield Label(self._subtitle, id="modal-subtitle")
            with Horizontal(id="multi-pick-split"):
                with Vertical(id="multi-pick-left"):
                    yield Input(placeholder="filter…", id="multi-pick-filter")
                    yield _PickTree("platforms", id="multi-pick-tree")
                with VerticalScroll(id="multi-pick-right"):
                    yield Static("selected", classes="panel-title")
                    yield Static(id="multi-pick-chosen")
            with Horizontal(id="modal-buttons"):
                yield Button("Add 0 selected", variant="primary", id="confirm")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        tree = self.query_one("#multi-pick-tree", _PickTree)
        tree.show_root = False
        tree.auto_expand = False
        self._populate("")
        self._refresh_chosen()
        self.query_one("#multi-pick-filter", Input).focus()

    def _leaf_label(self, name: str) -> Text:
        # A Rich Text (not a markup string) — "[x]" would otherwise be parsed as
        # a console-markup tag and vanish. Lets us tint the checked marker too.
        checked = name in self._chosen
        label = Text()
        label.append("[x] " if checked else "[ ] ", style="green" if checked else "dim")
        label.append(name)
        return label

    def _populate(self, flt: str) -> None:
        tree = self.query_one("#multi-pick-tree", _PickTree)
        tree.clear()
        flt = flt.strip().lower()
        for cat, names in self._groups:
            matches = [n for n in names if not flt or flt in n.lower()]
            if not matches:
                continue
            # Filtering opens the platforms with hits; otherwise stay collapsed
            # so a long catalog reads as a tidy list of platforms to open.
            node = tree.root.add(f"{cat}  ({len(matches)})", expand=bool(flt))
            for name in matches:
                node.add_leaf(self._leaf_label(name), data=name)

    @on(Input.Changed, "#multi-pick-filter")
    def _filter(self, event: Input.Changed) -> None:
        self._populate(event.value)

    @on(Tree.NodeSelected, "#multi-pick-tree")
    def _on_select(self, event: Tree.NodeSelected) -> None:
        node = event.node
        name = node.data
        if name is None:  # a platform row → open/close the dropdown
            node.toggle()
            return
        if name in self._chosen:
            self._chosen.discard(name)
        else:
            self._chosen.add(name)
        node.set_label(self._leaf_label(name))
        self._refresh_chosen()

    def _refresh_chosen(self) -> None:
        chosen = self.query_one("#multi-pick-chosen", Static)
        btn = self.query_one("#confirm", Button)
        n = len(self._chosen)
        btn.label = f"Add {n} selected"
        btn.disabled = n == 0
        if not self._chosen:
            chosen.update(Text("(nothing selected yet)", style="dim"))
            return
        body = Text()
        # Walk the original (platform-grouped) order so the picked list mirrors
        # the catalog's grouping, not a/z by name.
        for name in self._all_ids:
            if name not in self._chosen:
                continue
            body.append("• ", style="green")
            body.append(name)
            body.append(f"   [{self._cat_of.get(name, '?')}]\n", style="dim")
        chosen.update(body)

    @on(Button.Pressed, "#confirm")
    def action_confirm(self) -> None:
        if not self._chosen:
            return
        # Return in platform-grouped order so manifest entries keep the grouping.
        self.dismiss([name for name in self._all_ids if name in self._chosen])

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmModal(ModalScreen[bool]):
    """A yes/no confirmation. Returns True on confirm, False otherwise."""

    BINDINGS = [
        Binding("escape", "no", "No"),
        Binding("n", "no", "No"),
        Binding("y", "yes", "Yes"),
    ]

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-card", classes="confirm"):
            yield Label(self._message, id="modal-title")
            with Horizontal(id="modal-buttons"):
                yield Button("Yes", variant="error", id="yes")
                yield Button("No", variant="primary", id="no")

    @on(Button.Pressed, "#yes")
    def action_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def action_no(self) -> None:
        self.dismiss(False)


class PreviewModal(ModalScreen[None]):
    """Read-only scrollable view of the manifest YAML."""

    BINDINGS = [Binding("escape,q,p", "close", "Close")]

    def __init__(self, text: str, title: str = "manifest preview") -> None:
        super().__init__()
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
