"""Declarative form rows — a Textual reimplementation of the Bagels Fields/Field
idea, switching on a field descriptor's kind instead of copying Bagels source.

A field spec is a plain dict:
    {
        "key":         str,          # the config/secret/target key
        "label":       str,          # display label (defaults to key)
        "kind":        "text" | "int" | "bool" | "secret" | "select",
        "options":     [(label, value), ...]   # select only; blank is always allowed
        "value":       initial value (str/int/bool/None),
        "placeholder": str,          # e.g. a default or the suggested env var
        "required":    bool,
        "help":        str,          # one-line description
    }

`kind == "secret"` is a text input that collects an ENV VAR NAME (never a
secret value); the caller turns it into a ${env:VAR} reference via api.set_secret.
"""

from __future__ import annotations

from typing import Any, Optional

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, Label, Select, Switch

from framework.secret_resolver import env_var_name

# Select.BLANK was renamed Select.NULL; 8.0 only knows the old name.
_NULL = getattr(Select, "NULL", getattr(Select, "BLANK", None))


def env_name_from_ref(ref: Optional[str]) -> str:
    """'${env:FOO}' -> 'FOO'. Returns the raw string for anything else, '' for None.

    Delegates to secret_resolver so the form prefills the same name the runner
    will look up. The loose startswith/endswith test this used to do accepted
    '${env:foo}', which the runner rejects.
    """
    if not ref:
        return ""
    return env_var_name(ref) or str(ref)


class FieldRow(Vertical):
    """A labelled input for one field spec. Read the typed value with get_value()."""

    def __init__(self, spec: dict, group: str = "") -> None:
        super().__init__(classes="field-row")
        self.spec = spec
        self.group = group

    def compose(self) -> ComposeResult:
        spec = self.spec
        kind = spec.get("kind", "text")
        head = spec.get("label") or spec["key"]
        req = " [b red]*[/]" if spec.get("required") else ""
        help_text = spec.get("help") or ""

        if kind == "secret":
            # Make it unmistakable: this field holds the NAME of an env var, not
            # the credential itself.
            yield Label(f"{head}{req}", classes="field-label")
            note = "the env var NAME — not the secret value; the runner reads the value from it at run time"
            if help_text:
                note = f"{note}  ·  {help_text}"
            yield Label(note, classes="field-note")
        else:
            suffix = f"  [dim]{help_text}[/]" if help_text else ""
            yield Label(f"{head}{req}{suffix}", classes="field-label")

        if kind == "bool":
            yield Switch(value=bool(spec.get("value")), id="field-input")
        elif kind == "select":
            # Blank is a choice: it means "unset", and the caller drops the key.
            yield Select(
                [(label, val) for label, val in spec.get("options", [])],
                value=spec.get("value") or _NULL,
                prompt=spec.get("placeholder") or "inherit",
                allow_blank=True,
                id="field-input",
            )
        else:
            value = spec.get("value")
            yield Input(
                value="" if value is None else str(value),
                placeholder=spec.get("placeholder", ""),
                type="integer" if kind == "int" else "text",
                id="field-input",
            )

    def get_value(self) -> Any:
        kind = self.spec.get("kind", "text")
        if kind == "bool":
            return self.query_one(Switch).value
        if kind == "select":
            value = self.query_one(Select).value
            return None if value is _NULL or value == _NULL else value
        raw = self.query_one(Input).value.strip()
        if raw == "":
            return None
        if kind == "int":
            try:
                return int(raw)
            except ValueError:
                return None
        return raw
