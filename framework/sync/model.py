"""Data model for the plan/apply engine.

A provider compares what a run wants with what it can see and returns
`Action`s. The engine applies them in order and records one `Outcome` each.
Nothing here knows about a particular API.

There is no delete verb. An update that replaces a collection must call
`ensure_superset` first, so it can add items but never remove them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Protocol

Verb = Literal["create", "update", "link", "tag", "deliver", "noop", "refuse"]
Status = Literal["applied", "noop", "failed", "skipped", "refused"]
OnFailure = Literal["stop", "continue"]


class Unknown:
    """A value that cannot be read before apply. There is one instance: `UNKNOWN`."""

    _instance: Optional["Unknown"] = None

    def __new__(cls) -> "Unknown":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "unknown"

    def __reduce__(self) -> Any:
        return (Unknown, ())


UNKNOWN = Unknown()


@dataclass(frozen=True)
class Ref:
    """The field `field` of the result of an earlier action, known only after it applies."""

    action_id: str
    field: str


@dataclass
class Action:
    id: str  # "<provider>/<key>"; events refer to it
    provider: str
    key: str
    verb: Verb
    summary: str
    changes: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    fix: Optional[str] = None  # for `refuse` only: what the user must do
    on_failure: OnFailure = "continue"
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Outcome:
    action_id: str
    status: Status
    result: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


def _encode(value: Any) -> Any:
    if isinstance(value, Ref):
        return {"$ref": [value.action_id, value.field]}
    if isinstance(value, Unknown):
        return {"$unknown": True}
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode(v) for v in value]
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$ref"}:
            action_id, ref_field = value["$ref"]
            return Ref(action_id, ref_field)
        if value == {"$unknown": True}:
            return UNKNOWN
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


@dataclass
class Plan:
    actions: List[Action] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        """Plain JSON data; Refs become {"$ref": [id, field]}, UNKNOWN {"$unknown": true}."""
        return {
            "actions": [
                {
                    "id": a.id,
                    "provider": a.provider,
                    "key": a.key,
                    "verb": a.verb,
                    "summary": a.summary,
                    "changes": _encode(a.changes),
                    "warnings": list(a.warnings),
                    "fix": a.fix,
                    "on_failure": a.on_failure,
                    "payload": _encode(a.payload),
                }
                for a in self.actions
            ],
            "notes": list(self.notes),
        }

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Plan":
        return cls(
            actions=[
                Action(
                    id=a["id"],
                    provider=a["provider"],
                    key=a["key"],
                    verb=a["verb"],
                    summary=a["summary"],
                    changes=_decode(a.get("changes", {})),
                    warnings=list(a.get("warnings", [])),
                    fix=a.get("fix"),
                    on_failure=a.get("on_failure", "continue"),
                    payload=_decode(a.get("payload", {})),
                )
                for a in data.get("actions", [])
            ],
            notes=list(data.get("notes", [])),
        )


def ensure_superset(observed: set, desired: set) -> None:
    """Raise ValueError if `desired` would drop anything in `observed`."""
    removed = observed - desired
    if removed:
        names = ", ".join(sorted(repr(x) if not isinstance(x, str) else x for x in removed))
        raise ValueError(f"this update would remove {names}; the engine never removes data")


@dataclass
class SyncContext:
    run_dir: Optional[Path]
    upload_cfg: Dict[str, Any]
    stack_override: Optional[str] = None
    only_file: Optional[str] = None
    # Typed per-provider options, keyed by provider name.
    options: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class Provider(Protocol):
    """One kind of workspace object. Only `apply` has side effects."""

    name: str
    runs_after: tuple[str, ...]  # provider names; the engine orders by this

    def desired(self, ctx: SyncContext) -> list: ...

    def observe(self, desired: list, reader: Any) -> dict: ...

    def diff(self, desired: list, observed: dict) -> List[Action]: ...

    def apply(self, action: Action, resources: Any, resolve: Callable[[Any], Any]) -> Outcome: ...
