"""Run the existing validator sync as one engine action, between evidence sets and delivery.

A new evidence set then has its validators before its first batch is
submitted. The sync itself is unchanged (`api.sync_validators`); this
provider only gives it a place in the plan.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional

from framework.sync.model import Action, Outcome, SyncContext

ACTION_KEY = "registry"
SYNC_FAILED = "validator sync had errors"


def _sets(n: int) -> str:
    return f"{n} evidence set" if n == 1 else f"{n} evidence sets"


class LegacyValidatorsProvider:
    name: str = "validators"
    runs_after: tuple[str, ...] = ("evidence_sets",)

    def __init__(
        self,
        root: Path,
        config_path: Optional[Path],
        reference_ids: Iterable[str],
        *,
        online: bool = True,
        custom_tags: bool = True,
        on_event: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._root = Path(root)
        self._config_path = config_path
        self._reference_ids = sorted(set(reference_ids))
        self._online = online
        self._custom_tags = custom_tags
        self._on_event = on_event

    def desired(self, ctx: SyncContext) -> list:
        return list(self._reference_ids)

    def observe(self, desired: list, reader: Any) -> dict:
        return {}  # the syncer reads what it needs when it runs

    def diff(self, desired: list, observed: dict) -> List[Action]:
        if not desired:
            return []  # no scope would make the syncer fall back to the whole registry
        return [Action(
            id=f"{self.name}/{ACTION_KEY}", provider=self.name, key=ACTION_KEY,
            verb="update" if self._online else "noop",
            summary=f"sync validators for {_sets(len(desired))}",
            payload={"reference_ids": list(desired)},
        )]

    def apply(self, action: Action, resources: Any, resolve: Callable[[Any], Any]) -> Outcome:
        if action.verb == "noop":
            return Outcome(action.id, "noop", message=action.summary)
        from framework import api  # api imports this module's caller; import at use

        summary = api.sync_validators(
            self._root,
            config_path=self._config_path,
            reference_ids=list(action.payload["reference_ids"]),
            dry_run=False,
            on_event=self._on_event,
            custom_tags=self._custom_tags,
        )
        if summary.get("ok", True):
            return Outcome(action.id, "applied", summary)
        return Outcome(action.id, "failed", summary, SYNC_FAILED)
