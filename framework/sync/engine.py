"""The plan/apply loop.

`plan()` asks each provider, in `runs_after` order, what it wants and what it
sees, and collects the actions. `apply()` runs them in plan order:

- a `refuse` action is a planned result and is never applied;
- every other action (`noop` included) goes to its provider's `apply`;
- each `Ref` in an action's payload is replaced with the matching field of an
  earlier outcome; if that action did not apply (or was a no-op), the action
  is skipped;
- an exception with a true `fatal` attribute, or a failure of an action marked
  `on_failure="stop"`, skips every action after it; any other exception fails
  only that action.

This module is generic: it must not import an API client.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Dict, List, Optional, Sequence

from framework.sync.model import Action, Outcome, Plan, Provider, Ref, SyncContext

_COMPLETED = ("applied", "noop")

Event = Callable[[dict], None]


class _Unresolved(Exception):
    """A Ref points at an action that did not complete."""

    def __init__(self, action_id: str) -> None:
        super().__init__(f"skipped: {action_id} did not complete")


class _MissingField(Exception):
    """A Ref names a field its action's result does not have (a provider bug)."""


def order(providers: Sequence[Provider]) -> List[Provider]:
    """Providers sorted so each runs after the ones named in its `runs_after`.

    A name in `runs_after` that is not among `providers` is ignored. Among
    providers with no constraint between them, input order is kept.
    """
    names = {p.name for p in providers}
    pending = list(providers)
    done: set[str] = set()
    result: List[Provider] = []
    while pending:
        ready = next(
            (p for p in pending if all(n in done for n in p.runs_after if n in names)),
            None,
        )
        if ready is None:
            stuck = ", ".join(p.name for p in pending)
            raise ValueError(f"providers have a runs_after cycle: {stuck}")
        pending.remove(ready)
        done.add(ready.name)
        result.append(ready)
    return result


def plan(providers: Sequence[Provider], ctx: SyncContext, reader: Any) -> Plan:
    """Read-only: collect every provider's actions, in provider order."""
    actions: List[Action] = []
    for provider in order(providers):
        desired = provider.desired(ctx)
        observed = provider.observe(desired, reader)
        actions.extend(provider.diff(desired, observed))
    return Plan(actions=actions)


def _resolver(outcomes: Dict[str, Outcome]) -> Callable[[Any], Any]:
    def resolve(value: Any) -> Any:
        if isinstance(value, Ref):
            done = outcomes.get(value.action_id)
            if done is None or done.status not in _COMPLETED:
                raise _Unresolved(value.action_id)
            if value.field not in done.result:
                raise _MissingField(f"{value.action_id} has no result field {value.field!r}")
            return done.result[value.field]
        if isinstance(value, dict):
            return {k: resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [resolve(v) for v in value]
        if isinstance(value, tuple):
            return tuple(resolve(v) for v in value)
        return value

    return resolve


def _run_one(
    action: Action,
    providers: Dict[str, Provider],
    resources: Any,
    resolve: Callable[[Any], Any],
) -> tuple[Outcome, Optional[BaseException]]:
    """Run one action. The second value is the exception that stops the run, if any."""
    if action.verb == "refuse":
        return Outcome(action.id, "refused", message=action.fix or ""), None
    provider = providers.get(action.provider)
    if provider is None:
        return Outcome(action.id, "failed", message=f"no provider named {action.provider}"), None
    try:
        resolved = replace(action, payload=resolve(action.payload))
        return provider.apply(resolved, resources, resolve), None
    except _Unresolved as exc:
        return Outcome(action.id, "skipped", message=str(exc)), None
    except Exception as exc:  # any other provider error fails only its action
        outcome = Outcome(action.id, "failed", message=str(exc))
        return outcome, (exc if getattr(exc, "fatal", False) else None)


def apply(
    plan: Plan,
    providers: Sequence[Provider],
    resources: Any,
    on_event: Optional[Event] = None,
) -> List[Outcome]:
    """Apply the plan. Returns one Outcome per action, in plan order."""
    emit: Event = on_event or (lambda _event: None)
    by_name = {p.name: p for p in providers}
    by_id: Dict[str, Outcome] = {}
    resolve = _resolver(by_id)
    outcomes: List[Outcome] = []
    stopped: Optional[str] = None

    for action in plan.actions:
        if stopped is not None:
            outcome = Outcome(action.id, "skipped", message=f"stopped: {stopped}")
        else:
            emit({"event": "action_start", "action_id": action.id})
            outcome, fatal = _run_one(action, by_name, resources, resolve)
            if fatal is not None:
                stopped = str(fatal)
            elif outcome.status == "failed" and action.on_failure == "stop":
                stopped = outcome.message
        by_id[action.id] = outcome
        outcomes.append(outcome)
        emit({
            "event": "action_end",
            "action_id": action.id,
            "status": outcome.status,
            "message": outcome.message,
        })
    return outcomes
