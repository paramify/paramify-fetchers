"""Plain-text views of a plan and of what applying it did.

The CLI prints these lines and the TUI shows them, so both say the same
thing. No colour codes: a front-end styles the lines if it wants to.
"""
from __future__ import annotations

from typing import Dict, List, Sequence

from framework.sync.model import Outcome, Plan

DELIVERY = "delivery"
_DELIVERY_VERBS = ("deliver", "noop", "refuse")
_OTHER_VERBS = ("create", "update", "link", "tag", "refuse")
# An outcome with no `state` in its result (the engine made it) reads by status.
_STATE_BY_STATUS: Dict[str, str] = {
    "applied": "applied", "noop": "noop", "failed": "failed", "skipped": "skipped", "refused": "refused",
}


def outcome_state(outcome: Outcome) -> str:
    """An entry's state: the provider's own `state`, else the engine's status."""
    state = outcome.result.get("state") if outcome.result else None
    return str(state) if state else _STATE_BY_STATUS.get(outcome.status, outcome.status)


def _key(action_id: str) -> str:
    return action_id.split("/", 1)[1] if "/" in action_id else action_id


def render_plan(plan: Plan) -> List[str]:
    """Actions grouped by provider in plan (engine) order, then one totals line."""
    lines: List[str] = [f"! {n}" for n in plan.notes]
    current = None
    for a in plan.actions:
        if a.provider != current:
            current = a.provider
            lines.append(a.provider)
        lines.append(f"  {a.verb} {a.key}: {a.summary}")
        lines.extend(f"    ! {w}" for w in a.warnings)
        if a.provider == DELIVERY:
            lines.extend(f"    ! dropped {d['original_file_name']}: {d['reason']}"
                         for d in a.payload.get("dropped") or [])
        if a.verb == "refuse" and a.fix:
            lines.append(f"    → fix: {a.fix}")
    lines.append(_totals(plan))
    return lines


def _totals(plan: Plan) -> str:
    delivery: List[str] = [a.verb for a in plan.actions if a.provider == DELIVERY]
    parts = [f"{delivery.count(v)} {v}" for v in _DELIVERY_VERBS]
    others = [a for a in plan.actions if a.provider != DELIVERY]
    for verb in _OTHER_VERBS:
        hits = [a for a in others if a.verb == verb]
        if not hits:
            continue
        if verb == "refuse":  # name whose, so it is not read as a delivery refusal
            for provider in dict.fromkeys(a.provider for a in hits):
                parts.append(f"{sum(a.provider == provider for a in hits)} refuse ({provider})")
        else:
            parts.append(f"{len(hits)} {verb}")
    return " · ".join(parts)


def render_outcomes(outcomes: Sequence[Outcome]) -> List[str]:
    """One line per delivery entry (state, batch, message), plus any other action that did not complete."""
    lines: List[str] = []
    for o in outcomes:
        state = outcome_state(o)
        if o.action_id.startswith(f"{DELIVERY}/"):
            batch = o.result.get("batch_reference") or o.result.get("batch_id") if o.result else None
            head = f"{state} {_key(o.action_id)}" + (f" {batch}" if batch else "")
        elif o.status in ("failed", "refused", "skipped"):
            head = f"{state} {o.action_id}"
        else:
            continue
        lines.append(f"{head}: {o.message}" if o.message else head)
    return lines
