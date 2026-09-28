"""Deriving an Implementation Date from the Paramify audit log.

PROBE REQUIRED before trusting this against a live workspace
------------------------------------------------------------
`/audit-logs` is absent from the published OpenAPI document, so its record shape
is known only from the API reference UI. The documented example shows

    "action": {"verb": "UPDATE", "changes": [{"old": "Open", "new": "Closed"}]}

with **no field name on the change entry**. If that is the whole shape, an
implementation-status change is not directly distinguishable from a rename.

Rather than guess, two resolution strategies run in order and the one that
succeeded is recorded on every result:

  1. `field` — a change entry carries a field-name key naming the status field.
  2. `value` — no field name is present, so the change is identified by its
     `new` value being a member of Paramify's implementation-status vocabulary.
     Inferential but sound: those tokens appear in no other field.

Neither succeeding yields UNRESOLVED, which is reported and leaves the date
blank. It never guesses a date, because a wrong Implementation Date propagates
into Purview as an assessment fact.

Run `run.py --probe-audit` to dump the real record shape (keys only, no values)
and pin the candidates below.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from config import PARAMIFY_STATUSES
from mapping import parse_iso8601

#: PROBE-GATED — candidate keys naming which field a change entry refers to.
FIELD_NAME_KEYS = ("field", "fieldName", "attribute", "property", "name", "key")

#: PROBE-GATED — values of the above that mean "implementation status".
STATUS_FIELD_NAMES = {
    "implementationstatus",
    "implementation_status",
    "implementation status",
    "status",
}

#: PROBE-GATED — `resource.type` values that mean a solution capability.
SOLCAP_RESOURCE_TYPES = {
    "SOLUTION_CAPABILITY",
    "SOLUTIONCAPABILITY",
    "SOLUTION CAPABILITY",
    "SOLCAP",
}

#: The status vocabulary, in both the API's enum spelling and a display spelling,
#: used by the value-matching strategy.
_STATUS_TOKENS = {s.upper() for s in PARAMIFY_STATUSES} | {
    s.replace("_", " ").upper() for s in PARAMIFY_STATUSES
} | {s.replace("_", "").upper() for s in PARAMIFY_STATUSES}


@dataclass
class DateResolution:
    """When a capability's implementation status last changed, and how we know."""

    timestamp: Optional[datetime]
    status_from_audit: Optional[str]
    method: str  # "field" | "value" | "unresolved"
    event_id: Optional[str] = None
    detail: Optional[str] = None


UNRESOLVED = DateResolution(None, None, "unresolved", None, "no status-change event found")


def _get_ci(obj: dict[str, Any], name: str) -> Any:
    for key, value in obj.items():
        if str(key).lower() == name.lower():
            return value
    return None


def is_status_token(value: Any) -> bool:
    """Whether a change value looks like an implementation-status enum member."""
    text = str(value or "").strip().upper()
    return bool(text) and text in _STATUS_TOKENS


def resource_is_solcap(event: dict[str, Any]) -> bool:
    resource = event.get("resource") or {}
    kind = str(_get_ci(resource, "type") or "").strip().upper()
    return kind in SOLCAP_RESOURCE_TYPES


def resource_id(event: dict[str, Any]) -> Optional[str]:
    resource = event.get("resource") or {}
    value = _get_ci(resource, "id")
    return str(value) if value else None


def status_change_in(event: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Find an implementation-status change on one event.

    Returns (new_status, method) or (None, None) when the event does not carry one.
    """
    action = event.get("action") or {}
    changes = _get_ci(action, "changes") or []
    if isinstance(changes, dict):
        changes = [changes]

    # Strategy 1: an explicit field name.
    for change in changes:
        if not isinstance(change, dict):
            continue
        for key in FIELD_NAME_KEYS:
            named = _get_ci(change, key)
            if named and str(named).strip().lower() in STATUS_FIELD_NAMES:
                new = _get_ci(change, "new")
                if new:
                    return str(new), "field"

    # Strategy 2: the values themselves are status tokens.
    #
    # BOTH sides must qualify (or `old` be empty, for a first transition out of
    # nothing). Observed Paramify change entries are exactly
    # {"old": "NOT_SET", "new": "IMPLEMENTED"} — so requiring the pair costs
    # nothing real and removes the strategy's one false positive: with no field
    # name on a change entry, any field edited TO the literal text of a status
    # token would otherwise be read as a status transition.
    for change in changes:
        if not isinstance(change, dict):
            continue
        new = _get_ci(change, "new")
        if not is_status_token(new):
            continue
        old = _get_ci(change, "old")
        if old in (None, "") or is_status_token(old):
            return str(new), "value"

    return None, None


def index_by_capability(events: list[dict[str, Any]]) -> dict[str, DateResolution]:
    """Most recent implementation-status change per solution capability.

    The audit log is documented newest-first, but that is not relied on: every
    candidate event is compared by timestamp so an out-of-order page cannot
    produce a stale date.
    """
    best: dict[str, DateResolution] = {}
    for event in events:
        if not isinstance(event, dict) or not resource_is_solcap(event):
            continue
        rid = resource_id(event)
        if not rid:
            continue
        new_status, method = status_change_in(event)
        if not new_status:
            continue
        stamp = parse_iso8601(event.get("timestamp"))
        if stamp is None:
            continue
        current = best.get(rid)
        if current is None or (current.timestamp and stamp > current.timestamp):
            best[rid] = DateResolution(
                timestamp=stamp,
                status_from_audit=new_status,
                method=method,
                event_id=str(event.get("id") or "") or None,
            )
    return best


def probe_shape(events: list[dict[str, Any]], sample: Optional[int] = None,
                include_values: bool = False) -> dict[str, Any]:
    """Structural inventory of the audit log.

    Keys, counts and distributions — never field values, unless `include_values`
    is set, and then only SHORT ones (status enums are short; narratives are
    not), so a probe can be pasted into a review without leaking prose.

    Counts run over EVERY fetched event by default rather than a sample. A
    sample of the newest 40 is exactly what hides the diagnosis this is for: a
    freshly copied workspace's most recent events are all CREATE, which looks
    identical to a workspace that simply has no recent edits.
    """
    scanned = events if sample is None else events[:sample]
    verbs: Counter = Counter()
    resource_types: Counter = Counter()
    top: set[str] = set()
    resource_keys: set[str] = set()
    action_keys: set[str] = set()
    change_keys: set[str] = set()
    with_changes = 0
    solcap_events = 0
    solcap_with_changes = 0
    values: Counter = Counter()

    for event in scanned:
        if not isinstance(event, dict):
            continue
        top |= set(event)
        resource = event.get("resource") or {}
        is_solcap = False
        if isinstance(resource, dict):
            resource_keys |= set(resource)
            kind = str(resource.get("type") or "")
            if kind:
                resource_types[kind] += 1
            is_solcap = kind.strip().upper() in SOLCAP_RESOURCE_TYPES
        solcap_events += int(is_solcap)

        action = event.get("action") or {}
        if not isinstance(action, dict):
            continue
        action_keys |= set(action)
        if action.get("verb"):
            verbs[str(action["verb"])] += 1
        changes = action.get("changes") or []
        changes = changes if isinstance(changes, list) else [changes]
        entries = [c for c in changes if isinstance(c, dict)]
        if entries:
            with_changes += 1
            solcap_with_changes += int(is_solcap)
        for change in entries:
            change_keys |= set(change)
            if include_values and is_solcap:
                for side in ("old", "new"):
                    value = change.get(side)
                    text = "" if value is None else str(value)
                    # Short values only: status enums are short, prose is not.
                    if text and len(text) <= 40:
                        values[f"{side}={text}"] += 1

    shape = {
        "events_scanned": len(scanned),
        "event_keys": sorted(top),
        "resource_keys": sorted(resource_keys),
        "resource_type_counts": dict(resource_types.most_common()),
        "action_keys": sorted(action_keys),
        "action_verb_counts": dict(verbs.most_common()),
        "change_entry_keys": sorted(change_keys),
        "change_entry_has_field_name": bool(
            {k.lower() for k in change_keys} & {k.lower() for k in FIELD_NAME_KEYS}
        ),
        "events_carrying_changes": with_changes,
        "solution_capability_events": solcap_events,
        "solution_capability_events_with_changes": solcap_with_changes,
        "diagnosis": _diagnose(len(scanned), with_changes, solcap_events,
                               solcap_with_changes),
    }
    if include_values:
        shape["solution_capability_change_values"] = dict(values.most_common(40))
    return shape


def _diagnose(total: int, with_changes: int, solcap: int, solcap_changes: int) -> str:
    """Say plainly what the numbers mean for deriving an Implementation Date."""
    if total == 0:
        return "no audit events were returned at all"
    if with_changes == 0:
        return (
            "every event is a creation with no field changes. This workspace has no "
            "modification history — the usual cause is that it was recently COPIED or "
            "imported, which recreates every record fresh and leaves the original "
            "status history behind in the source workspace. No Implementation Date or "
            "Status can be derived here; use the workspace where the status changes "
            "actually happened, or make a status change and re-run to test the mechanism."
        )
    if solcap == 0:
        return "no SOLUTION_CAPABILITY events at all; status changes are not recorded here"
    if solcap_changes == 0:
        return (
            "solution capabilities appear, but none of their events carry field "
            "changes — so no status transition is recoverable"
        )
    return (
        f"{solcap_changes} solution-capability event(s) carry field changes; "
        "run with --probe-values to see what those values look like"
    )
