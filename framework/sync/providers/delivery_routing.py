"""The routing rules of delivery, as pure functions over observed API data.

- `resolve_channel`: which channel of the evidence set, by the entry's stack.
- `resolve_request`: which artifact request on that channel.
- `attribute`: which batch is this entry's for this run, found from the
  `run_id=` and `entry=` (or `fetcher=`) tokens in its artifacts' notes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Optional, Set, Tuple

from framework.paramify.resources import (
    Artifact,
    ArtifactRequest,
    Batch,
    Channel,
    EvidenceSet,
    Stack,
)
from framework.sync.providers.desired import EntryDesired

DONE = ("SUBMITTED", "APPROVED")


@dataclass(frozen=True)
class Refusal:
    message: str
    fix: str


@dataclass(frozen=True)
class DirectRoute:
    """The entry goes through the old upload route, not a batch."""
    reason: str


@dataclass(frozen=True)
class Attribution:
    mine: Optional[Batch]
    earlier_open: List[Tuple[Batch, str]]  # (batch, its run id)



def _stack_list(stacks: List[Stack]) -> str:
    return ", ".join(f"{s.name} ({s.id})" for s in stacks) or "none"


def stack_name(stack_id: str, stacks: List[Stack]) -> Optional[str]:
    return next((s.name for s in stacks if s.id == stack_id), None)


def _find_stack(wanted: str, stacks: List[Stack]) -> Stack | Refusal | None:
    """The stack with this id, else the one stack with this name. None: no such stack."""
    by_id = next((s for s in stacks if s.id == wanted), None)
    if by_id is not None:
        return by_id
    by_name = [s for s in stacks if s.name == wanted]
    if len(by_name) > 1:
        ids = ", ".join(s.id for s in by_name)
        return Refusal(f"stack name {wanted} matches more than one stack", f"use the stack id: {ids}")
    return by_name[0] if by_name else None


def resolve_channel(entry: EntryDesired, evidence: Optional[EvidenceSet], stacks: List[Stack]) -> Channel | Refusal | None:
    """The channel to deliver on; None means the evidence set itself (it has no channels)."""
    channels = list(evidence.channels) if evidence is not None else []
    ref = entry.reference_id
    if not channels:
        return None
    if len(channels) == 1:
        only = channels[0]
        if not entry.stack or entry.stack == only.stack_id:
            return only
        found = _find_stack(entry.stack, stacks)
        if isinstance(found, Refusal):
            return found
        if found is not None and found.id == only.stack_id:
            return only
        on = stack_name(only.stack_id, stacks) or only.stack_id
        says = found.name if found is not None else entry.stack
        return Refusal(
            f"{ref}'s only channel is on stack {on}; the manifest says {says}",
            f"set this entry's stack to {on}, or create a channel for stack {says} on {ref} in the app",
        )
    if entry.stack:
        found = _find_stack(entry.stack, stacks)
        if isinstance(found, Refusal):
            return found
        if found is None:
            return Refusal(
                f"stack {entry.stack} is not in this workspace",
                f"use one of the workspace's stacks: {_stack_list(stacks)}",
            )
        stack = found
    elif len(stacks) == 1:
        stack = stacks[0]
    else:
        return Refusal(
            f"{ref} has {len(channels)} channels and no stack is configured",
            "set a stack (paramify manifest set-stack, or paramify upload --stack); "
            f"stacks: {_stack_list(stacks)}",
        )
    on_stack = [c for c in channels if c.stack_id == stack.id]
    if not on_stack:
        return Refusal(
            f"{ref} has no channel on stack {stack.name}",
            f"create a channel for stack {stack.name} on {ref} in the app",
        )
    if len(on_stack) > 1:
        names = ", ".join(c.reference_id for c in on_stack)
        return Refusal(
            f"{ref} has {len(on_stack)} channels on stack {stack.name}: {names}",
            f"keep one channel for stack {stack.name} on {ref} in the app",
        )
    return on_stack[0]


def resolve_request(
    entry: EntryDesired,
    channel: Channel,
    requests: List[ArtifactRequest],
    current_ids: Set[str],
    today: date,
) -> ArtifactRequest | Refusal | DirectRoute | None:
    """The current request on the channel, else the latest past one.

    With none: `direct` returns a DirectRoute, `evidence` returns None (deliver at evidence level).
    """
    on_channel = [r for r in requests if r.channel_id == channel.id]
    current = [r for r in on_channel if r.id in current_ids]
    if current:
        return max(current, key=lambda r: (r.requested_date, r.due_date))
    past = [r for r in on_channel if r.requested_date <= today]
    if past:
        return max(past, key=lambda r: r.due_date)
    if entry.no_request == "evidence":
        return None
    if entry.no_request == "direct":
        return DirectRoute(f"{channel.reference_id} has no artifact request")
    return Refusal(
        f"no current or past artifact request on channel {channel.reference_id} of {entry.reference_id}",
        f"create an artifact request on {channel.reference_id} in the app, or remove no_request: refuse "
        "from this entry to send it direct",
    )


def note_tokens(note: str) -> List[str]:
    return note.split("; ")


def _token(tokens: List[str], key: str) -> Optional[str]:
    prefix = f"{key}="
    return next((t[len(prefix):] for t in tokens if t.startswith(prefix)), None)


def _of_entry(tokens: List[str], entry: EntryDesired) -> bool:
    """The note names this entry: `entry=<key>`, or for older notes `fetcher=<use>` when key == use."""
    if _token(tokens, "entry") is not None:
        return f"entry={entry.entry_key}" in tokens
    return entry.entry_key == entry.use and f"fetcher={entry.use}" in tokens


def own_batch_ids(artifacts: List[Artifact], entry: EntryDesired) -> List[str]:
    """Ids of the batches holding an artifact of this entry from this run, in first-seen order."""
    ids: List[str] = []
    for a in artifacts:
        tokens = note_tokens(a.note)
        if (a.batch_id and a.batch_id not in ids and entry.run_id
                and _token(tokens, "run_id") == entry.run_id and _of_entry(tokens, entry)):
            ids.append(a.batch_id)
    return ids


def delivered_before_batches(artifacts: List[Artifact], entry: EntryDesired) -> List[str]:
    """Names of this entry's files from this run that the pre-batch uploader sent (no batch id)."""
    names: List[str] = []
    for a in artifacts:
        tokens = note_tokens(a.note)
        if (not a.batch_id and a.original_file_name not in names and entry.run_id
                and _token(tokens, "run_id") == entry.run_id and _of_entry(tokens, entry)):
            names.append(a.original_file_name)
    return names


def delivered_files(artifacts: List[Artifact], entry: EntryDesired) -> List[str]:
    """Names of this entry's files from this run that are on the set, with or without a batch."""
    names: List[str] = []
    for a in artifacts:
        tokens = note_tokens(a.note)
        if (a.original_file_name not in names and entry.run_id
                and _token(tokens, "run_id") == entry.run_id and _of_entry(tokens, entry)):
            names.append(a.original_file_name)
    return names


def attribute(batches: List[Batch], artifacts: Dict[str, List[Artifact]], entry: EntryDesired) -> Attribution:
    """Which batch is this entry's for this run, and which of its batches from earlier runs are still open."""
    mine: List[Batch] = []
    earlier: List[Tuple[Batch, str]] = []
    for b in batches:
        arts = artifacts.get(b.id) or []
        if not arts:
            if entry.recorded_batch_id and b.id == entry.recorded_batch_id:
                mine.append(b)
            continue
        runs: List[str] = []
        for a in arts:
            tokens = note_tokens(a.note)
            run_id = _token(tokens, "run_id")
            if run_id is not None and _of_entry(tokens, entry) and run_id not in runs:
                runs.append(run_id)
        if entry.run_id and entry.run_id in runs:
            mine.append(b)
        elif runs and b.status == "OPEN":
            earlier.append((b, runs[0]))
    # A finished batch wins over an open one, so a stray duplicate never gets resumed.
    mine.sort(key=lambda b: 0 if b.status in DONE else 1)
    return Attribution(mine[0] if mine else None, earlier)


def stack_drift(entry: EntryDesired, stacks: List[Stack]) -> Optional[str]:
    if not entry.stack or entry.stack_name is None:
        return None
    s = next((s for s in stacks if s.id == entry.stack), None)
    if s is None or s.name == entry.stack_name:
        return None
    return f"stack {s.id} is now named {s.name} (manifest label: {entry.stack_name})"
