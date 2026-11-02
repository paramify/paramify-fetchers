"""Deliver each manifest entry's files as one batch per run: the plan side.

For each entry, in this order (the first refusal ends the entry):

1. channel: by the evidence set's channels and the entry's stack;
2. artifact request on that channel: the current one, else the latest past one;
3. batch: this entry's batch for this run is found on the server, from the
   `run_id=` and `entry=` (or `fetcher=`) tokens in its artifacts' notes, so a
   second upload of a run resumes or skips it and never makes another;
4. WAF: a file the production WAF would block is dropped at plan time.

The rules are the pure functions `resolve_channel`, `resolve_request` and
`attribute`; `DeliveryProvider.diff` composes them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from framework.paramify.resources import (
    Artifact,
    ArtifactRequest,
    Batch,
    Channel,
    EvidenceSet,
    Stack,
)
from framework.sync.model import UNKNOWN, Action, Ref, SyncContext
from framework.sync.providers import waf
from framework.sync.providers.desired import (
    DeliveryFile,
    EntryDesired,
    artifact_content,
    desired_from_run,
    is_enveloped,
)
from framework.sync.state import RunState

DONE = ("SUBMITTED", "APPROVED")
EVIDENCE_LEVEL_WARNING = "evidence-level batch: does not count toward the solution capability"
ALL_DROPPED = "every file was dropped"


@dataclass(frozen=True)
class Refusal:
    message: str
    fix: str


@dataclass(frozen=True)
class Attribution:
    mine: Optional[Batch]
    earlier_open: List[Tuple[Batch, str]]  # (batch, its run id)


@dataclass
class EntryObserved:
    """What observe read for one entry. `evidence` is None when the set does not exist yet."""

    evidence: Optional[EvidenceSet]
    stacks: List[Stack] = field(default_factory=list)
    requests: List[ArtifactRequest] = field(default_factory=list)
    current_ids: Set[str] = field(default_factory=set)
    batches: List[Batch] = field(default_factory=list)
    artifacts: Dict[str, List[Artifact]] = field(default_factory=dict)  # batch id -> artifacts


# ---- routing rules --------------------------------------------------------- #

def _stack_list(stacks: List[Stack]) -> str:
    return ", ".join(f"{s.name} ({s.id})" for s in stacks) or "none"


def _stack_name(stack_id: str, stacks: List[Stack]) -> Optional[str]:
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
        if not entry.stack:
            return only
        found = _find_stack(entry.stack, stacks)
        if isinstance(found, Refusal):
            return found
        if found is not None and found.id == only.stack_id:
            return only
        on = _stack_name(only.stack_id, stacks) or only.stack_id
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
) -> ArtifactRequest | Refusal | None:
    """The current request on the channel, else the latest past one. None: deliver at evidence level."""
    on_channel = [r for r in requests if r.channel_id == channel.id]
    current = [r for r in on_channel if r.id in current_ids]
    if current:
        return max(current, key=lambda r: (r.requested_date, r.due_date))
    past = [r for r in on_channel if r.requested_date <= today]
    if past:
        return max(past, key=lambda r: r.due_date)
    if entry.no_request == "evidence":
        return None
    return Refusal(
        f"no current or past artifact request on channel {channel.reference_id} of {entry.reference_id}",
        f"create an artifact request on {channel.reference_id} in the app, or set no_request: evidence on "
        "this entry to deliver at the evidence level (it does not count toward the solution capability)",
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


@dataclass(frozen=True)
class _Route:
    channel: Optional[Channel]
    request: Optional[ArtifactRequest]  # None: deliver on the evidence set
    warning: Optional[str]


def _route(entry: EntryDesired, obs: EntryObserved, today: date) -> _Route | Refusal:
    """Steps 1 and 2: channel, then artifact request. A set that does not exist yet has no channels."""
    if obs.evidence is None:
        return _Route(None, None, None)
    channel = resolve_channel(entry, obs.evidence, obs.stacks)
    if channel is None or isinstance(channel, Refusal):
        return _Route(None, None, None) if channel is None else channel
    request = resolve_request(entry, channel, obs.requests, obs.current_ids, today)
    if isinstance(request, Refusal):
        return request
    if request is None:
        return _Route(channel, None, EVIDENCE_LEVEL_WARNING)
    late = None if request.id in obs.current_ids else (
        f"late submission to {request.reference_id} (due {request.due_date.isoformat()})")
    return _Route(channel, request, late)


def _open_warning(b: Batch, run_id: str, arts: List[Artifact], today: date) -> str:
    dates = []
    for a in arts:
        try:
            dates.append(date.fromisoformat(a.created_at[:10]))
        except ValueError:
            continue
    if not dates:
        return f"{b.reference_id} from run {run_id} is still open (age unknown)"
    return f"{b.reference_id} from run {run_id} has been open {_count((today - min(dates)).days, 'day')}"


def _stack_drift(entry: EntryDesired, stacks: List[Stack]) -> Optional[str]:
    if not entry.stack or entry.stack_name is None:
        return None
    s = next((s for s in stacks if s.id == entry.stack), None)
    if s is None or s.name == entry.stack_name:
        return None
    return f"stack {s.id} is now named {s.name} (manifest label: {entry.stack_name})"


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _file_json(f: DeliveryFile) -> Dict[str, str]:
    return {"path": str(f.path), "original_file_name": f.original_file_name, "title": f.title, "note": f.note}


# ---- provider -------------------------------------------------------------- #

class DeliveryProvider:
    name: str = "delivery"
    runs_after: tuple[str, ...] = ("evidence_sets", "validators")

    def __init__(self, run_state: Optional[RunState] = None, today: Callable[[], date] = date.today) -> None:
        self._run_state = run_state
        self._today = today
        self._payload_mode = "envelope"
        self._waf_hits: Dict[Tuple[str, str], List[str]] = {}
        self.entries: Dict[str, EntryDesired] = {}  # by entry key, for apply's re-plan

    # -- desired ---------------------------------------------------------- #
    def desired(self, ctx: SyncContext) -> list:
        mode = ctx.upload_cfg.get("artifact_payload", "envelope")
        if mode not in ("envelope", "payload"):
            raise ValueError(f"artifact_payload must be 'envelope' or 'payload', got {mode!r}")
        self._payload_mode = mode
        entries = desired_from_run(
            ctx.run_dir, ctx.upload_cfg, stack_override=ctx.stack_override, only_file=ctx.only_file
        ) if ctx.run_dir is not None else []
        self.entries = {e.entry_key: e for e in entries}
        return entries

    def _scan(self, f: DeliveryFile) -> List[str]:
        """WAF signatures in what the upload of `f` would send: the bytes, the note and the title."""
        key = (str(f.path), self._payload_mode)
        if key not in self._waf_hits:
            try:
                raw = f.path.read_bytes()
            except OSError:
                raw = b""  # gone since desired(); apply reports it
            try:
                envelope = json.loads(raw)
                content = artifact_content(envelope, self._payload_mode) if is_enveloped(envelope) else raw
            except ValueError:
                content = raw
            self._waf_hits[key] = waf.scan(content, f.note, f.title)
        return self._waf_hits[key]

    def _split(self, entry: EntryDesired) -> Tuple[List[DeliveryFile], List[Dict[str, str]], List[Dict[str, str]]]:
        """(sendable files, WAF drops, skipped files)."""
        files: List[DeliveryFile] = []
        dropped: List[Dict[str, str]] = []
        skipped: List[Dict[str, str]] = []
        for f in entry.files:
            if f.skip_reason:
                skipped.append({"original_file_name": f.original_file_name, "reason": f.skip_reason})
                continue
            hits = self._scan(f)
            if hits:
                found = ", ".join(f"'{s}' ({waf.RULES[s]})" for s in hits)
                dropped.append({
                    "original_file_name": f.original_file_name,
                    "reason": f"blocked by the production WAF: {found}",
                })
            else:
                files.append(f)
        return files, dropped, skipped

    # -- observe ---------------------------------------------------------- #
    def observe(self, desired: list, reader: Any) -> dict:
        if reader is None:
            return {e.entry_key: UNKNOWN for e in desired}
        # Same refs, same order as the evidence_sets provider, so the reader's memo answers.
        refs = list(dict.fromkeys(
            e.reference_id for e in desired if e.reference_id and any(f.skip_reason is None for f in e.files)
        ))
        sets = reader.evidence_by_reference(refs) if refs else {}
        return {
            e.entry_key: self._observe_entry(e, sets.get(e.reference_id), reader)
            for e in desired
            if self._split(e)[0]
        }

    def _observe_entry(self, e: EntryDesired, ev: Optional[EvidenceSet], reader: Any) -> EntryObserved:
        obs = EntryObserved(evidence=ev)
        if e.stack or (ev is not None and len(ev.channels) > 1):
            obs.stacks = reader.stacks()
        if ev is None:
            return obs  # created in this run: no batches yet
        channel = resolve_channel(e, ev, obs.stacks)
        if isinstance(channel, Refusal):
            return obs
        target: Optional[ArtifactRequest] = None
        if channel is not None:
            obs.requests = reader.artifact_requests(ev.id)
            obs.current_ids = {r.id for r in reader.artifact_requests(ev.id, current=True)}
            request = resolve_request(e, channel, obs.requests, obs.current_ids, self._today())
            if isinstance(request, Refusal):
                return obs
            target = request
        if target is not None:
            obs.batches = reader.batches(artifact_request_id=target.id)
        else:
            obs.batches = [b for b in reader.batches(evidence_id=ev.id) if b.artifact_request_id is None]
        obs.artifacts = {b.id: reader.artifacts(ev.id, batch_id=b.id) for b in obs.batches}
        return obs

    # -- diff ------------------------------------------------------------- #
    def diff(self, desired: list, observed: dict) -> List[Action]:
        today = self._today()
        return [self._plan_entry(e, observed.get(e.entry_key, UNKNOWN), today) for e in desired]

    def _plan_entry(self, e: EntryDesired, obs: Any, today: date) -> Action:
        files, dropped, skipped = self._split(e)
        payload: Dict[str, Any] = {
            "entry_key": e.entry_key, "evidence_id": None, "target": None, "artifact_request_id": None,
            "planned_current": False, "resume_batch_id": None,
            "files": [_file_json(f) for f in files], "dropped": dropped, "skipped": skipped,
        }

        def action(verb: Any, summary: str, **kw: Any) -> Action:
            return Action(id=f"{self.name}/{e.entry_key}", provider=self.name, key=e.entry_key,
                          verb=verb, summary=summary, payload=payload, **kw)

        if not files:
            if dropped:
                return action("refuse", ALL_DROPPED, fix=(
                    "remove the strings the production WAF blocks (named in each dropped file) "
                    "from the evidence and collect again"))
            return action("noop", f"nothing to send: {_count(len(skipped), 'file')} skipped")
        if obs is UNKNOWN:
            payload.update(evidence_id=UNKNOWN, target=UNKNOWN)
            return action(
                "deliver", f"deliver {_count(len(files), 'file')} to {e.reference_id} (routing unknown offline)",
                changes={"stack": UNKNOWN, "channel": UNKNOWN, "target": UNKNOWN},
            )

        warnings = [w for w in (_stack_drift(e, obs.stacks),) if w]
        route = _route(e, obs, today)
        if isinstance(route, Refusal):
            return action("refuse", route.message, fix=route.fix, warnings=warnings)
        channel, request = route.channel, route.request
        if route.warning:
            warnings.append(route.warning)
        if obs.evidence is None:
            payload["evidence_id"] = Ref(f"evidence_sets/{e.reference_id}", "id")
            where = f"{e.reference_id} (new evidence set, evidence level)"
        else:
            payload["evidence_id"] = obs.evidence.id
            where = f"{e.reference_id} (evidence level)"
        stack_name = _stack_name(channel.stack_id, obs.stacks) if channel else None
        if request is not None and channel is not None:
            stack = f"stack {stack_name}, " if stack_name else ""
            where = f"{request.reference_id} ({stack}channel {channel.reference_id})"
        payload.update(
            target="ARTIFACT_REQUEST" if request else "EVIDENCE",
            artifact_request_id=request.id if request else None,
            planned_current=bool(request and request.id in obs.current_ids),
        )
        changes: Dict[str, Any] = {
            "stack": {"id": channel.stack_id, "name": stack_name} if channel else None,
            "channel": channel.reference_id if channel else None,
            "target": payload["target"],
            "artifact_request": None if request is None else {
                "reference_id": request.reference_id, "requested_date": request.requested_date.isoformat(),
                "due_date": request.due_date.isoformat(), "current": payload["planned_current"],
            },
        }

        found = attribute(obs.batches, obs.artifacts, e)
        warnings += [_open_warning(b, rid, obs.artifacts.get(b.id) or [], today) for b, rid in found.earlier_open]
        mine = found.mine
        if mine is not None:
            changes["batch"] = {"id": mine.id, "reference_id": mine.reference_id, "status": mine.status}
        if mine is not None and mine.status in DONE:
            payload.update(batch_id=mine.id, batch_reference=mine.reference_id, status=mine.status)
            return action("noop", f"already delivered in {mine.reference_id}", changes=changes, warnings=warnings)
        if mine is None:
            tail = "new batch"
        else:
            have = {a.original_file_name for a in obs.artifacts.get(mine.id) or []}
            missing = [f for f in files if f.original_file_name not in have]
            payload.update(resume_batch_id=mine.id, files=[_file_json(f) for f in missing])
            tail = f"resume {mine.reference_id} ({len(missing)} missing)" if missing \
                else f"resume {mine.reference_id} (submit only)"
        n = _count(len(payload["files"]), "file")
        return action("deliver", f"deliver {n} to {where}: {tail}", changes=changes, warnings=warnings)
