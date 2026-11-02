"""Deliver each manifest entry's files as one batch per run: the plan side.

For each entry, in this order (the first refusal ends the entry):

1. channel: by the evidence set's channels and the entry's stack;
2. artifact request on that channel: the current one, else the latest past one;
3. batch: this entry's batch for this run is looked for among ALL batches of
   the evidence set, so a second upload of a run skips or resumes it, even
   after the cycle rolled over, and never makes another;
4. WAF: a file the production WAF would block is dropped at plan time.

The rules live in `delivery_routing` as pure functions; `diff` composes them.
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
from framework.sync.providers.delivery_routing import (
    DONE,
    Refusal,
    attribute,
    resolve_channel,
    resolve_request,
    stack_drift,
    stack_name,
)
from framework.sync.providers.desired import (
    DeliveryFile,
    EntryDesired,
    artifact_content,
    desired_from_run,
    is_enveloped,
)
from framework.sync.state import RunState

EVIDENCE_LEVEL_WARNING = "evidence-level batch: does not count toward the solution capability"
ALL_DROPPED = "every file was dropped"


@dataclass
class EntryObserved:
    """What observe read for one entry. `evidence` is None when the set does not exist yet."""

    evidence: Optional[EvidenceSet]
    stacks: List[Stack] = field(default_factory=list)
    requests: List[ArtifactRequest] = field(default_factory=list)
    current_ids: Set[str] = field(default_factory=set)
    batches: List[Batch] = field(default_factory=list)
    artifacts: Dict[str, List[Artifact]] = field(default_factory=dict)  # batch id -> artifacts


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


def _batch_target(
    mine: Batch, channel: Optional[Channel], obs: EntryObserved
) -> Tuple[Optional[ArtifactRequest], Optional[str], Optional[str]]:
    """(request, request id, warning) for this run's batch where it already is."""
    ar_id = mine.artifact_request_id
    if ar_id is None:
        return None, None, EVIDENCE_LEVEL_WARNING
    known = next((r for r in obs.requests
                  if r.id == ar_id and (channel is None or r.channel_id == channel.id)), None)
    if ar_id in obs.current_ids:
        return known, ar_id, None
    if known is None:
        return None, ar_id, f"resuming {mine.reference_id} on an earlier artifact request"
    return known, ar_id, f"late submission to {known.reference_id} (due {known.due_date.isoformat()})"


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
        if channel is not None:
            obs.requests = reader.artifact_requests(ev.id)
            obs.current_ids = {r.id for r in reader.artifact_requests(ev.id, current=True)}
            if isinstance(resolve_request(e, channel, obs.requests, obs.current_ids, self._today()), Refusal):
                return obs
        # Every batch of the set, on any request: this run's batch may sit on an
        # earlier request if the cycle rolled over since the last upload.
        obs.batches = reader.batches(evidence_id=ev.id)
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

        warnings = [w for w in (stack_drift(e, obs.stacks),) if w]
        route = _route(e, obs, today)
        if isinstance(route, Refusal):
            return action("refuse", route.message, fix=route.fix, warnings=warnings)
        channel = route.channel
        found = attribute(obs.batches, obs.artifacts, e)
        mine = found.mine
        route_ar = route.request.id if route.request else None
        request, ar_id, target_warning = route.request, route_ar, route.warning
        if mine is not None and mine.artifact_request_id != route_ar:
            # This run's batch is on another target: it stays there.
            request, ar_id, target_warning = _batch_target(mine, channel, obs)
            if mine.status in DONE:
                target_warning = None
        if target_warning:
            warnings.append(target_warning)
        warnings += [
            _open_warning(b, rid, obs.artifacts.get(b.id) or [], today)
            for b, rid in found.earlier_open
            if b.artifact_request_id == route_ar
        ]

        if obs.evidence is None:
            payload["evidence_id"] = Ref(f"evidence_sets/{e.reference_id}", "id")
            where = f"{e.reference_id} (new evidence set, evidence level)"
        else:
            payload["evidence_id"] = obs.evidence.id
            where = f"{e.reference_id} (evidence level)"
        named = stack_name(channel.stack_id, obs.stacks) if channel else None
        if ar_id is not None:
            route_text = f"{f'stack {named}, ' if named else ''}channel {channel.reference_id}" if channel else e.reference_id
            where = f"{request.reference_id if request else 'an earlier artifact request'} ({route_text})"
        payload.update(
            target="ARTIFACT_REQUEST" if ar_id else "EVIDENCE",
            artifact_request_id=ar_id,
            planned_current=bool(ar_id and ar_id in obs.current_ids),
        )
        changes: Dict[str, Any] = {
            "stack": {"id": channel.stack_id, "name": named} if channel else None,
            "channel": channel.reference_id if channel else None,
            "target": payload["target"],
            "artifact_request": None if ar_id is None else {
                "id": ar_id,
                "reference_id": request.reference_id if request else None,
                "requested_date": request.requested_date.isoformat() if request else None,
                "due_date": request.due_date.isoformat() if request else None,
                "current": payload["planned_current"],
            },
        }

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
