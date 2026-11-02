"""Deliver each manifest entry's files as one batch per run: the plan side.

For each entry, in this order (the first refusal ends the entry):

1. channel: by the evidence set's channels and the entry's stack;
2. artifact request on that channel: the current one, else the latest past one;
3. batch: this entry's batch for this run is found anywhere on the evidence
   set, through one artifacts query by file name, so a second upload of a run
   skips or resumes it, even after the cycle rolled over, and never makes
   another. A file of this run that the pre-batch uploader already sent (an
   artifact with no batch) is left out; when every file was, the entry is a
   no-op;
4. WAF: a file the production WAF would block is dropped at plan time.

The rules live in `delivery_routing` as pure functions; `diff` composes them.

Apply, per `deliver` action: re-check that a new batch's request is still
current (else re-plan the entry once), create the batch and record its id at
once (or resume), upload each missing file, drop a file on a permanent
failure and hold the batch OPEN on a temporary one, submit only when nothing
is held, and read the batch back.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from framework.paramify.client import ApiError, ErrorKind
from framework.paramify.resources import (
    Artifact,
    ArtifactRequest,
    Batch,
    Channel,
    EvidenceSet,
    Reader,
    Stack,
)
from framework.sync.model import UNKNOWN, Action, Outcome, Ref, SyncContext
from framework.sync.providers import waf
from framework.sync.providers.delivery_routing import (
    DONE,
    Refusal,
    attribute,
    delivered_before_batches,
    own_batch_ids,
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
BEFORE_BATCHES = "already delivered before batches"
WAF_BLOCKED = "blocked by the production WAF"
_FAILING = ("FAIL", "ERROR")


@dataclass
class EntryObserved:
    """What observe read for one entry. `evidence` is None when the set does not exist yet."""

    evidence: Optional[EvidenceSet]
    stacks: List[Stack] = field(default_factory=list)
    requests: List[ArtifactRequest] = field(default_factory=list)
    current_ids: Set[str] = field(default_factory=set)
    batches: List[Batch] = field(default_factory=list)
    artifacts: Dict[str, List[Artifact]] = field(default_factory=dict)  # batch id -> artifacts
    # This run's files the pre-batch uploader already sent (their artifacts have no batch).
    before_batches: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Route:
    channel: Optional[Channel]
    request: Optional[ArtifactRequest]  # None: deliver on the evidence set
    warning: Optional[str]


@dataclass
class _Delivered:
    """What apply did for one entry; `result` is the outcome's JSON."""

    batch_id: Optional[str] = None
    batch_reference: Optional[str] = None
    status: Optional[str] = None
    approval: str = ""
    uploaded: List[str] = field(default_factory=list)
    already_present: List[str] = field(default_factory=list)
    dropped: List[Dict[str, str]] = field(default_factory=list)  # {name, reason}
    held: List[str] = field(default_factory=list)
    validators_failed: List[str] = field(default_factory=list)

    def result(self, state: str) -> Dict[str, Any]:
        return {
            "state": state, "batch_id": self.batch_id, "batch_reference": self.batch_reference,
            "status": self.status, "uploaded": list(self.uploaded), "already_present": list(self.already_present),
            "dropped": [dict(d) for d in self.dropped], "validators_failed": list(self.validators_failed),
        }

    @property
    def name(self) -> str:
        return self.batch_reference or self.batch_id or "the batch"


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

    def __init__(
        self,
        run_state: Optional[RunState] = None,
        today: Callable[[], date] = date.today,
        on_event: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._run_state = run_state
        self._today = today
        self._on_event = on_event
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

    def _content(self, path: Path) -> bytes:
        """The bytes an upload of `path` sends, in this run's payload mode. Raises OSError."""
        raw = path.read_bytes()
        try:
            envelope = json.loads(raw)
        except ValueError:
            return raw
        return artifact_content(envelope, self._payload_mode) if is_enveloped(envelope) else raw

    def _scan(self, f: DeliveryFile) -> List[str]:
        """WAF signatures in what the upload of `f` would send: the bytes, the note and the title."""
        key = (str(f.path), self._payload_mode)
        if key not in self._waf_hits:
            try:
                content = self._content(f.path)
            except OSError:
                content = b""  # gone since desired(); apply reports it
            self._waf_hits[key] = waf.scan(content, f.note, f.title)
        return self._waf_hits[key]

    def _split(self, entry: EntryDesired) -> Tuple[List[DeliveryFile], List[Dict[str, str]], List[Dict[str, str]]]:
        """(sendable files, WAF drops, skipped files)."""
        files: List[DeliveryFile] = []
        dropped: List[Dict[str, str]] = []
        skipped: List[Dict[str, str]] = []
        for f in entry.files:
            if f.skip_reason:
                skipped.append({"original_file_name": f.original_file_name, "reason": f.skip_reason,
                                "kind": f.skip_kind})
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
        # This run's batch, wherever it is (the cycle may have rolled over since
        # the last upload): one query by this entry's file names, then only the
        # batches those artifacts name. Reads stay flat as the set's history grows.
        # It runs before routing: a run sent before batches existed needs no route.
        names = [f.original_file_name for f in e.files if f.skip_reason is None]
        # No names would make the filter vanish and read the whole set's artifacts.
        found = reader.artifacts(ev.id, original_file_names=names) if names else []
        obs.before_batches = delivered_before_batches(found, e)
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
        candidates = own_batch_ids(found, e)
        if e.recorded_batch_id and e.recorded_batch_id not in candidates:
            candidates.append(e.recorded_batch_id)  # may still have no artifacts
        for bid in candidates:
            try:
                b = reader.batch(bid)
            except ApiError as exc:
                if exc.kind is not ErrorKind.MISSING:
                    raise
                continue  # a stale id, e.g. from a run uploaded to another workspace
            if b.evidence_id == ev.id:
                obs.batches.append(b)
                obs.artifacts[b.id] = [a for a in found if a.batch_id == b.id]
        # Other runs' open batches, for the warning: only on the chosen target.
        if target is not None:
            open_here = reader.batches(artifact_request_id=target.id, status="OPEN")
        else:
            open_here = [b for b in reader.batches(evidence_id=ev.id, status="OPEN") if b.artifact_request_id is None]
        for b in open_here:
            if b.id not in obs.artifacts:
                obs.batches.append(b)
            obs.artifacts[b.id] = reader.artifacts(ev.id, batch_id=b.id)
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
        earlier = [f.original_file_name for f in files if f.original_file_name in obs.before_batches]
        if earlier:
            payload["before_batches"] = earlier
            if len(earlier) == len(files):
                return action("noop", f"{BEFORE_BATCHES} ({_count(len(files), 'file')})", warnings=warnings)
            files = [f for f in files if f.original_file_name not in earlier]
            payload["files"] = [_file_json(f) for f in files]
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

    # -- apply ------------------------------------------------------------ #
    def apply(self, action: Action, resources: Any, resolve: Callable[[Any], Any]) -> Outcome:
        p = action.payload
        if action.verb == "noop":
            return self._noop(action.id, p, action.summary)
        if action.verb != "deliver":
            return Outcome(action.id, "failed", message=f"unexpected verb {action.verb}")
        note = ""
        # Step 1. A resumed batch stays on its own request by design, so only a
        # new batch on a request planned as current is re-checked.
        if p.get("planned_current") and not p.get("resume_batch_id"):
            try:
                current = {r.id for r in resources.artifact_requests(p["evidence_id"], current=True)}
                again = None if p["artifact_request_id"] in current else self._replan(p, resources)
            except ApiError as exc:
                if exc.kind is not ErrorKind.TEMPORARY:
                    raise
                return self._held(action.id, _Delivered(), f"the artifact request check failed temporarily ({exc.message})")
            if again is not None:
                note = "; ".join([f"re-planned, the artifact request rolled over: {again.summary}", *again.warnings])
                if again.verb == "refuse":
                    return Outcome(action.id, "refused", _Delivered().result("refused"),
                                   "; ".join([f"{again.summary}: {again.fix}", *again.warnings]))
                if again.verb == "noop":
                    return self._noop(action.id, again.payload, note)
                p = resolve(again.payload)
        return self._deliver(action.id, p, resources, note)

    def _replan(self, p: Dict[str, Any], resources: Any) -> Action:
        """This entry's action from a fresh read, once (the caller does not loop)."""
        entry = self.entries.get(p["entry_key"])
        if entry is None:
            raise ValueError(f"artifact request {p['artifact_request_id']} is no longer current; plan again")
        reader = Reader(resources)
        ev = reader.evidence_by_reference([entry.reference_id]).get(entry.reference_id)
        return self._plan_entry(entry, self._observe_entry(entry, ev, reader), self._today())

    def _noop(self, action_id: str, p: Dict[str, Any], message: str) -> Outcome:
        done = _Delivered(p.get("batch_id"), p.get("batch_reference"), p.get("status"),
                          already_present=list(p.get("before_batches") or []))
        return Outcome(action_id, "noop", done.result("noop"), message)

    def _emit(self, action_id: str, name: str, outcome: str, n: Optional[int], of: int, size: int,
              reason: Optional[str] = None) -> None:
        if self._on_event is not None:
            event = {"event": "delivery_file", "action_id": action_id, "file": name,
                     "outcome": outcome, "n": n, "of": of, "bytes": size}
            if reason:
                event["reason"] = reason
            self._on_event(event)

    def _deliver(self, action_id: str, p: Dict[str, Any], resources: Any, note: str) -> Outcome:
        # Files that are errors (unreadable, not evidence) show in the entry state
        # as drops, so a delivered entry that left some behind says so.
        run = _Delivered(dropped=[{"name": d["original_file_name"], "reason": d["reason"]}
                                  for d in [*(p.get("dropped") or []),
                                            *(s for s in p.get("skipped") or [] if s.get("kind") == "error")]])
        ev_id, ar_id = p["evidence_id"], p.get("artifact_request_id")
        target = f"artifact request {ar_id}" if ar_id else f"evidence set {ev_id}"
        # Step 2: create (and record at once) or resume.
        try:
            if p.get("resume_batch_id"):
                run.batch_id = p["resume_batch_id"]
                present = {a.original_file_name for a in resources.artifacts(ev_id, batch_id=run.batch_id)}
            else:
                made = (resources.create_batch(artifact_request_id=ar_id) if ar_id
                        else resources.create_batch(evidence_id=ev_id))
                run.batch_id, run.batch_reference, run.status = made.id, made.reference_id, made.status
                if self._run_state is not None:
                    self._run_state.record_batch(p["entry_key"], made.id)
                present = set()
        except ApiError as exc:
            if exc.kind is ErrorKind.TEMPORARY:  # an outage, not a configuration gap
                return self._held(action_id, run, exc.message)
            return self._failed(action_id, exc, run, resources, ev_id, target)

        # Step 3: upload what the batch does not have yet.
        files = p.get("files") or []
        entry = self.entries.get(p["entry_key"])
        wanted = [f.original_file_name for f in self._split(entry)[0]] if entry is not None \
            else [*(p.get("before_batches") or []), *(f["original_file_name"] for f in files)]
        present |= set(p.get("before_batches") or [])  # sent before batches existed
        run.already_present = [n for n in wanted if n in present]
        to_send = [f for f in files if f["original_file_name"] not in present]
        for name in run.already_present:
            self._emit(action_id, name, "already_present", None, len(to_send), 0)
        for n, f in enumerate(to_send, 1):
            name = f["original_file_name"]
            try:
                content = self._content(Path(f["path"]))
            except OSError as exc:
                run.dropped.append({"name": name, "reason": f"cannot read {name}: {exc.strerror or exc}"})
                self._emit(action_id, name, "dropped", n, len(to_send), 0, run.dropped[-1]["reason"])
                continue
            reason: Optional[str] = None
            try:
                resources.upload_to_batch(run.batch_id, name, content, {"title": f["title"], "note": f["note"]})
                run.uploaded.append(name)
                outcome = "uploaded"
            except ApiError as exc:
                if exc.kind is ErrorKind.PERMANENT:
                    reason = WAF_BLOCKED if exc.status == 403 else exc.message
                    run.dropped.append({"name": name, "reason": reason})
                    outcome = "dropped"
                elif exc.kind is ErrorKind.TEMPORARY:
                    run.held.append(name)
                    outcome, reason = "held", exc.message
                else:
                    return self._failed(action_id, exc, run, resources, ev_id, f"batch {run.name}")
            self._emit(action_id, name, outcome, n, len(to_send), len(content), reason)

        # Step 4: submit only when nothing is held and the batch is not empty.
        if run.held:
            self._read_back(run, resources, ev_id)
            return self._held(action_id, run, f"{', '.join(run.held)} failed temporarily")
        if not run.uploaded and not run.already_present:
            self._read_back(run, resources, ev_id)
            return Outcome(action_id, "failed", run.result("failed"), ALL_DROPPED)
        try:
            resources.submit_batch(run.batch_id)
        except ApiError as exc:
            if exc.kind is not ErrorKind.TEMPORARY:
                return self._failed(action_id, exc, run, resources, ev_id, f"batch {run.name}")
            self._read_back(run, resources, ev_id)
            if run.status not in DONE:  # the submit may still have taken effect
                return self._held(action_id, run, f"the submit failed temporarily ({exc.message})")
        # Step 5: read the batch back.
        parts = [note] if note else []
        if not self._read_back(run, resources, ev_id):
            run.status = None  # the submit took effect; what it led to is unknown
            parts.append("submitted; status could not be read back")
        elif run.status == "SUBMITTED":
            parts.append(f"{run.name} SUBMITTED: held because validators failed: {', '.join(run.validators_failed)}"
                         if run.validators_failed else
                         f"{run.name} SUBMITTED: waiting for review (approval {run.approval or 'unknown'})")
        else:
            parts.append(f"{run.name} {run.status}")
        if run.dropped:
            parts.append(f"dropped {', '.join(d['name'] for d in run.dropped)}")
        return Outcome(action_id, "applied", run.result("delivered_with_drops" if run.dropped else "delivered"),
                       "; ".join(parts))

    def _held(self, action_id: str, run: _Delivered, why: str) -> Outcome:
        """A temporary failure: the next upload of this run resumes (or creates) the batch."""
        then = (f"{run.name} stays OPEN for the next upload to resume" if run.batch_id
                else "no batch was recorded; the next upload tries again")
        return Outcome(action_id, "failed", run.result("held"), f"held: {why}; {then}")

    def _failed(self, action_id: str, exc: ApiError, run: _Delivered, resources: Any, ev_id: str,
                what: str) -> Outcome:
        """A failure that ends the entry. FATAL stops the whole apply."""
        if exc.fatal:
            raise exc
        if exc.kind is ErrorKind.CONFLICT and run.batch_id:
            self._read_back(run, resources, ev_id)
            message = f"{run.name} is {run.status or 'in an unknown state'}: {exc.message}"
        elif exc.kind is ErrorKind.MISSING:
            message = f"{what} no longer exists; plan the upload again"
        else:
            message = exc.message
        return Outcome(action_id, "failed", run.result("failed"), message)

    def _read_back(self, run: _Delivered, resources: Any, ev_id: str) -> bool:
        """Status and reference from the API; failing validators of a batch held for them.

        False when the batch could not be read (a fatal error still raises).
        """
        try:
            b = resources.batch(run.batch_id)
        except ApiError as exc:
            if exc.fatal:
                raise
            return False
        run.batch_reference, run.status, run.approval = b.reference_id, b.status, b.when_to_approve
        if b.status == "SUBMITTED" and b.when_to_approve == "SUBMISSION_WITH_PASSING_VALIDATORS":
            try:
                arts = resources.artifacts(ev_id, batch_id=b.id)
            except ApiError as exc:
                if exc.fatal:
                    raise
                return True  # the status is known; which validators failed is not
            run.validators_failed = list(dict.fromkeys(
                name for a in arts for name, result in a.validators if result in _FAILING))
        return True
