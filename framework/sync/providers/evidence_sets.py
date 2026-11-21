"""Make sure every evidence set a run needs exists, tag it, and keep its frequency.

A missing set is created. An existing one is tagged (additively). Each action's
result carries the set id and its channels, so a later provider can name
`Ref("evidence_sets/<reference_id>", "id")`.

An existing set's frequency is changed by a second provider, `evidence_frequency`,
when the manifest or upload.yaml chose a different one. It runs after delivery:
Paramify may rebuild a set's artifact requests when its frequency changes, and
delivery plans the request it sends to before apply starts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable, Dict, List, Mapping, Optional

from framework.contract import (
    DEFAULT_EVIDENCE_FREQUENCY,
    FREQUENCY_WORDS,
    SCHEDULE_FREQUENCIES,
)
from framework.custom_tags import ENTITY_EVIDENCE, Tagger, resolve_tag_policy
from framework.paramify.client import ApiError, ErrorKind
from framework.paramify.resources import EvidenceSet
from framework.sync.model import UNKNOWN, Action, Outcome, Ref, SyncContext
from framework.sync.providers.desired import EntryDesired, desired_from_run

TAGS_UNAVAILABLE = "tags unavailable for this token"
FREQUENCY = "evidence_frequency"
# An outcome's result `state` for a change that was skipped but must still be seen.
WARNING = "warning"


@dataclass
class SetDesired:
    reference_id: str
    name: str
    description: str
    instructions: str
    frequency: str
    approval: str
    category: Optional[str]
    entry_keys: List[str] = field(default_factory=list)
    approvals: Dict[str, str] = field(default_factory=dict)  # entry key -> approval
    explicit: Dict[str, str] = field(default_factory=dict)  # entry key -> approval set in the manifest
    frequency_explicit: bool = False  # chosen in the manifest or upload.yaml, not the fetcher's default
    frequency_rank: int = 3  # see _source_rank; lower wins, 3 is nothing seen yet
    frequency_problem: Optional[str] = None  # why the chosen frequency can't be sent

    @property
    def conflict(self) -> bool:
        return len(set(self.approvals.values())) > 1


def _said(frequency: str) -> str:
    return FREQUENCY_WORDS.get(frequency, frequency)


def _cadence(frequency: str) -> int:
    """Shorter intervals sort first; NOT_SET (or anything else) sorts last."""
    order = list(SCHEDULE_FREQUENCIES)
    return order.index(frequency) if frequency in order else len(order)


def _source_rank(source: str) -> int:
    """A frequency someone wrote down (the entry, upload.yaml) beats the schedule,
    which only implies one; the fetcher's default ranks last."""
    if source == "fetcher":
        return 2
    return 1 if source == "schedule" else 0


def group_by_reference(entries: List[EntryDesired]) -> List[SetDesired]:
    """One record per distinct reference id, in first-seen order.

    Entries that share a set and choose different frequencies: a written one (the
    entry's, upload.yaml's) beats one the schedule implies, and among the same
    kind the shortest wins, since the set receives an artifact that often.
    """
    sets: Dict[str, SetDesired] = {}
    for e in entries:
        if not e.reference_id:
            continue
        es = e.evidence_set or {}
        rec = sets.get(e.reference_id)
        if rec is None:
            rec = sets[e.reference_id] = SetDesired(
                reference_id=e.reference_id,
                name=str(es.get("name") or e.reference_id),
                description=str(es.get("description") or ""),
                instructions=str(es.get("instructions") or ""),
                frequency=str(es.get("frequency") or DEFAULT_EVIDENCE_FREQUENCY),
                approval=e.approval,
                category=e.category,
            )
        elif rec.category is None:
            rec.category = e.category
        wanted = str(es.get("frequency") or DEFAULT_EVIDENCE_FREQUENCY)
        rank = _source_rank(e.frequency_source)
        if rank < 2 and (rank < rec.frequency_rank
                         or (rank == rec.frequency_rank and _cadence(wanted) < _cadence(rec.frequency))):
            rec.frequency, rec.frequency_explicit, rec.frequency_rank = wanted, True, rank
        if e.frequency_problem and rec.frequency_problem is None:
            rec.frequency_problem = e.frequency_problem
        rec.entry_keys.append(e.entry_key)
        rec.approvals[e.entry_key] = e.approval
        if e.approval_explicit:
            rec.explicit[e.entry_key] = e.approval
    return list(sets.values())


def _channels(es: EvidenceSet) -> List[Dict[str, str]]:
    return [{"id": c.id, "reference_id": c.reference_id, "stack_id": c.stack_id} for c in es.channels]


def _sets(ctx: SyncContext) -> List[SetDesired]:
    """The sets a run delivers to: what both providers here plan from."""
    entries = desired_from_run(
        ctx.run_dir, ctx.upload_cfg, stack_override=ctx.stack_override, only_file=ctx.only_file,
        owner_override=ctx.owner_override,
    ) if ctx.run_dir is not None else []
    deliverable = [e for e in entries if any(f.skip_reason is None for f in e.files)]
    return group_by_reference(deliverable)


def _observe(desired: list, reader: Any) -> dict:
    refs = [d.reference_id for d in desired]
    if reader is None:
        return {r: UNKNOWN for r in refs}
    return dict(reader.evidence_by_reference(refs))


def _bad_frequency(action_id: str, provider: str, d: SetDesired) -> Action:
    return Action(
        id=action_id, provider=provider, key=d.reference_id, verb="refuse",
        summary=f"evidence set {d.reference_id}: upload.yaml's frequency isn't valid",
        fix=d.frequency_problem,
    )


class EvidenceSetsProvider:
    name: str = "evidence_sets"
    runs_after: tuple[str, ...] = ()

    def __init__(
        self,
        tags_enabled: bool,
        display_names: Mapping[str, str],
        tag_config: Mapping[str, Any],
        today: Callable[[], date] = date.today,
    ) -> None:
        policy = resolve_tag_policy(tag_config, override_off=None if tags_enabled else "tags disabled")
        self._tagger = Tagger(None, policy=policy, display_names=display_names)
        self._today = today
        self._tags_unavailable = False

    # -- plan ------------------------------------------------------------- #
    def desired(self, ctx: SyncContext) -> list:
        return _sets(ctx)

    def observe(self, desired: list, reader: Any) -> dict:
        return _observe(desired, reader)

    def diff(self, desired: list, observed: dict) -> List[Action]:
        actions: List[Action] = []
        for d in desired:
            action_id = f"{self.name}/{d.reference_id}"
            seen = observed.get(d.reference_id)
            # A set this run would create gets the bad value in its POST; offline, it may.
            # A set that exists is refused by evidence_frequency instead, and still delivered to.
            if d.frequency_problem and (seen is UNKNOWN or seen is None):
                actions.append(_bad_frequency(action_id, self.name, d))
                continue
            if seen is UNKNOWN:
                actions.append(Action(
                    id=action_id, provider=self.name, key=d.reference_id, verb="noop",
                    summary=f"evidence set {d.reference_id}: state unknown (offline)",
                ))
                continue
            if d.conflict and seen is None:  # only a set this run creates needs one approval
                pairs = ", ".join(f"{k}={v}" for k, v in d.approvals.items())
                actions.append(Action(
                    id=action_id, provider=self.name, key=d.reference_id, verb="refuse",
                    summary=f"evidence set {d.reference_id}: entries disagree on approval",
                    fix=(
                        f"entries {', '.join(d.entry_keys)} all map to evidence set {d.reference_id} "
                        f"but set different approval values ({pairs}); give them the same approval"
                    ),
                ))
                continue
            if seen is None:
                body: Dict[str, Any] = {
                    "referenceId": d.reference_id,
                    "name": d.name,
                    "frequency": d.frequency,
                    "startDate": self._today().isoformat(),
                    "whenToApproveArtifactRequest": d.approval,
                }
                if d.description:
                    body["description"] = d.description
                if d.instructions:
                    body["instructions"] = d.instructions
                actions.append(Action(
                    id=action_id, provider=self.name, key=d.reference_id, verb="create",
                    summary=f"create evidence set {d.reference_id}", changes=dict(body),
                    payload={"body": body},
                ))
            else:
                warnings: List[str] = []
                # Only an approval the manifest sets is drift; the default would note every older set.
                for wanted in dict.fromkeys(d.explicit.values()):
                    if seen.approval != wanted:
                        warnings.append(f"approval is {seen.approval} here; this upload's batches get {wanted}")
                if seen.name != d.name:
                    warnings.append(f"name in Paramify is '{seen.name}'; the fetcher calls it '{d.name}'")
                actions.append(Action(
                    id=action_id, provider=self.name, key=d.reference_id, verb="noop",
                    summary=f"evidence set {d.reference_id} exists", warnings=warnings,
                    payload={"id": seen.id, "channels": _channels(seen)},
                ))
            tags = self._tagger.plan(d.category)
            if tags:
                actions.append(Action(
                    id=f"{self.name}/tags/{d.reference_id}", provider=self.name,
                    key=f"tags/{d.reference_id}", verb="tag",
                    summary=f"tag evidence set {d.reference_id}: {', '.join(tags)}",
                    payload={"evidence_id": Ref(action_id, "id"), "tags": tags, "category": d.category},
                ))
        return actions

    # -- apply ------------------------------------------------------------ #
    def apply(self, action: Action, resources: Any, resolve: Callable[[Any], Any]) -> Outcome:
        if action.verb == "create":
            made = resources.create_evidence(action.payload["body"])
            return Outcome(action.id, "applied", {"id": made.id, "channels": _channels(made)})
        if action.verb == "noop":
            result: Dict[str, Any] = {k: action.payload[k] for k in ("id", "channels") if k in action.payload}
            return Outcome(action.id, "noop", result)
        if action.verb == "tag":
            if self._tags_unavailable:
                return Outcome(action.id, "noop", message=TAGS_UNAVAILABLE)
            try:
                resources.add_tags(ENTITY_EVIDENCE, action.payload["evidence_id"], list(action.payload["tags"]))
            except ApiError as exc:
                if exc.fatal:  # a 401: nothing else in this run can succeed either
                    raise
                if exc.kind is ErrorKind.WARNING and exc.status == 403:
                    self._tags_unavailable = True
                    return Outcome(action.id, "applied", message=TAGS_UNAVAILABLE)
                # Tagging never breaks an upload: the set is delivered untagged.
                return Outcome(action.id, "failed", message=f"tags not added: {exc.message}")
            return Outcome(action.id, "applied")
        return Outcome(action.id, "failed", message=f"unexpected verb {action.verb}")


class EvidenceFrequencyProvider:
    """Change the frequency of evidence sets that exist, after delivery.

    Only a frequency someone chose (the manifest or upload.yaml) changes a set:
    the fetcher's default would undo every change made in the app. A set this
    run creates gets its frequency in the POST, so it has nothing to do here.
    """

    name: str = FREQUENCY
    runs_after: tuple[str, ...] = ("delivery",)

    # -- plan ------------------------------------------------------------- #
    def desired(self, ctx: SyncContext) -> list:
        return _sets(ctx)

    def observe(self, desired: list, reader: Any) -> dict:
        return _observe(desired, reader)  # the Reader caches it: no second read

    def diff(self, desired: list, observed: dict) -> List[Action]:
        actions: List[Action] = []
        for d in desired:
            seen = observed.get(d.reference_id)
            if seen is UNKNOWN or seen is None:
                continue
            action_id = f"{self.name}/{d.reference_id}"
            if d.frequency_problem:
                actions.append(_bad_frequency(action_id, self.name, d))
            elif d.frequency_explicit and seen.frequency and seen.frequency != d.frequency:
                actions.append(Action(
                    id=action_id, provider=self.name, key=d.reference_id, verb="update",
                    summary=f"{d.reference_id}: frequency {_said(seen.frequency)} → {_said(d.frequency)}",
                    changes={"frequency": [seen.frequency, d.frequency]},
                    payload={"id": seen.id, "body": {"frequency": d.frequency}},
                ))
        return actions

    # -- apply ------------------------------------------------------------ #
    def apply(self, action: Action, resources: Any, resolve: Callable[[Any], Any]) -> Outcome:
        if action.verb != "update":
            return Outcome(action.id, "failed", message=f"unexpected verb {action.verb}")
        wanted = _said(str(action.payload["body"].get("frequency")))
        result: Dict[str, Any] = {"id": action.payload["id"]}
        try:
            resources.update_evidence(action.payload["id"], dict(action.payload["body"]))
        except ApiError as exc:
            if exc.status == 403:
                # A key without Write Evidences: an upload to sets that exist never
                # needed it, so the files went and only the frequency stays as it was.
                return Outcome(action.id, "noop", {**result, "state": WARNING},
                               message=f"Couldn't change {action.key}'s frequency to {wanted}: "
                                       "this key can't edit evidence sets.")
            if exc.fatal:  # a 401: nothing else in this run can succeed either
                raise
            return Outcome(action.id, "failed", result,
                           message=f"Couldn't change {action.key}'s frequency to {wanted}: {exc.message}")
        return Outcome(action.id, "applied", result)
