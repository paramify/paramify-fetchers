"""Upload one run through the sync engine: what `api.plan_upload` and `api.upload_run` call.

This is the integration layer, so unlike the engine it knows the Paramify API.
It loads the uploader config, builds the providers (evidence sets, then the
validator sync when asked, then delivery), checks once whether the workspace
takes batches (when it does not, every entry is sent direct and the plan says
so in a note), plans and applies under the run lock, and maps the outcomes to
what front-ends have always read: the `uploaded` / `skipped_duplicate` /
`skipped_failed` / `errors` / `ok` summary (plus `dropped`; `ok` is
`errors == 0`), the `upload_start` / `upload_file` / `upload_complete` events
and `upload_log.json`. The plan, each entry's state and mode, the `batches`
capability and the engine's own events are added beside them.

A dry run plans offline: no token, no HTTP request.
"""
from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv

from framework import yaml_io
from framework.custom_tags import Tagger, category_display_names, resolve_tag_policy
from framework.paramify.client import Client, base_url_error
from framework.paramify.resources import Reader, Resources
from framework.paramify.version import Capability, delivery_capability
from framework.paramify_auth import (
    missing_token_error,
    resolve_base_url,
    resolve_upload_token,
)
from framework.run_files import is_evidence_file
from framework.runner import manifest_loader
from framework.sync import engine
from framework.sync.model import Action, Outcome, Plan, SyncContext, Unknown
from framework.sync.providers.delivery import (
    BATCHES_OFF,
    DeliveryProvider,
    delivery_mode,
)
from framework.sync.providers.desired import settings_notes
from framework.sync.providers.evidence_sets import (
    TAGS_UNAVAILABLE,
    EvidenceSetsProvider,
)
from framework.sync.providers.legacy_validators import LegacyValidatorsProvider
from framework.sync.render import outcome_state
from framework.sync.state import RunLocked, RunState

logger = logging.getLogger(__name__)

Event = Callable[[dict], None]

UPLOAD_LOG = "upload_log.json"
OK_STATES = frozenset({"delivered", "delivered_with_drops", "noop"})
NO_TAGS = "--no-tags"
DELIVERY = "delivery"
# delivery_file outcome -> the legacy upload_file outcome
_FILE_OUTCOME = {"uploaded": "uploaded", "already_present": "skipped_duplicate",
                 "dropped": "dropped", "held": "error", "error": "error"}
# A planned-only entry state, for a dry run.
_PLANNED_STATE = {"deliver": "planned", "noop": "noop", "refuse": "refused"}
INTERRUPTED = "not applied: upload interrupted"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(config_path: Optional[Path]) -> Dict[str, Any]:
    if not config_path:
        return {}
    data = yaml_io.load_path(Path(config_path)) or {}
    if not isinstance(data, dict):
        raise ValueError(f"the uploader config {config_path} is not a mapping")
    return data


def _run_manifest(run_dir: Path, root: Path) -> Optional[Path]:
    """The manifest the run records in `_run_metadata.json`, when that file is still there.

    `paramify run` records it relative to the repo root, or absolute when it is
    outside the root (see api._manifest_id).
    """
    try:
        meta = json.loads((run_dir / "_run_metadata.json").read_text())
    except (OSError, ValueError):
        return None
    manifest_id = meta.get("manifest") if isinstance(meta, dict) else None
    if not isinstance(manifest_id, str) or not manifest_id:
        return None
    path = Path(manifest_id)
    path = path if path.is_absolute() else Path(root) / path
    return path if path.is_file() else None


def manifest_notes(run_dir: Path, root: Path, manifest_path: Optional[Path],
                   stack_override: Optional[str], owner_override: Optional[str] = None) -> List[str]:
    """Plan notes for the Paramify settings the manifest now sets differently from the run.

    `paramify run` records each entry's settings in the run, and the upload uses
    those. A `manifest set-stack` or an edit after the run changes nothing for
    it, so the plan says so. With no `manifest_path` the run's own manifest is
    used. A manifest that is missing or cannot be read gives no notes: this is
    advice, and it must not stop an upload.
    """
    path = Path(manifest_path) if manifest_path else _run_manifest(run_dir, root)
    if path is None or not path.is_file():
        return []
    try:
        meta = json.loads((run_dir / "_run_metadata.json").read_text())
        run_settings = meta.get("paramify")
        parsed = manifest_loader.parse_manifest(yaml_io.load_path(path))
        now = {key: {"use": e.use, **manifest_loader.resolved_paramify(parsed, e)}
               for e, key in zip(parsed.entries, manifest_loader.entry_keys(parsed.entries))}
    except Exception:  # noqa: BLE001 — advice only; a bad manifest is reported where it is used
        return []
    if not isinstance(run_settings, dict):
        return []
    return settings_notes(run_settings, now, stack_override=stack_override, owner_override=owner_override)


# ---- setup ------------------------------------------------------------------ #

class _Setup:
    """The checks every upload makes before it plans, and what they resolved."""

    def __init__(self, run_dir: Any, config_path: Optional[Path], stack: Optional[str],
                 only_file: Optional[str], *, upload_cfg: Optional[Dict[str, Any]] = None,
                 token: Optional[str] = None, base_url: Optional[str] = None,
                 owner: Optional[str] = None) -> None:
        load_dotenv()
        self.run_dir = Path(run_dir)
        if not self.run_dir.is_dir():
            raise ValueError(f"No run directory to upload: {self.run_dir}")
        self.config_path = config_path
        # An in-memory config replaces the file: nothing is read or written.
        self.config = upload_cfg if upload_cfg is not None else load_config(config_path)
        self.token = token
        # Config wins, then an explicit argument, then the environment.
        self.base_url, _ = resolve_base_url((self.config.get("paramify") or {}).get("base_url") or base_url)
        url_error = base_url_error(self.base_url)
        if url_error:
            raise ValueError(url_error)
        self.files = [p for p in sorted(self.run_dir.glob("*.json"))
                      if is_evidence_file(p) and (not only_file or p.name == only_file)]
        if not self.files:
            raise ValueError(f"no evidence files found in {self.run_dir} — nothing to upload (wrong directory?)")
        self.ctx = SyncContext(self.run_dir, self.config, stack_override=stack, only_file=only_file,
                               owner_override=owner)
        # Plan notes the caller adds (see manifest_notes).
        self.notes: List[str] = []

    def client(self) -> Client:
        token = self.token or resolve_upload_token()[0]
        if not token:
            raise ValueError(missing_token_error())
        return Client(token, self.base_url)

    def providers(
        self,
        root: Path,
        *,
        online: bool,
        custom_tags: bool,
        with_validators: bool,
        run_state: Optional[RunState] = None,
        on_event: Optional[Event] = None,
        on_delivery_event: Optional[Event] = None,
        capability: Optional[Capability] = None,
    ) -> Tuple[List[Any], DeliveryProvider]:
        delivery = DeliveryProvider(run_state, on_event=on_delivery_event, capability=capability)
        providers: List[Any] = [EvidenceSetsProvider(custom_tags, category_display_names(root), self.config)]
        if with_validators:
            from framework.api import reference_ids_from_run  # api imports this module

            providers.append(LegacyValidatorsProvider(
                root, self.config_path, reference_ids_from_run(self.run_dir),
                online=online, custom_tags=custom_tags, on_event=on_event,
            ))
        providers.append(delivery)
        return providers, delivery


def _plan(providers: Sequence[Any], ctx: Any, reader: Any, capability: Optional[Capability] = None,
          notes: Sequence[str] = ()) -> Plan:
    """The engine's plan, less the tags of sets that get no delivery, with a note when batches are off
    and the `notes` given (see manifest_notes).

    The tag action runs before delivery, so without this an entry that is
    refused (no request, a stack mismatch) would still tag its set.
    """
    plan = engine.plan(providers, ctx, reader)
    if capability is not None and not capability.batches:
        plan.notes.append(f"{BATCHES_OFF} ({capability.reason}); every entry is sent direct, as before batches")
    plan.notes.extend(notes)
    verbs: Dict[str, List[str]] = defaultdict(list)
    for a in plan.actions:
        if a.provider == "delivery" and a.payload.get("reference_id"):
            verbs[a.payload["reference_id"]].append(a.verb)
    refused = {ref for ref, vs in verbs.items() if vs and all(v == "refuse" for v in vs)}
    plan.actions = [a for a in plan.actions
                    if not (a.provider == "evidence_sets" and a.verb == "tag"
                            and a.key.startswith("tags/") and a.key[len("tags/"):] in refused)]
    return plan


def plan_upload(
    run_dir: Any,
    root: Path,
    config_path: Optional[Path] = None,
    *,
    online: bool,
    stack: Optional[str] = None,
    only_file: Optional[str] = None,
    custom_tags: bool = True,
    with_validators: bool = False,
    manifest_path: Optional[Path] = None,
    owner: Optional[str] = None,
) -> Plan:
    """The plan for uploading `run_dir`. Online it reads the workspace (read-only); offline it needs no token.

    `manifest_path` is the manifest to compare the run's Paramify settings with
    (see manifest_notes); without it, the run's own manifest is used.
    """
    setup = _Setup(run_dir, config_path, stack, only_file, owner=owner)
    notes = manifest_notes(setup.run_dir, root, manifest_path, stack, owner)
    reader = None
    capability: Optional[Capability] = None  # offline: no check, no note
    if online:
        client = setup.client()
        capability = delivery_capability(client)
        reader = Reader(Resources(client))
    providers, _ = setup.providers(root, online=online, custom_tags=custom_tags, with_validators=with_validators,
                                   capability=capability)
    return _plan(providers, setup.ctx, reader, capability, notes)


# ---- the legacy view of a plan and its outcomes ----------------------------- #

def _known(value: Any) -> Any:
    return None if isinstance(value, Unknown) else value


class _Report:
    """Turns engine and delivery events into `upload_file` events, counts and entries."""

    def __init__(self, emit: Event, dry_run: bool, tagger: Tagger) -> None:
        self.emit = emit
        self.dry_run = dry_run
        self.tagger = tagger  # session-less: plans tag names, writes nothing
        self.plan = Plan()
        self.capability: Optional[Capability] = None  # None: not checked (a dry run, or the check failed)
        self.actions: Dict[str, Action] = {}
        self.refs: Dict[str, str] = {}  # entry key -> evidence set reference id
        self.categories: Dict[str, Optional[str]] = {}  # entry key -> category
        self.results: List[Dict[str, Any]] = []
        self.counts: Counter = Counter()
        self.errors_by_action: Counter = Counter()
        self.file_errors = 0  # unreadable / non-evidence files: they make `ok` false (drops do not)
        self._started: set = set()
        self._reported: Dict[str, set] = {}
        self._tag_status: Dict[str, Tuple[str, str]] = {}  # tag action id -> (status, message)

    def bind(self, plan: Plan, delivery: DeliveryProvider) -> None:
        self.plan = plan
        self.actions = {a.id: a for a in plan.actions}
        self.refs = {key: e.reference_id for key, e in delivery.entries.items()}
        self.categories = {key: e.category for key, e in delivery.entries.items()}

    # -- per file --------------------------------------------------------- #
    def _tags_for(self, action: Action) -> List[str]:
        """The tags this file's set got (online), or would get (a dry run plans no tag actions)."""
        if self.dry_run:
            return self.tagger.plan(self.categories.get(action.key))
        ref = self.refs.get(action.key)
        tag_action = self.actions.get(f"evidence_sets/tags/{ref}") if ref else None
        if tag_action is None:
            return []
        status, message = self._tag_status.get(tag_action.id, ("", ""))
        if status != "applied" or message == TAGS_UNAVAILABLE:
            return []
        return list(tag_action.payload.get("tags") or [])

    def file(self, action: Action, name: str, outcome: str, reason: Optional[str] = None) -> None:
        ev: Dict[str, Any] = {"event": "upload_file", "file": name, "outcome": outcome, "action_id": action.id}
        ref = self.refs.get(action.key)
        if ref:
            ev["reference_id"] = ref
        channel = _known(action.changes.get("channel"))
        if channel:
            ev["channel"] = channel
        tags = self._tags_for(action) if outcome in ("uploaded", "skipped_duplicate", "would_upload") else []
        if tags:
            ev["tags"] = tags
        if reason:
            ev["reason"] = reason
        self.results.append({k: v for k, v in ev.items() if k != "event"})
        self.counts[outcome] += 1
        if outcome == "error":
            self.errors_by_action[action.id] += 1
        self._reported.setdefault(action.id, set()).add(name)
        self.emit(ev)

    def _start(self, action: Action) -> None:
        """Files known at plan time: skipped ones and plan-time WAF drops."""
        if action.id in self._started:
            return
        self._started.add(action.id)
        for s in action.payload.get("skipped") or []:
            outcome = "error" if s.get("kind") == "error" else "skipped_failed"
            if outcome == "error":
                self.file_errors += 1
            self.file(action, s["original_file_name"], outcome, s.get("reason"))
        for d in action.payload.get("dropped") or []:
            self.file(action, d["original_file_name"], "dropped", d.get("reason"))

    # -- dry run ---------------------------------------------------------- #
    def planned(self) -> None:
        for action in self.plan.actions:
            if action.provider != DELIVERY:
                continue
            self._start(action)
            if action.verb == "deliver":
                for f in action.payload.get("files") or []:
                    self.file(action, f["original_file_name"], "would_upload")

    # -- apply ------------------------------------------------------------ #
    def on_engine(self, ev: dict) -> None:
        self.emit(ev)
        action = self.actions.get(ev.get("action_id", ""))
        if action is None:
            return
        if action.verb == "tag" and ev["event"] == "action_end":
            self._tag_status[action.id] = (ev.get("status", ""), ev.get("message", ""))
        if action.provider != DELIVERY:
            return
        self._start(action)
        if ev["event"] != "action_end" or ev.get("status") == "applied":
            return
        # Files no delivery event named: a no-op already has them; anything else did not send them.
        noop = ev.get("status") == "noop"
        done = self._reported.get(action.id, set())
        for f in action.payload.get("files") or []:
            if f["original_file_name"] not in done:
                self.file(action, f["original_file_name"], "skipped_duplicate" if noop else "error",
                          None if noop else ev.get("message") or None)

    def on_delivery(self, ev: dict) -> None:
        self.emit(ev)
        action = self.actions.get(ev.get("action_id", ""))
        if action is None or ev.get("event") != "delivery_file":
            return
        self._start(action)
        outcome = _FILE_OUTCOME.get(ev.get("outcome", ""), "error")
        if ev.get("outcome") == "error":  # unreadable at apply: an error, as at plan time
            self.file_errors += 1
        self.file(action, ev["file"], outcome, ev.get("reason"))

    # -- summary ---------------------------------------------------------- #
    def entries(self, outcomes: Optional[Sequence[Outcome]]) -> Dict[str, Dict[str, Any]]:
        by_id = {o.action_id: o for o in outcomes or []}
        out: Dict[str, Dict[str, Any]] = {}
        for a in self.plan.actions:
            if a.provider != DELIVERY:
                continue
            o = by_id.get(a.id)
            entry: Dict[str, Any] = dict(o.result) if o is not None and o.result else {}
            if o is None:  # a dry run
                entry.update(state=_PLANNED_STATE.get(a.verb, a.verb), message=a.fix or a.summary)
            else:
                entry.update(state=outcome_state(o), message=o.message)
            for key in ("batch_id", "batch_reference", "status"):
                entry.setdefault(key, None)
            entry["stack"] = _known(a.changes.get("stack"))
            entry["channel"] = _known(a.changes.get("channel"))
            entry["artifact_request"] = _known(a.changes.get("artifact_request"))
            # How apply sent it (a re-plan can change it), else how the plan routed it.
            entry["mode"] = entry["mode"] if "mode" in entry else delivery_mode(a.payload.get("target"))
            out[a.key] = entry
        return out

    def summary(self, outcomes: Optional[Sequence[Outcome]]) -> Dict[str, Any]:
        entries = self.entries(outcomes)
        if outcomes is None:
            refused = [a.id for a in self.plan.actions if a.verb == "refuse"]
            ok = not refused and self.file_errors == 0
        else:
            refused = [o.action_id for o in outcomes if o.status == "refused"]
            # Tags never block an upload; a failed set or validator sync does.
            others_ok = all(
                o.status in ("applied", "noop") for o in outcomes
                if not o.action_id.startswith(f"{DELIVERY}/") and self._verb(o.action_id) != "tag"
            )
            ok = (others_ok and all(e["state"] in OK_STATES for e in entries.values())
                  and self.file_errors == 0)
        return {
            "uploaded": self.counts["uploaded"],
            "skipped_duplicate": self.counts["skipped_duplicate"],
            "skipped_failed": self.counts["skipped_failed"],
            "errors": self._errors(entries, refused, applied=outcomes is not None),
            "dropped": self.counts["dropped"],
            "ok": ok,
            "plan": self.plan.to_json(),
            "entries": entries,
            "batches": None if self.capability is None else {
                "available": self.capability.batches, "reason": self.capability.reason},
        }

    def _errors(self, entries: Dict[str, Dict[str, Any]], refused: List[str], *, applied: bool) -> int:
        """Error files, one per refusal, and at least one per entry that did not end well.

        Dropped files are not errors (they have their own count), so an entry
        whose files were all dropped still counts one: `ok` is `errors == 0`.
        """
        errors = sum(1 for aid in refused if not aid.startswith(f"{DELIVERY}/"))
        for a in self.plan.actions:
            if a.provider != DELIVERY:
                continue
            if a.id in refused:
                errors += 1
                continue
            n = self.errors_by_action[a.id]
            if applied and n == 0 and entries[a.key]["state"] not in OK_STATES:
                n = 1
            errors += n
        return errors

    def _verb(self, action_id: str) -> str:
        action = self.actions.get(action_id)
        return action.verb if action else ""

    def tags(self, policy: Any, outcomes: Optional[Sequence[Outcome]]) -> Dict[str, Any]:
        """The legacy `tags` block: the policy, and what the tag actions did."""
        applied = failed = skipped = 0
        disabled = None
        for o in outcomes or []:
            if self._verb(o.action_id) != "tag":
                continue
            if o.message == TAGS_UNAVAILABLE:
                skipped += 1
                disabled = TAGS_UNAVAILABLE
            elif o.status == "applied":
                applied += 1
            elif o.status == "failed":
                failed += 1
            else:
                skipped += 1
        return {
            "enabled": policy.enabled, "reason": policy.off_reason, "provenance": policy.provenance,
            "service": policy.service, "applied": applied, "failed": failed, "skipped": skipped,
            "disabled": disabled,
        }


# ---- run -------------------------------------------------------------------- #

def run_upload(
    run_dir: Any,
    root: Path,
    config_path: Optional[Path] = None,
    *,
    dry_run: bool = False,
    on_event: Optional[Event] = None,
    custom_tags: bool = True,
    stack: Optional[str] = None,
    only_file: Optional[str] = None,
    with_validators: bool = False,
    upload_cfg: Optional[Dict[str, Any]] = None,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    deprecations: Sequence[str] = (),
    manifest_path: Optional[Path] = None,
    owner: Optional[str] = None,
) -> Dict[str, Any]:
    """Plan and apply the upload of one run; see the module docstring.

    `upload_cfg`, `token` and `base_url` are for callers that already hold them
    (the legacy uploader script): a config dict is used instead of reading
    `config_path`, and the token and base URL win over the environment.
    `deprecations` are notes written to `upload_log.json`. `manifest_path` is
    as for plan_upload.

    Raises ValueError for setup errors (no run dir, no evidence, bad base URL
    or config, no token, another upload of this run in progress). An API
    error that stops planning (an old API, a 401) is raised as it is.
    """
    emit: Event = on_event or (lambda _ev: None)
    setup = _Setup(run_dir, config_path, stack, only_file,
                   upload_cfg=upload_cfg, token=token, base_url=base_url, owner=owner)
    setup.notes = manifest_notes(setup.run_dir, root, manifest_path, stack, owner)
    policy = resolve_tag_policy(setup.config, override_off=None if custom_tags else NO_TAGS)
    report = _Report(emit, dry_run, Tagger(None, "", policy=policy, display_names=category_display_names(root)))
    base = {"run_dir": str(setup.run_dir), "base_url": setup.base_url, "dry_run": dry_run,
            "files": len(setup.files)}

    if dry_run:
        providers, delivery = setup.providers(
            root, online=False, custom_tags=custom_tags, with_validators=with_validators, on_event=emit)
        emit({"event": "upload_start", **base})
        report.bind(_plan(providers, setup.ctx, None, notes=setup.notes), delivery)
        emit({"event": "plan", "plan": report.plan.to_json()})
        report.planned()
        summary = {**base, **report.summary(None), "tags": report.tags(policy, None),
                   "results": report.results, "log_path": None}
        planned = next((a for a in report.plan.actions if a.provider == "validators"), None)
        if planned is not None:  # what --with-validators would sync; nothing is synced
            summary["validators"] = {"dry_run": True, "planned": planned.summary,
                                     "reference_ids": list(planned.payload.get("reference_ids") or [])}
        emit({"event": "upload_complete", **summary})
        return summary

    client = setup.client()
    state = RunState(setup.run_dir)
    try:
        with state.lock():
            summary = _apply_locked(setup, root, client, state, report, policy, base,
                                    custom_tags=custom_tags, with_validators=with_validators, emit=emit,
                                    deprecations=deprecations)
    except RunLocked as exc:
        raise ValueError(str(exc)) from None
    emit({"event": "upload_complete", **summary})
    return summary


def _apply_locked(
    setup: _Setup,
    root: Path,
    client: Client,
    state: RunState,
    report: _Report,
    policy: Any,
    base: Dict[str, Any],
    *,
    custom_tags: bool,
    with_validators: bool,
    emit: Event,
    deprecations: Sequence[str] = (),
) -> Dict[str, Any]:
    outcomes: Optional[List[Outcome]] = None
    done: List[Outcome] = []  # filled as apply goes, so an interruption keeps what finished
    error: Optional[str] = None
    try:
        emit({"event": "upload_start", **base})
        report.capability = delivery_capability(client)
        resources = Resources(client)
        providers, delivery = setup.providers(
            root, online=True, custom_tags=custom_tags, with_validators=with_validators,
            run_state=state, on_event=emit, on_delivery_event=report.on_delivery, capability=report.capability,
        )
        report.bind(_plan(providers, setup.ctx, Reader(resources), report.capability, setup.notes), delivery)
        emit({"event": "plan", "plan": report.plan.to_json()})
        outcomes = engine.apply(report.plan, providers, resources, on_event=report.on_engine, outcomes=done)
    except BaseException as exc:
        error = str(exc) or type(exc).__name__
        # Every action without an outcome was not applied; none of them is "planned" any more.
        finished = {o.action_id for o in done}
        outcomes = done + [Outcome(a.id, "skipped", message=INTERRUPTED)
                           for a in report.plan.actions if a.id not in finished]
        raise
    finally:
        summary = {**base, **report.summary(outcomes or []), "tags": report.tags(policy, outcomes),
                   "results": report.results, "outcomes": [asdict(o) for o in outcomes or []]}
        if error is not None:
            summary["ok"] = False
        validators = next((o for o in outcomes or [] if o.action_id == "validators/registry"), None)
        if validators is not None:
            summary["validators"] = validators.result  # the validator sync's own summary
        if deprecations:
            summary["deprecations"] = list(deprecations)
        summary["log_path"] = _write_log(setup.run_dir, summary, error)
    return summary


def _write_log(run_dir: Path, summary: Dict[str, Any], error: Optional[str]) -> Optional[str]:
    """upload_log.json: the fields it has always had, plus `dropped`, `plan`, `entries`
    (each entry's mode, batch, stack, channel and request), `batches`, `outcomes` and the validator sync."""
    log: Dict[str, Any] = {
        "uploaded_at": _utc_now(),
        "run_dir": summary["run_dir"],
        "uploaded": summary["uploaded"],
        "skipped_duplicate": summary["skipped_duplicate"],
        "skipped_failed": summary["skipped_failed"],
        "errors": summary["errors"],
        "dropped": summary["dropped"],
        "ok": summary["ok"],
        "tags": summary["tags"],
        "results": summary["results"],
        "plan": summary["plan"],
        "entries": summary["entries"],
        "batches": summary["batches"],
        "outcomes": summary["outcomes"],
    }
    if "validators" in summary:
        log["validators"] = summary["validators"]
    if summary.get("deprecations"):
        log["deprecations"] = summary["deprecations"]
    if error is not None:
        log["error"] = error
    path = run_dir / UPLOAD_LOG
    text = json.dumps(log, indent=2, default=str)
    try:
        path.write_text(text)
    except OSError as exc:
        logger.warning("could not write %s (%s); log follows:\n%s", UPLOAD_LOG, exc, text)
        return None
    return str(path)
