"""What a collected run wants delivered, one `EntryDesired` per manifest entry.

Providers consume this; none of them reads an envelope. Values are JSON-native,
except `DeliveryFile.path`, which stays a `Path` so apply can read the file.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Dict, Literal, Optional

from framework.run_files import RESERVED_RUN_FILES, is_evidence_file
from framework.sync.state import RunState

DEFAULT_APPROVAL = "SUBMISSION_WITH_PASSING_VALIDATORS"
DEFAULT_NO_REQUEST = "refuse"

_ENVELOPE_KEYS = {"schema_version", "metadata", "payload"}

# Target fields preferred as the single identifying suffix in an artifact title.
# program_name leads: where a target carries both a readable label and an opaque
# id (Paramify programs), the reviewer picking among artifacts needs the label.
# Fetchers whose id IS readable (gitlab's group/project) declare no program_name,
# so they fall through to project_id.
_TITLE_KEYS = ("program_name", "project_id", "name", "id", "region", "cluster", "host", "bucket", "account_id")


@dataclass(frozen=True)
class DeliveryFile:
    path: Path
    original_file_name: str
    title: str
    note: str
    kind: Literal["evidence", "inventory"]
    skip_reason: Optional[str]
    # "error": a file that could not be read or is not evidence (the old uploader
    # counted these as errors). "skipped": a decision (skip_failed, incomplete inventory).
    skip_kind: Literal["skipped", "error"] = "skipped"


@dataclass(frozen=True)
class EntryDesired:
    entry_key: str
    use: str
    run_id: str
    reference_id: str
    evidence_set: Dict[str, Any]
    category: Optional[str]
    approval: str
    stack: Optional[str]
    stack_name: Optional[str]
    no_request: str
    files: tuple[DeliveryFile, ...]
    recorded_batch_id: Optional[str]
    collected_on: Optional[date] = None  # the day the run started (UTC), from _run_metadata.json
    approval_explicit: bool = False  # `approval` came from the manifest, not the default


def is_enveloped(obj: Any) -> bool:
    return isinstance(obj, dict) and _ENVELOPE_KEYS <= set(obj.keys())


def override_for(metadata: Dict, overrides: Dict) -> Dict:
    """The customer override block for the fetcher that produced this evidence."""
    return overrides.get(metadata.get("fetcher_name"), {}) or {}


def resolve_evidence_set(metadata: Dict, overrides: Dict) -> Optional[Dict]:
    """Merge the envelope's evidence_set with any per-fetcher customer override."""
    es = metadata.get("evidence_set")
    if not es:
        return None
    ov = override_for(metadata, overrides)
    resolved = dict(es)
    for key in ("reference_id", "name", "instructions", "description", "frequency"):
        if key in ov:
            resolved[key] = ov[key]
    return resolved


def artifact_content(envelope: Dict, mode: str) -> bytes:
    """Bytes to upload: the whole envelope (default, self-describing) or just the payload."""
    obj = envelope["payload"] if mode == "payload" else envelope
    return json.dumps(obj, indent=2).encode("utf-8")


def artifact_title(metadata: Dict, es_name: str) -> str:
    target = metadata.get("target")
    if not target:
        return es_name
    # One identifying value, not every field (avoids dumping url/branch into the title).
    suffix = next((str(target[k]) for k in _TITLE_KEYS if target.get(k)), None)
    if suffix is None:
        suffix = next((str(v) for v in target.values()), None)
    return f"{es_name} - {suffix}" if suffix else es_name


def artifact_note(metadata: Dict, *, entry_key: Optional[str] = None) -> str:
    parts = [
        f"fetcher={metadata.get('fetcher_name')}",
        f"version={metadata.get('fetcher_version')}",
        f"run_id={metadata.get('run_id')}",
        f"status={metadata.get('status')}",
    ]
    target = metadata.get("target")
    if target:
        parts.append(f"target={json.dumps(target, separators=(',', ':'))}")
    if entry_key:
        parts.append(f"entry={entry_key}")
    return "; ".join(parts)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _run_metadata(run_dir: Path) -> Dict:
    try:
        data = _read_json(run_dir / "_run_metadata.json")
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# Skip reasons that are errors, not decisions (a file the run should not hold).
ERROR_SKIP = "missing/incomplete evidence_set"


def _started_on(run_meta: Dict) -> Optional[date]:
    try:
        return date.fromisoformat(str(run_meta.get("started_at") or "")[:10])
    except ValueError:
        return None


def _skip_reason(metadata: Dict, es: Optional[Dict], skip_failed: bool) -> Optional[str]:
    """The uploader's skip decisions, with its wording."""
    if not es or not es.get("reference_id") or not es.get("name"):
        return ERROR_SKIP
    inventory = metadata.get("inventory")
    if isinstance(inventory, dict) and inventory.get("complete") is not True:
        why = "; ".join(inventory.get("incomplete_because") or ["not marked complete"])
        return f"incomplete inventory not sent: {why}"
    if metadata.get("status") == "failed" and skip_failed:
        return "status=failed and skip_failed set"
    return None


def desired_from_run(
    run_dir: Path,
    upload_cfg: dict,
    *,
    stack_override: Optional[str] = None,
    only_file: Optional[str] = None,
) -> list[EntryDesired]:
    run_dir = Path(run_dir)
    overrides = upload_cfg.get("overrides") or {}
    skip_failed = bool(upload_cfg.get("skip_failed", False))
    run_meta = _run_metadata(run_dir)
    raw_settings = run_meta.get("paramify")
    settings: Dict = raw_settings if isinstance(raw_settings, dict) else {}

    file_entry: Dict[str, str] = {}
    order: list[str] = []
    for rec in run_meta.get("invocations") or []:
        key = rec.get("entry_key")
        if not key:
            continue
        if key not in order:
            order.append(key)
        for out in rec.get("outputs") or []:
            file_entry.setdefault(Path(out).name, key)

    paths = sorted(p for p in run_dir.glob("*.json") if is_evidence_file(p) and p.name not in RESERVED_RUN_FILES)
    if only_file:
        paths = [p for p in paths if p.name == only_file]

    groups: Dict[str, list[tuple[Path, Any, Optional[str], Optional[Dict]]]] = {}
    for path in paths:
        envelope: Any = None
        problem: Optional[str] = None
        try:
            envelope = _read_json(path)
            if not is_enveloped(envelope):
                problem = "not envelope-wrapped"
        except (OSError, ValueError) as e:
            problem = f"cannot read as JSON ({e})"
        metadata = envelope["metadata"] if problem is None else {}
        key = file_entry.get(path.name) or metadata.get("fetcher_name") or path.stem
        groups.setdefault(key, []).append((path, metadata, problem, envelope))

    keys = [k for k in order if k in groups] + [k for k in groups if k not in order]
    state = RunState(run_dir)
    result: list[EntryDesired] = []
    for key in keys:
        files: list[DeliveryFile] = []
        chosen: Optional[Dict] = None
        chosen_es: Optional[Dict] = None
        first_es: Optional[Dict] = None
        first_md: Optional[Dict] = None
        for path, metadata, problem, _env in groups[key]:
            es = resolve_evidence_set(metadata, overrides) if problem is None else None
            reason = problem or _skip_reason(metadata, es, skip_failed)
            if problem is None:
                if first_md is None:
                    first_md, first_es = metadata, es
                if reason is None and chosen is None:
                    chosen, chosen_es = metadata, es
            inventory = metadata.get("inventory")
            files.append(DeliveryFile(
                path=path,
                original_file_name=path.name,
                title=artifact_title(metadata, es["name"]) if es and es.get("name") else path.name,
                note=artifact_note(metadata, entry_key=key) if problem is None else "",
                kind="inventory" if isinstance(inventory, dict) else "evidence",
                skip_reason=reason,
                skip_kind="error" if problem or reason == ERROR_SKIP else "skipped",
            ))
        md = chosen if chosen is not None else (first_md or {})
        es_final = (chosen_es if chosen is not None else first_es) or {}
        cfg = settings.get(key) or {}
        result.append(EntryDesired(
            entry_key=key,
            use=cfg.get("use") or md.get("fetcher_name") or key,
            run_id=str(run_meta.get("run_id") or md.get("run_id") or ""),
            reference_id=str(es_final.get("reference_id") or ""),
            evidence_set=es_final,
            category=md.get("category"),
            approval=cfg.get("approval") or DEFAULT_APPROVAL,
            stack=stack_override if stack_override else cfg.get("stack"),
            stack_name=None if stack_override else cfg.get("stack_name"),
            no_request=cfg.get("no_request") or DEFAULT_NO_REQUEST,
            files=tuple(files),
            recorded_batch_id=state.batch_for(key),
            collected_on=_started_on(run_meta),
            approval_explicit=bool(cfg.get("approval")),
        ))
    return result
