#!/usr/bin/env python3
"""Sync validators from the central registry to Paramify and associate them.

A separate stage from evidence upload (docs/validators_guide.md, step 6): it reads
the `validators/` registry, scopes to the validators whose `evidence_sets`
intersect the sets a manifest produces, and for each one:

  1. resolves whether the customer's Paramify instance already has it — by a
     cached id (the lock file) or, failing that, by matching `name`,
  2. **creates it only if absent** (`POST /validators`); an existing validator is
     never patched unless `--update` is passed, so customer tuning survives,
  3. **associates on create** — after creating, CONNECTs the validator to
     each of its evidence sets (`POST /evidence/{id}/associate`). A validator
     that already existed is paired only with `pair_existing` (the TUI's sync
     asks for it), and then only with the in-scope sets it isn't paired with
     yet; the CLI leaves existing wiring alone,
  4. puts the default custom tags on it — provenance + the registry category's
     display name — additively, on every run, created or not
     (framework/custom_tags.py).

The shipped validators are TEMPLATES (~80% right); customers tune them in
Paramify. That is why the default is create-or-skip and why the per-instance
validator id lives in a customer-side lock file, never in the shared registry.

Auth: PARAMIFY_UPLOAD_API_TOKEN, falling back to PARAMIFY_API_TOKEN (source-agnostic
env — .env, secret manager, CI).
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from dotenv import load_dotenv

# Also runnable directly from any cwd, where only its own directory lands on
# sys.path. Its position in the repo is fixed, so derive the root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework import yaml_io  # noqa: E402
from framework.custom_tags import (  # noqa: E402
    ENTITY_VALIDATOR,
    build_tagger,
    category_display_names,
)
from framework.paramify.client import ApiError, Client  # noqa: E402
from framework.paramify.connection import open_workspace  # noqa: E402

logger = logging.getLogger("paramify_validators_syncer")

DEFAULT_LOCK_PATH = "./.paramify/validators-sync.lock.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_payload(v: Dict) -> Dict:
    """Registry validator dict -> Paramify create/update body.

    Maps validation_rules -> validationRules / attestation_rules ->
    attestationRules; repo-side fields (key, role, rules_summary) are not sent.
    """
    vtype = v["type"]
    payload = {"name": v["name"], "statement": v["statement"], "type": vtype}
    if vtype == "AUTOMATED":
        payload["regex"] = v.get("regex")
        payload["validationRules"] = v.get("validation_rules") or []
    else:
        payload["attestationRules"] = v.get("attestation_rules") or []
    return payload


# What the API fills in on a rule the registry leaves it out of. A remote rule
# that only adds these still matches the registry's.
_RULE_DEFAULTS = {"disposition": "PASS"}


def _norm(value):
    if isinstance(value, str):
        return value.strip()  # the API may append a newline to text it stores
    if isinstance(value, list):
        return [_norm(x) for x in value]
    if isinstance(value, dict):
        return {k: _norm(x) for k, x in value.items() if x is not None}
    return value


def _rule_matches(local: Dict, remote: Dict) -> bool:
    local, remote = _norm(local), _norm(remote)
    extra = {k: v for k, v in remote.items() if k not in local}
    return all(remote.get(k) == v for k, v in local.items()) and all(
        _RULE_DEFAULTS.get(k) == v for k, v in extra.items())


def differs(payload: Dict, remote: Dict) -> Optional[bool]:
    """Whether Paramify's copy of a validator differs from the registry payload:
    True or False, or None when the remote content was not read."""
    if not remote:
        return None
    for k, v in payload.items():
        if k in ("validationRules", "attestationRules"):
            theirs = remote.get(k) or []
            mine = v or []
            if not isinstance(theirs, list) or len(theirs) != len(mine):
                return True
            if not all(isinstance(t, dict) and _rule_matches(m, t) for m, t in zip(mine, theirs)):
                return True
        elif _norm(v) != _norm(remote.get(k)):
            return True
    return False


def load_lock(lock_path: Path) -> Dict[str, str]:
    """Read the customer-side {key: paramify_id} lock, or {} if absent/unreadable."""
    try:
        data = json.loads(lock_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data.get("validators", {}) if isinstance(data, dict) else {}


def write_lock(lock_path: Path, mapping: Dict[str, str]) -> Optional[Path]:
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(
            json.dumps(
                {"updated_at": _utc_now(), "validators": mapping}, indent=2, sort_keys=True
            )
        )
        return lock_path
    except OSError as e:
        logger.warning("could not write lock %s (%s)", lock_path, e)
        return None


def _emit(on_event: Optional[Callable[[dict], None]], event: dict) -> None:
    if on_event is not None:
        on_event(event)


# --------------------------------------------------------------------------- #
# Reconcile engine
# --------------------------------------------------------------------------- #
def sync_validators(
    validators: List[Dict],
    *,
    client: Optional[Client] = None,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    dry_run: bool = False,
    update: bool = False,
    pair_existing: bool = False,
    lock_path: Optional[str] = None,
    on_event: Optional[Callable[[dict], None]] = None,
    config: Optional[Dict] = None,
    display_names: Optional[Dict[str, str]] = None,
    custom_tags: bool = True,
) -> Dict:
    """Reconcile a list of registry validator dicts against Paramify.

    Create-or-skip; associate on create; `update` opt-in patches an existing
    validator whose content differs (or can't be read); `pair_existing` opt-in
    pairs an existing validator with the in-scope sets (`pair_sets`, else
    `evidence_sets`) it isn't paired with yet. `dry_run` performs no writes
    (reads only, to report accurately, when a client is available). Returns a
    summary dict; never raises for per-validator errors (those are isolated and
    counted), only for setup errors.
    """
    config = config or {}
    base_url, resources = open_workspace(config, base_url=base_url, token=token, client=client,
                                         dry_run=dry_run, log=logger)

    lock_file = Path(
        lock_path or (config.get("validators") or {}).get("lock_path") or DEFAULT_LOCK_PATH
    )
    lock = load_lock(lock_file)

    # Default custom tags on every validator this run sees, created or existing.
    # `display_names` maps registry category -> service tag; the facade reads it
    # from the category files, since this function has no repo root of its own.
    try:
        tagger = build_tagger(
            None if dry_run else resources, config=config, display_names=display_names,
            override_off=None if custom_tags else "--no-tags",
        )
    except ValueError as e:
        logger.error(str(e))
        raise

    def _tag(validator_id: Optional[str], category: Optional[str]) -> List[str]:
        """Tag one validator; the names applied, or [] when off, dry-run, or refused."""
        if dry_run or not validator_id:
            return []
        info = tagger.tag(ENTITY_VALIDATOR, validator_id, category)
        return info["tags"] if info["outcome"] in ("applied", "already") else []

    _emit(on_event, {
        "event": "sync_start",
        "base_url": base_url,
        "dry_run": dry_run,
        "update": update,
        "pair_existing": pair_existing,
        "validators": len(validators),
        "lock_path": str(lock_file),
    })

    _name_index: Optional[Dict[str, str]] = None
    _content: Dict[str, Dict] = {}

    def name_index() -> Dict[str, str]:
        nonlocal _name_index
        if _name_index is None:
            if resources is None:
                _name_index = {}
            else:
                # Build fully, THEN cache. If the read raises, a half or empty
                # index is never cached: the error repeats per validator (each
                # isolated), so a transient failure cannot leave reconcile blind
                # and create duplicates. Fail closed.
                index: Dict[str, str] = {}
                content: Dict[str, Dict] = {}
                for ex in resources.validators():
                    if ex.name and ex.id:
                        index.setdefault(ex.name, ex.id)
                        content[ex.id] = dict(getattr(ex, "content", None) or {})
                _content.update(content)
                _name_index = index
        return _name_index

    results: List[Dict] = []
    created = updated = skipped = associated = set_not_found = errors = assoc_errors = 0
    paired_existing = 0

    def add_result(r: Dict) -> None:
        results.append(r)
        _emit(on_event, {"event": "sync_validator", **r})

    stopped: Optional[str] = None

    def stop(e: Exception) -> None:
        nonlocal stopped
        stopped = str(e)[:300]
        logger.error("stopping the sweep: %s", stopped)

    def connect(key: str, vid: str, refs: List[str], name: Optional[str] = None) -> Dict[str, List[str]]:
        """CONNECT `vid` to each set in `refs`, isolating each failure. With `name`
        (an existing validator), a set it is already paired with is left alone,
        and a dry run only reports what it would pair."""
        nonlocal associated, set_not_found, assoc_errors, paired_existing
        assert resources is not None
        out: Dict[str, List[str]] = {"paired": [], "already_paired": [], "set_not_found": [],
                                     "associate_failed": []}
        for ref in refs:
            try:
                found = resources.evidence_by_reference([ref]).get(ref)
                if not found:
                    out["set_not_found"].append(ref)
                    set_not_found += 1
                    continue
                if name is not None and (vid in found.validators or name in found.validators):
                    out["already_paired"].append(ref)
                    continue
                if not dry_run:
                    resources.associate(found.id, "VALIDATOR", vid)
                    associated += 1
                if name is not None:
                    paired_existing += 1
                out["paired"].append(ref)
            except Exception as ae:
                out["associate_failed"].append(ref)
                assoc_errors += 1
                logger.error("%s: associate to %s failed: %s", key, ref, ae)
                if isinstance(ae, ApiError) and ae.fatal:
                    stop(ae)  # the validator exists and is locked; record it, then stop
                    break
        return out

    for v in validators:
        if stopped:
            break
        key = v.get("key", "<unknown>")
        try:
            key = v["key"]  # inside try: a missing key is an isolated error, not a crash
            existing_id = lock.get(key)
            adopted = False
            if existing_id is None and resources is not None:
                existing_id = name_index().get(v["name"])
                if existing_id:
                    lock[key] = existing_id
                    adopted = True

            payload = build_payload(v)
            refs = v.get("evidence_sets", [])
            category = v.get("category")

            if existing_id is None:
                if dry_run:
                    created += 1
                    add_result({
                        "key": key, "outcome": "would_create", "evidence_sets": refs,
                        "tags": tagger.plan(category),
                    })
                    continue
                assert resources is not None  # not dry_run => a client, or connect() raised
                vid = resources.create_validator(payload)
                lock[key] = vid  # persist before associating so a re-run won't recreate
                created += 1
                tags = _tag(vid, category)
                # A failed association must NOT undo/duplicate the created validator
                # nor mark the whole validator an error — isolate per set.
                done = connect(key, vid, refs)
                result = {
                    "key": key, "outcome": "created", "validator_id": vid,
                    "associated": done["paired"], "set_not_found": done["set_not_found"], "tags": tags,
                }
                if done["associate_failed"]:
                    result["associate_failed"] = done["associate_failed"]
                add_result(result)
                continue

            # An existing validator. Read the workspace's copy (the name index
            # holds it) only when it decides something: an update or a preview.
            changed: Optional[bool] = None
            if resources is not None and (update or dry_run):
                name_index()
                changed = differs(payload, _content.get(existing_id) or {})
            wiring: Dict[str, List[str]] = {}
            if pair_existing and resources is not None:
                wiring = connect(key, existing_id, v.get("pair_sets") or refs, name=v["name"])
            extra: Dict = {"differs": changed}
            if wiring.get("paired"):
                extra["would_pair" if dry_run else "paired"] = wiring["paired"]
            for field in ("set_not_found", "associate_failed"):
                if wiring.get(field):
                    extra[field] = wiring[field]

            if update and changed is not False:
                if dry_run:
                    add_result({"key": key, "outcome": "would_update", "validator_id": existing_id, **extra})
                else:
                    assert resources is not None  # not dry_run => a client, or connect() raised
                    resources.update_validator(existing_id, payload)
                    add_result({"key": key, "outcome": "updated", "validator_id": existing_id,
                                "tags": _tag(existing_id, category), **extra})
                updated += 1
                continue

            skipped += 1
            add_result({
                "key": key,
                "outcome": "would_skip_exists" if dry_run else "skipped_exists",
                "validator_id": existing_id,
                "adopted": adopted,
                "tags": _tag(existing_id, category),
                **extra,
            })
        except Exception as e:  # noqa: BLE001
            logger.error("%s: sync failed: %s", key, e)
            errors += 1
            add_result({"key": key, "outcome": "error", "error": str(e)[:300]})
            if isinstance(e, ApiError) and e.fatal:
                stop(e)  # a rejected token fails every later call the same way

    lock_written = None
    if not dry_run:
        lock_written = write_lock(lock_file, lock)

    summary = {
        "base_url": base_url,
        "dry_run": dry_run,
        "update": update,
        "pair_existing": pair_existing,
        "validators": len(validators),
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "associated": associated,
        "paired_existing": paired_existing,
        "set_not_found": set_not_found,
        "errors": errors,
        "associate_errors": assoc_errors,
        "tags": tagger.summary(),
        "results": results,
        "lock_path": str(lock_written) if lock_written else str(lock_file),
        "stopped": stopped,
        "ok": errors == 0 and assoc_errors == 0,
    }
    logger.info(
        "Done: created=%d updated=%d skipped=%d associated=%d set_not_found=%d "
        "errors=%d associate_errors=%d%s",
        created, updated, skipped, associated, set_not_found, errors, assoc_errors,
        " (dry-run)" if dry_run else "",
    )
    _emit(on_event, {"event": "sync_complete", **summary})
    return summary


# --------------------------------------------------------------------------- #
# Registry collection (standalone use) — imports framework discovery
# --------------------------------------------------------------------------- #
def _validator_to_dict(v) -> Dict:
    return {
        "key": v.key,
        "name": v.name,
        "type": v.type,
        "statement": v.statement,
        "regex": v.regex,
        "validation_rules": v.validation_rules,
        "attestation_rules": v.attestation_rules,
        "evidence_sets": v.evidence_sets,
        "category": getattr(v, "category", None),
    }


def collect_validators(
    root: Path,
    manifest_path: Optional[Path] = None,
    reference_ids: Optional[List[str]] = None,
) -> List[Dict]:
    """Discover the registry and scope the selection.

    Precedence: an explicit `reference_ids` set (e.g. what an evidence run
    produced) > a `manifest`'s fetchers' sets > the whole registry.
    """
    from framework import api
    from framework.config_loader import discover_fetchers
    from framework.validators import (
        discover_validators,
        manifest_reference_ids,
        pipeline_reference_ids,
        select_validators,
    )

    from framework.validators import manifest_tracked_sets

    registry = discover_validators(root)
    # key -> the manifest sets that track it, when a manifest scopes the run.
    # Pairing an existing validator stays inside these, not every set it lists.
    scope: Optional[Dict[str, List[str]]] = None
    if reference_ids is not None and manifest_path is not None:
        # A manifest's selection applies to an explicit set list too.
        fetchers = discover_fetchers(root)
        pipeline = pipeline_reference_ids(fetchers)
        scope = manifest_tracked_sets(api.read_manifest(manifest_path), fetchers, registry.values(),
                                      set(reference_ids) - pipeline)
    elif reference_ids is not None:
        pipeline = pipeline_reference_ids(discover_fetchers(root))
        wanted = set(reference_ids) - pipeline
        selected = select_validators(registry.values(), wanted)
        return [dict(_validator_to_dict(v), pair_sets=[r for r in v.evidence_sets if r in wanted])
                for v in selected]
    elif manifest_path is not None:
        fetchers = discover_fetchers(root)
        manifest = api.read_manifest(manifest_path)
        # Only what the manifest tracks, not every validator for its sets.
        scope = manifest_tracked_sets(manifest, fetchers, registry.values())
    if scope is None:
        return [_validator_to_dict(v) for v in registry.values()]
    by_key = {v.key: v for v in registry.values()}
    return [dict(_validator_to_dict(by_key[k]), pair_sets=sets) for k, sets in scope.items()]


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    parser = argparse.ArgumentParser(description="Sync registry validators to Paramify")
    parser.add_argument("--root", default=".", help="Repo root containing validators/ (default .)")
    parser.add_argument("--manifest", help="Scope to validators for this manifest's fetchers")
    parser.add_argument("--config", help="Uploader config YAML (base_url, tags, validators.lock_path)")
    parser.add_argument("--lock", help=f"Lock file path (default {DEFAULT_LOCK_PATH})")
    parser.add_argument("--update", action="store_true", help="Also PATCH existing validators (overwrites tuning)")
    parser.add_argument("--dry-run", action="store_true", help="Report planned actions; make no writes")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        validators = collect_validators(root, Path(args.manifest) if args.manifest else None)
    except (ValueError, RuntimeError) as e:
        logger.error("could not collect validators: %s", e)
        return 1
    if not validators:
        logger.info("No validators in scope — nothing to sync.")
        return 0

    config: Dict = (yaml_io.load_path(Path(args.config)) or {}) if args.config else {}

    try:
        summary = sync_validators(
            validators, dry_run=args.dry_run, update=args.update, lock_path=args.lock,
            config=config, display_names=category_display_names(root),
        )
    except ValueError:
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
