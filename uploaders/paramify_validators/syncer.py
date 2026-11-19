#!/usr/bin/env python3
"""Sync validators from the central registry to Paramify and associate them.

A separate stage from evidence upload (docs/validators_guide.md, step 6): it reads
the `validators/` registry, scopes to the validators whose `evidence_sets`
intersect the sets a manifest produces, and for each one:

  1. resolves whether the customer's Paramify instance already has it — by a
     cached id (the lock file) or, failing that, by matching `name`,
  2. **creates it only if absent** (`POST /validators`); an existing validator is
     never patched unless `--update` is passed, so customer tuning survives,
  3. **associates on create only** — after creating, CONNECTs the validator to
     each of its evidence sets (`POST /evidence/{id}/associate`); it never
     re-asserts wiring on a validator that already existed,
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
from pathlib import Path
from typing import Callable, Dict, List, Optional

from dotenv import load_dotenv

# Also runnable directly from any cwd, where only its own directory lands on
# sys.path. Its position in the repo is fixed, so derive the root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework import upload_config  # noqa: E402
from framework.clock import utc_now  # noqa: E402
from framework.custom_tags import (  # noqa: E402
    ENTITY_VALIDATOR,
    build_tagger,
    category_display_names,
)
from framework.paramify.client import ApiError, Client  # noqa: E402
from framework.paramify.connection import open_workspace  # noqa: E402

logger = logging.getLogger("paramify_validators_syncer")

DEFAULT_LOCK_PATH = "./.paramify/validators-sync.lock.json"


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
                {"updated_at": utc_now(), "validators": mapping}, indent=2, sort_keys=True
            )
        )
        return lock_path
    except OSError as e:
        logger.warning("could not write lock %s (%s)", lock_path, e)
        return None


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
    lock_path: Optional[str] = None,
    on_event: Optional[Callable[[dict], None]] = None,
    config: Optional[Dict] = None,
    display_names: Optional[Dict[str, str]] = None,
    custom_tags: bool = True,
) -> Dict:
    """Reconcile a list of registry validator dicts against Paramify.

    Create-or-skip; associate on create only; `update` opt-in patches existing;
    `dry_run` performs no writes (reads only, to report accurately, when a client
    is available). Returns a summary dict; never raises for per-validator errors
    (those are isolated and counted), only for setup errors.
    """
    on_event = on_event or (lambda _event: None)
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

    on_event({
        "event": "sync_start",
        "base_url": base_url,
        "dry_run": dry_run,
        "update": update,
        "validators": len(validators),
        "lock_path": str(lock_file),
    })

    _name_index: Optional[Dict[str, str]] = None

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
                for ex in resources.validators():
                    if ex.name and ex.id:
                        index.setdefault(ex.name, ex.id)
                _name_index = index
        return _name_index

    results: List[Dict] = []
    created = updated = skipped = associated = set_not_found = errors = assoc_errors = 0

    def add_result(r: Dict) -> None:
        results.append(r)
        on_event({"event": "sync_validator", **r})

    stopped: Optional[str] = None

    def stop(e: Exception) -> None:
        nonlocal stopped
        stopped = str(e)[:300]
        logger.error("stopping the sweep: %s", stopped)

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
                assoc, missing, failed = [], [], []
                for ref in refs:
                    try:
                        found = resources.evidence_by_reference([ref]).get(ref)
                        if found:
                            resources.associate(found.id, "VALIDATOR", vid)
                            assoc.append(ref)
                            associated += 1
                        else:
                            missing.append(ref)
                            set_not_found += 1
                    except Exception as ae:
                        failed.append(ref)
                        assoc_errors += 1
                        logger.error("%s: associate to %s failed: %s", key, ref, ae)
                        if isinstance(ae, ApiError) and ae.fatal:
                            stop(ae)  # the validator exists and is locked; record it, then stop
                            break
                result = {
                    "key": key, "outcome": "created", "validator_id": vid,
                    "associated": assoc, "set_not_found": missing, "tags": tags,
                }
                if failed:
                    result["associate_failed"] = failed
                add_result(result)
                continue

            if update:
                if dry_run:
                    add_result({"key": key, "outcome": "would_update", "validator_id": existing_id})
                else:
                    assert resources is not None  # not dry_run => a client, or connect() raised
                    resources.update_validator(existing_id, payload)
                    add_result({"key": key, "outcome": "updated", "validator_id": existing_id,
                                "tags": _tag(existing_id, category)})
                updated += 1
                continue

            skipped += 1
            add_result({
                "key": key,
                "outcome": "would_skip_exists" if dry_run else "skipped_exists",
                "validator_id": existing_id,
                "adopted": adopted,
                "tags": _tag(existing_id, category),
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
        "validators": len(validators),
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "associated": associated,
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
    on_event({"event": "sync_complete", **summary})
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

    registry = discover_validators(root)
    if reference_ids is not None:
        pipeline = pipeline_reference_ids(discover_fetchers(root))
        selected = select_validators(registry.values(), set(reference_ids) - pipeline)
    elif manifest_path is not None:
        fetchers = discover_fetchers(root)
        manifest = api.read_manifest(manifest_path)
        refs = manifest_reference_ids(manifest, fetchers)
        selected = select_validators(registry.values(), refs)
    else:
        selected = list(registry.values())
    return [_validator_to_dict(v) for v in selected]


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

    try:
        config = upload_config.load(args.config)
    except (OSError, ValueError) as e:
        logger.error("%s", e)
        return 1

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
