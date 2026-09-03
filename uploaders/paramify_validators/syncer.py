#!/usr/bin/env python3
"""Sync validators from the central registry to Paramify and associate them.

A separate stage from evidence upload (per docs/validators_design.md): it reads
the `validators/` registry, scopes to the validators whose `evidence_sets`
intersect the sets a manifest produces, and for each one:

  1. resolves whether the customer's Paramify instance already has it — by a
     cached id (the lock file) or, failing that, by matching `name`,
  2. **creates it only if absent** (`POST /validators`); an existing validator is
     never patched unless `--update` is passed, so customer tuning survives,
  3. **associates on create only** — after creating, CONNECTs the validator to
     each of its evidence sets (`POST /evidence/{id}/associate`); it never
     re-asserts wiring on a validator that already existed.

The shipped validators are TEMPLATES (~80% right); customers tune them in
Paramify. That is why the default is create-or-skip and why the per-instance
validator id lives in a customer-side lock file, never in the shared registry.

Auth: PARAMIFY_UPLOAD_API_TOKEN (source-agnostic env — .env, secret manager, CI).
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

logger = logging.getLogger("paramify_validators_syncer")

DEFAULT_BASE_URL = "https://app.paramify.com/api/v0"
DEFAULT_LOCK_PATH = "./.paramify/validators-sync.lock.json"
_REQUEST_TIMEOUT = 30


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Paramify API client
# --------------------------------------------------------------------------- #
class ParamifyError(RuntimeError):
    pass


class ValidatorClient:
    """Thin client over the Paramify REST API v0 validator + associate endpoints."""

    def __init__(self, token: str, base_url: str, timeout: int = _REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def list_validators(self) -> List[Dict]:
        """All validators on the instance. GET /validators exposes no name filter,
        so name-matching (for reconcile) is done client-side over this list."""
        r = self.session.get(f"{self.base_url}/validators", timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return data.get("validators", []) if isinstance(data, dict) else (data or [])

    def create_validator(self, payload: Dict) -> str:
        r = self.session.post(
            f"{self.base_url}/validators", json=payload, timeout=self.timeout
        )
        if r.status_code not in (200, 201):
            raise ParamifyError(
                f"create validator {payload.get('name')!r} failed "
                f"(HTTP {r.status_code}): {r.text[:300]}"
            )
        vid = r.json().get("id")
        if not vid:
            raise ParamifyError(
                f"create validator {payload.get('name')!r} returned no id: {r.text[:300]}"
            )
        return vid

    def update_validator(self, validator_id: str, payload: Dict) -> None:
        r = self.session.patch(
            f"{self.base_url}/validators/{validator_id}",
            json=payload,
            timeout=self.timeout,
        )
        if r.status_code not in (200, 201, 204):
            raise ParamifyError(
                f"update validator {validator_id} failed "
                f"(HTTP {r.status_code}): {r.text[:300]}"
            )

    def find_evidence_set(self, reference_id: str) -> Optional[str]:
        """Return the evidence-set id for a reference_id, or None. Server-side filter."""
        r = self.session.get(
            f"{self.base_url}/evidence",
            params={"referenceId": reference_id},
            timeout=self.timeout,
        )
        r.raise_for_status()
        for ev in r.json().get("evidences", []):
            if ev.get("referenceId") == reference_id:
                return ev.get("id")
        return None

    def associate_validator(self, evidence_id: str, validator_id: str) -> None:
        body = {
            "associationType": "CONNECT",
            "subjectType": "VALIDATOR",
            "subjectId": validator_id,
        }
        r = self.session.post(
            f"{self.base_url}/evidence/{evidence_id}/associate",
            json=body,
            timeout=self.timeout,
        )
        if r.status_code not in (200, 201, 204):
            raise ParamifyError(
                f"associate validator {validator_id} to set {evidence_id} failed "
                f"(HTTP {r.status_code}): {r.text[:300]}"
            )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _base_url_error(base_url: str) -> Optional[str]:
    parsed = urlparse(base_url)
    if parsed.scheme != "https" and (parsed.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
        return (
            "base_url must be https to protect the API token "
            f"(got {base_url!r}); only localhost may use http"
        )
    return None


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
    else:  # ATTESTATION
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
    client: Optional[ValidatorClient] = None,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    dry_run: bool = False,
    update: bool = False,
    lock_path: Optional[str] = None,
    on_event: Optional[Callable[[dict], None]] = None,
    config: Optional[Dict] = None,
) -> Dict:
    """Reconcile a list of registry validator dicts against Paramify.

    Create-or-skip; associate on create only; `update` opt-in patches existing;
    `dry_run` performs no writes (reads only, to report accurately, when a client
    is available). Returns a summary dict; never raises for per-validator errors
    (those are isolated and counted), only for setup errors.
    """
    load_dotenv()
    config = config or {}
    paramify_cfg = config.get("paramify") or {}
    base_url = (
        paramify_cfg.get("base_url")
        or base_url
        or os.environ.get("PARAMIFY_API_BASE_URL")
        or DEFAULT_BASE_URL
    )
    url_error = _base_url_error(base_url)
    if url_error:
        logger.error(url_error)
        raise ValueError(url_error)

    lock_file = Path(
        lock_path or (config.get("validators") or {}).get("lock_path") or DEFAULT_LOCK_PATH
    )
    lock = load_lock(lock_file)

    token = token or os.environ.get("PARAMIFY_UPLOAD_API_TOKEN")
    if client is None:
        # Build a client whenever we have a token — even in dry-run, so reads can
        # report create-vs-skip precisely. Writes stay gated on `not dry_run`.
        if token:
            client = ValidatorClient(token, base_url)
        elif not dry_run:
            msg = "PARAMIFY_UPLOAD_API_TOKEN is not set"
            logger.error(msg)
            raise ValueError(msg)

    _emit(on_event, {
        "event": "sync_start",
        "base_url": base_url,
        "dry_run": dry_run,
        "update": update,
        "validators": len(validators),
        "lock_path": str(lock_file),
    })

    # Lazily fetched name -> id index over existing validators (for reconcile).
    _name_index: Optional[Dict[str, str]] = None

    def name_index() -> Dict[str, str]:
        nonlocal _name_index
        if _name_index is None:
            if client is None:
                _name_index = {}
            else:
                # Build fully, THEN cache. If list_validators() raises, we do NOT
                # cache a half/empty index — the exception re-raises per validator
                # (each isolated as an error), so a transient GET failure can never
                # leave reconcile blind and create duplicates. Fail closed.
                index: Dict[str, str] = {}
                for ex in client.list_validators():
                    if ex.get("name") and ex.get("id"):
                        index.setdefault(ex["name"], ex["id"])
                _name_index = index
        return _name_index

    results: List[Dict] = []
    created = updated = skipped = associated = set_not_found = errors = assoc_errors = 0

    def add_result(r: Dict) -> None:
        results.append(r)
        _emit(on_event, {"event": "sync_validator", **r})

    for v in validators:
        key = v.get("key", "<unknown>")  # fallback label if the dict is malformed
        try:
            key = v["key"]  # inside try: a missing key is an isolated error, not a crash
            existing_id = lock.get(key)
            adopted = False
            if existing_id is None and client is not None:
                existing_id = name_index().get(v["name"])
                if existing_id:
                    lock[key] = existing_id
                    adopted = True

            payload = build_payload(v)
            refs = v.get("evidence_sets", [])

            # ---- create (absent) -> create, then associate on create only ----
            if existing_id is None:
                if dry_run:
                    created += 1
                    add_result({
                        "key": key, "outcome": "would_create", "evidence_sets": refs,
                    })
                    continue
                assert client is not None  # not dry_run => token present or we raised
                vid = client.create_validator(payload)
                lock[key] = vid  # persist before associating so a re-run won't recreate
                created += 1
                # A failed association must NOT undo/duplicate the created validator
                # nor mark the whole validator an error — isolate per set.
                assoc, missing, failed = [], [], []
                for ref in refs:
                    try:
                        eid = client.find_evidence_set(ref)
                        if eid:
                            client.associate_validator(eid, vid)
                            assoc.append(ref)
                            associated += 1
                        else:
                            missing.append(ref)
                            set_not_found += 1
                    except Exception as ae:
                        failed.append(ref)
                        assoc_errors += 1
                        logger.error("%s: associate to %s failed: %s", key, ref, ae)
                result = {
                    "key": key, "outcome": "created", "validator_id": vid,
                    "associated": assoc, "set_not_found": missing,
                }
                if failed:
                    result["associate_failed"] = failed
                add_result(result)
                continue

            # ---- exists -> skip, or (opt-in) update; never re-associate ----
            if update:
                if dry_run:
                    add_result({"key": key, "outcome": "would_update", "validator_id": existing_id})
                else:
                    assert client is not None  # not dry_run => token present or we raised
                    client.update_validator(existing_id, payload)
                    add_result({"key": key, "outcome": "updated", "validator_id": existing_id})
                updated += 1
                continue

            skipped += 1
            add_result({
                "key": key,
                "outcome": "would_skip_exists" if dry_run else "skipped_exists",
                "validator_id": existing_id,
                "adopted": adopted,
            })
        except Exception as e:  # per-validator isolation
            logger.error("%s: sync failed: %s", key, e)
            errors += 1
            add_result({"key": key, "outcome": "error", "error": str(e)[:300]})
            continue

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
        "results": results,
        "lock_path": str(lock_written) if lock_written else str(lock_file),
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
        select_validators,
    )

    registry = discover_validators(root)
    if reference_ids is not None:
        selected = select_validators(registry.values(), set(reference_ids))
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
        summary = sync_validators(
            validators, dry_run=args.dry_run, update=args.update, lock_path=args.lock
        )
    except ValueError:
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
