#!/usr/bin/env python3
"""Sync fetcher entry scripts to Paramify and associate them to evidence sets.

A provisioning stage, separate from evidence upload (see docs/uploader_guide.md, step 5):
evidence upload runs every collection; this runs only when `fetchers/**` changes.
It reconciles the tenant to the repo — GitOps style — because the Paramify
`/scripts` API has no stable external key and no server-side versioning:

  * identity   — a marker stored in the script's `description` field
                 (`paramify-fetcher: <fetcher name>`), since scripts have no
                 referenceId to get-or-create against.
  * versioning — the fetcher.yaml `version` is the update signal; git is the
                 history of record; the app just holds "current".
  * drift      — a sha256 of the entry file guards against a code edit that
                 forgot to bump the version: warn (skip) by default, --force to push.

Per fetcher (one that declares an `evidence_set`):
  1. read the entry file (fetcher.py / fetcher.sh) — shared modules are ignored,
  2. get-or-create the script by its marker key (create / update / no-op),
  3. CONNECT the script to the fetcher's evidence set (get-or-created by
     reference_id, the same identity the evidence uploader uses).

Only SCRIPT associations are automated; solution-capability / control /
validator linkage stays Paramify-side.

Auth: PARAMIFY_UPLOAD_API_TOKEN (source-agnostic env — .env, secret manager, CI).
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from datetime import date
from pathlib import Path
from typing import Callable, Dict, List, Optional

from dotenv import load_dotenv

# Also runnable directly from any cwd, where only its own directory lands on
# sys.path. Its position in the repo is fixed, so derive the root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework import yaml_io  # noqa: E402
from framework.contract import DEFAULT_EVIDENCE_FREQUENCY  # noqa: E402
from framework.custom_tags import (  # noqa: E402
    ENTITY_EVIDENCE,
    ENTITY_SCRIPT,
    build_tagger,
)
from framework.paramify.client import ApiError, Client  # noqa: E402
from framework.paramify.connection import open_workspace  # noqa: E402
from framework.paramify.resources import Resources  # noqa: E402
from framework.sync.providers.desired import resolve_evidence_set  # noqa: E402

logger = logging.getLogger("paramify_scripts_uploader")

_MARKER_KEY = "paramify-fetcher"


# --------------------------------------------------------------------------- #
# Marker helpers — identity + version + hash live in the script `description`
# --------------------------------------------------------------------------- #
def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def build_description(fetcher_name: str, version: str, sha: str) -> str:
    return "\n".join([
        f"{_MARKER_KEY}: {fetcher_name}",
        f"version: {version}",
        f"sha256: {sha}",
        "",
        "Managed by paramify-fetchers; edits here are overwritten on the next sync.",
    ])


def parse_marker(description: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in (description or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _emit(on_event: Optional[Callable[[dict], None]], event: dict) -> None:
    if on_event is not None:
        on_event(event)


def load_config(path: Optional[str]) -> Dict:
    return (yaml_io.load_path(Path(path)) or {}) if path else {}


def _evidence_id(resources: Resources, ref: Dict) -> str:
    """The id of the fetcher's evidence set, creating the set when it is absent."""
    found = resources.evidence_by_reference([ref["reference_id"]]).get(ref["reference_id"])
    if found is None:
        found = resources.create_evidence({
            "referenceId": ref["reference_id"],
            "name": ref["name"],
            "frequency": ref["frequency"],
            # The frequency schedule counts from the day the set is created.
            "startDate": date.today().isoformat(),
        })
    return found.id


def _resolve_reference(fetcher_name: str, es: Dict, overrides: Dict) -> Dict:
    """The fetcher's evidence set with the uploader config's overrides applied, so
    the script lands on the same set the evidence upload targets."""
    resolved = resolve_evidence_set({"fetcher_name": fetcher_name, "evidence_set": es}, overrides) or {}
    resolved.setdefault("frequency", DEFAULT_EVIDENCE_FREQUENCY)
    return resolved


def _discover_specs(root: Path, include: Optional[set] = None) -> List[Dict]:
    """Build one script spec per fetcher that declares an evidence set and has a
    readable entry file.

    ``include`` restricts the sweep to fetchers whose name is in the set (the
    fetchers a manifest actually uses); ``None`` means every discovered fetcher.
    """
    from framework.config_loader import discover_fetchers  # lazy: repo-side only

    specs: List[Dict] = []
    for f in sorted(discover_fetchers(root).values(), key=lambda x: x.name):
        if include is not None and f.name not in include:
            continue
        if not f.evidence_set:
            logger.warning("%s: no evidence_set; skipping (nothing to associate a script to)", f.name)
            continue
        entry = f.entry_path
        if not entry.exists():
            logger.warning("%s: entry file %s not found; skipping", f.name, f.runtime_entry)
            continue
        try:
            code = entry.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            logger.warning("%s: cannot read entry file (%s); skipping", f.name, e)
            continue
        specs.append({
            "fetcher_name": f.name,
            "category": f.category,
            "version": str(f.version),
            "entry": f.runtime_entry,
            "code": code,
            "evidence_set": {
                "reference_id": f.evidence_set.reference_id,
                "name": f.evidence_set.name,
                "frequency": f.evidence_set.frequency,
            },
        })
    return specs


# --------------------------------------------------------------------------- #
# Sync
# --------------------------------------------------------------------------- #
def sync_scripts(
    root,
    *,
    config: Optional[Dict] = None,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
    reassociate: bool = False,
    include: Optional[set] = None,
    on_event: Optional[Callable[[dict], None]] = None,
    custom_tags: bool = True,
    client: Optional[Client] = None,
) -> Dict:
    """Reconcile every fetcher's entry script into Paramify and associate it.

    Actions per fetcher: create (new), update (version bumped), drift (code
    changed but version did not — warn, skip unless --force), noop. Association
    is ensured on create/update (and on every fetcher when --reassociate).
    A failure on one fetcher is recorded and the sweep goes on, except one no
    later call can survive (a rejected token), which ends it.
    """
    config = config or {}
    base_url, resources = open_workspace(config, base_url=base_url, token=token, client=client,
                                         dry_run=dry_run, log=logger)
    overrides = config.get("overrides") or {}

    root = Path(root)
    specs = _discover_specs(root, include)

    # Default custom tags on every script and set this sweep touches. Resolved
    # up front so a malformed `tags:` block fails like any other config mistake.
    try:
        tagger = build_tagger(
            None if dry_run else resources, config=config, root=root,
            override_off=None if custom_tags else "--no-tags",
        )
    except ValueError as e:
        logger.error(str(e))
        raise

    logger.info("Syncing %d fetcher script(s) → %s%s", len(specs), base_url, " (dry-run)" if dry_run else "")
    _emit(on_event, {"event": "sync_start", "base_url": base_url, "dry_run": dry_run, "fetchers": len(specs)})

    index: Dict[str, Dict] = {}
    if resources is not None:
        for script in resources.scripts():
            m = parse_marker(script.description)
            key = m.get(_MARKER_KEY)
            if key:
                index[key] = {"id": script.id, "version": m.get("version"), "sha256": m.get("sha256")}

    results: List[Dict] = []
    counts = {"created": 0, "updated": 0, "drift": 0, "noop": 0, "associated": 0, "errors": 0}

    def add_result(result: Dict) -> None:
        results.append(result)
        _emit(on_event, {"event": "sync_item", **result})

    def _tag(entity: str, entity_id: Optional[str], category: Optional[str]) -> List[str]:
        """Tag one entity; the names applied, or [] when off, dry-run, or refused."""
        if dry_run or not entity_id:
            return []
        info = tagger.tag(entity, entity_id, category)
        return info["tags"] if info["outcome"] in ("applied", "already") else []

    stopped: Optional[str] = None
    for spec in specs:
        name = spec["fetcher_name"]
        category = spec.get("category")
        sha = code_hash(spec["code"])
        cur = index.get(name)
        ref = _resolve_reference(name, spec["evidence_set"], overrides)
        description = build_description(name, spec["version"], sha)
        display_name = ref["name"]

        if cur is None:
            action = "create"
        elif (cur.get("version") or "") != spec["version"]:
            action = "update"
        elif (cur.get("sha256") or "") != sha:
            action = "drift"
        else:
            action = "noop"

        base = {"fetcher": name, "reference_id": ref["reference_id"], "action": action}

        if dry_run:
            note = None
            if action == "drift":
                note = "entry file changed but version not bumped" + (" (would push: --force)" if force else " (skipped)")
            add_result({
                **base,
                "outcome": f"would_{action}" if action != "drift" else "would_drift",
                "reason": note,
                "tags": tagger.plan(category),
            })
            continue

        assert resources is not None  # not dry_run => a client, or connect() raised
        script_id = cur["id"] if cur else None
        try:
            do_associate = reassociate

            if action == "create":
                script_id = resources.create_script(display_name, description, spec["code"])
                counts["created"] += 1
                do_associate = True
            elif action == "update":
                resources.update_script(script_id, display_name, description, spec["code"])
                counts["updated"] += 1
                do_associate = True
            elif action == "drift":
                counts["drift"] += 1
                if force:
                    resources.update_script(script_id, display_name, description, spec["code"])
                    do_associate = True
                    logger.warning("%s: entry changed without a version bump — pushed (--force)", name)
                else:
                    logger.warning("%s: entry file changed but version %s not bumped — skipped (use --force)", name, spec["version"])
                    add_result({**base, "outcome": "drift_skipped",
                                "reason": "entry changed but version not bumped; rerun with --force",
                                "tags": _tag(ENTITY_SCRIPT, script_id, category)})
                    continue
            else:
                counts["noop"] += 1

            if do_associate and script_id:
                evidence_id = _evidence_id(resources, ref)
                resources.associate(evidence_id, "SCRIPT", script_id)
                counts["associated"] += 1
                _tag(ENTITY_EVIDENCE, evidence_id, category)
                add_result({**base, "outcome": action, "script_id": script_id, "evidence_id": evidence_id,
                            "associated": True, "tags": _tag(ENTITY_SCRIPT, script_id, category)})
            else:
                add_result({**base, "outcome": action, "script_id": script_id, "associated": False,
                            "tags": _tag(ENTITY_SCRIPT, script_id, category)})

        except Exception as e:  # noqa: BLE001 — one bad fetcher must not abort the sweep
            logger.error("%s: sync failed: %s", name, e)
            counts["errors"] += 1
            add_result({**base, "outcome": "error", "error": str(e)[:300],
                        **({"script_id": script_id} if script_id else {})})
            if isinstance(e, ApiError) and e.fatal:
                # No later call can succeed (a rejected token). A script created
                # just now stays unassociated until a --reassociate run.
                stopped = str(e)[:300]
                logger.error("stopping the sweep: %s", stopped)
                break

    summary = {
        "base_url": base_url,
        "dry_run": dry_run,
        "fetchers": len(specs),
        **counts,
        "tags": tagger.summary(),
        "results": results,
        "stopped": stopped,
        "ok": counts["errors"] == 0,
    }
    logger.info(
        "Done: created=%d updated=%d drift=%d noop=%d associated=%d errors=%d",
        counts["created"], counts["updated"], counts["drift"], counts["noop"], counts["associated"], counts["errors"],
    )
    _emit(on_event, {"event": "sync_complete", **summary})
    return summary


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    parser = argparse.ArgumentParser(description="Sync fetcher entry scripts to Paramify and associate them to evidence sets")
    parser.add_argument("--root", help="Repo root (default: auto-detected)")
    parser.add_argument("--config", help="Uploader config YAML (base_url, overrides, tags)")
    parser.add_argument("--dry-run", action="store_true", help="Report the plan; read-only (no writes)")
    parser.add_argument("--force", action="store_true", help="Push scripts whose code drifted without a version bump")
    parser.add_argument("--reassociate", action="store_true", help="Ensure the script↔evidence-set association for every fetcher, not just changed ones")
    parser.add_argument("--manifest", help="Sync only the fetchers this manifest uses (default: manifest.yaml at the repo root)")
    parser.add_argument("--all", dest="all_fetchers", action="store_true", help="Sync every fetcher in the repo, not just the manifest's")
    args = parser.parse_args(argv)

    from framework import api

    root = Path(args.root) if args.root else api.find_repo_root()

    # Default to the manifest's fetchers; --all provisions the whole catalog. A
    # manifest that does not resolve is an error, never an empty manifest that
    # syncs nothing.
    include = None
    if not args.all_fetchers:
        try:
            mpath = api.resolve_manifest_path(root, args.manifest) if args.manifest else root / "manifest.yaml"
        except api.ManifestNotFound as e:
            logger.error("%s", e)
            return 1
        if not mpath.is_file():
            logger.error("no manifest at %s: name one with --manifest, or pass --all", mpath)
            return 1
        entries = (api.read_manifest(mpath).get("run") or {}).get("fetchers") or []
        include = {e.get("use") for e in entries if e.get("use")}

    try:
        summary = sync_scripts(
            root,
            config=load_config(args.config),
            dry_run=args.dry_run,
            force=args.force,
            reassociate=args.reassociate,
            include=include,
        )
    except ValueError:
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
