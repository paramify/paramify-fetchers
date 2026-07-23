#!/usr/bin/env python3
"""Sync fetcher entry scripts to Paramify and associate them to evidence sets.

A provisioning stage, separate from evidence upload (see docs/uploader_design.md):
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
import json
import logging
import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

logger = logging.getLogger("paramify_scripts_uploader")

DEFAULT_BASE_URL = "https://app.paramify.com/api/v0"
_REQUEST_TIMEOUT = 30
_MARKER_KEY = "paramify-fetcher"


# --------------------------------------------------------------------------- #
# Paramify API client — /scripts + the association endpoint
# --------------------------------------------------------------------------- #
class ParamifyError(RuntimeError):
    pass


class ParamifyScriptsClient:
    """Thin client over the Paramify REST API v0 scripts + association endpoints."""

    def __init__(self, token: str, base_url: str, timeout: int = _REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    # -- scripts ---------------------------------------------------------- #
    def list_scripts(self) -> List[Dict]:
        """All scripts in the tenant. The API offers no name/marker filter, so we
        fetch once and index client-side by the marker in each description."""
        r = self.session.get(f"{self.base_url}/scripts", timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("scripts", [])

    def create_script(self, name: str, description: str, code: str) -> Dict:
        body = {"name": name, "description": description, "code": code}
        r = self.session.post(f"{self.base_url}/scripts", json=body, timeout=self.timeout)
        if r.status_code not in (200, 201):
            raise ParamifyError(f"create script {name!r} failed (HTTP {r.status_code}): {r.text[:300]}")
        return r.json()

    def update_script(self, script_id: str, name: str, description: str, code: str) -> Dict:
        body = {"name": name, "description": description, "code": code}
        r = self.session.patch(f"{self.base_url}/scripts/{script_id}", json=body, timeout=self.timeout)
        if r.status_code not in (200, 201):
            raise ParamifyError(f"update script {script_id} failed (HTTP {r.status_code}): {r.text[:300]}")
        return r.json()

    # -- evidence set (mirrors paramify_evidence; kept minimal on purpose) - #
    def find_evidence_set(self, reference_id: str) -> Optional[str]:
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

    def create_evidence_set(self, reference_id: str, name: str) -> Optional[str]:
        body = {"referenceId": reference_id, "name": name, "automated": True}
        r = self.session.post(f"{self.base_url}/evidence", json=body, timeout=self.timeout)
        if r.status_code in (200, 201):
            return r.json().get("id")
        if r.status_code == 400 and "already exists" in r.text.lower():
            return self.find_evidence_set(reference_id)
        raise ParamifyError(
            f"create evidence set {reference_id} failed (HTTP {r.status_code}): {r.text[:300]}"
        )

    def get_or_create_evidence_set(self, reference_id: str, name: str) -> Optional[str]:
        return self.find_evidence_set(reference_id) or self.create_evidence_set(reference_id, name)

    # -- association ------------------------------------------------------ #
    def associate_script(self, evidence_id: str, script_id: str) -> None:
        """CONNECT a script to an evidence set. Tolerant of an already-connected
        state (the API has no pre-check endpoint), so re-runs are idempotent."""
        body = {"associationType": "CONNECT", "subjectType": "SCRIPT", "subjectId": script_id}
        r = self.session.post(
            f"{self.base_url}/evidence/{evidence_id}/associate",
            json=body,
            timeout=self.timeout,
        )
        if r.status_code in (200, 201, 204):
            return
        if r.status_code in (400, 409) and any(t in r.text.lower() for t in ("already", "exists", "connected")):
            return  # already associated — treat as success
        raise ParamifyError(
            f"associate script {script_id} -> evidence {evidence_id} failed "
            f"(HTTP {r.status_code}): {r.text[:300]}"
        )


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


def _base_url_error(base_url: str) -> Optional[str]:
    parsed = urlparse(base_url)
    if parsed.scheme != "https" and (parsed.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
        return (
            "base_url must be https to protect the API token "
            f"(got {base_url!r}); only localhost may use http"
        )
    return None


def load_config(path: Optional[str]) -> Dict:
    if not path:
        return {}
    import yaml  # local import: keeps the client importable without pyyaml
    data = yaml.safe_load(Path(path).read_text())
    return data or {}


def _resolve_reference(fetcher_name: str, es: Dict, overrides: Dict) -> Dict:
    """Apply any per-fetcher reference_id/name override so scripts associate to the
    SAME evidence set the evidence uploader targets (overrides share that config)."""
    ov = overrides.get(fetcher_name, {}) or {}
    return {
        "reference_id": ov.get("reference_id", es["reference_id"]),
        "name": ov.get("name", es["name"]),
    }


def _discover_specs(root: Path) -> List[Dict]:
    """Build one script spec per fetcher that declares an evidence set and has a
    readable entry file. Discovery lives here (not the client) so the client stays
    pure API I/O."""
    from framework.config_loader import discover_fetchers  # lazy: repo-side only

    specs: List[Dict] = []
    for f in sorted(discover_fetchers(root).values(), key=lambda x: x.name):
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
            "version": str(f.version),
            "entry": f.runtime_entry,
            "code": code,
            "evidence_set": {"reference_id": f.evidence_set.reference_id, "name": f.evidence_set.name},
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
    on_event: Optional[Callable[[dict], None]] = None,
) -> Dict:
    """Reconcile every fetcher's entry script into Paramify and associate it.

    Actions per fetcher: create (new), update (version bumped), drift (code
    changed but version did not — warn, skip unless --force), noop. Association
    is ensured on create/update (and on every fetcher when --reassociate).
    """
    load_dotenv()
    config = config or {}
    paramify_cfg = config.get("paramify") or {}
    base_url = (
        paramify_cfg.get("base_url") or base_url
        or os.environ.get("PARAMIFY_API_BASE_URL") or DEFAULT_BASE_URL
    )
    url_error = _base_url_error(base_url)
    if url_error:
        logger.error(url_error)
        raise ValueError(url_error)

    overrides = config.get("overrides") or {}
    token = token or os.environ.get("PARAMIFY_UPLOAD_API_TOKEN")
    if not token and not dry_run:
        msg = "PARAMIFY_UPLOAD_API_TOKEN is not set"
        logger.error(msg)
        raise ValueError(msg)

    root = Path(root)
    specs = _discover_specs(root)

    logger.info("Syncing %d fetcher script(s) → %s%s", len(specs), base_url, " (dry-run)" if dry_run else "")
    _emit(on_event, {"event": "sync_start", "base_url": base_url, "dry_run": dry_run, "fetchers": len(specs)})

    # A client is created whenever a token is available — even in dry-run, where
    # it makes only read-only GETs so the plan reflects the real tenant state.
    client = ParamifyScriptsClient(token, base_url) if token else None
    index: Dict[str, Dict] = {}
    if client is not None:
        for s in client.list_scripts():
            m = parse_marker(s.get("description"))
            key = m.get(_MARKER_KEY)
            if key:
                index[key] = {"id": s.get("id"), "version": m.get("version"), "sha256": m.get("sha256")}

    results: List[Dict] = []
    counts = {"created": 0, "updated": 0, "drift": 0, "noop": 0, "associated": 0, "errors": 0}

    def add_result(result: Dict) -> None:
        results.append(result)
        _emit(on_event, {"event": "sync_item", **result})

    for spec in specs:
        name = spec["fetcher_name"]
        sha = code_hash(spec["code"])
        cur = index.get(name)
        ref = _resolve_reference(name, spec["evidence_set"], overrides)
        description = build_description(name, spec["version"], sha)
        display_name = ref["name"]  # decided: script display name == evidence_set name

        # Decide the action from the tenant marker (create when we couldn't list).
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
            add_result({**base, "outcome": f"would_{action}" if action != "drift" else "would_drift", "reason": note})
            continue

        try:
            script_id = cur["id"] if cur else None
            do_associate = reassociate

            if action == "create":
                script_id = client.create_script(display_name, description, spec["code"]).get("id")
                counts["created"] += 1
                do_associate = True
            elif action == "update":
                client.update_script(script_id, display_name, description, spec["code"])
                counts["updated"] += 1
                do_associate = True
            elif action == "drift":
                counts["drift"] += 1
                if force:
                    client.update_script(script_id, display_name, description, spec["code"])
                    do_associate = True
                    logger.warning("%s: entry changed without a version bump — pushed (--force)", name)
                else:
                    logger.warning("%s: entry file changed but version %s not bumped — skipped (use --force)", name, spec["version"])
                    add_result({**base, "outcome": "drift_skipped",
                                "reason": "entry changed but version not bumped; rerun with --force"})
                    continue
            else:  # noop
                counts["noop"] += 1

            if do_associate and script_id:
                evidence_id = client.get_or_create_evidence_set(ref["reference_id"], ref["name"])
                if not evidence_id:
                    raise ParamifyError(f"could not get or create evidence set {ref['reference_id']}")
                client.associate_script(evidence_id, script_id)
                counts["associated"] += 1
                add_result({**base, "outcome": action, "script_id": script_id, "evidence_id": evidence_id, "associated": True})
            else:
                add_result({**base, "outcome": action, "script_id": script_id, "associated": False})

        except Exception as e:  # noqa: BLE001 — one bad fetcher must not abort the sweep
            logger.error("%s: sync failed: %s", name, e)
            counts["errors"] += 1
            add_result({**base, "outcome": "error", "error": str(e)[:300]})
            continue

    summary = {
        "base_url": base_url,
        "dry_run": dry_run,
        "fetchers": len(specs),
        **counts,
        "results": results,
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
    parser.add_argument("--config", help="Uploader config YAML (base_url, overrides)")
    parser.add_argument("--dry-run", action="store_true", help="Report the plan; read-only (no writes)")
    parser.add_argument("--force", action="store_true", help="Push scripts whose code drifted without a version bump")
    parser.add_argument("--reassociate", action="store_true", help="Ensure the script↔evidence-set association for every fetcher, not just changed ones")
    args = parser.parse_args(argv)

    if args.root:
        root = Path(args.root)
    else:
        from framework.api import find_repo_root
        root = find_repo_root()

    try:
        summary = sync_scripts(
            root,
            config=load_config(args.config),
            dry_run=args.dry_run,
            force=args.force,
            reassociate=args.reassociate,
        )
    except ValueError:
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
