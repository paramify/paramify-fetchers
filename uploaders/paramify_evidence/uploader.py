#!/usr/bin/env python3
"""Upload enveloped evidence from a run directory to Paramify.

A separate stage (per docs/design.md): reads a completed `run-<timestamp>/`
directory of envelope-wrapped evidence files and pushes each to Paramify as an
artifact on its evidence set. It reads nothing from fetcher source and needs only
the run directory plus a Paramify API token, so it can be pointed at an old run to
re-upload. See docs/uploader_design.md.

Per evidence file the uploader:
  1. reads the envelope `metadata.evidence_set` (skips with a warning if absent),
  2. applies any customer override (reference_id / name / instructions / frequency),
  3. get-or-creates the evidence set by reference_id,
  4. picks the channel to upload through, where the set has any (see
     resolve_channel — artifacts uploaded outside a configured channel do not
     count toward the solution capability),
  5. attaches the evidence as an artifact (idempotent: skips if an artifact with
     the same filename + run_id already exists on the set).

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
import yaml
from dotenv import load_dotenv

# This file is also runnable directly (`python uploaders/paramify_evidence/uploader.py`)
# from any cwd, where only its own directory lands on sys.path. Its position in the
# repo is fixed, so derive the root rather than duplicating the token-resolution
# rule locally — duplicating it is what let the uploader and the fetchers disagree.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework.contract import DEFAULT_EVIDENCE_FREQUENCY  # noqa: E402
from framework.paramify_auth import (  # noqa: E402
    READ_TOKEN_ENV,
    UPLOAD_TOKEN_ENV,
    resolve_base_url,
    resolve_upload_token,
)

logger = logging.getLogger("paramify_evidence_uploader")

_REQUEST_TIMEOUT = 30
_ENVELOPE_KEYS = {"schema_version", "metadata", "payload"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Paramify API client
# --------------------------------------------------------------------------- #
class ParamifyError(RuntimeError):
    pass


class ChannelError(ParamifyError):
    """No single channel could be resolved for an evidence set.

    Its own type because it is a per-file config problem, not an API failure:
    upload_run reports the file and carries on with the batch.
    """


class ParamifyClient:
    """Thin client over the Paramify REST API v0 evidence endpoints."""

    def __init__(self, token: str, base_url: str, timeout: int = _REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def find_evidence_set(self, reference_id: str) -> Optional[Dict]:
        """Return the evidence-set record for a reference_id, or None. Server-side filter.

        The whole record rather than just its id: the response carries the set's
        `channels[]`, which is what channel routing resolves against, and this
        call is made either way.
        """
        r = self.session.get(
            f"{self.base_url}/evidence",
            params={"referenceId": reference_id},
            timeout=self.timeout,
        )
        r.raise_for_status()
        for ev in r.json().get("evidences", []):
            if ev.get("referenceId") == reference_id:
                return ev
        return None

    def create_evidence_set(self, es: Dict) -> Optional[Dict]:
        """Create the evidence set; on 'already exists' fall back to find (idempotent)."""
        body = {
            "referenceId": es["reference_id"],
            "name": es["name"],
            "automated": True,
            # Envelopes written before the field existed carry no frequency.
            "frequency": es.get("frequency") or DEFAULT_EVIDENCE_FREQUENCY,
        }
        if es.get("description"):
            body["description"] = es["description"]
        if es.get("instructions"):
            body["instructions"] = es["instructions"]
        r = self.session.post(f"{self.base_url}/evidence", json=body, timeout=self.timeout)
        if r.status_code in (200, 201):
            return r.json()
        if r.status_code == 400 and "already exists" in r.text.lower():
            return self.find_evidence_set(es["reference_id"])
        raise ParamifyError(
            f"create evidence set {es['reference_id']} failed (HTTP {r.status_code}): {r.text[:300]}"
        )

    def get_or_create_evidence_set(self, es: Dict) -> Optional[Dict]:
        return self.find_evidence_set(es["reference_id"]) or self.create_evidence_set(es)

    def artifact_exists(self, evidence_id: str, original_file_name: str, run_id: Optional[str]) -> bool:
        """True if an artifact with this filename AND run_id already exists on the set.

        Makes re-running the uploader on the same run idempotent, while still letting
        a *different* run (different run_id) add a new versioned artifact.
        """
        if not run_id:
            return False
        r = self.session.get(
            f"{self.base_url}/evidence/{evidence_id}/artifacts",
            params={"originalFileName": original_file_name},
            timeout=self.timeout,
        )
        if r.status_code != 200:
            return False
        data = r.json()
        artifacts = data if isinstance(data, list) else data.get("artifacts", [])
        for a in artifacts:
            # Exact-token match on the note's `run_id=<value>` field — a bare
            # substring test would wrongly dedup run_id "1" against "run_id=12".
            note_tokens = (a.get("note") or "").split("; ")
            if a.get("originalFileName") == original_file_name and f"run_id={run_id}" in note_tokens:
                return True
        return False

    def upload_artifact(self, evidence_id: str, filename: str, content: bytes, artifact_meta: Dict) -> Dict:
        files = {
            "file": (filename, content, "application/json"),
            "artifact": ("artifact.json", json.dumps(artifact_meta), "application/json"),
        }
        r = self.session.post(
            f"{self.base_url}/evidence/{evidence_id}/artifacts/upload",
            files=files,
            timeout=self.timeout,
        )
        if r.status_code not in (200, 201):
            raise ParamifyError(
                f"upload artifact {filename} failed (HTTP {r.status_code}): {r.text[:300]}"
            )
        return r.json()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def is_enveloped(obj) -> bool:
    return isinstance(obj, dict) and _ENVELOPE_KEYS <= set(obj.keys())


def find_latest_run(output_dir: Path) -> Optional[Path]:
    """The newest run that holds evidence — not simply the newest run, which is
    often a pipeline manifest's (issue reports only) sharing the same output dir."""
    if not output_dir.is_dir():
        return None
    runs = sorted((p for p in output_dir.glob("run-*") if p.is_dir()), reverse=True)
    return next((r for r in runs if any(iter_evidence_files(r))), None)


def iter_evidence_files(run_dir: Path):
    for p in sorted(run_dir.glob("*.json")):
        if p.name in ("_run_metadata.json", "upload_log.json"):
            continue
        yield p


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


def _channel_labels(channels: List[Dict]) -> str:
    return ", ".join(ch.get("referenceId") or ch.get("id") or "?" for ch in channels) or "none"


def resolve_channel(
    channels: Optional[List[Dict]], *, where: str = "this evidence set"
) -> Optional[Dict]:
    """The channel to upload an artifact through, or None for unchanneled.

    Channels are created in the Paramify app; the API only lets us choose among
    the ones a set already has. Where a customer has configured one, an artifact
    uploaded outside it is invisible to validation on the solution capability —
    so a set that has a channel uses it, and only a set with none at all uploads
    unchanneled. Neither case needs any configuration.

    More than one channel on a set is out of scope for now, and raises rather
    than picking: choosing wrong looks exactly like succeeding, so there is
    nothing to be gained by guessing before the multi-channel rules exist.
    """
    channels = list(channels or [])
    if len(channels) == 1:
        return channels[0]
    if not channels:
        return None
    raise ChannelError(
        f"{where} has {len(channels)} channels ({_channel_labels(channels)}); "
        "uploading through more than one channel is not supported yet"
    )


# Target fields preferred as the single identifying suffix in an artifact title.
# program_name leads: where a target carries both a readable label and an opaque
# id (Paramify programs), the reviewer picking among artifacts needs the label.
# Fetchers whose id IS readable (gitlab's group/project) declare no program_name,
# so they fall through to project_id exactly as before.
_TITLE_KEYS = ("program_name", "project_id", "name", "id", "region", "cluster", "host", "bucket", "account_id")


def build_artifact_meta(metadata: Dict, es_name: str, channel_id: Optional[str] = None) -> Dict:
    target = metadata.get("target")
    title = es_name
    if target:
        # One identifying value, not every field (avoids dumping url/branch into the title).
        suffix = next((str(target[k]) for k in _TITLE_KEYS if target.get(k)), None)
        if suffix is None:
            suffix = next((str(v) for v in target.values()), None)
        if suffix:
            title = f"{es_name} - {suffix}"
    note_parts = [
        f"fetcher={metadata.get('fetcher_name')}",
        f"version={metadata.get('fetcher_version')}",
        f"run_id={metadata.get('run_id')}",
        f"status={metadata.get('status')}",
    ]
    if target:
        note_parts.append(f"target={json.dumps(target, separators=(',', ':'))}")
    meta = {
        "title": title,
        "note": "; ".join(note_parts),
        "effectiveDate": metadata.get("collected_at") or _utc_now(),
    }
    if channel_id:
        meta["channelId"] = channel_id
    return meta


def artifact_content(envelope: Dict, mode: str) -> bytes:
    """Bytes to upload: the whole envelope (default, self-describing) or just the payload."""
    obj = envelope["payload"] if mode == "payload" else envelope
    return json.dumps(obj, indent=2).encode("utf-8")


def load_config(path: Optional[str]) -> Dict:
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text())
    return data or {}


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


def upload_run(
    run_dir: Path,
    *,
    config: Optional[Dict] = None,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    dry_run: bool = False,
    on_event: Optional[Callable[[dict], None]] = None,
) -> Dict:
    """Upload one completed run directory.

    The standalone CLI still logs to stderr, while front-ends can pass on_event
    to render upload_start / upload_file / upload_complete in their own UI.
    """
    load_dotenv()
    config = config or {}
    paramify_cfg = config.get("paramify") or {}
    base_url, _ = resolve_base_url(paramify_cfg.get("base_url") or base_url)

    url_error = _base_url_error(base_url)
    if url_error:
        logger.error(url_error)
        raise ValueError(url_error)

    overrides = config.get("overrides") or {}
    skip_failed = bool(config.get("skip_failed", False))
    artifact_payload = config.get("artifact_payload", "envelope")
    if artifact_payload not in ("envelope", "payload"):
        msg = f"artifact_payload must be 'envelope' or 'payload', got {artifact_payload!r}"
        logger.error(msg)
        raise ValueError(msg)

    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        msg = f"No run directory to upload: {run_dir}"
        logger.error(msg)
        raise ValueError(msg)

    if not token:
        token, _ = resolve_upload_token()
    if not token and not dry_run:
        msg = (
            f"{UPLOAD_TOKEN_ENV} is not set (or {READ_TOKEN_ENV} as a fallback)"
        )
        logger.error(msg)
        raise ValueError(msg)

    files = list(iter_evidence_files(run_dir))
    logger.info("Uploading evidence from %s%s", run_dir, " (dry-run)" if dry_run else "")
    _emit(on_event, {
        "event": "upload_start",
        "run_dir": str(run_dir),
        "base_url": base_url,
        "dry_run": dry_run,
        "files": len(files),
    })

    client = None if dry_run else ParamifyClient(token, base_url)
    results: List[Dict] = []
    uploaded = skipped_dup = skipped_failed = errors = seen = 0

    def add_result(result: Dict) -> None:
        results.append(result)
        _emit(on_event, {"event": "upload_file", **result})

    for path in files:
        seen += 1
        try:
            envelope = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            logger.error("%s: cannot read as JSON (%s)", path.name, e)
            errors += 1
            add_result({"file": path.name, "outcome": "error", "reason": f"cannot read as JSON ({e})"})
            continue

        # Per-file isolation: one bad file (malformed envelope, API error, etc.)
        # must never abort the batch — the uploader processes arbitrary run dirs.
        try:
            if not is_enveloped(envelope):
                logger.error("%s: not envelope-wrapped (no metadata/payload); skipping", path.name)
                errors += 1
                add_result({"file": path.name, "outcome": "error", "reason": "not envelope-wrapped"})
                continue

            metadata = envelope["metadata"]
            es = resolve_evidence_set(metadata, overrides)
            if not es or not es.get("reference_id") or not es.get("name"):
                logger.error(
                    "%s: evidence_set missing or incomplete (need reference_id and name); skipping",
                    path.name,
                )
                errors += 1
                add_result({"file": path.name, "outcome": "error", "reason": "missing/incomplete evidence_set"})
                continue

            if metadata.get("status") == "failed" and skip_failed:
                logger.info("%s: status=failed and skip_failed set; skipping", path.name)
                skipped_failed += 1
                add_result({"file": path.name, "outcome": "skipped_failed", "reference_id": es["reference_id"]})
                continue

            if dry_run:
                # Title only — the channel needs the set's record, and a dry-run
                # makes no API calls at all.
                logger.info(
                    "would upload %s → set %s (%s) as %r",
                    path.name, es["reference_id"], es["name"],
                    build_artifact_meta(metadata, es["name"])["title"],
                )
                add_result({"file": path.name, "outcome": "would_upload", "reference_id": es["reference_id"]})
                continue

            record = client.get_or_create_evidence_set(es)
            evidence_id = (record or {}).get("id")
            if not evidence_id:
                logger.error("%s: could not get or create evidence set %s", path.name, es["reference_id"])
                errors += 1
                add_result({"file": path.name, "outcome": "error", "reference_id": es["reference_id"]})
                continue

            try:
                channel = resolve_channel(
                    record.get("channels"),
                    where=f"evidence set {es['reference_id']}",
                )
            except ChannelError as e:
                # Before the dedup check on purpose: an unroutable set is worth
                # reporting on every file it affects, not just new ones.
                logger.error("%s: %s", path.name, e)
                errors += 1
                add_result({
                    "file": path.name,
                    "outcome": "error",
                    "reference_id": es["reference_id"],
                    "evidence_id": evidence_id,
                    "reason": str(e),
                })
                continue

            if client.artifact_exists(evidence_id, path.name, metadata.get("run_id")):
                logger.info("%s: artifact already uploaded for this run; skipping", path.name)
                skipped_dup += 1
                add_result({
                    "file": path.name,
                    "outcome": "skipped_duplicate",
                    "reference_id": es["reference_id"],
                    "evidence_id": evidence_id,
                })
                continue
            content = artifact_content(envelope, artifact_payload)
            meta_art = build_artifact_meta(
                metadata, es["name"], channel_id=channel["id"] if channel else None
            )
            art = client.upload_artifact(evidence_id, path.name, content, meta_art)
            uploaded += 1
            logger.info(
                "uploaded %s → set %s%s artifact %s",
                path.name,
                es["reference_id"],
                f" via {channel.get('referenceId') or channel['id']}" if channel else "",
                art.get("id"),
            )
            # The channel is logged because it cannot be read back: an artifact
            # response carries no channelId, so upload_log.json is the only
            # record of where each artifact was sent.
            add_result({
                "file": path.name,
                "outcome": "uploaded",
                "reference_id": es["reference_id"],
                "evidence_id": evidence_id,
                "artifact_id": art.get("id"),
                "channel": (channel.get("referenceId") if channel else None),
                "channel_id": (channel.get("id") if channel else None),
            })
        except Exception as e:
            logger.error("%s: upload failed: %s", path.name, e)
            errors += 1
            add_result({"file": path.name, "outcome": "error", "error": str(e)[:300]})
            continue

    if seen == 0:
        msg = f"no evidence files found in {run_dir} — nothing to upload (wrong directory?)"
        logger.error(msg)
        raise ValueError(msg)

    log_path = None
    if not dry_run:
        log = {
            "uploaded_at": _utc_now(),
            "run_dir": str(run_dir),
            "uploaded": uploaded,
            "skipped_duplicate": skipped_dup,
            "skipped_failed": skipped_failed,
            "errors": errors,
            "results": results,
        }
        log_path = run_dir / "upload_log.json"
        try:
            log_path.write_text(json.dumps(log, indent=2))
        except OSError as e:
            logger.warning("could not write upload_log.json (%s); log follows:\n%s", e, json.dumps(log, indent=2))
            log_path = None

    summary = {
        "run_dir": str(run_dir),
        "base_url": base_url,
        "dry_run": dry_run,
        "uploaded": uploaded,
        "skipped_duplicate": skipped_dup,
        "skipped_failed": skipped_failed,
        "errors": errors,
        "files": seen,
        "results": results,
        "log_path": str(log_path) if log_path else None,
        "ok": errors == 0,
    }
    logger.info(
        "Done: uploaded=%d skipped_duplicate=%d skipped_failed=%d errors=%d",
        uploaded, skipped_dup, skipped_failed, errors,
    )
    _emit(on_event, {"event": "upload_complete", **summary})
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

    parser = argparse.ArgumentParser(description="Upload enveloped evidence to Paramify")
    parser.add_argument("run_dir", nargs="?", help="Run directory to upload (default: latest under --output-dir)")
    parser.add_argument("--output-dir", default="./evidence", help="Base dir to find the latest run in (default ./evidence)")
    parser.add_argument("--config", help="Uploader config YAML (base_url, overrides, skip_failed, artifact_payload)")
    parser.add_argument("--dry-run", action="store_true", help="Resolve and report what would upload; no API calls")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir) if args.run_dir else find_latest_run(Path(args.output_dir))
    if not run_dir or not run_dir.is_dir():
        logger.error(
            "No run directory to upload (looked for %s)",
            args.run_dir or f"latest run-* under {args.output_dir}",
        )
        return 1
    try:
        summary = upload_run(run_dir, config=load_config(args.config), dry_run=args.dry_run)
    except ValueError:
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
