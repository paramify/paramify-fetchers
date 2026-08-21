#!/usr/bin/env python3
"""Upload raw issue reports from a run directory into Paramify assessment intake.

The sibling of [`paramify_evidence`](../paramify_evidence/uploader.py), for the
other collection kind. Where that uploader attaches an envelope-wrapped JSON file
to an evidence set, this one posts a scan report — the vendor's own CSV, XML, JSON
or Nessus file — to `POST /assessment/{assessmentId}/intake`, where Paramify
parses it into issues.

Reads `<run>/issue-reports/_issue_reports.json` (written by the runner; see
framework/issue_reports.py) and uploads each report it lists. Like the evidence
uploader it reads nothing from fetcher source and needs only a run directory plus
a token, so it can be pointed at an old run to re-upload.

Two behaviors differ from the evidence uploader, both forced by the endpoint:

- **Files are sent byte-for-byte.** Paramify's intake parses the vendor's own
  structure, so the bytes on disk are the bytes posted. Nothing is re-serialized,
  and identity travels in the `artifact` metadata part and the sidecar instead.
- **Dedup is local.** The endpoint documents that it *adds* to a cycle's intake
  without replacing, and offers no way to list what is already attached, so
  re-running would silently create duplicate issue sets. This uploader records
  what it sent in `<run>/issue-reports/_intake_log.json` and skips those on a
  second run. The log is the only thing making a re-run safe: delete it and a
  re-run WILL duplicate.

Auth: PARAMIFY_UPLOAD_API_TOKEN (source-agnostic env — .env, secret manager, CI).

Endpoint contract per framework/reference/paramify_api_0.6.0.json.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import quote, urlparse

import requests
import yaml
from dotenv import load_dotenv

# Runnable directly (`python uploaders/paramify_issues/uploader.py`) from any cwd,
# where only its own directory lands on sys.path. Its position in the repo is
# fixed, so derive the root rather than duplicating the token-resolution rule.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework.issue_reports import (  # noqa: E402
    INTAKE_LOG_NAME,
    ISSUE_REPORTS_DIR,
    SIDECAR_NAME,
)
from framework.paramify_auth import (  # noqa: E402
    READ_TOKEN_ENV,
    UPLOAD_TOKEN_ENV,
    resolve_base_url,
    resolve_upload_token,
)

logger = logging.getLogger("paramify_issues_uploader")

# Generous next to the evidence uploader's 30s: the endpoint accepts files up to
# 10 GB, and a full Nessus export is routinely hundreds of megabytes.
_REQUEST_TIMEOUT = 600

# Content types the intake endpoint accepts, keyed by the fetcher's declared
# `output.type`. A report whose format is not here cannot be intaken at all, which
# the fetcher schema already refuses — this is the second line of that fence.
_CONTENT_TYPES = {
    "csv": "text/csv",
    "json": "application/json",
    "xml": "application/xml",
    # Nessus files are XML. Paramify keys the parser off the file extension, so
    # the generic XML type is correct and the .nessus name carries the meaning.
    "nessus": "application/xml",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Paramify API client
# --------------------------------------------------------------------------- #
class ParamifyError(RuntimeError):
    pass


class IntakeNotEnabled(ParamifyError):
    """HTTP 501 — assessment intake is not enabled for this workspace.

    Its own type because it is not a per-file problem: every subsequent upload in
    the batch will fail the same way, so the run stops instead of issuing one
    identical error per report.
    """


class ParamifyClient:
    """Thin client over the Paramify REST API v0 assessment-intake endpoint."""

    def __init__(self, token: str, base_url: str, timeout: int = _REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def submit_intake(
        self, assessment_id: str, filename: str, content: bytes, content_type: str,
        artifact_meta: Dict,
    ) -> Dict:
        """POST one report to an assessment's intake. Returns the response body.

        The `artifact` part is required by the endpoint even when every field in
        it is optional, and is sent as a JSON part exactly as the evidence
        uploader sends its own artifact metadata.
        """
        files = {
            # The spec asks for a URL-encoded filename ("certain special
            # characters may cause upload errors"); Paramify decodes it. safe=""
            # so a slash in a vendor-generated name cannot escape the field.
            "file": (quote(filename, safe=""), content, content_type),
            "artifact": ("artifact.json", json.dumps(artifact_meta), "application/json"),
        }
        r = self.session.post(
            f"{self.base_url}/assessment/{assessment_id}/intake",
            files=files,
            timeout=self.timeout,
        )
        if r.status_code == 501:
            raise IntakeNotEnabled(
                f"assessment intake is not enabled for this workspace (HTTP 501): "
                f"{_error_message(r)}"
            )
        if r.status_code == 404:
            raise ParamifyError(
                f"assessment {assessment_id} not found (HTTP 404) — the id may belong to "
                f"another workspace, or the assessment was deleted. Re-pick it with "
                f"`paramify assessments select`. {_error_message(r)}"
            )
        if r.status_code in (401, 403):
            raise ParamifyError(
                f"Paramify rejected the token (HTTP {r.status_code}); it needs write scope "
                f"on this assessment. {_error_message(r)}"
            )
        if r.status_code not in (200, 201):
            raise ParamifyError(
                f"intake of {filename} failed (HTTP {r.status_code}): {_error_message(r)}"
            )
        try:
            return r.json()
        except ValueError:
            return {}


def _error_message(resp) -> str:
    """Pull Paramify's own error message out of a response, with the requestId.

    The requestId is the only thing that lets support find the failure, so it is
    always carried through to the operator rather than dropped for brevity.
    """
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300]
    if not isinstance(body, dict):
        return str(body)[:300]
    error = body.get("error")
    msg = ""
    if isinstance(error, dict):
        msg = error.get("message") or ""
    msg = msg or body.get("statusMessage") or resp.text[:300]
    request_id = body.get("requestId")
    return f"{msg} (requestId={request_id})" if request_id else str(msg)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def find_latest_run(output_dir: Path) -> Optional[Path]:
    if not output_dir.is_dir():
        return None
    runs = sorted((p for p in output_dir.glob("run-*") if p.is_dir()), reverse=True)
    return runs[0] if runs else None


def read_sidecar(run_dir: Path) -> Optional[dict]:
    """Read the run's issue-report index, or None when the run produced none."""
    path = Path(run_dir) / ISSUE_REPORTS_DIR / SIDECAR_NAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("reports"), list):
        raise ValueError(f"{path} is not an issue-report index (no reports list)")
    return data


def _log_key(record: dict, assessment_id: str) -> str:
    """Dedup identity: this file, from this run, into this assessment.

    Deliberately the same shape as the evidence uploader's filename+run_id
    idempotency, so both uploaders answer "will re-running duplicate?" the same
    way. Keyed on the assessment too, so pointing a manifest at a second
    assessment and re-uploading correctly sends the report again.
    """
    return f"{assessment_id}|{record.get('run_id')}|{record.get('file')}"


def read_intake_log(run_dir: Path) -> Dict[str, dict]:
    path = Path(run_dir) / ISSUE_REPORTS_DIR / INTAKE_LOG_NAME
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        # Fail loudly rather than silently re-uploading: a corrupt log that is
        # treated as empty duplicates every issue in the report.
        raise ValueError(
            f"cannot read {path} ({e}) — it records what was already intaken, and "
            f"ignoring it would duplicate. Inspect or delete it to proceed."
        ) from e
    entries = data.get("uploaded") if isinstance(data, dict) else None
    return entries if isinstance(entries, dict) else {}


def write_intake_log(run_dir: Path, uploaded: Dict[str, dict]) -> Optional[Path]:
    path = Path(run_dir) / ISSUE_REPORTS_DIR / INTAKE_LOG_NAME
    body = {"updated_at": _utc_now(), "uploaded": uploaded}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body, indent=2))
    except OSError as e:
        logger.error(
            "could not write %s (%s) — a re-run will duplicate these uploads", path, e
        )
        return None
    return path


def build_artifact_meta(record: dict) -> Dict:
    """The `artifact` part: title, provenance note, and the effective date.

    `effectiveDate` is the collection time, not now. The endpoint routes an
    artifact to the cycle(s) its effective date falls in, so uploading a run from
    last month has to land in last month's cycle — defaulting to today would file
    an old scan against the current one.
    """
    note_parts = [
        f"fetcher={record.get('fetcher_name')}",
        f"version={record.get('fetcher_version')}",
        f"run_id={record.get('run_id')}",
        f"status={record.get('status')}",
    ]
    if record.get("sha256"):
        note_parts.append(f"sha256={record['sha256']}")
    if record.get("target"):
        note_parts.append(f"target={json.dumps(record['target'], separators=(',', ':'))}")
    return {
        "title": record.get("title") or record.get("file"),
        "note": "; ".join(note_parts),
        "effectiveDate": record.get("collected_at") or _utc_now(),
    }


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
    force: bool = False,
    on_event: Optional[Callable[[dict], None]] = None,
) -> Dict:
    """Intake every issue report in one completed run directory.

    Returns a summary in the same shape as the evidence uploader's, so a
    front-end renders both with one code path.

    `force` re-sends reports already listed in this run's `_intake_log.json`.
    The endpoint ADDS rather than replaces, so this will duplicate issues —
    only use it when a previous intake was parsed incorrectly.
    """
    load_dotenv()
    config = config or {}
    paramify_cfg = config.get("paramify") or {}
    base_url, _ = resolve_base_url(paramify_cfg.get("base_url") or base_url)

    url_error = _base_url_error(base_url)
    if url_error:
        logger.error(url_error)
        raise ValueError(url_error)

    # Unlike the evidence uploader this defaults to True. A failed evidence fetch
    # still documents the attempt, but a truncated scan report is parsed into
    # issues: findings missing from a partial file read as resolved, silently
    # closing real vulnerabilities. Opt in per run if you know the file is whole.
    skip_failed = bool(config.get("skip_failed", True))
    overrides = config.get("overrides") or {}

    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        msg = f"No run directory to upload: {run_dir}"
        logger.error(msg)
        raise ValueError(msg)

    index = read_sidecar(run_dir)
    if index is None:
        msg = (
            f"{run_dir} has no {ISSUE_REPORTS_DIR}/{SIDECAR_NAME} — this run collected no "
            f"issue reports (a run of evidence fetchers only). Nothing to intake."
        )
        logger.error(msg)
        raise ValueError(msg)

    if not token:
        token, _ = resolve_upload_token()
    if not token and not dry_run:
        msg = f"{UPLOAD_TOKEN_ENV} is not set (or {READ_TOKEN_ENV} as a fallback)"
        logger.error(msg)
        raise ValueError(msg)

    records = index.get("reports") or []
    logger.info(
        "Intaking %d issue report(s) from %s%s",
        len(records), run_dir, " (dry-run)" if dry_run else "",
    )
    _emit(on_event, {
        "event": "upload_start",
        "run_dir": str(run_dir),
        "base_url": base_url,
        "dry_run": dry_run,
        "files": len(records),
    })

    client = None if dry_run else ParamifyClient(token, base_url)
    already = {} if dry_run else read_intake_log(run_dir)
    results: List[Dict] = []
    uploaded = skipped_dup = skipped_failed = errors = 0
    halted: Optional[str] = None

    def add_result(result: Dict) -> None:
        results.append(result)
        _emit(on_event, {"event": "upload_file", **result})

    for record in records:
        name = record.get("file") or "?"
        # Per-file isolation, same as the evidence uploader: one unreadable or
        # rejected report never aborts the batch.
        try:
            assessment_id = (
                overrides.get(record.get("fetcher_name"), {}) or {}
            ).get("assessment_id") or record.get("assessment_id")
            if not assessment_id:
                logger.error(
                    "%s: no assessment_id — collected but nowhere to send it", name
                )
                errors += 1
                add_result({
                    "file": name,
                    "outcome": "error",
                    "reason": (
                        f"no assessment_id for {record.get('fetcher_name')}; set one with "
                        f"`paramify assessments select {record.get('fetcher_name')}` and "
                        f"re-run, or pass an override in --config"
                    ),
                })
                continue

            if record.get("status") == "failed" and skip_failed:
                logger.info("%s: collection failed and skip_failed set; skipping", name)
                skipped_failed += 1
                add_result({"file": name, "outcome": "skipped_failed",
                            "assessment_id": assessment_id})
                continue

            content_type = _CONTENT_TYPES.get(record.get("format") or "")
            if not content_type:
                logger.error("%s: format %r cannot be intaken", name, record.get("format"))
                errors += 1
                add_result({
                    "file": name,
                    "outcome": "error",
                    "reason": (
                        f"format {record.get('format')!r} is not one of "
                        f"{', '.join(sorted(_CONTENT_TYPES))}"
                    ),
                })
                continue

            path = run_dir / ISSUE_REPORTS_DIR / name
            if not path.is_file():
                logger.error("%s: listed in the index but missing from disk", name)
                errors += 1
                add_result({"file": name, "outcome": "error",
                            "reason": "listed in the index but not on disk"})
                continue

            key = _log_key(record, assessment_id)
            if key in already and not force:
                logger.info("%s: already intaken into this assessment; skipping", name)
                skipped_dup += 1
                add_result({"file": name, "outcome": "skipped_duplicate",
                            "assessment_id": assessment_id,
                            "artifact_id": already[key].get("artifact_id")})
                continue

            meta = build_artifact_meta(record)
            if dry_run:
                logger.info(
                    "would intake %s (%s, %s bytes) → assessment %s as %r",
                    name, record.get("format"), record.get("bytes"), assessment_id,
                    meta["title"],
                )
                add_result({"file": name, "outcome": "would_upload",
                            "assessment_id": assessment_id, "title": meta["title"]})
                continue

            # Read as bytes and post unchanged — the whole point of an issue
            # report. Never json.load/dump a .json report here: re-serializing
            # would reorder keys and rewrite numbers, and the file is supposed to
            # be the vendor's own artifact.
            content = path.read_bytes()
            resp = client.submit_intake(assessment_id, name, content, content_type, meta)
            artifacts = resp.get("artifacts") or []
            artifact_id = artifacts[0].get("id") if artifacts and isinstance(artifacts[0], dict) else None
            uploaded += 1
            already[key] = {
                "file": name,
                "assessment_id": assessment_id,
                "artifact_id": artifact_id,
                "artifact_count": len(artifacts),
                "sha256": record.get("sha256"),
                "uploaded_at": _utc_now(),
            }
            # Written per file, not once at the end: a batch that dies halfway
            # through must not re-send what it already sent.
            write_intake_log(run_dir, already)
            logger.info(
                "intaken %s → assessment %s (%d artifact(s))", name, assessment_id, len(artifacts)
            )
            add_result({
                "file": name,
                "outcome": "uploaded",
                "assessment_id": assessment_id,
                "artifact_id": artifact_id,
                "artifact_count": len(artifacts),
            })
        except IntakeNotEnabled as e:
            # Workspace-wide, not per-file: every remaining report would fail
            # identically, so stop and say so once.
            logger.error("%s", e)
            errors += 1
            halted = str(e)
            add_result({"file": name, "outcome": "error", "error": str(e)[:300]})
            break
        except Exception as e:  # noqa: BLE001 — one report's failure is not the batch's
            logger.error("%s: intake failed: %s", name, e)
            errors += 1
            add_result({"file": name, "outcome": "error", "error": str(e)[:300]})
            continue

    log_path = None
    if not dry_run and uploaded:
        log_path = write_intake_log(run_dir, already)

    summary = {
        "run_dir": str(run_dir),
        "base_url": base_url,
        "dry_run": dry_run,
        "uploaded": uploaded,
        "skipped_duplicate": skipped_dup,
        "skipped_failed": skipped_failed,
        "errors": errors,
        "files": len(records),
        "results": results,
        "log_path": str(log_path) if log_path else None,
        "ok": errors == 0,
    }
    if halted:
        summary["halted"] = halted
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

    parser = argparse.ArgumentParser(
        description="Intake raw issue reports from a run directory into Paramify assessments"
    )
    parser.add_argument("run_dir", nargs="?",
                        help="Run directory to upload (default: latest under --output-dir)")
    parser.add_argument("--output-dir", default="./evidence",
                        help="Base dir to find the latest run in (default ./evidence)")
    parser.add_argument("--config", help="Uploader config YAML (base_url, overrides, skip_failed)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Resolve and report what would be intaken; no API calls")
    parser.add_argument("--force", action="store_true",
                        help="Re-intake reports already listed in this run's _intake_log.json "
                             "(duplicates issues — the endpoint adds, it does not replace)")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir) if args.run_dir else find_latest_run(Path(args.output_dir))
    if not run_dir or not run_dir.is_dir():
        logger.error(
            "No run directory to upload (looked for %s)",
            args.run_dir or f"latest run-* under {args.output_dir}",
        )
        return 1
    try:
        summary = upload_run(
            run_dir, config=load_config(args.config), dry_run=args.dry_run, force=args.force
        )
    except ValueError:
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
