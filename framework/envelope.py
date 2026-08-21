"""Wrap fetcher outputs in the standard evidence envelope.

Fetchers write raw evidence dicts; the runner calls `wrap_outputs()` after each
invocation to add the `{schema_version, metadata, payload}` wrapper so every
evidence file is self-describing and the uploader has one shape to read. This
keeps the v0.x "fetchers write raw dicts" interim clause true — the framework
adds the envelope, not the fetcher. See docs/envelope_design.md.
"""

import json
import logging
from pathlib import Path

from framework.contract import Fetcher, InvocationResult

logger = logging.getLogger("framework.envelope")

ENVELOPE_SCHEMA_VERSION = "1.0"
_ERROR_TAIL_CHARS = 4000
_ENVELOPE_KEYS = {"schema_version", "metadata", "payload"}


def is_enveloped(obj) -> bool:
    """True if obj already looks like an envelope (so we don't double-wrap)."""
    return isinstance(obj, dict) and _ENVELOPE_KEYS <= set(obj.keys())


def build_metadata(result: InvocationResult, fetcher: Fetcher, run_id: str) -> dict:
    meta = {
        "fetcher_name": result.fetcher_name,
        "fetcher_version": result.fetcher_version,
        "category": fetcher.category,
        "run_id": run_id,
        "target": result.target,
        "collected_at": result.completed_at,
        "status": "success" if result.exit_code == 0 else "failed",
        "exit_code": result.exit_code,
    }
    if result.exit_code != 0:
        # What the fetcher reported via $FETCHER_STATUS_FILE wins; the stderr tail
        # is the fallback for fetchers that don't use the channel. The tail is a
        # heuristic — it assumes the last thing logged is why the run failed, which
        # is false for any fetcher whose final log line is an INFO message — so it
        # is the second choice, not the first. The payload is never consulted: it
        # is fetcher-shaped and unredacted. See docs/fetcher_contract.md.
        error = result.error or (result.stderr[-_ERROR_TAIL_CHARS:] if result.stderr else None)
        if error:
            meta["error"] = error
        if result.error_code:
            meta["error_code"] = result.error_code
    if fetcher.evidence_set:
        es = fetcher.evidence_set
        es_meta = {"reference_id": es.reference_id, "name": es.name}
        if es.instructions is not None:
            es_meta["instructions"] = es.instructions
        if es.description is not None:
            es_meta["description"] = es.description
        meta["evidence_set"] = es_meta
    return meta


def wrap_outputs(
    result: InvocationResult, fetcher: Fetcher, run_id: str, run_dir: Path
) -> None:
    """Wrap each JSON output file from one invocation in an envelope, in place.

    Non-JSON files and already-enveloped files are left untouched. A failure to
    wrap a single file is logged and skipped — it never aborts the run.

    An issue-report fetcher is skipped entirely. Its output is the source tool's
    own file, which Paramify's assessment intake parses directly, so wrapping it
    would break the parse. The guard is on `kind` rather than the file extension
    because a JSON scan report is still a scan report — its identity lives in the
    sidecar index instead (see framework/issue_reports.py).
    """
    if fetcher.is_issue_report:
        return

    meta = build_metadata(result, fetcher, run_id)
    for name in result.outputs:
        if not name.endswith(".json"):
            continue
        path = run_dir / name
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("envelope: skipping %s (cannot read as JSON: %s)", name, e)
            continue
        if is_enveloped(raw):
            continue
        envelope = {
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "metadata": meta,
            "payload": raw,
        }
        path.write_text(json.dumps(envelope, indent=2))
