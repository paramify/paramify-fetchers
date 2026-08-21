"""Issue reports: the raw-file half of the collection contract.

An evidence fetcher's identity travels *inside* its output — the runner wraps the
payload in `{schema_version, metadata, payload}` and the uploader reads
`metadata.evidence_set` back out. An issue report cannot work that way. Paramify's
assessment intake parses the source tool's own CSV/XML/JSON/Nessus structure, so
anything the framework adds to the file breaks the parse. The file must land on
disk byte-for-byte as the tool emitted it.

So identity moves out of band. Issue reports go to `<run>/issue-reports/`, and
this module writes `_issue_reports.json` beside them: one record per file,
carrying everything the envelope would have carried plus the assessment the
report is destined for. The uploader reads that index instead of opening the
reports. Same job as framework/envelope.py, done next to the file rather than
inside it.

Two things follow from the sidecar being the only channel:

- It is written on every run that produced a report, success or failure. A failed
  collection still gets a record (`status: failed`), because "the scan ran and
  came back empty" and "the scan never ran" are different facts and the uploader
  has to be able to tell them apart.
- The `_` prefix keeps it out of the uploader's own file set, the same convention
  `_run_metadata.json` uses.

See docs/issue_report_fetchers.md.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from framework.contract import ConfigField, Fetcher, InvocationResult

logger = logging.getLogger("framework.issue_reports")

# Subdirectory of the run dir that raw reports land in. The runner points
# EVIDENCE_DIR here for an issue-report fetcher, so fetchers never name it.
ISSUE_REPORTS_DIR = "issue-reports"
SIDECAR_NAME = "_issue_reports.json"
SIDECAR_SCHEMA_VERSION = "1.0"

# Where the uploader records what it already sent (see the uploader's dedup note).
INTAKE_LOG_NAME = "_intake_log.json"

# Files the sidecar and the uploader both ignore when looking for reports.
RESERVED_NAMES = frozenset({SIDECAR_NAME, INTAKE_LOG_NAME})

# Framework-reserved config fields every issue-report fetcher accepts. Injected
# into the fetcher's config_schema at load time rather than restated in each
# fetcher.yaml — they are framework knowledge (which assessment to intake into),
# not fetcher knowledge, and a field every issue-report fetcher must declare
# identically is a field that will eventually be declared differently.
#
# Neither carries an `env`: the fetcher has no use for them. The runner resolves
# them from the manifest and writes them into the sidecar for the uploader.
#
# `required: False` is deliberate. A required config field raises before the
# fetcher runs, which would make "collect now, decide where it goes later"
# impossible — and collecting with no Paramify connection at all is a property
# the framework is supposed to have (docs/design.md). A missing assessment is
# instead reported by `paramify validate` and refused by the uploader, at the
# points where it actually matters.
ASSESSMENT_ID_FIELD = "assessment_id"
ASSESSMENT_NAME_FIELD = "assessment_name"


def reserved_config_schema() -> Dict[str, ConfigField]:
    """The config fields the framework adds to every issue-report fetcher."""
    return {
        ASSESSMENT_ID_FIELD: ConfigField(
            name=ASSESSMENT_ID_FIELD,
            type="string",
            required=False,
            description=(
                "UUID of the Paramify assessment this report is intaken into. Set it by "
                "name with `paramify assessments select` rather than by hand — that "
                "command reads the workspace and writes the UUID for you."
            ),
        ),
        ASSESSMENT_NAME_FIELD: ConfigField(
            name=ASSESSMENT_NAME_FIELD,
            type="string",
            required=False,
            description=(
                "Human-readable name of the assessment, written alongside assessment_id "
                "so the manifest is readable and a stale UUID is recognisable. Not used "
                "to resolve the assessment — assessment_id is authoritative."
            ),
        ),
    }


def reports_dir(run_dir: Path) -> Path:
    return Path(run_dir) / ISSUE_REPORTS_DIR


def sidecar_path(run_dir: Path) -> Path:
    return reports_dir(run_dir) / SIDECAR_NAME


def _sha256(path: Path) -> Optional[str]:
    """Hash a report in chunks — a Nessus export can be hundreds of MB."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as e:
        logger.warning("issue_reports: cannot hash %s (%s)", path.name, e)
        return None
    return h.hexdigest()


def _title(fetcher: Fetcher, result: InvocationResult, filename: str) -> str:
    """Artifact title: the declared one, plus a target identifier for a fanout run.

    Falls back to the filename, which is what the intake endpoint would default to
    anyway, so a fetcher that declares no title still produces something readable.
    """
    base = (fetcher.issue_report.title if fetcher.issue_report else None) or filename
    target = result.target or {}
    if target:
        suffix = next((str(v) for v in target.values() if v), None)
        if suffix:
            return f"{base} - {suffix}"
    return base


def build_record(
    filename: str,
    result: InvocationResult,
    fetcher: Fetcher,
    run_id: str,
    run_dir: Path,
    assessment: Optional[Dict[str, Any]] = None,
) -> dict:
    """One sidecar record. Mirrors envelope.build_metadata field for field, so a
    reader who knows the envelope can read this without a second reference."""
    assessment = assessment or {}
    path = reports_dir(run_dir) / filename
    record = {
        "file": filename,
        "fetcher_name": result.fetcher_name,
        "fetcher_version": result.fetcher_version,
        "category": fetcher.category,
        "run_id": run_id,
        "target": result.target,
        "collected_at": result.completed_at,
        "status": "success" if result.exit_code == 0 else "failed",
        "exit_code": result.exit_code,
        "format": fetcher.output_type,
        "title": _title(fetcher, result, filename),
        "assessment_id": assessment.get(ASSESSMENT_ID_FIELD),
        "assessment_name": assessment.get(ASSESSMENT_NAME_FIELD),
        "assessment_type": (
            fetcher.issue_report.assessment_type if fetcher.issue_report else None
        ),
        "sha256": _sha256(path),
        "bytes": path.stat().st_size if path.exists() else None,
    }
    if result.exit_code != 0:
        # Same precedence as the envelope: what the fetcher reported via
        # $FETCHER_STATUS_FILE wins, stderr tail is the fallback.
        error = result.error or (result.stderr[-4000:] if result.stderr else None)
        if error:
            record["error"] = error
        if result.error_code:
            record["error_code"] = result.error_code
    return record


def record_outputs(
    result: InvocationResult,
    fetcher: Fetcher,
    run_id: str,
    run_dir: Path,
    assessment: Optional[Dict[str, Any]] = None,
) -> List[dict]:
    """Append this invocation's reports to the run's sidecar index.

    Read-modify-write rather than accumulate-in-memory so the index is complete
    on disk after every invocation: a run killed halfway through still leaves an
    uploadable index for what it did collect. Returns the records added.

    `result.outputs` are run-dir-relative (`issue-reports/scan.csv`); anything
    outside the issue-reports directory is ignored, so an issue-report fetcher
    that also writes elsewhere cannot corrupt the index.
    """
    prefix = f"{ISSUE_REPORTS_DIR}/"
    names = [
        name[len(prefix):]
        for name in result.outputs
        if name.startswith(prefix) and Path(name).name not in RESERVED_NAMES
    ]
    if not names:
        return []

    path = sidecar_path(run_dir)
    index: Dict[str, Any] = {
        "schema_version": SIDECAR_SCHEMA_VERSION, "run_id": run_id, "reports": [],
    }
    if path.exists():
        try:
            existing = json.loads(path.read_text())
            if isinstance(existing, dict) and isinstance(existing.get("reports"), list):
                index = existing
        except (OSError, json.JSONDecodeError) as e:
            # Losing prior records is bad, but refusing to record this
            # invocation's is worse: the alternative is a run whose reports
            # exist on disk with nothing pointing at them.
            logger.warning(
                "issue_reports: %s is unreadable (%s); starting a fresh index", path.name, e
            )

    added = [
        build_record(name, result, fetcher, run_id, run_dir, assessment) for name in names
    ]
    reports: List[dict] = list(index.get("reports") or [])
    reports.extend(added)
    index["reports"] = reports
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(index, indent=2, default=str))
    except OSError as e:
        logger.error(
            "issue_reports: could not write %s (%s) — these reports will not be "
            "uploadable until it is rewritten", path, e
        )
        return []
    return added


def read_index(run_dir: Path) -> Optional[dict]:
    """Read a run's sidecar index, or None when the run collected no reports.

    None and an empty `reports` list mean different things to the uploader: no
    index at all is "this run had no issue-report fetchers", which is not an
    error.
    """
    path = sidecar_path(run_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read issue-report index {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("reports"), list):
        raise ValueError(f"{path} is not an issue-report index (no reports list)")
    return data
