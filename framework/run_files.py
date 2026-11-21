"""Which files in a run directory are evidence.

A run directory holds evidence envelopes next to the engine's own bookkeeping.
Every reader of a run directory uses this rule, so a new bookkeeping file never
gets mistaken for evidence.
"""

from __future__ import annotations

from pathlib import Path

UPLOAD_STATE_FILE = "_upload_state.json"
UPLOAD_LOCK_FILE = "_upload.lock"

RESERVED_RUN_FILES: frozenset[str] = frozenset(
    {"_run_metadata.json", "upload_log.json", UPLOAD_STATE_FILE, UPLOAD_LOCK_FILE}
)


def is_evidence_file(path: Path) -> bool:
    """True for a `*.json` file that is not engine bookkeeping."""
    name = path.name
    return (
        name.endswith(".json")
        and not name.startswith("_")
        and name not in RESERVED_RUN_FILES
    )
