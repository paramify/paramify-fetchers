"""The one place a fetcher reports WHY it failed.

Import it, don't copy it:

    SCRIPT_DIR = Path(__file__).resolve().parent
    sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
    from fetcher_status import report_failure   # noqa: E402

Same mechanism as a category `_shared` module, one directory up. This module is
stdlib-only and imports nothing from `framework/` on purpose: the runner execs a
fetcher as a subprocess with `cwd` set to the fetcher's own directory and no
PYTHONPATH, so `framework` is not importable from here.

Why this file exists at all: the write below is nine lines, and an earlier
revision of the porting playbook printed those nine lines and told authors to
paste them. The result was 27 copies under two names: `report_failure` 25 times
(22 fetchers, falcon_client, and both templates) and `write_status` twice
(azure_common, gcp_common) — plus seven whole categories (aws, okta, knowbe4,
k8s, paramify, rippling, checkov) that never pasted anything and so reported
nothing.

The `write_status` alias is gone: azure_common and gcp_common re-export
`report_failure`, and all 46 of their fetchers call it by that name. There is
one spelling now. See docs/fetcher_contract.md § Output.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

__all__ = ["report_failure", "STATUS_CODES"]

# The contract's closed set for `code` (docs/fetcher_contract.md § Output).
# Exit codes stay binary (0 / non-zero); the category goes here, so the
# exit-code space — shared with the shell and with signals — stays uncarved.
STATUS_CODES = frozenset(
    {
        "auth_failed",
        "not_authorized",
        "target_unreachable",
        "rate_limited",
        "bad_config",
        "partial_failure",
        "internal_error",
    }
)

# `error` is shown in a UI cell, and the runner truncates at 4000 chars anyway
# (framework/runner/executor.py). Bound it here too so a multi-megabyte API body
# never reaches the status file in the first place.
_MAX_ERROR_CHARS = 2000

_LOGGER = logging.getLogger("fetcher_status")

# Matches the bash twin's `;` collapsing (status.sh:_normalize_reason).
_DUP_SEP = re.compile(r";(?:\s*;)+")
_EDGE_SEP = re.compile(r"^\s*;\s*|\s*;\s*$")


def _normalize_reason(error: str) -> str:
    """One line, with separator noise collapsed.

    Callers build a reason by joining a failure log, which leaves a dangling
    separator and turns a blank entry into an empty `;;` segment. Cleaning it
    here means 100+ call sites don't each have to get the joining exactly right.
    """
    one_line = " ".join(str(error).split())
    one_line = _DUP_SEP.sub(";", one_line)
    one_line = _EDGE_SEP.sub("", one_line).strip()
    return one_line


def _fetcher_label() -> str:
    """"<category>_<name>", matching the `name:` in fetcher.yaml.

    Every entry script in the tree is called `fetcher.py`, so a basename is always
    the useless string "fetcher"; the identity is in the two enclosing directory
    names (fetchers/<category>/<name>/fetcher.py). Derived from argv[0] rather
    than a caller frame — the entry script is what the runner exec'd, which is
    exactly the thing whose name we want.
    """
    try:
        entry = Path(sys.argv[0]).resolve()
        name, category = entry.parent.name, entry.parent.parent.name
        if name and category:
            return f"{category}_{name}"
    except (OSError, IndexError, ValueError):
        pass
    return "fetcher_status"


def report_failure(error: str, code: Optional[str] = None) -> None:
    """Log why this invocation failed AND report it to the runner.

    This is the whole failure path — callers do not also need their own
    `logger.error`. Logging here is what guarantees the reason is the LAST thing
    on stderr, which matters because the runner's fallback takes the stderr
    *tail*: a fetcher that logs its error before its "Evidence saved" INFO line
    reports that success message as its failure reason (issue #24).

    A no-op on the status file when the runner set no `$FETCHER_STATUS_FILE`
    (running the fetcher by hand). Never raises: the exit code is the
    authoritative failure signal, so a status-file problem must not turn a
    reportable failure into a crash, or an otherwise-fine run into a failed one.
    """
    one_line = _normalize_reason(error) or "collection failed"
    if len(one_line) > _MAX_ERROR_CHARS:
        one_line = one_line[:_MAX_ERROR_CHARS].rstrip() + " ..."

    if code is not None and code not in STATUS_CODES:
        _LOGGER.warning("dropping unrecognized status code %r", code)
        code = None

    # Log first, so the reason reaches stderr even if the write below fails.
    # Named for the fetcher, so the line sits alongside its own log lines rather
    # than being attributed to this helper.
    logging.getLogger(_fetcher_label()).error("%s", one_line)

    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return

    body = {"error": one_line}
    if code:
        body["code"] = code
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(body, sort_keys=True))
    except OSError as exc:
        _LOGGER.warning("could not write FETCHER_STATUS_FILE %s: %s", path, exc)
