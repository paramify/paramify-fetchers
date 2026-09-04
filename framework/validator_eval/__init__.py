"""Evaluate a registry validator against an evidence artifact, as Paramify would.

A validator cannot be reviewed by reading it. Its failure modes are silent: a
rule that reads nothing *passes*, so a validator asserting the wrong thing looks
identical to one that works until the evidence changes shape. This module makes
that behaviour testable, which is what turns the "prove it fails too" step of
authoring from an honour-system instruction into a gate.

The evaluator itself is `score.mjs` and runs under Node, deliberately: Paramify's
engine is ECMAScript, and the `(?<name>...)` groups this repo requires do not
compile under Python `re` at all. Testing in Python would use the wrong engine
and silently disagree with production.

    from framework.validator_eval import evaluate, node_available

    result = evaluate(validator_dict, artifact_text)
    result["verdict"]   # PASS | FAIL | ERROR | COMPILE_ERROR
    result["vacuous"]   # True when a PASS was reached having read nothing
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

__all__ = ["evaluate", "node_available", "NodeUnavailable", "SCORER"]

SCORER = Path(__file__).resolve().parent / "score.mjs"
_TIMEOUT = 30


class NodeUnavailable(RuntimeError):
    """Raised when `node` is not on PATH, so ECMAScript evaluation is impossible."""


def node_available() -> bool:
    """True when a `node` binary is on PATH."""
    return shutil.which("node") is not None


def evaluate(
    validator: Dict[str, Any],
    artifact: str,
    mode: str = "as-designed",
    node_bin: Optional[str] = None,
) -> Dict[str, Any]:
    """Run one validator against one artifact and return the verdict + rule trace.

    `validator` is a registry validator as loaded from YAML. `artifact` is the
    evidence file's text — the WHOLE envelope, since that is what Paramify's
    regex sees, not just the payload.

    `mode` selects which reality to judge against:
      * "as-designed" — ERROR resolves before FAIL before PASS.
      * "api-today"   — `disposition` is discarded by the REST API, so every
        rule is a pass-requirement. This is what a live tenant actually does.

    Raises NodeUnavailable when `node` is missing; callers that must degrade
    gracefully should check `node_available()` first.
    """
    if mode not in ("as-designed", "api-today"):
        raise ValueError(f"unknown mode {mode!r}")
    node = node_bin or shutil.which("node")
    if not node:
        raise NodeUnavailable(
            "`node` is not on PATH. Paramify evaluates validator regexes with "
            "ECMAScript, so they cannot be checked with Python `re`."
        )

    with tempfile.TemporaryDirectory() as tmp:
        vpath = Path(tmp) / "validator.json"
        apath = Path(tmp) / "artifact.json"
        vpath.write_text(json.dumps(validator))
        apath.write_text(artifact)
        proc = subprocess.run(
            [node, str(SCORER), str(vpath), str(apath), "--mode", mode],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    if proc.returncode != 0:
        raise RuntimeError(
            f"validator evaluation failed (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    return json.loads(proc.stdout)
