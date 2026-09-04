"""Run the behaviour cases in validators/_cases/ through the ECMAScript evaluator.

Authoring aid, not a merge gate. A validator's failure modes are silent — a rule
that reads nothing passes — so the only way to know one works is to run it
against evidence that should fail as well as evidence that should pass. This
turns that into one command instead of a hand-rolled node invocation per rule.

Returns one presentation-agnostic model; the CLI and `--json` both render it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from framework.validator_eval import evaluate, node_available

# Paramify combines a set's validators worst-first.
_RANK = {"PASS": 0, "FAIL": 1, "ERROR": 2, "COMPILE_ERROR": 3}


def _combine(verdicts: List[str]) -> str:
    return max(verdicts, key=lambda v: _RANK.get(v, 9)) if verdicts else "PASS"


def _payload(v) -> Dict[str, Any]:
    return {"key": v.key, "regex": v.regex, "validation_rules": v.validation_rules}


def run_cases(
    root: Path,
    select: Optional[str] = None,
    mode: str = "api-today",
) -> Dict[str, Any]:
    """Evaluate every case file under validators/_cases/.

    `select` filters to one validator key or evidence-set reference_id.
    `mode` is "api-today" (what a live tenant does) or "as-designed".
    """
    from framework.validators import discover_validators

    if not node_available():
        return {
            "ok": False,
            "error": "`node` is not on PATH. Paramify evaluates validator regexes "
                     "with ECMAScript, so they cannot be checked with Python re.",
            "files": [],
            "summary": {},
        }

    registry = discover_validators(root)
    cases_dir = root / "validators" / "_cases"
    files: List[Dict[str, Any]] = []
    covered: set = set()
    n_cases = n_failed = n_vacuous = 0

    for path in sorted(cases_dir.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text()) or {}
        key, ref = doc.get("validator"), doc.get("evidence_set")
        if bool(key) == bool(ref):
            files.append({"file": path.name, "error":
                          "give exactly one of `validator:` or `evidence_set:`"})
            n_failed += 1
            continue

        if key:
            target, targets = f"validator:{key}", ([registry[key]] if key in registry else [])
        else:
            target = f"set:{ref}"
            targets = [v for v in registry.values() if ref in v.evidence_sets]
        if not targets:
            files.append({"file": path.name, "target": target,
                          "error": "names nothing in the registry"})
            n_failed += 1
            continue
        if select and select not in (key, ref) and select not in {t.key for t in targets}:
            continue
        covered.update(t.key for t in targets)

        file_mode = doc.get("mode", mode)
        rows = []
        for case in doc.get("cases", []):
            artifact = case["artifact"]
            verdicts, vacuous, trace = [], False, []
            for v in targets:
                r = evaluate(_payload(v), artifact, mode=file_mode)
                verdicts.append(r["verdict"])
                vacuous = vacuous or r["vacuous"]
                trace.append({"key": v.key, "verdict": r["verdict"],
                              "matches": r["matchCount"], "vacuous": r["vacuous"]})
            got = _combine(verdicts)
            ok = got == case["expect"] and not (vacuous and got == "PASS")
            n_cases += 1
            n_failed += 0 if ok else 1
            n_vacuous += 1 if (vacuous and got == "PASS") else 0
            rows.append({"name": case["name"], "expect": case["expect"], "got": got,
                         "ok": ok, "vacuous": vacuous and got == "PASS",
                         "note": (case.get("note") or "").strip(), "trace": trace})
        files.append({"file": path.name, "target": target, "mode": file_mode,
                      "validators": [t.key for t in targets], "cases": rows})

    uncovered = sorted(
        k for k, v in registry.items() if v.type == "AUTOMATED" and k not in covered
    )
    return {
        "ok": n_failed == 0,
        "mode": mode,
        "files": files,
        "summary": {
            "files": len(files),
            "cases": n_cases,
            "failed": n_failed,
            "vacuous_passes": n_vacuous,
            "validators_without_cases": uncovered,
        },
    }
