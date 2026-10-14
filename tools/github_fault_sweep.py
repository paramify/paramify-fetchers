#!/usr/bin/env python3
"""Fail every recorded GitHub call, one at a time, six ways, and report any run that still exits 0.

A run that exits 0 after a call failed either did not need the call, read the
failure as a legitimate state, or hid a failure. TOLERATED names the ones that
are legitimate states, with the reason; anything else is a finding.

    python tools/github_fault_sweep.py                 # every cassette
    python tools/github_fault_sweep.py dependabot_alerts
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import requests

ROOT = Path(__file__).resolve().parent.parent
CASSETTES = ROOT / "tests" / "fixtures" / "github_cassettes"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import github_cassette as gcas  # noqa: E402

FAULTS: Dict[str, Callable[[str], requests.Response]] = {
    "401": lambda url: gcas.to_response({"status": 401, "body": {"message": "Bad credentials"}}, url),
    "403": lambda url: gcas.to_response({"status": 403, "body": {
        "message": "Resource not accessible by personal access token"}}, url),
    "404": lambda url: gcas.to_response({"status": 404, "body": {"message": "Not Found"}}, url),
    "429": lambda url: gcas.to_response({"status": 429, "body": {"message": "API rate limit exceeded"},
                                         "headers": {"Retry-After": "99999"}}, url),
    "500": lambda url: gcas.to_response({"status": 500, "body": {"message": "Server Error"}}, url),
    "timeout": lambda url: (_ for _ in ()).throw(requests.exceptions.ConnectionError("timed out")),
}
# (path fragment, fault): why exit 0 is right there.
TOLERATED: List[Tuple[str, str, str]] = [
    ("/dependency-graph/sbom", "404", "the dependency graph is off: reported as dependency_graph_enabled false"),
    ("/codeowners/errors", "404", "no CODEOWNERS file: reported as missing, and flagged where code-owner review is required"),
    ("/attestations/", "404", "no attestation for the digest: reported as without build provenance"),
]


LAST_STATUS: dict = {}  # the status file of the latest run_once, for tests that tell failure kinds apart


def load(fetcher: str):
    spec = importlib.util.spec_from_file_location(f"sweep_{fetcher}", ROOT / "fetchers/github" / fetcher / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, sys.modules["github_client"]


def run_once(fetcher: str, cassette: dict, fault=None) -> Tuple[int, dict, list]:
    module, gc = load(fetcher)
    replay = gcas.Replay(cassette["entries"], fault)
    saved = (gc.requests.Session, gc.time.sleep, dict(os.environ))
    gc.requests.Session = lambda: replay
    gc.time.sleep = lambda s: None
    with tempfile.TemporaryDirectory() as tmp:
        os.environ.update({**cassette["env"], "GITHUB_TOKEN": "ghs_replay" if cassette.get("token_kind") == "app" else "github_pat_replay", "EVIDENCE_DIR": f"{tmp}/evidence",
                           "FETCHER_STATUS_FILE": f"{tmp}/status.json", "LOG_LEVEL": "CRITICAL"})
        try:
            code = gc.run(module.NAME, module.collect, getattr(module, "CONFIG", None),
                          inventory=getattr(module, "INVENTORY", False))
            evidence = json.loads(next(Path(tmp, "evidence").glob("*.json")).read_text())
            status = Path(tmp, "status.json")
            LAST_STATUS.clear()
            LAST_STATUS.update(json.loads(status.read_text()) if status.exists() else {})
        finally:
            gc.requests.Session, gc.time.sleep = saved[0], saved[1]
            os.environ.clear()
            os.environ.update(saved[2])
    return code, evidence, replay.calls


def sweep(fetcher: str) -> Tuple[int, List[str]]:
    cassette = json.loads((CASSETTES / f"{fetcher}.json").read_text())
    base_code, _, calls = run_once(fetcher, cassette)
    findings, runs = [], 0
    for k in dict.fromkeys(calls):
        for name, fault in FAULTS.items():
            runs += 1
            code, evidence, _ = run_once(fetcher, cassette, (k, fault))
            if code == 0 and not any(frag in k and f == name for frag, f, _ in TOLERATED):
                findings.append(f"{fetcher}: {name} on {k} -> exit 0")
            if code != 0 and "records_included" in evidence and (evidence["data"] or evidence["records_included"]):
                findings.append(f"{fetcher}: {name} on {k} -> a failed inventory kept its records")
    if base_code != cassette["exit_code"]:
        findings.append(f"{fetcher}: replay exit {base_code}, recorded {cassette['exit_code']}")
    return runs, findings


def main() -> int:
    names = sys.argv[1:] or sorted(p.stem for p in CASSETTES.glob("*.json"))
    total, findings = 0, []
    for name in names:
        runs, found = sweep(name)
        total += runs
        findings += found
        print(f"{name}: {runs} faulted runs, {len(found)} silent", flush=True)
    for f in findings:
        print("  " + f)
    print(f"{total} runs, {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
