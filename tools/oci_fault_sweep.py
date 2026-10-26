#!/usr/bin/env python3
"""
Fail every recorded OCI call, one at a time, and check that each fetcher notices.

WHY. The silent-green failure this category has to guard against is one call
failing in a way the fetcher reads as "nothing there": a denied child listing
read as no bastions, a bogus target compartment read as an empty one, a missing
grant read as an unsubscribed service. Hand-written tests find those one at a
time. This checks the whole class: for every interaction in every cassette, and for each fault kind (401,
404, 429, 500, a connect timeout), the fetcher is run with that one call failing.

WHAT PASSES. The run exits non-zero with evidence naming the failure — or exits
0 having recorded the call in `skipped_calls`, and the operation is on the short
list of calls that are context rather than evidence (TOLERATED_OK). Anything
else is reported: exit 0 with nothing recorded (silent), exit 0 with failures
recorded, a traceback or a missing evidence file, a tolerated call that is not
on the list, or a faulted call the fetcher never made.

    python tools/oci_fault_sweep.py                      # all fetchers, all kinds (~2 min on 12 cores)
    python tools/oci_fault_sweep.py --kinds 404 zpr_policies

Not part of `pytest`: it is ~1,800 subprocesses. Run it after changing how a
fetcher handles errors, and before a release.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO / "fetchers" / "oci"
CASSETTES = FETCHER_ROOT / "tests" / "cassettes"
BOOTSTRAP = REPO / "tests" / "oci_replay_bootstrap"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oci_cassette import FAULT_KINDS  # noqa: E402

# Skipped rather than failed, by design: which regions the tenancy subscribes to
# qualifies the evidence and is not itself evidence (see oci_common.region_coverage).
TOLERATED_OK = {"identity.list_region_subscriptions"}


def _signing_key() -> str:
    sys.path.insert(0, str(REPO / "tests"))
    from oci_test_key import throwaway_signing_key

    return throwaway_signing_key()


def run_one(name: str, key: str, kind: str, signing_key: str, workdir: Path) -> dict:
    out_dir = Path(tempfile.mkdtemp(dir=workdir))
    hits = out_dir / "hits"
    env = {
        "PATH": os.environ.get("PATH", ""), "HOME": str(out_dir), "PYTHONPATH": str(BOOTSTRAP),
        "EVIDENCE_DIR": str(out_dir), "OCI_CASSETTE": str(CASSETTES / f"{name}.json"),
        "OCI_CASSETTE_MODE": "replay", "OCI_FAULT_KEY": key, "OCI_FAULT_KIND": kind,
        "OCI_FAULT_HITS": str(hits),
        "OCI_TENANCY_OCID": "ocid1.tenancy.oc1..aaaaaaaatenancy",
        "OCI_USER_OCID": "ocid1.user.oc1..aaaaaaaauser",
        "OCI_FINGERPRINT": "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
        "OCI_PRIVATE_KEY": signing_key, "OCI_REGION": "us-phoenix-1",
    }
    result = subprocess.run([sys.executable, str(FETCHER_ROOT / name / "fetcher.py")],
                            env=env, capture_output=True, text=True, timeout=300)
    evidence_file = next(out_dir.glob("oci_*.json"), None)
    metadata = json.loads(evidence_file.read_text())["metadata"] if evidence_file else {}
    skipped = [s.get("operation", "") for s in metadata.get("skipped_calls", [])]
    run = {"fetcher": name, "key": key, "kind": kind, "rc": result.returncode,
           "hits": hits.read_text().count("x") if hits.exists() else 0,
           "failures": len(metadata.get("api_failures", [])), "skipped": skipped}
    if run["hits"] == 0:
        verdict = "never called"
    elif not evidence_file or "Traceback" in result.stderr:
        verdict = "crashed"
    elif result.returncode == 0 and run["failures"]:
        verdict = "exit 0 with failures recorded"
    elif result.returncode == 0 and not skipped:
        verdict = "SILENT: exit 0, nothing recorded"
    elif result.returncode == 0 and not set(skipped) <= TOLERATED_OK:
        verdict = "tolerated, not on TOLERATED_OK"
    else:
        verdict = "ok"
    run["verdict"] = verdict
    if verdict == "crashed":
        run["stderr"] = result.stderr[-800:]
    return run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("fetchers", nargs="*", help="default: every fetcher with a cassette")
    parser.add_argument("--kinds", default=",".join(FAULT_KINDS),
                        help=f"comma-separated, from {', '.join(FAULT_KINDS)}")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = parser.parse_args()

    kinds = [k for k in args.kinds.split(",") if k]
    names = args.fetchers or sorted(p.stem for p in CASSETTES.glob("*.json"))
    jobs = [(name, interaction["key"], kind)
            for name in names
            for interaction in json.loads((CASSETTES / f"{name}.json").read_text())["interactions"]
            for kind in kinds]
    signing_key = _signing_key()

    with tempfile.TemporaryDirectory() as workdir, \
            concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        runs = list(pool.map(lambda job: run_one(job[0], job[1], job[2], signing_key, Path(workdir)), jobs))

    verdicts = collections.Counter(r["verdict"] for r in runs)
    print(f"{len(runs)} runs: " + ", ".join(f"{n} {v}" for v, n in verdicts.most_common()))
    bad = [r for r in runs if r["verdict"] != "ok"]
    for r in bad:
        print(f"\n{r['verdict']}: {r['fetcher']} {r['kind']} {r['key']}")
        print(f"  exit {r['rc']}, {r['failures']} failures, skipped {r['skipped']}")
        if "stderr" in r:
            print("  " + r["stderr"].replace("\n", "\n  "))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
