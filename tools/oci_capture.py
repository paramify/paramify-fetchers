#!/usr/bin/env python3
"""
Record a cassette per OCI fetcher from a live tenancy.

    python tools/oci_capture.py                 # every fetcher
    python tools/oci_capture.py vault_keys ...  # named ones

Needs working OCI credentials and READS ONLY. Each fetcher is run in-process
with `tools/oci_cassette` recording the HTTP traffic, and the result is written
to `fetchers/oci/tests/cassettes/<fetcher>.json`, redacted (tenancy and user
OCIDs, the account email, the API key fingerprint).

Re-record after any change to which calls a fetcher makes — `tests/test_oci_fetchers.py`
fails loudly on an unmatched request rather than quietly collecting nothing.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "oci"
CASSETTE_DIR = FETCHER_ROOT / "tests" / "cassettes"

sys.path.insert(0, str(REPO_ROOT / "tools"))
from oci_cassette import Cassette, install  # noqa: E402


def fetcher_names() -> list[str]:
    return sorted(
        d.name for d in FETCHER_ROOT.iterdir()
        if d.is_dir() and not d.name.startswith("_") and (d / "fetcher.py").exists()
    )


def load_fetcher(name: str):
    sys.path.insert(0, str(FETCHER_ROOT / "_shared"))
    spec = importlib.util.spec_from_file_location(f"oci_{name}", FETCHER_ROOT / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capture(name: str) -> tuple[int, float, int]:
    cassette = Cassette()
    uninstall = install(cassette, mode="record")
    try:
        with tempfile.TemporaryDirectory() as evidence:
            os.environ["EVIDENCE_DIR"] = evidence
            code = load_fetcher(name).main()
    finally:
        uninstall()
    cassette.save(CASSETTE_DIR / f"{name}.json")
    return code, cassette.size_kb(), len(cassette.interactions)


def main() -> int:
    names = sys.argv[1:] or fetcher_names()
    total = 0.0
    failed = []
    for name in names:
        code, size, count = capture(name)
        total += size
        marker = "ok " if code == 0 else "EXIT %d" % code
        if code != 0:
            failed.append(name)
        print(f"{marker} {name:34} {count:3d} interactions  {size:6.1f} KB")
    print(f"\n{len(names)} cassettes, {total:.1f} KB total -> {CASSETTE_DIR.relative_to(REPO_ROOT)}")
    if failed:
        print("recorded a non-zero exit for:", ", ".join(failed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
