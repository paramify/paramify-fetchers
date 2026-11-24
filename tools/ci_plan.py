#!/usr/bin/env python3
"""Decide how much of CI a change needs. Run by the `changes` job in ci.yml.

Most pull requests add or fix a fetcher: files under fetchers/, their tests and
their docs. Running five Pythons and two textual versions over those re-tests
framework code the change did not touch, and the queue that builds up delays
every other pull request. So a change gets one of two scopes:

  full      everything. Any push (main is always tested in full), and any pull
            request that touches a file outside the list below.
  fetchers  the oldest and the deployed Python, the latest textual, and the
            azure-sdk / oci jobs only when their side of the tree changed.

The list is an ALLOWLIST. A path nobody thought about lands in `full`, so the
planner can only ever be wrong in the direction of running too much. That is
also why this file, ci.yml, pyproject.toml and requirements.txt need no entry
here: none of them is on the list, so a dependency bump (the case PR #59 slipped
through) always runs every job.

Usage, from a checkout with the parent commit present:
    python tools/ci_plan.py --event pull_request     # diffs HEAD^1..HEAD
    python tools/ci_plan.py --event push
Prints `key=value` lines and appends them to $GITHUB_OUTPUT when it is set.
Stdlib only, like tools/generate_chart.py: the job has no install step.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

# Trees a fetcher pull request may touch and still get the `fetchers` scope.
FETCHER_SCOPE_DIRS = ("fetchers/", "tests/", "docs/", "examples/", "comparators/", "validators/")

# Under tests/, these belong to the framework or the TUI and need `full`:
# conftest.py is shared by every test, and the rest is the suite the tui job
# runs. Keep in step with that job's pytest step in ci.yml.
FRAMEWORK_TESTS = re.compile(
    r"^tests/(conftest\.py$|test_tui_|__snapshots__/|test_manifest_autosave\.py$|test_target_editor\.py$)"
)

# Shared fetcher code and the category files: any provider's fetchers can read
# these, so a change here runs both SDK jobs.
SHARED_FETCHER_CODE = ("fetchers/_lib/", "fetchers/_categories/")

# Sentinel fetchers live under fetchers/azure/, and `entra` covers the Graph ones.
AZURE = re.compile(r"azure|entra|sentinel", re.IGNORECASE)
OCI = re.compile(r"(^|[/_.-])oci([/_.-]|$)", re.IGNORECASE)


def needs_full(path: str) -> bool:
    """True if this one path is outside what a fetcher pull request may touch."""
    if FRAMEWORK_TESTS.match(path):
        return True
    if path.startswith(FETCHER_SCOPE_DIRS):
        return False
    return not path.endswith(".md")


# The weekly release PR always comes from this branch (tools/release.py).
RELEASE_BRANCH = "release/next"


def plan(event: str, paths: list[str] | None, head_ref: str = "") -> dict[str, str]:
    """The scope and the jobs to run. `paths` is None when the diff could not be read.

    `head_ref` is the pull request's source branch. The release-check job runs
    only for the release branch, whatever the scope.
    """
    release = str(head_ref == RELEASE_BRANCH).lower()
    if event != "pull_request" or not paths or any(needs_full(p) for p in paths):
        return {"scope": "full", "azure": "true", "oci": "true", "release": release}
    shared = any(p.startswith(SHARED_FETCHER_CODE) for p in paths)
    return {
        "scope": "fetchers",
        "azure": str(shared or any(AZURE.search(p) for p in paths)).lower(),
        "oci": str(shared or any(OCI.search(p) for p in paths)).lower(),
        "release": release,
    }


def changed_paths() -> list[str] | None:
    """Paths the pull request changes, or None if git cannot say.

    On pull_request the checkout is the merge commit, whose first parent is the
    base branch, so HEAD^1..HEAD is exactly what the pull request brings.
    --no-renames lists both the old and the new path of a moved file.
    """
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames", "-z", "HEAD^1", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"ci_plan: could not read the diff, running everything: {exc}", file=sys.stderr)
        return None
    return [p for p in out.split("\0") if p]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True, help="github.event_name")
    args = parser.parse_args()

    paths = changed_paths() if args.event == "pull_request" else None
    result = plan(args.event, paths, os.environ.get("GITHUB_HEAD_REF", ""))

    if paths:
        widening = [p for p in paths if needs_full(p)]
        print(f"{len(paths)} changed file(s); {len(widening)} outside the fetcher scope", file=sys.stderr)
        for p in widening[:20]:
            print(f"  full because of: {p}", file=sys.stderr)

    lines = [f"{key}={value}" for key, value in result.items()]
    print("\n".join(lines))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
