#!/usr/bin/env python3
"""What GitHub Actions ran in a window: every workflow run with its trigger, commit and result, and the artifacts it kept."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import iso, newest_since, now_epoch, run  # noqa: E402

NAME = "github_workflow_runs"
CONFIG = {
    "days_back": ("GITHUB_WORKFLOW_RUNS_DAYS_BACK", 30),
    "max_runs": ("GITHUB_MAX_WORKFLOW_RUNS", 2000),
    "max_artifacts": ("GITHUB_MAX_ARTIFACTS", 2000),
    "include_branch_names": ("GITHUB_WORKFLOW_RUNS_INCLUDE_BRANCH_NAMES", True),
    "include_actors": ("GITHUB_WORKFLOW_RUNS_INCLUDE_ACTORS", True),
}
MAX_DAYS_BACK = 366
FAILED = ("failure", "timed_out", "startup_failure")
SCHEDULE_NOTE = ("No person starts a scheduled run. GitHub reports as its actor the user who last changed the "
                 "workflow's schedule (or the repository's default branch), so actor is null on scheduled runs. "
                 "triggering_actor is null on a scheduled run's first attempt and names who re-ran it on a later one.")


def run_row(r, default_branch):
    head_repo = r.get("head_repository") or {}
    # A pull request from a fork can carry a branch of the same name as the default branch (measured).
    own = head_repo.get("id") is not None and head_repo.get("id") == (r.get("repository") or {}).get("id")
    # On a scheduled run GitHub's actor is whoever last changed the schedule, not someone who started this run, so it
    # is not carried as one. A re-run is started by a person: triggering_actor is kept from the second attempt on.
    scheduled = r.get("event") == "schedule"
    rerun = (r.get("run_attempt") or 1) > 1
    return {
        "id": r.get("id"),
        "workflow": r.get("name"),
        "path": r.get("path"),
        "run_number": r.get("run_number"),
        "run_attempt": r.get("run_attempt"),
        "event": r.get("event"),
        "status": r.get("status"),
        "conclusion": r.get("conclusion"),
        "head_branch": r.get("head_branch"),
        "head_sha": r.get("head_sha"),
        "head_repository": head_repo.get("full_name"),
        "on_default_branch": own and r.get("head_branch") == default_branch,
        "actor": None if scheduled else (r.get("actor") or {}).get("login"),
        "triggering_actor": None if scheduled and not rerun else (r.get("triggering_actor") or {}).get("login"),
        "created_at": r.get("created_at"),
        "updated_at": r.get("updated_at"),
        "artifacts": [],
    }


def repo_record(client, org, repo, since, config):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    runs = newest_since(client, f"{base}/actions/runs", "workflow_runs", since, config["max_runs"],
                        "workflow runs", "GITHUB_MAX_WORKFLOW_RUNS")
    if runs is None:
        return {"repository": name, "collected": False}
    rows = [run_row(r, repo.get("default_branch")) for r in runs]
    if rows:
        # An artifact is uploaded after its run starts, so the artifacts of every run in the window are in it too.
        artifacts = newest_since(client, f"{base}/actions/artifacts", "artifacts", since, config["max_artifacts"],
                                 "artifacts", "GITHUB_MAX_ARTIFACTS")
        if artifacts is None:
            return {"repository": name, "collected": False}
        by_run = {r["id"]: r for r in rows}
        for a in artifacts:
            owner = by_run.get((a.get("workflow_run") or {}).get("id"))
            if owner is not None:
                owner["artifacts"].append({"name": a.get("name"), "size_in_bytes": a.get("size_in_bytes"),
                                           "digest": a.get("digest"), "created_at": a.get("created_at"),
                                           "expires_at": a.get("expires_at"), "expired": a.get("expired")})
    return {"repository": name, "collected": True, "default_branch": repo.get("default_branch"), "runs": rows}


def outcome(r):
    return r["conclusion"] or r["status"] or "unknown"


def collect(client, org, repos, config):
    if not 1 <= config["days_back"] <= MAX_DAYS_BACK or config["max_runs"] < 1 or config["max_artifacts"] < 1:
        client.fail("config", "BadConfig", f"GITHUB_WORKFLOW_RUNS_DAYS_BACK must be 1..{MAX_DAYS_BACK}, "
                    "GITHUB_MAX_WORKFLOW_RUNS and GITHUB_MAX_ARTIFACTS at least 1", "bad_config")
        return None
    since = now_epoch() - config["days_back"] * 86400
    records = [repo_record(client, org["login"], r, since, config) for r in repos]
    done = [r for r in records if r["collected"]]
    if not config["include_branch_names"]:
        # on_default_branch is worked out from the branch name before it is dropped, so it still says whether a run
        # came from the default branch. The key is removed, not nulled, and metadata.include_branch_names says why.
        for r in done:
            for x in r["runs"]:
                x.pop("head_branch", None)
    if not config["include_actors"]:
        # Removed, not nulled, like branch names: metadata.include_actors says why the keys are absent.
        for r in done:
            for x in r["runs"]:
                x.pop("actor", None)
                x.pop("triggering_actor", None)
    runs = [(r["repository"], x) for r in done for x in r["runs"]]
    scheduled_runs = sum(1 for _, x in runs if x["event"] == "schedule")
    on_default = [(repo, x) for repo, x in runs if x["on_default_branch"]]
    artifacts = [a for _, x in runs for a in x["artifacts"]]
    # A workflow is failing on the default branch when its newest finished run there failed. Runs are newest first.
    latest = {}
    for repo, x in on_default:
        if x["status"] == "completed":
            latest.setdefault(f"{repo}:{x['path']}", x)
    return {
        "metadata": {"since": iso(since),
                     **({"scheduled_runs_actor_note": SCHEDULE_NOTE}
                        if scheduled_runs and config["include_actors"] else {})},
        "summary": {
            "runs_total": len(runs),
            "runs_by_outcome": {o: sum(1 for _, x in runs if outcome(x) == o)
                                for o in sorted({outcome(x) for _, x in runs})},
            "default_branch_runs": len(on_default),
            "default_branch_runs_failed": sum(1 for _, x in on_default if x["conclusion"] in FAILED),
            "workflows_failing_on_default_branch": sorted(k for k, x in latest.items() if x["conclusion"] in FAILED),
            "runs_rerun": sum(1 for _, x in runs if (x["run_attempt"] or 1) > 1),
            "runs_scheduled": scheduled_runs,
            "workflows_run": len({f"{repo}:{x['path']}" for repo, x in runs}),
            "repositories_with_runs": sorted(r["repository"] for r in done if r["runs"]),
            "repositories_without_runs": sorted(r["repository"] for r in done if not r["runs"]),
            "artifacts_total": len(artifacts),
            "artifacts_expired": sum(1 for a in artifacts if a["expired"]),
            "artifacts_size_bytes": sum(a["size_in_bytes"] or 0 for a in artifacts),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
