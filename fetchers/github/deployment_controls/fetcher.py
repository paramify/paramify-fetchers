#!/usr/bin/env python3
"""Who may deploy to production, and what was deployed: environment reviewers, wait timers, branch policies and production deployments."""

import fnmatch
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import iso, now_epoch, run, split_list, to_epoch  # noqa: E402

NAME = "github_deployment_controls"
CONFIG = {
    "production_environments": ("GITHUB_PRODUCTION_ENVIRONMENTS", "prod*,prd*,live"),
    "days_back": ("GITHUB_DEPLOYMENT_DAYS_BACK", 30),
    "max_deployments": ("GITHUB_MAX_DEPLOYMENTS", 500),
}
MAX_DAYS_BACK = 366
SHA_BATCH = 20
# A deployment a workflow job made links its run in every status (measured): .../actions/runs/<id>/job/<id>.
RUN_URL = re.compile(r"/actions/runs/(\d+)(?:/|$)")
# A job held by an environment's protection rules sits in "waiting", then goes to "queued" once released (measured).
PASSED = ("queued", "in_progress", "success")


def rule(env, kind):
    return next((r for r in env.get("protection_rules") or [] if r.get("type") == kind), None)


def environment_record(client, base, env, production):
    name = env.get("name") or ""
    path = f"{base}/environments/{quote(name, safe='')}"
    policy = env.get("deployment_branch_policy")
    custom = client.paginate_required(f"{path}/deployment-branch-policies", key="branch_policies") \
        if (policy or {}).get("custom_branch_policies") else []
    apps = client.paginate_required(f"{path}/deployment_protection_rules", key="custom_deployment_protection_rules")
    if custom is None or apps is None:
        return None
    reviewers = rule(env, "required_reviewers")
    return {
        "name": name,
        "production": production,
        "required_reviewers": None if reviewers is None else [
            {"type": r.get("type"), "reviewer": (r.get("reviewer") or {}).get("login")
             or (r.get("reviewer") or {}).get("slug")} for r in reviewers.get("reviewers") or []],
        "prevent_self_review": None if reviewers is None else reviewers.get("prevent_self_review"),
        "wait_timer_minutes": (rule(env, "wait_timer") or {}).get("wait_timer"),
        # null: any branch may deploy. protected_branches: only branches with protection. custom: the listed patterns.
        "branch_policy": None if policy is None else
        "protected_branches" if policy.get("protected_branches") else "custom",
        "allowed_refs": [{"name": c.get("name"), "type": c.get("type") or "branch"} for c in custom],
        "custom_protection_rules": [{"app": (a.get("app") or {}).get("slug"), "enabled": a.get("enabled")}
                                    for a in apps],
        "admins_can_bypass": env.get("can_admins_bypass"),
    }


def run_id(status):
    for field in ("log_url", "target_url"):
        found = RUN_URL.search(str(status.get(field) or ""))
        if found:
            return int(found.group(1))
    return None


def gate(states):
    """How a deployment fared at its environment's protection rules, from its states newest first: passed, waiting,
    stopped (held, then rejected, cancelled or timed out before it ran), or None when the history shows neither."""
    if any(s in PASSED for s in states):
        return "passed"
    if "waiting" in states:
        return "waiting" if states[0] == "waiting" else "stopped"
    return None


def approvals(client, base, run, env_name):
    """(the run's reviews of `env_name`, why unknown). A failure is recorded and answers (None, "failed").

    Each entry is one review: it releases or rejects every job then waiting on the environment, and names the
    environment once per job (measured). It carries no job and no time, so when one run made several deployments a
    review cannot be tied to one of them. A run deleted after its retention answers 404: unknown, not unapproved.
    """
    before = len(client.failures)
    found, body = client.lookup(f"{base}/actions/runs/{run}/approvals")
    if not found:
        return None, "failed" if len(client.failures) > before else "run_deleted"
    rows = []
    for a in body or []:
        jobs = sum(1 for e in a.get("environments") or [] if e.get("name") == env_name)
        if jobs:
            user = a.get("user") or {}
            rows.append({"user": user.get("login"),
                         "bot": user.get("type") == "Bot" or str(user.get("login") or "").endswith("[bot]"),
                         "state": a.get("state"), "comment": a.get("comment") or None, "jobs": jobs})
    return rows, None


def independent(d, made):
    """Whether a person other than the deployment's creator approved it: False when none did, None when unknown.

    A review names no job, but a reviewer approves a job only once. So the most jobs one such person approved in the
    run is a floor on the jobs they released; when it covers every deployment the run made, each one had them.
    """
    if d["gate"] != "passed" or d["approvals"] is None:
        return None
    jobs = Counter()
    for a in d["approvals"]:
        if a["state"] == "approved" and not a["bot"] and a["user"] != d["creator"]:
            jobs[a["user"]] += a["jobs"]
    if not jobs:
        return False
    return True if max(jobs.values()) >= made else None


def deployments(client, base, env_name, since, cap):
    """Deployments to one environment since `since`, newest first, each with its status history. None on failure."""
    seen = []
    found = client.paginate_required(f"{base}/deployments", {"environment": env_name},
                                     until=lambda d: seen.append(d) or (to_epoch(d.get("created_at")) or since) < since
                                     or len(seen) > cap)
    if found is None:
        return None
    if len(seen) > cap and (to_epoch(seen[-1].get("created_at")) or since) >= since:
        client.fail(f"GET {base}/deployments", "Truncated",
                    f"more than {cap} deployments to {env_name} in the window; raise GITHUB_MAX_DEPLOYMENTS",
                    "partial_failure")
        return None
    rows, by_run = [], {}
    for d in found:
        state, statuses = client.read(f"{base}/deployments/{d.get('id')}/statuses", {"per_page": 100})
        if state is not None:
            if state != "failed":
                client.fail(f"GET {base}/deployments/{d.get('id')}/statuses", "UnexpectedState", state,
                            "not_authorized")
            return None
        statuses = [x for x in statuses or [] if isinstance(x, dict)]  # newest first
        latest = statuses[0] if statuses else {}
        via_app = (d.get("performed_via_github_app") or {}).get("slug")
        # The oldest status is the one Actions wrote when the job asked for the environment.
        run = next((run_id(x) for x in reversed(statuses) if run_id(x)), None) if via_app == "github-actions" else None
        # One run can make several deployments, one per job (measured on cli/cli): its reviews are read once.
        if run is not None and run not in by_run:
            by_run[run] = approvals(client, base, run, env_name)
        approved, unknown = (None, "not_made_by_actions") if via_app != "github-actions" else \
            (None, "run_not_linked") if run is None else by_run[run]
        if unknown == "failed":
            return None
        rows.append({"id": d.get("id"), "created_at": d.get("created_at"), "ref": d.get("ref"), "sha": d.get("sha"),
                     "task": d.get("task"), "creator": (d.get("creator") or {}).get("login"),
                     "via_app": via_app, "production_environment_flag": d.get("production_environment"),
                     "latest_state": latest.get("state"), "latest_state_at": latest.get("created_at"),
                     "gate": gate([x.get("state") for x in statuses]),
                     "run_id": run, "approvals": approved, "approvals_unknown": unknown})
    made = Counter(r["run_id"] for r in rows if r["run_id"] is not None and r["gate"] == "passed")
    for r in rows:
        r["independent_approval"] = independent(r, made[r["run_id"]])
    return rows


def on_default_branch(client, org, repo, shas):
    """{sha: True/False/None}: whether each commit is in the default branch's history; None for an unknown commit.

    Ref.compare answers IDENTICAL for a commit that does not exist (measured), so each is paired with an object lookup.
    """
    out = {}
    branch = repo.get("default_branch")
    i, batch = 0, SHA_BATCH
    while i < len(shas):
        chunk = shas[i:i + batch]
        params = ", ".join(f"$s{k}: String!, $o{k}: GitObjectID!" for k in range(len(chunk)))
        body = " ".join(f"o{k}: object(oid: $o{k}) {{ oid }} c{k}: ref(qualifiedName: $ref) "
                        f"{{ compare(headRef: $s{k}) {{ aheadBy }} }}" for k in range(len(chunk)))
        state, data = client.graphql(
            f"GraphQL compare repos/{org}/{repo['name']}",
            f"query($owner: String!, $name: String!, $ref: String!, {params}) {{ "
            f"repository(owner: $owner, name: $name) {{ {body} }} }}",
            {"owner": org, "name": repo["name"], "ref": f"refs/heads/{branch}",
             **{f"s{k}": sha for k, sha in enumerate(chunk)}, **{f"o{k}": sha for k, sha in enumerate(chunk)}})
        if state == "timeout" and batch > 1:
            batch = max(1, batch // 2)
            continue
        if state == "timeout":
            client.fail(f"GraphQL compare repos/{org}/{repo['name']}", "GraphQLTimeout",
                        f"timed out on {chunk[0]} alone", "target_unreachable")
        if state != "ok":
            return None
        found = data.get("repository") or {}
        for k, sha in enumerate(chunk):
            ahead = ((found.get(f"c{k}") or {}).get("compare") or {}).get("aheadBy")
            out[sha] = None if not found.get(f"o{k}") or ahead is None else ahead == 0
        i += len(chunk)
    return out


def repo_record(client, org, repo, patterns, since, cap):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    envs = client.paginate_required(f"{base}/environments", key="environments")
    if envs is None:
        return {"repository": name, "collected": False}
    rows = []
    for env in envs:
        production = any(fnmatch.fnmatchcase((env.get("name") or "").lower(), p.lower()) for p in patterns)
        record = environment_record(client, base, env, production)
        if record is None:
            return {"repository": name, "collected": False}
        if production:
            record["deployments"] = deployments(client, base, env.get("name"), since, cap)
            if record["deployments"] is None:
                return {"repository": name, "collected": False}
        rows.append(record)
    shas = sorted({d["sha"] for e in rows for d in e.get("deployments") or [] if d["sha"]})
    contained = on_default_branch(client, org, repo, shas) if shas else {}
    if contained is None:
        return {"repository": name, "collected": False}
    for e in rows:
        for d in e.get("deployments") or []:
            d["on_default_branch"] = contained.get(d["sha"])
    return {"repository": name, "collected": True, "default_branch": repo.get("default_branch"), "environments": rows}


def collect(client, org, repos, config):
    patterns = split_list(config["production_environments"])
    if not 1 <= config["days_back"] <= MAX_DAYS_BACK or not patterns or config["max_deployments"] < 1:
        client.fail("config", "BadConfig", f"GITHUB_DEPLOYMENT_DAYS_BACK must be 1..{MAX_DAYS_BACK}, "
                    "GITHUB_PRODUCTION_ENVIRONMENTS non-empty, GITHUB_MAX_DEPLOYMENTS at least 1", "bad_config")
        return None
    since = now_epoch() - config["days_back"] * 86400
    records = [repo_record(client, org["login"], r, patterns, since, config["max_deployments"]) for r in repos]
    done = [r for r in records if r["collected"]]
    prod = [(r, e) for r in done for e in r["environments"] if e["production"]]
    deploys = [(r, e, d) for r, e in prod for d in e["deployments"]]

    def label(r, e):
        return f"{r['repository']}:{e['name']}"

    def approved(d):
        return [a for a in d["approvals"] or [] if a["state"] == "approved"]
    # Approval is judged only for deployments that got past the gate; one held there never ran.
    shipped = [(r, e, d) for r, e, d in deploys if d["gate"] == "passed" and d["approvals"] is not None]
    return {
        "metadata": {"since": iso(since)},
        "summary": {
            "environments_total": sum(len(r["environments"]) for r in done),
            "production_environments": sorted(label(r, e) for r, e in prod),
            "production_without_required_reviewers": sorted(label(r, e) for r, e in prod
                                                            if not e["required_reviewers"]),
            "production_allowing_self_review": sorted(label(r, e) for r, e in prod
                                                      if e["required_reviewers"] and not e["prevent_self_review"]),
            "production_deployable_from_any_branch": sorted(label(r, e) for r, e in prod if e["branch_policy"] is None),
            "production_admins_can_bypass": sorted(label(r, e) for r, e in prod if e["admins_can_bypass"]),
            "production_admin_bypass_unknown": sorted(label(r, e) for r, e in prod if e["admins_can_bypass"] is None),
            "production_deployments": len(deploys),
            # By commit, not by ref: a deployment names a branch, a tag or a bare commit, and a release branch can carry
            # commits the default branch never had.
            "production_deployments_not_on_default_branch": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in deploys if d["on_default_branch"] is False),
            "production_deployments_commit_unknown": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in deploys if d["on_default_branch"] is None),
            # Deployments a workflow job made carry the github-actions app; one made through the API by a person or
            # another tool does not, and no environment protection rule ran for it.
            "production_deployments_not_by_actions": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in deploys if d["via_app"] != "github-actions"),
            "production_deployments_by_state": {s: sum(1 for *_, d in deploys if (d["latest_state"] or "none") == s)
                                                for s in sorted({d["latest_state"] or "none" for *_, d in deploys})},
            "production_deployments_by_gate": {g: sum(1 for *_, d in deploys if (d["gate"] or "none") == g)
                                               for g in sorted({d["gate"] or "none" for *_, d in deploys})},
            # Held by the protection rules (waiting for review, or rejected or cancelled there): the gate working.
            "production_deployments_held_at_gate": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in deploys if d["gate"] in ("waiting", "stopped")),
            # Of the deployments that passed the gate, which the run's reviews approved. Unknown (no status, not made
            # by Actions, no run linked, or the run deleted) is listed apart from approved by nobody.
            "production_deployments_approved": len([d for *_, d in shipped if approved(d)]),
            "production_deployments_without_approval": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in shipped if not approved(d)),
            "production_deployments_approval_unknown": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in deploys
                if d["gate"] not in ("waiting", "stopped") and (d["gate"] is None or d["approvals"] is None)),
            # A person other than the creator approved it. A run's reviews cannot be tied to one of its deployments,
            # so a bot or the creator is named only when every approving review of the run was theirs, and a run whose
            # reviews cannot cover each of its deployments with a person is listed as ambiguous.
            "production_deployments_approved_independently": len([d for *_, d in shipped
                                                                  if d["independent_approval"]]),
            "production_deployments_without_independent_approver": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in shipped if approved(d) and d["independent_approval"] is False),
            "production_deployments_approved_by_bot": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in shipped if approved(d) and all(a["bot"] for a in approved(d))),
            "production_deployments_self_approved": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in shipped
                if approved(d) and all(a["user"] == d["creator"] for a in approved(d))),
            "production_deployments_approver_ambiguous": sorted(
                f"{label(r, e)}#{d['id']}" for r, e, d in shipped if approved(d) and d["independent_approval"] is None),
            "repositories_with_production_environment": len({r["repository"] for r, _ in prod}),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
