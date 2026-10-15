#!/usr/bin/env python3
"""How changes reached each default branch in a window: merged pull requests with their reviews and checks, and direct pushes.

Pull requests and commits are read over GraphQL: about 2 points per 50 pull requests with their reviews and checks,
where REST costs three calls per pull request and one per commit (measured on microsoft/vscode: ~8400 REST calls for
30 days). Each node is converted to the REST shape the rest of this file reads. A pull request whose reviews or checks
do not fit in one GraphQL page is read over REST, as is a commit whose associated pull requests do not.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import iso, run, to_epoch  # noqa: E402

NAME = "github_pull_request_checks"
CONFIG = {
    "days_back": ("GITHUB_PR_DAYS_BACK", 30),
    "max_pull_requests": ("GITHUB_PR_MAX_PER_REPOSITORY", 2000),
    "max_commits": ("GITHUB_MAX_COMMITS_PER_REPOSITORY", 5000),
}
REVIEWS_PAGE, CONTEXTS_PAGE, ASSOCIATED_PAGE = 50, 100, 5
PULL_REQUESTS = """
query($owner: String!, $name: String!, $branch: String!, $first: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(baseRefName: $branch, states: MERGED, orderBy: {field: UPDATED_AT, direction: DESC},
                 first: $first, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number title updatedAt mergedAt headRefOid
        mergeCommit { oid }
        author { login __typename }
        mergedBy { login __typename }
        labels(first: 20) { totalCount nodes { name } }
        reviews(first: %d) { totalCount nodes { state submittedAt author { login __typename } commit { oid } } }
        commits(last: 1) { nodes { commit { oid statusCheckRollup { contexts(first: %d) { totalCount nodes {
          __typename
          ... on CheckRun { name status conclusion startedAt completedAt }
          ... on StatusContext { context state createdAt }
        } } } } } }
      }
    }
  }
}""" % (REVIEWS_PAGE, CONTEXTS_PAGE)
HISTORY = """
query($owner: String!, $name: String!, $ref: String!, $since: GitTimestamp!, $first: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    isEmpty
    ref(qualifiedName: $ref) { target { ... on Commit {
      history(since: $since, first: $first, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          oid message committedDate
          author { name user { login } }
          signature { isValid }
          associatedPullRequests(first: %d) { totalCount nodes { mergedAt } }
        }
      }
    } } }
  }
}""" % ASSOCIATED_PAGE
FAILED = {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}
PASSED = {"success", "neutral", "skipped"}


def actor(node):
    """A GraphQL actor as a REST user. GraphQL drops the "[bot]" REST puts on an app's login."""
    if not node or not node.get("login"):
        return None
    bot = node.get("__typename") == "Bot"
    login = node["login"] if not bot or node["login"].endswith("[bot]") else f"{node['login']}[bot]"
    return {"login": login, "type": "Bot" if bot else "User"}


def lower(value):
    return value.lower() if isinstance(value, str) else value


def rest_reviews(nodes):
    return [{"user": actor(r.get("author")), "state": r.get("state"), "submitted_at": r.get("submittedAt"),
             "commit_id": (r.get("commit") or {}).get("oid")} for r in nodes]


def rest_checks(contexts):
    """statusCheckRollup contexts as (check runs, commit statuses) in REST's lower-case vocabulary."""
    runs, statuses = [], []
    for c in contexts:
        if c.get("__typename") == "CheckRun":
            runs.append({"name": c.get("name"), "status": lower(c.get("status")), "conclusion": lower(c.get("conclusion")),
                         "started_at": c.get("startedAt"), "completed_at": c.get("completedAt")})
        elif c.get("__typename") == "StatusContext":
            # EXPECTED is a required status not yet reported; REST's combined status has no such state.
            state = lower(c.get("state"))
            statuses.append({"context": c.get("context"), "state": "pending" if state == "expected" else state,
                             "updated_at": c.get("createdAt")})
    return runs, statuses


def is_bot(user):
    return bool(user) and (user.get("type") == "Bot" or str(user.get("login", "")).endswith("[bot]"))


def approvals(reviews, author, merged_at, head_sha):
    """Reviewers whose latest decisive review before the merge is APPROVED, excluding the author."""
    latest = {}
    for review in sorted(reviews, key=lambda r: r.get("submitted_at") or ""):
        user = review.get("user") or {}
        submitted = to_epoch(review.get("submitted_at"))
        if not user.get("login") or user.get("login") == author or (merged_at and submitted and submitted > merged_at):
            continue
        if review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[user["login"]] = review
    approved = [r for r in latest.values() if r.get("state") == "APPROVED"]
    return [{"reviewer": r["user"]["login"], "bot": is_bot(r["user"]),
             "on_final_commit": r.get("commit_id") == head_sha} for r in approved]


def check_outcomes(runs, statuses):
    """Per check name, the conclusion of its most recent completed run; legacy commit statuses alongside."""
    by_name = {}
    for check in sorted(runs, key=lambda c: c.get("completed_at") or c.get("started_at") or ""):
        if check.get("status") == "completed":
            by_name[check.get("name")] = check.get("conclusion") or "unknown"  # conclusion is nullable
        else:
            by_name.setdefault(check.get("name"), "pending")
    for status in sorted(statuses, key=lambda s: s.get("updated_at") or ""):
        by_name[f"status:{status.get('context')}"] = {"error": "failure"}.get(status.get("state"), status.get("state"))
    return by_name


def required_checks(client, base, branch):
    """Check names the branch requires now, from enforced rules and classic protection. None when unreadable."""
    rules = client.paginate_required(f"{base}/rules/branches/{branch}")
    state, protection = client.read(f"{base}/branches/{branch}/protection")
    if rules is None or state == "failed":
        return None
    names = {c.get("context") for r in rules if r.get("type") == "required_status_checks"
             for c in (r.get("parameters") or {}).get("required_status_checks") or []}
    checks = (protection if state is None else {}).get("required_status_checks") or {}
    names |= set(checks.get("contexts") or []) | {c.get("context") for c in checks.get("checks") or []}
    return sorted(n for n in names if n)


def pr_from_graphql(node):
    """A pullRequests node as REST's pull request, with its reviews and checks when they fit the page (else None)."""
    reviews = node.get("reviews") or {}
    head = ((node.get("commits") or {}).get("nodes") or [{}])[-1].get("commit") or {}
    contexts = (head.get("statusCheckRollup") or {}).get("contexts") or {"totalCount": 0, "nodes": []}
    labels = node.get("labels") or {}
    complete = lambda conn: (conn.get("totalCount") or 0) <= len(conn.get("nodes") or [])  # noqa: E731
    checks_ok = head.get("oid") == node.get("headRefOid") and complete(contexts)
    return {
        "number": node["number"], "title": node.get("title"), "user": actor(node.get("author")),
        "merged_by": actor(node.get("mergedBy")), "merged_at": node.get("mergedAt"),
        "updated_at": node.get("updatedAt"), "merge_commit_sha": (node.get("mergeCommit") or {}).get("oid"),
        "head": {"sha": node.get("headRefOid")},
        "labels": [{"name": n.get("name")} for n in labels.get("nodes") or []] if complete(labels) else None,
        "reviews": rest_reviews(reviews.get("nodes") or []) if complete(reviews) else None,
        "checks": rest_checks(contexts.get("nodes") or []) if checks_ok else None,
    }


def pr_record(client, base, pr, required):
    number, author = pr["number"], (pr.get("user") or {}).get("login")
    head_sha, merged_at = pr["head"]["sha"], to_epoch(pr.get("merged_at"))
    reviews = pr.get("reviews")
    if reviews is None:
        reviews = client.paginate_required(f"{base}/pulls/{number}/reviews")
    if pr.get("checks") is not None:
        runs, statuses = pr["checks"]
    else:
        runs = client.paginate_required(f"{base}/commits/{head_sha}/check-runs", {"filter": "latest"}, key="check_runs")
        status = client.get(f"{base}/commits/{head_sha}/status")
        statuses = None if status is None else status.get("statuses") or []
    labels = pr.get("labels")
    if labels is None:
        labels = client.paginate_required(f"{base}/issues/{number}/labels")
    if reviews is None or runs is None or statuses is None or labels is None:
        return {"number": number, "collected": False}
    approved = approvals(reviews, author, merged_at, head_sha)
    checks = check_outcomes(runs, statuses)
    merged_by = pr.get("merged_by")
    return {
        "number": number,
        "collected": True,
        "title": pr.get("title"),
        "author": author,
        "author_is_bot": is_bot(pr.get("user")),
        "merged_at": pr.get("merged_at"),
        "merged_by": (merged_by or {}).get("login"),
        "merged_by_bot": is_bot(merged_by),
        "labels": sorted(label.get("name") for label in labels if label.get("name")),
        "merge_commit_sha": pr.get("merge_commit_sha"),
        "head_sha": head_sha,
        "approvals": approved,
        "human_approvals": len([a for a in approved if not a["bot"]]),
        "approved": bool(approved),
        "approved_by_human": any(not a["bot"] for a in approved),
        "checks": checks,
        "checks_failed": sorted(n for n, c in checks.items() if c in FAILED),
        # A required check counts only when it passed; failed, pending or unknown all leave the gate unmet.
        "required_checks_failed": None if required is None else sorted(
            n for n in required if (n in checks or f"status:{n}" in checks)
            and checks.get(n, checks.get(f"status:{n}")) not in PASSED),
        "required_checks_missing": None if required is None else sorted(
            n for n in required if n not in checks and f"status:{n}" not in checks),
        "checks_pending": sorted(n for n, c in checks.items() if c == "pending"),
        "checks_unknown": sorted(n for n, c in checks.items() if c == "unknown"),
        "had_checks": bool(checks),
    }


def merged_pull_requests(client, owner, name, branch, since, cap):
    """Merged PRs into `branch` since `since`, newest first, stopping at the window. (items, truncated)"""
    # Merging updates a PR, so every PR merged in the window was updated in it; the walk stops at the first older one.
    nodes = client.graphql_nodes(f"GraphQL pullRequests repos/{owner}/{name}", PULL_REQUESTS,
                                 {"owner": owner, "name": name, "branch": branch},
                                 lambda d: ((d.get("repository") or {}).get("pullRequests")),
                                 until=lambda n: (to_epoch(n.get("updatedAt")) or since) < since)
    if nodes is None:
        return None, False
    recent = [pr_from_graphql(n) for n in nodes]
    merged = [pr for pr in recent if pr.get("merged_at") and (to_epoch(pr["merged_at"]) or 0) >= since]
    merged.sort(key=lambda p: p["merged_at"], reverse=True)
    return merged[:cap], len(merged) > cap


def history(data):
    """The branch's history connection; a branch with no commits yet (an empty repository) has none."""
    repository = data.get("repository")
    if repository is not None and repository.get("isEmpty") is True:
        return {"nodes": [], "pageInfo": {"hasNextPage": False}}
    return (((repository or {}).get("ref") or {}).get("target") or {}).get("history")


def direct_pushes(client, owner, name, branch, since, merge_shas, cap):
    """Commits on the branch in the window that no pull request brought in. (commits, truncated)"""
    seen = []
    commits = client.graphql_nodes(f"GraphQL history repos/{owner}/{name}", HISTORY,
                                   {"owner": owner, "name": name, "ref": f"refs/heads/{branch}", "since": iso(since)},
                                   history, until=lambda n: seen.append(n) or len(seen) > cap)
    if commits is None:
        return None, False
    pushed = []
    for commit in commits:
        if commit.get("oid") in merge_shas:
            continue
        associated = commit.get("associatedPullRequests") or {}
        nodes = associated.get("nodes") or []
        merged = any(p.get("mergedAt") for p in nodes)
        if not merged and (associated.get("totalCount") or 0) > len(nodes):
            more = client.paginate_required(f"repos/{owner}/{name}/commits/{commit.get('oid')}/pulls")
            if more is None:
                return None, False
            merged = any(p.get("merged_at") for p in more)
        if not merged:
            message = commit.get("message") or ""
            author = commit.get("author") or {}
            pushed.append({"sha": commit.get("oid"),
                           "author": (author.get("user") or {}).get("login") or author.get("name"),
                           "committed_at": commit.get("committedDate"),
                           "message": message.splitlines()[0][:120] if message else None,
                           "verified_signature": bool((commit.get("signature") or {}).get("isValid"))})
    return pushed, len(seen) > cap


def repo_record(client, org, repo, since, config):
    name, branch = repo["name"], repo.get("default_branch")
    base = f"repos/{org}/{name}"
    record = {"repository": name, "default_branch": branch}
    prs, prs_truncated = merged_pull_requests(client, org, name, branch, since, config["max_pull_requests"])
    if prs is None:
        return {**record, "collected": False}
    required = required_checks(client, base, branch)
    records = [pr_record(client, base, pr, required) for pr in prs]
    pushes, pushes_truncated = direct_pushes(client, org, name, branch, since,
                                             {p.get("merge_commit_sha") for p in prs}, config["max_commits"])
    if pushes is None:
        return {**record, "collected": False}
    for what, truncated in (("pull requests", prs_truncated), ("commits", pushes_truncated)):
        if truncated:
            client.fail(f"GET {base}", "WindowTruncated",
                        f"more {what} in the window than the configured maximum; raise it or shorten days_back",
                        "partial_failure")
    done = [r for r in records if r["collected"]]
    record.update({
        "collected": all(r["collected"] for r in records),
        "merged_pull_requests": len(records),
        "merged_without_approval": [r["number"] for r in done if not r["approved"]],
        "merged_without_human_approval": [r["number"] for r in done if not r["approved_by_human"]],
        "merged_by_bot": [r["number"] for r in done if r["merged_by_bot"]],
        "required_checks_now": required,
        "merged_with_failed_checks": [r["number"] for r in done if r["checks_failed"]],
        "merged_with_failed_required_checks": None if required is None else
        [r["number"] for r in done if r["required_checks_failed"] or r["required_checks_missing"]],
        "merged_with_pending_checks": [r["number"] for r in done if r["checks_pending"]],
        "merged_without_checks": [r["number"] for r in done if not r["had_checks"]],
        "direct_pushes": pushes,
        "truncated": prs_truncated or pushes_truncated,
        "pull_requests": records,
    })
    return record


def summarize(records):
    done = [r for r in records if r["collected"]]

    def total(key):
        return sum(len(r[key]) for r in done)

    return {
        "repositories_total": len(records),
        "not_collected": [r["repository"] for r in records if not r["collected"]],
        "merged_pull_requests": sum(r["merged_pull_requests"] for r in done),
        "merged_without_approval": total("merged_without_approval"),
        "merged_without_human_approval": total("merged_without_human_approval"),
        "merged_with_failed_checks": total("merged_with_failed_checks"),
        "merged_with_failed_required_checks": sum(len(r["merged_with_failed_required_checks"] or [])
                                                  for r in done),
        "required_checks_unreadable": [r["repository"] for r in done if r["required_checks_now"] is None],
        "merged_without_checks": total("merged_without_checks"),
        "direct_pushes": total("direct_pushes"),
        "repositories_with_direct_pushes": [r["repository"] for r in done if r["direct_pushes"]],
        "repositories_with_unreviewed_merges": [r["repository"] for r in done if r["merged_without_approval"]],
    }


def collect(client, org, repos, config):
    since_dt = datetime.now(timezone.utc) - timedelta(days=config["days_back"])
    since = since_dt.timestamp()
    records = [repo_record(client, org["login"], repo, since, config) for repo in repos]
    return {
        "metadata": {"window_start": iso(since)},
        "summary": summarize(records),
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
