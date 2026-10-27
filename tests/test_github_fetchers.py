"""GitHub fetchers, driven without GitHub.

FakeGitHub stands in for requests.Session and serves one small organization
whose responses copy shapes measured against a live org and public
repositories (fetchers/github/README.md, "What the client guards against").
Shape tests hold every fetcher to the category's pattern; client tests pin
paging, rate limiting and the 403/404 states that are not failures; fetcher
tests pin each verdict.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
import requests
import yaml
from requests.structures import CaseInsensitiveDict

REPO_ROOT = Path(__file__).resolve().parent.parent
GITHUB = REPO_ROOT / "fetchers" / "github"
FETCHERS = sorted(p.parent.name for p in GITHUB.glob("*/fetcher.py") if not p.parent.name.startswith("_"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"github_{name}_under_test", GITHUB / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODS = {name: _load(name) for name in FETCHERS}
gc = sys.modules["github_client"]
API = "https://api.github.test"
ORG = "acme"


# --- the fake ------------------------------------------------------------------

def response(status, body=None, headers=None, url=""):
    resp = requests.Response()
    resp.status_code = status
    resp._content = b"" if body is None else json.dumps(body).encode()
    resp.headers = CaseInsensitiveDict({"Content-Type": "application/json", "X-RateLimit-Limit": "5000",
                                        "X-RateLimit-Remaining": "4999", "X-RateLimit-Reset": "0", **(headers or {})})
    resp.url = url
    resp.reason = {200: "OK", 204: "No Content", 403: "Forbidden", 404: "Not Found"}.get(status, "")
    return resp


class FakeGitHub:
    """routes: path -> list (paged), dict (object), or (status, body[, headers])."""

    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=None):
        parsed = urlparse(url)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        query.update({k: str(v) for k, v in (params or {}).items()})
        path = parsed.path.removeprefix("/")
        self.calls.append((path, query))
        route = self.routes.get(path)
        if callable(route):
            route = route(query)
        if route is None:
            return response(404, {"message": "Not Found"}, url=url)
        if isinstance(route, tuple):
            return response(route[0], route[1], route[2] if len(route) > 2 else None, url=url)
        if isinstance(route, list):
            per_page, page = int(query.get("per_page", 30)), int(query.get("page", 1))
            chunk = route[(page - 1) * per_page: page * per_page]
            headers = {}
            if page * per_page < len(route):
                nxt = {k: v for k, v in query.items()} | {"page": page + 1}
                headers["Link"] = f'<{API}/{path}?{urlencode(nxt)}>; rel="next"'
            return response(200, chunk, headers, url=url)
        return response(200, route, url=url)

    def post(self, url, json=None, timeout=None):
        assert urlparse(url).path.endswith("/graphql") and "mutation" not in json["query"]
        self.calls.append(("graphql", json["variables"]))
        route = self.routes.get("graphql")
        if callable(route):
            route = route(json["query"], json["variables"])
        if route is None:
            route = graphql_from_rest(self.routes, json["query"], json["variables"])
        return response(route[0], route[1], route[2] if len(route) > 2 else {"X-RateLimit-Resource": "graphql"},
                        url=url)


# GraphQL is served from the same REST-shaped routes: the fixtures stay in one vocabulary, and the fetcher's
# GraphQL-to-REST conversion is exercised by every test.

def gql_actor(user):
    if not user:
        return None
    bot = user.get("type") == "Bot"
    return {"login": user["login"].removesuffix("[bot]") if bot else user["login"], "__typename": "Bot" if bot else "User"}


def gql_page(items, variables):
    start = int(variables.get("after") or 0)
    chunk = items[start:start + variables["first"]]
    more = start + variables["first"] < len(items)
    return {"pageInfo": {"hasNextPage": more, "endCursor": str(start + variables["first"]) if more else None},
            "nodes": chunk}


def _get(routes, path, query=None):
    route = routes.get(path)
    return route(query or {}) if callable(route) else route


def gql_pr(routes, base, p):
    reviews = _get(routes, f"{base}/pulls/{p['number']}/reviews") or []
    runs = (_get(routes, f"{base}/commits/{p['head']['sha']}/check-runs") or (200, {"check_runs": []}))[1]["check_runs"]
    statuses = (_get(routes, f"{base}/commits/{p['head']['sha']}/status") or {}).get("statuses") or []
    for part in (reviews,):
        if isinstance(part, tuple):
            return part
    contexts = [{"__typename": "CheckRun", "name": c.get("name"), "status": (c.get("status") or "").upper() or None,
                 "conclusion": c["conclusion"].upper() if c.get("conclusion") else None,
                 "startedAt": c.get("started_at"), "completedAt": c.get("completed_at")} for c in runs]
    contexts += [{"__typename": "StatusContext", "context": st.get("context"), "state": (st.get("state") or "").upper(),
                  "createdAt": st.get("updated_at")} for st in statuses]
    labels = p.get("labels") or []
    return {"number": p["number"], "title": p.get("title"), "updatedAt": p.get("updated_at"), "mergedAt": p.get("merged_at"),
            "headRefOid": p["head"]["sha"], "mergeCommit": {"oid": p.get("merge_commit_sha")},
            "author": gql_actor(p.get("user")), "mergedBy": gql_actor(p.get("merged_by")),
            "labels": {"totalCount": len(labels), "nodes": labels},
            "reviews": {"totalCount": len(reviews), "nodes": [
                {"state": r.get("state"), "submittedAt": r.get("submitted_at"), "author": gql_actor(r.get("user")),
                 "commit": {"oid": r.get("commit_id")}} for r in reviews]},
            "commits": {"nodes": [{"commit": {"oid": p["head"]["sha"], "statusCheckRollup": {
                "contexts": {"totalCount": len(contexts), "nodes": contexts}} if contexts else None}}]}}


def gql_repos(routes, query, variables):
    """Aliased repository batches: each repository's fields from its REST-shaped fixture routes."""
    out = {}
    for key, name in variables.items():
        if not key.startswith("n"):
            continue
        base = f"repos/{variables['owner']}/{name}"
        node = {}
        if ".github/workflows" in query:
            files = _get(routes, f"{base}/.workflows")
            if isinstance(files, tuple):
                return files
            node["object"] = None if files is None else {"entries": [
                {"name": f, "type": "tree" if text is None else "blob",
                 "object": None if text is None else {"text": text, "isBinary": False, "isTruncated": False}}
                for f, text in files.items()]}
        if "isSecurityPolicyEnabled" in query:
            node.update(_get(routes, f"{base}/.policy") or {"isSecurityPolicyEnabled": False, "securityPolicyUrl": None})
        out[f"r{key[1:]}"] = node
    return 200, {"data": out}


def graphql_from_rest(routes, query, variables):
    if "$n0" in query:
        return gql_repos(routes, query, variables)
    base = f"repos/{variables['owner']}/{variables['name']}"
    if "pullRequests(" in query:
        pulls = _get(routes, f"{base}/pulls")
        if isinstance(pulls, tuple):
            return pulls
        merged = sorted((p for p in pulls or [] if p.get("merged_at")), key=lambda p: p["updated_at"], reverse=True)
        page = gql_page(merged, variables)
        nodes = [gql_pr(routes, base, p) for p in page["nodes"]]
        for n in nodes:
            if isinstance(n, tuple):
                return n
        return 200, {"data": {"repository": {"pullRequests": {**page, "nodes": nodes}}}}
    commits = _get(routes, f"{base}/commits")
    if isinstance(commits, tuple):
        return commits
    nodes = []
    for c in commits or []:
        info = c.get("commit") or {}
        associated = _get(routes, f"{base}/commits/{c['sha']}/pulls") or []
        nodes.append({"oid": c["sha"], "message": info.get("message"),
                      "committedDate": (info.get("committer") or {}).get("date"),
                      "author": {"name": (info.get("author") or {}).get("name"),
                                 "user": {"login": c["author"]["login"]} if c.get("author") else None},
                      "signature": {"isValid": True} if (info.get("verification") or {}).get("verified") else None,
                      "associatedPullRequests": {"totalCount": len(associated),
                                                 "nodes": [{"mergedAt": a.get("merged_at")} for a in associated]}})
    history = gql_page(nodes, variables)
    return 200, {"data": {"repository": {"isEmpty": False, "ref": {"target": {"history": history}}}}}


def repo(name, **kw):
    return {"name": name, "default_branch": "main", "visibility": "public", "archived": False, "fork": False,
            "size": 10, "pushed_at": "2026-10-01T00:00:00Z", **kw}


def ruleset(id_, name, enforcement, rules, include=("~DEFAULT_BRANCH",), source_type="Repository", **kw):
    return {"id": id_, "name": name, "target": "branch", "enforcement": enforcement, "source_type": source_type,
            "source": f"{ORG}/x", "conditions": {"ref_name": {"include": list(include), "exclude": []}},
            "rules": rules, "bypass_actors": kw.pop("bypass_actors", []), **kw}


PR_RULE = {"type": "pull_request", "parameters": {"required_approving_review_count": 1,
                                                   "dismiss_stale_reviews_on_push": True,
                                                   "require_code_owner_review": False,
                                                   "require_last_push_approval": False,
                                                   "required_review_thread_resolution": False}}
CHECKS_RULE = {"type": "required_status_checks",
               "parameters": {"strict_required_status_checks_policy": False,
                              "required_status_checks": [{"context": "ci"}]}}
NFF_RULE = {"type": "non_fast_forward"}
NOT_PROTECTED = (404, {"message": "Branch not protected"})


def enforced(rules, ruleset_id):
    return [{**r, "ruleset_source_type": "Repository", "ruleset_source": f"{ORG}/x", "ruleset_id": ruleset_id}
            for r in rules]


def org_routes(repos, public=None):
    return {
        f"orgs/{ORG}": {"login": ORG, "plan": {"name": "free"},
                        "public_repos": len(repos) if public is None else public, "total_private_repos": 0},
        f"orgs/{ORG}/repos": repos,
    }


def sandbox_routes():
    """The six-repository sandbox as measured, plus classic protection and an org ruleset with always-bypass."""
    active = ruleset(1, "fetcher-test-main", "active", [PR_RULE, CHECKS_RULE, NFF_RULE])
    names = ["protected", "disabled-rules", "evaluate-rules", "unprotected", "classic-only", "org-bypass"]
    routes = org_routes([repo(n) for n in names])
    for n in names:
        routes[f"repos/{ORG}/{n}/rulesets/rule-suites"] = []
        routes[f"repos/{ORG}/{n}/rules/branches/main"] = []
        routes[f"repos/{ORG}/{n}/rulesets"] = []
        routes[f"repos/{ORG}/{n}/branches/main/protection"] = NOT_PROTECTED
    routes[f"repos/{ORG}/protected/rules/branches/main"] = enforced(active["rules"], 1)
    routes[f"repos/{ORG}/protected/rulesets"] = [active]
    routes[f"repos/{ORG}/protected/rulesets/1"] = active
    for n, mode, id_ in (("disabled-rules", "disabled", 2), ("evaluate-rules", "evaluate", 3)):
        rs = ruleset(id_, "fetcher-test-main", mode, [PR_RULE, CHECKS_RULE, NFF_RULE],
                     bypass_actors=[{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}])
        routes[f"repos/{ORG}/{n}/rulesets"] = [rs]
        routes[f"repos/{ORG}/{n}/rulesets/{id_}"] = rs
    routes[f"repos/{ORG}/classic-only/branches/main/protection"] = {
        "required_status_checks": {"strict": True, "contexts": ["build"], "checks": [{"context": "build"}]},
        "required_pull_request_reviews": {"required_approving_review_count": 2, "dismiss_stale_reviews": True},
        "enforce_admins": {"enabled": False}, "required_signatures": {"enabled": True},
        "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False},
    }
    org_rs = ruleset(9, "org-baseline", "active", [PR_RULE, {"type": "copilot_code_review", "parameters": {}}],
                     source_type="Organization",
                     bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}])
    routes[f"repos/{ORG}/org-bypass/rulesets"] = [org_rs]
    routes[f"repos/{ORG}/org-bypass/rulesets/9"] = org_rs
    routes[f"repos/{ORG}/org-bypass/rules/branches/main"] = enforced(org_rs["rules"], 9)
    return routes


@pytest.fixture
def fake(monkeypatch):
    holder = {}

    def install(routes):
        holder["fake"] = FakeGitHub(routes)
        monkeypatch.setattr(gc.requests, "Session", lambda: holder["fake"])
        monkeypatch.setattr(gc.time, "sleep", lambda s: holder.setdefault("slept", []).append(s))
        return holder["fake"]
    install.holder = holder
    return install


def run_fetcher(name, monkeypatch, tmp_path, **env):
    monkeypatch.setenv("GITHUB_ORG", ORG)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_API_URL", API)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    code = gc.run(MODS[name].NAME, MODS[name].collect, getattr(MODS[name], "CONFIG", None),
                  inventory=getattr(MODS[name], "INVENTORY", False))
    evidence = json.loads(next(tmp_path.glob(f"{MODS[name].NAME}_*.json")).read_text())
    status = json.loads((tmp_path / "status.json").read_text()) if (tmp_path / "status.json").exists() else None
    return code, evidence, status


# --- the shape every fetcher follows -------------------------------------------

BP_TARGET = yaml.safe_load((GITHUB / "branch_protection" / "fetcher.yaml").read_text())["target_schema"]


@pytest.mark.parametrize("name", FETCHERS)
def test_every_fetcher_follows_the_shape(name):
    m, spec = MODS[name], yaml.safe_load((GITHUB / name / "fetcher.yaml").read_text())
    assert m.NAME == spec["name"] == f"github_{name}"
    assert callable(m.collect)
    assert spec["target_schema"] == BP_TARGET  # one target shape for the whole category
    assert spec["evidence_set"]["reference_id"].startswith("EVD-GITHUB-")
    declared = {f["env"] for f in spec.get("config_schema", {}).values()}
    assert {env for env, _ in getattr(m, "CONFIG", {}).values()} <= declared
    assert len(spec["evidence_set"]["instructions"].split()) <= 80


@pytest.mark.parametrize("api_url,graphql", [
    ("https://api.github.com", "https://api.github.com/graphql"),
    ("https://api.acme.ghe.com", "https://api.acme.ghe.com/graphql"),
    ("https://git.acme.internal/api/v3", "https://git.acme.internal/api/graphql"),
])
def test_graphql_lives_beside_each_hosts_rest_api(api_url, graphql):
    assert gc.GitHubClient(api_url, "t").graphql_url() == graphql


# --- the client ------------------------------------------------------------------

def client_for(fake, routes):
    fake(routes)
    return gc.GitHubClient(API, "t")


def test_a_repeated_page_fails_instead_of_looping(fake):
    client = client_for(fake, {"loop": lambda q: (200, [1], {"Link": f'<{API}/loop?page=1>; rel="next"'})})
    state, _ = client.paginate("loop")
    assert state == "failed" and client.failures[0]["type"] == "PaginationNotAdvancing"


def test_an_absolute_url_off_the_api_host_is_refused(fake):
    client = client_for(fake, {})
    with pytest.raises(ValueError):
        client.read("https://evil.example/x")


@pytest.mark.parametrize("status,message,state", [
    (404, "Branch not protected", gc.NOT_PROTECTED),
    (403, "Upgrade to GitHub Team to enable this feature.", gc.PLAN_UNAVAILABLE),
    (403, "Dependabot alerts are disabled for this repository.", gc.FEATURE_OFF),
    (404, "Vulnerability alerts are disabled.", gc.FEATURE_OFF),
    (404, "Secret scanning is disabled on this repository.", gc.FEATURE_OFF),
    (404, "no analysis found", gc.NOT_SET_UP),
])
def test_measured_feature_states_are_not_failures(fake, status, message, state):
    client = client_for(fake, {"x": (status, {"message": message})})
    assert client.read("x")[0] == state
    assert client.paginate("x")[0] == state
    assert client.failures == []


@pytest.mark.parametrize("status,message", [
    (404, "Not Found"),                                          # no permission, measured on classic protection
    (403, "You are not authorized to perform this operation."),  # measured on another org's alerts
    (403, "You are not authorized to read code scanning alerts."),
])
def test_permission_responses_are_failures_that_name_the_permission(fake, status, message):
    client = client_for(fake, {"x": (status, {"message": message},
                                     {"X-Accepted-GitHub-Permissions": "administration=read"})})
    assert client.read("x")[0] == "failed"
    assert "administration=read" in client.failures[0]["message"]
    assert client.failure_code() == "not_authorized"


def test_rate_limit_fails_rather_than_outsleeping_the_runner(fake):
    client = client_for(fake, {"x": (403, {"message": "API rate limit exceeded"},
                                     {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 3600)})})
    assert client.read("x")[0] == "failed"
    assert "slept" not in fake.holder
    assert client.codes == ["rate_limited"]  # a 403, but not a missing permission


def test_an_allowlisted_repo_the_token_cannot_see_fails_as_bad_config(fake):
    client = client_for(fake, {**org_routes([repo("a"), repo("b")]), f"repos/{ORG}/B": repo("b")})
    repos = gc.list_repos(client, client.get(f"orgs/{ORG}"), ["B", "ghost"], False)
    assert [r["name"] for r in repos] == ["b"]
    assert client.codes == ["bad_config"]


def test_archived_repos_are_skipped_unless_asked_for(fake):
    client = client_for(fake, org_routes([repo("live"), repo("old", archived=True)]))
    org = client.get(f"orgs/{ORG}")
    assert [r["name"] for r in gc.list_repos(client, org, [], False)] == ["live"]
    assert [r["name"] for r in gc.list_repos(client, org, [], True)] == ["live", "old"]


# Measured 2026-10-04: one active ruleset per pattern on a sandbox repository, then
# rules/branches/{branch} for each branch. A bare ** does not cross "/"; only **/ does.
GLOB_PATTERNS = ["refs/heads/**/*", "refs/heads/*", "refs/heads/release/*", "refs/heads/release/**",
                 "refs/heads/**", "refs/heads/3.*", "refs/heads/?ev", "refs/heads/a/**/c"]
GITHUB_APPLIES = {
    "3.12": {"refs/heads/*", "refs/heads/**", "refs/heads/**/*", "refs/heads/3.*"},
    "a/b/c": {"refs/heads/**/*", "refs/heads/a/**/c"},
    "dev": {"refs/heads/*", "refs/heads/**", "refs/heads/**/*", "refs/heads/?ev"},
    "feature/x": {"refs/heads/**/*"},
    "main": {"refs/heads/*", "refs/heads/**", "refs/heads/**/*"},
    "release/1.0": {"refs/heads/**/*", "refs/heads/release/*", "refs/heads/release/**"},
}


@pytest.mark.parametrize("branch", sorted(GITHUB_APPLIES))
def test_ref_matching_agrees_with_what_github_applied(branch):
    ours = {p for p in GLOB_PATTERNS if gc.ref_matches(p, f"refs/heads/{branch}", "main")}
    assert ours == GITHUB_APPLIES[branch]


# --- branch_protection -------------------------------------------------------------

def test_branch_protection_verdicts_on_the_sandbox(fake, monkeypatch, tmp_path):
    fake(sandbox_routes())
    code, ev, status = run_fetcher("branch_protection", monkeypatch, tmp_path)
    assert code == 0 and status is None and ev["metadata"]["partial_failure"] is False
    s = ev["summary"]
    assert s["repositories_total"] == 6
    assert s["requiring_approval"] == 3  # protected, classic-only, org-bypass
    assert sorted(s["without_status_checks"]) == ["disabled-rules", "evaluate-rules", "org-bypass", "unprotected"]
    assert sorted(s["with_rulesets_not_enforced"]) == ["disabled-rules", "evaluate-rules"]
    assert s["with_always_bypass"] == ["org-bypass"]
    assert s["admins_exempt_from_classic"] == ["classic-only"]
    assert sorted(s["unprotected"]) == ["disabled-rules", "evaluate-rules", "unprotected"]
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["classic-only"]["requirements"]["approvals"] == 2
    assert by["classic-only"]["requirements"]["signed_commits"] is True
    assert by["protected"]["requirements"]["status_checks"] == ["ci"]
    # enforcement comes from what GitHub reports enforced, never from the ruleset's own definition
    assert [r["enforced_on_default_branch"] for r in by["disabled-rules"]["rulesets"]] == [False]
    assert [r["enforced_on_default_branch"] for r in by["protected"]["rulesets"]] == [True]
    assert "copilot_code_review" in by["org-bypass"]["requirements"]["rule_types"]  # unknown types carried through


def test_unreadable_classic_protection_is_unknown_never_unprotected(fake, monkeypatch, tmp_path):
    # Measured on cpython/vscode/kubernetes: 403 "Resource not accessible by personal access token".
    routes = sandbox_routes()
    for n in ("unprotected", "protected"):
        routes[f"repos/{ORG}/{n}/branches/main/protection"] = (
            403, {"message": "Resource not accessible by personal access token"},
            {"X-Accepted-GitHub-Permissions": "administration=read"})
    fake(routes)
    code, ev, status = run_fetcher("branch_protection", monkeypatch, tmp_path)
    assert code == 1 and status["code"] == "not_authorized" and "administration=read" in status["error"]
    by = {r["repository"]: r for r in ev["repositories"]}
    assert len(by) == 6  # one unreadable repository does not discard the others
    assert by["unprotected"]["requires_approval"] is None  # unknown, not a fabricated finding
    assert by["protected"]["requires_approval"] is True  # an enforced rule proves it regardless
    s = ev["summary"]
    assert "unprotected" not in s["unprotected"] and "unprotected" not in s["without_approval"]
    assert sorted(s["classic_protection_unreadable"]) == ["protected", "unprotected"]


def test_bad_target_config_fails_before_any_call(fake, monkeypatch, tmp_path):
    f = fake({})
    monkeypatch.setenv("GITHUB_API_URL", "http://insecure.test")
    monkeypatch.setenv("GITHUB_ORG", ORG)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    assert gc.run("github_branch_protection", MODS["branch_protection"].collect) == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config" and f.calls == []


# --- pull_request_checks ---------------------------------------------------------

def ago(days):
    return gc.iso(time.time() - days * 86400)


def pr(number, merged_days_ago, author="dev", head=None, updated_days_ago=None):
    merged = None if merged_days_ago is None else ago(merged_days_ago)
    return {"number": number, "title": f"PR {number}", "user": {"login": author, "type": "User"},
            "merged_at": merged, "merge_commit_sha": f"m{number}", "head": {"sha": head or f"h{number}"},
            "updated_at": ago(updated_days_ago if updated_days_ago is not None else (merged_days_ago or 1))}


def review(user, state, days_ago, commit="h1", bot=False):
    return {"user": {"login": user, "type": "Bot" if bot else "User"}, "state": state,
            "submitted_at": ago(days_ago), "commit_id": commit}


def check(name, conclusion, completed_days_ago=1, status="completed"):
    return {"name": name, "status": status, "conclusion": conclusion, "completed_at": ago(completed_days_ago)}


def pr_routes(pulls, reviews, runs, statuses=None, commits=None, associated=None, rules=None, protection=NOT_PROTECTED):
    routes = org_routes([repo("app")])
    base = f"repos/{ORG}/app"
    routes[f"{base}/pulls"] = pulls
    routes[f"{base}/rules/branches/main"] = rules or []
    routes[f"{base}/branches/main/protection"] = protection
    for p in pulls:
        n, sha = p["number"], p["head"]["sha"]
        routes[f"{base}/pulls/{n}/reviews"] = reviews.get(n, [])
        routes[f"{base}/commits/{sha}/check-runs"] = lambda q, r=runs.get(n, []): (200, {"total_count": len(r),
                                                                                          "check_runs": r})
        routes[f"{base}/commits/{sha}/status"] = {"statuses": (statuses or {}).get(n, [])}
    routes[f"{base}/commits"] = commits or []
    for sha, prs in (associated or {}).items():
        routes[f"{base}/commits/{sha}/pulls"] = prs
    return routes


def test_approval_is_the_latest_decisive_review_before_the_merge():
    a = MODS["pull_request_checks"].approvals
    merged = time.time() - 86400
    assert a([review("x", "APPROVED", 3), review("x", "CHANGES_REQUESTED", 2)], "dev", merged, "h1") == []
    assert a([review("x", "CHANGES_REQUESTED", 3), review("x", "COMMENTED", 2.5), review("x", "APPROVED", 2)],
             "dev", merged, "h1")[0]["reviewer"] == "x"
    assert a([review("dev", "APPROVED", 2)], "dev", merged, "h1") == []           # the author cannot approve
    assert a([review("x", "APPROVED", 0.5)], "dev", merged, "h1") == []          # after the merge
    got = a([review("github-actions[bot]", "APPROVED", 2, bot=True), review("y", "APPROVED", 2, commit="old")],
            "dev", merged, "h1")
    assert {(g["reviewer"], g["bot"], g["on_final_commit"]) for g in got} == {
        ("github-actions[bot]", True, True), ("y", False, False)}


def test_the_pr_walk_stops_at_the_first_pr_updated_before_the_window(fake, monkeypatch, tmp_path):
    pulls = [pr(i, 1) for i in range(1, 151)] + [pr(1000 + i, 90) for i in range(300)]
    f = fake(pr_routes(pulls, {}, {}))
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    assert code == 0 and ev["summary"]["merged_pull_requests"] == 150
    pages = [v for p, v in f.calls if p == "graphql" and "branch" in v]
    assert len(pages) == 4  # 50 a page; the fourth holds the first older PR, so not all 9


def test_pull_request_verdicts(fake, monkeypatch, tmp_path):
    rules = enforced([CHECKS_RULE], 1)  # requires "ci"
    pulls = [pr(1, 2), pr(2, 2), pr(3, 2), pr(4, 2), pr(5, None, updated_days_ago=2)]  # 5 closed unmerged
    reviews = {1: [review("lead", "APPROVED", 3)], 2: [review("github-actions[bot]", "APPROVED", 3, commit="h2", bot=True)]}
    runs = {1: [check("ci", "success", 3)], 2: [check("ci", "success", 3), check("lint", "failure", 3)],
            3: [check("ci", "failure", 3)], 4: []}
    commits = [{"sha": "m1"}, {"sha": "m2"}, {"sha": "m3"}, {"sha": "m4"},
               {"sha": "d1", "commit": {"message": "hotfix\nbody", "committer": {"date": ago(1)}},
                "author": {"login": "admin"}}]
    fake(pr_routes(pulls, reviews, runs, commits=commits, associated={"d1": []}, rules=rules))
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    assert code == 0
    r = ev["repositories"][0]
    assert r["merged_pull_requests"] == 4 and r["required_checks_now"] == ["ci"]
    assert r["merged_without_approval"] == [3, 4]
    assert r["merged_without_human_approval"] == [2, 3, 4]
    assert r["merged_with_failed_checks"] == [2, 3]
    assert r["merged_with_failed_required_checks"] == [3, 4]  # 2 failed only optional lint; 4 never ran ci
    assert r["merged_without_checks"] == [4]
    assert [d["sha"] for d in r["direct_pushes"]] == ["d1"] and r["direct_pushes"][0]["message"] == "hotfix"


def test_a_window_beyond_the_maximum_fails_as_truncated(fake, monkeypatch, tmp_path):
    fake(pr_routes([pr(i, 1) for i in range(1, 6)], {}, {}))
    code, ev, status = run_fetcher("pull_request_checks", monkeypatch, tmp_path, GITHUB_PR_MAX_PER_REPOSITORY="3")
    assert code == 1 and status["code"] == "partial_failure" and "WindowTruncated" in json.dumps(ev["metadata"])
    assert ev["repositories"][0]["truncated"] is True


def test_who_merged_and_the_labels_are_reported(fake, monkeypatch, tmp_path):
    # Measured on kubernetes/kubernetes: Prow merges after `lgtm` and `approved` labels, with no GitHub review.
    prow = pr(1, 1)
    prow.update({"merged_by": {"login": "kubernetes-prow[bot]", "type": "Bot"},
                 "labels": [{"name": "lgtm"}, {"name": "approved"}]})
    self_merge = pr(2, 1)
    self_merge["merged_by"] = {"login": "dev", "type": "User"}
    fake(pr_routes([prow, self_merge], {}, {}))
    _, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    r = ev["repositories"][0]
    by = {p["number"]: p for p in r["pull_requests"]}
    assert by[1]["merged_by"] == "kubernetes-prow[bot]" and by[1]["merged_by_bot"] is True
    assert by[1]["labels"] == ["approved", "lgtm"]
    assert by[2]["merged_by"] == "dev" and by[2]["merged_by_bot"] is False
    assert r["merged_by_bot"] == [1] and r["merged_without_approval"] == [1, 2]


def test_reviews_checks_and_labels_beyond_one_graphql_page_are_read_over_rest(fake, monkeypatch, tmp_path):
    pc = MODS["pull_request_checks"]
    routes = pr_routes([pr(1, 2)], {1: [review("lead", "APPROVED", 3)]}, {1: [check("ci", "failure", 3)]})
    base = f"repos/{ORG}/app"

    def overflowing(query, variables):
        status, body = graphql_from_rest(routes, query, variables)
        for node in (body["data"]["repository"].get("pullRequests") or {}).get("nodes") or []:
            node["reviews"] = {"totalCount": pc.REVIEWS_PAGE + 1, "nodes": []}
            node["labels"] = {"totalCount": 21, "nodes": []}
            node["commits"]["nodes"][0]["commit"]["statusCheckRollup"] = {
                "contexts": {"totalCount": pc.CONTEXTS_PAGE + 1, "nodes": []}}
        return status, body
    routes["graphql"] = overflowing
    routes[f"{base}/issues/1/labels"] = [{"name": "bug"}]
    f = fake(routes)
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    rec = ev["repositories"][0]["pull_requests"][0]
    assert code == 0 and rec["approved"] is True and rec["checks_failed"] == ["ci"] and rec["labels"] == ["bug"]
    rest = {p for p, _ in f.calls if p != "graphql"}
    assert {f"{base}/pulls/1/reviews", f"{base}/commits/h1/check-runs", f"{base}/issues/1/labels"} <= rest


def test_a_graphql_timeout_halves_the_page_until_it_answers(fake, monkeypatch, tmp_path):
    routes = pr_routes([pr(i, 1) for i in range(1, 31)], {}, {})
    routes["graphql"] = lambda q, v: ((502, {"message": "Bad Gateway"}) if v["first"] > 12
                                      else graphql_from_rest(routes, q, v))
    f = fake(routes)
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    assert code == 0 and ev["summary"]["merged_pull_requests"] == 30
    sizes = [v["first"] for p, v in f.calls if p == "graphql" and "branch" in v]
    assert sizes[:3] == [50, 25, 12]
    assert "slept" not in fake.holder  # a timeout is never retried at the same size


def test_a_graphql_page_that_never_answers_fails(fake, monkeypatch, tmp_path):
    routes = pr_routes([pr(1, 1)], {}, {})
    routes["graphql"] = lambda q, v: (502, {"message": "Bad Gateway"})
    fake(routes)
    code, ev, status = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    assert code == 1 and "GraphQLTimeout" in json.dumps(ev["metadata"]["api_failures"])
    assert ev["repositories"][0]["collected"] is False


def test_an_empty_repository_has_no_pushes_rather_than_failing(fake, monkeypatch, tmp_path):
    routes = pr_routes([], {}, {})

    def empty(query, variables):
        if "history(" in query:
            return 200, {"data": {"repository": {"isEmpty": True, "ref": None}}}
        return graphql_from_rest(routes, query, variables)
    routes["graphql"] = empty
    fake(routes)
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    assert code == 0 and ev["repositories"][0]["direct_pushes"] == []


def test_a_missing_branch_in_a_repository_with_commits_fails(fake, monkeypatch, tmp_path):
    routes = pr_routes([], {}, {})
    routes["graphql"] = lambda q, v: ((200, {"data": {"repository": {"isEmpty": False, "ref": None}}})
                                      if "history(" in q else graphql_from_rest(routes, q, v))
    fake(routes)
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    assert code == 1 and ev["repositories"][0]["collected"] is False


def test_a_commit_with_more_associated_prs_than_fit_is_read_over_rest(fake, monkeypatch, tmp_path):
    pc = MODS["pull_request_checks"]
    commits = [{"sha": "c1", "commit": {"message": "x", "committer": {"date": ago(1)}}}]
    routes = pr_routes([], {}, {}, commits=commits, associated={"c1": [{"merged_at": None}] * pc.ASSOCIATED_PAGE})
    routes_rest = f"repos/{ORG}/app/commits/c1/pulls"

    def crowded(query, variables):
        status, body = graphql_from_rest(routes, query, variables)
        if "history(" in query:
            body["data"]["repository"]["ref"]["target"]["history"]["nodes"][0]["associatedPullRequests"]["totalCount"] += 1
            routes[routes_rest] = [{"merged_at": ago(1)}]
        return status, body
    routes["graphql"] = crowded
    fake(routes)
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    assert code == 0 and ev["repositories"][0]["direct_pushes"] == []  # the sixth PR merged it


def test_a_commit_status_still_expected_is_pending():
    pc = MODS["pull_request_checks"]
    runs, statuses = pc.rest_checks([{"__typename": "StatusContext", "context": "ci/legacy", "state": "EXPECTED",
                                      "createdAt": ago(1)}])
    assert runs == [] and pc.check_outcomes(runs, statuses) == {"status:ci/legacy": "pending"}
    assert pc.actor({"login": "dependabot", "__typename": "Bot"}) == {"login": "dependabot[bot]", "type": "Bot"}
    assert pc.actor(None) is None and pc.actor({"login": None}) is None


def test_unreadable_required_checks_are_unknown_not_none_failed(fake, monkeypatch, tmp_path):
    fake(pr_routes([pr(1, 1)], {}, {1: [check("ci", "failure")]},
                   protection=(403, {"message": "Resource not accessible by personal access token"})))
    code, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    r = ev["repositories"][0]
    assert code == 1 and r["required_checks_now"] is None and r["merged_with_failed_required_checks"] is None
    assert r["merged_with_failed_checks"] == [1]
    assert ev["summary"]["required_checks_unreadable"] == ["app"]


# --- dependabot_alerts -------------------------------------------------------------

def dependabot_alert(number, state, severity, created_days_ago, closed_days_ago=None, cve="CVE-2021-1", reason=None):
    closed = None if closed_days_ago is None else ago(closed_days_ago)
    return {"number": number, "state": state, "created_at": ago(created_days_ago),
            "fixed_at": closed if state == "fixed" else None,
            "dismissed_at": closed if state == "dismissed" else None, "dismissed_reason": reason,
            "auto_dismissed_at": closed if state == "auto_dismissed" else None,
            "security_advisory": {"ghsa_id": f"GHSA-{number}", "cve_id": cve, "severity": severity,
                                  "epss": {"percentage": 0.5}},
            "security_vulnerability": {"severity": severity, "first_patched_version": {"identifier": "9.9"}},
            "dependency": {"package": {"ecosystem": "pip", "name": "django"}, "manifest_path": "requirements.txt",
                           "scope": "runtime"}}


def sbom(*names):
    return {"sbom": {"packages": [{"SPDXID": "SPDXRef-github-acme-x-main-repository", "name": "com.github.acme/x"}]
                     + [{"SPDXID": f"SPDXRef-{n}", "name": n} for n in names]}}


def dependabot_routes():
    names = ["scanned", "off", "graph-empty", "graph-off"]
    routes = org_routes([repo(n) for n in names])
    base = f"repos/{ORG}"
    routes[f"{base}/scanned/dependabot/alerts"] = [
        dependabot_alert(1, "open", "critical", 40, cve="CVE-KEV-1"),
        dependabot_alert(2, "open", "high", 3),
        dependabot_alert(3, "fixed", "high", 20, closed_days_ago=10),
        dependabot_alert(4, "dismissed", "low", 20, closed_days_ago=15, reason="tolerable_risk"),
    ]
    routes[f"{base}/scanned/dependency-graph/sbom"] = sbom("django", "requests")
    routes[f"{base}/scanned/automated-security-fixes"] = {"enabled": True, "paused": False}
    routes[f"{base}/off/dependabot/alerts"] = (403, {"message": "Dependabot alerts are disabled for this repository."})
    routes[f"{base}/off/dependency-graph/sbom"] = sbom("lodash")
    routes[f"{base}/off/automated-security-fixes"] = {"enabled": False, "paused": False}
    routes[f"{base}/graph-empty/dependabot/alerts"] = []  # measured: alerts on, manifests never parsed
    routes[f"{base}/graph-empty/dependency-graph/sbom"] = sbom()
    routes[f"{base}/graph-empty/automated-security-fixes"] = {"enabled": False, "paused": False}
    routes[f"{base}/graph-off/dependabot/alerts"] = []
    routes[f"{base}/graph-off/automated-security-fixes"] = {"enabled": False, "paused": False}  # sbom route absent: 404
    return routes


@pytest.fixture
def no_kev(monkeypatch):
    monkeypatch.setattr(MODS["dependabot_alerts"], "known_exploited", lambda client: {"CVE-KEV-1"})


def test_dependabot_coverage_and_alert_verdicts(fake, monkeypatch, tmp_path, no_kev):
    fake(dependabot_routes())
    code, ev, _ = run_fetcher("dependabot_alerts", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["repositories_alerts_disabled"] == ["off"]
    assert s["repositories_dependency_graph_empty"] == ["graph-empty"]
    assert s["repositories_dependency_graph_disabled"] == ["graph-off"]
    assert sorted(s["repositories_without_security_updates"]) == ["graph-empty", "graph-off", "off"]
    assert s["open_total"] == 2 and s["open_by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert s["open_older_than_days"]["30"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert s["open_known_exploited"] == 1
    assert s["fixed_total"] == 1 and s["median_days_to_fix"] == 10.0
    assert s["dismissed_by_reason"] == {"tolerable_risk": 1}
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["off"]["alerts"] == [] and by["off"]["alerts_enabled"] is False  # a disabled scanner, not a failure
    assert by["scanned"]["open_known_exploited"] == [1]


def test_an_unreachable_kev_catalog_fails_but_keeps_the_alerts(fake, monkeypatch, tmp_path):
    def broken(*a, **kw):
        raise requests.exceptions.ConnectionError("no route to cisa.gov")
    monkeypatch.setattr(MODS["dependabot_alerts"].requests, "get", broken)
    fake(dependabot_routes())
    code, ev, status = run_fetcher("dependabot_alerts", monkeypatch, tmp_path)
    assert code == 1 and "check_kev false" in status["error"]
    assert ev["summary"]["open_total"] == 2 and ev["summary"]["known_exploited_checked"] is False


def test_unauthorized_dependabot_read_is_a_failure_not_a_disabled_scanner(fake, monkeypatch, tmp_path, no_kev):
    routes = dependabot_routes()
    routes[f"repos/{ORG}/scanned/dependabot/alerts"] = (403, {"message": "You are not authorized to perform this operation."})
    fake(routes)
    code, ev, status = run_fetcher("dependabot_alerts", monkeypatch, tmp_path)
    assert code == 1 and status["code"] == "not_authorized"
    assert ev["summary"]["not_collected"] == ["scanned"] and "scanned" not in ev["summary"]["repositories_alerts_disabled"]


# --- code_scanning_alerts --------------------------------------------------------

def cs_alert(number, state, sev, created_days_ago, closed_days_ago=None, rule="py/sql-injection"):
    closed = None if closed_days_ago is None else ago(closed_days_ago)
    return {"number": number, "state": state, "created_at": ago(created_days_ago),
            "fixed_at": closed if state == "fixed" else None, "dismissed_at": closed if state == "dismissed" else None,
            "dismissed_reason": "false positive" if state == "dismissed" else None,
            "rule": {"id": rule, "severity": "error", "security_severity_level": sev},
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {"ref": "refs/heads/main", "location": {"path": "app.py"}}}


def cs_routes():
    names = ["scanned", "stale", "never", "ghas-off", "third-party"]
    routes = org_routes([repo(n) for n in names])
    b = f"repos/{ORG}"
    routes[f"{b}/scanned/code-scanning/default-setup"] = {"state": "configured", "languages": ["python"]}
    routes[f"{b}/scanned/code-scanning/analyses"] = [{"created_at": ago(1), "tool": {"name": "CodeQL"}}]
    routes[f"{b}/scanned/code-scanning/alerts"] = [cs_alert(1, "open", "high", 40), cs_alert(2, "open", None, 5,
                                                   rule="py/unused-import"),
                                                   cs_alert(3, "fixed", "critical", 30, 20), cs_alert(4, "dismissed", "low", 9, 8),
                                                   cs_alert(5, None, "high", 12)]
    routes[f"{b}/stale/code-scanning/default-setup"] = {"state": "configured", "languages": ["go"]}
    routes[f"{b}/stale/code-scanning/analyses"] = [{"created_at": ago(30), "tool": {"name": "CodeQL"}}]
    routes[f"{b}/stale/code-scanning/alerts"] = []
    routes[f"{b}/never/code-scanning/default-setup"] = {"state": "not-configured", "languages": []}
    routes[f"{b}/never/code-scanning/analyses"] = (404, {"message": "no analysis found"})
    routes[f"{b}/never/code-scanning/alerts"] = (404, {"message": "no analysis found"})
    for path in ("default-setup", "analyses", "alerts"):
        routes[f"{b}/ghas-off/code-scanning/{path}"] = (
            403, {"message": "Advanced Security must be enabled for this repository to use code scanning."})
    routes[f"{b}/third-party/code-scanning/default-setup"] = {"state": "not-configured", "languages": []}
    routes[f"{b}/third-party/code-scanning/analyses"] = [{"created_at": ago(2), "tool": {"name": "Trivy"}}]
    routes[f"{b}/third-party/code-scanning/alerts"] = [cs_alert(9, "open", "medium", 2, rule="CVE-2024-1")]
    return routes


def test_code_scanning_coverage_and_verdicts(fake, monkeypatch, tmp_path):
    fake(cs_routes())
    code, ev, _ = run_fetcher("code_scanning_alerts", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert sorted(s["repositories_not_analysed"]) == ["ghas-off", "never"]
    assert s["repositories_analysis_stale"] == ["stale"]
    assert s["tools"] == ["CodeQL", "Trivy"]  # uploaded SARIF counts, default setup or not
    assert s["open_total"] == 3 and s["open_by_security_severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 0}
    assert s["open_older_than_days"]["30"]["high"] == 1
    assert s["fixed_total"] == 1 and s["median_days_to_fix"] == 10.0 and s["dismissed_total"] == 1
    assert s["state_unknown_total"] == 1
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["ghas-off"]["code_scanning_available"] is False and by["ghas-off"]["default_setup"] == "disabled"
    assert by["third-party"]["default_setup"] == "not-configured" and by["third-party"]["analysed"] is True


# --- secret_scanning ----------------------------------------------------------------

def ss_alert(number, state="open", validity="inactive", bypassed=False, resolution=None, leaked_value="ghp_x"):
    return {"number": number, "state": state, "resolution": resolution, "secret_type": "github_personal_access_token",
            "secret_type_display_name": "GitHub Personal Access Token", "secret": leaked_value,
            "validity": validity, "publicly_leaked": False, "multi_repo": False,
            "push_protection_bypassed": bypassed,
            "push_protection_bypassed_by": {"login": "dev"} if bypassed else None,
            "created_at": ago(5), "resolved_at": ago(1) if state == "resolved" else None}


def sa(scanning="enabled", push="enabled"):
    return {"secret_scanning": {"status": scanning}, "secret_scanning_push_protection": {"status": push},
            "secret_scanning_non_provider_patterns": {"status": "disabled"},
            "secret_scanning_validity_checks": {"status": "disabled"}}


def ss_routes():
    repos = [repo("clean", security_and_analysis=sa()), repo("leaked", security_and_analysis=sa(push="disabled")),
             repo("off", security_and_analysis=sa("disabled", "disabled")), repo("outsider")]
    routes = org_routes(repos)
    b = f"repos/{ORG}"
    routes[f"{b}/clean/secret-scanning/alerts"] = [ss_alert(1, "resolved", resolution="revoked")]
    routes[f"{b}/leaked/secret-scanning/alerts"] = [ss_alert(2, bypassed=True), ss_alert(3, validity="active")]
    routes[f"{b}/off/secret-scanning/alerts"] = (404, {"message": "Secret scanning is disabled on this repository."})
    routes[f"{b}/outsider/secret-scanning/alerts"] = []
    return routes


def test_secret_scanning_verdicts(fake, monkeypatch, tmp_path):
    f = fake(ss_routes())
    code, ev, _ = run_fetcher("secret_scanning", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["repositories_scanning_disabled"] == ["off"]
    assert s["repositories_push_protection_disabled"] == ["leaked", "off"]
    assert s["settings_unreadable"] == ["outsider"]  # null, never "disabled"
    assert s["open_total"] == 2 and s["open_by_validity"] == {"active": 1, "inactive": 1, "unknown": 0}
    assert s["push_protection_bypasses"] == 1 and s["resolved_by_resolution"] == {"revoked": 1}
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["outsider"]["push_protection_enabled"] is None
    assert all(q.get("hide_secret") == "true" for p, q in f.calls if p.endswith("/secret-scanning/alerts"))


# --- org_security_settings ----------------------------------------------------------

def org_settings_routes(owner=True):
    repos = [repo("a", security_and_analysis=sa()), repo("b", security_and_analysis=sa(push="disabled")),
             repo("c")]
    routes = org_routes(repos)
    org = routes[f"orgs/{ORG}"]
    if owner:
        org.update({"two_factor_requirement_enabled": False, "default_repository_permission": "write",
                    "members_can_create_public_repositories": True,
                    "members_can_invite_outside_collaborators": True})
    routes[f"orgs/{ORG}/members"] = lambda q: (200, [{"login": "nofa"}]) if q.get("filter") == "2fa_disabled" \
        else (200, [{"login": "nofa"}, {"login": "ok"}])
    routes[f"orgs/{ORG}/actions/permissions"] = {"enabled_repositories": "all", "allowed_actions": "all",
                                                 "sha_pinning_required": False}
    routes[f"orgs/{ORG}/actions/permissions/workflow"] = {"default_workflow_permissions": "write",
                                                          "can_approve_pull_request_reviews": True}
    routes[f"orgs/{ORG}/code-security/configurations"] = [
        {"id": 1, "name": "GitHub recommended", "target_type": "global", "enforcement": "unenforced",
         "secret_scanning": "enabled"},
        {"id": 2, "name": "baseline", "target_type": "organization", "enforcement": "enforced",
         "secret_scanning": "enabled"}]
    routes[f"orgs/{ORG}/code-security/configurations/defaults"] = [
        {"default_for_new_repos": "all", "configuration": {"id": 2}}]
    routes[f"orgs/{ORG}/code-security/configurations/1/repositories"] = []  # measured: defined, attached to nothing
    routes[f"orgs/{ORG}/code-security/configurations/2/repositories"] = [
        {"status": "enforced", "repository": {"name": "a"}}, {"status": "failed", "repository": {"name": "b"}}]
    return routes


def test_org_security_settings_verdicts(fake, monkeypatch, tmp_path):
    fake(org_settings_routes())
    code, ev, _ = run_fetcher("org_security_settings", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["two_factor_required"] is False and s["members_without_two_factor"] == 1
    assert ev["members_without_two_factor"] == ["nofa"]
    assert s["actions_default_token_permissions"] == "write" and s["actions_can_approve_pull_requests"] is True
    assert s["repositories_without_security_configuration"] == ["b", "c"]  # failed attachment is not applied
    assert s["repositories_settings_unreadable"] == ["c"]
    assert s["repositories_secret_scanning_push_protection_off"] == ["b"]
    configs = {c["name"]: c for c in ev["security_configurations"]}
    assert configs["GitHub recommended"]["repositories"] == [] and configs["baseline"]["default_for_new_repos"] == "all"


def test_two_factor_is_unknown_to_a_non_owner(fake, monkeypatch, tmp_path):
    f = fake(org_settings_routes(owner=False))
    _, ev, _ = run_fetcher("org_security_settings", monkeypatch, tmp_path)
    assert ev["summary"]["two_factor_required"] is None and ev["summary"]["members_without_two_factor"] is None
    assert not any(q.get("filter") == "2fa_disabled" for _, q in f.calls)


# --- access_review --------------------------------------------------------------

def access_routes():
    routes = org_routes([repo("app"), repo("infra")])
    o = f"orgs/{ORG}"
    routes[f"{o}/members"] = lambda q: (200, [{"login": "boss"}]) if q.get("role") == "admin" \
        else (200, [{"login": "boss"}, {"login": "dev"}])
    routes[f"{o}/outside_collaborators"] = [{"login": "contractor"}]
    routes[f"{o}/invitations"] = [{"login": None, "email": "new.hire@example.com", "role": "direct_member",
                                   "created_at": ago(3), "inviter": {"login": "boss"}}]
    routes[f"{o}/teams"] = [{"slug": "platform", "privacy": "closed"}]
    routes[f"{o}/teams/platform/members"] = [{"login": "dev"}]
    b = f"repos/{ORG}"
    routes[f"{b}/app/collaborators"] = [{"login": "boss", "role_name": "admin"},
                                        {"login": "dev", "role_name": "admin"},
                                        {"login": "contractor", "role_name": "write"}]
    routes[f"{b}/app/teams"] = [{"slug": "platform", "permission": "admin"}]
    routes[f"{b}/infra/collaborators"] = [{"login": "boss", "permissions": {"admin": True}},
                                          {"login": "contractor", "permissions": {"pull": True}}]
    routes[f"{b}/infra/teams"] = [{"slug": "platform", "permission": "push"}]
    routes[f"{o}/organization-roles"] = {"total_count": 3, "roles": [
        {"id": 1, "name": "security_manager", "source": "Predefined", "base_role": None, "permissions": ["x"]},
        {"id": 2, "name": "all_repo_admin", "source": "Predefined", "base_role": "admin", "permissions": []},
        {"id": 3, "name": "all_repo_read", "source": "Predefined", "base_role": "read", "permissions": []}]}
    routes[f"{o}/organization-roles/1/users"] = [{"login": "sec", "assignment": "direct", "inherited_from": []}]
    routes[f"{o}/organization-roles/1/teams"] = []
    routes[f"{o}/organization-roles/2/users"] = [{"login": "dev", "assignment": "indirect",
                                                  "inherited_from": [{"slug": "platform"}]}]
    routes[f"{o}/organization-roles/2/teams"] = [{"slug": "platform", "assignment": "direct"}]
    routes[f"{o}/organization-roles/3/users"] = []
    routes[f"{o}/organization-roles/3/teams"] = []
    return routes


def test_organization_roles_and_who_holds_them(fake, monkeypatch, tmp_path):
    fake(access_routes())
    code, ev, _ = run_fetcher("access_review", monkeypatch, tmp_path)
    s = ev["summary"]
    assert code == 0 and s["organization_role_holders"] == {"all_repo_admin": ["dev"], "security_manager": ["sec"]}
    assert s["organization_wide_write_or_admin"] == ["dev"]
    admin = next(r for r in ev["organization_roles"] if r["role"] == "all_repo_admin")
    assert admin["users"] == [{"login": "dev", "assignment": "indirect", "via_teams": ["platform"]}]
    assert ev["metadata"]["organization_roles_available"] is True


def test_organization_roles_unreadable_or_switched_off(fake, monkeypatch, tmp_path):
    routes = access_routes()
    routes[f"orgs/{ORG}/organization-roles"] = (403, {"message": "Resource not accessible by personal access token"},
                                                {"X-Accepted-GitHub-Permissions": "organization_custom_org_roles=read"})
    fake(routes)
    code, ev, status = run_fetcher("access_review", monkeypatch, tmp_path)
    assert code == 1 and "organization_custom_org_roles=read" in status["error"]
    assert ev["summary"]["organization_role_holders"] is None and ev["summary"]["owners"] == ["boss"]
    f = fake(routes)
    code, ev, _ = run_fetcher("access_review", monkeypatch, tmp_path, GITHUB_INCLUDE_ORGANIZATION_ROLES="false")
    assert code == 0 and not any("organization-roles" in p for p, _ in f.calls)
    routes[f"orgs/{ORG}/organization-roles"] = (404, {"message": "Upgrade to GitHub Enterprise to use this feature"})
    fake(routes)
    monkeypatch.delenv("GITHUB_INCLUDE_ORGANIZATION_ROLES")
    code, ev, _ = run_fetcher("access_review", monkeypatch, tmp_path)
    assert code == 0 and ev["metadata"]["organization_roles_available"] is False


def test_access_review_verdicts(fake, monkeypatch, tmp_path):
    fake(access_routes())
    code, ev, _ = run_fetcher("access_review", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["owners"] == ["boss"] and s["members_total"] == 2
    assert s["outside_collaborators_with_write"] == ["contractor"]  # write on app, read-only on infra
    assert s["repositories_with_non_owner_admins"] == ["app"]  # owners are excluded
    assert s["teams_with_admin"] == ["platform"] and ev["teams"][0]["write_on"] == ["infra"]
    assert ev["pending_invitations"][0]["email_domain"] == "example.com"
    assert "new.hire" not in json.dumps(ev)  # the address itself is never stored


def test_access_review_needs_owner_reads(fake, monkeypatch, tmp_path):
    routes = access_routes()
    routes[f"orgs/{ORG}/outside_collaborators"] = (403, {"message": "You must be an owner of this organization to list outside collaborators."},
                                                   {"X-Accepted-GitHub-Permissions": "members=read"})
    fake(routes)
    code, ev, status = run_fetcher("access_review", monkeypatch, tmp_path)
    assert code == 1 and "members=read" in status["error"] and "repositories" not in ev


# --- non_user_credentials ------------------------------------------------------------

def credential_routes(pats=None):
    routes = org_routes([repo("app"), repo("site")])
    routes[f"orgs/{ORG}"]["deploy_keys_enabled_for_repositories"] = True
    o, b = f"orgs/{ORG}", f"repos/{ORG}"
    routes[f"{o}/installations"] = lambda q: (200, {"total_count": 2, "installations": [
        {"app_slug": "ci-bot", "repository_selection": "all", "permissions": {"contents": "write", "metadata": "read"}},
        {"app_slug": "reader", "repository_selection": "selected", "permissions": {"metadata": "read"}}]})
    routes[f"{o}/actions/secrets"] = lambda q: (200, {"total_count": 1, "secrets": [
        {"name": "ORG_OLD", "updated_at": ago(400)}]})
    routes[f"{o}/hooks"] = [{"id": 1, "active": True, "events": ["push"],
                             "config": {"url": "https://hooks.example.com/x?token=SHOULDNOTLEAK", "insecure_ssl": "0",
                                        "secret": "********"}}]
    routes[f"{o}/personal-access-tokens"] = pats if pats is not None else [
        {"id": 5, "owner": {"login": "dev"}, "repository_selection": "all", "permissions": {},
         "token_expired": False, "token_expires_at": None, "token_last_used_at": ago(200),
         "access_granted_at": ago(300)}]
    routes[f"{b}/app/keys"] = [{"id": 1, "title": "deploy-rw", "read_only": False, "created_at": ago(30)}]
    routes[f"{b}/site/keys"] = [{"id": 2, "title": "deploy-ro", "read_only": True, "created_at": ago(3)}]
    routes[f"{b}/app/actions/secrets"] = lambda q: (200, {"total_count": 1, "secrets": [
        {"name": "NEW", "updated_at": ago(2)}]})
    routes[f"{b}/site/actions/secrets"] = lambda q: (200, {"total_count": 0, "secrets": []})
    routes[f"{b}/app/hooks"] = [{"id": 9, "active": True, "events": ["push"],
                                 "config": {"url": "https://ci.invalid/h", "insecure_ssl": "1"}}]
    routes[f"{b}/site/hooks"] = []
    return routes


def test_non_user_credential_verdicts(fake, monkeypatch, tmp_path):
    fake(credential_routes())
    code, ev, _ = run_fetcher("non_user_credentials", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["deploy_keys_allowed"] is True and s["deploy_keys_total"] == 2 and s["write_deploy_keys"] == ["app:deploy-rw"]
    assert s["apps_with_write"] == ["ci-bot"] and s["apps_on_all_repositories"] == ["ci-bot"]
    assert s["fine_grained_tokens_without_expiry"] == 1 and s["fine_grained_tokens_unused"] == 1
    assert s["actions_secrets_total"] == 2 and s["actions_secrets_older_than_max"] == ["org:ORG_OLD"]
    assert s["webhooks_insecure_ssl"] == 1 and s["webhooks_without_secret"] == 1
    assert "SHOULDNOTLEAK" not in json.dumps(ev)  # webhook URLs are reduced to their host


def test_a_missing_key_access_or_tls_setting_is_unknown_not_safe(fake, monkeypatch, tmp_path):
    routes = credential_routes()
    routes[f"repos/{ORG}/app/keys"] = [{"id": 9, "title": "mystery", "read_only": None, "created_at": ago(1)}]
    routes[f"repos/{ORG}/app/hooks"] = [{"id": 5, "active": True, "config": {"url": "https://h.test/x"}}]
    fake(routes)
    _, ev, _ = run_fetcher("non_user_credentials", monkeypatch, tmp_path)
    s = ev["summary"]
    assert s["deploy_keys_access_unknown"] == ["app:mystery"] and "app:mystery" not in s["write_deploy_keys"]
    assert s["webhooks_tls_unknown"] >= 1


def test_a_personal_token_never_asks_for_the_apps_only_token_list(fake, monkeypatch, tmp_path):
    f = fake(credential_routes())
    code, ev, _ = run_fetcher("non_user_credentials", monkeypatch, tmp_path, GITHUB_TOKEN="github_pat_test")
    assert code == 0 and ev["summary"]["fine_grained_tokens"] is None and ev["fine_grained_tokens"] is None
    assert ev["metadata"]["fine_grained_tokens_readable"] is False
    assert "GitHub Apps only" in ev["metadata"]["fine_grained_tokens_unreadable_because"]
    assert f"orgs/{ORG}/personal-access-tokens" not in {p for p, _ in f.calls}


# --- optional or nullable fields --------------------


def test_a_required_check_that_finished_without_a_conclusion_did_not_pass(fake, monkeypatch, tmp_path):
    runs = {1: [{"name": "ci", "status": "completed", "conclusion": None, "completed_at": ago(2)}]}
    fake(pr_routes([pr(1, 1)], {}, runs, rules=enforced([CHECKS_RULE], 1)))
    _, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    rec = ev["repositories"][0]["pull_requests"][0]
    assert rec["checks"] == {"ci": "unknown"} and rec["checks_unknown"] == ["ci"]
    assert rec["required_checks_failed"] == ["ci"]


def test_a_bypass_is_seen_through_either_field(fake, monkeypatch, tmp_path):
    routes = ss_routes()
    alert = ss_alert(7)
    alert.update({"push_protection_bypassed": None, "push_protection_bypassed_by": {"login": "dev"}})
    routes[f"repos/{ORG}/leaked/secret-scanning/alerts"] = [alert]
    fake(routes)
    _, ev, _ = run_fetcher("secret_scanning", monkeypatch, tmp_path)
    assert ev["summary"]["push_protection_bypasses"] == 1


# --- found by mutation testing (mutate_all.py): paths no test exercised -----------------------

def test_every_rule_type_and_classic_flag_reaches_the_requirements():
    bp = MODS["branch_protection"]
    rules = [PR_RULE, CHECKS_RULE, NFF_RULE, {"type": "deletion"}, {"type": "required_signatures"},
             {"type": "required_linear_history"},
             {"type": "workflows", "parameters": {"workflows": [{"path": ".github/workflows/sec.yml"}]}},
             {"type": "code_scanning", "parameters": {"code_scanning_tools": [{"tool": "CodeQL"}, {}]}},
             {"type": "pull_request", "parameters": {"required_approving_review_count": 2,
                                                     "require_code_owner_review": True}}]
    req = bp.from_rules(rules)
    assert req["approvals"] == 2 and req["code_owner_review"] is True and req["dismiss_stale_reviews"] is True
    assert req["status_checks"] == ["ci"] and req["strict_status_checks"] is False
    assert (req["blocks_force_push"], req["blocks_deletion"], req["signed_commits"], req["linear_history"]) == \
        (True, True, True, True)
    assert req["required_workflows"] == 1 and req["code_scanning_tools"] == ["CodeQL"]
    classic = bp.from_classic({"required_status_checks": {"strict": True, "contexts": ["a"], "checks": [{"context": "b"}]},
                               "allow_force_pushes": {"enabled": True}, "allow_deletions": {"enabled": False},
                               "required_linear_history": {"enabled": False}})
    assert classic == {"status_checks": ["a", "b"], "strict_status_checks": True, "blocks_deletion": True}
    assert "pull_request" not in bp.from_classic({}) and bp.from_rules([]) == {"rule_types": []}
    merged = bp.merge({"approvals": 1, "signed_commits": False, "status_checks": ["a"], "required_workflows": 1},
                      {"approvals": 3, "signed_commits": True, "status_checks": ["b"], "required_workflows": 2})
    assert merged == {"approvals": 3, "signed_commits": True, "status_checks": ["a", "b"], "required_workflows": 3}


def test_org_rulesets_target_repositories_by_name():
    t = MODS["branch_protection"].ruleset_targets_branch
    rs = {"target": "branch", "conditions": {"repository_name": {"include": ["api-*"], "exclude": ["api-legacy"]},
                                             "ref_name": {"include": ["~DEFAULT_BRANCH"]}}}
    assert t(rs, "api-core", "main") is True
    assert t(rs, "api-legacy", "main") is False and t(rs, "web", "main") is False
    assert t({**rs, "target": "tag"}, "api-core", "main") is False
    assert t({"conditions": {"repository_property": {}}}, "api-core", "main") is None


def test_classic_protection_and_ruleset_details_are_reported(fake, monkeypatch, tmp_path):
    routes = sandbox_routes()
    routes[f"repos/{ORG}/classic-only/branches/main/protection"]["required_pull_request_reviews"][
        "bypass_pull_request_allowances"] = {"users": [{"login": "boss"}], "teams": []}
    routes[f"repos/{ORG}/org-bypass/rulesets/9"] = None  # detail unreadable falls back to the list entry
    fake(routes)
    _, ev, _ = run_fetcher("branch_protection", monkeypatch, tmp_path)
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["classic-only"]["classic_protection"] == {"enforce_admins": False, "bypass_pull_request_allowances": True}
    assert by["classic-only"]["requirements"]["blocks_force_push"] is True
    assert by["org-bypass"]["rulesets"][0]["name"] == "org-baseline"
    assert ev["metadata"]["org_rulesets_available"] is False and by["protected"]["empty"] is False


FAILING = (500, {"message": "Server Error"})


@pytest.mark.parametrize("fetcher,path", [
    ("branch_protection", "repos/acme/app/rules/branches/main"),
    ("pull_request_checks", "repos/acme/app/pulls"),
    ("pull_request_checks", "repos/acme/app/commits"),
    ("pull_request_checks", "repos/acme/app/pulls/1/reviews"),
    ("secret_scanning", "repos/acme/app/secret-scanning/alerts"),
    ("non_user_credentials", "repos/acme/app/keys"),
    ("access_review", "repos/acme/app/collaborators"),
    ("code_scanning_alerts", "repos/acme/app/code-scanning/alerts"),
])
def test_one_repository_failing_is_not_collected_and_the_rest_are(fake, monkeypatch, tmp_path, fetcher, path):
    routes = one_failing_routes(fetcher)
    routes[path] = FAILING
    fake(routes)
    code, ev, status = run_fetcher(fetcher, monkeypatch, tmp_path)
    assert code == 1 and status["code"] == "internal_error"
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["app"]["collected"] is False and by["site"]["collected"] is True
    assert ev["summary"]["not_collected"] == ["app"]


def one_failing_routes(fetcher):
    """Two healthy repositories (app, site) with every endpoint the fetcher reads."""
    routes = org_routes([repo("app"), repo("site")])
    for n in ("app", "site"):
        b = f"repos/{ORG}/{n}"
        routes.update({f"{b}/rules/branches/main": [], f"{b}/rulesets": [], f"{b}/branches/main/protection": NOT_PROTECTED,
                       f"{b}/pulls": [pr(1, 1)], f"{b}/pulls/1/reviews": [], f"{b}/commits": [],
                       f"{b}/commits/h1/check-runs": lambda q: (200, {"total_count": 0, "check_runs": []}),
                       f"{b}/commits/h1/status": {"statuses": []},
                       f"{b}/secret-scanning/alerts": [], f"{b}/keys": [], f"{b}/hooks": [],
                       f"{b}/actions/secrets": lambda q: (200, {"total_count": 0, "secrets": []}),
                       f"{b}/collaborators": [], f"{b}/teams": [],
                       f"{b}/code-scanning/default-setup": {"state": "configured"},
                       f"{b}/code-scanning/analyses": [{"created_at": ago(1), "tool": {"name": "CodeQL"}}],
                       f"{b}/code-scanning/alerts": []})
    o = f"orgs/{ORG}"
    routes.update({f"{o}/members": [{"login": "boss"}], f"{o}/outside_collaborators": [], f"{o}/invitations": [],
                   f"{o}/teams": [], f"{o}/installations": lambda q: (200, {"installations": []}),
                   f"{o}/actions/secrets": lambda q: (200, {"secrets": []}), f"{o}/hooks": [],
                   f"{o}/personal-access-tokens": [], f"{o}/organization-roles": {"roles": []}})
    return routes


def test_review_order_bot_logins_and_window_edges():
    pc = MODS["pull_request_checks"]
    merged = time.time() - 86400
    late, early = review("x", "APPROVED", 2), review("x", "CHANGES_REQUESTED", 3)
    assert pc.approvals([late, early], "dev", merged, "h1")[0]["reviewer"] == "x"  # sorted by time, not list order
    assert pc.is_bot({"login": "renovate[bot]", "type": "User"}) and not pc.is_bot({"login": "dev", "type": "User"})
    assert not pc.is_bot(None)
    out = pc.check_outcomes([], [{"context": "legacy", "state": "success", "updated_at": ago(1)},
                                 {"context": "legacy", "state": "failure", "updated_at": ago(2)}])
    assert out == {"status:legacy": "success"}  # statuses sorted by time; the latest wins


def test_a_pr_merged_before_the_window_is_excluded_even_if_updated_inside_it(fake, monkeypatch, tmp_path):
    pulls = [pr(1, 2), pr(2, 60, updated_days_ago=1), pr(3, 5)]
    commits = [{"sha": "d9", "commit": {"message": "x" * 300, "committer": {"date": ago(1)},
                                        "author": {"name": "Local Name"}}, "author": None}]
    fake(pr_routes(pulls, {}, {}, commits=commits, associated={"d9": []}))
    _, ev, _ = run_fetcher("pull_request_checks", monkeypatch, tmp_path)
    r = ev["repositories"][0]
    assert [p["number"] for p in r["pull_requests"]] == [1, 3]  # newest merge first, PR 2 outside the window
    push = r["direct_pushes"][0]
    assert push["author"] == "Local Name" and len(push["message"]) == 120


def test_per_repository_alert_fields(fake, monkeypatch, tmp_path):
    fake(cs_routes())
    _, ev, _ = run_fetcher("code_scanning_alerts", monkeypatch, tmp_path)
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["scanned"]["open_by_security_severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 0}
    assert by["scanned"]["code_scanning_available"] is True and by["scanned"]["default_setup"] == "configured"
    assert by["scanned"]["analysis_current"] is True and by["stale"]["last_analysis_age_days"] >= 29
    assert ev["summary"]["open_older_than_days"]["7"]["medium"] == 0  # the Trivy alert is 2 days old
    fixed = [a for a in by["scanned"]["alerts"] if a["state"] == "fixed"][0]
    assert fixed["age_days"] is None and fixed["days_to_close"] == 10.0


def test_non_provider_secret_alerts_are_requested_by_name(fake, monkeypatch, tmp_path):
    # GitHub returns provider patterns only unless secret_type names the generic ones.
    routes = ss_routes()
    generic = dict(ss_alert(4), secret_type="rsa_private_key")
    routes[f"repos/{ORG}/clean/secret-scanning/alerts"] = lambda q: (
        [generic] if "rsa_private_key" in q.get("secret_type", "") else [ss_alert(1, "resolved", resolution="revoked")])
    fake(routes)
    _, ev, _ = run_fetcher("secret_scanning", monkeypatch, tmp_path)
    clean = {r["repository"]: r for r in ev["repositories"]}["clean"]
    assert sorted(a["number"] for a in clean["alerts"]) == [1, 4] and clean["open_alerts"] == 1


def test_a_plan_without_secret_scanning_is_not_scanning(fake, monkeypatch, tmp_path):
    routes = ss_routes()
    routes[f"repos/{ORG}/clean/secret-scanning/alerts"] = (403, {"message": "Upgrade to GitHub Team to enable this feature."})
    fake(routes)
    _, ev, _ = run_fetcher("secret_scanning", monkeypatch, tmp_path)
    assert {r["repository"]: r for r in ev["repositories"]}["clean"]["scanning_enabled"] is False


def test_per_repository_secret_fields(fake, monkeypatch, tmp_path):
    fake(ss_routes())
    _, ev, _ = run_fetcher("secret_scanning", monkeypatch, tmp_path)
    by = {r["repository"]: r for r in ev["repositories"]}
    assert by["leaked"]["open_alerts"] == 2 and by["leaked"]["open_active"] == [3]
    assert by["clean"]["push_protection_enabled"] is True and by["leaked"]["push_protection_enabled"] is False
    resolved = by["clean"]["alerts"][0]
    assert resolved["age_days"] is None and resolved["days_to_resolve"] == 4.0
    assert ev["summary"]["oldest_open_days"] == 5.0


def test_credential_record_fields(fake, monkeypatch, tmp_path):
    fake(credential_routes())
    _, ev, _ = run_fetcher("non_user_credentials", monkeypatch, tmp_path)
    hooks = {h["scope"]: h for h in ev["webhooks"]}
    assert hooks["organization"]["url_host"] == "hooks.example.com" and hooks["organization"]["has_secret"] is True
    assert hooks["app"]["insecure_ssl"] is True and hooks["app"]["has_secret"] is False
    assert ev["apps"][0]["write_permissions"] == ["contents"] and ev["fine_grained_tokens"][0]["owner"] == "dev"
    assert ev["summary"]["deploy_keys_allowed"] is True


def test_webhook_host_drops_credentials_in_the_url(fake, monkeypatch, tmp_path):
    routes = credential_routes()
    hook = routes[f"orgs/{ORG}/hooks"][0]
    hook["config"]["url"] = "https://user:s3cret@hooks.example.com:8443/path"
    fake(routes)
    _, ev, _ = run_fetcher("non_user_credentials", monkeypatch, tmp_path)
    assert "s3cret" not in json.dumps(ev)
    assert {h["scope"]: h for h in ev["webhooks"]}["organization"]["url_host"] == "hooks.example.com"


def test_access_record_fields(fake, monkeypatch, tmp_path):
    routes = access_routes()
    routes[f"repos/{ORG}/infra/collaborators"].append({"login": "ci", "type": "Bot", "permissions": None})
    routes[f"orgs/{ORG}/invitations"].append({"login": "ghost", "email": None, "role": "admin"})
    routes[f"orgs/{ORG}/teams/platform/members"] = FAILING
    fake(routes)
    code, ev, _ = run_fetcher("access_review", monkeypatch, tmp_path)
    infra = next(r for r in ev["repositories"] if r["repository"] == "infra")
    assert infra["outside_collaborators"] == [{"login": "contractor", "role": "pull"}]
    assert ev["pending_invitations"][1]["email_domain"] is None
    assert code == 1 and ev["teams"][0]["members"] is None  # unreadable, not empty


def sequence(*responses):
    it = iter(responses)
    return lambda q: next(it)


def test_server_errors_and_dropped_connections_are_retried_then_succeed(fake, monkeypatch):
    for status in (500, 502, 503, 504):
        client = client_for(fake, {"x": sequence((status, {"message": "oops"}), (200, {"ok": True}))})
        assert client.read("x") == (None, {"ok": True}) and client.failures == []
    calls = {"n": 0}

    def flaky(url, params=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.exceptions.ConnectionError("reset")
        return response(200, {"ok": True})
    client = client_for(fake, {})
    monkeypatch.setattr(client.session, "get", flaky)
    assert client.read("x") == (None, {"ok": True}) and calls["n"] == 2


def test_errors_that_never_clear_fail_with_the_right_code(fake, monkeypatch):
    client = client_for(fake, {"x": (502, {"message": "Bad Gateway"})})
    assert client.read("x")[0] == "failed" and client.codes == ["internal_error"]
    client = client_for(fake, {})
    monkeypatch.setattr(client.session, "get",
                        lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ConnectionError("down")))
    assert client.read("x")[0] == "failed" and client.codes == ["target_unreachable"]
    assert "ConnectionError" in client.failures[0]["message"]
    client = client_for(fake, {"x": (401, {"message": "Bad credentials"})})
    client.read("x")
    assert client.codes == ["auth_failed"]


def test_secondary_rate_limits_are_honoured(fake):
    # GitHub's secondary limit: 403 with Retry-After, and a primary limit with only a reset time.
    client = client_for(fake, {"x": sequence((403, {"message": "You have exceeded a secondary rate limit"},
                                              {"Retry-After": "3"}), (200, {"ok": 1}))})
    assert client.read("x") == (None, {"ok": 1}) and fake.holder["slept"] == [3]
    fake.holder["slept"].clear()
    client = client_for(fake, {"x": sequence((429, {"message": "API rate limit exceeded"},
                                              {"X-RateLimit-Remaining": "0",
                                               "X-RateLimit-Reset": str(int(time.time()) + 5)}), (200, {"ok": 2}))})
    assert client.read("x") == (None, {"ok": 2}) and 0 < fake.holder["slept"][0] <= 5
    assert client.rate["limit"] == 5000 and client.rate["remaining"] == 4999


def test_empty_and_unparseable_bodies(fake):
    client = client_for(fake, {"empty": (204, None)})
    assert client.read("empty") == (None, None)

    class Html(FakeGitHub):
        def get(self, url, params=None, timeout=None):
            resp = response(502 if "err" in url else 200, None, url=url)
            resp._content = b"<html>Bad Gateway</html>"
            resp.headers["Content-Type"] = "text/html"
            return resp
    client = gc.GitHubClient(API, "t")
    client.session = Html({})
    assert client.read("ok")[0] == "failed" and client.failures[0]["type"] == "InvalidJSON"
    client.read("err")
    assert "<html>Bad Gateway</html>" in client.failures[1]["message"]
    assert client.paginate("ok")[0] == "failed" and client.failures[2]["type"] == "InvalidJSON"


def test_lookup_and_get_on_states(fake):
    client = client_for(fake, {"gone": (404, {"message": "Not Found"}), "boom": (500, {"message": "x"}),
                               "off": (403, {"message": "Dependabot alerts are disabled for this repository."}),
                               "obj": {"a": 1}, "shape": {"not": "a list"}})
    assert client.lookup("gone") == (False, None) and client.failures == []
    assert client.lookup("boom") == (False, None) and client.failures[0]["type"] == "HTTP 500"
    assert client.lookup("obj") == (True, {"a": 1})
    assert client.get("off") is None and client.failures[-1]["type"] == "UnexpectedState"
    assert client.paginate_required("off") is None and client.failures[-1]["type"] == "UnexpectedState"
    assert client.paginate("shape")[0] == "failed" and client.failures[-1]["type"] == "UnexpectedShape"


def test_private_repositories_count_toward_completeness(fake):
    routes = org_routes([repo("a"), repo("b")], public=1)
    routes[f"orgs/{ORG}"]["total_private_repos"] = 2  # 3 exist, 2 listed: the token sees only some private ones
    client = client_for(fake, routes)
    gc.list_repos(client, client.get(f"orgs/{ORG}"), [], False)
    assert client.failures[0]["type"] == "IncompleteCollection" and "reports 3" in client.failures[0]["message"]


def test_enterprise_server_evidence_names_its_host(fake, monkeypatch, tmp_path):
    fake(sandbox_routes())
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3")
    run_fetcher("branch_protection", monkeypatch, tmp_path, GITHUB_API_URL="https://ghe.example.com/api/v3")
    assert (tmp_path / "github_branch_protection_ghe_example_com_acme.json").exists()


def test_many_failures_are_summarised(fake, monkeypatch, tmp_path):
    routes = sandbox_routes()
    for n in ("protected", "disabled-rules", "evaluate-rules", "unprotected", "classic-only", "org-bypass"):
        routes[f"repos/{ORG}/{n}/rules/branches/main"] = FAILING
        routes[f"repos/{ORG}/{n}/rulesets"] = FAILING
    fake(routes)
    code, _, status = run_fetcher("branch_protection", monkeypatch, tmp_path)
    assert code == 1 and status["error"].startswith("12 collection failure(s)") and "(+2 more)" in status["error"]


def test_remaining_requirement_flags():
    bp = MODS["branch_protection"]
    strict = {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": True,
                                                               "required_status_checks": []}}
    assert bp.from_rules([PR_RULE, strict]) == {"rule_types": ["pull_request", "required_status_checks"],
                                                "pull_request": True, "approvals": 1, "code_owner_review": False,
                                                "dismiss_stale_reviews": True, "last_push_approval": False,
                                                "status_checks": [], "strict_status_checks": True}
    classic = bp.from_classic({"required_pull_request_reviews": {}, "required_linear_history": {"enabled": True}})
    assert classic["pull_request"] is True and classic["linear_history"] is True and classic["approvals"] == 0
    assert bp.merge({}, {"signed_commits": False}) == {"signed_commits": False}


# Answers from Ruby's File.fnmatch(FNM_PATHNAME), which reproduces GitHub's measured table; the matcher was then
# fuzzed against Ruby on 6 million random valid refs and patterns with 0 disagreements.
@pytest.mark.parametrize("pattern,ref,expected", [
    ("refs/heads/-**/a", "refs/heads/-9/x/a", False),      # ** is * unless it is a whole segment before /
    ("refs/heads/?**/*", "refs/heads/x/y/z", False),       # so ?**/* spans exactly two segments
    ("refs/heads/?**/*", "refs/heads/x/y", True),
    ("refs/heads/****/", "refs/heads/a", False),
    ("refs/heads/[ab]x", "refs/heads/bx", True),
    ("refs/heads/[!a]x", "refs/heads/ax", False),
    ("refs/heads/[a-c]", "refs/heads/b", True),
    ("refs/heads/[!a]", "refs/heads/x/y", False),          # a class never matches /
    ("refs/heads/[]a]", "refs/heads/a", False),            # [] is an empty class: matches nothing
    ("refs/heads/[!]]", "refs/heads/x]", True),            # [!] is any one character
    ("refs/heads/[b-a]", "refs/heads/a", True),            # a reversed range matches its endpoints
    ("refs/heads/[b-a]", "refs/heads/b", True),
    ("refs/heads/[z-a]", "refs/heads/m", False),
    ("refs/heads/[a-]", "refs/heads/-", True),
    ("refs/heads/[\\]]", "refs/heads/]", True),
    ("refs/heads/a[", "refs/heads/a[", False),             # an unclosed [ matches nothing
    ("refs/heads/{a,b}", "refs/heads/a", False),           # braces are literal without FNM_EXTGLOB
])
def test_glob_agrees_with_ruby_fnmatch(pattern, ref, expected):
    assert gc.ref_matches(pattern, ref, "main") is expected


# Backslash escapes, answered by Ruby 4.0 (File.fnmatch, FNM_PATHNAME). Git refs cannot contain a backslash, so only
# the pattern side matters; a lone trailing backslash is dropped (the fuzz missed it until its tokens included one).
@pytest.mark.parametrize("pattern,text,expected", [
    ('a\\*b', 'a*b', True),
    ('a\\*b', 'axb', False),
    ('a\\', 'a\\', False),
    ('a\\', 'a', True),
    ('\\?', '?', True),
    ('\\?', 'x', False),
    ('x\\[y', 'x[y', True),
    ('[\\]]', ']', True),
    ('[\\]]', '\\', False),
    ('[a\\-z]', '-', True),
    ('[a\\-z]', 'm', False),
    ('[a\\-z]', 'z', True),
    ('[\\a-c]', 'b', True),
    ('[\\a-c]', '\\', False),
    ('[a-\\c]', 'b', True),
    ('[a-\\c]', '\\', False),
    ('[\\a-\\c]', 'b', True),
    ('[\\a-\\c]', 'd', False),
    ('[!\\]]', ']', False),
    ('[!\\]]', 'x', True),
    ('[a\\]', 'a', False),
    ('[a\\]', '\\', False),
    ('[a\\]', ']', False),
    ('[\\-a]', '-', True),
    ('[\\-a]', 'b', False),
    ('[x-\\]', 'x', False),
    ('[x-\\]', '-', False),
    ('[x-\\]', '\\', False),
    ('[a-\\]', 'a', False),
    ('[a-\\]', 'b', False),
    ('refs/heads/re\\lease', 'refs/heads/release', True),
    ('refs/heads/[\\/]', 'refs/heads//', False),
    ('\\', '', True),
    ('\\', '\\', False),
    ('a\\b\\', 'ab', True),
    ('a\\/b', 'a/b', True),
    ('*\\', 'abc', True),
    ('*\\', 'abc\\', True),
    ('a\\\\', 'a\\', True),
    ('a\\\\', 'a', False),
    ('**/\\', 'x/', True),
    ('**/\\', 'x', False),
    ('[a-cx]', 'x', True),
    ('[a-cx]', 'b', True),
    ('[a-\\cx]', 'x', True),
    ('[a-\\cx]', 'b', True),
    ('[\\a-cx]', 'x', True),
    ('[a-c\\x]', 'x', True),
    ('[a-\\c\\x]', 'x', True),
    ('[a-\\c-]', '-', True),
    ('[a-\\]x]', 'x', True),
    ('a/***/b', 'a/x/y/b', False),
    ('a/***/b', 'a/x/b', True),
    ('a/**/b', 'a/x/y/b', True),
    ('***/b', 'x/y/b', False),
])
def test_glob_escapes_agree_with_ruby_fnmatch(pattern, text, expected):
    assert bool(gc.glob_regex(pattern).match(text)) is expected


# --- repository_inventory ----------------------------------------------------------

from framework import inventory as framework_inventory  # noqa: E402


def inv_routes(repos=None, schema=None, values=None):
    repos = repos if repos is not None else [repo("app", id=1, html_url="https://github.test/acme/app",
                                                  full_name="acme/app", topics=["web", "pci"],
                                                  security_and_analysis={"secret_scanning": {"status": "enabled"},
                                                                         "dependabot_security_updates":
                                                                             {"status": "disabled"}}),
                                             repo("site", id=2, visibility="private")]
    routes = org_routes(repos)
    routes[f"orgs/{ORG}/properties/schema"] = schema if schema is not None else [
        {"property_name": "environment"}, {"property_name": "owners"}]
    routes[f"orgs/{ORG}/properties/values"] = values if values is not None else [
        {"repository_id": 1, "repository_name": "app",
         "properties": [{"property_name": "environment", "value": "production"},
                        {"property_name": "owners", "value": ["web-team", "sec"]},
                        {"property_name": "deleted-since", "value": "x"}]}]
    return routes


def test_inventory_records_one_per_repository_with_flat_fields(fake, monkeypatch, tmp_path):
    fake(inv_routes())
    code, ev, _ = run_fetcher("repository_inventory", monkeypatch, tmp_path)
    assert code == 0 and framework_inventory.check(ev, code)["complete"] is True
    app, site = ev["data"]
    assert app["unique_asset_identifier"] == f"{API}/repositories/1" and app["public"] is True
    assert app["topics"] == "web, pci" and app["secret_scanning"] is True and app["dependabot_security_updates"] is False
    assert app["advanced_security"] is None  # absent from the response: unknown, not off
    assert app["property_environment"] == "production" and app["property_owners"] == "web-team, sec"
    assert "property_deleted-since" not in app  # a value for a property the schema no longer defines
    assert site["property_environment"] is None and site["public"] is False
    assert site["security_settings_readable"] is False and site["secret_scanning"] is None
    assert set(app) == set(site)  # one pipeline mapping holds for every record
    assert ev["record_count"] == 2 and ev["summary"]["by_visibility"] == {"private": 1, "public": 1}


def test_an_unknown_visibility_is_counted_as_unknown(fake, monkeypatch, tmp_path):
    fake(inv_routes(repos=[repo("app", id=1, visibility=None)]))
    _, ev, _ = run_fetcher("repository_inventory", monkeypatch, tmp_path)
    assert ev["summary"]["by_visibility"] == {"unknown": 1} and ev["data"][0]["public"] is None


def test_custom_properties_on_a_plan_without_them_are_absent_not_a_failure(fake, monkeypatch, tmp_path):
    routes = inv_routes()
    routes[f"orgs/{ORG}/properties/schema"] = (404, {"message": "Upgrade to GitHub Team to use this feature"})
    fake(routes)
    code, ev, _ = run_fetcher("repository_inventory", monkeypatch, tmp_path)
    assert code == 0 and ev["metadata"]["custom_properties_available"] is False
    assert not any(k.startswith("property_") for k in ev["data"][0])


# --- actions_security ------------------------------------------------------------

SHA = "a" * 40
SAFE_WORKFLOW = f"""name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
      - run: make test
"""
RISKY_WORKFLOW = """name: triage
on:
  pull_request_target:
    types: [opened]
permissions: write-all
jobs:
  label:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: docker://alpine:3.20
      - run: echo "${{ github.event.pull_request.title }}"
      - uses: actions/github-script@v7
        with:
          script: console.log("${{ github.event.issue.body }}")
  call:
    uses: other-org/shared/.github/workflows/deploy.yml@main
    secrets: inherit
"""
OIDC_WORKFLOW = f"""on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: ./.github/actions/local
      - uses: docker://alpine@sha256:{"b" * 64}
      - uses: aws-actions/configure-aws-credentials@{SHA}
"""


def actions_routes(files=None, repo_perms=None, org_perms=None, runners=None):
    routes = org_routes([repo("app"), repo("site", visibility="private")])
    o = f"orgs/{ORG}"
    routes.update({
        f"{o}/actions/permissions": org_perms or {"enabled_repositories": "all", "allowed_actions": "all",
                                                  "sha_pinning_required": False},
        f"{o}/actions/permissions/workflow": {"default_workflow_permissions": "write",
                                              "can_approve_pull_request_reviews": True},
        f"{o}/actions/permissions/fork-pr-contributor-approval": {"approval_policy": "first_time_contributors"},
        f"{o}/actions/permissions/fork-pr-workflows-private-repos": {"run_workflows_from_fork_pull_requests": False},
        f"{o}/actions/permissions/artifact-and-log-retention": {"days": 90, "maximum_allowed_days": 400},
        f"{o}/actions/permissions/self-hosted-runners": {"enabled_repositories": "all"},
        f"{o}/actions/runners": lambda q: (200, {"total_count": 0, "runners": []}),
    })
    for n in ("app", "site"):
        b = f"repos/{ORG}/{n}"
        routes.update({
            f"{b}/actions/permissions": (repo_perms or {}).get(n, {"enabled": True, "allowed_actions": "all",
                                                                   "sha_pinning_required": False}),
            f"{b}/actions/permissions/workflow": {"default_workflow_permissions": "read",
                                                  "can_approve_pull_request_reviews": False},
            f"{b}/actions/runners": (lambda rs: lambda q: (200, {"total_count": len(rs), "runners": rs}))(
                (runners or {}).get(n, [])),
            f"{b}/.workflows": (files or {}).get(n),
        })
    return routes


def test_workflow_files_are_read_and_judged(fake, monkeypatch, tmp_path):
    files = {"app": {"ci.yml": SAFE_WORKFLOW, "triage.yaml": RISKY_WORKFLOW, "notes.md": "x", "sub": None},
             "site": {"deploy.yml": OIDC_WORKFLOW}}
    fake(actions_routes(files))
    code, ev, _ = run_fetcher("actions_security", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["workflows_total"] == 3 and s["workflows_unparsed"] == []
    assert s["workflows_with_unpinned_actions"] == ["app:triage.yaml"]
    assert s["action_references_unpinned"] == 4
    assert s["workflows_without_permissions_block"] == []
    assert s["workflows_granting_write_all"] == ["app:triage.yaml"]
    assert s["workflows_on_privileged_triggers"] == ["app:triage.yaml"]
    assert s["workflows_checking_out_untrusted_pr_code"] == ["app:triage.yaml"]
    assert s["workflows_with_untrusted_input_in_scripts"] == ["app:triage.yaml"]
    assert s["workflows_using_oidc"] == ["site:deploy.yml"]
    assert s["workflows_on_self_hosted_runners"] == ["app:triage.yaml"]
    triage = next(w for w in ev["repositories"][0]["workflows"] if w["file"] == "triage.yaml")
    assert triage["unpinned"] == ["actions/checkout@v4", "actions/github-script@v7", "docker://alpine:3.20",
                                  "other-org/shared/.github/workflows/deploy.yml@main"]
    assert triage["unpinned_owners"] == ["actions", "other-org"]
    assert triage["untrusted_input_in_scripts"] == ["github.event.issue.body", "github.event.pull_request.title"]
    assert triage["passes_all_secrets"] is True and triage["triggers"] == ["pull_request_target"]


def test_actions_settings_reach_the_summary(fake, monkeypatch, tmp_path):
    perms = {"app": {"enabled": True, "allowed_actions": "selected", "sha_pinning_required": True},
             "site": {"enabled": False}}
    routes = actions_routes(repo_perms=perms)
    routes[f"repos/{ORG}/app/actions/permissions/selected-actions"] = {"github_owned_allowed": True,
                                                                     "patterns_allowed": ["acme/*"]}
    routes[f"repos/{ORG}/app/actions/permissions/workflow"] = {"default_workflow_permissions": "write",
                                                             "can_approve_pull_request_reviews": True}
    f = fake(routes)
    code, ev, _ = run_fetcher("actions_security", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["organization_allowed_actions"] == "all" and s["organization_default_workflow_permissions"] == "write"
    assert s["organization_workflow_token_can_approve_prs"] is True
    assert s["fork_pr_contributor_approval"] == "first_time_contributors"
    assert s["repositories_with_actions"] == 1 and s["repositories_allowing_all_actions"] == []
    assert s["repositories_without_sha_pinning_required"] == []
    assert s["repositories_with_write_token_default"] == ["app"] == s["repositories_token_can_approve_prs"]
    assert ev["repositories"][0]["selected_actions"]["patterns_allowed"] == ["acme/*"]
    # Actions off: no token or allow-list call for that repository.
    assert f"repos/{ORG}/site/actions/permissions/workflow" not in {p for p, _ in f.calls}


def test_a_workflow_without_a_permissions_block_everywhere_takes_the_default():
    m = MODS["actions_security"]
    half = "on: push\njobs:\n  a:\n    permissions: {}\n    runs-on: x\n  b:\n    runs-on: x\n"
    assert m.analyse("f.yml", half)["permissions_set"] is False
    assert m.analyse("f.yml", half.replace("  b:\n    runs-on: x\n", ""))["permissions_set"] is True
    assert m.analyse("f.yml", "on: push\njobs: {}\n")["permissions_set"] is False
    assert m.analyse("f.yml", "permissions: read-all\non: push\njobs: {}\n")["writes"] == []


@pytest.mark.parametrize("uses,expected", [
    ("actions/checkout@v4", ("action", "actions", False)),
    (f"actions/checkout@{SHA}", ("action", "actions", True)),
    (f"actions/checkout@{SHA.upper()}", ("action", "actions", False)),
    (f"actions/checkout@{SHA[:7]}", ("action", "actions", False)),
    ("actions/checkout", ("action", "actions", False)),
    (f"org/repo/path/to@{SHA}", ("action", "org", True)),
    ("./local", ("local", None, True)),
    ("docker://alpine:3", ("docker", None, False)),
    (f"docker://ghcr.io/x/y@sha256:{'c' * 64}", ("docker", None, True)),
])
def test_action_references(uses, expected):
    assert MODS["actions_security"].reference(uses) == expected


@pytest.mark.parametrize("text,triggers", [
    ("on: push\njobs: {}\n", ["push"]),
    ("on: [push, pull_request_target]\njobs: {}\n", ["push", "pull_request_target"]),
    ("'on':\n  workflow_run:\n    workflows: [x]\njobs: {}\n", ["workflow_run"]),
    ("jobs: {}\n", []),
])
def test_triggers_in_every_yaml_form(text, triggers):
    assert MODS["actions_security"].analyse("f.yml", text)["triggers"] == triggers


@pytest.mark.parametrize("script,expected", [
    ("gh pr checkout ${{ github.event.pull_request.number }}", True),
    ("git fetch origin pull/${{ github.event.number }}/head:pr && git checkout pr", True),
    ("git checkout ${{ github.head_ref }}", True),
    ("git fetch origin main", False),
    ("echo ${{ github.event.pull_request.head.sha }}", False),
])
def test_a_script_that_fetches_pull_request_code_is_a_head_checkout(script, expected):
    text = f"on: pull_request_target\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: {json.dumps(script)}\n"
    assert MODS["actions_security"].analyse("f.yml", text)["checks_out_pull_request_head"] is expected


def test_unparseable_and_unreadable_workflows_are_reported_not_guessed(fake, monkeypatch, tmp_path):
    routes = actions_routes({"app": {"bad.yml": "on: [push\n", "list.yml": "- a\n"}})
    fake(routes)
    code, ev, _ = run_fetcher("actions_security", monkeypatch, tmp_path)
    assert code == 0 and ev["summary"]["workflows_unparsed"] == ["app:bad.yml", "app:list.yml"]
    assert MODS["actions_security"].workflow_files.__doc__  # files GitHub ignores are skipped above


def test_runners_and_public_repositories_running_them(fake, monkeypatch, tmp_path):
    runner = {"name": "r1", "os": "Linux", "status": "online", "busy": False, "labels": [{"name": "self-hosted"}]}
    routes = actions_routes(runners={"app": [runner], "site": [runner]})
    routes[f"orgs/{ORG}/actions/runners"] = lambda q: (200, {"total_count": 1, "runners": [runner]})
    fake(routes)
    code, ev, _ = run_fetcher("actions_security", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["self_hosted_runners_organization"] == 1 and s["self_hosted_runners_repository"] == 2
    assert s["public_repositories_with_self_hosted_runners"] == ["app"]
    assert ev["repositories"][0]["self_hosted_runners"][0]["labels"] == ["self-hosted"]


def test_workflow_files_are_batched_and_a_timeout_halves_the_batch(fake, monkeypatch, tmp_path):
    names = [f"r{i:02}" for i in range(23)]
    routes = actions_routes()
    routes.update(org_routes([repo(n) for n in names]))
    for n in names:
        routes[f"repos/{ORG}/{n}/actions/permissions"] = {"enabled": False}
        routes[f"repos/{ORG}/{n}/actions/runners"] = lambda q: (200, {"runners": []})
        routes[f"repos/{ORG}/{n}/.workflows"] = {"ci.yml": SAFE_WORKFLOW}
    sizes = []

    def gql(query, variables):
        batch = sum(1 for k in variables if k.startswith("n"))
        sizes.append(batch)
        return (502, {"message": "timeout"}) if batch > 5 and len(sizes) == 2 else gql_repos(routes, query, variables)
    routes["graphql"] = gql
    fake(routes)
    code, ev, _ = run_fetcher("actions_security", monkeypatch, tmp_path)
    assert code == 0 and sizes == [10, 10, 5, 5, 3]
    assert len(ev["repositories"]) == 23


def test_a_graphql_error_on_workflow_files_fails_the_run(fake, monkeypatch, tmp_path):
    routes = actions_routes()
    routes["graphql"] = lambda q, v: (200, {"data": None, "errors": [{"type": "FORBIDDEN", "message": "no"}]})
    fake(routes)
    code, ev, status = run_fetcher("actions_security", monkeypatch, tmp_path)
    assert code == 1 and status["code"] == "not_authorized" and "repositories" not in ev


# --- significant_change_notifications ----------------------------------------------

_gl_spec = importlib.util.spec_from_file_location(
    "gitlab_scn_fixtures", REPO_ROOT / "fetchers/gitlab/significant_change_notifications/tests/mock_gitlab.py")
GL = importlib.util.module_from_spec(_gl_spec)
_gl_spec.loader.exec_module(GL)
SCN_ENV = {"PARAMIFY_CERT_PACKAGE_URI": GL.FALLBACK_URI}


def scn_pr(number, body, days_ago=2, labels=(), state="MERGED"):
    return {"number": number, "title": f"PR {number}", "body": body, "state": state,
            "url": f"https://github.test/{ORG}/app/pull/{number}", "createdAt": ago(days_ago + 1),
            "updatedAt": ago(days_ago), "mergedAt": ago(days_ago) if state == "MERGED" else None,
            "baseRefName": "main", "headRefName": f"b{number}", "author": {"login": "dev"},
            "mergedBy": {"login": "lead"}, "mergeCommit": {"oid": f"m{number}"},
            "labels": {"nodes": [{"name": x} for x in labels]}}


def scn_routes(prs, reviews=None):
    routes = org_routes([repo("app")])

    def gql(query, variables):
        assert "states: [MERGED]" in query or "states: [OPEN" in query
        return 200, {"data": {"repository": {"pullRequests": gql_page(prs, variables)}}}
    routes["graphql"] = gql
    for p in prs:
        routes[f"repos/{ORG}/app/pulls/{p['number']}/reviews"] = (reviews or {}).get(p["number"], [
            review("alice", "APPROVED", 1), review("bob", "APPROVED", 1), review("bob", "DISMISSED", 0)])
    return routes


def test_flagged_pull_requests_become_fedramp_notifications(fake, monkeypatch, tmp_path):
    prs = [scn_pr(1, GL.CHANGE_MR_COMPLETE), scn_pr(2, GL.ROUTINE_MR), scn_pr(3, GL.PLAIN_MR),
           scn_pr(4, GL.CHANGE_MR, labels=["significant-change"]), scn_pr(5, GL.BROKEN_MR),
           scn_pr(6, GL.CHANGE_MR_COMPLETE, days_ago=40)]
    fake(scn_routes(prs))
    code, ev, status = run_fetcher("significant_change_notifications", monkeypatch, tmp_path, **SCN_ENV)
    s = ev["summary"]
    assert s["pull_requests_scanned"] == 5 and s["flagged_count"] == 3
    assert s["unticked_marker_count"] == 1 and s["routine_recurring_count"] == 1
    by = {n["pull_request"]["number"]: n for n in ev["notifications"]}
    complete = by[1]
    assert complete["validation"] == {"valid": True, "errors": []} and complete["completeness"]["complete"] is True
    assert complete["scn"]["certificationPackageOverviewUri"] == GL.CPO_URI  # the description wins over config
    assert complete["pull_request"]["approvers"] == ["alice"]  # bob's approval was dismissed
    assert complete["pull_request"]["notification_id"] == f"SCN-{ORG}_app-1"
    assert by[4]["completeness"]["complete"] is False and by[5]["validation"]["valid"] is False
    # Strict and complete are both on by default: the run fails and names each pull request.
    assert code == 1 and "app#5" in status["error"] and "app#4: missing" in status["error"]


def test_a_label_flags_a_pull_request_without_the_checkbox(fake, monkeypatch, tmp_path):
    body = GL.CHANGE_MR_COMPLETE.replace("- [x] Significant Change", "- [ ] Significant Change").replace(
        "- [X] Significant Change", "- [ ] Significant Change")
    fake(scn_routes([scn_pr(1, body, labels=["Significant-Change"])]))
    code, ev, _ = run_fetcher("significant_change_notifications", monkeypatch, tmp_path,
                              GITHUB_SCN_MARKER_LABEL="significant-change", **SCN_ENV)
    assert code == 0 and ev["notifications"][0]["pull_request"]["marked_via"] == "label"


def test_unreadable_reviews_are_a_failure_not_an_empty_approver_list(fake, monkeypatch, tmp_path):
    routes = scn_routes([scn_pr(1, GL.CHANGE_MR_COMPLETE)])
    routes[f"repos/{ORG}/app/pulls/1/reviews"] = (403, {"message": "Resource not accessible"})
    fake(routes)
    code, ev, _ = run_fetcher("significant_change_notifications", monkeypatch, tmp_path, **SCN_ENV)
    assert code == 1 and ev["summary"]["approvers_unreadable"] == ["app#1"]


# --- release_integrity ---------------------------------------------------------------

def bundle(digest_hex, predicate="https://slsa.dev/provenance/v1"):
    payload = json.dumps({"_type": "https://in-toto.io/Statement/v1", "predicateType": predicate,
                          "subject": [{"name": "artifact.txt", "digest": {"sha256": digest_hex}}]})
    import base64
    return {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": {"payload": base64.b64encode(payload.encode()).decode(), "payloadType": "x"}}


def release(tag, assets, immutable=False, draft=False):
    return {"tag_name": tag, "name": tag, "draft": draft, "prerelease": False, "immutable": immutable,
            "published_at": ago(1), "author": {"login": "github-actions[bot]"}, "assets": assets}


def asset(name, hexd):
    return {"name": name, "size": 10, "digest": f"sha256:{hexd}" if hexd else None, "uploader": {"login": "x"}}


def release_routes(releases, rulesets=(), attestations=None, immutable=None):
    routes = org_routes([repo("app")])
    b = f"repos/{ORG}/app"
    routes.update({f"orgs/{ORG}/settings/immutable-releases": {"enforced_repositories": "none"},
                   f"{b}/releases": releases, f"{b}/immutable-releases": immutable or {"enabled": False,
                                                                                         "enforced_by_owner": False},
                   f"{b}/rulesets": [{k: v for k, v in r.items() if k != "rules"} for r in rulesets]})
    for r in rulesets:
        routes[f"{b}/rulesets/{r['id']}"] = r
    for hexd, found in (attestations or {}).items():
        routes[f"{b}/attestations/sha256:{hexd}"] = {"attestations": found}
    return routes


def tag_ruleset(id_, include, rules=("deletion", "update"), enforcement="active", **kw):
    return {"id": id_, "name": f"tags-{id_}", "target": "tag", "enforcement": enforcement, "source_type": "Repository",
            "conditions": {"ref_name": {"include": list(include), "exclude": []}},
            "rules": [{"type": t} for t in rules], "bypass_actors": kw.get("bypass_actors", [])}


def test_release_verdicts(fake, monkeypatch, tmp_path):
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    rels = [release("v3", [asset("x", c)], immutable=True), release("v2", [asset("x", b)]),
            release("v1", [asset("x", a), asset("old", None)]), release("v0", [asset("x", a)], draft=True)]
    routes = release_routes(rels, [tag_ruleset(1, ["refs/tags/v1"]), tag_ruleset(2, ["refs/tags/v2"],
                                                                                rules=("deletion",))],
                            {b: [{"bundle": bundle(b)}], c: [{"bundle": bundle(c)}, {"bundle": bundle(c, "x/sbom")}]})
    fake(routes)
    code, ev, _ = run_fetcher("release_integrity", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["releases_checked"] == 3 and s["release_assets"] == 4
    assert s["release_assets_without_digest"] == ["app@v1:old"]
    assert s["release_assets_with_build_provenance"] == 2 and s["release_assets_without_build_provenance"] == ["app@v1:x"]
    assert s["releases_not_immutable"] == ["app@v1", "app@v2"]
    # v1: deletion and update refused; v2: only deletion, so the tag can still be moved; v3 is immutable.
    assert s["release_tags_not_locked"] == ["app@v2"] and s["release_tags_lock_unknown"] == []
    v3 = ev["repositories"][0]["releases"][0]["assets"][0]["provenance"]
    assert v3 == {"count": 2, "initiators": [], "predicate_types": ["https://slsa.dev/provenance/v1", "x/sbom"],
                  "subject_matches": True, "bundles_not_inline": 0}
    calls = [q for p, q in fake.holder["fake"].calls if "/attestations/" in p]
    assert calls and all(q.get("predicate_type") == "provenance" for q in calls)


def test_an_attestation_whose_statement_names_another_digest_does_not_count():
    m = MODS["release_integrity"]
    s = m.attestation_summary([{"bundle": bundle("f" * 64)}], "sha256:" + "a" * 64)
    assert s["subject_matches"] is False
    s = m.attestation_summary([{"bundle": {"dsseEnvelope": {"payload": "!!"}}}], "sha256:" + "a" * 64)
    assert s["subject_matches"] is False
    assert m.attestation_summary([], "sha256:" + "a" * 64)["subject_matches"] is None


def test_a_bundle_served_from_storage_counts_without_a_subject_check(fake, monkeypatch, tmp_path):
    d = "d" * 64
    found = [{"bundle": None, "bundle_url": "https://blob.example/x.json.sn", "initiator": "user"}]
    fake(release_routes([release("v1", [asset("x", d)])], attestations={d: found}))
    _, ev, _ = run_fetcher("release_integrity", monkeypatch, tmp_path)
    a = ev["repositories"][0]["releases"][0]["assets"][0]
    assert a["build_provenance"] is True and a["provenance"]["subject_matches"] is None
    assert a["provenance"]["bundles_not_inline"] == 1 and a["provenance"]["initiators"] == ["user"]
    bad = [{"bundle": bundle("f" * 64), "initiator": "user"}]
    fake(release_routes([release("v1", [asset("x", d)])], attestations={d: bad}))
    _, ev, _ = run_fetcher("release_integrity", monkeypatch, tmp_path)
    assert ev["summary"]["release_assets_without_build_provenance"] == ["app@v1:x"]


def test_tag_ruleset_reach(fake, monkeypatch, tmp_path):
    m = MODS["release_integrity"]
    always = [{"actor_type": "OrganizationAdmin", "actor_id": 1, "bypass_mode": "always"}]
    assert m.tag_rules([tag_ruleset(1, ["refs/tags/v*"], bypass_actors=always)], "app", "v1.2", "main") == {
        "locked": True, "rules": ["deletion", "update"], "always_bypass": ["tags-1"]}
    assert m.tag_rules([tag_ruleset(1, ["refs/tags/v*"], enforcement="evaluate")], "app", "v1", "main")["locked"] is False
    assert m.tag_rules([tag_ruleset(1, ["~ALL"])], "app", "anything", "main")["locked"] is True
    branch_rs = {**tag_ruleset(1, ["~ALL"]), "target": "branch"}
    assert m.tag_rules([branch_rs], "app", "v1", "main")["locked"] is False
    by_property = {**tag_ruleset(1, []), "conditions": {"repository_property": {"include": []}}}
    assert m.tag_rules([by_property], "app", "v1", "main")["locked"] is None


def test_releases_per_repository_bounds_the_walk(fake, monkeypatch, tmp_path):
    rels = [release(f"v{i}", []) for i in range(30, 0, -1)]
    fake(release_routes(rels))
    code, ev, _ = run_fetcher("release_integrity", monkeypatch, tmp_path, GITHUB_RELEASES_PER_REPOSITORY="5")
    assert code == 0 and [r["tag"] for r in ev["repositories"][0]["releases"]] == ["v30", "v29", "v28", "v27", "v26"]


# --- deployment_controls -------------------------------------------------------------

def environment(name, reviewers=None, self_review=False, wait=None, policy=None, bypass=True):
    rules = []
    if reviewers is not None:
        rules.append({"type": "required_reviewers", "prevent_self_review": not self_review,
                      "reviewers": [{"type": "Team", "reviewer": {"slug": r}} for r in reviewers]})
    if wait is not None:
        rules.append({"type": "wait_timer", "wait_timer": wait})
    return {"name": name, "protection_rules": rules, "deployment_branch_policy": policy, "can_admins_bypass": bypass}


def deployment(id_, ref, days_ago, app="github-actions", creator="dev"):
    return {"id": id_, "ref": ref, "sha": f"s{id_}", "task": "deploy", "created_at": ago(days_ago),
            "creator": {"login": creator}, "performed_via_github_app": {"slug": app} if app else None,
            "production_environment": True}


def deploy_routes(envs, deploys=None, statuses=None, ahead=None):
    """ahead: {sha: commits ahead of the default branch}, None for a commit that does not exist; default 0."""
    routes = org_routes([repo("app")])
    b = f"repos/{ORG}/app"

    def compare(query, variables):
        assert variables["ref"] == "refs/heads/main"
        out = {}
        for key, sha in variables.items():
            if key.startswith("s"):
                n = (ahead or {}).get(sha, 0)
                out[f"o{key[1:]}"] = None if n is None else {"oid": sha}
                out[f"c{key[1:]}"] = {"compare": {"aheadBy": 0 if n is None else n}}  # IDENTICAL for a bad oid
        return 200, {"data": {"repository": out}}
    routes["graphql"] = compare
    routes[f"{b}/environments"] = lambda q: (200, {"total_count": len(envs), "environments": envs})
    for e in envs:
        p = f"{b}/environments/{e['name']}"
        routes[f"{p}/deployment-branch-policies"] = lambda q: (200, {"branch_policies": [{"name": "main"}]})
        routes[f"{p}/deployment_protection_rules"] = lambda q: (200, {"custom_deployment_protection_rules": []})
    by_env = deploys or {}
    routes[f"{b}/deployments"] = lambda q: (200, by_env.get(q.get("environment"), []))
    for env_deploys in by_env.values():
        for d in env_deploys:
            routes[f"{b}/deployments/{d['id']}/statuses"] = [{"state": (statuses or {}).get(d["id"], "success"),
                                                              "created_at": d["created_at"]}]
    return routes


def test_a_compare_that_times_out_halves_then_fails_loudly(fake, monkeypatch, tmp_path):
    envs = [environment("production", ["ops"])]
    deploys = {"production": [deployment(2, "main", 1), deployment(1, "main", 2)]}
    routes = deploy_routes(envs, deploys)
    answer = routes["graphql"]
    routes["graphql"] = lambda q, v: answer(q, v) if len([k for k in v if k.startswith("s")]) == 1 else (502, {})
    fake(routes)
    code, ev, _ = run_fetcher("deployment_controls", monkeypatch, tmp_path)
    assert code == 0 and ev["summary"]["not_collected"] == []

    routes["graphql"] = lambda q, v: (502, {})
    fake(routes)
    code, ev, _ = run_fetcher("deployment_controls", monkeypatch, tmp_path)
    assert code != 0 and ev["summary"]["not_collected"] == ["app"]
    assert any(f["type"] == "GraphQLTimeout" for f in ev["metadata"]["api_failures"])


def test_deployment_verdicts(fake, monkeypatch, tmp_path):
    envs = [environment("production", ["ops"], wait=5, policy={"protected_branches": False,
                                                                "custom_branch_policies": True}, bypass=False),
            environment("Prod-EU", ["ops"], self_review=True), environment("staging"), environment("live")]
    deploys = {"production": [deployment(3, "main", 1), deployment(2, "hotfix", 2, app=None, creator="admin"),
                              deployment(1, "main", 40)],
               "live": [deployment(4, "main", 3)]}
    fake(deploy_routes(envs, deploys, statuses={2: "failure"}, ahead={"s2": 3, "s4": None}))
    code, ev, _ = run_fetcher("deployment_controls", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["environments_total"] == 4
    assert s["production_environments"] == ["app:Prod-EU", "app:live", "app:production"]
    assert s["production_without_required_reviewers"] == ["app:live"]
    assert s["production_allowing_self_review"] == ["app:Prod-EU"]
    assert s["production_deployable_from_any_branch"] == ["app:Prod-EU", "app:live"]
    assert s["production_admins_can_bypass"] == ["app:Prod-EU", "app:live"]
    assert s["production_deployments"] == 3  # the 40-day-old one is outside the window
    assert s["production_deployments_not_on_default_branch"] == ["app:production#2"]
    assert s["production_deployments_commit_unknown"] == ["app:live#4"]
    assert s["production_deployments_not_by_actions"] == ["app:production#2"]
    assert s["production_deployments_by_state"] == {"failure": 1, "success": 2}
    prod = next(e for e in ev["repositories"][0]["environments"] if e["name"] == "production")
    assert prod["allowed_refs"] == [{"name": "main", "type": "branch"}] and prod["wait_timer_minutes"] == 5
    assert prod["required_reviewers"] == [{"type": "Team", "reviewer": "ops"}]
    staging = next(e for e in ev["repositories"][0]["environments"] if e["name"] == "staging")
    assert "deployments" not in staging


def test_more_deployments_than_the_cap_fail_rather_than_cut_history(fake, monkeypatch, tmp_path):
    envs = [environment("production", ["ops"])]
    fake(deploy_routes(envs, {"production": [deployment(i, "main", 1) for i in range(10, 0, -1)]}))
    code, ev, status = run_fetcher("deployment_controls", monkeypatch, tmp_path, GITHUB_MAX_DEPLOYMENTS="5")
    assert code == 1 and "GITHUB_MAX_DEPLOYMENTS" in status["error"] and ev["summary"]["not_collected"] == ["app"]
    # Exactly at the cap, with the next one outside the window, is complete.
    fake(deploy_routes(envs, {"production": [deployment(i, "main", 1) for i in range(5, 0, -1)]
                              + [deployment(0, "main", 90)]}))
    code, ev, _ = run_fetcher("deployment_controls", monkeypatch, tmp_path, GITHUB_MAX_DEPLOYMENTS="5")
    assert code == 0 and ev["summary"]["production_deployments"] == 5


def test_deployed_commits_are_compared_in_batches(fake, monkeypatch, tmp_path):
    deploys = {"production": [deployment(i, "main", 1) for i in range(45, 0, -1)]}
    f = fake(deploy_routes([environment("production", ["ops"])], deploys))
    code, ev, _ = run_fetcher("deployment_controls", monkeypatch, tmp_path)
    batches = [sum(1 for k in q if k.startswith("s")) for p, q in f.calls if p == "graphql"]
    assert code == 0 and batches == [20, 20, 5] and ev["summary"]["production_deployments_not_on_default_branch"] == []


@pytest.mark.parametrize("env", [{"GITHUB_DEPLOYMENT_DAYS_BACK": "0"}, {"GITHUB_PRODUCTION_ENVIRONMENTS": ","},
                                 {"GITHUB_MAX_DEPLOYMENTS": "0"}])
def test_deployment_configuration_errors(fake, monkeypatch, tmp_path, env):
    fake(deploy_routes([]))
    code, _, status = run_fetcher("deployment_controls", monkeypatch, tmp_path, **env)
    assert code == 1 and status["code"] == "bad_config"


# --- vulnerability_disclosure -----------------------------------------------------

def advisory(ghsa, state, created_days_ago, resolved_days_ago=None, submitted=False):
    end = ago(resolved_days_ago) if resolved_days_ago is not None else None
    return {"ghsa_id": ghsa, "cve_id": None, "summary": "s", "severity": "high", "state": state,
            "created_at": ago(created_days_ago), "published_at": end if state == "published" else None,
            "closed_at": end if state == "closed" else None, "withdrawn_at": None,
            "submission": {"accepted": state != "triage"} if submitted else None}


def vd_routes(pvr, policy, advisories):
    routes = org_routes([repo("app"), repo("site", visibility="private")])
    for n in ("app", "site"):
        b = f"repos/{ORG}/{n}"
        routes[f"{b}/private-vulnerability-reporting"] = {"enabled": pvr.get(n, False)}
        routes[f"{b}/security-advisories"] = advisories.get(n, [])
        routes[f"{b}/.policy"] = {"isSecurityPolicyEnabled": policy.get(n, False),
                                   "securityPolicyUrl": f"https://github.test/{n}/security/policy"
                                   if policy.get(n) else None}
    return routes


def test_vulnerability_disclosure_verdicts(fake, monkeypatch, tmp_path):
    advisories = {"app": [advisory("GHSA-1", "triage", 20, submitted=True), advisory("GHSA-2", "draft", 5),
                          advisory("GHSA-3", "published", 40, 10, submitted=True), advisory("GHSA-4", "closed", 9, 8)]}
    fake(vd_routes({"site": True}, {"site": True}, advisories))
    code, ev, _ = run_fetcher("vulnerability_disclosure", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["public_repositories_without_private_reporting"] == ["app"]
    assert s["repositories_with_private_reporting"] == 1
    assert s["repositories_without_security_policy"] == ["app"]
    assert s["advisories_total"] == 4 and s["private_reports"] == 2
    assert s["advisories_by_state"] == {"closed": 1, "draft": 1, "published": 1, "triage": 1}
    assert s["advisories_awaiting_resolution"] == ["app:GHSA-1", "app:GHSA-2"]
    assert s["oldest_unresolved_days"] == 20.0
    rows = {a["ghsa_id"]: a for a in ev["repositories"][0]["advisories"]}
    assert rows["GHSA-3"]["days_to_resolution"] == 30.0 and rows["GHSA-3"]["days_open"] is None
    assert rows["GHSA-1"]["report_accepted"] is False and rows["GHSA-2"]["reported_privately"] is False


# --- branch_protection: CODEOWNERS and ruleset bypasses -------------------------------

CODE_OWNER_RULE = {"type": "pull_request", "parameters": {**PR_RULE["parameters"], "require_code_owner_review": True}}


def owners_routes(errors):
    routes = sandbox_routes()
    rs = ruleset(1, "fetcher-test-main", "active", [CODE_OWNER_RULE, NFF_RULE])
    routes.update({f"repos/{ORG}/protected/rulesets": [rs], f"repos/{ORG}/protected/rulesets/1": rs,
                   f"repos/{ORG}/protected/rules/branches/main": enforced(rs["rules"], 1)})
    if errors is not None:
        routes[f"repos/{ORG}/protected/codeowners/errors"] = errors
    return routes


@pytest.mark.parametrize("errors,state", [
    (None, "missing"),
    ({"errors": []}, "valid"),
    ({"errors": [{"line": 3, "column": 1, "kind": "Unknown owner", "message": "x", "path": ".github/CODEOWNERS",
                  "source": "* @nobody", "suggestion": None}]}, "errors"),
])
def test_required_code_owner_review_needs_a_valid_codeowners_file(fake, monkeypatch, tmp_path, errors, state):
    f = fake(owners_routes(errors))
    code, ev, _ = run_fetcher("branch_protection", monkeypatch, tmp_path)
    by = {r["repository"]: r for r in ev["repositories"]}
    assert code == 0 and by["protected"]["codeowners"]["state"] == state
    assert ev["summary"]["code_owner_review_without_valid_codeowners"] == ([] if state == "valid" else ["protected"])
    # Only a repository that requires code-owner review is asked.
    asked = [p for p, _ in f.calls if p.endswith("/codeowners/errors")]
    assert asked == [f"repos/{ORG}/protected/codeowners/errors"]
    assert by["unprotected"]["codeowners"] is None


def test_an_unreadable_bypass_log_is_unknown_and_keeps_the_record(fake, monkeypatch, tmp_path):
    routes = sandbox_routes()
    routes[f"repos/{ORG}/protected/rulesets/rule-suites"] = (403, {"message": "Resource not accessible"},
                                                            {"X-Accepted-GitHub-Permissions": "administration=read"})
    fake(routes)
    code, ev, status = run_fetcher("branch_protection", monkeypatch, tmp_path)
    by = {r["repository"]: r for r in ev["repositories"]}
    assert code == 1 and "administration=read" in status["error"]
    assert by["protected"]["collected"] is True and by["protected"]["requires_approval"] is True
    assert ev["summary"]["ruleset_bypasses_unreadable"] == ["protected"]


def test_scn_details_from_mutation_testing(fake, monkeypatch, tmp_path):
    """Each assertion pins a behaviour a surviving mutant once changed unnoticed."""
    prs = [scn_pr(1, GL.CHANGE_MR_COMPLETE), scn_pr(2, GL.EMERGENCY_MR), scn_pr(5, GL.BROKEN_MR)]
    fake(scn_routes(prs, reviews={1: [review("alice", "APPROVED", 2), review("alice", "COMMENTED", 1)]}))
    code, ev, status = run_fetcher("significant_change_notifications", monkeypatch, tmp_path,
                                   GITHUB_SCN_REQUIRE_COMPLETE="false", **SCN_ENV)
    by = {n["pull_request"]["number"]: n for n in ev["notifications"]}
    assert by[1]["pull_request"]["approvers"] == ["alice"]  # a later comment does not withdraw an approval
    assert by[1]["pull_request"]["author"] == "dev" and by[1]["pull_request"]["marked_via"] == "checkbox"
    assert not any("Emergency" in n for n in by[1]["parse_notes"])
    assert any("Emergency" in n for n in by[2]["parse_notes"]) and ev["summary"]["emergency_change_count"] == 1
    assert ev["summary"]["by_change_type"]["Adaptive"] == 2
    # Strict is on by default: the invalid notification fails the run, and only it is named.
    assert code == 1 and "app#5" in status["error"] and "app#1" not in status["error"]


def test_a_marker_label_does_not_flag_unlabelled_unticked_pull_requests(fake, monkeypatch, tmp_path):
    fake(scn_routes([scn_pr(3, GL.PLAIN_MR), scn_pr(1, GL.CHANGE_MR_COMPLETE)]))
    code, ev, _ = run_fetcher("significant_change_notifications", monkeypatch, tmp_path,
                              GITHUB_SCN_MARKER_LABEL="significant-change", **SCN_ENV)
    assert code == 0 and [n["pull_request"]["number"] for n in ev["notifications"]] == [1]
    assert ev["notifications"][0]["pull_request"]["marked_via"] == "checkbox"


def test_a_flagged_pull_request_without_the_section_is_invalid_and_incomplete(fake, monkeypatch, tmp_path):
    fake(scn_routes([scn_pr(1, GL.CHANGE_MR_COMPLETE)]))
    code, ev, _ = run_fetcher("significant_change_notifications", monkeypatch, tmp_path,
                              GITHUB_SCN_SECTION_HEADING="No Such Heading", **SCN_ENV)
    n = ev["notifications"][0]
    assert code == 1 and n["scn"] is None
    assert n["validation"]["valid"] is False and n["completeness"]["complete"] is False


def test_scn_lowest_window_is_accepted(fake, monkeypatch, tmp_path):
    fake(scn_routes([scn_pr(1, GL.CHANGE_MR_COMPLETE, days_ago=0)]))
    code, ev, _ = run_fetcher("significant_change_notifications", monkeypatch, tmp_path,
                              GITHUB_SCN_DAYS_BACK="1", **SCN_ENV)
    assert code == 0 and ev["summary"]["flagged_count"] == 1


def test_the_same_package_uri_twice_is_no_warning(fake, monkeypatch, tmp_path):
    fake(scn_routes([scn_pr(5, GL.PLAIN_MR)]))
    _, ev, _ = run_fetcher("significant_change_notifications", monkeypatch, tmp_path,
                           FEDRAMP_CERT_PACKAGE_URI=GL.FALLBACK_URI, **SCN_ENV)
    assert not ev["metadata"].get("config_warnings")
    fake(scn_routes([scn_pr(5, GL.PLAIN_MR)]))
    _, ev, _ = run_fetcher("significant_change_notifications", monkeypatch, tmp_path,
                           FEDRAMP_CERT_PACKAGE_URI=GL.FALLBACK_URI, PARAMIFY_CERT_PACKAGE_URI="")
    assert not ev["metadata"].get("config_warnings")


# --- audit_log ---------------------------------------------------------------------

def audit_event(action, hours_ago, actor="boss", **kw):
    return {"@timestamp": int((time.time() - hours_ago * 3600) * 1000), "action": action, "actor": actor,
            "actor_location": {"country_name": "United States"}, "_document_id": f"d-{action}-{hours_ago}", **kw}


def audit_routes(events, plan="enterprise"):
    routes = org_routes([repo("app")])
    routes[f"orgs/{ORG}"]["plan"] = {"name": plan}
    routes[f"orgs/{ORG}/audit-log"] = events
    return routes


def test_audit_log_counts_everything_and_keeps_security_events(fake, monkeypatch, tmp_path):
    events = [audit_event("protected_branch.policy_override", 1, repo=f"{ORG}/app"),
              audit_event("repo.access", 2, repo=f"{ORG}/app", visibility="public", previous_visibility="private"),
              audit_event("org.add_member", 3, user="newbie"),
              audit_event("workflows.completed_workflow_run", 4), audit_event("workflows.completed_workflow_run", 5)]
    f = fake(audit_routes(events))
    code, ev, _ = run_fetcher("audit_log", monkeypatch, tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["events_total"] == 5 and s["security_events"] == 3 and s["actors"] == 1
    assert s["by_family"] == {"org": 1, "protected_branch": 1, "repo": 1, "workflows": 2}
    assert s["by_action"]["workflows.completed_workflow_run"] == 2
    vis = next(e for e in ev["security_events"] if e["action"] == "repo.access")
    assert vis["previous_visibility"] == "private" and vis["visibility"] == "public" and vis["country"] == "United States"
    assert vis["at"].endswith("Z") and s["newest_event"] >= s["oldest_event"]
    q = next(q for p, q in f.calls if p.endswith("/audit-log"))
    assert q["phrase"].startswith("created:>=") and q["include"] == "web" and q["order"] == "desc"


@pytest.mark.parametrize("value,expected", [(1606929874512, "2020-12-02T17:24:34Z"), (1606929874, "2020-12-02T17:24:34Z"),
                                            (None, None), ("x", None)])
def test_audit_timestamps_in_seconds_or_milliseconds(value, expected):
    assert MODS["audit_log"].when(value) == expected


@pytest.mark.parametrize("env", [{"GITHUB_AUDIT_DAYS_BACK": "0"}, {"GITHUB_AUDIT_DAYS_BACK": "181"},
                                 {"GITHUB_AUDIT_MAX_EVENTS": "0"}])
def test_audit_configuration_errors(fake, monkeypatch, tmp_path, env):
    fake(audit_routes([]))
    code, _, status = run_fetcher("audit_log", monkeypatch, tmp_path, **env)
    assert code == 1 and status["code"] == "bad_config"


@pytest.mark.parametrize("env", [{"GITHUB_AUDIT_DAYS_BACK": "1"}, {"GITHUB_AUDIT_DAYS_BACK": "180"},
                                 {"GITHUB_AUDIT_MAX_EVENTS": "1"}])
def test_audit_limits_at_their_edges_are_accepted(fake, monkeypatch, tmp_path, env):
    fake(audit_routes([audit_event("repo.create", 1, repository=f"{ORG}/app")]))
    code, ev, _ = run_fetcher("audit_log", monkeypatch, tmp_path, **env)
    assert code == 0 and ev["security_events"][0]["repo"] == f"{ORG}/app"  # the newer field name, when repo is absent


def test_access_review_sharper_verdicts(fake, monkeypatch, tmp_path):
    """Read-only outsiders, bots, writers and team admin rights, each told apart from its opposite."""
    routes = access_routes()
    b = f"repos/{ORG}"
    routes[f"{b}/app/collaborators"] = [{"login": "boss", "role_name": "admin"},
                                        {"login": "dev", "role_name": "write"},
                                        {"login": "ci-bot", "role_name": "triage", "type": "Bot"},
                                        {"login": "contractor", "role_name": "read"}]
    fake(routes)
    code, ev, _ = run_fetcher("access_review", monkeypatch, tmp_path)
    s = ev["summary"]
    assert code == 0 and s["outside_collaborators_with_write"] == []
    app = next(r for r in ev["repositories"] if r["repository"] == "app")
    assert app["writers"] == ["dev"]
    team = next(t for t in ev["teams"] if t["team"] == "platform")
    assert team["admin_on"] == ["app"]
    roles = {r["role"]: r for r in ev["organization_roles"]}
    assert roles["security_manager"]["permissions"] == ["x"]


def test_user_reviewers_and_protection_apps_are_named(fake, monkeypatch, tmp_path):
    env = environment("production", [])
    env["protection_rules"][0]["reviewers"] = [{"type": "User", "reviewer": {"login": "lead"}}]
    routes = deploy_routes([env])
    routes[f"repos/{ORG}/app/environments/production/deployment_protection_rules"] = lambda q: (200, {
        "custom_deployment_protection_rules": [{"app": {"slug": "datadog"}, "enabled": True}]})
    fake(routes)
    _, ev, _ = run_fetcher("deployment_controls", monkeypatch, tmp_path)
    prod = ev["repositories"][0]["environments"][0]
    assert prod["required_reviewers"] == [{"type": "User", "reviewer": "lead"}]
    assert prod["custom_protection_rules"] == [{"app": "datadog", "enabled": True}]


@pytest.mark.parametrize("unreadable", ["include", "exclude"])
def test_a_ref_pattern_the_matcher_cannot_read_leaves_the_reach_unknown(monkeypatch, unreadable):
    monkeypatch.setattr(gc, "ref_matches", lambda p, ref, default: None if p == "?" else p == ref)
    names = {"include": ["?"], "exclude": []} if unreadable == "include" else {"include": ["r"], "exclude": ["?"]}
    refs = {"include": ["?"], "exclude": []} if unreadable == "include" else {"include": ["refs/heads/main"],
                                                                               "exclude": ["?"]}
    for conditions in ({"repository_name": names, "ref_name": {"include": ["refs/heads/main"]}},
                       {"ref_name": refs}):
        assert gc.ruleset_targets_ref({"conditions": conditions}, "r", "refs/heads/main", "main") is None


@pytest.mark.parametrize("raw,expected", [("true", True), ("false", False), ("", True)])
def test_boolean_settings_read_from_the_environment(monkeypatch, raw, expected):
    monkeypatch.setenv("GITHUB_TEST_FLAG", raw)
    assert gc._env_value("GITHUB_TEST_FLAG", True) is expected
