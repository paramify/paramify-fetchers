#!/usr/bin/env python3
"""Check every field the GitHub fetchers read against GitHub's own OpenAPI description.

A mock cannot catch a wrong field name: it is written from the same assumption
as the fetcher, so the two agree and both disagree with the API. GitHub
publishes the spec that serves its REST API (github/rest-api-description);
this reads the response schemas each fetcher's endpoints return and reports:

  - a field a fetcher reads that no response it handles defines, and
  - a field the spec types as an object that a fetcher tests for truth.

A field read from a GraphQL response must be selected by a query in the same
file (GitHub itself rejects a query naming a field its schema lacks, so the
recorded cassettes prove the queries; this proves the reads match them).

    python tools/github_schema_check.py            # check against the committed snapshot
    python tools/github_schema_check.py --refresh  # re-extract the snapshot from the live spec
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

import requests

ROOT = Path(__file__).resolve().parent.parent
FETCHERS = ROOT / "fetchers" / "github"
SNAPSHOT = Path(__file__).with_name("github_schema_snapshot.json")
SPEC_URL = ("https://raw.githubusercontent.com/github/rest-api-description/main/"
            "descriptions/api.github.com/api.github.com.json")
# Enterprise Cloud-only endpoints (the organization audit log) are described only in the GHEC spec.
GHEC_SPEC_URL = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/ghec/ghec.json"
MAX_DEPTH = 12

# The response schemas each file handles, from the endpoints it calls (paths in the fetcher).
REGISTRY: Dict[str, List[str]] = {
    "_shared/github_client.py": ["organization-full", "minimal-repository", "full-repository", "repository-ruleset"],
    "branch_protection/fetcher.py": ["repository-rule-detailed", "repository-ruleset", "branch-protection",
                                     "rule-suites", "codeowners-errors", "minimal-repository", "organization-full"],
    "pull_request_checks/fetcher.py": ["pull-request-simple", "pull-request-review", "check-run",
                                       "combined-commit-status", "commit", "repository-rule-detailed",
                                       "branch-protection", "minimal-repository"],
    "dependabot_alerts/fetcher.py": ["dependabot-alert", "dependency-graph-spdx-sbom",
                                     "check-automated-security-fixes", "minimal-repository"],
    "code_scanning_alerts/fetcher.py": ["code-scanning-alert-items", "code-scanning-analysis",
                                        "code-scanning-default-setup", "minimal-repository"],
    "secret_scanning/fetcher.py": ["secret-scanning-alert", "minimal-repository"],
    "org_security_settings/fetcher.py": ["organization-full", "actions-organization-permissions",
                                         "actions-get-default-workflow-permissions", "simple-user",
                                         "code-security-configuration", "code-security-default-configurations",
                                         "code-security-configuration-repositories", "minimal-repository"],
    "access_review/fetcher.py": ["simple-user", "collaborator", "team", "organization-invitation",
                                 "team-member", "organization-role", "user-role-assignment",
                                 "team-role-assignment", "minimal-repository"],
    "repository_inventory/fetcher.py": ["custom-property", "org-repo-custom-property-values", "minimal-repository",
                                        "organization-full"],
    "non_user_credentials/fetcher.py": ["installation", "organization-actions-secret", "actions-secret", "org-hook",
                                        "hook", "organization-programmatic-access-grant", "deploy-key",
                                        "organization-full", "minimal-repository"],
    "actions_security/fetcher.py": ["actions-organization-permissions", "selected-actions",
                                    "actions-get-default-workflow-permissions", "actions-fork-pr-contributor-approval",
                                    "actions-fork-pr-workflows-private-repos",
                                    "actions-artifact-and-log-retention-response", "self-hosted-runners-settings",
                                    "runner", "actions-repository-permissions", "minimal-repository",
                                    "organization-full"],
    "significant_change_notifications/fetcher.py": ["pull-request-review", "minimal-repository", "organization-full"],
    "release_integrity/fetcher.py": ["release", "release-asset", "check-immutable-releases",
                                     "immutable-releases-organization-settings", "repository-ruleset",
                                     "minimal-repository", "organization-full"],
    "audit_log/fetcher.py": ["audit-log-event", "minimal-repository", "organization-full"],
    "vulnerability_disclosure/fetcher.py": ["repository-advisory", "minimal-repository", "organization-full"],
    "deployment_controls/fetcher.py": ["environment", "deployment-branch-policy", "deployment-protection-rule",
                                       "deployment", "deployment-status", "minimal-repository", "organization-full"],
}
# Read from the KEV catalog (cisa.gov), not GitHub; and from GitHub's error bodies.
NOT_GITHUB = {"vulnerabilities", "cveID", "message"}
# Keys a fetcher reads from something other than a component schema: a workflow file in the repository (Actions
# workflow syntax); the GitLab SCN parser's output and FedRAMP's schema; the in-toto statement inside a Sigstore
# bundle; and the attestations response, whose schema is inline in the spec (attestations[].bundle.dsseEnvelope,
# initiator; checked by hand against spec 1.1.4).
NOT_API = {
    "actions_security/fetcher.py": {"on", "jobs", "steps", "uses", "with", "run", "runs-on", "group", "labels",
                                    "permissions", "secrets", "script"},
    "significant_change_notifications/fetcher.py": {"emergency_change", "changeType", "$schemaVersion"},
    # can_admins_bypass is returned (measured) but missing from the spec's environment schema; compare/aheadBy are
    # selected by a GraphQL query built per batch of commits.
    "deployment_controls/fetcher.py": {"can_admins_bypass", "compare", "aheadBy"},
    "release_integrity/fetcher.py": {"attestations", "bundle", "dsseEnvelope", "initiator", "payload", "predicateType",
                                     "subject", "sha256"},
}
# The GraphQL response envelope and connection fields the shared client reads for every query.
GRAPHQL_ENVELOPE = {"data", "errors", "type", "message", "nodes", "pageInfo", "hasNextPage", "endCursor"}
# The dependency SBOM is SPDX; GitHub's schema lists the package fields loosely.
SPDX = {"SPDXID", "name", "versionInfo", "packages", "sbom"}


# --- the snapshot ---------------------------------------------------------------

def _flatten(spec: dict, schema: dict, depth: int = 0) -> Dict[str, dict]:
    """{field: {"types": [...], "children": {...}}} through refs, allOf/oneOf/anyOf and arrays."""
    if depth > MAX_DEPTH or not isinstance(schema, dict):
        return {}
    if "$ref" in schema:
        return _flatten(spec, spec["components"]["schemas"][schema["$ref"].split("/")[-1]], depth + 1)
    out: Dict[str, dict] = {}
    for key in ("allOf", "oneOf", "anyOf"):
        for part in schema.get(key) or []:
            _merge(out, _flatten(spec, part, depth + 1))
    if schema.get("type") == "array" or "items" in schema:
        _merge(out, _flatten(spec, schema.get("items") or {}, depth + 1))
    for name, prop in (schema.get("properties") or {}).items():
        types = _types(spec, prop)
        _merge(out, {name: {"types": types, "children": _flatten(spec, prop, depth + 1)}})
    return out


def _types(spec: dict, prop: dict) -> List[str]:
    if "$ref" in prop:
        return _types(spec, spec["components"]["schemas"][prop["$ref"].split("/")[-1]])
    found: Set[str] = set()
    t = prop.get("type")
    found.update(t if isinstance(t, list) else [t] if t else [])
    for key in ("allOf", "oneOf", "anyOf"):
        for part in prop.get(key) or []:
            found.update(_types(spec, part))
    if not found and "properties" in prop:
        found.add("object")
    return sorted(found)


def _merge(into: Dict[str, dict], more: Dict[str, dict]) -> None:
    for name, entry in more.items():
        if name in into:
            into[name]["types"] = sorted(set(into[name]["types"]) | set(entry["types"]))
            _merge(into[name]["children"], entry["children"])
        else:
            into[name] = {"types": list(entry["types"]), "children": dict(entry["children"])}


def refresh() -> None:
    specs = []
    for url in (SPEC_URL, GHEC_SPEC_URL):
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        specs.append(resp.json())
    spec = specs[0]
    names = sorted({n for schemas in REGISTRY.values() for n in schemas})
    # Each schema from the github.com spec, or from the GHEC spec when only Enterprise Cloud has it.
    owner = {n: next(s for s in specs if n in s["components"]["schemas"]) for n in names}
    snapshot = {"source": SPEC_URL, "ghec_source": GHEC_SPEC_URL, "spec_version": spec["info"]["version"],
                "schemas": {n: _flatten(owner[n], owner[n]["components"]["schemas"][n]) for n in names}}
    SNAPSHOT.write_text(json.dumps(snapshot, indent=1, sort_keys=True) + "\n")
    print(f"wrote {SNAPSHOT.name}: {len(names)} schemas from spec {snapshot['spec_version']}")


# --- the check ---------------------------------------------------------------------

def _all_fields(tree: Dict[str, dict]) -> Dict[str, Set[str]]:
    """Every field name at any depth, with every type the spec gives it."""
    out: Dict[str, Set[str]] = {}
    for name, entry in tree.items():
        out.setdefault(name, set()).update(entry["types"])
        for child, types in _all_fields(entry["children"]).items():
            out.setdefault(child, set()).update(types)
    return out


NON_API_RECEIVERS = {"headers", "environ", "links"}


def _receiver_is_api(node: ast.expr) -> bool:
    """False for HTTP headers, os.environ and Link relations, which are not response fields."""
    while isinstance(node, (ast.Call, ast.Subscript, ast.Attribute)):
        if isinstance(node, ast.Attribute) and node.attr in NON_API_RECEIVERS:
            return False
        node = node.func if isinstance(node, ast.Call) else node.value
    return True


def _reads(tree: ast.AST) -> Iterable[Tuple[str, int, bool]]:
    """(field, line, read in a truth test) for every x.get("field") and x["field"]."""
    tests: Set[int] = set()
    for node in ast.walk(tree):
        cond = None
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            cond = node.test
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            cond = node.operand
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "bool" and node.args:
            cond = node.args[0]
        elif isinstance(node, ast.comprehension):
            for c in node.ifs:
                tests.add(id(c))
        if cond is not None:
            tests.add(id(cond))
        if isinstance(node, ast.BoolOp):
            # `x.get("obj") or {}` defaults a missing object; it is not a truth test of it.
            defaulted = isinstance(node.op, ast.Or) and isinstance(node.values[-1], (ast.Dict, ast.List, ast.Constant))
            for v in node.values if not defaulted else node.values[:-1][1:]:
                tests.add(id(v))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get"
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                and _receiver_is_api(node.func.value)):
            yield node.args[0].value, node.lineno, id(node) in tests
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                and isinstance(node.slice.value, str) and _receiver_is_api(node.value):
            yield node.slice.value, node.lineno, id(node) in tests


def _own_keys(tree: ast.AST) -> Set[str]:
    """Keys of dict literals and of `x["k"] = …` assignments: the fetcher's own records, not API fields."""
    keys: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys.update(k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str))
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant):
                    keys.add(str(t.slice.value))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
            keys.update(k.arg for k in node.keywords if k.arg)
    return keys


def _graphql_fields(tree: ast.AST) -> Set[str]:
    """Every name selected by a GraphQL query string in the file, or by a *_FIELDS selection handed to graphql_repos."""
    names: Set[str] = set()
    selections = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id.endswith("_FIELDS") for t in n.targets)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and (
                re.match(r"\s*query\b", node.value) or id(node) in selections):
            body = re.sub(r"\$\w+|\(.*?\)", " ", node.value, flags=re.S)  # drop variables and arguments
            names |= set(re.findall(r"[A-Za-z_]\w*", body))
    return names


def check(snapshot: dict) -> List[str]:
    problems: List[str] = []
    own: Set[str] = set()
    trees = {}
    for rel in REGISTRY:
        trees[rel] = ast.parse((FETCHERS / rel).read_text())
        own |= _own_keys(trees[rel])
    for rel, names in REGISTRY.items():
        fields: Dict[str, Set[str]] = {}
        for n in names:
            for name, types in _all_fields(snapshot["schemas"][n]).items():
                fields.setdefault(name, set()).update(types)
        graphql = _graphql_fields(trees[rel]) | (GRAPHQL_ENVELOPE if rel.startswith("_shared/") else set())
        for field, line, in_test in _reads(trees[rel]):
            if field in NOT_GITHUB or field in SPDX or field in graphql or field in NOT_API.get(rel, ()):
                continue
            if field not in fields:
                if field not in own:
                    problems.append(f"{rel}:{line}: reads '{field}', which no response it handles defines")
                continue
            types = fields[field]
            if in_test and types and types <= {"object", "null"} and field not in own:
                problems.append(f"{rel}:{line}: tests '{field}' for truth, but the spec types it {sorted(types)}")
    return problems


def unregistered() -> List[str]:
    files = {str(p.relative_to(FETCHERS)) for p in FETCHERS.glob("*/fetcher.py")} | {"_shared/github_client.py"}
    return sorted(files - set(REGISTRY))


def main() -> int:
    if "--refresh" in sys.argv:
        refresh()
    snapshot = json.loads(SNAPSHOT.read_text())
    problems = check(snapshot) + [f"{f}: not registered in REGISTRY" for f in unregistered()]
    for p in problems:
        print(p)
    reads = sum(1 for rel in REGISTRY for _ in _reads(ast.parse((FETCHERS / rel).read_text())))
    print(f"{len(REGISTRY)} files, {reads} field reads, spec {snapshot['spec_version']}: "
          f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
