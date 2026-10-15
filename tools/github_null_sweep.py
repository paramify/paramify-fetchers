#!/usr/bin/env python3
"""Null every field of every recorded GitHub response, one path at a time, and report summaries that read better.

A field going missing should never make an organization look more compliant.
Each finding is a run that still exited 0 with a summary value that improved: a count of problems that fell,
a list of offenders that shrank, or a verdict that turned true. Findings need
human triage — some are the spec allowing the field to be absent and the
fetcher's reading being right.

    python tools/github_null_sweep.py [fetcher ...]
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Iterable, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import github_fault_sweep as sweep  # noqa: E402

# Reviewed findings: (fetcher, nulled path suffix, summary key, why it is right). Anything else is new.
EXPECTED = [
    ("access_review", "*.permission", "teams_with_admin", "required in the team schema"),
    ("access_review", "*.slug", "teams_with_admin", "required in the team schema"),
    ("branch_protection", "*.type", "blocking_force_push", "required on every rule"),
    ("code_scanning_alerts", "*.rule", "open_by_security_severity", "required on an alert"),
    ("code_scanning_alerts", "*.state", "open_by_security_severity", "required on an alert"),
    ("code_scanning_alerts", "*.rule.security_severity_level", "open_by_security_severity",
     "null for quality-only rules; counted in open_without_security_severity"),
    ("dependabot_alerts", "*.state", "open_by_severity", "required on an alert"),
    ("dependabot_alerts", "*.state", "open_older_than_days", "required and non-null on an alert"),
    ("dependabot_alerts", "*.created_at", "open_older_than_days", "required and non-null on an alert"),
    ("code_scanning_alerts", "*.state", "open_older_than_days", "nullable; counted in state_unknown_total"),
    ("code_scanning_alerts", "*.rule", "open_older_than_days", "required and non-null on an alert"),
    ("code_scanning_alerts", "*.rule.security_severity_level", "open_older_than_days",
     "null for quality-only rules; counted in open_without_security_severity"),
    ("code_scanning_alerts", "*.created_at", "open_older_than_days", "required and non-null on an alert"),
    ("code_scanning_alerts", "*.created_at", "repositories_analysis_stale",
     "required and non-null on an analysis; a null one lists the repository as not analysed"),
    ("org_security_settings", "security_and_analysis", "", "absent without admin; listed in repositories_settings_unreadable"),
    ("secret_scanning", "security_and_analysis", "", "absent without admin; listed in settings_unreadable"),
    ("pull_request_checks", "contexts.nodes.*.name", "merged_with_failed_checks", "CheckRun.name is non-null"),
    ("pull_request_checks", "contexts.nodes.*.status", "merged_with_failed_checks", "CheckRun.status is non-null"),
    ("pull_request_checks", "contexts.nodes.*.conclusion", "merged_with_failed_checks",
     "a completed check without a conclusion is checks_unknown, and fails a required-check gate"),
    ("pull_request_checks", "__typename", "", "GraphQL always answers __typename"),
    ("pull_request_checks", "statusCheckRollup", "merged_with_failed_checks",
     "null is GitHub's 'no checks'; the PR moves to merged_without_checks"),
    ("pull_request_checks", "statusCheckRollup.contexts", "merged_with_failed_checks",
     "non-null on a rollup; read as no checks, so the PR moves to merged_without_checks"),
    ("non_user_credentials", "read_only", "write_deploy_keys", "null is listed in deploy_keys_access_unknown"),
    ("non_user_credentials", "config", "webhooks_insecure_ssl", "null is counted in webhooks_tls_unknown"),
    ("non_user_credentials", "config.insecure_ssl", "webhooks_insecure_ssl", "null is counted in webhooks_tls_unknown"),
    ("repository_inventory", "visibility", "by_visibility",
     "counted as unknown, never as private; the record's public is null"),
    ("pull_request_checks", "pullRequests.nodes.*.mergedAt", "",
     "non-null on every MERGED pull request, the only state the query asks for"),
    ("actions_security", "enabled", "", "required in actions-repository-permissions"),
    ("actions_security", "allowed_actions", "", "absent only when Actions is off, and then nothing runs"),
    ("actions_security", "can_approve_pull_request_reviews", "", "required in actions-get-default-workflow-permissions"),
    ("actions_security", "default_workflow_permissions", "", "required in actions-get-default-workflow-permissions"),
    ("actions_security", ".object", "", "null object or entries: no .github/workflows directory, so no workflows"),
    ("actions_security", ".object.entries", "", "Tree.entries null is an empty tree"),
    ("actions_security", ".entries.*.name", "", "TreeEntry.name is non-null"),
    ("actions_security", ".entries.*.type", "", "TreeEntry.type is non-null"),
    ("actions_security", ".entries.*.object", "", "null only for a submodule entry, which is not a workflow"),
    ("actions_security", ".entries.*.object.text", "", "null text is listed in workflows_unparsed"),
    ("branch_protection", "*.ruleset_id", "", "required on every rule"),
    ("branch_protection", "bypass_actors", "with_always_bypass", "null is listed in bypass_actors_unreadable"),
    ("branch_protection", "bypass_actors.*.bypass_mode", "", "required on a bypass actor"),
    ("deployment_controls", "*.state", "production_deployments_by_state", "required on a deployment status"),
    ("deployment_controls", "can_admins_bypass", "", "null is listed in production_admin_bypass_unknown"),
    ("release_integrity", "*.assets", "", "required on a release"),
    ("release_integrity", "*.assets.*.digest", "", "null is listed in release_assets_without_digest"),
    ("release_integrity", "*.immutable", "", "null is listed in releases_immutability_unknown"),
    ("release_integrity", "attestations", "", "required in the attestations answer"),
    ("release_integrity", "enabled", "", "required in check-immutable-releases"),
    ("release_integrity", "conditions", "release_tags_not_locked",
     "a ruleset whose reach cannot be read moves the tag to release_tags_lock_unknown"),
    ("release_integrity", "conditions.ref_name", "release_tags_not_locked", "as conditions"),
    ("release_integrity", "conditions.ref_name.include", "release_tags_not_locked", "as conditions"),
    ("significant_change_notifications", "nodes.*.body", "", "a null body is an empty description: nothing is flagged"),
    ("vulnerability_disclosure", "visibility", "", "required on a repository"),
    ("vulnerability_disclosure", "*.state", "", "required on an advisory"),
    ("vulnerability_disclosure", "*.created_at", "oldest_unresolved_days", "null is listed in unresolved_age_unknown"),
]

# Summary keys where a larger number or a longer list is better, not worse.
MORE_IS_BETTER = ("requiring_", "total", "fixed_", "members_total", "deploy_keys_allowed", "known_exploited_checked",
                  "merged_pull_requests", "apps_installed", "teams_total", "owners", "tools",
                  "_with_build_provenance", "repositories_with_private_reporting", "repositories_with_immutable_releases",
                  "repositories_with_actions")


def paths(value: Any, prefix: Tuple = ()) -> Iterable[Tuple]:
    """Field paths with list indices generalised to '*'."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield prefix + (k,)
            yield from paths(v, prefix + (k,))
    elif isinstance(value, list):
        for item in value:
            yield from paths(item, prefix + ("*",))


def null_at(value: Any, path: Tuple) -> None:
    if not path:
        return
    head, rest = path[0], path[1:]
    if head == "*" and isinstance(value, list):
        for item in value:
            null_at(item, rest) if rest else None
    elif isinstance(value, dict) and head in value:
        if rest:
            null_at(value[head], rest)
        else:
            value[head] = None


def better(key: str, before: Any, after: Any) -> bool:
    if any(key.startswith(p) or key.endswith(p) for p in MORE_IS_BETTER):
        return False
    if isinstance(before, bool) or isinstance(after, bool):
        return before is not True and after is True
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        return after < before
    if isinstance(before, list) and isinstance(after, list):
        return len(after) < len(before)
    if isinstance(before, dict) and isinstance(after, dict):
        return any(better(f"{key}.{k}", before.get(k), after.get(k)) for k in before)
    return False


def sweep_fetcher(fetcher: str) -> Tuple[int, List[str]]:
    cassette = json.loads((sweep.CASSETTES / f"{fetcher}.json").read_text())
    _, base, _ = sweep.run_once(fetcher, cassette)
    findings, runs = [], 0
    for k, entry in cassette["entries"].items():
        if entry["status"] >= 300 or entry["body"] is None:
            continue
        for path in dict.fromkeys(paths(entry["body"])):
            mutated = copy.deepcopy(cassette)
            null_at(mutated["entries"][k]["body"], path)
            runs += 1
            try:
                code, ev, _ = sweep.run_once(fetcher, mutated)
            except Exception as exc:  # noqa: BLE001 - a crash is a finding too
                findings.append(f"{fetcher}: CRASH nulling {'.'.join(map(str, path))} in {k}: {exc!r}")
                continue
            if code != 0:
                continue  # the run failed loudly; an emptier summary on a failed run is not a silent pass
            dotted = ".".join(map(str, path))
            for key, before in base.get("summary", {}).items():
                expected = any(f == fetcher and dotted.endswith(p) and k in key for f, p, k, _ in EXPECTED)
                if not expected and better(key, before, ev.get("summary", {}).get(key)):
                    findings.append(f"{fetcher}: nulling {'.'.join(map(str, path))} in {k} -> {key}: "
                                    f"{json.dumps(before)[:60]} -> {json.dumps(ev['summary'].get(key))[:60]}")
    return runs, findings


def main() -> int:
    names = sys.argv[1:] or sorted(p.stem for p in sweep.CASSETTES.glob("*.json"))
    total, findings = 0, []
    for name in names:
        runs, found = sweep_fetcher(name)
        total += runs
        findings += found
        print(f"{name}: {runs} nulled fields, {len(found)} finding(s)", flush=True)
    for f in findings:
        print("  " + f)
    print(f"{total} runs, {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
