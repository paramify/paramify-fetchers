"""GitHub fetchers replayed against responses recorded from a live organization.

The cassettes (tests/fixtures/github_cassettes/) were recorded by
tools/github_cassette.py from a sandbox organization staged with known
compliant and non-compliant repositories. Replay fakes only the socket, so the
shared client and every fetcher run as they do live. Each test pins a fact
that was staged on purpose; the fault sweep breaks every recorded call.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CASSETTES = ROOT / "tests" / "fixtures" / "github_cassettes"
_spec = importlib.util.spec_from_file_location("github_fault_sweep", ROOT / "tools" / "github_fault_sweep.py")
sweep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sweep)
FETCHERS = sorted(p.stem for p in CASSETTES.glob("*.json"))


def replay(fetcher, fault=None):
    cassette = json.loads((CASSETTES / f"{fetcher}.json").read_text())
    code, evidence, calls = sweep.run_once(fetcher, cassette, fault)
    return cassette, code, evidence, calls


@pytest.mark.parametrize("fetcher", FETCHERS)
def test_replay_reproduces_the_recorded_run(fetcher):
    cassette, code, evidence, calls = replay(fetcher)
    assert code == cassette["exit_code"]
    assert set(calls) <= set(cassette["entries"]), "a call the recording never made: the run is not deterministic"
    assert evidence["metadata"]["organization"] == cassette["env"]["GITHUB_ORG"]


def test_every_github_fetcher_has_a_cassette():
    built = sorted(p.parent.name for p in (ROOT / "fetchers" / "github").glob("*/fetcher.py"))
    assert FETCHERS == built


@pytest.mark.parametrize("fetcher", FETCHERS)
def test_a_failed_call_never_exits_clean(fetcher):
    """A sample of the sweep that runs in CI: the first and last recorded call, each fault."""
    cassette, _, _, calls = replay(fetcher)
    for k in dict.fromkeys([calls[0], calls[-1]]):
        for name, fault in sweep.FAULTS.items():
            code, _, _ = sweep.run_once(fetcher, cassette, (k, fault))
            tolerated = any(frag in k and f == name for frag, f, _ in sweep.TOLERATED)
            assert code != 0 or tolerated, f"{name} on {k} exited 0"


def _summary(fetcher):
    return replay(fetcher)[2]["summary"]


# --- the staged estate, as recorded ------------------------------------------------------

def test_branch_protection_on_the_recorded_sandbox():
    s = _summary("branch_protection")
    assert s["requiring_approval"] == 1 and s["requiring_status_checks"] == 1
    assert {"fetcher-test-disabled-rules", "fetcher-test-evaluate-rules"} <= set(s["with_rulesets_not_enforced"])
    assert "fetcher-test-protected" not in s["without_approval"]


def test_pull_requests_on_the_recorded_sandbox():
    s = _summary("pull_request_checks")
    assert s["merged_pull_requests"] == 3 and s["merged_without_human_approval"] == 3  # one bot-approved
    assert s["merged_without_approval"] == 2 and s["merged_with_failed_checks"] == 1
    assert s["merged_with_failed_required_checks"] == 0  # the failing check is optional where it ran


def test_dependabot_on_the_recorded_sandbox():
    s = _summary("dependabot_alerts")
    assert s["open_total"] == 56 and s["open_by_severity"]["critical"] == 7
    assert s["repositories_alerts_disabled"] == ["fetcher-test-scanning-off"]
    assert "fetcher-test-vulnerable" not in s["repositories_dependency_graph_disabled"]


def test_code_scanning_on_the_recorded_sandbox():
    s = _summary("code_scanning_alerts")
    assert s["open_by_security_severity"]["high"] == 1 and s["tools"] == ["CodeQL"]
    assert "fetcher-test-vulnerable" not in s["repositories_not_analysed"]


def test_secret_scanning_on_the_recorded_sandbox():
    s = _summary("secret_scanning")
    assert s["open_total"] == 0 and s["push_protection_bypasses"] == 1  # the bypass resolved its own alert
    assert s["resolved_by_resolution"] == {"used_in_tests": 1}


def test_org_settings_on_the_recorded_sandbox():
    s = _summary("org_security_settings")
    assert s["two_factor_required"] is False and s["actions_can_approve_pull_requests"] is True
    assert s["security_configurations"] == 1 and len(s["repositories_without_security_configuration"]) == 8


def test_access_on_the_recorded_sandbox():
    s = _summary("access_review")
    assert s["owners"] == ["sandbox-owner"] and s["teams_with_admin"] == ["fetcher-test-admins"]
    assert s["pending_invitations"] == 1


def test_credentials_on_the_recorded_sandbox():
    s = _summary("non_user_credentials")
    assert s["write_deploy_keys"] == ["fetcher-test-unprotected:fetcher-test-rw"] and s["deploy_keys_total"] == 2
    assert s["webhooks_insecure_ssl"] == 1 and s["webhooks_without_secret"] == 1  # staged on purpose
    assert s["fine_grained_tokens"] is None  # recorded with a personal token: the list is GitHub Apps only


def test_inventory_on_the_recorded_sandbox():
    from framework import inventory
    _, code, ev, _ = replay("repository_inventory")
    assert inventory.check(ev, code) == {"records": 8, "records_included": True, "complete": True}
    assert len({r["unique_asset_identifier"] for r in ev["data"]}) == 8
    assert ev["metadata"]["custom_properties_available"] is True and ev["metadata"]["custom_properties"] == []


def test_actions_security_on_the_recorded_sandbox():
    s = _summary("actions_security")
    assert s["organization_default_workflow_permissions"] == "write" and s["organization_sha_pinning_required"] is False
    assert s["action_references_unpinned"] == 3 and s["self_hosted_runners_organization"] == 0
    assert s["workflows_on_self_hosted_runners"] == ["fetcher-test-actions:pwn-request.yml"]


def test_deployments_on_the_recorded_sandbox():
    s = _summary("deployment_controls")
    assert s["production_environments"] == ["fetcher-test-deploy:prod-eu", "fetcher-test-deploy:production"]
    assert s["production_without_required_reviewers"] == ["fetcher-test-deploy:prod-eu"]
    assert s["production_deployable_from_any_branch"] == ["fetcher-test-deploy:prod-eu"]
    assert s["production_deployments"] == 3 and len(s["production_deployments_not_by_actions"]) == 2  # made by the API
    assert s["production_deployments_by_state"] == {"failure": 1, "success": 2}


def test_releases_on_the_recorded_sandbox():
    s = _summary("release_integrity")
    assert s["release_assets"] == 3 and s["release_assets_with_build_provenance"] == 2
    assert s["release_assets_without_build_provenance"] == ["fetcher-test-releases@v0.1.1:artifact.txt"]
    assert s["releases_not_immutable"] == ["fetcher-test-releases@v0.1.1", "fetcher-test-releases@v0.1.2"]
    assert s["release_tags_not_locked"] == ["fetcher-test-releases@v0.1.2"]  # v0.1.1 has a tag ruleset, v0.1.3 is immutable


def test_significant_changes_on_the_recorded_sandbox():
    s = _summary("significant_change_notifications")
    assert s["flagged_count"] == 3 and s["schema_valid_count"] == 2 and s["schema_invalid_count"] == 1
    assert s["scn_cso_inf_incomplete_count"] == 1 and s["unticked_marker_count"] == 1
    assert s["routine_recurring_count"] == 1


def test_vulnerability_disclosure_on_the_recorded_sandbox():
    s = _summary("vulnerability_disclosure")
    assert s["advisories_by_state"] == {"draft": 1} and s["repositories_with_private_reporting"] == 1
    assert s["advisories_awaiting_resolution"] == ["fetcher-test-protected:GHSA-6c9w-4gxw-x9fx"]
    assert "fetcher-test-scn" not in s["repositories_without_security_policy"]


def test_codeowners_and_bypasses_on_the_recorded_sandbox():
    s = _summary("branch_protection")
    assert s["code_owner_review_without_valid_codeowners"] == ["fetcher-test-scn"]
    assert s["with_ruleset_bypasses_last_month"] == ["fetcher-test-scn"] and s["ruleset_bypasses_unreadable"] == []


def test_audit_log_on_a_free_organization():
    cassette, code, _, calls = replay("audit_log")
    assert code == 1 and not any("/audit-log" in k for k in calls)  # refused from the plan, before the call


def _nulled(fetcher, path_fragment, edit):
    """Replay with one recorded answer edited in place."""
    cassette = json.loads((CASSETTES / f"{fetcher}.json").read_text())
    for k, entry in cassette["entries"].items():
        if path_fragment in k and entry["body"] is not None:
            edit(entry["body"])
    code, evidence, _ = sweep.run_once(fetcher, cassette)
    return code, evidence["summary"]


def test_unreadable_fields_are_unknown_never_dropped():
    def no_admin_bypass(body):
        for env in body["environments"]:
            env["can_admins_bypass"] = None
    _, s = _nulled("deployment_controls", "/environments?", no_admin_bypass)
    assert s["production_admins_can_bypass"] == [] and len(s["production_admin_bypass_unknown"]) == 2

    def no_immutable(body):
        for rel in body:
            rel["immutable"] = None
    _, s = _nulled("release_integrity", "/releases?", no_immutable)
    assert s["releases_not_immutable"] == [] and len(s["releases_immutability_unknown"]) == 3

    def no_created(body):
        for a in body:
            a["created_at"] = None
    _, s = _nulled("vulnerability_disclosure", "/security-advisories?", no_created)
    assert s["oldest_unresolved_days"] is None
    assert s["unresolved_age_unknown"] == ["fetcher-test-protected:GHSA-6c9w-4gxw-x9fx"]

    def no_actors(body):
        if isinstance(body, dict):
            body.pop("bypass_actors", None)
    _, s = _nulled("branch_protection", "/rulesets/", no_actors)
    assert s["with_always_bypass"] == [] and "fetcher-test-scn" in s["bypass_actors_unreadable"]
    assert "fetcher-test-disabled-rules" not in s["bypass_actors_unreadable"]  # not enforced: no bypass to have


def _faulted(fetcher, path_fragment, fault="500", env=None):
    """Replay with the first recorded call whose key holds path_fragment answering `fault`."""
    cassette = json.loads((CASSETTES / f"{fetcher}.json").read_text())
    cassette["env"].update(env or {})
    key = next(k for k in cassette["entries"] if path_fragment in k)
    code, evidence, _ = sweep.run_once(fetcher, cassette, (key, sweep.FAULTS[fault]))
    return code, evidence["summary"], dict(sweep.LAST_STATUS)


@pytest.mark.parametrize("fetcher,fragment,repo", [
    ("deployment_controls", "fetcher-test-deploy/environments?", "fetcher-test-deploy"),
    ("deployment_controls", "/deployment_protection_rules", "fetcher-test-deploy"),
    ("deployment_controls", "fetcher-test-deploy/deployments?", "fetcher-test-deploy"),
    ("deployment_controls", "/statuses", "fetcher-test-deploy"),
    ("deployment_controls", "POST /graphql", "fetcher-test-deploy"),
    ("release_integrity", "fetcher-test-releases/immutable-releases", "fetcher-test-releases"),
    ("release_integrity", "fetcher-test-releases/attestations/", "fetcher-test-releases"),
    ("vulnerability_disclosure", "fetcher-test-protected/private-vulnerability-reporting", "fetcher-test-protected"),
])
@pytest.mark.parametrize("fault", ["404", "500"])
def test_a_failed_call_marks_the_repository_not_collected(fetcher, fragment, repo, fault):
    if fault == "404" and "/attestations/" in fragment:
        pytest.skip("404 is no attestation: reported as without build provenance")
    code, s, _ = _faulted(fetcher, fragment, fault)
    assert code != 0 and repo in s["not_collected"]


@pytest.mark.parametrize("fragment", ["/organization-roles?", "/users?", "/teams?"])
@pytest.mark.parametrize("fault", ["404", "500"])
def test_unreadable_organization_roles_are_unknown_and_fail(fragment, fault):
    if not any(fragment in k and "organization-roles" in k
               for k in json.loads((CASSETTES / "access_review.json").read_text())["entries"]):
        pytest.skip("no role holds users or teams in the recording")
    code, s, _ = _faulted("access_review", "organization-roles" if fragment == "/organization-roles?" else fragment)
    assert code != 0 and s["organization_role_holders"] is None


def test_recorded_fields_reach_the_evidence():
    _, _, ev, _ = replay("deployment_controls")
    envs = {e["name"]: e for r in ev["repositories"] if r["collected"] for e in r["environments"]}
    assert all(x["reviewer"] for x in envs["production"]["required_reviewers"])
    assert all(d["creator"] for d in envs["production"]["deployments"])
    _, _, ev, _ = replay("release_integrity")
    assert ev["summary"]["organization_immutable_releases"] == "none"
    rels = ev["repositories"][next(i for i, r in enumerate(ev["repositories"]) if r.get("releases"))]["releases"]
    assert all(r["author"] for r in rels) and all(a["uploader"] for r in rels for a in r["assets"])
    assert all(rs["rule_types"] for r in ev["repositories"] if r["collected"] for rs in r["tag_rulesets"])
    _, _, ev, _ = replay("branch_protection")
    assert ev["summary"]["requiring_pull_request"] == 2
    assert any(rs["rule_types"] for r in ev["repositories"] for rs in r.get("rulesets") or [])
    s = _summary("vulnerability_disclosure")
    assert "fetcher-test-protected" not in s["public_repositories_without_private_reporting"]  # it has reporting on
    s = _summary("significant_change_notifications")
    assert s["by_change_type"] == {"Adaptive": 2, "unspecified": 1} and s["notifications_with_parse_notes"] == 3


def test_a_ruleset_of_unknown_reach_leaves_immutable_releases_out_of_lock_unknown():
    def no_conditions(body):
        if isinstance(body, dict):
            body["conditions"] = None
    _, s = _nulled("release_integrity", "/rulesets/", no_conditions)
    assert s["release_tags_lock_unknown"] == ["fetcher-test-releases@v0.1.1", "fetcher-test-releases@v0.1.2"]


def test_an_empty_repository_is_reported_empty():
    def empty(body):
        for r in body if isinstance(body, list) else [body]:
            if isinstance(r, dict) and r.get("name") == "fetcher-test-unprotected":
                r["size"], r["pushed_at"] = 0, None
    _, s = _nulled("branch_protection", "/repos/Fetcher-Tester/fetcher-test-unprotected", empty)
    assert s["empty"] == ["fetcher-test-unprotected"]


@pytest.mark.parametrize("env,code_name", [
    ({"GITHUB_DEPLOYMENT_DAYS_BACK": "1"}, None),
    ({"GITHUB_MAX_DEPLOYMENTS": "1"}, "partial_failure"),  # 1 is allowed; three deployments overflow it
])
def test_deployment_limits_at_their_lowest(env, code_name):
    cassette = json.loads((CASSETTES / "deployment_controls.json").read_text())
    cassette["env"].update(env)
    sweep.run_once("deployment_controls", cassette)
    assert sweep.LAST_STATUS.get("code") == code_name
