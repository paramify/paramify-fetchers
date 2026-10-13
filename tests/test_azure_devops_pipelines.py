"""azure_devops_pipelines, driven without Azure DevOps.

FakeADO stands in for requests.Session and serves one organization with a web
project: a YAML pipeline whose preview run returns its final YAML, an infra
pipeline whose preview is refused so its file is read from the repo, a classic
pipeline, runs, test runs, two environments with checks and deployments, and
branch policies. Bodies follow the Azure DevOps REST 7.1 reference samples.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "devops_pipelines" / "fetcher.py"
spec = importlib.util.spec_from_file_location("azure_devops_pipelines_under_test", FETCHER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
dr = sys.modules["devops_rest"]

ORG = "https://dev.azure.com/contoso"
P = "p-web"
NOW = datetime.now(timezone.utc)


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")


FINAL_YAML = """
stages:
- stage: Build
  jobs:
  - job: Build
    steps:
    - task: DotNetCoreCLI@2
      displayName: Unit tests
      inputs:
        command: test
    - task: PublishTestResults@2
      inputs:
        testResultsFiles: '**/TEST-*.xml'
    - task: AdvancedSecurity-Codeql-Analyze@1
    - task: CmdLine@2
      displayName: Sign image
      inputs:
        script: cosign sign --key azurekms://kv/key $(image)
    - task: ManifestGeneratorTask@0
      inputs:
        BuildDropPath: $(Build.ArtifactStagingDirectory)
- stage: Deploy
  jobs:
  - deployment: DeployWeb
    environment:
      name: prod
    strategy:
      runOnce:
        preDeploy:
          steps:
          - task: Notation@0
            inputs:
              command: verify
        deploy:
          steps:
          - task: AzureWebApp@1
            displayName: Deploy to test slot
            inputs:
              appName: web
"""

INFRA_RAW_YAML = """
trigger: [main]
stages:
- stage: Plan
  jobs:
  - job: Plan
    steps:
    - script: terraform plan -out tfplan
- stage: Apply
  jobs:
  - deployment: Apply
    environment: prod.vm1
    strategy:
      runOnce:
        deploy:
          steps:
          - task: TerraformTaskV4@4
            inputs:
              command: apply
"""


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body = status, body
        self.headers = headers or {}
        self.text = json.dumps(body)
        self.reason = "OK" if status < 400 else "Error"

    def json(self):
        return self._body


def err(status, message, type_key="Exception"):
    return Resp(status, {"$id": "1", "message": message, "typeKey": type_key, "errorCode": 0})


def definition(id_, name, process, repo):
    return {"id": id_, "name": name, "path": "\\", "queueStatus": "enabled", "process": process,
            "repository": repo, "type": "build"}


WEB_REPO = {"id": "r-web", "name": "web", "type": "TfsGit", "defaultBranch": "refs/heads/main"}
INFRA_REPO = {"id": "r-infra", "name": "infra", "type": "TfsGit", "defaultBranch": "refs/heads/main"}


def build(id_, definition_id, result, branch="refs/heads/main", hours=1):
    return {"id": id_, "buildNumber": f"2026.{id_}", "definition": {"id": definition_id}, "result": result,
            "reason": "individualCI", "sourceBranch": branch, "sourceVersion": f"sha{id_}",
            "requestedFor": {"displayName": "Pipeline Bot"}, "finishTime": ago(hours=hours)}


def ado_test_run(id_, build_id, total, passed, failed, definition_id=None):
    run = {"id": id_, "name": f"run {id_}", "state": "Completed", "isAutomated": True,
           "build": {"id": str(build_id)}, "totalTests": total, "passedTests": passed,
           "unanalyzedTests": failed, "completedDate": ago(hours=2)}
    if definition_id:
        run["buildConfiguration"] = {"buildDefinitionId": definition_id}
    return run


class FakeADO:
    """Routes by URL path; a route is a Resp, a list of Resps by continuation token, or a callable."""

    def __init__(self):
        b = f"/contoso/{P}"
        self.calls = []
        self.routes = {
            "/contoso/_apis/projects": Resp(body={"value": [{"id": P, "name": "Web", "state": "wellFormed"}]}),
            f"{b}/_apis/build/generalsettings": Resp(body={
                "disableClassicPipelineCreation": True, "enforceJobAuthScope": True,
                "enforceSettableVar": True, "publishPipelineMetadata": False, "statusBadgesArePrivate": True}),
            f"{b}/_apis/build/definitions": {
                None: Resp(body={"value": [
                    definition(10, "web-ci-cd", {"type": 2, "yamlFilename": "/azure-pipelines.yml"}, WEB_REPO)]},
                    headers={"x-ms-continuationtoken": "page2"}),
                "page2": Resp(body={"value": [
                    definition(11, "infra", {"type": 2, "yamlFilename": "/infra/pipeline.yml"}, INFRA_REPO),
                    definition(13, "legacy", {"type": 1}, WEB_REPO)]}),
            },
            f"{b}/_apis/pipelines/10/preview": Resp(body={"finalYaml": FINAL_YAML}),
            f"{b}/_apis/pipelines/11/preview": err(400, "A value for the 'region' parameter must be provided.",
                                                   "PipelineValidationException"),
            f"{b}/_apis/git/repositories/r-infra/items": Resp(body={"path": "/infra/pipeline.yml",
                                                                    "content": INFRA_RAW_YAML}),
            f"{b}/_apis/build/builds": Resp(body={"value": [
                build(100, 10, "succeeded", hours=3), build(101, 10, "failed", hours=5),
                build(102, 11, "succeeded", "refs/heads/feature/x", hours=6)]}),
            f"{b}/_apis/test/runs": self.test_runs,
            f"{b}/_apis/distributedtask/environments": Resp(body={"value": [
                {"id": 2, "name": "staging", "resources": []},
                {"id": 1, "name": "prod", "resources": [{"id": 5, "name": "vm1", "type": "virtualMachine"}]}]}),
            f"{b}/_apis/pipelines/checks/configurations": self.checks,
            f"{b}/_apis/distributedtask/environments/1/environmentdeploymentrecords": {
                None: Resp(body={"value": [
                    {"id": 9, "environmentId": 1, "definition": {"id": 10, "name": "web-ci-cd"},
                     "owner": {"id": 100, "name": "2026.100"}, "stageName": "Deploy", "jobName": "DeployWeb",
                     "result": "succeeded", "queueTime": ago(hours=3), "startTime": ago(hours=3),
                     "finishTime": ago(hours=2)},
                    {"id": 8, "environmentId": 1, "definition": {"id": 11, "name": "infra"},
                     "owner": {"id": 102, "name": "2026.102"}, "stageName": "Apply", "jobName": "Apply",
                     "result": "failed", "queueTime": ago(hours=6), "startTime": ago(hours=6)},
                    {"id": 7, "environmentId": 1, "definition": {"id": 10, "name": "web-ci-cd"},
                     "owner": {"id": 50, "name": "2026.50"}, "result": "succeeded", "queueTime": ago(days=90)}]},
                    headers={"x-ms-continuationtoken": "older"}),
            },
            f"{b}/_apis/distributedtask/environments/2/environmentdeploymentrecords": Resp(body={"value": []}),
            f"{b}/_apis/git/repositories": Resp(body={"value": [
                {"id": "r-web", "name": "web", "defaultBranch": "refs/heads/main"},
                {"id": "r-infra", "name": "infra", "defaultBranch": "refs/heads/main"},
                {"id": "r-old", "name": "old", "defaultBranch": "refs/heads/master", "isDisabled": True}]}),
            f"{b}/_apis/policy/configurations": Resp(body={"value": [
                {"id": 1, "isEnabled": True, "isBlocking": True, "isDeleted": False,
                 "type": {"id": mod.MIN_REVIEWERS_POLICY, "displayName": "Minimum number of reviewers"},
                 "settings": {"minimumApproverCount": 2, "creatorVoteCounts": False, "resetOnSourcePush": True,
                              "scope": [{"repositoryId": "r-web", "refName": "refs/heads/main", "matchKind": "Exact"}]}},
                {"id": 2, "isEnabled": True, "isBlocking": True, "isDeleted": False,
                 "type": {"id": mod.BUILD_POLICY, "displayName": "Build"},
                 "settings": {"buildDefinitionId": 10, "validDuration": 720, "manualQueueOnly": False,
                              "scope": [{"repositoryId": None, "refName": "refs/heads/", "matchKind": "Prefix"}]}},
                {"id": 3, "isEnabled": True, "isBlocking": True, "isDeleted": True,
                 "type": {"id": mod.MIN_REVIEWERS_POLICY},
                 "settings": {"minimumApproverCount": 1,
                              "scope": [{"repositoryId": "r-infra", "refName": "refs/heads/main", "matchKind": "Exact"}]}},
                {"id": 4, "isEnabled": False, "isBlocking": True, "isDeleted": False,
                 "type": {"id": mod.MIN_REVIEWERS_POLICY},
                 "settings": {"minimumApproverCount": 1,
                              "scope": [{"repositoryId": "r-infra", "refName": "refs/heads/main", "matchKind": "Exact"}]}},
            ]}),
        }

    @staticmethod
    def test_runs(params, body):
        # Every slice answers the same runs; the fetcher must not double count them.
        return Resp(body={"value": [
            ado_test_run(500, 100, 120, 118, 2, definition_id=10),
            ado_test_run(501, 101, 120, 100, 20),
            ado_test_run(502, 9999, 5, 5, 0)]})

    @staticmethod
    def checks(params, body):
        if params.get("resourceId") == 2:
            return Resp(body={"value": []})
        return Resp(body={"value": [
            {"id": 22, "type": {"id": "8c6f20a7-a545-4486-9777-f762fafe0d4d", "name": "Approval"}, "timeout": 43200,
             "resource": {"type": "environment", "id": "1"}, "modifiedOn": ago(days=40),
             "settings": {"approvers": [{"displayName": "Release Managers", "id": "g1"}], "minRequiredApprovers": 1,
                          "requesterCannotBeApprover": True}},
            {"id": 23, "type": {"id": "fe1de3ee-a436-41b4-bb20-f6eb4cb879a7", "name": "Task Check"}, "timeout": 1440,
             "settings": {"displayName": "Branch control",
                          "definitionRef": {"id": "86b05a0c-73e6-4f7d-b3cf-e38f3b39a75b",
                                            "name": "evaluatebranchProtection", "version": "0.0.1"},
                          "inputs": {"allowedBranches": "refs/heads/main", "ensureProtectionOfBranch": "true",
                                     "allowUnknownStatusBranch": "false"}}},
            {"id": 24, "type": {"name": "ExtendsCheck"}, "isDisabled": True,
             "settings": {"extendsChecks": [{"repositoryType": "git", "repositoryName": "templates",
                                             "repositoryRef": "refs/heads/main", "templatePath": "deploy.yml"}]}},
        ]})

    def request(self, method, url, headers=None, params=None, timeout=None, allow_redirects=True, json=None):
        params = dict(params or {})
        path = urlsplit(url).path
        self.calls.append((method, path, params, json))
        route = self.routes.get(path)
        if route is None:
            raise AssertionError(f"unexpected request {method} {path} {params}")
        if callable(route):
            return route(params, json)
        if isinstance(route, dict):
            token = params.get("continuationToken")
            if token not in route:
                raise AssertionError(f"unexpected page {token!r} of {path}")
            return route[token]
        return route


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    for key in ("AZURE_DEVOPS_PROJECTS", mod.LOOKBACK_ENV):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AZURE_DEVOPS_ORG_URL", ORG)
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "pat")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(dr.time, "sleep", lambda s: None)


def run(tmp_path, fake=None):
    fake = fake or FakeADO()
    code = dr.run_org(fetcher=mod.NAME, logger=mod.logger, collect=mod.collect, session=fake)
    evidence = json.loads((tmp_path / "azure_devops_pipelines_contoso.json").read_text())
    status = tmp_path / "status.json"
    return code, evidence, json.loads(status.read_text()) if status.exists() else None, fake


def pipeline(evidence, name):
    return next(p for p in evidence["results"]["projects"][0]["pipelines"] if p["name"] == name)


def environment(evidence, name):
    return next(e for e in evidence["results"]["projects"][0]["environments"] if e["name"] == name)


# --- collect() end to end ---------------------------------------------------------

def test_collects_the_organization_and_exits_zero(tmp_path):
    code, evidence, status, _ = run(tmp_path)
    assert code == 0 and status is None
    assert evidence["metadata"]["partial_failure"] is False
    s = evidence["summary"]
    assert (s["pipelines_total"], s["yaml_pipelines"], s["classic_pipelines"]) == (3, 2, 1)
    assert s["yaml_pipelines_analyzed"] == 2 and s["yaml_pipelines_with_templates_expanded"] == 1
    assert s["deploying_pipelines"] == 2
    assert s["deploying_pipelines_with_tests"] == 1
    assert s["deploying_pipelines_testing_before_deploy"] == 1
    assert s["deploying_pipelines_without_tests"] == ["Web/infra"]
    assert s["pipelines_with_security_scan"] == 1
    assert s["pipelines_with_iac_validation"] == 1 and s["pipelines_deploying_infrastructure"] == 1
    assert (s["pipelines_signing_artifacts"], s["pipelines_verifying_signatures"], s["pipelines_generating_sbom"]) == (1, 1, 1)
    assert s["projects_with_classic_pipeline_creation_disabled"] == 1


def test_final_yaml_comes_from_the_preview_run_without_queueing(tmp_path):
    _, evidence, _, fake = run(tmp_path)
    web = pipeline(evidence, "web-ci-cd")
    assert web["yaml_source"] == "preview" and web["templates_expanded"] is True
    assert len(web["yaml_sha256"]) == 64
    previews = [c for c in fake.calls if c[1].endswith("/_apis/pipelines/10/preview")]
    assert previews == [("POST", f"/contoso/{P}/_apis/pipelines/10/preview", {"api-version": "7.1"}, {"previewRun": True})]
    assert web["analysis"]["environments"] == ["prod"]
    assert [s["step"] for s in web["analysis"]["steps"]["test"]] == ["Unit tests", "PublishTestResults@2"]
    assert web["analysis"]["steps"]["signature_verification"][0]["job"] == "DeployWeb"


def test_a_refused_preview_falls_back_to_the_file_on_the_default_branch(tmp_path):
    code, evidence, _, fake = run(tmp_path)
    infra = pipeline(evidence, "infra")
    assert code == 0
    assert infra["yaml_source"] == "repository" and infra["templates_expanded"] is False
    assert "(400) PipelineValidationException" in infra["yaml_error"]
    assert infra["analysis"]["environments"] == ["prod"]
    item = next(c for c in fake.calls if c[1].endswith("/items"))
    assert item[2]["path"] == "/infra/pipeline.yml" and item[2]["versionDescriptor.version"] == "main"


def test_classic_pipelines_are_listed_not_analysed(tmp_path):
    _, evidence, _, fake = run(tmp_path)
    legacy = pipeline(evidence, "legacy")
    assert legacy["type"] == "classic" and legacy["analysis"] is None
    assert not any(c[1].endswith("/pipelines/13/preview") for c in fake.calls)


def test_runs_and_test_results_attach_to_their_pipeline_once(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    web = pipeline(evidence, "web-ci-cd")
    assert web["runs"]["in_window"] == 2 and web["runs"]["failed"] == 1
    assert web["runs"]["last"]["source_version"] == "sha100"
    # run 500 by buildConfiguration, run 501 by its build id; each counted once across the 7-day slices
    assert web["test_runs"] == {**web["test_runs"], "in_window": 2, "total_tests": 240, "passed_tests": 218,
                                "failed_tests": 22}
    project = evidence["results"]["projects"][0]
    assert project["test_runs_in_window"] == 3 and project["test_runs_unattributed"] == 1


def test_test_runs_are_queried_in_slices_of_at_most_seven_days(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.LOOKBACK_ENV, "30")
    _, _, _, fake = run(tmp_path)
    slices = [c[2] for c in fake.calls if c[1].endswith("/_apis/test/runs")]
    assert len(slices) == 5
    spans = [dr.parse_time(s["maxLastUpdatedDate"]) - dr.parse_time(s["minLastUpdatedDate"]) for s in slices]
    assert all(span <= timedelta(days=7) for span in spans)
    assert all(a["maxLastUpdatedDate"] == b["minLastUpdatedDate"] for a, b in zip(slices, slices[1:]))


def test_environment_checks_and_deployments_carry_provenance_and_test_results(tmp_path):
    _, evidence, _, fake = run(tmp_path)
    prod = environment(evidence, "prod")
    assert prod["approval_required"] and prod["branch_control"]
    assert prod["required_template"] is False  # the only required-template check is disabled
    approval = next(c for c in prod["checks"] if c["kind"] == "approval")
    assert approval["approvers"] == ["Release Managers"] and approval["requester_cannot_be_approver"] is True
    branch = next(c for c in prod["checks"] if c["kind"] == "branch_control")
    assert branch["allowed_branches"] == ["refs/heads/main"] and branch["requires_branch_protection"] is True
    assert prod["deployments_in_window"] == 2
    web_deploy = prod["deployments"][0]
    assert (web_deploy["run_id"], web_deploy["source_version"], web_deploy["from_default_branch"]) == (100, "sha100", True)
    assert (web_deploy["run_test_runs"], web_deploy["run_tests_passed"], web_deploy["run_tests_failed"]) == (1, 118, 2)
    infra_deploy = prod["deployments"][1]
    assert infra_deploy["from_default_branch"] is False and infra_deploy["run_test_runs"] == 0
    # newest first: the 90-day-old record ends the read, so the next page is never requested
    pages = [c for c in fake.calls if c[1].endswith("/environments/1/environmentdeploymentrecords")]
    assert len(pages) == 1
    s = evidence["summary"]
    assert s["environments_without_checks"] == ["Web/staging"]
    assert (s["deployments_in_window"], s["deployments_from_default_branch"], s["deployments_with_test_runs"]) == (2, 1, 1)


def test_default_branch_policies_per_repository(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    repos = {r["name"]: r for r in evidence["results"]["projects"][0]["repositories"]}
    assert set(repos) == {"web", "infra"}  # the disabled repository is left out
    web, infra = repos["web"], repos["infra"]
    assert web["min_reviewers"]["count"] == 2 and web["requires_review"] is True
    assert web["build_validation"] == [{"pipeline_id": 10, "pipeline": "web-ci-cd", "blocking": True,
                                        "valid_duration_minutes": 720, "manual_queue_only": False}]
    assert infra["min_reviewers"] is None and infra["requires_review"] is False  # deleted and disabled policies ignored
    assert infra["requires_build_validation"] is True  # project-wide prefix policy
    assert evidence["summary"]["repositories_without_review_or_build_validation"] == []


def test_project_filter_reports_a_missing_project_as_bad_config(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_PROJECTS", "Web,Ghost")
    code, evidence, status, _ = run(tmp_path)
    assert code == 1 and status["code"] == "bad_config"
    assert evidence["summary"]["projects_collected"] == 1


def test_missing_environment_scope_fails_the_run_and_names_the_scope(tmp_path):
    fake = FakeADO()
    fake.routes[f"/contoso/{P}/_apis/distributedtask/environments"] = err(
        401, "TF400813: The user 'x' is not authorized to access this resource.", "UnauthorizedRequestException")
    code, evidence, status, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "auth_failed"
    failure = evidence["metadata"]["api_failures"][0]
    assert failure["operation"] == "distributedtask.environments.list(Web)"
    assert "TF400813" in failure["message"] and "PAT scope needed: Environment (Read & manage)" in failure["message"]
    assert evidence["summary"]["pipelines_total"] == 3  # the rest is still collected


def test_a_preview_server_error_is_a_collection_failure(tmp_path):
    fake = FakeADO()
    fake.routes[f"/contoso/{P}/_apis/pipelines/10/preview"] = err(500, "boom")
    fake.routes[f"/contoso/{P}/_apis/git/repositories/r-web/items"] = Resp(body={"content": FINAL_YAML})
    code, evidence, status, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "internal_error"
    assert [f["operation"] for f in evidence["metadata"]["api_failures"]] == ["pipelines.preview(Web/web-ci-cd)"]
    web = pipeline(evidence, "web-ci-cd")
    assert web["yaml_source"] == "repository" and web["analysis"]["tests"] is True


def test_a_missing_organization_is_bad_config(tmp_path):
    fake = FakeADO()
    fake.routes["/contoso/_apis/projects"] = Resp(404, {"message": "The resource cannot be found."})
    code, _, status, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "bad_config" and "not found" in status["error"]


def test_invalid_lookback_is_bad_config(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.LOOKBACK_ENV, "a month")
    code, _, status, _ = run(tmp_path)
    assert code == 1 and status["code"] == "bad_config"


# --- YAML analysis -----------------------------------------------------------------

@pytest.mark.parametrize("step,expected", [
    ({"task": "DotNetCoreCLI@2", "inputs": {"command": "test"}}, ["test"]),
    ({"task": "DotNetCoreCLI@2", "inputs": {"command": "build"}}, []),
    ({"task": "Maven@4", "inputs": {"goals": "clean verify"}}, ["test"]),
    ({"task": "Npm@1", "inputs": {"command": "custom", "customCommand": "run test:ci"}}, ["test"]),
    ({"task": "Bash@3", "inputs": {"targetType": "inline", "script": "python -m pytest -q"}}, ["test"]),
    ({"script": "npm run lint", "displayName": "Run tests"}, []),
    ({"task": "AzureWebApp@1", "displayName": "Deploy to test env"}, ["application_deploy"]),
    ({"task": "AzureCLI@2", "inputs": {"inlineScript": "az deployment group create -f main.bicep"}},
     ["infrastructure_deploy"]),
    ({"task": "AzureCLI@2", "inputs": {"inlineScript": "az deployment group what-if -f main.bicep"}},
     ["iac_validation"]),
    ({"task": "TerraformTaskV4@4", "inputs": {"command": "plan"}}, ["iac_validation"]),
    ({"task": "TerraformTaskV4@4", "inputs": {"command": "apply"}}, ["infrastructure_deploy"]),
    ({"task": "AzureResourceManagerTemplateDeployment@3"}, ["infrastructure_deploy"]),
    ({"task": "Notation@0", "inputs": {"command": "sign"}}, ["signing"]),
    ({"task": "Notation@0", "inputs": {"command": "verify"}}, ["signature_verification"]),
    ({"script": "cosign verify-attestation --type slsaprovenance $IMG"}, ["signature_verification"]),
    ({"task": "TrustedSigning@0"}, ["signing"]),
    ({"task": "ManifestGeneratorTask@0"}, ["sbom"]),
    ({"task": "AdvancedSecurity-Dependency-Scanning@1"}, ["security_scan"]),
    ({"pwsh": "trivy image --exit-code 1 $(image)"}, ["security_scan"]),
])
def test_classify_step(step, expected):
    assert mod.classify_step(step) == expected


def test_bare_steps_pipeline_is_one_job():
    analysis = mod.analyze_yaml("steps:\n- script: go test ./...\n")
    assert analysis["tests"] is True and analysis["deploys"] is False
    assert analysis["steps"]["test"] == [{"stage": None, "job": None, "step": "script"}]


def test_tests_after_deploy_are_not_before_it():
    analysis = mod.analyze_yaml("""
jobs:
- deployment: Ship
  environment: prod
  strategy: {runOnce: {deploy: {steps: [{task: AzureWebApp@1}]}}}
- job: Smoke
  steps: [{script: npx playwright test}]
""")
    assert analysis["tests"] and analysis["deploys"]
    assert analysis["tests_before_first_deploy"] is False


def test_unexpanded_extends_is_reported():
    analysis = mod.analyze_yaml("extends:\n  template: secure.yml@templates\n  parameters: {}\n")
    assert analysis["extends_template"] == "secure.yml@templates"
    assert analysis["steps"]["test"] == []


def test_invalid_yaml_is_recorded_on_the_pipeline_not_raised(tmp_path):
    fake = FakeADO()
    fake.routes[f"/contoso/{P}/_apis/pipelines/10/preview"] = Resp(body={"finalYaml": "stages: [unclosed"})
    code, evidence, _, _ = run(tmp_path, fake)
    web = pipeline(evidence, "web-ci-cd")
    assert code == 0 and web["analysis"] is None and web["yaml_error"].startswith("ParserError")


@pytest.mark.parametrize("scope,branch,applies", [
    ({"repositoryId": "r1", "refName": "refs/heads/main", "matchKind": "Exact"}, "refs/heads/main", True),
    ({"repositoryId": "r1", "refName": "refs/heads/main", "matchKind": "Exact"}, "refs/heads/maint", False),
    ({"repositoryId": "r2", "refName": "refs/heads/main", "matchKind": "Exact"}, "refs/heads/main", False),
    ({"repositoryId": None, "refName": "refs/heads/", "matchKind": "Prefix"}, "refs/heads/main", True),
    ({"repositoryId": "r1", "matchKind": "DefaultBranch"}, "refs/heads/trunk", True),
    ({"repositoryId": None}, "refs/heads/main", True),
])
def test_policy_scope_matching(scope, branch, applies):
    assert mod.scope_matches(scope, "r1", branch) is applies


def test_unknown_task_check_keeps_its_definition_name():
    record = mod.check_record({"id": 1, "type": {"name": "Task Check"},
                               "settings": {"definitionRef": {"name": "SomeNewCheck"}}})
    assert (record["kind"], record["definition_ref"]) == ("other", "SomeNewCheck")
