#!/usr/bin/env python3
"""Azure DevOps pipelines per project: what they test, scan, sign and deploy, their runs and test results, environment checks, deployments and branch policies."""

import hashlib
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from devops_rest import (  # noqa: E402
    DevOpsClient,
    DevOpsCollector,
    DevOpsError,
    iso,
    list_projects,
    parse_time,
    run_org,
)

NAME = "azure_devops_pipelines"
LOOKBACK_ENV = "AZURE_DEVOPS_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 30
CHECKS_API = "7.1-preview.1"
TEST_QUERY_MAX_DAYS = 7  # the test runs query refuses a wider range
YAML_PROCESS = 2

MIN_REVIEWERS_POLICY = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
BUILD_POLICY = "0609b952-1397-4640-95ec-e00a01b2c241"
REQUIRED_REVIEWERS_POLICY = "fd2167ab-b0be-447a-8ec8-39368250530e"
COMMENTS_POLICY = "c6a1889d-b943-4856-b76f-9e46bb6b0df2"
WORK_ITEM_POLICY = "40e92b44-2fe1-4dd6-b3d8-74a9c21d0c6e"

SCOPE_BUILD = "Build (Read)"
SCOPE_CODE = "Code (Read)"
SCOPE_TEST = "Test Management (Read)"
SCOPE_ENV = "Environment (Read & manage)"
SCOPE_PROJECT = "Project and Team (Read)"

TEST_TASKS = {"publishtestresults", "vstest", "publishcodecoverageresults"}
SCAN_TASKS = re.compile(r"^(advancedsecurity-|microsoftsecuritydevops|credscan|sonarqube|sonarcloud|whitesource|mend|"
                        r"snyk|trivy|checkmarx|dependency-?check|antimalware|componentgovernance)")
INFRA_DEPLOY_TASKS = {"azureresourcemanagertemplatedeployment", "azureresourcegroupdeployment"}
APP_DEPLOY_TASKS = {"azurewebapp", "azurermwebappdeployment", "azurefunctionapp", "azurefunctionappcontainer",
                    "azurewebappcontainer", "azurecontainerapps", "azurestaticwebapp", "azurespringcloud",
                    "kubernetesmanifest", "helmdeploy", "sqlazuredacpacdeployment", "azuremysqldeployment",
                    "iiswebappdeploymentonmachinegroup", "azureappservicemanage"}
SIGN_TASKS = re.compile(r"^(trustedsigning|artifactsigning|esrpcodesigning|azuresigntool|codesigning)")
SBOM_TASKS = re.compile(r"^(manifestgeneratortask|sbom)")

TEST_TEXT = re.compile(
    r"\b(pytest|py\.test|tox|nose2|python3? -m unittest|(npm|yarn|pnpm)( run)? test|jest|vitest|mocha|karma|"
    r"dotnet test|vstest\.console|mvn\b[^\n]*\b(test|verify)|gradlew?\b[^\n]*\btest|go test|cargo test|phpunit|rspec|"
    r"playwright test|cypress run|newman run|invoke-pester)\b")
SCAN_TEXT = re.compile(r"\b(trivy|grype|snyk|checkov|tfsec|terrascan|kics|semgrep|gitleaks|trufflehog|bandit|"
                       r"npm audit|dependency-check|zap-(baseline|full-scan))\b")
IAC_VALIDATE_TEXT = re.compile(r"\b(terraform (validate|plan)|bicep (build|lint)|az deployment \w+ (validate|what-if)|"
                               r"what-if)\b")
INFRA_DEPLOY_TEXT = re.compile(r"\b(terraform apply|az deployment (group|sub|mg|tenant) create|"
                               r"new-azresourcegroupdeployment|new-azdeployment|pulumi up)\b")
APP_DEPLOY_TEXT = re.compile(r"\b(az (webapp|functionapp) deploy|az webapp deployment|az containerapp (update|up)|"
                             r"kubectl apply|helm (upgrade|install)|publish-azwebapp)\b")
SIGN_TEXT = re.compile(r"\b(cosign sign|notation sign|signtool(\.exe)? sign|azuresigntool sign|jarsigner|"
                       r"gpg\b[^\n]*--(detach-|clear)?sign|nuget sign|docker trust sign)\b")
VERIFY_TEXT = re.compile(r"\b(cosign verify(-attestation)?|notation verify|signtool(\.exe)? verify|jarsigner -verify|"
                         r"gpg\b[^\n]*--verify|nuget verify|sha(256|512)sum (-c|--check)|get-authenticodesignature)\b")
SBOM_TEXT = re.compile(r"\b(sbom-tool generate|syft|cyclonedx|cosign attest|slsa-)")

CHECK_KINDS = (("branchprotection", "branch_control"), ("businesshours", "business_hours"),
               ("artifact", "evaluate_artifact"), ("restapi", "invoke_rest_api"),
               ("azurefunction", "invoke_azure_function"), ("azuremonitor", "query_azure_monitor"))
GENERAL_SETTINGS = ("disableClassicPipelineCreation", "disableClassicBuildPipelineCreation",
                    "disableClassicReleasePipelineCreation", "enforceJobAuthScope", "enforceJobAuthScopeForReleases",
                    "enforceReferencedRepoScopedToken", "enforceSettableVar", "publishPipelineMetadata",
                    "forkProtectionEnabled", "enforceNoAccessToSecretsFromForks", "statusBadgesArePrivate")

logger = logging.getLogger(NAME)


def lookback_days() -> int:
    raw = (os.environ.get(LOOKBACK_ENV) or "").strip()
    if not raw:
        return DEFAULT_LOOKBACK_DAYS
    try:
        days = int(raw)
    except ValueError:
        raise ValueError(f"{LOOKBACK_ENV} must be an integer, got {raw!r}") from None
    if days < 1:
        raise ValueError(f"{LOOKBACK_ENV} must be at least 1, got {days}")
    return days


def call(collector: DevOpsCollector, operation: str, scope: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """collector.guard, naming the PAT scope on an auth refusal."""
    def scoped():
        try:
            return fn()
        except DevOpsError as exc:
            if exc.status in (401, 403):
                exc.args = (f"{exc} [PAT scope needed: {scope}]",)
            raise
    return collector.guard(operation, scoped, default)


# --- YAML analysis -------------------------------------------------------------

def task_name(step: Dict[str, Any]) -> str:
    return str(step.get("task") or "").split("@")[0].strip().lower()


def step_text(step: Dict[str, Any]) -> str:
    """Script bodies and task inputs, lowercased, for pattern matching."""
    parts = [str(step.get(k)) for k in ("script", "bash", "pwsh", "powershell") if step.get(k)]
    inputs = step.get("inputs")
    if isinstance(inputs, dict):
        parts += [f"{k} {v}" for k, v in inputs.items()]
    return "\n".join(parts).lower()


def input_value(step: Dict[str, Any], *keys: str) -> str:
    inputs = step.get("inputs") if isinstance(step.get("inputs"), dict) else {}
    lowered = {str(k).lower(): v for k, v in inputs.items()}
    return " ".join(str(lowered[k]).lower() for k in keys if lowered.get(k) is not None)


def classify_step(step: Dict[str, Any]) -> List[str]:
    task, text = task_name(step), step_text(step)
    command = input_value(step, "command", "action", "provider")
    found = []
    if (task in TEST_TASKS or (task == "dotnetcorecli" and "test" in command)
            or (task in ("maven", "gradle", "ant") and re.search(r"\b(test|verify)\b", input_value(step, "goals", "tasks", "targets")))
            or (task == "npm" and "test" in input_value(step, "customcommand"))
            or TEST_TEXT.search(text)):
        found.append("test")
    if SCAN_TASKS.match(task) or SCAN_TEXT.search(text):
        found.append("security_scan")
    if (task.startswith("terraform") and re.search(r"\b(validate|plan)\b", command)) or IAC_VALIDATE_TEXT.search(text):
        found.append("iac_validation")
    if (task in INFRA_DEPLOY_TASKS or (task.startswith("terraform") and "apply" in command)
            or INFRA_DEPLOY_TEXT.search(text)):
        found.append("infrastructure_deploy")
    if task in APP_DEPLOY_TASKS or (task == "kubernetes" and "apply" in command) or APP_DEPLOY_TEXT.search(text):
        found.append("application_deploy")
    if SIGN_TASKS.match(task) or (task == "notation" and "sign" in command) or SIGN_TEXT.search(text):
        found.append("signing")
    if (task == "notation" and "verify" in command) or VERIFY_TEXT.search(text):
        found.append("signature_verification")
    if SBOM_TASKS.match(task) or SBOM_TEXT.search(text):
        found.append("sbom")
    return found


def collect_steps(node: Any) -> Iterator[Dict[str, Any]]:
    """Every step under a job, deployment strategy hooks included."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "steps" and isinstance(value, list):
                yield from (s for s in value if isinstance(s, dict))
            elif isinstance(value, (dict, list)):
                yield from collect_steps(value)
    elif isinstance(node, list):
        for item in node:
            yield from collect_steps(item)


def environment_name(job: Dict[str, Any]) -> Optional[str]:
    env = job.get("environment")
    if isinstance(env, dict):
        env = env.get("name")
    return str(env).split(".")[0] if env else None


def iter_jobs(doc: Dict[str, Any]) -> Iterator[Tuple[Optional[str], Dict[str, Any]]]:
    """(stage name, job) in YAML order; a pipeline of bare steps is one implicit job."""
    if isinstance(doc.get("stages"), list):
        for stage in doc["stages"]:
            if isinstance(stage, dict):
                for job in stage.get("jobs") or []:
                    if isinstance(job, dict):
                        yield stage.get("stage"), job
    elif isinstance(doc.get("jobs"), list):
        for job in doc["jobs"]:
            if isinstance(job, dict):
                yield None, job
    elif isinstance(doc.get("steps"), list):
        yield None, {"job": None, "steps": doc["steps"]}


def analyze_yaml(text: str) -> Dict[str, Any]:
    """What a pipeline's YAML tests, scans, validates, deploys and signs, step by step in YAML order."""
    doc = yaml.safe_load(text) or {}
    if not isinstance(doc, dict):
        raise ValueError("pipeline YAML is not a mapping")
    found: Dict[str, List[Dict[str, Any]]] = {k: [] for k in (
        "test", "security_scan", "iac_validation", "infrastructure_deploy", "application_deploy",
        "signing", "signature_verification", "sbom")}
    stages, deployment_jobs, order = [], [], []
    for stage, job in iter_jobs(doc):
        if stage and stage not in stages:
            stages.append(stage)
        job_name = job.get("deployment") or job.get("job")
        if "deployment" in job:
            deployment_jobs.append({"stage": stage, "job": job_name, "environment": environment_name(job)})
            order.append("deploy")
        for step in collect_steps(job):
            label = step.get("displayName") or step.get("task") or next(
                (k for k in ("script", "bash", "pwsh", "powershell", "checkout", "download", "publish", "template")
                 if k in step), "step")
            for category in classify_step(step):
                found[category].append({"stage": stage, "job": job_name, "step": str(label)})
                order.append("deploy" if category.endswith("_deploy") else category)
    extends = doc.get("extends") if isinstance(doc.get("extends"), dict) else None
    first_test = order.index("test") if "test" in order else None
    first_deploy = order.index("deploy") if "deploy" in order else None
    return {
        "stages": stages,
        "deployment_jobs": deployment_jobs,
        "environments": sorted({d["environment"] for d in deployment_jobs if d["environment"]}),
        "extends_template": extends.get("template") if extends else None,
        "steps": found,
        "tests": bool(found["test"]),
        "deploys": first_deploy is not None,
        "tests_before_first_deploy": first_test is not None and (first_deploy is None or first_test < first_deploy),
    }


# --- collection ------------------------------------------------------------------

def read_yaml(client: DevOpsClient, collector: DevOpsCollector, project: Dict[str, Any],
              definition: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(yaml text, source, error): the preview run's finalYaml, else the file on the default branch."""
    pid, pipeline_id = project["id"], definition["id"]
    error = None
    try:
        body = client.post(f"{pid}/_apis/pipelines/{pipeline_id}/preview", {"previewRun": True})
        if body.get("finalYaml"):
            return body["finalYaml"], "preview", None
        error = "preview returned no finalYaml"
    except DevOpsError as exc:
        error = str(exc)
        # A 400 is the pipeline's own problem (invalid YAML, a parameter with no default), not a collection failure.
        if exc.status != 400:
            collector.record(f"pipelines.preview({project['name']}/{definition.get('name')})", exc)
    repo = definition.get("repository") or {}
    path = (definition.get("process") or {}).get("yamlFilename")
    if repo.get("type") != "TfsGit" or not path or not repo.get("id"):
        return None, None, error
    branch = re.sub(r"^refs/heads/", "", repo.get("defaultBranch") or "")
    params = {"path": path, "includeContent": "true", "$format": "json"}
    if branch:
        params.update({"versionDescriptor.version": branch, "versionDescriptor.versionType": "branch"})
    item = call(collector, f"git.items.get({project['name']}/{repo.get('name')}:{path})", SCOPE_CODE,
                lambda: client.get(f"{pid}/_apis/git/repositories/{repo['id']}/items", params=params))
    if item and item.get("content") is not None:
        return item["content"], "repository", error
    return None, None, error


def pipeline_record(client, collector, project, definition, runs, tests) -> Dict[str, Any]:
    process = definition.get("process") or {}
    repo = definition.get("repository") or {}
    is_yaml = process.get("type") == YAML_PROCESS
    record: Dict[str, Any] = {
        "id": definition.get("id"),
        "name": definition.get("name"),
        "folder": definition.get("path"),
        "type": "yaml" if is_yaml else "classic",
        "queue_status": definition.get("queueStatus"),
        "yaml_path": process.get("yamlFilename"),
        "repository": {"id": repo.get("id"), "name": repo.get("name"), "type": repo.get("type"),
                       "default_branch": repo.get("defaultBranch")},
        "yaml_source": None,
        "templates_expanded": False,
        "yaml_sha256": None,
        "yaml_error": None,
        "analysis": None,
        "runs": runs,
        "test_runs": tests,
    }
    if not is_yaml:
        return record
    text, source, error = read_yaml(client, collector, project, definition)
    record.update(yaml_source=source, templates_expanded=source == "preview", yaml_error=error)
    if text is None:
        return record
    record["yaml_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    try:
        record["analysis"] = analyze_yaml(text)
    except (yaml.YAMLError, ValueError) as exc:
        record["yaml_error"] = f"{type(exc).__name__}: {exc}".splitlines()[0]
    return record


def run_summary(builds: List[Dict[str, Any]]) -> Dict[str, Any]:
    results = Counter(b.get("result") or "none" for b in builds)
    last = builds[0] if builds else None
    return {
        "in_window": len(builds),
        "succeeded": results.get("succeeded", 0),
        "partially_succeeded": results.get("partiallySucceeded", 0),
        "failed": results.get("failed", 0),
        "canceled": results.get("canceled", 0),
        "last": build_ref(last) if last else None,
    }


def build_ref(build: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": build.get("id"),
        "number": build.get("buildNumber"),
        "result": build.get("result"),
        "reason": build.get("reason"),
        "source_branch": build.get("sourceBranch"),
        "source_version": build.get("sourceVersion"),
        "requested_for": (build.get("requestedFor") or {}).get("displayName"),
        "finish_time": iso(parse_time(build.get("finishTime"))),
    }


def test_summary(test_runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    completed = [parse_time(r.get("completedDate")) for r in test_runs]
    return {
        "in_window": len(test_runs),
        "automated": sum(1 for r in test_runs if r.get("isAutomated")),
        "total_tests": sum(r.get("totalTests") or 0 for r in test_runs),
        "passed_tests": sum(r.get("passedTests") or 0 for r in test_runs),
        "failed_tests": sum(r.get("unanalyzedTests") or 0 for r in test_runs),
        "last_completed": iso(max((c for c in completed if c), default=None)),
    }


def list_test_runs(client, collector, project, since: datetime, until: datetime) -> Optional[List[Dict[str, Any]]]:
    runs: Dict[Any, Dict[str, Any]] = {}
    start = since
    while start < until:
        end = min(start + timedelta(days=TEST_QUERY_MAX_DAYS), until)
        page = call(collector, f"test.runs.query({project['name']}, {iso(start)}..{iso(end)})", SCOPE_TEST,
                    lambda s=start, e=end: client.list(f"{project['id']}/_apis/test/runs", params={
                        "minLastUpdatedDate": iso(s), "maxLastUpdatedDate": iso(e), "$top": 100}))
        if page is None:
            return None
        runs.update({r.get("id"): r for r in page})
        start = end
    return list(runs.values())


def check_record(check: Dict[str, Any]) -> Dict[str, Any]:
    type_name = (check.get("type") or {}).get("name") or ""
    settings = check.get("settings") if isinstance(check.get("settings"), dict) else {}
    ref = ((settings.get("definitionRef") or {}).get("name") or "")
    folded = type_name.lower().replace(" ", "")
    if folded == "approval":
        kind = "approval"
    elif folded == "extendscheck":
        kind = "required_template"
    elif folded == "exclusivelock":
        kind = "exclusive_lock"
    else:
        kind = next((k for marker, k in CHECK_KINDS if marker in ref.lower()), "other")
    inputs = settings.get("inputs") if isinstance(settings.get("inputs"), dict) else {}
    record = {
        "id": check.get("id"),
        "kind": kind,
        "type": type_name,
        "definition_ref": ref or None,
        "display_name": settings.get("displayName"),
        "disabled": bool(check.get("isDisabled")),
        "timeout_minutes": check.get("timeout"),
        "modified_on": iso(parse_time(check.get("modifiedOn"))),
    }
    if kind == "approval":
        record.update(
            approvers=[a.get("displayName") for a in settings.get("approvers") or []],
            min_required_approvers=settings.get("minRequiredApprovers"),
            requester_cannot_be_approver=settings.get("requesterCannotBeApprover"),
        )
    elif kind == "branch_control":
        record.update(
            allowed_branches=[b.strip() for b in str(inputs.get("allowedBranches") or "").split(",") if b.strip()],
            requires_branch_protection=str(inputs.get("ensureProtectionOfBranch")).lower() == "true",
            allows_unknown_status_branch=str(inputs.get("allowUnknownStatusBranch")).lower() == "true",
        )
    elif kind == "required_template":
        record["required_templates"] = [
            {"repository": t.get("repositoryName"), "ref": t.get("repositoryRef"), "path": t.get("templatePath")}
            for t in settings.get("extendsChecks") or []]
    return record


def deployment_records(client, collector, project, env, since: datetime) -> Optional[List[Dict[str, Any]]]:
    """Deployments to an environment inside the window; stops paging once older ones start, if newest come first."""
    def read():
        kept, previous, descending = [], None, True
        for rec in client.iter(f"{project['id']}/_apis/distributedtask/environments/{env['id']}/environmentdeploymentrecords",
                               params={"top": 100}):
            when = parse_time(rec.get("queueTime") or rec.get("startTime"))
            if previous and when and when > previous:
                descending = False
            previous = when or previous
            if when and when < since:
                if descending:
                    break
                continue
            kept.append(rec)
        return kept
    return call(collector, f"distributedtask.environmentdeploymentrecords.list({project['name']}/{env.get('name')})",
                SCOPE_ENV, read)


def deployment_record(rec: Dict[str, Any], builds: Dict[Any, Dict[str, Any]],
                      tests_by_build: Dict[Any, List[Dict[str, Any]]], pipelines: Dict[Any, Dict[str, Any]]) -> Dict[str, Any]:
    run_id = (rec.get("owner") or {}).get("id")
    build = builds.get(run_id) or {}
    pipeline = pipelines.get((rec.get("definition") or {}).get("id")) or {}
    default_branch = (pipeline.get("repository") or {}).get("default_branch")
    run_tests = tests_by_build.get(run_id, [])
    return {
        "pipeline_id": (rec.get("definition") or {}).get("id"),
        "pipeline": (rec.get("definition") or {}).get("name"),
        "run_id": run_id,
        "run_number": (rec.get("owner") or {}).get("name"),
        "stage": rec.get("stageName"),
        "job": rec.get("jobName"),
        "result": rec.get("result"),
        "start_time": iso(parse_time(rec.get("startTime"))),
        "finish_time": iso(parse_time(rec.get("finishTime"))),
        "source_branch": build.get("sourceBranch"),
        "source_version": build.get("sourceVersion"),
        "requested_for": (build.get("requestedFor") or {}).get("displayName"),
        "from_default_branch": (build.get("sourceBranch") == default_branch) if build and default_branch else None,
        "run_test_runs": len(run_tests),
        "run_tests_passed": sum(r.get("passedTests") or 0 for r in run_tests),
        "run_tests_failed": sum(r.get("unanalyzedTests") or 0 for r in run_tests),
    }


def environment_record(client, collector, project, env, since, builds, tests_by_build, pipelines) -> Dict[str, Any]:
    checks = call(collector, f"pipelines.checks.configurations.list({project['name']}/{env.get('name')})", SCOPE_BUILD,
                  lambda: client.list(f"{project['id']}/_apis/pipelines/checks/configurations", CHECKS_API, params={
                      "resourceType": "environment", "resourceId": env["id"], "$expand": "settings"}))
    checks = [check_record(c) for c in checks or []]
    active = {c["kind"] for c in checks if not c["disabled"]}
    records = deployment_records(client, collector, project, env, since)
    deployments = [deployment_record(r, builds, tests_by_build, pipelines) for r in records or []]
    results = Counter(d["result"] for d in deployments)
    return {
        "id": env.get("id"),
        "name": env.get("name"),
        "resources": [{"type": r.get("type"), "name": r.get("name")} for r in env.get("resources") or []],
        "checks": checks,
        "approval_required": "approval" in active,
        "branch_control": "branch_control" in active,
        "required_template": "required_template" in active,
        "evaluate_artifact": "evaluate_artifact" in active,
        "deployments_collected": records is not None,
        "deployments_in_window": len(deployments),
        "deployments_succeeded": results.get("succeeded", 0),
        "deployments_failed": results.get("failed", 0),
        "deployments": deployments,
    }


def scope_matches(scope: Dict[str, Any], repo_id: str, branch: str) -> bool:
    if scope.get("repositoryId") not in (None, repo_id):
        return False
    ref, kind = scope.get("refName"), (scope.get("matchKind") or "exact").lower()
    if kind == "defaultbranch" or not ref:
        return True
    return branch.startswith(ref) if kind == "prefix" else branch == ref


def repository_record(repo: Dict[str, Any], policies: List[Dict[str, Any]], pipeline_names: Dict[Any, str]) -> Dict[str, Any]:
    branch = repo.get("defaultBranch")
    applied = [p for p in policies if branch and any(
        scope_matches(s, repo.get("id"), branch) for s in (p.get("settings") or {}).get("scope") or [{}])]

    def of(type_id):
        return [p for p in applied if (p.get("type") or {}).get("id") == type_id]

    reviewers = of(MIN_REVIEWERS_POLICY)
    strongest = max(reviewers, key=lambda p: (bool(p.get("isBlocking")), p["settings"].get("minimumApproverCount") or 0),
                    default=None)
    builds = [{
        "pipeline_id": p["settings"].get("buildDefinitionId"),
        "pipeline": pipeline_names.get(p["settings"].get("buildDefinitionId")),
        "blocking": bool(p.get("isBlocking")),
        "valid_duration_minutes": p["settings"].get("validDuration"),
        "manual_queue_only": bool(p["settings"].get("manualQueueOnly")),
    } for p in of(BUILD_POLICY)]
    return {
        "id": repo.get("id"),
        "name": repo.get("name"),
        "default_branch": branch,
        "min_reviewers": None if strongest is None else {
            "count": strongest["settings"].get("minimumApproverCount"),
            "blocking": bool(strongest.get("isBlocking")),
            "creator_vote_counts": strongest["settings"].get("creatorVoteCounts"),
            "reset_on_source_push": strongest["settings"].get("resetOnSourcePush"),
            "block_last_pusher_vote": strongest["settings"].get("blockLastPusherVote"),
        },
        "build_validation": builds,
        "required_reviewer_policies": len(of(REQUIRED_REVIEWERS_POLICY)),
        "comment_resolution_required": any(p.get("isBlocking") for p in of(COMMENTS_POLICY)),
        "work_item_linking_required": any(p.get("isBlocking") for p in of(WORK_ITEM_POLICY)),
        "requires_review": bool(strongest and strongest.get("isBlocking")
                                and (strongest["settings"].get("minimumApproverCount") or 0) >= 1),
        "requires_build_validation": any(b["blocking"] for b in builds),
    }


def collect_project(client, collector, project, since: datetime, until: datetime) -> Dict[str, Any]:
    pid, pname = project["id"], project["name"]
    settings = call(collector, f"build.generalsettings.get({pname})", SCOPE_PROJECT,
                    lambda: client.get(f"{pid}/_apis/build/generalsettings"))
    definitions = call(collector, f"build.definitions.list({pname})", SCOPE_BUILD,
                       lambda: client.list(f"{pid}/_apis/build/definitions",
                                           params={"includeAllProperties": "true", "$top": 1000}), default=[])
    builds_list = call(collector, f"build.builds.list({pname})", SCOPE_BUILD,
                       lambda: client.list(f"{pid}/_apis/build/builds", params={
                           "minTime": iso(since), "queryOrder": "finishTimeDescending",
                           "statusFilter": "completed", "$top": 1000}), default=[])
    test_runs = list_test_runs(client, collector, project, since, until) or []

    builds = {b.get("id"): b for b in builds_list}
    runs_by_definition: Dict[Any, List[Dict[str, Any]]] = {}
    for b in builds_list:
        runs_by_definition.setdefault((b.get("definition") or {}).get("id"), []).append(b)
    tests_by_build: Dict[Any, List[Dict[str, Any]]] = {}
    tests_by_definition: Dict[Any, List[Dict[str, Any]]] = {}
    unattributed = 0
    for run in test_runs:
        build_id = (run.get("build") or {}).get("id")
        build_id = int(build_id) if str(build_id or "").isdigit() else build_id
        definition_id = ((run.get("buildConfiguration") or {}).get("buildDefinitionId")
                         or ((builds.get(build_id) or {}).get("definition") or {}).get("id"))
        if build_id is not None:
            tests_by_build.setdefault(build_id, []).append(run)
        if definition_id:
            tests_by_definition.setdefault(definition_id, []).append(run)
        else:
            unattributed += 1

    pipelines = [pipeline_record(client, collector, project, d,
                                 run_summary(runs_by_definition.get(d.get("id"), [])),
                                 test_summary(tests_by_definition.get(d.get("id"), [])))
                 for d in sorted(definitions, key=lambda d: (d.get("path") or "", d.get("name") or ""))]
    by_id = {p["id"]: p for p in pipelines}

    envs = call(collector, f"distributedtask.environments.list({pname})", SCOPE_ENV,
                lambda: client.list(f"{pid}/_apis/distributedtask/environments", params={"$top": 1000}), default=[])
    environments = [environment_record(client, collector, project, e, since, builds, tests_by_build, by_id)
                    for e in sorted(envs, key=lambda e: e.get("name") or "")]

    repos = call(collector, f"git.repositories.list({pname})", SCOPE_CODE,
                 lambda: client.list(f"{pid}/_apis/git/repositories"), default=[])
    policies = call(collector, f"policy.configurations.list({pname})", SCOPE_CODE,
                    lambda: client.list(f"{pid}/_apis/policy/configurations", params={"$top": 1000}), default=[])
    live = [p for p in policies if p.get("isEnabled") and not p.get("isDeleted")]
    names = {p["id"]: p["name"] for p in pipelines}
    repositories = [repository_record(r, live, names)
                    for r in sorted(repos, key=lambda r: r.get("name") or "") if not r.get("isDisabled")]

    return {
        "id": pid,
        "name": pname,
        "general_settings": {k: settings.get(k) for k in GENERAL_SETTINGS} if isinstance(settings, dict) else None,
        "pipelines": pipelines,
        "environments": environments,
        "repositories": repositories,
        "test_runs_in_window": len(test_runs),
        "test_runs_unattributed": unattributed,
    }


def summarize(projects: List[Dict[str, Any]], days: int) -> Dict[str, Any]:
    def label(project, item):
        return f"{project['name']}/{item['name']}"

    pipelines = [(p, x) for p in projects for x in p["pipelines"]]
    yaml_pipes = [(p, x) for p, x in pipelines if x["type"] == "yaml"]
    analyzed = [(p, x) for p, x in yaml_pipes if x["analysis"]]
    deploying = [(p, x) for p, x in analyzed if x["analysis"]["deploys"]]

    def with_steps(category):
        return sum(1 for _, x in analyzed if x["analysis"]["steps"][category])

    envs = [(p, e) for p in projects for e in p["environments"]]
    deployments = [d for _, e in envs for d in e["deployments"]]
    repos = [(p, r) for p in projects for r in p["repositories"]]
    return {
        "lookback_days": days,
        "projects_collected": len(projects),
        "pipelines_total": len(pipelines),
        "yaml_pipelines": len(yaml_pipes),
        "classic_pipelines": len(pipelines) - len(yaml_pipes),
        "disabled_pipelines": sum(1 for _, x in pipelines if x["queue_status"] == "disabled"),
        "yaml_pipelines_analyzed": len(analyzed),
        "yaml_pipelines_with_templates_expanded": sum(1 for _, x in analyzed if x["templates_expanded"]),
        "yaml_pipelines_not_analyzed": [label(p, x) for p, x in yaml_pipes if not x["analysis"]],
        "pipelines_with_tests": with_steps("test"),
        "pipelines_with_security_scan": with_steps("security_scan"),
        "pipelines_with_iac_validation": with_steps("iac_validation"),
        "pipelines_deploying_infrastructure": with_steps("infrastructure_deploy"),
        "pipelines_signing_artifacts": with_steps("signing"),
        "pipelines_verifying_signatures": with_steps("signature_verification"),
        "pipelines_generating_sbom": with_steps("sbom"),
        "deploying_pipelines": len(deploying),
        "deploying_pipelines_with_tests": sum(1 for _, x in deploying if x["analysis"]["tests"]),
        "deploying_pipelines_testing_before_deploy": sum(1 for _, x in deploying
                                                         if x["analysis"]["tests_before_first_deploy"]),
        "deploying_pipelines_without_tests": [label(p, x) for p, x in deploying if not x["analysis"]["tests"]],
        "pipeline_runs_in_window": sum(x["runs"]["in_window"] for _, x in pipelines),
        "test_runs_in_window": sum(p["test_runs_in_window"] for p in projects),
        "tests_total": sum(x["test_runs"]["total_tests"] for _, x in pipelines),
        "tests_passed": sum(x["test_runs"]["passed_tests"] for _, x in pipelines),
        "tests_failed": sum(x["test_runs"]["failed_tests"] for _, x in pipelines),
        "pipelines_with_test_runs_in_window": sum(1 for _, x in pipelines if x["test_runs"]["in_window"]),
        "environments_total": len(envs),
        "environments_with_approval": sum(1 for _, e in envs if e["approval_required"]),
        "environments_with_branch_control": sum(1 for _, e in envs if e["branch_control"]),
        "environments_with_required_template": sum(1 for _, e in envs if e["required_template"]),
        "environments_with_artifact_evaluation": sum(1 for _, e in envs if e["evaluate_artifact"]),
        "environments_without_checks": [label(p, e) for p, e in envs
                                        if not any(not c["disabled"] for c in e["checks"])],
        "deployments_in_window": len(deployments),
        "deployments_succeeded": sum(1 for d in deployments if d["result"] == "succeeded"),
        "deployments_from_default_branch": sum(1 for d in deployments if d["from_default_branch"]),
        "deployments_with_test_runs": sum(1 for d in deployments if d["run_test_runs"]),
        "repositories_total": len(repos),
        "repositories_requiring_review": sum(1 for _, r in repos if r["requires_review"]),
        "repositories_requiring_build_validation": sum(1 for _, r in repos if r["requires_build_validation"]),
        "repositories_without_review_or_build_validation": [
            label(p, r) for p, r in repos if not (r["requires_review"] or r["requires_build_validation"])],
        "projects_with_classic_pipeline_creation_disabled": sum(
            1 for p in projects if (p["general_settings"] or {}).get("disableClassicPipelineCreation")),
    }


def collect(client: DevOpsClient, collector: DevOpsCollector) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    days = lookback_days()
    until = datetime.now(timezone.utc)
    since = until - timedelta(days=days)
    projects = [collector.guard(f"collect({p.get('name')})", lambda p=p: collect_project(client, collector, p, since, until))
                for p in list_projects(client, collector)]
    projects = [p for p in projects if p]
    results = {"window": {"start": iso(since), "end": iso(until), "lookback_days": days}, "projects": projects}
    return results, summarize(projects, days)


if __name__ == "__main__":
    sys.exit(run_org(fetcher=NAME, logger=logger, collect=collect))
