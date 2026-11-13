#!/usr/bin/env python3
"""How GitHub Actions is locked down, from the Actions settings and from every workflow file on the default branch."""

import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import run  # noqa: E402

NAME = "github_actions_security"
CONFIG = {"include_self_hosted_runners": ("GITHUB_INCLUDE_SELF_HOSTED_RUNNERS", True)}
WORKFLOW_FIELDS = ('object(expression: "HEAD:.github/workflows") { ... on Tree { entries { name type '
                  'object { ... on Blob { text isBinary isTruncated } } } } }')
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
# Triggers that run with the base repository's secrets and a write token on an event an outsider can cause.
PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run")
HEAD_CHECKOUT = re.compile(r"github\.event\.pull_request\.head\.|github\.head_ref|github\.event\.workflow_run\.head_|"
                           r"refs/pull/")
SCRIPT_CHECKOUT = re.compile(r"gh pr checkout|git (fetch|checkout|pull)\b[^\n]*(pull/|github\.event\.pull_request\.head|"
                             r"github\.head_ref)")
# Event fields an outsider writes, which GitHub Security Lab lists as unsafe inside a run: script.
UNTRUSTED_INPUT = re.compile(
    r"\$\{\{[^}]*?\b(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|"
    r"head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|"
    r"pages\S*?\.page_name|commits\S*?\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name))|"
    r"workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(email|name))))|github\.head_ref)\b")


def reference(uses):
    """One `uses:`: (kind, owner, pinned). A local path runs the same commit; a docker image pins by digest."""
    uses = str(uses).strip()
    if uses.startswith("./"):
        return "local", None, True
    if uses.startswith("docker://"):
        return "docker", None, "@sha256:" in uses
    path, _, ref = uses.partition("@")
    return "action", path.split("/")[0] or None, bool(FULL_SHA.match(ref))


def triggers(doc):
    on = doc.get("on", doc.get(True))  # YAML 1.1 reads a bare `on` key as true
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(t) for t in on]
    return [str(t) for t in on] if isinstance(on, dict) else []


def writes(permissions):
    """The scopes a permissions block grants write on; "write-all" is every scope. None when the block is absent."""
    if permissions is None:
        return None
    if isinstance(permissions, str):
        return ["*"] if permissions == "write-all" else []
    return sorted(str(k) for k, v in permissions.items() if v == "write") if isinstance(permissions, dict) else []


def grants(scopes, scope):
    return bool(scopes) and (scope in scopes or "*" in scopes)


def runner_labels(runs_on):
    if isinstance(runs_on, dict):
        return [str(x) for x in ([runs_on.get("group")] if runs_on.get("group") else [])
                + (runs_on.get("labels") if isinstance(runs_on.get("labels"), list) else [runs_on.get("labels")])
                if x]
    return [str(x) for x in runs_on] if isinstance(runs_on, list) else [str(runs_on)] if runs_on else []


def analyse(name, text):
    """One workflow file as evidence. An unparseable file is reported, not guessed at: GitHub will not run it either."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return {"file": name, "parsed": False, "error": str(exc).splitlines()[0][:200]}
    if not isinstance(doc, dict):
        return {"file": name, "parsed": False, "error": "not a mapping"}
    events = triggers(doc)
    privileged = [t for t in events if t in PRIVILEGED_TRIGGERS]
    top = writes(doc.get("permissions"))
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    refs, job_rows, head_checkout, injections, inherits = [], [], False, [], False
    for job_id, job in jobs.items():
        job = job if isinstance(job, dict) else {}
        steps = [s for s in job.get("steps") or [] if isinstance(s, dict)]
        if job.get("uses"):
            refs.append(job["uses"])
            inherits = inherits or job.get("secrets") == "inherit"
        for step in steps:
            if step.get("uses"):
                refs.append(step["uses"])
            with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
            if str(step.get("uses", "")).startswith("actions/checkout") and HEAD_CHECKOUT.search(str(with_.get("ref"))):
                head_checkout = True
            if SCRIPT_CHECKOUT.search(str(step.get("run") or "")):
                head_checkout = True
            for script in (step.get("run"), with_.get("script") if "github-script" in str(step.get("uses")) else None):
                injections += sorted({m.group(1) for m in UNTRUSTED_INPUT.finditer(str(script or ""))})
        job_writes = writes(job.get("permissions"))
        job_rows.append({"job": str(job_id), "runs_on": runner_labels(job.get("runs-on")),
                         "permissions_set": job_writes is not None, "writes": job_writes})
    classified = [(str(u), *reference(u)) for u in refs]
    return {
        "file": name,
        "parsed": True,
        "triggers": events,
        "privileged_triggers": privileged,
        # Without a block at the top or on every job, a job's token takes the repository default.
        "permissions_set": top is not None or bool(job_rows) and all(j["permissions_set"] for j in job_rows),
        "writes": sorted(set((top or []) + [w for j in job_rows for w in j["writes"] or []])),
        "oidc": grants(top, "id-token") or any(grants(j["writes"], "id-token") for j in job_rows),
        "self_hosted": any("self-hosted" in j["runs_on"] for j in job_rows),
        "runner_labels": sorted({label for j in job_rows for label in j["runs_on"]}),
        "references": len(classified),
        "unpinned": sorted({u for u, kind, _, pinned in classified if kind != "local" and not pinned}),
        "unpinned_owners": sorted({o for _, kind, o, pinned in classified if kind == "action" and not pinned and o}),
        "checks_out_pull_request_head": bool(privileged) and head_checkout,
        "untrusted_input_in_scripts": sorted(set(injections)),
        "passes_all_secrets": inherits,
    }


def workflow_files(client, org, repos):
    """{repository: [file analyses]}, or None. GitHub runs only .yml and .yaml files directly in .github/workflows."""
    found = client.graphql_repos("GraphQL workflow files", org, [r["name"] for r in repos], WORKFLOW_FIELDS)
    if found is None:
        return None
    out = {}
    for name, data in found.items():
        entries = (data.get("object") or {}).get("entries") or []
        rows = []
        for e in sorted(entries, key=lambda e: e.get("name") or ""):
            if e.get("type") != "blob" or not str(e.get("name")).endswith((".yml", ".yaml")):
                continue
            blob = e.get("object") or {}
            if blob.get("text") is None or blob.get("isTruncated") or blob.get("isBinary"):
                rows.append({"file": e["name"], "parsed": False, "error": "content not readable over GraphQL"})
            else:
                rows.append(analyse(e["name"], blob["text"]))
        out[name] = rows
    return out


def selected(client, base, policy):
    return client.get(f"{base}/actions/permissions/selected-actions") if policy == "selected" else None


def runners(client, path, include):
    if not include:
        return None
    found = client.paginate_required(path, key="runners")
    return None if found is None else [
        {"name": r.get("name"), "os": r.get("os"), "status": r.get("status"), "busy": r.get("busy"),
         "labels": sorted(label.get("name") for label in r.get("labels") or [] if label.get("name"))}
        for r in found]


def runner_groups(client, base, include):
    """The organization's runner groups, the runners in each and the repositories that may use them."""
    if not include:
        return None
    groups = client.paginate_required(f"{base}/actions/runner-groups", key="runner_groups")
    if groups is None:
        return None
    rows = []
    for g in groups:
        path = f"{base}/actions/runner-groups/{g.get('id')}"
        members = client.paginate_required(f"{path}/runners", key="runners")
        repos = client.paginate_required(f"{path}/repositories", key="repositories") \
            if g.get("visibility") == "selected" else None
        if members is None or g.get("visibility") == "selected" and repos is None:
            return None
        rows.append({
            "name": g.get("name"),
            "default": g.get("default"),
            "inherited_from_enterprise": g.get("inherited"),
            # all: every repository; selected: only `repositories`; private: private repositories only.
            "visibility": g.get("visibility"),
            "repositories": None if repos is None else sorted(r.get("name") for r in repos),
            "allows_public_repositories": g.get("allows_public_repositories"),
            "restricted_to_workflows": g.get("restricted_to_workflows"),
            "selected_workflows": g.get("selected_workflows") or [],
            "runners": sorted(r.get("name") for r in members),
        })
    return rows


def oidc_template(client, base):
    """The organization's OIDC subject template; {} when it was never customized (404)."""
    before = len(client.failures)
    found, body = client.lookup(f"{base}/actions/oidc/customization/sub")
    return body if found else None if len(client.failures) > before else {}


def oidc_claims(setting, org_template):
    """The claim keys a repository's OIDC subject is built from, or None when unknown.

    use_default true is GitHub's own subject (repo, context), whatever the organization's template says. false with
    keys is the repository's own template; false without keys opts in to the organization's template.
    """
    if setting is None or setting.get("use_default") not in (True, False):
        return None
    if setting["use_default"]:
        return ["repo", "context"]
    if setting.get("include_claim_keys"):
        return setting["include_claim_keys"]
    if org_template is None:
        return None
    return org_template.get("include_claim_keys") or ["repo", "context"]


def repo_record(client, org, repo, files, include_runners, org_template):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    perms = client.get(f"{base}/actions/permissions")
    if perms is None:
        return {"repository": name, "collected": False}
    enabled = perms.get("enabled")
    token = client.get(f"{base}/actions/permissions/workflow") if enabled else None
    allowed = selected(client, base, perms.get("allowed_actions")) if enabled else None
    hosted = runners(client, f"{base}/actions/runners", include_runners)
    # Read only where a workflow asks for an OIDC token: elsewhere the subject is never issued.
    uses_oidc = enabled and any(w.get("oidc") for w in files.get(name, []))
    oidc = client.get(f"{base}/actions/oidc/customization/sub") if uses_oidc else None
    if enabled and (token is None or perms.get("allowed_actions") == "selected" and allowed is None) \
            or include_runners and hosted is None or uses_oidc and oidc is None:
        return {"repository": name, "collected": False}
    return {
        "repository": name,
        "collected": True,
        "visibility": repo.get("visibility"),
        "actions_enabled": enabled,
        "allowed_actions": perms.get("allowed_actions"),
        "selected_actions": allowed,
        "sha_pinning_required": perms.get("sha_pinning_required"),
        "default_workflow_permissions": (token or {}).get("default_workflow_permissions"),
        "can_approve_pull_request_reviews": (token or {}).get("can_approve_pull_request_reviews"),
        "self_hosted_runners": hosted,
        "oidc_subject": None if oidc is None else {
            "use_default": oidc.get("use_default"),
            "include_claim_keys": oidc.get("include_claim_keys"),
            "use_immutable_subject": oidc.get("use_immutable_subject"),
            "effective_claim_keys": oidc_claims(oidc, org_template),
        },
        "workflows": files.get(name, []),
    }


def collect(client, org, repos, config):
    login, include = org["login"], config["include_self_hosted_runners"]
    base = f"orgs/{login}"
    perms = client.get(f"{base}/actions/permissions")
    files = workflow_files(client, login, repos)
    if perms is None or files is None:
        return None
    organization = {
        "enabled_repositories": perms.get("enabled_repositories"),
        "allowed_actions": perms.get("allowed_actions"),
        "selected_actions": selected(client, base, perms.get("allowed_actions")),
        "sha_pinning_required": perms.get("sha_pinning_required"),
        "workflow_token": client.get(f"{base}/actions/permissions/workflow"),
        "fork_pr_contributor_approval": (client.get(f"{base}/actions/permissions/fork-pr-contributor-approval")
                                         or {}).get("approval_policy"),
        "fork_pr_workflows_private_repos": client.get(f"{base}/actions/permissions/fork-pr-workflows-private-repos"),
        "artifact_and_log_retention": client.get(f"{base}/actions/permissions/artifact-and-log-retention"),
        "self_hosted_runners_allowed_in": (client.get(f"{base}/actions/permissions/self-hosted-runners")
                                           or {}).get("enabled_repositories"),
        "self_hosted_runners": runners(client, f"{base}/actions/runners", include),
        "runner_groups": runner_groups(client, base, include),
        "oidc_subject_template": oidc_template(client, base),
    }
    records = [repo_record(client, login, r, files, include, organization["oidc_subject_template"]) for r in repos]
    done = [r for r in records if r["collected"]]
    active = [r for r in done if r["actions_enabled"]]
    flows = [(r["repository"], w) for r in active for w in r["workflows"]]
    parsed = [(repo, w) for repo, w in flows if w["parsed"]]
    token = organization["workflow_token"] or {}
    groups = organization["runner_groups"]
    template = organization["oidc_subject_template"]
    oidc = [r for r in done if r.get("oidc_subject")]

    def group_names(test):
        return None if groups is None else sorted(g["name"] for g in groups if test(g))
    return {
        "summary": {
            "organization_allowed_actions": organization["allowed_actions"],
            "organization_sha_pinning_required": organization["sha_pinning_required"],
            "organization_default_workflow_permissions": token.get("default_workflow_permissions"),
            "organization_workflow_token_can_approve_prs": token.get("can_approve_pull_request_reviews"),
            "fork_pr_contributor_approval": organization["fork_pr_contributor_approval"],
            "repositories_with_actions": len(active),
            "repositories_allowing_all_actions": sorted(r["repository"] for r in active
                                                        if r["allowed_actions"] == "all"),
            "repositories_without_sha_pinning_required": sorted(r["repository"] for r in active
                                                                if r["sha_pinning_required"] is not True),
            "repositories_with_write_token_default": sorted(r["repository"] for r in active
                                                            if r["default_workflow_permissions"] == "write"),
            "repositories_token_can_approve_prs": sorted(r["repository"] for r in active
                                                         if r["can_approve_pull_request_reviews"]),
            "workflows_total": len(flows),
            "workflows_unparsed": sorted(f"{repo}:{w['file']}" for repo, w in flows if not w["parsed"]),
            "action_references_unpinned": sum(len(w["unpinned"]) for _, w in parsed),
            "workflows_with_unpinned_actions": sorted(f"{repo}:{w['file']}" for repo, w in parsed if w["unpinned"]),
            "workflows_without_permissions_block": sorted(f"{repo}:{w['file']}" for repo, w in parsed
                                                          if not w["permissions_set"]),
            "workflows_granting_write_all": sorted(f"{repo}:{w['file']}" for repo, w in parsed if "*" in w["writes"]),
            "workflows_on_privileged_triggers": sorted(f"{repo}:{w['file']}" for repo, w in parsed
                                                       if w["privileged_triggers"]),
            "workflows_checking_out_untrusted_pr_code": sorted(f"{repo}:{w['file']}" for repo, w in parsed
                                                               if w["checks_out_pull_request_head"]),
            "workflows_with_untrusted_input_in_scripts": sorted(f"{repo}:{w['file']}" for repo, w in parsed
                                                                if w["untrusted_input_in_scripts"]),
            "workflows_using_oidc": sorted(f"{repo}:{w['file']}" for repo, w in parsed if w["oidc"]),
            "workflows_on_self_hosted_runners": sorted(f"{repo}:{w['file']}" for repo, w in parsed
                                                       if w["self_hosted"]),
            "self_hosted_runners_organization": None if organization["self_hosted_runners"] is None
            else len(organization["self_hosted_runners"]),
            "self_hosted_runners_repository": None if not include
            else sum(len(r["self_hosted_runners"]) for r in done),
            # A public repository's runner executes code from anyone who can open a pull request.
            "public_repositories_with_self_hosted_runners": None if not include else sorted(
                r["repository"] for r in done if r["visibility"] == "public" and r["self_hosted_runners"]),
            "runner_groups": None if groups is None else len(groups),
            "runner_groups_open_to_all_repositories": group_names(lambda g: g["visibility"] == "all"),
            "runner_groups_allowing_public_repositories": group_names(lambda g: g["allows_public_repositories"]),
            "runner_groups_not_restricted_to_workflows": group_names(lambda g: not g["restricted_to_workflows"]),
            "organization_oidc_subject_claims": None if template is None
            else template.get("include_claim_keys") or ["repo", "context"],
            "repositories_with_custom_oidc_subject": sorted(r["repository"] for r in oidc
                                                            if r["oidc_subject"]["use_default"] is False
                                                            and r["oidc_subject"]["include_claim_keys"]),
            "repositories_on_organization_oidc_template": sorted(r["repository"] for r in oidc
                                                                 if r["oidc_subject"]["use_default"] is False
                                                                 and not r["oidc_subject"]["include_claim_keys"]),
            # A subject without the repository is the same for every repository, so a cloud trust policy keyed on
            # it cannot tell them apart.
            "repositories_oidc_subject_without_repository": sorted(
                r["repository"] for r in oidc if r["oidc_subject"]["effective_claim_keys"] is not None
                and not {"repo", "repository", "repository_id"} & set(r["oidc_subject"]["effective_claim_keys"])),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "organization": organization,
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
