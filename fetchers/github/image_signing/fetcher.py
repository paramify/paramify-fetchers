#!/usr/bin/env python3
"""Whether GitHub Actions signs and verifies container images with cosign: the steps in each workflow file, and how
the signing workflows ran."""

import re
import sys
from pathlib import Path
from urllib.parse import quote

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import iso, newest_since, now_epoch, run, workflow_file_texts  # noqa: E402

NAME = "github_image_signing"
CONFIG = {
    "include_runs": ("GITHUB_IMAGE_SIGNING_INCLUDE_RUNS", True),
    "days_back": ("GITHUB_IMAGE_SIGNING_DAYS_BACK", 30),
    "max_runs": ("GITHUB_IMAGE_SIGNING_MAX_RUNS", 1000),
}
MAX_DAYS_BACK = 366
INSTALLER = "sigstore/cosign-installer"
# Longest first, so "verify-attestation" and "sign-blob" are not read as "verify" and "sign".
SUBCOMMANDS = ("verify-attestation", "verify-blob", "sign-blob", "attest", "verify", "sign")
# cosign as a command (also by path, or as a container image's entry), any global flags, then the subcommand.
COSIGN = re.compile(r"(?<![\w-])cosign(?:\.exe)?(?:\s+-{1,2}[\w-]+(?:=\S+)?)*\s+(" + "|".join(SUBCOMMANDS)
                    + r")(?![\w-])")
MENTION = re.compile(r"cosign", re.IGNORECASE)
# What a script puts after `||` when it means to carry on whatever the command returned.
DISCARDS = re.compile(r"\s*(true|:|echo|printf)(\s|\Z)")
# A key held in a key management service, by the scheme cosign documents for it.
KEY_SCHEMES = {"azurekms": "azure_key_vault", "awskms": "aws_kms", "gcpkms": "gcp_kms",
               "hashivault": "hashicorp_vault", "k8s": "kubernetes_secret"}
KEY_KINDS = (*KEY_SCHEMES.values(), "environment_variable", "keyless", "other")
SCHEME = re.compile(r"(" + "|".join(KEY_SCHEMES) + r")://")
# Only a reference made of plain characters is kept: one built from an expression or a variable is not a name.
KMS_REFERENCE = re.compile(r"(?:" + "|".join(KEY_SCHEMES) + r")://[\w./:@-]+")
VARIABLE = re.compile(r"\$\{?(\w+)\}?\Z|\$\{\{\s*env\.(\w+)\s*\}\}\Z")
DIGEST = re.compile(r"@sha256:[0-9a-f]{6,}|@\$")
# Runs of these events are not counted as signing runs: a signing workflow often also runs on pull requests with its
# sign step skipped (as GitHub's docker-publish starter does), and such a run still ends in success.
PULL_REQUEST_EVENTS = ("pull_request", "pull_request_target")


def segments(script):
    """A script as [(simple command, the operator after it)], split where a shell would split it.

    Quotes and GitHub expressions are kept whole, so `'(a|b)'` and `${{ x || y }}` are text, not separators.
    Comments are dropped. Here-documents are not understood: a script that writes cosign commands into a file
    reads as running them.
    """
    text = re.sub(r"\\\r?\n", " ", str(script or ""))
    out, buf, quote, i = [], [], None, 0
    while i < len(text):
        c = text[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif text.startswith("${{", i):
            end = text.find("}}", i)
            end = len(text) if end < 0 else end + 2
            buf.append(text[i:end])
            i = end
            continue
        elif c in "\"'":
            quote = c
            buf.append(c)
        elif c == "#" and (not buf or buf[-1].isspace()):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        elif text.startswith(("&&", "||"), i):
            out.append(("".join(buf), text[i:i + 2]))
            buf = []
            i += 1
        elif c in ";|&\n":
            out.append(("".join(buf), c))
            buf = []
        else:
            buf.append(c)
        i += 1
    out.append(("".join(buf), ""))
    return out


def commands(script):
    """[(subcommand, the rest of that command, failure discarded)] for every cosign command in a step's script.

    A message (echo, printf) is not a command. failure discarded: the script follows the command with `|| true` or
    the like, so the step carries on when cosign fails. Only the script itself is read: cosign run from a script
    file, a make target, a composite action or a reusable workflow elsewhere is not seen here.
    """
    parts = segments(script)
    found = []
    for n, (text, operator) in enumerate(parts):
        if re.match(r"\s*(echo|printf)\b", text):
            continue
        matches = list(COSIGN.finditer(text))
        discarded = operator == "||" and n + 1 < len(parts) and bool(DISCARDS.match(parts[n + 1][0]))
        for k, m in enumerate(matches):
            # Two commands in one quoted string: each one's flags end where the next begins.
            end = matches[k + 1].start() if k + 1 < len(matches) else len(text)
            found.append((m.group(1), text[m.end():end], discarded and k == len(matches) - 1))
    return found


def flag(text, name):
    """The value of `--name value` or `--name=value`, without its quotes; None when the flag is absent.

    A GitHub expression is one value however it is spaced: `--key ${{ env.KEY }}` is not `${{`.
    """
    m = re.search(rf"(?<![\w-]){name}(?:=|\s+)(\"[^\"]*\"|'[^']*'|(?:\$\{{\{{.*?\}}\}}|\S)+)", text)
    return m.group(1).strip("\"'") if m else None


def literal_env(*blocks):
    """The env values written out in the workflow, later blocks (job, step) over earlier ones (workflow)."""
    env = {}
    for block in blocks:
        if isinstance(block, dict):
            env.update({str(k): v for k, v in block.items() if isinstance(v, str)})
    return env


def key_of(text, env):
    """(kind, reference) of the key a sign command uses.

    keyless: no --key and no --sk, so cosign signs with the workflow's OIDC identity. environment_variable: cosign's
    env:// form, the key itself held in a variable (in Actions, usually a secret). other: a key file, a hardware
    key, or a value only known when the workflow runs. The reference is kept only for a key management service.
    """
    value = flag(text, "--key")
    if value is None:
        return ("other" if re.search(r"(?<![\w-])--sk(?![\w-])", text) else "keyless"), None
    named = VARIABLE.match(value)
    if named:
        value = env.get(named.group(1) or named.group(2), value)
    if value.startswith("env://"):
        return "environment_variable", None
    scheme = SCHEME.match(value)
    if not scheme:
        return "other", None
    return KEY_SCHEMES[scheme.group(1)], value if KMS_REFERENCE.fullmatch(value) else None


def can_be_on(value):
    """A switch that is on, or an expression that can turn it on."""
    return value is True or isinstance(value, str) and value.strip().lower() != "false"


def step_rows(job_id, job, env):
    """(signing, verification, other) cosign commands of one job, whether it installs cosign, whether it names it."""
    signing, verification, other, installs, mentions = [], [], [], False, False
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    for number, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            continue
        installs = installs or str(step.get("uses") or "").lower().startswith(INSTALLER)
        mentions = mentions or bool(MENTION.search(str(step.get("uses") or ""))
                                    or any(MENTION.search(text) for text, _ in segments(step.get("run"))))
        scope = literal_env(env, step.get("env"))
        for sub, text, discarded in commands(step.get("run")):
            row = {
                "job": str(job_id),
                "step": step.get("name") if isinstance(step.get("name"), str) else None,
                "step_number": number,
                "command": sub,
                "names_digest": bool(DIGEST.search(text)),
                # A run can succeed without a step like this having run or passed.
                "conditional": step.get("if") is not None or job.get("if") is not None,
                "continue_on_error": can_be_on(step.get("continue-on-error")) or can_be_on(job.get("continue-on-error")),
                "failure_discarded": discarded,
            }
            if sub == "sign":
                kind, reference = key_of(text, scope)
                tlog = flag(text, "--tlog-upload")
                signing.append({**row, "key": kind, "key_reference": reference,
                                "skips_transparency_log": str(tlog).lower() == "false"})
            elif sub == "verify":
                checks = ("key" if flag(text, "--key") is not None
                          else "certificate_identity" if "--certificate-identity" in text else "unspecified")
                verification.append({**row, "checks": checks,
                                     "skips_transparency_log": "--insecure-ignore-tlog" in text})
            else:
                other.append(row)
    return signing, verification, other, installs, mentions


def analyse(name, text):
    """One workflow file as evidence. An unparseable file is reported, not guessed at: GitHub will not run it either."""
    row = {"file": name, "path": f".github/workflows/{name}", "parsed": False, "installs_cosign": False,
           "mentions_cosign": False, "signing_steps": [], "verification_steps": [], "other_cosign_steps": [],
           "reusable_workflows_called": [], "runs": None}
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return {**row, "error": str(exc).splitlines()[0][:200]}
    if not isinstance(doc, dict):
        return {**row, "error": "not a mapping"}
    row["parsed"] = True
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    for job_id, job in jobs.items():
        job = job if isinstance(job, dict) else {}
        if isinstance(job.get("uses"), str):
            # Its steps live in another file, possibly another repository: what it signs is not read here.
            row["reusable_workflows_called"].append(job["uses"])
        signing, verification, other, installs, mentions = step_rows(job_id, job,
                                                                       literal_env(doc.get("env"), job.get("env")))
        row["signing_steps"] += signing
        row["verification_steps"] += verification
        row["other_cosign_steps"] += other
        row["installs_cosign"] = row["installs_cosign"] or installs
        row["mentions_cosign"] = row["mentions_cosign"] or mentions or "cosign" in str(job.get("uses") or "").lower()
    return row


def run_history(client, base, file, since, cap):
    """How one workflow ran in the window. read is False when the runs could not be read: unknown, not none.

    Pull request runs are counted apart and left out of every other figure (see PULL_REQUEST_EVENTS).
    """
    listed = newest_since(client, f"{base}/actions/workflows/{quote(file, safe='')}/runs", "workflow_runs", since, cap,
                          "runs of a signing workflow", "GITHUB_IMAGE_SIGNING_MAX_RUNS")
    if listed is None:
        return {"read": False}
    runs = [r for r in listed if r.get("event") not in PULL_REQUEST_EVENTS]
    outcomes = [r.get("conclusion") or r.get("status") or "unknown" for r in runs]
    passed = [r for r in runs if r.get("conclusion") == "success"]
    return {
        "read": True,
        "pull_request_runs": len(listed) - len(runs),
        "total": len(runs),
        "successful": len(passed),
        "by_outcome": {o: outcomes.count(o) for o in sorted(set(outcomes))},
        "latest_run_at": runs[0].get("created_at") if runs else None,
        "latest_outcome": outcomes[0] if runs else None,
        "latest_success_at": passed[0].get("created_at") if passed else None,
    }


def repo_record(client, org, repo, files, since, config):
    name = repo["name"]
    unreadable = [f for f, text in files if text is None]
    if unreadable:
        # Its content is unknown, so whether this repository signs is unknown too.
        client.fail("GraphQL workflow files", "ContentUnreadable",
                    f"{name}: {len(unreadable)} workflow file(s) returned no readable content", "partial_failure")
        return {"repository": name, "collected": False}
    rows = [analyse(f, text) for f, text in files]
    if config["include_runs"]:
        for row in rows:
            if row["signing_steps"]:
                row["runs"] = run_history(client, f"repos/{org}/{name}", row["file"], since, config["max_runs"])
    return {"repository": name, "collected": True, "default_branch": repo.get("default_branch"), "workflows": rows}


def collect(client, org, repos, config):
    if not 1 <= config["days_back"] <= MAX_DAYS_BACK or config["max_runs"] < 1:
        client.fail("config", "BadConfig", f"GITHUB_IMAGE_SIGNING_DAYS_BACK must be 1..{MAX_DAYS_BACK} and "
                    "GITHUB_IMAGE_SIGNING_MAX_RUNS at least 1", "bad_config")
        return None
    files = workflow_file_texts(client, org["login"], repos)
    if files is None:
        return None
    since = now_epoch() - config["days_back"] * 86400
    records = [repo_record(client, org["login"], r, files.get(r["name"], []), since, config) for r in repos]
    done = [r for r in records if r["collected"]]
    flows = [(r["repository"], w) for r in done for w in r["workflows"]]
    signing = [(repo, w, s) for repo, w in flows for s in w["signing_steps"]]
    verifying = [(repo, w, s) for repo, w in flows for s in w["verification_steps"]]

    def at(repo, w):
        return f"{repo}:{w['path']}"

    def steps(rows, test):
        return sorted({f"{at(repo, w)}:{s['job']}:{s['step_number']}" for repo, w, s in rows if test(s)})

    signers = sorted({repo for repo, _, _ in signing})
    verifiers = {repo for repo, _, _ in verifying}
    # Run figures are known only when runs were asked for and every signing workflow's runs were read.
    histories = [(at(repo, w), w["runs"]) for repo, w in flows if w["signing_steps"]]
    runs_read = all(h and h["read"] for _, h in histories) if config["include_runs"] else None
    latest = sorted(h["latest_success_at"] for _, h in histories if runs_read and h["latest_success_at"])
    return {
        "metadata": {"since": iso(since) if config["include_runs"] else None},
        "summary": {
            "repositories_total": len(records),
            "workflow_files": len(flows),
            "workflow_files_unparsed": sorted(at(repo, w) for repo, w in flows if not w["parsed"]),
            "repositories_signing": signers,
            "signing_workflows": sorted({at(repo, w) for repo, w, _ in signing}),
            "signing_steps": len(signing),
            "signing_steps_by_key": {k: sum(1 for _, _, s in signing if s["key"] == k) for k in KEY_KINDS},
            "signing_steps_naming_a_digest": sum(1 for _, _, s in signing if s["names_digest"]),
            "signing_steps_skipping_transparency_log": sum(1 for _, _, s in signing if s["skips_transparency_log"]),
            "signing_steps_conditional": steps(signing, lambda s: s["conditional"]),
            "signing_steps_continue_on_error": steps(signing, lambda s: s["continue_on_error"]),
            "signing_steps_discarding_failure": steps(signing, lambda s: s["failure_discarded"]),
            "verification_workflows": sorted({at(repo, w) for repo, w, _ in verifying}),
            "verification_steps": len(verifying),
            # A verify step that cannot fail the run checks nothing that anyone must act on.
            "verification_steps_not_enforced": steps(verifying,
                                                     lambda s: s["continue_on_error"] or s["failure_discarded"]),
            "repositories_signing_without_verification": [r for r in signers if r not in verifiers],
            # cosign is used here in a way this file does not show: a script, a make target, another workflow.
            "workflows_mentioning_cosign_without_a_cosign_command": sorted(
                at(repo, w) for repo, w in flows
                if w["mentions_cosign"] and not (w["signing_steps"] or w["verification_steps"] or w["other_cosign_steps"])),
            # Their steps live in another file, possibly another repository, so what they sign is not read here.
            "workflows_calling_reusable_workflows": sorted(at(repo, w) for repo, w in flows
                                                           if w["reusable_workflows_called"]),
            "runs_read": runs_read,
            "signing_workflow_runs": sum(h["total"] for _, h in histories) if runs_read else None,
            "signing_workflow_runs_successful": sum(h["successful"] for _, h in histories) if runs_read else None,
            "signing_workflow_pull_request_runs": (sum(h["pull_request_runs"] for _, h in histories)
                                                   if runs_read else None),
            "signing_workflows_without_successful_run": (sorted(k for k, h in histories if not h["successful"])
                                                         if runs_read else None),
            "latest_successful_signing_run": latest[-1] if latest else None,
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
