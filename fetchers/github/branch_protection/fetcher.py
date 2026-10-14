#!/usr/bin/env python3
"""The protection actually enforced on each repository's default branch, from rulesets and classic branch protection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import ruleset_targets_ref, run  # noqa: E402

NAME = "github_branch_protection"


def ruleset_targets_branch(ruleset, repo_name, default_branch):
    """True/False when the ruleset's conditions can be evaluated here; None when they depend on repository properties."""
    return ruleset_targets_ref(ruleset, repo_name, f"refs/heads/{default_branch}", default_branch)


def from_rules(rules):
    """Requirements from the rules GitHub reports as enforced on the branch (rules/branches/{branch})."""
    req = {"rule_types": sorted({r.get("type") for r in rules if r.get("type")})}
    for rule in rules:
        kind, params = rule.get("type"), rule.get("parameters") or {}
        if kind == "pull_request":
            req["pull_request"] = True
            req["approvals"] = max(req.get("approvals", 0), params.get("required_approving_review_count") or 0)
            for key, out in (("require_code_owner_review", "code_owner_review"),
                             ("dismiss_stale_reviews_on_push", "dismiss_stale_reviews"),
                             ("require_last_push_approval", "last_push_approval")):
                req[out] = req.get(out, False) or bool(params.get(key))
        elif kind == "required_status_checks":
            checks = [c.get("context") for c in params.get("required_status_checks") or [] if c.get("context")]
            req["status_checks"] = sorted(set(req.get("status_checks", [])) | set(checks))
            req["strict_status_checks"] = req.get("strict_status_checks", False) or bool(
                params.get("strict_required_status_checks_policy"))
        elif kind == "workflows":
            req["required_workflows"] = req.get("required_workflows", 0) + len(params.get("workflows") or [])
        elif kind == "code_scanning":
            req["code_scanning_tools"] = sorted({t.get("tool") for t in params.get("code_scanning_tools") or []
                                                 if t.get("tool")} | set(req.get("code_scanning_tools", [])))
        elif kind == "required_signatures":
            req["signed_commits"] = True
        elif kind == "non_fast_forward":
            req["blocks_force_push"] = True
        elif kind == "deletion":
            req["blocks_deletion"] = True
        elif kind == "required_linear_history":
            req["linear_history"] = True
    return req


def from_classic(protection):
    """Requirements from classic branch protection, in the same vocabulary as from_rules."""
    req = {}
    reviews = protection.get("required_pull_request_reviews")
    if reviews is not None:
        req["pull_request"] = True
        req["approvals"] = reviews.get("required_approving_review_count") or 0
        req["code_owner_review"] = bool(reviews.get("require_code_owner_reviews"))
        req["dismiss_stale_reviews"] = bool(reviews.get("dismiss_stale_reviews"))
        req["last_push_approval"] = bool(reviews.get("require_last_push_approval"))
    checks = protection.get("required_status_checks")
    if checks is not None:
        contexts = set(checks.get("contexts") or []) | {c.get("context") for c in checks.get("checks") or []
                                                       if c.get("context")}
        req["status_checks"] = sorted(contexts)
        req["strict_status_checks"] = bool(checks.get("strict"))
    if (protection.get("required_signatures") or {}).get("enabled"):
        req["signed_commits"] = True
    if (protection.get("allow_force_pushes") or {}).get("enabled") is False:
        req["blocks_force_push"] = True
    if (protection.get("allow_deletions") or {}).get("enabled") is False:
        req["blocks_deletion"] = True
    if (protection.get("required_linear_history") or {}).get("enabled"):
        req["linear_history"] = True
    return req


def merge(a, b):
    """The stricter of two requirement sets. GitHub enforces rulesets and classic protection together."""
    out = dict(a)
    for key, value in b.items():
        if key == "approvals":
            out[key] = max(out.get(key, 0), value)
        elif isinstance(value, list):
            out[key] = sorted(set(out.get(key, [])) | set(value))
        elif isinstance(value, bool):
            out[key] = out.get(key, False) or value
        else:
            out[key] = out.get(key, 0) + value
    return out


def bypass_summary(ruleset):
    actors = ruleset.get("bypass_actors")
    if actors is None:
        return None  # only returned to a token with admin rights on the ruleset's source
    return [{"actor_type": a.get("actor_type"), "actor_id": a.get("actor_id"), "bypass_mode": a.get("bypass_mode")}
            for a in actors]


def codeowners(client, base, branch):
    """{"state": "valid" | "errors" | "missing", "errors": [...]}, or None when unreadable (recorded).

    Required code-owner review with no CODEOWNERS file, or a file GitHub cannot parse, requires nothing: GitHub skips
    the lines it cannot read and a path with no owner needs no owner's review.
    """
    failures = len(client.failures)
    found, body = client.lookup(f"{base}/codeowners/errors", {"ref": branch})  # 404: no CODEOWNERS file
    if len(client.failures) > failures:
        return None
    if not found:
        return {"state": "missing", "errors": []}
    errors = [{"path": e.get("path"), "line": e.get("line"), "kind": e.get("kind"), "message": e.get("message")}
              for e in (body or {}).get("errors") or []]
    return {"state": "errors" if errors else "valid", "errors": errors}


def bypasses(client, base):
    """Pushes in the last month that bypassed a ruleset (rule suites), or None when unreadable (recorded)."""
    found = client.paginate_required(f"{base}/rulesets/rule-suites", {"time_period": "month",
                                                                       "rule_suite_result": "bypass"})
    return None if found is None else [
        {"actor": s.get("actor_name"), "ref": s.get("ref"), "pushed_at": s.get("pushed_at"),
         "after_sha": s.get("after_sha")} for s in found]


def repo_record(client, org, repo, details):
    name, branch = repo["name"], repo.get("default_branch")
    record = {
        "repository": name,
        "visibility": repo.get("visibility"),
        "archived": bool(repo.get("archived")),
        "fork": bool(repo.get("fork")),
        "default_branch": branch,
        "empty": repo.get("size") == 0 and not repo.get("pushed_at"),
    }
    base = f"repos/{org}/{name}"

    rules = client.paginate_required(f"{base}/rules/branches/{branch}")
    rulesets = client.paginate_required(f"{base}/rulesets", {"includes_parents": "true"})
    if rules is None or rulesets is None:
        record.update({"collected": False, "requires_pull_request": None, "requires_approval": None,
                       "requires_status_checks": None})
        return record
    state, protection = client.read(f"{base}/branches/{branch}/protection")

    enforced_ids = {r.get("ruleset_id") for r in rules}
    sets = []
    for summary in rulesets:
        key = summary["id"]
        if key not in details:
            details[key] = client.get(f"{base}/rulesets/{key}")
        detail = details[key] or summary
        sets.append({
            "id": key,
            "name": detail.get("name"),
            "source_type": detail.get("source_type"),
            "source": detail.get("source"),
            "enforcement": detail.get("enforcement"),
            "targets_default_branch": ruleset_targets_branch(detail, name, branch),
            "enforced_on_default_branch": key in enforced_ids,
            "rule_types": sorted({r.get("type") for r in detail.get("rules") or [] if r.get("type")}),
            "bypass_actors": bypass_summary(detail),
        })

    classic = protection if state is None else None
    classic_known = state != "failed"  # a token without administration:read cannot see classic protection
    requirements = merge(from_rules(rules), from_classic(classic or {}))
    # Like classic protection, each of these is unknown when unreadable (and the run fails), never a reason to drop
    # what the rules already prove.
    owners = codeowners(client, base, branch) if requirements.get("code_owner_review") else None
    # Rule suites record ruleset evaluations only; classic protection has no bypass log.
    bypassed = bypasses(client, base) if rulesets else []
    record.update({
        "classic_protection": None if classic is None else {
            "enforce_admins": (classic.get("enforce_admins") or {}).get("enabled"),
            "bypass_pull_request_allowances": bool(
                ((classic.get("required_pull_request_reviews") or {}).get("bypass_pull_request_allowances") or {})
                .get("users") or ((classic.get("required_pull_request_reviews") or {})
                                  .get("bypass_pull_request_allowances") or {}).get("teams")),
        },
        "collected": True,
        "classic_protection_state": "present" if classic is not None else "unreadable" if not classic_known else state,
        "requirements": requirements,
        "codeowners": owners,
        "ruleset_bypasses_last_month": bypassed,
        "rulesets": sets,
        "rulesets_not_enforced": [s["name"] for s in sets
                                  if s["targets_default_branch"] is not False and s["enforcement"] != "active"],
        "rulesets_with_always_bypass": [s["name"] for s in sets if s["enforced_on_default_branch"]
                                        and any(a["bypass_mode"] == "always" for a in s["bypass_actors"] or [])],
        "admins_exempt_from_classic": classic is not None and
                                      (classic.get("enforce_admins") or {}).get("enabled") is False,
    })
    # Rules alone can prove a requirement; only classic protection we could read can disprove one.
    for key, met in (("requires_pull_request", bool(requirements.get("pull_request"))),
                     ("requires_approval", requirements.get("approvals", 0) >= 1),
                     ("requires_status_checks", bool(requirements.get("status_checks")))):
        record[key] = True if met else (False if classic_known else None)
    return record


def summarize(records):
    def names(pred):
        return [r["repository"] for r in records if pred(r)]
    known = [r for r in records if r["collected"]]
    return {
        "repositories_total": len(records),
        "not_collected": names(lambda r: not r["collected"]),
        "classic_protection_unreadable": names(lambda r: r.get("classic_protection_state") == "unreadable"),
        "requiring_pull_request": len(names(lambda r: r["requires_pull_request"] is True)),
        "requiring_approval": len(names(lambda r: r["requires_approval"] is True)),
        "requiring_status_checks": len(names(lambda r: r["requires_status_checks"] is True)),
        "requiring_signed_commits": len([r for r in known if r["requirements"].get("signed_commits")]),
        "blocking_force_push": len([r for r in known if r["requirements"].get("blocks_force_push")]),
        "unprotected": [r["repository"] for r in known if not r["requirements"].get("rule_types")
                        and r["classic_protection_state"] in ("not_protected", "no_branch")],
        "without_approval": names(lambda r: r["requires_approval"] is False),
        "without_status_checks": names(lambda r: r["requires_status_checks"] is False),
        "with_rulesets_not_enforced": names(lambda r: r.get("rulesets_not_enforced")),
        "with_always_bypass": names(lambda r: r.get("rulesets_with_always_bypass")),
        # Bypass actors are returned only to a token with admin rights on the ruleset's source: unknown, not none.
        "bypass_actors_unreadable": names(lambda r: any(s["enforced_on_default_branch"] and s["bypass_actors"] is None
                                                        for s in r.get("rulesets") or [])),
        "admins_exempt_from_classic": names(lambda r: r.get("admins_exempt_from_classic")),
        "code_owner_review_without_valid_codeowners": names(
            lambda r: (r.get("codeowners") or {}).get("state") in ("missing", "errors")),
        "ruleset_bypasses_last_month": sum(len(r.get("ruleset_bypasses_last_month") or []) for r in known),
        "with_ruleset_bypasses_last_month": names(lambda r: r.get("ruleset_bypasses_last_month")),
        "ruleset_bypasses_unreadable": names(lambda r: r["collected"] and r.get("ruleset_bypasses_last_month") is None),
        "empty": names(lambda r: r["empty"]),
    }


def collect(client, org, repos, config):
    details = {}
    records = []
    for repo in repos:
        records.append(repo_record(client, org["login"], repo, details))
    plan = (org.get("plan") or {}).get("name")
    return {
        "metadata": {"org_rulesets_available": None if plan is None else plan not in ("free",)},
        "summary": summarize(records),
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect))
