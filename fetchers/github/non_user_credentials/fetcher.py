#!/usr/bin/env python3
"""Credentials that are not a person: deploy keys, installed apps, approved fine-grained tokens, Actions secrets and webhooks."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import iso, now_epoch, run, to_epoch  # noqa: E402

NAME = "github_non_user_credentials"
CONFIG = {
    "max_secret_age_days": ("GITHUB_MAX_SECRET_AGE_DAYS", 365),
    "max_unused_days": ("GITHUB_MAX_UNUSED_DAYS", 90),
}
WRITE_LEVELS = ("write", "admin")


def age_days(value, now):
    epoch = to_epoch(value)
    return None if epoch is None else round((now - epoch) / 86400, 1)


def secret_rows(items, now, max_age):
    return [{"name": s.get("name"), "updated_at": s.get("updated_at"), "age_days": age_days(s.get("updated_at"), now),
             "older_than_max": (age_days(s.get("updated_at"), now) or 0) > max_age} for s in items or []]


def hook_row(hook):
    cfg = hook.get("config") or {}
    return {"id": hook.get("id"), "active": hook.get("active"), "events": hook.get("events"),
            "url_host": (cfg.get("url") or "").split("/")[2] if "://" in (cfg.get("url") or "") else None,
            # "1" skips TLS verification, "0" verifies; missing is unknown, never verified.
            "insecure_ssl": {"1": True, "0": False}.get(str(cfg.get("insecure_ssl"))),
            # GitHub masks a configured secret as ********; absent means payloads are unsigned.
            "has_secret": bool(cfg.get("secret"))}


def repo_record(client, org, repo, now, config):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    keys = client.paginate_required(f"{base}/keys")
    state, secrets = client.paginate(f"{base}/actions/secrets", key="secrets")
    hooks = client.paginate_required(f"{base}/hooks")
    if keys is None or state == "failed" or hooks is None:
        return {"repository": name, "collected": False}
    deploy_keys = [{"id": k.get("id"), "title": k.get("title"), "read_only": k.get("read_only"),
                    "created_at": k.get("created_at"), "age_days": age_days(k.get("created_at"), now),
                    "last_used": k.get("last_used"), "added_by": k.get("added_by"), "verified": k.get("verified")}
                   for k in keys]
    return {
        "repository": name,
        "collected": True,
        "deploy_keys": deploy_keys,
        "write_deploy_keys": [k["title"] for k in deploy_keys if k["read_only"] is False],
        "deploy_keys_access_unknown": [k["title"] for k in deploy_keys if k["read_only"] is None],
        "actions_secrets": secret_rows(secrets, now, config["max_secret_age_days"]),
        "webhooks": [hook_row(h) for h in hooks],
    }


def collect(client, org, repos, config):
    login, now = org["login"], now_epoch()
    # Each organization section stands alone: one the token cannot read is null, and the others are kept.
    installs = client.paginate_required(f"orgs/{login}/installations", key="installations")
    org_secrets = client.paginate_required(f"orgs/{login}/actions/secrets", key="secrets")
    org_hooks = client.paginate_required(f"orgs/{login}/hooks")
    # GitHub lists an organization's fine-grained tokens to GitHub Apps only; a personal token always gets a 403
    # (measured with a token granted every organization permission). Unknown, never zero.
    state, pats = ("apps_only", None) if client.personal_token else \
        client.paginate(f"orgs/{login}/personal-access-tokens")
    apps = None if installs is None else [
        {"app": i.get("app_slug"), "repository_selection": i.get("repository_selection"),
         "permissions": i.get("permissions") or {}, "events": i.get("events"),
         "created_at": i.get("created_at"), "suspended": bool(i.get("suspended_at")),
         "write_permissions": sorted(k for k, v in (i.get("permissions") or {}).items() if v in WRITE_LEVELS)}
        for i in installs]
    tokens = None if state is not None else [
        {"id": p.get("id"), "owner": (p.get("owner") or {}).get("login"),
         "repository_selection": p.get("repository_selection"),
         "permissions": p.get("permissions"), "token_expired": p.get("token_expired"),
         "token_expires_at": p.get("token_expires_at"), "token_last_used_at": p.get("token_last_used_at"),
         "unused_days": age_days(p.get("token_last_used_at") or p.get("access_granted_at"), now)}
        for p in pats]
    records = [repo_record(client, login, r, now, config) for r in repos]
    done = [r for r in records if r["collected"]]
    org_secret_rows = None if org_secrets is None else secret_rows(org_secrets, now, config["max_secret_age_days"])
    hooks = [{"scope": "organization", **hook_row(h)} for h in org_hooks or []] + [
        {"scope": r["repository"], **h} for r in done for h in r["webhooks"]]
    return {
        "summary": {
            "deploy_keys_allowed": org.get("deploy_keys_enabled_for_repositories"),
            "deploy_keys_total": sum(len(r["deploy_keys"]) for r in done),
            "write_deploy_keys": sorted(f"{r['repository']}:{t}" for r in done for t in r["write_deploy_keys"]),
            "deploy_keys_access_unknown": sorted(f"{r['repository']}:{t}" for r in done
                                                 for t in r["deploy_keys_access_unknown"]),
            "apps_installed": None if apps is None else len(apps),
            "apps_with_write": None if apps is None else sorted(a["app"] for a in apps if a["write_permissions"]),
            "apps_on_all_repositories": None if apps is None else sorted(
                a["app"] for a in apps if a["repository_selection"] == "all"),
            "fine_grained_tokens": None if tokens is None else len(tokens),
            "fine_grained_tokens_without_expiry": None if tokens is None else
            len([t for t in tokens if not t["token_expires_at"]]),
            "fine_grained_tokens_unused": None if tokens is None else
            len([t for t in tokens if (t["unused_days"] or 0) > config["max_unused_days"]]),
            "actions_secrets_total": None if org_secret_rows is None else
            len(org_secret_rows) + sum(len(r["actions_secrets"]) for r in done),
            "actions_secrets_older_than_max": None if org_secret_rows is None else sorted(
                [f"org:{s['name']}" for s in org_secret_rows if s["older_than_max"]]
                + [f"{r['repository']}:{s['name']}" for r in done for s in r["actions_secrets"] if s["older_than_max"]]),
            "webhooks_insecure_ssl": None if org_hooks is None else len([h for h in hooks if h["insecure_ssl"]]),
            "webhooks_tls_unknown": None if org_hooks is None else len([h for h in hooks if h["insecure_ssl"] is None]),
            "webhooks_without_secret": None if org_hooks is None else len([h for h in hooks if not h["has_secret"]]),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "apps": apps,
        "fine_grained_tokens": tokens,
        "organization_actions_secrets": org_secret_rows,
        "webhooks": hooks,
        "repositories": records,
        "metadata": {"as_of": iso(now), "fine_grained_tokens_readable": tokens is not None,
                     **({"fine_grained_tokens_unreadable_because": "listed to GitHub Apps only; this run used a "
                                                                    "personal access token"}
                        if state == "apps_only" else {})},
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
