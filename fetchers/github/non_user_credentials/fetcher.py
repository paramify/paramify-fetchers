#!/usr/bin/env python3
"""Credentials that are not a person: deploy keys, installed apps, approved fine-grained tokens, Actions secrets and webhooks.

Actions secret names and ages are collected only when the token can list them.
Repository Secrets and organization Secrets read are not required: without that
grant the lists are null, metadata says why, and the rest of the evidence is kept.
The list API never returns a secret value.
"""

import sys
from pathlib import Path
from urllib.parse import quote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import iso, now_epoch, run, split_list, to_epoch  # noqa: E402

NAME = "github_non_user_credentials"
CONFIG = {
    "max_secret_age_days": ("GITHUB_MAX_SECRET_AGE_DAYS", 365),
    "max_unused_days": ("GITHUB_MAX_UNUSED_DAYS", 90),
    "scope_to_repositories": ("GITHUB_SCOPE_TO_REPOSITORIES", False),
    "apps_confirmed_reaching": ("GITHUB_APPS_CONFIRMED_REACHING", ""),
    "apps_confirmed_not_reaching": ("GITHUB_APPS_CONFIRMED_NOT_REACHING", ""),
}
CONFIRMATION_NOTE = ("GitHub shows the repositories of an app installed on selected repositories to that app alone. "
                     "The reach of the apps in apps_reach_confirmed_by_organization and "
                     "apps_left_out_by_confirmation comes from the organization's confirmation in this fetcher's "
                     "settings, not from GitHub.")
WRITE_LEVELS = ("write", "admin")
# Fine-grained token page names. GitHub quotes the one an endpoint requires in
# X-Accepted-GitHub-Permissions, which the client appends as "(needs: …)".
SECRETS_READ = {"secrets=read", "organization_secrets=read"}


def confirmed_apps(config):
    """(slugs confirmed reaching, slugs confirmed not reaching), lowercased."""
    return ({a.lower() for a in split_list(config["apps_confirmed_reaching"])},
            {a.lower() for a in split_list(config["apps_confirmed_not_reaching"])})


def check_settings(config):
    """The reason the settings cannot run, or None. Checked before the first API call."""
    confirmed_in, confirmed_out = confirmed_apps(config)
    if (confirmed_in or confirmed_out) and not config["scope_to_repositories"]:
        return "apps_confirmed_reaching and apps_confirmed_not_reaching only apply with scope_to_repositories"
    if confirmed_in & confirmed_out:
        return ("an app is named in both apps_confirmed_reaching and apps_confirmed_not_reaching: "
                + ", ".join(sorted(confirmed_in & confirmed_out)))
    return None


def app_reach(install, confirmed_in, confirmed_out):
    """(whether an installed app can reach a collected repository, where that answer comes from).

    An app on all repositories reaches every one ("github"). For an app on selected repositories GitHub gives the
    list to that app alone (GET /installation/repositories with its own token), so another caller cannot tell: unknown,
    never no, unless the organization confirmed it in the settings ("organization_confirmation"). A confirmation never
    overrides what GitHub shows, and is not applied to a selection GitHub did not name.
    """
    selection = install.get("repository_selection")
    if selection == "all":
        return True, "github"
    slug = str(install.get("app_slug") or "").lower()
    if selection == "selected" and slug in confirmed_in:
        return True, "organization_confirmation"
    if selection == "selected" and slug in confirmed_out:
        return False, "organization_confirmation"
    return None, None


def secret_reach(client, login, secret, repos, names):
    """Whether an organization secret is available to a collected repository: True, False, or None when unknown."""
    visibility = secret.get("visibility")
    if visibility == "all":
        return True
    if visibility == "private":
        kinds = {r.get("visibility") for r in repos}
        if "private" in kinds:
            return True
        # Whether "private" also covers internal repositories is not measured, and a repository whose visibility
        # GitHub did not return could be private: either leaves it unknown. Only all-public is a no.
        return False if kinds and kinds <= {"public"} else None
    if visibility == "selected":
        chosen = client.paginate_required(f"orgs/{login}/actions/secrets/{quote(str(secret.get('name')), safe='')}"
                                          "/repositories", key="repositories")
        return None if chosen is None else any((r.get("name") or "").lower() in names for r in chosen)
    return None


def token_reach(client, login, grant, names):
    """Whether a fine-grained token can reach a collected repository: True, False, or None when unknown."""
    selection = grant.get("repository_selection")
    if selection == "all":
        return True
    if selection == "none":
        return False
    if selection == "subset" and grant.get("id") is not None:
        chosen = client.paginate_required(f"orgs/{login}/personal-access-tokens/{grant['id']}/repositories")
        return None if chosen is None else any((r.get("name") or "").lower() in names for r in chosen)
    return None


def in_scope(rows, reaches):
    """(kept rows, each marked with its reach; count left out). A row is left out only on a proven no."""
    kept = [{**row, "reaches_collected_repositories": reach} for row, reach in zip(rows, reaches) if reach is not False]
    return kept, len(rows) - len(kept)


def age_days(value, now):
    epoch = to_epoch(value)
    return None if epoch is None else round((now - epoch) / 86400, 1)


def secret_rows(items, now, max_age):
    return [{"name": s.get("name"), "updated_at": s.get("updated_at"), "age_days": age_days(s.get("updated_at"), now),
             "older_than_max": (age_days(s.get("updated_at"), now) or 0) > max_age} for s in items or []]


def _missing_secrets_read(failure):
    """True when GitHub refused the call because this token lacks Secrets read."""
    if failure.get("type") != "HTTP 403":
        return False
    message = failure.get("message") or ""
    marker = "(needs: "
    if marker not in message or not message.endswith(")"):
        return False
    needed = message[message.rindex(marker) + len(marker):-1]
    grants = {part.strip().lower() for part in needed.replace(";", ",").split(",") if part.strip()}
    return bool(grants & SECRETS_READ)


def read_actions_secrets(client, path):
    """("ok", items), ("unreadable", None) or ("failed", None).

    A 403 that names secrets=read or organization_secrets=read is the token
    declining that grant. Drop that recorded failure so the run still succeeds
    and the caller can leave the list null. Any other error stays recorded.
    """
    recorded = len(client.failures)
    items = client.paginate_required(path, key="secrets")
    if items is not None:
        return "ok", items
    if len(client.failures) == recorded + 1 and _missing_secrets_read(client.failures[-1]):
        client.failures.pop()
        client.codes.pop()
        return "unreadable", None
    return "failed", None


def hook_row(hook):
    cfg = hook.get("config") or {}
    return {"id": hook.get("id"), "active": hook.get("active"), "events": hook.get("events"),
            # hostname, not netloc: a URL can carry user:password@ before the host.
            "url_host": urlparse(cfg.get("url") or "").hostname,
            # "1" skips TLS verification, "0" verifies; missing is unknown, never verified.
            "insecure_ssl": {"1": True, "0": False}.get(str(cfg.get("insecure_ssl"))),
            # GitHub masks a configured secret as ********; absent means payloads are unsigned.
            "has_secret": bool(cfg.get("secret"))}


def repo_record(client, org, repo, now, config):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    keys = client.paginate_required(f"{base}/keys")
    secret_state, secrets = read_actions_secrets(client, f"{base}/actions/secrets")
    hooks = client.paginate_required(f"{base}/hooks")
    if keys is None or secret_state == "failed" or hooks is None:
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
        "actions_secrets": None if secret_state == "unreadable" else secret_rows(
            secrets, now, config["max_secret_age_days"]),
        "webhooks": [hook_row(h) for h in hooks],
    }


def collect(client, org, repos, config):
    login, now = org["login"], now_epoch()
    confirmed_in, confirmed_out = confirmed_apps(config)
    # Each organization section stands alone: one the token cannot read is null, and the others are kept.
    installs = client.paginate_required(f"orgs/{login}/installations", key="installations")
    org_secret_state, org_secrets = read_actions_secrets(client, f"orgs/{login}/actions/secrets")
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
    org_secret_rows = None if org_secret_state != "ok" else [
        # all, private or selected: which of the organization's repositories may use the secret.
        {**row, "visibility": s.get("visibility")}
        for row, s in zip(secret_rows(org_secrets, now, config["max_secret_age_days"]), org_secrets)]
    # Scoping leaves out the organization's apps, tokens and secrets that are proven unable to reach a collected
    # repository. One whose reach cannot be told stays in, marked null: unknown is not out of scope. A section that
    # was not read stays null, and its left-out count with it.
    scoped = bool(config["scope_to_repositories"])
    confirmation = {"apps_left_out_by_confirmation": None, "apps_confirmed_unmatched": None,
                    "apps_confirmation_contradicted": None}
    left_out = {"apps": 0 if apps is not None else None, "fine_grained_tokens": 0 if tokens is not None else None,
                "organization_secrets": 0 if org_secret_rows is not None else None}
    if scoped:
        names = {(r.get("name") or "").lower() for r in repos}
        if apps is not None:
            reach = [app_reach(i, confirmed_in, confirmed_out) for i in installs]
            confirmed_out_apps = sorted(str(a["app"]) for a, (r, src) in zip(apps, reach)
                                        if r is False and src == "organization_confirmation")
            apps = [{**a, "reach_source": src} for a, (_, src) in zip(apps, reach)]
            apps, left_out["apps"] = in_scope(apps, [r for r, _ in reach])
            installed = {str(i.get("app_slug") or "").lower(): i.get("repository_selection") for i in installs}
            confirmation = {
                "apps_left_out_by_confirmation": confirmed_out_apps,
                # Named in the settings but not installed: a typo, or an app removed since it was confirmed.
                "apps_confirmed_unmatched": sorted((confirmed_in | confirmed_out) - set(installed)),
                # Confirmed as not reaching, but GitHub shows it on all repositories: GitHub wins, and it is kept.
                "apps_confirmation_contradicted": sorted(a for a in confirmed_out if installed.get(a) == "all"),
            }
        if tokens is not None:
            tokens, left_out["fine_grained_tokens"] = in_scope(
                tokens, [token_reach(client, login, p, names) for p in pats])
        if org_secret_rows is not None:
            org_secret_rows, left_out["organization_secrets"] = in_scope(
                org_secret_rows, [secret_reach(client, login, s, repos, names) for s in org_secrets])

    secret_lists = [r["actions_secrets"] for r in done]
    # A missing grant, or a repository whose list was not read, leaves the totals
    # null: a short count would look like the whole estate. Counted after scoping, so the totals cover only the
    # organization secrets that can reach the collected repositories.
    secrets_complete = org_secret_rows is not None and all(items is not None for items in secret_lists)
    secrets_unreadable = org_secret_state == "unreadable" or any(items is None for items in secret_lists)

    def unknown(rows, key):
        """Names of the kept rows whose reach is unknown; null when not scoped or the section was not read."""
        return None if not scoped or rows is None else sorted(
            str(r[key]) for r in rows if r["reaches_collected_repositories"] is None)
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
            "actions_secrets_total": None if not secrets_complete else
            len(org_secret_rows) + sum(len(items) for items in secret_lists),
            "actions_secrets_older_than_max": None if not secrets_complete else sorted(
                [f"org:{s['name']}" for s in org_secret_rows if s["older_than_max"]]
                + [f"{r['repository']}:{s['name']}" for r in done for s in r["actions_secrets"] if s["older_than_max"]]),
            "webhooks_insecure_ssl": None if org_hooks is None else len([h for h in hooks if h["insecure_ssl"]]),
            "webhooks_tls_unknown": None if org_hooks is None else len([h for h in hooks if h["insecure_ssl"] is None]),
            "webhooks_without_secret": None if org_hooks is None else len([h for h in hooks if not h["has_secret"]]),
            # Kept because their reach into the collected repositories could not be told; null when not scoped.
            "apps_reach_unknown": unknown(apps, "app"),
            # Kept on the organization's confirmation rather than on what GitHub shows; null when not scoped.
            "apps_reach_confirmed_by_organization": None if not scoped or apps is None else sorted(
                str(a["app"]) for a in apps if a["reach_source"] == "organization_confirmation"),
            "fine_grained_tokens_reach_unknown": unknown(tokens, "id"),
            "organization_secrets_reach_unknown": unknown(org_secret_rows, "name"),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "apps": apps,
        "fine_grained_tokens": tokens,
        "organization_actions_secrets": org_secret_rows,
        "webhooks": hooks,
        "repositories": records,
        "metadata": {"as_of": iso(now), "fine_grained_tokens_readable": tokens is not None,
                     # True: apps, tokens and organization secrets are limited to those that can reach the collected
                     # repositories, or whose reach is unknown. Organization webhooks are not scoped.
                     "scoped_to_repositories": scoped,
                     "apps_left_out": left_out["apps"],
                     "fine_grained_tokens_left_out": left_out["fine_grained_tokens"],
                     "organization_secrets_left_out": left_out["organization_secrets"],
                     **confirmation,
                     **({"apps_confirmation_note": CONFIRMATION_NOTE} if confirmed_in or confirmed_out else {}),
                     **({"fine_grained_tokens_unreadable_because": "listed to GitHub Apps only; this run used a "
                                                                    "personal access token"}
                        if state == "apps_only" else {}),
                     "actions_secrets_readable": secrets_complete,
                     **({"actions_secrets_unreadable_because":
                         "the token has no read access to Actions secrets; names and ages were left out. "
                         "This API never returns secret values."}
                        if secrets_unreadable else {})},
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG, check=check_settings))
