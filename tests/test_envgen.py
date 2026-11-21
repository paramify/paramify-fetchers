"""The .env a manifest needs: grouped by tool, never overwriting what is already set."""

from __future__ import annotations

import json
import os
from unittest import mock

import pytest
import yaml
from typer.testing import CliRunner

from framework import api, cli, envgen

ROOT = api.find_repo_root()
FOUND = api.discover(ROOT)


@pytest.fixture(autouse=True)
def _environ_restored():
    """refresh_env writes os.environ directly; no test leaves a variable behind."""
    with mock.patch.dict(os.environ):
        yield


def wired(name):
    """A manifest entry with every declared secret mapped to its declared variable, as adding
    a fetcher in the TUI does."""
    from framework.contract import effective_secrets, platform_for

    f = FOUND["fetchers"][name]
    secrets = {s.name: f"${{env:{s.env}}}" for s in effective_secrets(f, platform_for(f, FOUND["platforms"]))}
    return {"use": name, "secrets": secrets}


def manifest(*entries, platforms=None):
    """Names are wired (see `wired`); dicts are taken as written."""
    run = {"fetchers": [e if isinstance(e, dict) else wired(e) if e in FOUND["fetchers"] else {"use": e}
                        for e in entries]}
    if platforms:
        run["platforms"] = platforms
    return {"run": run}


def needs(*entries, platforms=None):
    return envgen.env_groups(FOUND["fetchers"], FOUND["platforms"], manifest(*entries, platforms=platforms))


def groups_for(*entries, platforms=None):
    return needs(*entries, platforms=platforms)[0]


def merge(env, groups):
    """Merge into a test file the way generate_env does, for hand-made groups."""
    text, result = envgen.merged(env.read_text() if env.exists() else "", groups)
    env.write_text(text)
    return result


def names(groups):
    return [v.name for g in groups for v in g.vars]


def test_groups_by_category_with_display_name():
    groups = groups_for("okta_least_privilege")
    assert [g.title for g in groups] == ["Paramify", "Okta"]
    assert names(groups[:1]) == ["PARAMIFY_UPLOAD_API_TOKEN", "PARAMIFY_API_BASE_URL"]
    assert groups[0].vars[0].required is True
    assert groups[0].vars[1].default == "https://app.paramify.com/api/v0"
    okta = {v.name: v for v in groups[1].vars}
    assert okta["OKTA_API_TOKEN"].required and okta["OKTA_ORG_URL"].required
    assert groups[1].about.startswith("Okta identity posture.")
    assert "\n" not in groups[1].about


def test_shared_variable_appears_once():
    groups = groups_for("okta_least_privilege", "okta_authenticators")
    assert names(groups).count("OKTA_API_TOKEN") == 1


def test_platform_level_credentials_are_included():
    groups = groups_for("aws_config_inventory")  # AWS credentials live on the category, not the fetcher
    key = next(v for g in groups for v in g.vars if v.name == "AWS_ACCESS_KEY_ID")
    assert key.required is False


def test_a_config_fields_own_env_name_is_not_listed():
    """The runner sets a config field's env for the fetcher from manifest values; nothing reads it
    from the shell, so filling it in .env would do nothing."""
    got = names(groups_for("okta_least_privilege", "aws_config_inventory"))
    assert "OKTA_KNOWN_SUPER_ADMINS" not in got and "CONFIG_INVENTORY_AGGREGATOR" not in got


def test_an_optional_default_is_written_commented_so_a_later_default_wins():
    text = envgen.plan("", groups_for("okta_least_privilege")).text
    assert "\n# PARAMIFY_API_BASE_URL=https://app.paramify.com/api/v0\n" in text
    base = next(v for v in groups_for()[:1][0].vars if v.name == "PARAMIFY_API_BASE_URL")
    assert "optional (default https://app.paramify.com/api/v0)" in base.note


def test_unknown_fetcher_is_ignored():
    assert [g.title for g in groups_for("nope")] == ["Paramify"]


def test_merge_never_overwrites_or_reorders(tmp_path):
    env = tmp_path / ".env"
    original = "# mine\nOKTA_ORG_URL=https://x\nUNRELATED=1\n"
    env.write_text(original)
    groups = groups_for("okta_least_privilege")
    res = merge(env, groups)
    text = env.read_text()
    assert text.startswith(original)
    assert "OKTA_ORG_URL" in res.already_set and "OKTA_ORG_URL" not in res.added
    assert "OKTA_API_TOKEN" in res.added and "PARAMIFY_UPLOAD_API_TOKEN" in res.added
    assert text.count("OKTA_ORG_URL=") == 1
    # Running again changes nothing.
    again = merge(env, groups)
    assert env.read_text() == text and again.added == []


def test_merge_without_trailing_newline_keeps_bytes(tmp_path):
    env = tmp_path / ".env"
    env.write_text("UNRELATED=1")
    merge(env, groups_for("okta_least_privilege"))
    assert env.read_text().startswith("UNRELATED=1\n")


def test_optional_without_default_is_commented_so_it_cannot_blank_ambient_credentials(tmp_path):
    text = envgen.plan("", groups_for("aws_config_inventory")).text
    assert "\n# AWS_ACCESS_KEY_ID=\n" in text


def test_missing_values_lists_empty_required(tmp_path, monkeypatch):
    for name in ("PARAMIFY_UPLOAD_API_TOKEN", "OKTA_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / ".env"
    env.write_text("OKTA_ORG_URL=https://x\nPARAMIFY_UPLOAD_API_TOKEN=\n")
    out = api.generate_env(ROOT, manifest("okta_least_privilege"), path=env)
    assert out["missing_values"] == ["PARAMIFY_UPLOAD_API_TOKEN", "OKTA_API_TOKEN"]
    assert "OKTA_ORG_URL" in out["already_set"]
    assert env.read_text() == "OKTA_ORG_URL=https://x\nPARAMIFY_UPLOAD_API_TOKEN=\n"  # write=False
    assert "https://x" not in out["text"]  # never echoes existing values


def test_generate_env_write(tmp_path):
    env = tmp_path / ".env"
    out = api.generate_env(ROOT, manifest("okta_least_privilege"), write=True, path=env)
    assert env.read_text() == out["text"]
    assert "OKTA_API_TOKEN" in out["added"]


def test_already_set_means_what_python_dotenv_reads(tmp_path):
    """Runs read .env with python-dotenv; `paramify env` must judge it the same way."""
    groups = [envgen.EnvGroup("T", "", [envgen.EnvVar(n, "x - required", True) for n in ("A", "B", "C")])]
    text = 'A="first\nsecond"\nB="has \\"quote\\""\nC=\n'
    result = envgen.plan(text, groups, environ={})
    assert result.already_set == ["A", "B"] and result.missing == ["C"]
    assert envgen.assigned(text) == {"A": "first\nsecond", "B": 'has "quote"', "C": ""}


def test_cli_prints_without_writing(tmp_path, monkeypatch):
    m = tmp_path / "m.yaml"
    m.write_text(yaml.safe_dump(manifest("okta_least_privilege")))
    env = tmp_path / ".env"
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(env)])
    assert out.exit_code == 0, out.output
    assert "OKTA_API_TOKEN=" in out.stdout and "# --- Okta ---" in out.stdout
    assert not env.exists()
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(env), "--write"])
    assert out.exit_code == 0, out.output
    assert "OKTA_API_TOKEN=" in env.read_text()
    assert "Still need a value" in out.stdout


def test_a_required_secret_the_manifest_does_not_map_is_named_with_the_command(tmp_path):
    m = tmp_path / "m.yaml"
    m.write_text(yaml.safe_dump({"run": {"fetchers": [{"use": "okta_least_privilege"}]}}))
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(tmp_path / ".env")])
    assert out.exit_code == 0, out.output
    assert "OKTA_API_TOKEN=" not in out.stdout.split("Not written")[0]  # a run would not read it
    assert f"paramify manifest set-secret -f {m} okta_least_privilege api_token OKTA_API_TOKEN" in out.stdout
    groups, unmapped = needs({"use": "okta_least_privilege"})
    assert [(u.fetcher, u.secret, u.env) for u in unmapped] == [
        ("okta_least_privilege", "api_token", "OKTA_API_TOKEN"), ("okta_least_privilege", "org_url", "OKTA_ORG_URL")]


def test_cli_unknown_manifest_fails(tmp_path):
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(tmp_path / "nope.yaml")])
    assert out.exit_code == 1


def test_new_variable_for_an_earlier_section_gets_a_continuation_header(tmp_path):
    env = tmp_path / ".env"
    original = "# --- Okta ---\nOKTA_ORG_URL=https://x\n\n# --- Datadog ---\nDATADOG_API_KEY=k\n"
    env.write_text(original)
    groups = groups_for("okta_least_privilege")
    groups.append(envgen.EnvGroup("Datadog", "", [envgen.EnvVar("DATADOG_API_KEY", "k", True)]))
    res = merge(env, groups)
    text = env.read_text()
    assert text.startswith(original)
    tail = text[len(original):]
    assert tail.index("# --- Okta (continued) ---") < tail.index("OKTA_API_TOKEN=")
    assert "DATADOG_API_KEY" not in tail and "OKTA_API_TOKEN" in res.added
    # idempotent, and a further addition to Okta (now not last either) continues again only once needed
    assert merge(env, groups).added == [] and env.read_text() == text


def test_new_variable_for_the_last_section_needs_no_header(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# --- Okta ---\nOKTA_ORG_URL=https://x\n")
    merge(env, groups_for("okta_least_privilege")[1:])
    text = env.read_text()
    assert text.count("# --- Okta") == 1
    assert text.index("OKTA_API_TOKEN=") > text.index("# --- Okta ---")
    assert "# --- " not in text[text.index("OKTA_ORG_URL"):]


def test_section_added_in_the_same_call_does_not_swallow_an_earlier_one(tmp_path):
    env = tmp_path / ".env"
    original = "# --- Okta ---\nOKTA_ORG_URL=https://x\n"
    env.write_text(original)
    merge(env, groups_for("okta_least_privilege"))
    text = env.read_text()
    assert text.startswith(original)
    paramify_at = text.index("# --- Paramify ---")
    cont_at = text.index("# --- Okta (continued) ---")
    assert paramify_at < cont_at < text.index("OKTA_API_TOKEN=")


def test_notes_are_word_aware_and_do_not_repeat_optional():
    long = "word " * 40
    note = envgen._note("Optional comma-separated logins. " + long, "x", False, None)
    assert note == "Comma-separated logins - optional"
    note = envgen._note(long, "x", True, None)
    assert note.endswith("... - required") and "wor..." not in note


def test_commented_required_placeholder_gets_one_live_line(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# OKTA_API_TOKEN=\n")
    groups = groups_for("okta_least_privilege")
    merge(env, groups)
    text = env.read_text()
    assert text.startswith("# OKTA_API_TOKEN=\n")
    assert text.count("\nOKTA_API_TOKEN=\n") == 1
    assert merge(env, groups).added == [] and env.read_text() == text


def test_a_value_exported_in_the_shell_is_not_missing(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("OKTA_ORG_URL=https://x\nPARAMIFY_UPLOAD_API_TOKEN=\nOKTA_API_TOKEN=\n")
    monkeypatch.setenv("OKTA_API_TOKEN", "exported")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "  ")  # blank is still missing
    out = api.generate_env(ROOT, manifest("okta_least_privilege"), path=env)
    assert out["missing_values"] == ["PARAMIFY_UPLOAD_API_TOKEN"]


def test_appending_to_a_crlf_file_keeps_crlf(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes(b"# mine\r\nOKTA_ORG_URL=https://x\r\n")
    api.generate_env(ROOT, manifest("okta_least_privilege"), write=True, path=env)
    data = env.read_bytes()
    assert data.startswith(b"# mine\r\nOKTA_ORG_URL=https://x\r\n")
    assert b"\nOKTA_API_TOKEN=\r\n" in data
    assert data.count(b"\n") == data.count(b"\r\n")


def test_a_spaced_placeholder_counts_as_one(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# OKTA_CLIENT_ID = \n")
    groups = [envgen.EnvGroup("Okta", "", [envgen.EnvVar("OKTA_CLIENT_ID", "note - optional", False)])]
    assert envgen.plan(env.read_text(), groups).added == []


def test_writing_through_a_symlinked_env_keeps_the_link(tmp_path):
    real = tmp_path / "secrets" / "fetchers.env"
    real.parent.mkdir()
    real.write_text("OKTA_ORG_URL=https://x\n")
    link = tmp_path / ".env"
    link.symlink_to(real)
    api.generate_env(ROOT, manifest("okta_least_privilege"), write=True, path=link)
    assert link.is_symlink()
    assert "OKTA_API_TOKEN=" in real.read_text()


# --------------------------------------------------------------------------- #
# The manifest's own ${env:} references win over the fetcher's declared names
# --------------------------------------------------------------------------- #

def test_a_secret_mapped_to_another_variable_uses_that_variable():
    entry = {"use": "okta_least_privilege",
             "secrets": {"api_token": "${env:OKTA_PROD_TOKEN}", "org_url": "${env:OKTA_ORG_URL}"}}
    groups = groups_for(entry)
    okta = {v.name: v for v in groups[1].vars}
    assert "OKTA_API_TOKEN" not in okta
    assert okta["OKTA_PROD_TOKEN"].required and okta["OKTA_ORG_URL"].required


def test_each_targets_secret_gets_its_own_variable():
    entry = {"use": "gitlab_ci_cd_pipeline_config", "targets": [
        {"project_id": "a/b", "secrets": {"api_token": "${env:GITLAB_TOKEN_1}"}},
        {"project_id": "a/c", "secrets": {"api_token": "${env:GITLAB_TOKEN_2}"}},
    ]}
    got = names(groups_for(entry))
    assert "GITLAB_TOKEN_1" in got and "GITLAB_TOKEN_2" in got
    declared = {s.env for s in api.discover(ROOT)["fetchers"]["gitlab_ci_cd_pipeline_config"].secrets}
    assert not declared & set(got) - {"GITLAB_TOKEN_1", "GITLAB_TOKEN_2"}


def test_a_config_value_that_references_a_variable_is_included():
    entry = {"use": "okta_least_privilege", "config": {"known_super_admins": "${env:OKTA_ADMINS}"},
             "secrets": {"api_token": "${env:OKTA_API_TOKEN}", "org_url": "${env:OKTA_ORG_URL}"}}
    okta = {v.name: v for v in groups_for(entry)[1].vars}
    assert "OKTA_ADMINS" in okta
    assert not okta["OKTA_ADMINS"].required  # unset, the field falls back to its default


def test_cli_reads_the_manifests_references(tmp_path):
    res = CliRunner().invoke(cli.app, ["env", "--manifest", str(ROOT / "examples" / "minimal_run.yaml"),
                                       "--path", str(tmp_path / ".env")])
    assert res.exit_code == 0, res.output
    assert "GITLAB_TOKEN_1=" in res.output and "GITLAB_TOKEN_2=" in res.output


def test_platform_config_references_and_passthrough_are_included():
    entry = {"use": "okta_least_privilege",
             "secrets": {"api_token": "${env:OKTA_API_TOKEN}", "org_url": "${env:OKTA_ORG_URL}"}}
    platforms = {"okta": {"config": {"known_super_admins": "${env:ADMINS_FROM_PLATFORM}"},
                          "auth": {"passthrough_env": ["HTTPS_PROXY"]}},
                 "azure": {"config": {"x": "${env:NOT_USED_HERE}"}}}
    okta = {v.name: v for v in groups_for(entry, platforms=platforms)[1].vars}
    assert "ADMINS_FROM_PLATFORM" in okta and not okta["ADMINS_FROM_PLATFORM"].required
    assert "OKTA_KNOWN_SUPER_ADMINS" not in okta
    assert not okta["HTTPS_PROXY"].required
    assert "NOT_USED_HERE" not in names(groups_for(entry, platforms=platforms))


# --------------------------------------------------------------------------- #
# run and doctor read <root>/.env
# --------------------------------------------------------------------------- #

def test_refresh_env_fills_unset_and_empty_but_never_overrides_an_export(tmp_path, monkeypatch):
    import os

    (tmp_path / ".env").write_text("A_UNSET=from-file\nB_EMPTY=from-file\nC_SET=from-file\nD_BLANK_IN_FILE=\n")
    monkeypatch.delenv("A_UNSET", raising=False)
    monkeypatch.setenv("B_EMPTY", "")  # what an earlier load_dotenv leaves when the file had OKTA_API_TOKEN=
    monkeypatch.setenv("C_SET", "exported")
    monkeypatch.delenv("D_BLANK_IN_FILE", raising=False)
    filled = api.refresh_env(tmp_path)
    assert sorted(filled) == ["A_UNSET", "B_EMPTY"]
    assert (os.environ["A_UNSET"], os.environ["B_EMPTY"], os.environ["C_SET"]) == ("from-file", "from-file", "exported")
    assert "D_BLANK_IN_FILE" not in os.environ
    assert api.refresh_env(tmp_path / "nowhere") == []


def _linked_root(tmp_path):
    """A checkout under tmp_path: the repo's files, symlinked, with its own .env and manifests."""
    root = tmp_path / "repo"
    root.mkdir()
    for entry in ROOT.iterdir():
        if entry.name not in (".env", "manifests", "evidence", ".git"):
            (root / entry.name).symlink_to(entry)
    return root


def test_run_reads_values_filled_into_env_since_startup(tmp_path, monkeypatch):
    """api.run fills unset or empty variables from <root>/.env before resolving ${env:...}."""
    import os

    from framework.runner import executor

    seen = {}

    def fake_invoke(fetcher, env, target, output_dir, *a, **k):
        seen.update(env)
        raise RuntimeError("stop here")
    monkeypatch.setattr(executor, "_invoke", fake_invoke)
    monkeypatch.setenv("OKTA_API_TOKEN", "")
    monkeypatch.setenv("OKTA_ORG_URL", "")
    monkeypatch.chdir(tmp_path)
    root = _linked_root(tmp_path)
    (root / ".env").write_text("OKTA_API_TOKEN=tok-from-file\nOKTA_ORG_URL=https://example.okta.com\n")
    manifest = api.init_manifest(str(tmp_path / "evidence"))
    api.add_entry(manifest, "okta_phishing_resistant_mfa")
    api.set_secret(manifest, "okta_phishing_resistant_mfa", "api_token", "OKTA_API_TOKEN")
    api.set_secret(manifest, "okta_phishing_resistant_mfa", "org_url", "OKTA_ORG_URL")
    api.run(manifest, root)
    assert seen.get("OKTA_API_TOKEN") == "tok-from-file"
    assert os.environ["OKTA_API_TOKEN"] == "tok-from-file"


def test_doctor_counts_a_value_kept_only_in_dotenv(tmp_path, monkeypatch):
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    monkeypatch.setenv("OKTA_ORG_URL", "")
    root = _linked_root(tmp_path)
    (root / ".env").write_text("OKTA_API_TOKEN=tok-from-file\nOKTA_ORG_URL=https://example.okta.com\n")
    mpath = tmp_path / "m.yaml"
    mpath.write_text(yaml.safe_dump({"run": {"output_dir": str(tmp_path / "ev"), "fetchers": [
        {"use": "okta_least_privilege",
         "secrets": {"api_token": "${env:OKTA_API_TOKEN}", "org_url": "${env:OKTA_ORG_URL}"}}]}}))
    report = api.doctor(root, mpath)
    assert report["manifest"]["fetchers"][0]["missing"] == []


def test_refresh_env_honours_python_dotenv_disabled(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("E_UNSET=from-file\n")
    monkeypatch.delenv("E_UNSET", raising=False)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    assert api.refresh_env(tmp_path) == []
    assert "E_UNSET" not in os.environ


def test_a_value_rotated_in_dotenv_reaches_the_next_run_but_an_export_still_wins(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_FILLED_FROM_DOTENV", set())
    monkeypatch.setenv("EXPORTED_TOKEN", "from-shell")
    os.environ.pop("ROTATED_TOKEN", None)
    (tmp_path / ".env").write_text("ROTATED_TOKEN=first\nEXPORTED_TOKEN=from-file\n")
    api.refresh_env(tmp_path)
    (tmp_path / ".env").write_text("ROTATED_TOKEN=second\nEXPORTED_TOKEN=from-file-2\n")
    api.refresh_env(tmp_path)  # a long-lived process (the TUI) running again
    assert (os.environ["ROTATED_TOKEN"], os.environ["EXPORTED_TOKEN"]) == ("second", "from-shell")


# --------------------------------------------------------------------------- #
# Read as the runner reads: per-target secrets, literals, passthrough
# --------------------------------------------------------------------------- #

def test_a_per_target_secret_is_read_from_each_target_only():
    entry = {"use": "github_access_review", "secrets": {"token": "${env:AT_THE_ENTRY}"},
             "targets": [{"secrets": {"token": "${env:GH_ONE}"}}, {}]}
    groups, unmapped = needs(entry)
    got = names(groups)
    assert "GH_ONE" in got and "AT_THE_ENTRY" not in got  # the runner never reads the entry's
    assert [(u.secret, u.per_target, u.target) for u in unmapped] == [("token", True, 1)]
    _, unmapped = needs({"use": "github_access_review"})
    assert [(u.per_target, u.target) for u in unmapped] == [(True, None)]  # no targets at all


def test_an_entry_secret_mapped_only_inside_a_target_is_unmapped():
    entry = {"use": "okta_least_privilege", "secrets": {"org_url": "${env:OKTA_ORG_URL}"},
             "targets": [{"secrets": {"api_token": "${env:IN_A_TARGET}"}}]}
    groups, unmapped = needs(entry)
    assert "IN_A_TARGET" not in names(groups)
    assert [(u.secret, u.per_target) for u in unmapped] == [("api_token", False)]


def test_a_literal_secret_needs_nothing():
    entry = {"use": "okta_least_privilege",
             "secrets": {"api_token": "${env:OKTA_API_TOKEN}", "org_url": "https://example.okta.com"}}
    groups, unmapped = needs(entry)
    assert unmapped == [] and "OKTA_ORG_URL" not in names(groups)


def test_the_categorys_passthrough_variables_are_listed_as_optional():
    groups, _ = needs({"use": "aws_config_inventory"})
    aws = {v.name: v for g in groups for v in g.vars}
    assert "AWS_PROFILE" in aws and not aws["AWS_PROFILE"].required


def test_a_platform_key_no_fetcher_declares_is_not_listed():
    platforms = {"okta": {"config": {"not_a_field": "${env:NOBODY_READS_THIS}"}}}
    assert "NOBODY_READS_THIS" not in names(groups_for("okta_least_privilege", platforms=platforms))


def test_cli_says_how_to_map_a_per_target_secret(tmp_path):
    m = tmp_path / "m.yaml"
    m.write_text(yaml.safe_dump({"run": {"fetchers": [
        {"use": "github_access_review", "targets": [{"secrets": {"token": "${env:GH_ONE}"}}, {}]}]}}))
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(tmp_path / ".env")])
    assert out.exit_code == 0, out.output
    assert "github_access_review target 1: add  token: ${env:GITHUB_TOKEN}" in out.stdout


def test_a_comparator_does_not_take_its_categorys_platform_block():
    platforms = {"azure": {"config": {"origins": "${env:ORIGINS}"}, "auth": {"passthrough_env": ["EXTRA_X"]}}}
    alone = names(groups_for({"use": "azure_change_work_items"}, platforms=platforms))
    assert "ORIGINS" not in alone and "EXTRA_X" not in alone
    first = names(groups_for({"use": "azure_change_work_items"}, {"use": "azure_activity_log_alerts"}))
    last = names(groups_for({"use": "azure_activity_log_alerts"}, {"use": "azure_change_work_items"}))
    assert set(first) == set(last) and "AZURE_CLIENT_ID" in first  # order doesn't matter


def test_secret_references_are_read_as_resolve_reads_them():
    entry = {"use": "okta_least_privilege",
             "secrets": {"api_token": "${env:okta_tok}", "org_url": "https://${env:OKTA_HOST}"}}
    groups, unmapped = needs(entry)
    assert "okta_tok" not in names(groups) and "OKTA_HOST" not in names(groups)  # literal: passed as is
    assert [(u.secret, u.malformed) for u in unmapped] == [("api_token", True)]


# --------------------------------------------------------------------------- #
# Config references, read by the runner's own merged_config
# --------------------------------------------------------------------------- #

def test_a_required_config_reference_with_a_platform_value_to_fall_back_on_is_optional():
    entry = {**wired("aws_config_inventory"), "config": {"aggregator_name": "${env:AGGREGATOR}"}}
    alone = {v.name: v for g in groups_for(entry) for v in g.vars}
    assert alone["AGGREGATOR"].required  # nothing to fall back on: the run needs it
    platforms = {"aws": {"config": {"aggregator_name": "org-aggregator"}}}
    backed = {v.name: v for g in groups_for(entry, platforms=platforms) for v in g.vars}
    assert not backed["AGGREGATOR"].required  # unset, the run takes the platform value


def test_a_platform_reference_an_entry_literal_shadows_is_not_listed():
    entry = {**wired("aws_config_inventory"), "config": {"aggregator_name": "mine"}}
    platforms = {"aws": {"config": {"aggregator_name": "${env:NEVER_READ}"}}}
    assert "NEVER_READ" not in names(groups_for(entry, platforms=platforms))


def test_config_references_the_runner_refuses_are_not_listed():
    entry = {**wired("aws_guard_duty_findings"), "config": {
        "lookback_days": "${env:ON_AN_INTEGER}",           # references work on string fields only
        "not_a_field": "${env:UNDECLARED}",               # passed through unresolved
    }}
    got = names(groups_for(entry))
    assert "ON_AN_INTEGER" not in got and "UNDECLARED" not in got
    entry = {**wired("aws_config_inventory"), "config": {"aggregator_name": "${env:MY_API_KEY}"}}
    assert "MY_API_KEY" not in names(groups_for(entry))  # a credential's name: refused


def test_resolve_reads_the_environment_it_is_given():
    from framework.secret_resolver import UnsetSecretError, resolve

    with mock.patch.dict(os.environ, {"SET_IN_THE_SHELL": "shell"}):
        assert resolve("${env:SET_IN_THE_SHELL}") == "shell"  # the default is os.environ, as before
        assert resolve("${env:SET_IN_THE_SHELL}", {"SET_IN_THE_SHELL": "given"}) == "given"
        with pytest.raises(UnsetSecretError):
            resolve("${env:SET_IN_THE_SHELL}", {})


# --------------------------------------------------------------------------- #
# --json: what to put in a secret manager, never a value
# --------------------------------------------------------------------------- #

def test_json_lists_each_variable_with_who_needs_it_and_never_a_value(tmp_path, monkeypatch):
    monkeypatch.delenv("OKTA_ORG_URL", raising=False)
    monkeypatch.setenv("OKTA_API_TOKEN", "exported-secret")
    m = tmp_path / "m.yaml"
    m.write_text(yaml.safe_dump({"run": {"fetchers": [wired("okta_least_privilege"), wired("okta_authenticators"),
                                                      {"use": "github_access_review"}]}}))
    env = tmp_path / ".env"
    env.write_text("OKTA_ORG_URL=https://file-value.example\n")
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(env), "--json"])
    assert out.exit_code == 0, out.output
    assert "exported-secret" not in out.stdout and "file-value" not in out.stdout
    doc = json.loads(out.stdout)
    by_name = {v["name"]: v for v in doc["variables"]}
    token = by_name["OKTA_API_TOKEN"]
    assert (token["tool"], token["required"], token["set"]) == ("Okta", True, True)  # set in the environment
    assert token["fetchers"] == ["okta_least_privilege", "okta_authenticators"]
    assert by_name["OKTA_ORG_URL"]["set"] is True  # set in the file
    assert by_name["PARAMIFY_UPLOAD_API_TOKEN"]["fetchers"] == []  # the upload needs it, not a fetcher
    assert doc["unmapped"] == [{"fetcher": "github_access_review", "secret": "token", "env": "GITHUB_TOKEN",
                                "per_target": True, "target": None, "malformed": False}]
    assert doc["ok"] is True and doc["written"] is False and "text" not in doc
    assert env.read_text() == "OKTA_ORG_URL=https://file-value.example\n"


def test_json_with_write_says_what_it_wrote(tmp_path):
    m = tmp_path / "m.yaml"
    m.write_text(yaml.safe_dump(manifest("okta_least_privilege")))
    env = tmp_path / ".env"
    doc = json.loads(CliRunner().invoke(cli.app, ["env", "-m", str(m), "--path", str(env), "--write", "--json"]).stdout)
    assert doc["written"] is True and "OKTA_API_TOKEN" in doc["added"]
    assert "OKTA_API_TOKEN=" in env.read_text()


def test_json_reports_an_unreadable_manifest_as_json(tmp_path):
    out = CliRunner().invoke(cli.app, ["env", "-m", str(tmp_path / "nope.yaml"), "--json"])
    assert out.exit_code == 1 and json.loads(out.stdout)["ok"] is False


def test_a_note_does_not_stop_at_an_abbreviation():
    assert envgen._first_sentence("Okta org base URL, no trailing slash (e.g. https://your-org.okta.com).") == \
        "Okta org base URL, no trailing slash (e.g. https://your-org.okta.com)."
    assert envgen._first_sentence("Read-only token. Create it in Settings.") == "Read-only token."
    assert envgen._first_sentence("Ends here") == "Ends here"


def test_the_mapping_command_names_a_manifest_under_the_current_folder_relatively(tmp_path, monkeypatch):
    (tmp_path / "manifests").mkdir()
    m = tmp_path / "manifests" / "m.yaml"
    m.write_text(yaml.safe_dump({"run": {"fetchers": [{"use": "okta_least_privilege"}]}}))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(api, "find_repo_root", lambda start=None: ROOT)
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(tmp_path / ".env")])
    assert "paramify manifest set-secret -f manifests/m.yaml okta_least_privilege api_token OKTA_API_TOKEN" in out.stdout
