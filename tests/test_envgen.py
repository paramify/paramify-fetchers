"""The .env a manifest needs: grouped by tool, never overwriting what is already set."""

from __future__ import annotations

import os

import yaml
from typer.testing import CliRunner

from framework import api, cli, envgen

ROOT = api.find_repo_root()
FOUND = api.discover(ROOT)


def manifest(*entries, platforms=None):
    run = {"fetchers": [e if isinstance(e, dict) else {"use": e} for e in entries]}
    if platforms:
        run["platforms"] = platforms
    return {"run": run}


def groups_for(*entries, platforms=None):
    return envgen.env_groups(FOUND["fetchers"], FOUND["platforms"], manifest(*entries, platforms=platforms))


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
    # AWS credentials live on the category, not the fetcher.
    groups = groups_for("aws_iam_mfa_status") if "aws_iam_mfa_status" in api.discover(ROOT)["fetchers"] \
        else groups_for(*[n for n, f in FOUND["fetchers"].items() if f.category == "aws"][:1])
    assert "AWS_ACCESS_KEY_ID" in names(groups)
    key = next(v for g in groups for v in g.vars if v.name == "AWS_ACCESS_KEY_ID")
    assert key.required is False


def test_config_default_is_shown_as_optional():
    groups = groups_for("okta_least_privilege")
    var = next(v for g in groups for v in g.vars if v.name == "OKTA_KNOWN_SUPER_ADMINS")
    assert var.required is False and var.default is None  # '' is no default
    text = envgen.plan("", groups).text
    assert "optional" in text
    base = next(v for v in groups[0].vars if v.name == "PARAMIFY_API_BASE_URL")
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
    text = envgen.plan("", groups_for("okta_least_privilege")).text
    assert "\n# OKTA_KNOWN_SUPER_ADMINS=" in text
    assert "\nOKTA_API_TOKEN=\n" in text


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
    assert env.read_text() == out["text"] or env.read_text().endswith(out["text"])
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
    m.write_text(yaml.safe_dump({"run": {"fetchers": [{"use": "okta_least_privilege"}]}}))
    env = tmp_path / ".env"
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(env)])
    assert out.exit_code == 0, out.output
    assert "OKTA_API_TOKEN=" in out.stdout and "# --- Okta ---" in out.stdout
    assert not env.exists()
    out = CliRunner().invoke(cli.app, ["env", "--manifest", str(m), "--path", str(env), "--write"])
    assert out.exit_code == 0, out.output
    assert "OKTA_API_TOKEN=" in env.read_text()
    assert "Still need a value" in out.stdout


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
    assert okta["OKTA_ADMINS"].required
    assert "okta_least_privilege" in okta["OKTA_ADMINS"].note


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
    assert okta["ADMINS_FROM_PLATFORM"].required
    assert "OKTA_KNOWN_SUPER_ADMINS" not in okta  # set at the platform level
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
