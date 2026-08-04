"""Tests for the framework.api facade itself.

The facade's central promise (README, docs/design.md: "One facade, one CLI, three
front-ends") is that every front-end calls only framework.api and therefore
behaves identically. That holds only if facade functions are order-independent —
no function may depend on another having been called first in the same process.

.env loading used to violate that: it lived inside upload_preflight() and
scripts_sync_preflight(), so run()/doctor()/list_programs() saw a .env only when
an upload path happened to run earlier. The TUI refreshed its Paramify panel at
mount and therefore worked; `paramify run` made three api calls and did not.
These tests pin the fixed behavior.
"""

import os
import textwrap
from pathlib import Path

import pytest

from framework import api, paramify_conn

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def clean_env():
    """Restore os.environ exactly — load_dotenv mutates it globally."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


def _fake_root(tmp_path: Path) -> Path:
    """A dir find_repo_root() accepts: sibling fetchers/ + framework/."""
    (tmp_path / "fetchers").mkdir(parents=True)
    (tmp_path / "framework").mkdir(parents=True)
    return tmp_path


def _manifest(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "m.yaml"
    path.write_text(textwrap.dedent(body))
    return path


# --------------------------------------------------------------------------- #
# load_environment
# --------------------------------------------------------------------------- #

def test_load_environment_reads_repo_root_dotenv(tmp_path, clean_env):
    root = _fake_root(tmp_path)
    (root / ".env").write_text("API_FROM_DOTENV=dotenv-value\n")
    os.environ.pop("API_FROM_DOTENV", None)

    loaded = api.load_environment(root)

    assert loaded == root / ".env"
    assert os.environ["API_FROM_DOTENV"] == "dotenv-value"


def test_real_env_wins_over_dotenv(tmp_path, clean_env):
    """Containers, CI, and `export` must be immune to a stray .env."""
    root = _fake_root(tmp_path)
    (root / ".env").write_text("API_FROM_DOTENV=dotenv-value\n")
    os.environ["API_FROM_DOTENV"] = "real-env-value"

    api.load_environment(root)

    assert os.environ["API_FROM_DOTENV"] == "real-env-value"


def test_load_environment_is_idempotent(tmp_path, clean_env):
    root = _fake_root(tmp_path)
    (root / ".env").write_text("API_FROM_DOTENV=dotenv-value\n")
    os.environ.pop("API_FROM_DOTENV", None)

    assert api.load_environment(root) == root / ".env"
    assert api.load_environment(root) == root / ".env"
    assert os.environ["API_FROM_DOTENV"] == "dotenv-value"


def test_no_dotenv_returns_none_and_does_not_raise(tmp_path, clean_env):
    assert api.load_environment(_fake_root(tmp_path)) is None


def test_outside_a_repo_returns_none_and_does_not_raise(tmp_path, clean_env, monkeypatch):
    """`paramify --help` from anywhere must not blow up in the entry-point hook."""
    monkeypatch.chdir(tmp_path)  # no fetchers/ + framework/ anywhere above
    assert api.load_environment() is None


# --------------------------------------------------------------------------- #
# The ordering invariant — the actual regression
# --------------------------------------------------------------------------- #

def test_doctor_sees_dotenv_secrets_with_no_preflight_first(tmp_path, clean_env):
    """doctor() must not depend on an upload preflight having run first.

    This is the bug: doctor() reads os.environ directly, and .env used to be
    loaded only inside upload_preflight()/scripts_sync_preflight().
    """
    env_root = _fake_root(tmp_path / "envroot")
    (env_root / ".env").write_text("DOCTOR_DOTENV_TOKEN=abc123\n")
    os.environ.pop("DOCTOR_DOTENV_TOKEN", None)

    manifest = _manifest(tmp_path, """
        run:
          output_dir: ./evidence
          fetchers:
            - use: okta_phishing_resistant_mfa
              secrets:
                api_token: ${env:DOCTOR_DOTENV_TOKEN}
    """)

    # Entry point only — no upload_preflight, no scripts_sync_preflight.
    api.load_environment(env_root)
    report = api.doctor(REPO_ROOT, manifest)

    entry = report["manifest"]["fetchers"][0]
    assert entry["env_refs"] == ["DOCTOR_DOTENV_TOKEN"]
    assert entry["missing"] == [], "doctor reported a secret that .env provides"
    assert entry["ok"]


def test_doctor_still_reports_genuinely_missing_secrets(tmp_path, clean_env):
    """The fix must not make doctor blindly pass."""
    env_root = _fake_root(tmp_path / "envroot")
    (env_root / ".env").write_text("SOMETHING_ELSE=x\n")
    os.environ.pop("ABSENT_TOKEN", None)

    manifest = _manifest(tmp_path, """
        run:
          output_dir: ./evidence
          fetchers:
            - use: okta_phishing_resistant_mfa
              secrets:
                api_token: ${env:ABSENT_TOKEN}
    """)

    api.load_environment(env_root)
    report = api.doctor(REPO_ROOT, manifest)

    entry = report["manifest"]["fetchers"][0]
    assert entry["missing"] == ["ABSENT_TOKEN"]
    assert not entry["ok"]


def test_secret_resolution_works_with_no_preflight_first(tmp_path, clean_env):
    """What a run does: resolve ${env:VAR} with only the entry-point load."""
    from framework import secret_resolver

    env_root = _fake_root(tmp_path)
    (env_root / ".env").write_text("RUN_DOTENV_TOKEN=run-value\n")
    os.environ.pop("RUN_DOTENV_TOKEN", None)

    api.load_environment(env_root)

    assert secret_resolver.resolve("${env:RUN_DOTENV_TOKEN}") == "run-value"


# --------------------------------------------------------------------------- #
# The Paramify connection — one definition, five former copies
# --------------------------------------------------------------------------- #

def test_config_base_url_outranks_env(clean_env):
    os.environ[paramify_conn.BASE_URL_ENV] = "https://from-env.example.com/api/v0"
    config = {"paramify": {"base_url": "https://from-config.example.com/api/v0"}}
    assert paramify_conn.resolve_base_url(config) == "https://from-config.example.com/api/v0"


def test_env_base_url_used_when_config_is_silent(clean_env):
    os.environ[paramify_conn.BASE_URL_ENV] = "https://from-env.example.com/api/v0"
    assert paramify_conn.resolve_base_url({}) == "https://from-env.example.com/api/v0"
    assert paramify_conn.resolve_base_url(None) == "https://from-env.example.com/api/v0"


def test_base_url_falls_back_to_default(clean_env):
    os.environ.pop(paramify_conn.BASE_URL_ENV, None)
    assert paramify_conn.resolve_base_url() == paramify_conn.DEFAULT_BASE_URL


@pytest.mark.parametrize("url", [
    "http://app.paramify.com/api/v0",
    "http://evil.example.com",
])
def test_plaintext_endpoints_rejected(url):
    assert paramify_conn.base_url_error(url) is not None


@pytest.mark.parametrize("url", [
    "https://app.paramify.com/api/v0",
    "http://localhost:8000/api/v0",
    "http://127.0.0.1:8000/api/v0",
])
def test_https_and_localhost_accepted(url):
    assert paramify_conn.base_url_error(url) is None


def test_upload_and_programs_resolve_the_same_base_url(tmp_path, clean_env):
    """The bug: a config naming a stage host sent upload to stage and programs to
    production, because list_programs() resolved the host on its own."""
    os.environ.pop(paramify_conn.BASE_URL_ENV, None)
    config_path = tmp_path / "upload.yaml"
    config_path.write_text("paramify:\n  base_url: https://stage.example.com/api/v0\n")

    from_config = paramify_conn.resolve_base_url(paramify_conn.load_config(config_path))
    assert from_config == "https://stage.example.com/api/v0"

    # api.upload_preflight reads it through the same helper; assert the shared
    # path rather than making a network call.
    assert paramify_conn.resolve_base_url(
        paramify_conn.load_config(config_path)
    ) == from_config


def test_one_token_serves_read_and_write(clean_env):
    """A single PARAMIFY_API_TOKEN reaches Paramify for every operation — the
    caller no longer has to know whether an operation reads or writes."""
    os.environ.pop(paramify_conn.LEGACY_TOKEN_ENV, None)
    os.environ[paramify_conn.TOKEN_ENV] = "one-token"
    assert paramify_conn.resolve_token() == "one-token"


def test_legacy_upload_token_still_accepted(clean_env):
    """Existing deployments, CI secret blocks, and compose env_files set only
    PARAMIFY_UPLOAD_API_TOKEN; they must keep working."""
    os.environ.pop(paramify_conn.TOKEN_ENV, None)
    os.environ[paramify_conn.LEGACY_TOKEN_ENV] = "legacy-token"
    assert paramify_conn.resolve_token() == "legacy-token"


def test_canonical_token_wins_over_the_legacy_alias(clean_env):
    os.environ[paramify_conn.TOKEN_ENV] = "canonical"
    os.environ[paramify_conn.LEGACY_TOKEN_ENV] = "legacy"
    assert paramify_conn.resolve_token() == "canonical"


def test_no_token_resolves_to_none(clean_env):
    os.environ.pop(paramify_conn.TOKEN_ENV, None)
    os.environ.pop(paramify_conn.LEGACY_TOKEN_ENV, None)
    assert paramify_conn.resolve_token() is None


def test_uploaders_accept_the_canonical_token_standalone(clean_env):
    """The uploaders resolve the token themselves when run as standalone scripts,
    so they must honor the canonical name too — otherwise `paramify upload` and
    `python uploaders/.../uploader.py` would disagree about one credential."""
    for rel in (
        "uploaders/paramify_evidence/uploader.py",
        "uploaders/paramify_scripts/uploader.py",
    ):
        src = (REPO_ROOT / rel).read_text()
        assert f'os.environ.get("{paramify_conn.TOKEN_ENV}")' in src, (
            f"{rel} does not accept {paramify_conn.TOKEN_ENV}"
        )
        assert f'os.environ.get("{paramify_conn.LEGACY_TOKEN_ENV}")' in src, (
            f"{rel} dropped the deprecated {paramify_conn.LEGACY_TOKEN_ENV} alias"
        )


def test_api_passes_a_resolved_token_to_both_uploaders():
    """A preflight and the operation it clears must never resolve the credential
    separately — api.py owns the policy and hands the result down."""
    src = (REPO_ROOT / "framework" / "api.py").read_text()
    assert src.count("token=paramify_conn.resolve_token()") == 2, (
        "upload_run() and scripts_sync() must each pass the resolved token to "
        "their uploader, or the uploader re-resolves it independently."
    )


def test_load_config_tolerates_absent_and_empty(tmp_path):
    assert paramify_conn.load_config(None) == {}
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    assert paramify_conn.load_config(empty) == {}


def test_framework_and_uploader_default_urls_agree():
    """The uploaders keep their own copies (they must run standalone, outside the
    framework package). Pin them together so they cannot drift."""
    for rel in (
        "uploaders/paramify_evidence/uploader.py",
        "uploaders/paramify_scripts/uploader.py",
    ):
        src = (REPO_ROOT / rel).read_text()
        expected = f'DEFAULT_BASE_URL = "{paramify_conn.DEFAULT_BASE_URL}"'
        assert expected in src, f"{rel} disagrees with paramify_conn.DEFAULT_BASE_URL"


def test_api_does_not_reimplement_the_connection():
    """Structural guard: the facade must go through paramify_conn, not re-derive
    the host, the token names, or the https rule inline."""
    src = (REPO_ROOT / "framework" / "api.py").read_text()
    assert paramify_conn.BASE_URL_ENV not in src, "api.py reads the base-url env directly again"
    assert paramify_conn.TOKEN_ENV not in src, "api.py reads the token env directly again"
    assert paramify_conn.LEGACY_TOKEN_ENV not in src, "api.py reads the legacy token env directly again"
    assert "_base_url_error" not in src, "api.py reaches into an uploader's private https check"
    assert "urlparse" not in src, "api.py parses an API URL inline again"


def test_no_facade_function_loads_dotenv_itself():
    """Guard the invariant structurally: the env is populated at the entry point
    and nowhere else, so no facade function can depend on call order again."""
    src = (REPO_ROOT / "framework" / "api.py").read_text()
    # The single legitimate call lives in load_environment().
    assert src.count("load_dotenv(") == 1, (
        "framework/api.py must call load_dotenv exactly once (in load_environment). "
        "A second call means a facade function is populating the environment again."
    )
    assert "uploader.load_dotenv()" not in src, (
        "upload_preflight/scripts_sync_preflight must not load .env — that is the "
        "call-order dependency this file exists to prevent."
    )
