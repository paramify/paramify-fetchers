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

from framework import api

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
