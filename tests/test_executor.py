"""Tests for the runner's execution core (framework/runner/executor.py).

These cover the parts that actually touch secrets and customer config:

  - config merge precedence (category default <- platform <- per-fetcher), incl.
    the subtle "falsy defaults survive" rule the naive truthiness filter breaks;
  - env ISOLATION — the fetcher subprocess sees ONLY a small whitelist plus the
    secrets/config/target vars explicitly declared for it, never the runner's
    ambient secrets;
  - secret + target-field injection and the documented setup failures.

The end-to-end isolation test runs a REAL fetcher subprocess that dumps its own
os.environ to disk, so we assert what the child actually received — not what a
mock was told to return.
"""

from __future__ import annotations

import json
import os

import pytest

from framework.contract import (
    ConfigField,
    Fetcher,
    ManifestEntry,
    PlatformConfig,
    PlatformSpec,
    Secret,
    TargetField,
    TargetInstance,
)
from framework.runner.executor import _apply_config, _build_env, run_entry


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def make_fetcher(path, **overrides) -> Fetcher:
    defaults = dict(
        name="t_fetcher",
        version="0.1.0",
        description="test fetcher",
        category="testcat",
        runtime_type="python",
        runtime_entry="fetcher.py",
        runtime_timeout=None,
        output_type="json",
        output_path="out.json",
        output_aggregation=None,
        secrets=[],
        supports_targets=False,
        target_schema={},
        path=path,
        config_schema={},
        evidence_set=None,
    )
    defaults.update(overrides)
    return Fetcher(**defaults)


def cfg(name, env, *, default=None, required=False, type="string") -> ConfigField:
    return ConfigField(name=name, type=type, required=required, env=env, default=default)


# --------------------------------------------------------------------------- #
# Config merge precedence (executor._apply_config)
# --------------------------------------------------------------------------- #

def test_config_precedence_ladder(tmp_path):
    """default <- platform values <- per-fetcher entry config. With all three set
    to DIFFERENT values there is exactly one correct winner per layer, so a
    reordered merge fails this (a single-value happy-path test would not)."""
    field = cfg("region", "REGION", default="from-default")
    fetcher = make_fetcher(tmp_path, config_schema={"region": field})
    spec = PlatformSpec(category="testcat", config_schema={"region": field})

    # all three present -> per-fetcher entry wins
    env: dict = {}
    _apply_config(env, fetcher, spec, PlatformConfig(config={"region": "from-platform"}),
                  ManifestEntry(use="x", config={"region": "from-entry"}))
    assert env["REGION"] == "from-entry"

    # platform + default -> platform wins
    env = {}
    _apply_config(env, fetcher, spec, PlatformConfig(config={"region": "from-platform"}),
                  ManifestEntry(use="x"))
    assert env["REGION"] == "from-platform"

    # default only
    env = {}
    _apply_config(env, fetcher, spec, None, ManifestEntry(use="x"))
    assert env["REGION"] == "from-default"


def test_per_fetcher_schema_overrides_platform_on_name_clash(tmp_path):
    """When both the platform and the fetcher declare the same config field, the
    fetcher's schema (incl. its env mapping) wins."""
    platform_field = cfg("region", "PLATFORM_REGION", default="p")
    fetcher_field = cfg("region", "FETCHER_REGION", default="f")
    fetcher = make_fetcher(tmp_path, config_schema={"region": fetcher_field})
    spec = PlatformSpec(category="testcat", config_schema={"region": platform_field})

    env: dict = {}
    _apply_config(env, fetcher, spec, None, ManifestEntry(use="x"))
    # the fetcher's env name is used, the platform's is not
    assert env.get("FETCHER_REGION") == "f"
    assert "PLATFORM_REGION" not in env


def test_falsy_config_default_survives(tmp_path):
    """A boolean-false / 0 / "" default must be INJECTED, not dropped. The
    naive `if value:` filter would silently drop these, so this guards the exact
    `is not None` decision."""
    fetcher = make_fetcher(tmp_path, config_schema={
        "verbose": cfg("verbose", "VERBOSE", default=False, type="boolean"),
        "retries": cfg("retries", "RETRIES", default=0, type="integer"),
        "prefix": cfg("prefix", "PREFIX", default=""),
    })
    env: dict = {}
    _apply_config(env, fetcher, None, None, ManifestEntry(use="x"))
    assert env["VERBOSE"] == "false"   # bool coerced to lowercase, present
    assert env["RETRIES"] == "0"       # zero present, not dropped
    assert env["PREFIX"] == ""         # empty string present, not dropped


def test_required_config_without_value_raises(tmp_path):
    fetcher = make_fetcher(tmp_path, config_schema={
        "region": cfg("region", "REGION", required=True),
    })
    with pytest.raises(RuntimeError, match="required config 'region'"):
        _apply_config({}, fetcher, None, None, ManifestEntry(use="x"))


def test_passthrough_env_only_passes_vars_actually_set(tmp_path, monkeypatch):
    """passthrough_env opts a var THROUGH the whitelist, but only when it is
    actually present in the runner's environment."""
    spec = PlatformSpec(category="testcat", passthrough_env=["AMBIENT_TOKEN"])
    fetcher = make_fetcher(tmp_path)

    monkeypatch.delenv("AMBIENT_TOKEN", raising=False)
    env: dict = {}
    _apply_config(env, fetcher, spec, None, ManifestEntry(use="x"))
    assert "AMBIENT_TOKEN" not in env

    monkeypatch.setenv("AMBIENT_TOKEN", "abc123")
    env = {}
    _apply_config(env, fetcher, spec, None, ManifestEntry(use="x"))
    assert env["AMBIENT_TOKEN"] == "abc123"


# --------------------------------------------------------------------------- #
# Env build / isolation (executor._build_env)
# --------------------------------------------------------------------------- #

def test_build_env_strips_undeclared_ambient_vars(tmp_path, monkeypatch):
    """The runner does NOT inherit its own environment — an ambient var the
    fetcher never declared must not reach the child's env dict."""
    monkeypatch.setenv("SNEAKY_AMBIENT_SECRET", "leak-me")
    fetcher = make_fetcher(tmp_path)

    env = _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)

    assert "SNEAKY_AMBIENT_SECRET" not in env       # stripped
    assert env["EVIDENCE_DIR"] == str(tmp_path.resolve())
    if "PATH" in os.environ:  # whitelist still passes PATH (interp bin may be prepended)
        assert env["PATH"].endswith(os.environ["PATH"])


def test_build_env_prepends_interpreter_bin_to_path(tmp_path, monkeypatch):
    """Console scripts living next to the running interpreter (a pipx venv, an
    unactivated .venv) must be resolvable by fetchers — e.g. the checkov CLI,
    which pipx installs into a bin/ it never puts on PATH."""
    import sys
    from pathlib import Path as _P
    interp_bin = str(_P(sys.executable).parent)

    monkeypatch.setenv("PATH", "/usr/bin")
    fetcher = make_fetcher(tmp_path)
    env = _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)
    assert env["PATH"].split(os.pathsep) == [interp_bin, "/usr/bin"]

    # already on PATH → not duplicated
    monkeypatch.setenv("PATH", os.pathsep.join([interp_bin, "/usr/bin"]))
    env2 = _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)
    assert env2["PATH"].split(os.pathsep).count(interp_bin) == 1


def test_build_env_injects_resolved_secret_under_declared_name(tmp_path, monkeypatch):
    """The resolved secret VALUE lands under the fetcher's declared env name; the
    SOURCE env var named in the ${env:...} ref is not itself passed through."""
    monkeypatch.setenv("SRC_TOKEN", "s3cr3t-value")
    fetcher = make_fetcher(tmp_path, secrets=[Secret(name="api_token", env="API_TOKEN")])
    entry = ManifestEntry(use="x", secrets={"api_token": "${env:SRC_TOKEN}"})

    env = _build_env(fetcher, entry, None, tmp_path)

    assert env["API_TOKEN"] == "s3cr3t-value"   # resolved, under the declared name
    assert "SRC_TOKEN" not in env               # source var not leaked


def test_build_env_missing_secret_raises(tmp_path):
    fetcher = make_fetcher(tmp_path, secrets=[Secret(name="api_token", env="API_TOKEN")])
    with pytest.raises(RuntimeError, match="missing secret 'api_token'"):
        _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)


def test_build_env_per_target_secret_without_target_raises(tmp_path):
    fetcher = make_fetcher(tmp_path, secrets=[Secret(name="tok", env="TOK", per_target=True)])
    with pytest.raises(RuntimeError, match="per_target secret 'tok'"):
        _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)


def test_build_env_target_field_injected_and_required_missing_raises(tmp_path):
    ts = {"region": TargetField(name="region", type="string", required=True, env="AWS_DEFAULT_REGION")}
    fetcher = make_fetcher(tmp_path, supports_targets=True, target_schema=ts)

    env = _build_env(
        fetcher, ManifestEntry(use="x"),
        TargetInstance(values={"region": "us-east-1"}, secrets={}), tmp_path,
    )
    assert env["AWS_DEFAULT_REGION"] == "us-east-1"

    with pytest.raises(RuntimeError, match="missing required field 'region'"):
        _build_env(
            fetcher, ManifestEntry(use="x"),
            TargetInstance(values={}, secrets={}), tmp_path,
        )


# --------------------------------------------------------------------------- #
# End-to-end isolation through a REAL subprocess (the gold-standard check)
# --------------------------------------------------------------------------- #

# A fetcher that simply dumps the environment it was given. The assertions then
# describe what the CHILD actually saw, not what a mock claims.
_ENV_DUMP_FETCHER = """\
import json, os
out = os.path.join(os.environ["EVIDENCE_DIR"], "env_dump.json")
with open(out, "w") as fh:
    json.dump(dict(os.environ), fh)
"""


def test_real_subprocess_env_isolation_end_to_end(tmp_path, monkeypatch):
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(_ENV_DUMP_FETCHER)
    out_dir = tmp_path / "out"

    monkeypatch.setenv("AMBIENT_LEAK", "should-not-appear")   # undeclared
    monkeypatch.setenv("SRC_TOKEN", "the-secret-value")        # the secret source

    fetcher = make_fetcher(fdir, secrets=[Secret(name="api_token", env="API_TOKEN")])
    entry = ManifestEntry(use="t_fetcher", secrets={"api_token": "${env:SRC_TOKEN}"})

    results = run_entry(fetcher, entry, out_dir)
    assert len(results) == 1
    assert results[0].exit_code == 0, results[0].stderr
    assert results[0].outputs == ["env_dump.json"]

    dumped = json.loads((out_dir / "env_dump.json").read_text())
    assert dumped["API_TOKEN"] == "the-secret-value"   # declared secret reached the child
    assert "SRC_TOKEN" not in dumped                    # ...but not the source var
    assert "AMBIENT_LEAK" not in dumped                 # ...and ambient secret was stripped
    assert dumped["EVIDENCE_DIR"] == str(out_dir.resolve())


def test_real_subprocess_nonzero_exit_is_captured(tmp_path):
    """A fetcher that fails is reported with its real exit code (failure detection
    must not be silently swallowed)."""
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text("import sys\nsys.exit(3)\n")

    fetcher = make_fetcher(fdir)
    results = run_entry(fetcher, ManifestEntry(use="t_fetcher"), tmp_path / "out")

    assert len(results) == 1
    assert results[0].exit_code == 3
