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
from framework.runner.executor import _apply_config, _build_env, _emit_notes, run_entry
from framework.secret_resolver import SecretResolutionError, UnsetSecretError

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
    if "PATH" in os.environ:                          # whitelist still passes PATH
        assert env["PATH"] == os.environ["PATH"]


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


# --- optional secrets: the ambient-identity case ---------------------------- #
# A cloud category's credential chain prefers links that hand over no secret at
# all (IRSA, workload identity, managed identity) while also accepting static
# keys. `required=False` is how a fetcher advertises the static keys without
# breaking the deployments that supply none.

def test_build_env_optional_secret_omitted_is_not_injected(tmp_path):
    """Omitting an optional secret is not an error, and injects nothing — the
    fetcher's credential chain is left to fall through to ambient identity."""
    fetcher = make_fetcher(
        tmp_path,
        secrets=[Secret(name="client_secret", env="AZURE_CLIENT_SECRET", required=False)],
    )
    env = _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)
    assert "AZURE_CLIENT_SECRET" not in env


def test_build_env_optional_secret_supplied_is_injected_and_masked(tmp_path, monkeypatch):
    """Supplied, an optional secret behaves exactly like a required one — resolved
    under its declared name and registered for masking out of captured output."""
    monkeypatch.setenv("SRC_SP_SECRET", "sp-value")
    fetcher = make_fetcher(
        tmp_path,
        secrets=[Secret(name="client_secret", env="AZURE_CLIENT_SECRET", required=False)],
    )
    entry = ManifestEntry(use="x", secrets={"client_secret": "${env:SRC_SP_SECRET}"})
    sink = set()
    env = _build_env(fetcher, entry, None, tmp_path, secret_sink=sink)
    assert env["AZURE_CLIENT_SECRET"] == "sp-value"
    assert "sp-value" in sink


def test_build_env_optional_per_target_secret_without_target_does_not_raise(tmp_path):
    """The per_target branch honours `required` too, so a fetcher can declare an
    optional per-target credential and still run with no targets."""
    fetcher = make_fetcher(
        tmp_path,
        secrets=[Secret(name="tok", env="TOK", per_target=True, required=False)],
    )
    env = _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)
    assert "TOK" not in env


def test_build_env_optional_secret_with_unresolvable_ref_is_not_injected(tmp_path, monkeypatch):
    """A reference the manifest carries but cannot resolve is an omission when the
    secret is optional — the ambient-deployment case.

    The TUI auto-wires every optional secret to its default env var on add, so a
    manifest built there arrives in an ECS task / IRSA pod holding refs for keys
    that deployment deliberately does not set. Raising would fail the entry at
    setup, before the fetcher runs, over credentials it never needed.
    """
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    fetcher = make_fetcher(
        tmp_path,
        secrets=[Secret(name="access_key_id", env="AWS_ACCESS_KEY_ID", required=False)],
    )
    entry = ManifestEntry(use="x", secrets={"access_key_id": "${env:AWS_ACCESS_KEY_ID}"})
    env = _build_env(fetcher, entry, None, tmp_path)
    assert "AWS_ACCESS_KEY_ID" not in env


def test_build_env_skipped_optional_secret_is_recorded_for_the_operator(tmp_path, monkeypatch):
    """The skip must not be silent: a typo'd var name is indistinguishable from an
    ambient deployment, so the operator has to see which credential was dropped."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    fetcher = make_fetcher(
        tmp_path,
        secrets=[Secret(name="access_key_id", env="AWS_ACCESS_KEY_ID", required=False)],
    )
    entry = ManifestEntry(use="x", secrets={"access_key_id": "${env:AWS_ACCESS_KEY_ID}"})
    notes = []
    _build_env(fetcher, entry, None, tmp_path, note_sink=notes)
    assert notes == [("access_key_id", "AWS_ACCESS_KEY_ID")]


def test_emit_notes_coalesces_a_whole_credential_set_into_one_line(monkeypatch):
    """A cloud category declares several static-key secrets and an ambient
    deployment drops all of them at once. One line per invocation, or the run
    output fills with text nobody reads."""
    seen = []
    _emit_notes(
        [("access_key_id", "AWS_ACCESS_KEY_ID"),
         ("secret_access_key", "AWS_SECRET_ACCESS_KEY"),
         ("session_token", "AWS_SESSION_TOKEN")],
        seen.append,
    )
    assert len(seen) == 1
    assert "3 optional secrets" in seen[0]
    for name in ("access_key_id", "secret_access_key", "session_token"):
        assert name in seen[0]
    assert "ambient identity" in seen[0]


def test_emit_notes_says_nothing_when_no_secret_was_dropped():
    """The channel stays quiet on a normal run."""
    seen = []
    _emit_notes([], seen.append)
    assert seen == []


def test_build_env_optional_secret_with_malformed_ref_still_raises(tmp_path):
    """Optionality excuses an unset var, never a broken reference. A lowercase
    name is the usual typo, and passing it through would hand the fetcher the
    literal string as its credential."""
    fetcher = make_fetcher(
        tmp_path,
        secrets=[Secret(name="access_key_id", env="AWS_ACCESS_KEY_ID", required=False)],
    )
    entry = ManifestEntry(use="x", secrets={"access_key_id": "${env:aws_access_key_id}"})
    with pytest.raises(SecretResolutionError, match="Malformed secret reference"):
        _build_env(fetcher, entry, None, tmp_path)


def test_build_env_required_secret_with_unresolvable_ref_still_raises(tmp_path, monkeypatch):
    """The fallback is scoped to optional secrets. A required credential that
    cannot be resolved is still a hard failure before the fetcher runs."""
    monkeypatch.delenv("API_TOKEN", raising=False)
    fetcher = make_fetcher(tmp_path, secrets=[Secret(name="api_token", env="API_TOKEN")])
    entry = ManifestEntry(use="x", secrets={"api_token": "${env:API_TOKEN}"})
    with pytest.raises(SecretResolutionError, match="could not be resolved"):
        _build_env(fetcher, entry, None, tmp_path)


def test_build_env_optional_per_target_secret_with_unresolvable_ref_is_skipped(tmp_path, monkeypatch):
    """The per_target branch shares the fallback — add_target wires per-target
    secrets the same way, so the same refs arrive on targets."""
    monkeypatch.delenv("TOK", raising=False)
    fetcher = make_fetcher(
        tmp_path,
        secrets=[Secret(name="tok", env="TOK", per_target=True, required=False)],
    )
    target = TargetInstance(values={}, secrets={"tok": "${env:TOK}"})
    entry = ManifestEntry(use="x", targets=[target])
    env = _build_env(fetcher, entry, target, tmp_path)
    assert "TOK" not in env


def test_build_env_required_secret_still_raises_alongside_an_optional_one(tmp_path):
    """Adding optional secrets must not weaken the fail-fast on required ones."""
    fetcher = make_fetcher(
        tmp_path,
        secrets=[
            Secret(name="client_secret", env="AZURE_CLIENT_SECRET", required=False),
            Secret(name="api_token", env="API_TOKEN"),
        ],
    )
    with pytest.raises(RuntimeError, match="missing secret 'api_token'"):
        _build_env(fetcher, ManifestEntry(use="x"), None, tmp_path)


# --- category-declared secrets ---------------------------------------------- #

def test_build_env_inherits_secrets_declared_on_the_category(tmp_path, monkeypatch):
    """A category declares shared credentials once; every fetcher in it resolves
    them without repeating the declaration in its own fetcher.yaml."""
    monkeypatch.setenv("SRC_SP_SECRET", "from-category")
    spec = PlatformSpec(
        category="testcat",
        secrets=[Secret(name="client_secret", env="AZURE_CLIENT_SECRET", required=False)],
    )
    fetcher = make_fetcher(tmp_path, secrets=[])
    entry = ManifestEntry(use="x", secrets={"client_secret": "${env:SRC_SP_SECRET}"})
    env = _build_env(fetcher, entry, None, tmp_path, platform_spec=spec)
    assert env["AZURE_CLIENT_SECRET"] == "from-category"


def test_fetcher_secret_overrides_the_category_declaration_on_a_name_clash(tmp_path, monkeypatch):
    """Per-fetcher wins, mirroring how config merges platform -> fetcher."""
    monkeypatch.setenv("SRC_SP_SECRET", "v")
    spec = PlatformSpec(
        category="testcat",
        secrets=[Secret(name="tok", env="CATEGORY_ENV", required=False)],
    )
    fetcher = make_fetcher(tmp_path, secrets=[Secret(name="tok", env="FETCHER_ENV")])
    entry = ManifestEntry(use="x", secrets={"tok": "${env:SRC_SP_SECRET}"})
    env = _build_env(fetcher, entry, None, tmp_path, platform_spec=spec)
    assert env["FETCHER_ENV"] == "v"
    assert "CATEGORY_ENV" not in env


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


# --------------------------------------------------------------------------- #
# $FETCHER_STATUS_FILE — the failure-reason channel (issue #24)
# --------------------------------------------------------------------------- #

_REPORTING_FETCHER = """\
import json, os, sys
# What every fetcher used to do: log a success line last, then exit non-zero.
# The stderr tail is therefore useless as a failure reason.
print("2026-01-01 INFO t_fetcher Evidence saved to out.json", file=sys.stderr)
with open(os.environ["FETCHER_STATUS_FILE"], "w") as f:
    json.dump({"error": "the real reason", "code": "target_unreachable"}, f)
open(os.path.join(os.environ["EVIDENCE_DIR"], "t_fetcher.json"), "w").write("{}")
sys.exit(1)
"""


def test_reported_failure_reason_reaches_the_result(tmp_path):
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(_REPORTING_FETCHER)

    r = run_entry(make_fetcher(fdir), ManifestEntry(use="t_fetcher"), tmp_path / "out")[0]

    assert r.exit_code == 1
    assert r.error == "the real reason"
    assert r.error_code == "target_unreachable"
    # The stderr tail — what the envelope used to use — is still the wrong answer.
    assert "Evidence saved" in r.stderr


def test_status_file_is_not_collected_as_evidence(tmp_path):
    """It lives outside EVIDENCE_DIR, so the output diff can't pick it up.

    If it were written into the evidence dir it would be enveloped and uploaded
    as if it were collected evidence.
    """
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(_REPORTING_FETCHER)

    out_dir = tmp_path / "out"
    r = run_entry(make_fetcher(fdir), ManifestEntry(use="t_fetcher"), out_dir)[0]

    assert r.outputs == ["t_fetcher.json"]
    assert not any("status" in n for n in r.outputs)
    assert [p.name for p in out_dir.iterdir()] == ["t_fetcher.json"]


def test_status_file_path_is_per_invocation_and_cleaned_up(tmp_path):
    """The temp dir goes away with the invocation — nothing outlives the run."""
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(
        "import os\n"
        "p = os.environ['FETCHER_STATUS_FILE']\n"
        "open(os.path.join(os.environ['EVIDENCE_DIR'], 'ev.json'), 'w').write('\"%s\"' % p)\n"
    )

    out_dir = tmp_path / "out"
    run_entry(make_fetcher(fdir), ManifestEntry(use="t_fetcher"), out_dir)

    reported_path = json.loads((out_dir / "ev.json").read_text())
    assert not os.path.exists(reported_path)             # cleaned up
    assert str(out_dir.resolve()) not in reported_path   # and never inside EVIDENCE_DIR


@pytest.mark.parametrize("body", [
    "{ not json",                     # malformed
    '["error", "boom"]',              # right JSON, wrong shape
    '{"code": "auth_failed"}',        # code without an error
    '{"error": "   "}',               # blank message
    '{"error": 42}',                  # wrong type
])
def test_unusable_status_file_falls_back_silently(tmp_path, body):
    """A fetcher must not be able to break a run by writing a bad status file."""
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text(
        "import os, sys\n"
        f"open(os.environ['FETCHER_STATUS_FILE'], 'w').write({body!r})\n"
        "print('stderr reason', file=sys.stderr)\n"
        "sys.exit(1)\n"
    )

    r = run_entry(make_fetcher(fdir), ManifestEntry(use="t_fetcher"), tmp_path / "out")[0]

    assert r.exit_code == 1        # the run still reports the failure
    assert r.error is None         # ...and falls back to the stderr tail
    assert "stderr reason" in r.stderr


def test_no_status_file_written_is_not_an_error(tmp_path):
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text("import sys\nsys.exit(1)\n")

    r = run_entry(make_fetcher(fdir), ManifestEntry(use="t_fetcher"), tmp_path / "out")[0]
    assert r.exit_code == 1
    assert r.error is None and r.error_code is None


# --------------------------------------------------------------------------- #
# Timeout containment. The runner's own timeout is the only ceiling on a run,
# so it has to hold when the process that is actually stuck is a grandchild —
# which is the common shape here, since most fetchers are bash shelling out to
# aws/curl/kubectl.
# --------------------------------------------------------------------------- #

def _bash_fetcher(tmp_path, script: str, timeout: int):
    (tmp_path / "fetcher.sh").write_text(script)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return make_fetcher(
        tmp_path, runtime_type="bash", runtime_entry="fetcher.sh",
        runtime_timeout=timeout,
    ), out


def test_timeout_kills_the_whole_process_group(tmp_path):
    """A hung grandchild must not outlive the timeout.

    bash sleeps in the foreground with a child sleep of its own. Killing only
    the direct child leaves the grandchild holding the inherited stdout pipe,
    so the drain threads block on a pipe that never reaches EOF and the runner
    waits out the full sleep instead of its own timeout.
    """
    import time

    from framework.runner.executor import _invoke

    fetcher, out = _bash_fetcher(tmp_path, "#!/bin/bash\nsleep 30\n", timeout=1)
    started = time.monotonic()
    result = _invoke(fetcher, {"PATH": "/usr/bin:/bin"}, None, out)
    elapsed = time.monotonic() - started

    assert result.exit_code == 124, "timeout should report the timeout exit code"
    assert elapsed < 15, f"timeout did not bound the run: took {elapsed:.1f}s for a 1s timeout"


def test_a_backgrounded_grandchild_does_not_hang_the_run(tmp_path, monkeypatch):
    """A fetcher that exits 0 leaving a background child is still bounded.

    No timeout fires here — bash exits immediately and successfully — so the
    process-group kill never runs. The orphan still holds the stdout pipe, and
    only the drain deadline stops the runner waiting on it indefinitely.

    The deadline is shortened for the test: this path always waits it out, so at
    the real 10s it would cost that on every CI leg to prove the same thing.
    """
    import time

    from framework.runner import executor

    monkeypatch.setattr(executor, "_DRAIN_JOIN_TIMEOUT", 1.0)

    fetcher, out = _bash_fetcher(tmp_path, "#!/bin/bash\nsleep 30 &\nexit 0\n", timeout=60)
    started = time.monotonic()
    result = executor._invoke(fetcher, {"PATH": "/usr/bin:/bin"}, None, out)
    elapsed = time.monotonic() - started

    assert result.exit_code == 0
    assert elapsed < 6, f"drain was not bounded: {elapsed:.1f}s"


def test_a_raising_log_callback_does_not_fail_the_fetcher(tmp_path):
    """The runner must not kill a healthy fetcher because its consumer raised.

    _drain's finally closes the pipe, so an exception escaping on_line makes the
    child die on its next write — and the run then reports a fetcher failure for
    a failure the runner itself caused. The live case is the TUI, which forwards
    each line as a Textual message; that raises once the screen is torn down, so
    quitting mid-run would mark the running fetcher failed.
    """
    from framework.runner.executor import _invoke

    fetcher, out = _bash_fetcher(
        tmp_path,
        '#!/bin/bash\nfor i in $(seq 1 200); do echo "line $i"; done\nexit 0\n',
        timeout=60,
    )

    seen = []

    def hostile(line):
        seen.append(line)
        raise RuntimeError("consumer is gone")

    result = _invoke(fetcher, {"PATH": "/usr/bin:/bin"}, None, out, on_line=hostile)

    assert result.exit_code == 0, "a healthy fetcher must survive a raising consumer"
    assert result.stdout.count("line ") == 200, "every line must still reach the record"
    assert len(seen) == 1, "forwarding stops after the consumer first raises"
