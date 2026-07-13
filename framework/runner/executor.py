"""Execute fetchers via subprocess — single-target or fanout.

The runner's contract with a fetcher:
- Set EVIDENCE_DIR to the per-run output directory
- Resolve every declared secret and set the corresponding env var
- For fanout: also set target_schema fields → env vars per target_schema.<field>.env
- Exec the fetcher's entry script
- Capture stdout, stderr, exit code, duration
- Diff the output dir to discover what files the fetcher wrote
- Continue on per-target failures (each target is its own failure domain)
"""

import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from framework.contract import (
    Fetcher,
    InvocationResult,
    ManifestEntry,
    PlatformConfig,
    PlatformSpec,
    TargetInstance,
)
from framework.secret_resolver import SecretResolutionError, resolve

_INHERITED_ENV_VARS = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "USER", "TZ")

# Per-invocation wall-clock cap so a hung fetcher can't stall the whole run.
# Override per fetcher via runtime.timeout in fetcher.yaml.
_DEFAULT_TIMEOUT_SEC = 600
# Exit code recorded when the runner kills a fetcher for exceeding its timeout
# (matches the shell convention for SIGTERM-on-timeout).
_TIMEOUT_EXIT_CODE = 124

# Mask resolved secret VALUES out of captured fetcher output before it is
# persisted (envelope metadata.error, _run_metadata.json stderr_tail) or streamed
# to a front-end. The runner is the only place that knows the exact values it
# injected, so we redact those literals — not patterns/guesses. Values shorter
# than _MIN_SECRET_LEN_TO_MASK are left alone so a trivial secret like "1"/"true"
# can't blank out unrelated text and corrupt the evidence. This masks only what
# the runner injected verbatim; a secret the fetcher DERIVES at runtime or
# transforms (encodes/truncates) won't match, so fetchers must still never print
# secrets — see docs/envelope_design.md.
_REDACTION_PLACEHOLDER = "***REDACTED***"
_MIN_SECRET_LEN_TO_MASK = 5


def _redact(text: str, secret_values) -> str:
    """Replace each known secret value in `text` with a placeholder. Longest
    first, so a value that contains another is fully masked before its substring
    is processed. Safe on empty/None inputs."""
    if not text or not secret_values:
        return text
    maskable = sorted(
        (s for s in secret_values if isinstance(s, str) and len(s) >= _MIN_SECRET_LEN_TO_MASK),
        key=len,
        reverse=True,
    )
    for value in maskable:
        if value in text:
            text = text.replace(value, _REDACTION_PLACEHOLDER)
    return text


# passthrough_env mixes credential material (AWS_SECRET_ACCESS_KEY,
# AWS_SESSION_TOKEN, …) with non-sensitive identity/region selectors (AWS_PROFILE,
# AWS_DEFAULT_REGION, AWS_ROLE_ARN, …) and path/endpoint vars (…_FILE, …_URI). We
# mask the credential ones out of captured output, but NOT the selectors/paths —
# region/profile/ARN are legitimate evidence content and masking them would
# corrupt the evidence.
_SENSITIVE_NAME_PARTS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE_KEY")


def _is_sensitive_env_name(name: str) -> bool:
    """Heuristic: does this env var NAME denote credential material (vs. an
    identity/region selector or a file/endpoint path)?"""
    up = name.upper()
    if up.endswith("_FILE") or up.endswith("_URI"):
        return False
    return any(part in up for part in _SENSITIVE_NAME_PARTS)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _coerce_env(value) -> str:
    """Serialize a config value for an env var. Booleans become lowercase
    'true'/'false' (what shell scripts compare against), everything else str()."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _apply_config(
    env: Dict[str, str],
    fetcher: Fetcher,
    platform_spec: Optional[PlatformSpec],
    platform_cfg: Optional[PlatformConfig],
    entry: ManifestEntry,
    secret_sink: Optional[set] = None,
) -> None:
    """Merge config (platform defaults <- platform values <- per-fetcher values)
    and inject each field that declares an `env` mapping. Also lets the
    platform's auth passthrough_env vars through the whitelist."""
    schema = {}
    if platform_spec:
        schema.update(platform_spec.config_schema)
    schema.update(fetcher.config_schema)  # per-fetcher overrides platform on name clash

    values = {name: f.default for name, f in schema.items() if f.default is not None}
    if platform_cfg:
        values.update({k: v for k, v in platform_cfg.config.items() if v is not None})
    values.update({k: v for k, v in entry.config.items() if v is not None})

    for name, fdef in schema.items():
        if not fdef.env:
            continue
        val = values.get(name)
        if val is None:
            if fdef.required:
                raise RuntimeError(
                    f"{fetcher.name}: required config '{name}' has no value "
                    f"(set it under platforms.{fetcher.category}.config or the fetcher's config)"
                )
            continue
        env[fdef.env] = _coerce_env(val)

    passthrough = set(platform_spec.passthrough_env if platform_spec else [])
    if platform_cfg:
        passthrough.update(platform_cfg.passthrough_env)
    for var in passthrough:
        if var in os.environ:
            value = os.environ[var]
            env[var] = value
            # Ambient creds (AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN, …) are
            # injected verbatim like declared secrets, so mask them out of
            # captured output too; identity/region/path selectors are not masked.
            if secret_sink is not None and _is_sensitive_env_name(var):
                secret_sink.add(value)


def _build_env(
    fetcher: Fetcher,
    entry: ManifestEntry,
    target: Optional[TargetInstance],
    output_dir: Path,
    platform_spec: Optional[PlatformSpec] = None,
    platform_cfg: Optional[PlatformConfig] = None,
    secret_sink: Optional[set] = None,
) -> Dict[str, str]:
    """Build the env dict to pass to a single fetcher invocation.

    Does NOT inherit the runner's full env — only a small whitelist of innocuous
    vars (PATH for tool resolution, locale vars, etc.), plus any platform
    auth passthrough vars. Secrets and config are set explicitly from the
    manifest + fetcher.yaml + category platform spec.
    """
    env = {k: os.environ[k] for k in _INHERITED_ENV_VARS if k in os.environ}
    # Console scripts installed next to the running interpreter (a pipx venv,
    # an unactivated .venv) must be visible to fetchers — e.g. the `checkov`
    # extra, whose CLI lands in a bin/ that pipx never puts on PATH.
    interp_bin = str(Path(sys.executable).parent)
    parts = env.get("PATH", "").split(os.pathsep) if env.get("PATH") else []
    if interp_bin not in parts:
        env["PATH"] = os.pathsep.join([interp_bin, *parts])
    env["PYTHONUNBUFFERED"] = "1"
    env["EVIDENCE_DIR"] = str(output_dir.resolve())

    _apply_config(env, fetcher, platform_spec, platform_cfg, entry, secret_sink)

    for secret in fetcher.secrets:
        if secret.per_target:
            if target is None:
                raise RuntimeError(
                    f"{fetcher.name}: per_target secret '{secret.name}' "
                    f"declared but no target was provided"
                )
            ref = target.secrets.get(secret.name)
            if ref is None:
                raise RuntimeError(
                    f"{fetcher.name}: target is missing per_target secret '{secret.name}'"
                )
            resolved = resolve(ref)
            env[secret.env] = resolved
            if secret_sink is not None:
                secret_sink.add(resolved)
        else:
            ref = entry.secrets.get(secret.name)
            if ref is None:
                raise RuntimeError(
                    f"{fetcher.name}: manifest entry is missing secret '{secret.name}'"
                )
            resolved = resolve(ref)
            env[secret.env] = resolved
            if secret_sink is not None:
                secret_sink.add(resolved)

    if target is not None:
        for field_name, field_spec in fetcher.target_schema.items():
            if not field_spec.env:
                continue
            value = target.values.get(field_name, field_spec.default)
            if value is None and field_spec.required:
                raise RuntimeError(
                    f"{fetcher.name}: target is missing required field '{field_name}'"
                )
            if value is not None:
                env[field_spec.env] = str(value)

    return env


def _drain(stream, sink: List[str], on_line: Optional[Callable[[str], None]],
           secret_values=None) -> None:
    """Read a subprocess pipe to EOF, accumulating lines and optionally
    forwarding each to on_line. Runs in its own thread so stdout/stderr are
    drained concurrently (no pipe-buffer deadlock) and stdout can stream live.
    Forwarded lines are secret-redacted so a live front-end never shows an
    injected secret value; the accumulated sink is redacted once at the end."""
    try:
        for line in stream:
            sink.append(line)
            if on_line is not None:
                on_line(_redact(line.rstrip("\n"), secret_values))
    finally:
        stream.close()


def _invoke(
    fetcher: Fetcher,
    env: Dict[str, str],
    target: Optional[TargetInstance],
    output_dir: Path,
    on_line: Optional[Callable[[str], None]] = None,
    secret_values=None,
) -> InvocationResult:
    """Run one fetcher invocation.

    When on_line is provided, each stdout line is forwarded as it arrives (live
    streaming for front-ends such as the TUI run console). When None, behavior
    matches the previous blocking run — full stdout/stderr are still captured
    into the result either way. The wall-clock timeout fires even if the fetcher
    emits no output.
    """
    if fetcher.runtime_type == "python":
        cmd = [sys.executable, str(fetcher.entry_path)]
    elif fetcher.runtime_type == "bash":
        cmd = ["bash", str(fetcher.entry_path)]
    else:
        raise RuntimeError(f"Unknown runtime: {fetcher.runtime_type}")

    started_at = _utc_now()
    start = time.monotonic()

    before = {p.name for p in output_dir.iterdir()} if output_dir.exists() else set()

    timeout = fetcher.runtime_timeout or _DEFAULT_TIMEOUT_SEC
    proc = subprocess.Popen(
        cmd,
        env=env,
        cwd=str(fetcher.path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered so on_line fires per line
    )

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_lines, on_line, secret_values))
    t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_lines, None, secret_values))
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()

    # Threads finish once the pipes hit EOF (which the kill guarantees).
    t_out.join()
    t_err.join()

    exit_code = _TIMEOUT_EXIT_CODE if timed_out else proc.returncode
    stdout = _redact("".join(stdout_lines), secret_values)
    stderr = _redact("".join(stderr_lines), secret_values)
    if timed_out:
        stderr += f"\nrunner: killed — exceeded timeout of {timeout}s"

    duration = time.monotonic() - start
    completed_at = _utc_now()

    after = {p.name for p in output_dir.iterdir()} if output_dir.exists() else set()
    outputs = sorted(after - before)

    return InvocationResult(
        fetcher_name=fetcher.name,
        fetcher_version=fetcher.version,
        target=target.values if target else None,
        started_at=started_at,
        completed_at=completed_at,
        duration_sec=round(duration, 3),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        outputs=outputs,
    )


def run_entry(
    fetcher: Fetcher,
    entry: ManifestEntry,
    output_dir: Path,
    platform_spec: Optional[PlatformSpec] = None,
    platform_cfg: Optional[PlatformConfig] = None,
    on_line: Optional[Callable[[str], None]] = None,
) -> List[InvocationResult]:
    """Run one manifest entry: single invocation, or one per target for fanout.

    Per-target failures are isolated — they don't abort sibling targets.
    When on_line is provided, each invocation streams its stdout lines to it.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if not fetcher.supports_targets:
        secrets_seen: set = set()
        env = _build_env(fetcher, entry, None, output_dir, platform_spec, platform_cfg, secrets_seen)
        return [_invoke(fetcher, env, None, output_dir, on_line, secrets_seen)]

    if not entry.targets:
        # No targets[] given. If every target field is optional, run once with the
        # ambient identity/region (the AWS credential chain's default) rather than
        # fanning out — "collect where deployed." A still-required target field is a
        # real manifest error, so keep raising in that case.
        if any(f.required for f in fetcher.target_schema.values()):
            raise RuntimeError(
                f"{fetcher.name}: supports_targets but manifest entry has no targets[]"
            )
        secrets_seen = set()
        env = _build_env(fetcher, entry, None, output_dir, platform_spec, platform_cfg, secrets_seen)
        return [_invoke(fetcher, env, None, output_dir, on_line, secrets_seen)]

    results = []
    for target in entry.targets:
        try:
            secrets_seen = set()
            env = _build_env(fetcher, entry, target, output_dir, platform_spec, platform_cfg, secrets_seen)
            results.append(_invoke(fetcher, env, target, output_dir, on_line, secrets_seen))
        except (RuntimeError, SecretResolutionError) as e:
            now = _utc_now()
            results.append(InvocationResult(
                fetcher_name=fetcher.name,
                fetcher_version=fetcher.version,
                target=target.values,
                started_at=now,
                completed_at=now,
                duration_sec=0.0,
                exit_code=255,
                stdout="",
                stderr=_redact(f"runner: failed to set up target invocation: {e}", secrets_seen),
                outputs=[],
            ))
    return results
