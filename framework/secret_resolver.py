"""Resolve ${env:VAR_NAME} references from manifest values.

v0.x supports a single reference form: ${env:VAR_NAME} — read VAR_NAME from the
runner's own environment. The shape leaves room for future backends like
${aws-secret:...}, ${vault:...}, but v0.x doesn't implement them.

Customers populate the runner's env via any mechanism (shell export, secret
manager → env, K8s secret env mounts, CI provider secret blocks, compose's
env_file, etc.). This module is secret-source-agnostic: it reads os.environ and
asks no questions about how a value got there.

Every source in that list populates the environment before Python starts, which
is exactly why an agnostic reader gets them for free. A `.env` file is the one
exception — it is a file on disk, so someone inside the process has to read it.
That happens once, at the entry point, in api.load_environment(); it is not this
module's job and must not become any other function's job either.
"""

import os
import re
from typing import Dict

_ENV_REF_PATTERN = re.compile(r"^\$\{env:([A-Z_][A-Z0-9_]*)\}$")


class SecretResolutionError(RuntimeError):
    pass


def resolve(value: str) -> str:
    """Resolve a ${env:VAR_NAME} reference. Plain strings pass through unchanged.

    Raises SecretResolutionError if the referenced env var is unset or empty.
    """
    if not isinstance(value, str):
        return value
    m = _ENV_REF_PATTERN.match(value.strip())
    if not m:
        return value
    env_var = m.group(1)
    resolved = os.environ.get(env_var, "")
    if not resolved:
        raise SecretResolutionError(
            f"Secret reference ${{env:{env_var}}} could not be resolved: "
            f"env var '{env_var}' is unset or empty in the runner's environment"
        )
    return resolved


def resolve_dict(d: Dict[str, str]) -> Dict[str, str]:
    return {k: resolve(v) for k, v in d.items()}
