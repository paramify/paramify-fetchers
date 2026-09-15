"""Resolve ${env:VAR_NAME} references from manifest values.

v0.x supports a single reference form: ${env:VAR_NAME} — read VAR_NAME from the
runner's own environment. The shape leaves room for future backends like
${aws-secret:...}, ${vault:...}, but v0.x doesn't implement them.

Customers populate the runner's env via any mechanism (.env, shell export,
secret manager → env, K8s secret env mounts, CI provider secret blocks, etc.).
The framework is secret-source-agnostic; .env is one path among many.
"""

import os
import re
from typing import Dict, Optional

_ENV_REF_PATTERN = re.compile(r"^\$\{env:([A-Z_][A-Z0-9_]*)\}$")

#: Anything opening with the reference sigil is an attempt at a reference.
#: Used to tell "this is a literal secret" (which passes through, by design)
#: apart from "this is a broken reference" (which must not).
_ENV_REF_ATTEMPT = re.compile(r"^\$\{env:")


class SecretResolutionError(RuntimeError):
    pass


class UnsetSecretError(SecretResolutionError):
    """A well-formed reference whose env var is unset or empty.

    Separate from a malformed reference so a caller holding an OPTIONAL secret
    can treat "nothing supplied" as an omission and let the fetcher's credential
    chain fall through to ambient identity, while a typo'd reference still fails
    loudly whether the secret is optional or not. Subclasses
    SecretResolutionError so callers that catch the base keep working.
    """

    def __init__(self, env_var: str, message: str):
        super().__init__(message)
        self.env_var = env_var


def resolve(value: str) -> str:
    """Resolve a ${env:VAR_NAME} reference. Plain strings pass through unchanged.

    Raises SecretResolutionError if the referenced env var is unset or empty.
    """
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    m = _ENV_REF_PATTERN.match(stripped)
    if not m:
        if _ENV_REF_ATTEMPT.match(stripped):
            # Looks like a reference but isn't one — a lowercase var name is the
            # usual cause. Passing it through hands the fetcher the literal
            # string "${env:...}" as its credential, and the TUI renders it as a
            # correctly-set variable, so the only symptom is a 401 whose echoed
            # credential redaction then hides. Fail here instead.
            raise SecretResolutionError(
                f"Malformed secret reference {stripped!r}: expected ${{env:VAR_NAME}} "
                f"where VAR_NAME is uppercase letters, digits and underscores "
                f"(e.g. ${{env:OKTA_API_TOKEN}}). A value that is not a reference at "
                f"all is passed through as a literal, but this one looks like one."
            )
        return value
    env_var = m.group(1)
    resolved = os.environ.get(env_var, "")
    if not resolved:
        raise UnsetSecretError(
            env_var,
            f"Secret reference ${{env:{env_var}}} could not be resolved: "
            f"env var '{env_var}' is unset or empty in the runner's environment",
        )
    return resolved


def resolve_dict(d: Dict[str, str]) -> Dict[str, str]:
    return {k: resolve(v) for k, v in d.items()}

def env_var_name(value) -> Optional[str]:
    """The VAR_NAME in a well-formed ${env:VAR_NAME}, else None.

    None means "not a valid reference" — either a literal secret or a malformed
    attempt. Callers that display a manifest must not render None as though the
    value were set; show the raw string so the operator can see what is wrong.
    Same regex resolve() enforces, so the display and the run agree.
    """
    if not isinstance(value, str):
        return None
    m = _ENV_REF_PATTERN.match(value.strip())
    return m.group(1) if m else None


def is_env_ref_attempt(value) -> bool:
    """True if the value opens with the reference sigil, well-formed or not."""
    return isinstance(value, str) and bool(_ENV_REF_ATTEMPT.match(value.strip()))
