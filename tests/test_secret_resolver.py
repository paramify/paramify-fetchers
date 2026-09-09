"""Tests for ${env:VAR} secret resolution (framework/secret_resolver.py).

The properties that matter: a valid reference resolves from the runner's env, and
an unset/empty reference fails LOUDLY (never silently injects an empty
credential). The last test characterizes the known silent-passthrough gap so a
future hardening changes it on purpose.
"""

from __future__ import annotations

import pytest

from framework.secret_resolver import (
    SecretResolutionError,
    UnsetSecretError,
    env_var_name,
    is_env_ref_attempt,
    resolve,
    resolve_dict,
)


def test_resolves_valid_reference_from_env(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "abc123")
    assert resolve("${env:MY_TOKEN}") == "abc123"


def test_unset_env_var_raises_loudly(monkeypatch):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    with pytest.raises(SecretResolutionError, match="NOPE_TOKEN"):
        resolve("${env:NOPE_TOKEN}")


def test_empty_env_value_raises_not_silently_empty(monkeypatch):
    # A var explicitly set to "" must be treated as unresolved, not as a
    # silently-empty secret that the fetcher would authenticate with.
    monkeypatch.setenv("EMPTY_TOKEN", "")
    with pytest.raises(SecretResolutionError):
        resolve("${env:EMPTY_TOKEN}")


def test_plain_string_passes_through_unchanged():
    assert resolve("a-literal-non-reference-value") == "a-literal-non-reference-value"


def test_surrounding_whitespace_is_tolerated(monkeypatch):
    monkeypatch.setenv("T", "v")
    assert resolve("  ${env:T}  ") == "v"


def test_non_string_value_passes_through():
    assert resolve(123) == 123


def test_resolve_dict_resolves_each_value(monkeypatch):
    monkeypatch.setenv("A", "1")
    monkeypatch.setenv("B", "2")
    assert resolve_dict({"a": "${env:A}", "b": "${env:B}"}) == {"a": "1", "b": "2"}


@pytest.mark.parametrize("bad", [
    "${env:my_token}",   # lowercase var name — the common typo
    "${env:MY-TOKEN}",   # hyphen is not a valid env var character
    "${env:}",           # empty name
    "${env:FOO",         # unclosed
])
def test_malformed_reference_raises_instead_of_passing_through(bad, monkeypatch):
    """A broken reference must fail loudly, not become the credential.

    This replaces a characterization test that pinned the old silent
    passthrough. Passing it through handed the fetcher the literal string
    "${env:my_token}" as its secret; the TUI rendered it as a correctly-set
    variable named my_token, and redaction then added the literal to the secret
    sink — so the 401 that echoed it back printed ***REDACTED*** exactly where
    the bug's own name would have been. Three layers agreeing on a wrong answer.
    """
    monkeypatch.setenv("my_token", "secret")
    with pytest.raises(SecretResolutionError, match="Malformed secret reference"):
        resolve(bad)


def test_a_value_that_is_not_a_reference_is_still_a_literal(monkeypatch):
    """Literal secrets are supported, so only a value that OPENS with the sigil
    counts as an attempted reference. An embedded ${env:...} stays a literal —
    substitution was never a feature, and a real password may contain anything."""
    monkeypatch.setenv("T", "v")
    assert resolve("prefix-${env:T}") == "prefix-${env:T}"
    assert resolve("hunter2") == "hunter2"
    assert resolve("https://host/path$notaref") == "https://host/path$notaref"


def test_env_var_name_and_resolve_agree_on_what_is_valid(monkeypatch):
    """The display path and the run path must not disagree — that disagreement
    is what let the console show a malformed ref as set."""
    monkeypatch.setenv("REAL_TOKEN", "v")
    assert env_var_name("${env:REAL_TOKEN}") == "REAL_TOKEN"
    assert resolve("${env:REAL_TOKEN}") == "v"

    assert env_var_name("${env:my_token}") is None
    assert is_env_ref_attempt("${env:my_token}") is True
    with pytest.raises(SecretResolutionError):
        resolve("${env:my_token}")

    assert env_var_name("literal") is None
    assert is_env_ref_attempt("literal") is False
    assert resolve("literal") == "literal"


# --- which error, and why it matters --------------------------------------- #
# The runner lets an OPTIONAL secret fall through to ambient identity when its
# env var is unset, but never when the reference itself is broken. That split is
# only expressible if the two failures are distinguishable here.

def test_unset_env_var_raises_the_distinct_unset_error(monkeypatch):
    monkeypatch.delenv("MISSING_TOK", raising=False)
    with pytest.raises(UnsetSecretError) as e:
        resolve("${env:MISSING_TOK}")
    assert e.value.env_var == "MISSING_TOK"


def test_empty_env_value_also_raises_the_unset_error(monkeypatch):
    monkeypatch.setenv("EMPTY_TOK", "")
    with pytest.raises(UnsetSecretError):
        resolve("${env:EMPTY_TOK}")


def test_malformed_reference_is_not_an_unset_error(monkeypatch):
    """A typo'd name must not qualify for the optional-secret fallback, or the
    credential the operator meant to supply is silently dropped."""
    monkeypatch.setenv("api_token", "v")
    with pytest.raises(SecretResolutionError) as e:
        resolve("${env:api_token}")
    assert not isinstance(e.value, UnsetSecretError)


def test_unset_error_is_catchable_as_the_base_error(monkeypatch):
    """Callers that catch the base class keep working unchanged."""
    monkeypatch.delenv("MISSING_TOK", raising=False)
    with pytest.raises(SecretResolutionError):
        resolve("${env:MISSING_TOK}")
