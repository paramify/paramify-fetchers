"""Resolving the Paramify API token and base URL, in one place.

Both were resolved independently in four places (each uploader, and each of
api.py's two preflights) and they did not agree, which is the whole reason this
module exists — see `resolve_upload_token`.

Nothing here reads a file or makes a request: callers populate the environment by
whatever mechanism they use (.env, shell export, secret manager, CI secret block,
K8s secret mount), and this only reads it back. Both functions report WHERE a
value came from, not just what it is, because "which URL am I about to upload to"
and "which of the two token vars is in play" are the two questions people
actually get wrong.
"""

import getpass
import os
import sys
from typing import Mapping, Optional, Tuple

DEFAULT_BASE_URL = "https://app.paramify.com/api/v0"

# The canonical name for the upload path. Purpose-specific, and what the docs
# and the TUI tell people to set.
UPLOAD_TOKEN_ENV = "PARAMIFY_UPLOAD_API_TOKEN"
# The read-scope token the paramify VER fetchers use. Accepted as a fallback for
# upload rather than treated as the same thing: the two names imply different
# scopes and a workspace may legitimately issue two tokens, so each side prefers
# its own name and falls back to the other. That fixes the common single-token
# setup without collapsing the two-token one.
READ_TOKEN_ENV = "PARAMIFY_API_TOKEN"

BASE_URL_ENV = "PARAMIFY_API_BASE_URL"


def resolve_upload_token(
    env: Optional[Mapping[str, str]] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the token for uploading. Returns (token, source_env_var).

    Prefers PARAMIFY_UPLOAD_API_TOKEN, falls back to PARAMIFY_API_TOKEN. Before
    this existed the uploaders accepted only the first name while the paramify
    fetchers accepted either, so setting the shorter, more obvious name gave you
    working fetchers and an upload that failed at the last step.

    Returns (None, None) when neither is set — callers decide whether that is
    fatal, since a dry run does not need a token.
    """
    src = env if env is not None else os.environ
    for name in (UPLOAD_TOKEN_ENV, READ_TOKEN_ENV):
        value = (src.get(name) or "").strip()
        if value:
            return value, name
    return None, None


def missing_token_error() -> str:
    """One wording for the missing-token error, since every upload stage raises it."""
    return (
        f"{UPLOAD_TOKEN_ENV} is not set (or {READ_TOKEN_ENV} as a fallback). "
        f"Set it in the environment by any means — export, .env, secret manager, "
        f"CI secret — or run `paramify doctor <manifest>` to check before a run."
    )


def resolve_base_url(
    config_base_url: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Tuple[str, str]:
    """Resolve the API base URL. Returns (url, source).

    Precedence is uploader config, then PARAMIFY_API_BASE_URL, then the app
    default — matching what the uploaders already did. `source` is one of
    "config", the env var name, or "default", so a caller can show which of
    stage / app / a self-hosted instance a run is about to talk to. Pointing at
    the wrong one is silent otherwise: the upload succeeds, against the wrong
    workspace.
    """
    src = env if env is not None else os.environ
    if config_base_url:
        return config_base_url, "config"
    from_env = (src.get(BASE_URL_ENV) or "").strip()
    if from_env:
        return from_env, BASE_URL_ENV
    return DEFAULT_BASE_URL, "default"


def can_prompt(env: Optional[Mapping[str, str]] = None) -> bool:
    """Is it safe to ask the user for a token right now?

    Requires a real terminal on both ends and the absence of CI, because a
    prompt in a pipeline does not get answered — it hangs the job until the
    runner's timeout kills it, which is a far worse failure than the clean error
    the caller would otherwise raise.
    """
    src = env if env is not None else os.environ
    if src.get("CI"):
        return False
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        # Streams can be replaced or closed under test runners and some hosts.
        return False


def prompt_for_token(base_url: str, *, persist_hint: bool = True) -> Optional[str]:
    """Ask for the API token interactively; return None if we must not prompt.

    Shows the destination first. Getting this far means a collection has already
    run, so the two things worth confirming before the token is typed are that a
    token is needed at all and which workspace it is about to be spent on.

    The value is exported into this process's environment so the rest of the run
    resolves it normally, and is NOT written to disk — persisting a credential is
    the user's decision, so we print how instead of guessing.
    """
    if not can_prompt():
        return None
    label = describe_base_url(base_url)
    print("\nParamify API token required to upload.", file=sys.stderr)
    print(f"  destination: {label} — {base_url}", file=sys.stderr)
    try:
        token = getpass.getpass("  token (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return None
    if not token:
        return None
    os.environ[UPLOAD_TOKEN_ENV] = token
    if persist_hint:
        print(
            f"  using it for this run only. To persist it, export {UPLOAD_TOKEN_ENV}"
            f" or add it to whichever secret source you already use.",
            file=sys.stderr,
        )
    return token


def describe_base_url(url: str) -> str:
    """A short human label for a base URL, for preflight output.

    Recognises the hosted environments by hostname and calls anything else
    self-hosted, so `paramify doctor` can say "stage" rather than making someone
    parse a URL to notice they are not pointed at production.
    """
    host = url.split("//", 1)[-1].split("/", 1)[0].lower()
    if host.startswith("app."):
        return "production"
    if host.startswith(("stage.", "staging.")):
        return "stage"
    if host.startswith(("dev.", "localhost", "127.0.0.1")):
        return "development"
    return "self-hosted"
