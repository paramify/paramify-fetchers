"""How the framework connects to Paramify — base URL, credentials, transport rule.

One definition of each, because there were five. Base-URL resolution was written
out in upload_preflight(), scripts_sync_preflight(), list_programs(), and both
uploaders, with three different precedence chains. list_programs() was the odd
one: it could not read a config file at all and re-literalled the default URL, so
pointing `paramify.base_url` at a stage host sent uploads to stage and
`paramify programs` to production. The https rule was implemented three times.

The uploaders keep their own copies on purpose. They live outside the framework
package (pyproject.toml ships `framework*` only; api.py loads them by path) and
must stay runnable as standalone scripts, so importing framework from them would
trade a small duplication for a real boundary violation. tests/test_api.py
asserts the two definitions of the default URL agree, so they cannot drift
silently.

One credential reaches Paramify, for reading and writing alike:
PARAMIFY_API_TOKEN. PARAMIFY_UPLOAD_API_TOKEN is accepted as a deprecated alias so
existing deployments, CI secret blocks, and compose env_files keep working.

The canonical name is not a new invention — the Paramify VER fetchers and
`paramify programs` already read PARAMIFY_API_TOKEN with the upload name as a
fallback (fetchers/paramify/_shared/ver_common.py, fetchers/_categories/
paramify.yaml). The uploaders were the last holdouts still demanding the
upload-specific name, which meant one workspace credential had to be exported
twice under two names. Everything now resolves through resolve_token().
"""

import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml

DEFAULT_BASE_URL = "https://app.paramify.com/api/v0"

BASE_URL_ENV = "PARAMIFY_API_BASE_URL"
# The one workspace credential — read and write.
TOKEN_ENV = "PARAMIFY_API_TOKEN"
# Deprecated alias, still honored so existing deployments keep working.
LEGACY_TOKEN_ENV = "PARAMIFY_UPLOAD_API_TOKEN"

# Exempt from the https rule so a local API stub can be developed against.
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def load_config(path: Optional[Path] = None) -> dict:
    """Read an uploader config YAML. Absent path or empty file -> {}.

    Matches uploaders/*/load_config(); this copy exists so framework code can read
    a config without loading an uploader module by path just to reach its loader.
    """
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text())
    return data or {}


def resolve_base_url(config: Optional[dict] = None, explicit: Optional[str] = None) -> str:
    """The Paramify API base URL.

    Precedence: the uploader config's `paramify.base_url` -> an explicitly passed
    value -> $PARAMIFY_API_BASE_URL -> the default. Config outranks the
    environment so a checked-in config can pin a tenant's host.
    """
    paramify_cfg = (config or {}).get("paramify") or {}
    return (
        paramify_cfg.get("base_url")
        or explicit
        or os.environ.get(BASE_URL_ENV)
        or DEFAULT_BASE_URL
    )


def base_url_error(base_url: str) -> Optional[str]:
    """Reject a plaintext endpoint: a Bearer token must not cross the wire in the
    clear. Returns an error message, or None when the URL is usable."""
    parsed = urlparse(base_url)
    if parsed.scheme != "https" and (parsed.hostname or "") not in _LOCAL_HOSTS:
        return (
            "base_url must be https to protect the API token "
            f"(got {base_url!r}); only localhost may use http"
        )
    return None


def resolve_token() -> Optional[str]:
    """The Paramify workspace credential — reads and writes both go through this.

    $PARAMIFY_API_TOKEN, falling back to the deprecated
    $PARAMIFY_UPLOAD_API_TOKEN. Every caller resolves the token here so that a
    preflight and the operation it clears can never disagree about which
    credential is in play.
    """
    return os.environ.get(TOKEN_ENV) or os.environ.get(LEGACY_TOKEN_ENV) or None


def missing_token_error() -> str:
    """The one wording for an absent credential."""
    return (
        f"No Paramify API token: set {TOKEN_ENV} to a token with read and write "
        f"scope on the workspace (the older {LEGACY_TOKEN_ENV} is still accepted)"
    )
