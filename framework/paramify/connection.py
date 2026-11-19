"""Where a stage talks to Paramify, and with what token: resolved once for every stage.

`settings()` answers without raising, for a preflight that lists every problem.
`connect()` raises on the first one and returns the `Client`, for a stage that is
about to make calls. `open_workspace()` is what a sync stage starts with.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Tuple

from dotenv import load_dotenv

from framework.paramify.client import Client, base_url_error
from framework.paramify.resources import Resources
from framework.paramify_auth import (
    missing_token_error,
    resolve_base_url,
    resolve_upload_token,
)


@dataclass(frozen=True)
class Settings:
    base_url: str
    base_url_source: str  # "config", "argument", the env var name, or "default"
    token: Optional[str]
    token_source: Optional[str]  # the env var it came from, "argument", or None

    def errors(self, *, need_token: bool) -> List[str]:
        """What stops a stage from running, in the order a person should fix it."""
        problems: List[str] = []
        url_error = base_url_error(self.base_url)
        if url_error:
            problems.append(url_error)
        if need_token and not self.token:
            problems.append(missing_token_error())
        return problems


def settings(
    config: Optional[Mapping[str, Any]] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
) -> Settings:
    """Resolve the base URL (config, then `base_url`, then the environment, then
    the default) and the token (`token`, then the environment)."""
    from_config = ((config or {}).get("paramify") or {}).get("base_url")
    if from_config or not base_url:
        url, url_source = resolve_base_url(from_config)
    else:
        url, url_source = base_url, "argument"
    token_source: Optional[str] = "argument" if token else None
    if not token:
        token, token_source = resolve_upload_token()
    return Settings(url, url_source, token, token_source)


def connect(
    config: Optional[Mapping[str, Any]] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    need_token: bool = True,
) -> "tuple[Settings, Optional[Client]]":
    """Resolve, check, and build the client. Raises ValueError for a setup error.

    Without `need_token` (a dry run) a missing token is allowed and the client is
    None; with a token a dry run still gets a client, so its reads can show the
    real workspace.
    """
    resolved = settings(config, base_url=base_url, token=token)
    problems = resolved.errors(need_token=need_token)
    if problems:
        raise ValueError(problems[0])
    client = Client(resolved.token, resolved.base_url) if resolved.token else None
    return resolved, client


def open_workspace(
    config: Optional[Mapping[str, Any]] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[Client] = None,
    dry_run: bool = False,
    log: Optional[logging.Logger] = None,
) -> Tuple[str, Optional[Resources]]:
    """A sync stage's start: load `.env`, connect, and return the base URL and the
    `Resources` to call (None for a dry run without a token).

    A given `client` is used as is. A dry run with a token still gets `Resources`,
    so its reads show the real workspace; it must not write. A setup error is
    logged to `log`, for a stage run as a script, then raised as ValueError.
    """
    load_dotenv()
    try:
        resolved, made = connect(config, base_url=base_url, token=token,
                                 need_token=not dry_run and client is None)
    except ValueError as e:
        (log or logging.getLogger(__name__)).error("%s", e)
        raise
    client = client or made
    return resolved.base_url, Resources(client) if client is not None else None
