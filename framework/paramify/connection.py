"""Where a stage talks to Paramify, and with what token: resolved once for every stage.

`settings()` answers without raising, for a preflight that lists every problem.
`connect()` raises on the first one and returns the `Client`, for a stage that is
about to make calls. `open_workspace()` is what a sync stage starts with.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, List, Mapping, Optional, Tuple, TypeVar

from dotenv import load_dotenv

from framework.paramify.client import Client, base_url_error
from framework.paramify.resources import Resources
from framework.paramify_auth import (
    missing_read_token_error,
    missing_token_error,
    resolve_base_url,
    resolve_read_token,
    resolve_upload_token,
)

W = TypeVar("W")

@dataclass(frozen=True)
class Settings:
    base_url: str
    base_url_source: str  # "config", "argument", the env var name, or "default"
    token: Optional[str]
    token_source: Optional[str]  # the env var it came from, "argument", or None
    read: bool = False  # a read-scope use: the read token first, and its wording

    def errors(self, *, need_token: bool) -> List[str]:
        """What stops a stage from running, in the order a person should fix it."""
        problems: List[str] = []
        # An env var by its name; anything else is the uploader config's base_url.
        setting = self.base_url_source if self.base_url_source.isupper() else "base_url"
        url_error = base_url_error(self.base_url, setting)
        if url_error:
            problems.append(url_error)
        if need_token and not self.token:
            problems.append(missing_read_token_error() if self.read else missing_token_error())
        return problems


def settings(
    config: Optional[Mapping[str, Any]] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    read: bool = False,
) -> Settings:
    """Resolve the base URL (config, then `base_url`, then the environment, then
    the default) and the token (`token`, then the environment: the upload token
    first, or the read token first when `read`)."""
    from_config = ((config or {}).get("paramify") or {}).get("base_url")
    if from_config or not base_url:
        url, url_source = resolve_base_url(from_config)
    else:
        url, url_source = base_url, "argument"
    token_source: Optional[str] = "argument" if token else None
    if not token:
        token, token_source = resolve_read_token() if read else resolve_upload_token()
    return Settings(url, url_source, token, token_source, read)


def client_for(resolved: Settings, **options: Any) -> Client:
    """The one place a Client is built from resolved settings (`options` go to
    Client: timeout, retry_budget_s). Tests patch `Client` here to reach every
    stage at once."""
    assert resolved.token, "client_for needs settings with a token"
    return Client(resolved.token, resolved.base_url, **options)


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
    client = client_for(resolved) if resolved.token else None
    return resolved, client


def open_workspace(
    config: Optional[Mapping[str, Any]] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[Client] = None,
    use: Optional[W] = None,
    dry_run: bool = False,
    wrap: Callable[[Client], W] = Resources,  # type: ignore[assignment]
    log: Optional[logging.Logger] = None,
) -> Tuple[str, Optional[W]]:
    """A sync stage's start: load `.env`, connect, and return the base URL and the
    client wrapped for the stage's endpoints (`Resources`, or e.g. `Pipelines`),
    None for a dry run without a token.

    `client` is a ready Client to wrap; `use` is a ready endpoint object, returned
    as is. Either one means no token is needed. A dry run with a token still gets
    one, so its reads show the real workspace; it must not write. A setup error is
    logged to `log` when given (for a stage run as a script), then raised as
    ValueError.
    """
    load_dotenv()
    given = client is not None or use is not None
    try:
        resolved, made = connect(config, base_url=base_url, token=None if given else token,
                                 need_token=not dry_run and not given)
    except ValueError as e:
        if log is not None:
            log.error("%s", e)
        raise
    if use is not None:
        return resolved.base_url, use
    client = client or made
    return resolved.base_url, wrap(client) if client is not None else None
