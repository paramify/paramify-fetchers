"""Content-root resolution for the overlay distribution model.

Three kinds of location, kept strictly separate (docs/distribution_design.md):
- core assets (schemas, ksis.yaml) — package-relative, always inside framework/
- content roots (fetchers, categories) — the ordered overlay search path below
- user data (manifests/, evidence/) — the project dir (checkout or cwd); the
  tool never resolves content from it and never writes into it

Search-path precedence (first root wins a fetcher-name collision, so a user
copy shadows a built-in):
  1. $PARAMIFY_FETCHERS_PATH  — explicit override, os.pathsep-separated
  2. the dev checkout's fetchers/ (cwd walk) — in-tree edits always win for devs
  3. $PARAMIFY_HOME/fetchers/ — user-created fetchers and overrides
  4. framework/_bundled/fetchers/ — built-ins shipped inside the package
"""

import os
from pathlib import Path
from typing import List, Optional

ENV_HOME = "PARAMIFY_HOME"
ENV_FETCHERS_PATH = "PARAMIFY_FETCHERS_PATH"


def user_home() -> Path:
    """The user's writable paramify dir: $PARAMIFY_HOME, else the platform's
    native user-data location (~/Library/Application Support/paramify on macOS,
    %LOCALAPPDATA%\\paramify on Windows, ~/.local/share/paramify on Linux)."""
    env = os.environ.get(ENV_HOME)
    if env:
        return Path(env).expanduser()
    from platformdirs import user_data_dir  # lazy: only needed without the env var
    return Path(user_data_dir("paramify"))


def find_checkout_root(start: Optional[Path] = None) -> Optional[Path]:
    """Locate a dev checkout by walking up for sibling fetchers/ + framework/
    dirs. Returns None outside a checkout (unlike api.find_repo_root, which
    raises)."""
    cur = (start or Path.cwd()).resolve()
    for parent in [cur, *cur.parents]:
        if (parent / "fetchers").is_dir() and (parent / "framework").is_dir():
            return parent
    return None


def bundled_content_root() -> Optional[Path]:
    """framework/_bundled — the shipped content snapshot, assembled into the
    wheel at build time. Absent in a dev tree, where the checkout's own
    fetchers/ serves instead."""
    p = Path(__file__).parent / "_bundled"
    return p if p.is_dir() else None


def fetcher_roots(
    checkout: Optional[Path] = None, start: Optional[Path] = None
) -> List[Path]:
    """The ordered fetchers/ search path; only existing dirs are returned.

    Pass `checkout` to pin the dev root explicitly (tests, `paramify tui --at`);
    otherwise it is located by walking up from `start` (default: cwd).
    """
    roots: List[Path] = []
    env = os.environ.get(ENV_FETCHERS_PATH)
    if env:
        roots += [Path(p).expanduser() for p in env.split(os.pathsep) if p]
    co = checkout or find_checkout_root(start)
    if co is not None:
        roots.append(Path(co) / "fetchers")
    roots.append(user_home() / "fetchers")
    bundled = bundled_content_root()
    if bundled is not None:
        roots.append(bundled / "fetchers")

    seen, ordered = set(), []
    for r in roots:
        if not r.is_dir():
            continue
        key = r.resolve()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(r)
    return ordered
