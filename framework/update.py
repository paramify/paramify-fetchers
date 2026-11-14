"""`paramify update`: move a clone from one release tag to another, safely.

This automates docs/versioning_guide.md: fetch the tags, read what changed
between the version you run and the target, check your manifests against the
target before touching your checkout, then switch, reinstall and validate.

Everything here returns JSON-able dicts. The CLI renders them (framework/
update_view.py) or prints them under --json; nothing in this module writes to
the terminal.

Three rules shape the code:

* Releases are tags named vX.Y.Z[-suffix]. `main` and archive/* are never
  targets, so a user can't land on unreleased work by running this.
* Nothing changes the user's checkout until they confirm. The pre-switch check
  runs the target's own `paramify validate` in a throwaway `git worktree`, which
  is removed whatever happens.
* Every git and pip call is a subprocess, and on this kind of laptop each one
  costs real time, so the code batches reads (one `git cat-file --batch` for
  every file it needs from the target) rather than calling git per file.
"""

from __future__ import annotations

import fnmatch
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

import yaml
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

RELEASE_TAG = re.compile(r"^v(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$")
DISTRIBUTION = "paramify-fetchers"
HIGHLIGHTS_DIR = "releases"
STATE_FILE = Path(".paramify") / "state.json"
NO_CHECK_ENV = "PARAMIFY_NO_UPDATE_CHECK"
CONTAINER_ENV = "PARAMIFY_CONTAINER"
CHECK_INTERVAL = 24 * 60 * 60
PUBLIC_REPO = "https://github.com/paramify/paramify-fetchers"
COMPOSE_BUILD = "docker compose -f deploy/docker-compose.yml build"

# Pills shown before a highlight's title. Order is display order within a
# release: what is new first, fixes last.
HIGHLIGHT_TAGS = ("new", "fetcher", "cli", "tui", "improved", "security", "fix", "deprecated", "breaking")


class UpdateError(RuntimeError):
    """A failure the user can act on. The message is shown as is."""


# --------------------------------------------------------------------------- #
# git
# --------------------------------------------------------------------------- #

def _git_env() -> Dict[str, str]:
    # A background or scripted call must never stop to ask for a password: fail
    # instead, and let the caller report it.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    env.setdefault("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
    return env


def git(root: Path, *args: str, timeout: Optional[float] = 120, input: Optional[str] = None) -> str:
    """Run git in `root` and return stdout. Raises UpdateError with git's own
    message, which is usually the most useful thing to show."""
    try:
        proc = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True,
            timeout=timeout, env=_git_env(), input=input,
        )
    except FileNotFoundError:
        raise UpdateError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise UpdateError(f"git {args[0]} took longer than {timeout:.0f}s") from None
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip().splitlines()
        raise UpdateError(msg[-1] if msg else f"git {args[0]} failed")
    return proc.stdout


def read_at(root: Path, ref: str, paths: Sequence[str]) -> Dict[str, Optional[str]]:
    """Read several files as they are at `ref`, in one git process.

    Missing files map to None. `git cat-file --batch` answers each request with
    `<sha> <type> <size>` and the bytes, or `<request> missing`.
    """
    if not paths:
        return {}
    try:
        proc = subprocess.run(
            ["git", "cat-file", "--batch"], cwd=root, capture_output=True,
            input="".join(f"{ref}:{p}\n" for p in paths).encode(), timeout=60, env=_git_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise UpdateError(f"could not read files at {ref}: {e}") from None
    out, pos = proc.stdout, 0
    result: Dict[str, Optional[str]] = {}
    for p in paths:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode(errors="replace").split()
        pos = nl + 1
        if len(header) == 3 and header[1] == "blob":
            size = int(header[2])
            result[p] = out[pos:pos + size].decode("utf-8", errors="replace")
            pos += size + 1
        else:
            result[p] = None
    return result


# --------------------------------------------------------------------------- #
# Releases and where you are
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Release:
    tag: str
    version: str
    key: Version

    def to_json(self) -> dict:
        return {"tag": self.tag, "version": self.version}


def parse_release(tag: str) -> Optional[Release]:
    """A Release for a vX.Y.Z[-suffix] tag, or None for anything else
    (archive/*, a typo'd tag, a suffix PEP 440 can't order)."""
    m = RELEASE_TAG.match(tag.strip())
    if not m:
        return None
    try:
        return Release(tag.strip(), m["version"], Version(m["version"]))
    except InvalidVersion:
        return None


def list_releases(root: Path) -> List[Release]:
    """Every local release tag, oldest first."""
    found = (parse_release(t) for t in git(root, "tag", "-l", "v*").splitlines())
    return sorted((r for r in found if r), key=lambda r: r.key)


def fetch_tags(root: Path, timeout: float = 90) -> None:
    git(root, "fetch", "--tags", "--quiet", timeout=timeout)


def position(root: Path) -> dict:
    """Where the checkout is: the nearest release tag behind HEAD, how far past
    it, and the branch if HEAD is on one."""
    sha = git(root, "rev-parse", "HEAD").strip()
    try:
        branch: Optional[str] = git(root, "symbolic-ref", "-q", "--short", "HEAD").strip() or None
    except UpdateError:
        branch = None
    tag, ahead = None, None
    try:
        described = git(root, "describe", "--tags", "--long", "--match", "v[0-9]*").strip()
        tag, n, _ = described.rsplit("-", 2)
        ahead = int(n)
    except (UpdateError, ValueError):
        pass
    rel = parse_release(tag) if tag else None
    return {
        "tag": tag,
        "version": rel.version if rel else None,
        "ahead": ahead,
        "exact": ahead == 0,
        "branch": branch,
        "sha": sha,
        "short": sha[:7],
    }


def is_container(root: Path) -> bool:
    """True inside the deploy image, or any copy of the code without git history.

    deploy/Dockerfile sets PARAMIFY_CONTAINER=1, and .dockerignore leaves .git
    out of the image, so either signal means there is no clone here to update.
    """
    return bool(os.environ.get(CONTAINER_ENV)) or not (Path(root) / ".git").exists()


def container_advice(root: Path) -> dict:
    """What to tell someone who runs `update` where it can't work."""
    return {
        "ok": False,
        "container": True,
        "errors": ["no git clone here: update the clone on the host, then rebuild the image"],
        "commands": ["paramify update", COMPOSE_BUILD],
        "version": installed_version(),
    }


def installed_version() -> Optional[str]:
    try:
        return metadata.version(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return None


def choose_target(
    releases: Sequence[Release], pos: dict, *, to: Optional[str] = None, next_release: bool = False,
) -> Optional[Release]:
    """The release to move to: --to's, the one after yours (--next), or the newest."""
    if to:
        want = to if to.startswith("v") else f"v{to}"
        for r in releases:
            if r.tag == want:
                return r
        names = ", ".join(r.tag for r in releases[-6:]) or "none"
        raise UpdateError(f"{to} is not a release tag (recent releases: {names})")
    if not releases:
        return None
    if next_release:
        base = parse_release(pos["tag"] or "")
        later = [r for r in releases if base is None or r.key > base.key]
        return later[0] if later else None
    return releases[-1]


def crossed(releases: Sequence[Release], pos: dict, target: Release) -> List[Release]:
    """Releases between yours (exclusive) and the target (inclusive), oldest first.

    Empty when the target is yours or older: nothing new is crossed going back.
    """
    base = parse_release(pos["tag"] or "")
    return [r for r in releases if (base is None or r.key > base.key) and r.key <= target.key]


# --------------------------------------------------------------------------- #
# CHANGELOG and highlights
# --------------------------------------------------------------------------- #

_SECTION = re.compile(r"^## \[(?P<version>[^\]]+)\](?:\s*-\s*(?P<date>\S+))?\s*$")
_SUBSECTION = re.compile(r"^### (?P<name>.+?)\s*$")


def parse_changelog(text: str) -> Dict[str, dict]:
    """{version: {date, heading, sections: {Breaking: [entry, ...], ...}}}.

    An entry is one top-level `- ` bullet with its continuation lines joined.
    """
    out: Dict[str, dict] = {}
    cur: Optional[dict] = None
    bucket: Optional[List[str]] = None
    for line in text.splitlines():
        m = _SECTION.match(line)
        if m:
            cur = out.setdefault(m["version"], {"date": m["date"], "heading": line[3:], "sections": {}})
            bucket = None
            continue
        if cur is None:
            continue
        m = _SUBSECTION.match(line)
        if m:
            bucket = cur["sections"].setdefault(m["name"], [])
            continue
        if bucket is None:
            continue
        if line.startswith("- "):
            bucket.append(line[2:].strip())
        elif line.startswith(" ") and line.strip() and bucket:
            bucket[-1] += " " + line.strip()
    return out


def entry_title(entry: str, limit: int = 90) -> str:
    """A one-line title for a CHANGELOG entry: its bold lead if it has one,
    else its first sentence, cut to `limit` characters."""
    m = re.match(r"\*\*(.+?)\*\*", entry)
    text = m[1] if m else re.split(r"(?<=[.:])\s", entry, maxsplit=1)[0]
    text = text.strip().rstrip(".:")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def changelog_anchor(heading: str) -> str:
    """GitHub's anchor for a `## [0.6.0-beta] - 2026-10-23` heading."""
    slug = re.sub(r"[^\w\- ]", "", heading.lower())
    return slug.replace(" ", "-")


def repo_web_url(root: Path) -> str:
    """The GitHub page of origin, for changelog links; the public repo when
    origin isn't on GitHub (a private mirror elsewhere still has the same tags)."""
    try:
        url = git(root, "remote", "get-url", "origin", timeout=10).strip()
    except UpdateError:
        return PUBLIC_REPO
    m = re.match(r"^(?:https://github\.com/|git@[^:]*github[^:]*:|ssh://git@github\.com/)(.+?)(?:\.git)?/?$", url)
    return f"https://github.com/{m[1]}" if m else PUBLIC_REPO


def highlights_schema() -> dict:
    # The running code's own copy: it is what this code knows how to read.
    return json.loads((Path(__file__).parent / "schemas/release_highlights_schema.json").read_text())


def highlights_errors(doc: Any, schema: dict) -> List[str]:
    from jsonschema import Draft202012Validator

    v = Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}" for e in v.iter_errors(doc)]


def _normalize_highlights(doc: dict) -> dict:
    """YAML reads an unquoted 2026-10-23 as a date and 0.6 as a float; the
    schema wants the text the author typed."""
    for key in ("date", "version"):
        if key in doc and not isinstance(doc[key], str):
            doc[key] = doc[key].isoformat() if hasattr(doc[key], "isoformat") else str(doc[key])
    return doc


def _load_highlights(text: Optional[str], schema: dict) -> Optional[dict]:
    if not text:
        return None
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if isinstance(doc, dict):
        doc = _normalize_highlights(doc)
    # A broken file falls back to "see the changelog" rather than failing the
    # update: highlights are a nicety, the CHANGELOG is the record.
    return doc if isinstance(doc, dict) and not highlights_errors(doc, schema) else None


def release_notes(root: Path, target: Release, releases: Sequence[Release]) -> List[dict]:
    """What each crossed release says, newest first.

    Reads the target's CHANGELOG and every releases/<version>.yaml as they are
    at the target tag, in one git call. A highlights file written after its
    release was tagged lives only in later trees (and on main), so the working
    tree is the fallback for one the target doesn't carry.
    """
    paths = ["CHANGELOG.md"] + [f"{HIGHLIGHTS_DIR}/{r.version}.yaml" for r in releases]
    files = read_at(root, target.tag, paths)
    changelog = parse_changelog(files.get("CHANGELOG.md") or "")
    schema = highlights_schema()
    web = repo_web_url(root)
    notes = []
    for r in reversed(releases):
        rel_path = f"{HIGHLIGHTS_DIR}/{r.version}.yaml"
        text = files.get(rel_path)
        if text is None and (Path(root) / rel_path).is_file():
            text = (Path(root) / rel_path).read_text()
        doc = _load_highlights(text, schema)
        section = changelog.get(r.version) or {}
        heading = section.get("heading")
        url = f"{web}/blob/{target.tag}/CHANGELOG.md" + (f"#{changelog_anchor(heading)}" if heading else "")
        rows: List[dict] = (doc or {}).get("highlights") or []
        notes.append({
            "tag": r.tag,
            "version": r.version,
            "date": (doc or {}).get("date") or section.get("date"),
            "has_highlights": doc is not None,
            "highlights": sorted(
                (h for h in rows if h["tag"] != "breaking"), key=lambda h: HIGHLIGHT_TAGS.index(h["tag"])
            ),
            "breaking": [h for h in rows if h["tag"] == "breaking"],
            "changelog_breaking": [entry_title(e) for e in section.get("sections", {}).get("Breaking", [])],
            "changelog_url": url,
        })
    return notes


# --------------------------------------------------------------------------- #
# The user's manifests
# --------------------------------------------------------------------------- #

def user_manifests(root: Path) -> List[dict]:
    """Each discovered manifest with the fetchers it uses and how it validates
    on the version running now, so the check can tell "this update breaks it"
    from "it was already broken"."""
    from framework import api

    out = []
    fetchers: Optional[dict] = None
    platforms: Optional[dict] = None
    try:
        fetchers = api.discover_fetchers(root)
        platforms = api.discover_platforms(root)
    except Exception:  # noqa: BLE001 (a broken tree still gets an update)
        pass
    for summary in api.list_manifests(root):
        path = Path(summary["path"])
        uses: List[str] = []
        errors: List[str] = []
        try:
            m = api.read_manifest(path)
            uses = sorted({e.get("use") for e in (m.get("run") or {}).get("fetchers") or [] if e.get("use")})
            errors = api.validate(m, root, fetchers, platforms) if fetchers is not None else []
        except Exception as e:  # noqa: BLE001
            errors = [str(e)]
        out.append({"path": str(path), "label": _label(path, root), "uses": uses, "errors_now": errors})
    return out


def _label(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def match_fetchers(patterns: Sequence[str], names: Sequence[str]) -> List[str]:
    return sorted({n for n in names for p in patterns if fnmatch.fnmatchcase(n, p)})


def pair_breaking(notes: Sequence[dict], manifests: Sequence[dict]) -> List[dict]:
    """Every breaking change crossed, with the manifests it touches.

    Uses the highlights' breaking rows when the release has them, else the
    CHANGELOG's Breaking titles, which have no fix line but are still the truth.
    """
    out = []
    for n in notes:
        if n["breaking"]:
            for b in n["breaking"]:
                hit = [
                    {"manifest": m["label"], "fetchers": match_fetchers(b["fetchers"], m["uses"])}
                    for m in manifests if b.get("fetchers") and match_fetchers(b["fetchers"], m["uses"])
                ]
                out.append({"release": n["version"], "title": b["title"], "fix": b["fix"],
                            "source": "highlights", "scoped": bool(b.get("fetchers")), "manifests": hit})
        else:
            for title in n["changelog_breaking"]:
                out.append({"release": n["version"], "title": title, "fix": None,
                            "source": "changelog", "scoped": False, "manifests": []})
    return out


# --------------------------------------------------------------------------- #
# Working tree
# --------------------------------------------------------------------------- #

def worktree_status(root: Path) -> dict:
    """Tracked changes (which block a switch) and untracked paths (which ride
    along: a checkout leaves files git doesn't track where they are)."""
    out = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=normal")
    tracked, untracked = [], []
    parts = out.split("\0")
    i = 0
    while i < len(parts):
        item = parts[i]
        i += 1
        if len(item) < 4:
            continue
        code, path = item[:2], item[3:]
        if code == "??":
            untracked.append(path)
        else:
            tracked.append(path)
            if code[0] in "RC":
                i += 1  # a rename's second NUL field is the old path
    return {"tracked": tracked, "untracked": untracked}


# --------------------------------------------------------------------------- #
# The pre-switch check
# --------------------------------------------------------------------------- #

@contextmanager
def temp_worktree(root: Path, ref: str) -> Iterator[Path]:
    """Check `ref` out in a throwaway worktree and remove it on the way out,
    whether the body succeeded, raised or was interrupted."""
    holder = Path(tempfile.mkdtemp(prefix="paramify-update-"))
    tree = holder / "tree"
    try:
        git(root, "worktree", "add", "--detach", "--quiet", str(tree), ref, timeout=300)
        yield tree
    finally:
        removed = False
        try:
            git(root, "worktree", "remove", "--force", str(tree), timeout=60)
            removed = True
        except UpdateError:
            pass
        shutil.rmtree(holder, ignore_errors=True)
        if not removed:
            # The directory is gone now, so prune drops its admin entry. Only on
            # this path: prune touches every worktree of the repo, not just ours.
            try:
                git(root, "worktree", "prune", timeout=30)
            except UpdateError:
                pass


def _mirror_local_fetchers(root: Path, tree: Path) -> List[str]:
    """Link the user's own fetcher dirs into the temp tree.

    Custom fetchers are untracked (or ignored), so a real switch keeps them,
    but a fresh worktree doesn't have them. Without this, every manifest that
    uses one would be reported as "unknown fetcher" and look broken.
    """
    try:
        out = git(root, "ls-files", "--others", "--directory", "-z", "--", "fetchers/")
    except UpdateError:
        return []
    linked = []
    for rel in filter(None, out.split("\0")):
        rel = rel.rstrip("/")
        if "__pycache__" in rel or rel.endswith((".pyc", ".DS_Store")):
            continue
        src, dst = root / rel, tree / rel
        if dst.exists() or not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            dst.symlink_to(src.resolve(), target_is_directory=src.is_dir())
            linked.append(rel)
        except OSError:
            pass
    return linked


_VALIDATE_SHIM = "import sys; sys.argv[0] = 'paramify'; from framework.cli import app; app()"


def run_validate(tree: Path, manifest: str, python: str = sys.executable) -> dict:
    """Run `paramify validate --json` from the code in `tree`.

    Run as `python -c` with `tree` first on sys.path, so it is the tree's own
    validator, not the one this process imported. Returns {ok, errors, notes}
    or {ok: None, reason} when the command could not run at all.
    """
    env = dict(os.environ, PYTHONPATH=str(tree), NO_COLOR="1", PYTHON_DOTENV_DISABLED="1")
    env.pop("FORCE_COLOR", None)
    try:
        proc = subprocess.run(
            [python, "-c", _VALIDATE_SHIM, "validate", manifest, "--json"],
            cwd=tree, capture_output=True, text=True, timeout=180, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": None, "errors": [], "notes": [], "reason": str(e)}
    try:
        doc = json.loads(proc.stdout)
        return {"ok": bool(doc.get("ok")), "errors": doc.get("errors") or [], "notes": doc.get("notes") or []}
    except (json.JSONDecodeError, AttributeError):
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        missing = re.search(r"No module named '([^']+)'", proc.stderr or "")
        reason = (
            f"needs the {missing[1]} package, which the reinstall step installs" if missing
            else (tail[-1] if tail else f"validate exited {proc.returncode}")
        )
        return {"ok": None, "errors": [], "notes": [], "reason": reason}


def _python_supported(tree: Path) -> Optional[str]:
    """The target's requires-python if this interpreter doesn't meet it."""
    import tomllib

    try:
        spec = tomllib.loads((tree / "pyproject.toml").read_text())["project"]["requires-python"]
        ok = SpecifierSet(spec).contains(".".join(map(str, sys.version_info[:3])))
    except (OSError, KeyError, tomllib.TOMLDecodeError, InvalidSpecifier):
        return None
    return None if ok else spec


def _fetcher_dirs(base: Path) -> Dict[str, str]:
    """{fetcher dir relative to the repo: fetcher name} for one tree."""
    out = {}
    for f in (base / "fetchers").rglob("fetcher.yaml"):
        rel = f.parent.relative_to(base).as_posix()
        if any(part.startswith("_") for part in rel.split("/")[1:]):
            continue  # _template*, _lib: scaffolding, not fetchers anyone runs
        try:
            name = (yaml.safe_load(f.read_text()) or {}).get("name")
        except (OSError, yaml.YAMLError):
            name = None
        out[rel] = name or f.parent.name
    return out


def fetcher_changes(root: Path, tree: Path, target: Release, manifests: Sequence[dict]) -> dict:
    """Which fetchers differ between HEAD and the target, split by whether
    the user's manifests use them."""
    before, after = _fetcher_dirs(root), _fetcher_dirs(tree)
    try:
        changed_paths = git(root, "diff", "--name-only", "HEAD", target.tag, "--", "fetchers/").splitlines()
    except UpdateError:
        changed_paths = []
    dirs = sorted(set(before) | set(after), key=len, reverse=True)
    changed: set = set()
    for p in changed_paths:
        for d in dirs:
            if p.startswith(d + "/"):
                changed.add(d)
                break
    used = {u: [m["label"] for m in manifests if u in m["uses"]] for m in manifests for u in m["uses"]}
    yours, others, added, removed = [], [], [], []
    for d in sorted(changed):
        name = after.get(d) or before.get(d)
        state = "added" if d not in before else "removed" if d not in after else "changed"
        if name in used:
            yours.append({"name": name, "change": state, "manifests": used[name]})
        elif state == "added":
            added.append(name)
        elif state == "removed":
            removed.append(name)
        else:
            others.append(name)
    return {"yours": yours, "others": sorted(others), "added": sorted(added), "removed": sorted(removed)}


def check_target(root: Path, target: Release, manifests: Sequence[dict], python: str = sys.executable) -> dict:
    """Validate every manifest with the target's own code, before switching.

    A manifest that validates today and fails on the target `breaks`; one that
    fails on both is `still_failing`, so the update isn't blamed for it.
    """
    results = []
    with temp_worktree(root, target.tag) as tree:
        linked = _mirror_local_fetchers(root, tree)
        too_old = _python_supported(tree)
        for m in manifests:
            res = run_validate(tree, m["path"], python)
            if res["ok"] is None:
                status = "unchecked"
            elif res["ok"]:
                status = "fixed" if m["errors_now"] else "ok"
            else:
                status = "still_failing" if m["errors_now"] else "breaks"
            results.append({"manifest": m["label"], "path": m["path"], "status": status,
                            "errors": res["errors"], "reason": res.get("reason")})
        changes = fetcher_changes(root, tree, target, manifests)
    return {
        "ok": not too_old and not any(r["status"] == "breaks" for r in results),
        "python_required": too_old,
        "python": ".".join(map(str, sys.version_info[:3])),
        "manifests": results,
        "linked_local_fetchers": linked,
        "fetchers": changes,
    }


# --------------------------------------------------------------------------- #
# Switch, reinstall, validate
# --------------------------------------------------------------------------- #

def switch(root: Path, ref: str, *, branch: bool = False) -> None:
    if branch:
        git(root, "switch", "--quiet", ref)
    else:
        git(root, "switch", "--quiet", "--detach", ref)


def detect_extras() -> Optional[List[str]]:
    """The extras this environment was installed with, as far as we can tell.

    pip doesn't record which extras were asked for, so an extra counts as
    installed when every package it pulls in is. Extras another kept extra
    already covers are dropped (`all` covers `tui`), so the command stays
    readable. None means paramify-fetchers isn't installed in this Python.
    """
    try:
        dist = metadata.distribution(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return None
    by_extra: Dict[str, set] = {}
    for raw in dist.requires or []:
        req = Requirement(raw)
        m = re.search(r"""extra\s*==\s*['"]([^'"]+)['"]""", str(req.marker or ""))
        if m:
            by_extra.setdefault(m[1], set()).add(canonicalize_name(req.name))
    installed = {canonicalize_name(d.metadata["Name"]) for d in metadata.distributions() if d.metadata["Name"]}
    present = sorted((e for e, names in by_extra.items() if names <= installed), key=lambda e: -len(by_extra[e]))
    kept: List[str] = []
    covered: set = set()
    for e in present:
        if not by_extra[e] <= covered:
            kept.append(e)
            covered |= by_extra[e]
    return sorted(kept)


def install_command(root: Path, extras: Optional[List[str]], python: str = sys.executable) -> List[str]:
    """`pip install -e` for the same interpreter that is running.

    A uv-made venv has no pip, so fall back to `uv pip --python` there. With no
    way to tell the extras, install `all`, which the versioning guide uses.
    """
    chosen = ["all"] if extras is None else extras
    spec = f"{root}[{','.join(chosen)}]" if chosen else str(root)
    if importlib.util.find_spec("pip") is None and shutil.which("uv"):
        return ["uv", "pip", "install", "--quiet", "--python", python, "-e", spec]
    return [python, "-m", "pip", "install", "--quiet", "-e", spec]


def environment() -> dict:
    """The interpreter the reinstall targets, for the plan and the step line."""
    venv = sys.prefix != sys.base_prefix
    return {
        "python": sys.executable,
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "venv": sys.prefix if venv else None,
    }


def reinstall(root: Path, extras: Optional[List[str]], python: str = sys.executable) -> dict:
    cmd = install_command(root, extras, python)
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "command": cmd, "error": str(e)}
    tail = (proc.stderr or proc.stdout).strip().splitlines()[-8:]
    return {"ok": proc.returncode == 0, "command": cmd, "error": "\n".join(tail) if proc.returncode else None}


def validate_all(root: Path, manifests: Sequence[dict], python: str = sys.executable) -> dict:
    """Validate each manifest with the code now checked out in `root`."""
    rows = []
    for m in manifests:
        res = run_validate(root, m["path"], python)
        rows.append({"manifest": m["label"], "ok": res["ok"], "errors": res["errors"], "reason": res.get("reason")})
    return {"ok": all(r["ok"] is not False for r in rows), "manifests": rows}


# --------------------------------------------------------------------------- #
# State: the version to roll back to, and the update-check cache
# --------------------------------------------------------------------------- #

def state_path(root: Path) -> Path:
    return Path(root) / STATE_FILE


def read_state(root: Path) -> dict:
    try:
        doc = json.loads(state_path(root).read_text())
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(root: Path, state: dict) -> None:
    """Write atomically. .paramify/ is gitignored, so this survives every
    checkout the update makes."""
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, p)


def remember_previous(root: Path, pos: dict) -> None:
    state = read_state(root)
    state["previous"] = {
        "ref": pos["branch"] or pos["sha"],
        "branch": pos["branch"],
        "sha": pos["sha"],
        "tag": pos["tag"] if pos["exact"] else None,
        "describe": describe(pos),
        "at": int(time.time()),
    }
    write_state(root, state)


def forget_previous(root: Path) -> None:
    state = read_state(root)
    state.pop("previous", None)
    write_state(root, state)


def describe(pos: dict) -> str:
    """How to name a position to a person: 0.6.0-beta, or main @ fa7444b."""
    if pos.get("exact") and pos.get("version"):
        return pos["version"]
    return f"{pos.get('branch') or 'detached'} @ {pos.get('short') or pos.get('sha', '')[:7]}"


# --------------------------------------------------------------------------- #
# The update-available check (shared with the TUI)
# --------------------------------------------------------------------------- #

def _background_fetch(root: Path) -> None:
    """Start `git fetch --tags` and don't wait for it. The tags it brings in are
    compared on the next check, so a slow or absent network never delays the
    command the user actually ran."""
    subprocess.Popen(
        ["git", "fetch", "--tags", "--quiet"], cwd=root, env=_git_env(),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def check_for_update(root: Path, *, now: Optional[float] = None, fetch: bool = True) -> Optional[dict]:
    """Is a newer release tag than the one you run available?

    Fetches tags from origin at most once a day (the time is kept in
    .paramify/state.json) and compares local tags, so it costs two quick git
    calls and never waits on the network. Returns None, quietly, when
    PARAMIFY_NO_UPDATE_CHECK is set, when there is no git clone (the deploy
    image), or when anything goes wrong.
    """
    if os.environ.get(NO_CHECK_ENV, "").strip() not in ("", "0") or is_container(root):
        return None
    now = time.time() if now is None else now
    try:
        state = read_state(root)
        cache = state.get("update_check") or {}
        last_fetch = cache.get("fetched_at")
        if fetch and (last_fetch is None or now - float(last_fetch) >= CHECK_INTERVAL):
            try:
                _background_fetch(root)
            except OSError:
                pass
            cache["fetched_at"] = now
        releases = list_releases(root)
        pos = position(root)
        latest = releases[-1] if releases else None
        base = parse_release(pos["tag"] or "")
        available = bool(latest and (base is None or latest.key > base.key))
        cache.update(latest=latest.tag if latest else None, checked_at=now)
        state["update_check"] = cache
        write_state(root, state)
        return {
            "current": describe(pos),
            "current_tag": pos["tag"],
            "latest": latest.version if latest else None,
            "latest_tag": latest.tag if latest else None,
            "update_available": available,
            "on_release": bool(pos["exact"]),
        }
    except Exception:  # noqa: BLE001 (a notice must never break a command)
        return None


def notice_due(root: Path, now: Optional[float] = None) -> bool:
    """True when the CLI hasn't considered the notice in the last day."""
    now = time.time() if now is None else now
    last = (read_state(root).get("update_notice") or {}).get("considered_at")
    return last is None or now - float(last) >= CHECK_INTERVAL


def mark_notice(root: Path, now: Optional[float] = None) -> None:
    state = read_state(root)
    state["update_notice"] = {"considered_at": time.time() if now is None else now}
    write_state(root, state)
