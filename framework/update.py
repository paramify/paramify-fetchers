"""`paramify update`: bring a clone up to date, safely.

A clone follows whatever it is on. A branch (normally main) is fast-forwarded
to the remote branch it tracks; a clone sitting on a release tag moves to the
newest release. `--to` switches between the two. Either way the steps are the
same: say what changes for this clone, check the user's manifests against the
target before touching the checkout, then move, reinstall if needed, validate.

Everything here returns JSON-able dicts. The CLI renders them (framework/
update_view.py) or prints them under --json; nothing in this module writes to
the terminal.

Three rules shape the code:

* Update fast-forwards or refuses. It never merges, and it never moves a clone
  to older code unless the user named that target.
* Nothing changes the user's checkout until they confirm. The pre-check runs
  the target's own `paramify validate` in a throwaway `git worktree`, which is
  removed whatever happens.
* Every git and pip call is a subprocess, and on some laptops each one costs
  real time, so the code batches reads (one `git cat-file --batch` for the
  files it needs from a commit, one `git log` for every fetcher's history).
"""

from __future__ import annotations

import datetime
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
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

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
MAIN = "main"
REMOTE = "origin"  # where updates come from: fetched, followed by --to main, linked for the changelog
HIGHLIGHTS_DIR = "releases"
UNRELEASED = "unreleased"
STATE_FILE = Path(".paramify") / "state.json"
NO_CHECK_ENV = "PARAMIFY_NO_UPDATE_CHECK"
CONTAINER_ENV = "PARAMIFY_CONTAINER"
CHECK_INTERVAL = 24 * 60 * 60
PUBLIC_REPO = "https://github.com/paramify/paramify-fetchers"
COMPOSE_FILE = Path("deploy") / "docker-compose.yml"
COMPOSE_BUILD = f"docker compose -f {COMPOSE_FILE.as_posix()} build"


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


FETCH_ARGS = ("fetch", "--tags", "--quiet", REMOTE)


def fetch(root: Path) -> None:
    """Bring in the remote's branches and release tags."""
    git(root, *FETCH_ARGS, timeout=90)


def current_branch(root: Path) -> Optional[str]:
    try:
        return git(root, "symbolic-ref", "-q", "--short", "HEAD").strip() or None
    except UpdateError:
        return None


def position(root: Path) -> dict:
    """Where the checkout is: the branch and the remote branch it follows (with
    how far apart they are), and the nearest release tag behind HEAD."""
    sha = git(root, "rev-parse", "HEAD").strip()
    branch = current_branch(root)
    tag, ahead = None, None
    try:
        described = git(root, "describe", "--tags", "--long", "--match", "v[0-9]*").strip()
        tag, n, _ = described.rsplit("-", 2)
        ahead = int(n)
    except (UpdateError, ValueError):
        pass
    rel = parse_release(tag) if tag else None
    upstream, behind = None, None
    if branch:
        try:
            upstream = git(root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}").strip() or None
            behind = int(git(root, "rev-list", "--count", "HEAD..@{upstream}").strip())
        except (UpdateError, ValueError):
            upstream = None
    return {
        "upstream": upstream,
        "behind": behind,
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


def container_advice() -> dict:
    """What to tell someone who runs `update` where it can't work."""
    return {
        "ok": False,
        "container": True,
        "errors": ["no git clone here: update the clone on the host, then rebuild the image"],
        "commands": ["paramify update", COMPOSE_BUILD],
        "version": installed_version(),
    }


def built_image(root: Path) -> bool:
    """Has this machine built the deploy image? Only then is "rebuild the image"
    worth saying after an update. The image name comes from the compose file;
    no docker, no compose file, a daemon that is not running or slow to answer
    all mean no."""
    compose = Path(root) / COMPOSE_FILE
    docker = shutil.which("docker")
    if not docker or not compose.is_file():
        return False
    try:
        services = (yaml.safe_load(compose.read_text()) or {}).get("services") or {}
    except (OSError, yaml.YAMLError):
        return False
    for svc in services.values():
        image = svc.get("image") if isinstance(svc, dict) else None
        if not isinstance(image, str):
            continue
        try:
            found = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        if found.returncode == 0:
            return True
    return False


def installed_version() -> Optional[str]:
    try:
        return metadata.version(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return None


@dataclass(frozen=True)
class Target:
    """Where an update moves the clone: a branch's upstream, or a release tag."""

    channel: str            # "branch" or "release"
    ref: str                # what git moves to: origin/main, or v0.7.0-beta
    sha: str
    label: str              # how to name it to a person: main, or 0.7.0-beta
    branch: Optional[str]   # the local branch to fast-forward; None for a release

    def to_json(self) -> dict:
        return {"channel": self.channel, "ref": self.ref, "sha": self.sha, "label": self.label,
                "branch": self.branch}


def _sha(root: Path, ref: str) -> str:
    return git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").strip()


def _release_target(root: Path, rel: Release) -> Target:
    return Target("release", rel.tag, _sha(root, rel.tag), rel.version, None)


def _refuse_own_commits(root: Path, branch: str, upstream: str, then: str) -> None:
    """Update fast-forwards, it never merges: a local branch with commits its
    upstream lacks is refused. A branch that doesn't exist yet has none (update
    creates it)."""
    try:
        mine = int(git(root, "rev-list", "--count", f"{upstream}..refs/heads/{branch}").strip())
    except (UpdateError, ValueError):
        return
    if mine:
        raise UpdateError(
            f"{branch} has {mine} commit{'s' if mine != 1 else ''} that {upstream} does not, so update "
            f"can't fast-forward it. {then}"
        )


def is_current(target: "Target", pos: dict) -> bool:
    """Nothing to do: the clone is at the target, on the target's branch."""
    return target.sha == pos["sha"] and target.branch == pos["branch"]


def choose_target(root: Path, pos: dict, releases: Sequence[Release], to: Optional[str] = None) -> Target:
    """The commit to move to, from --to or from what the clone is on.

    A branch follows the remote branch it tracks; a clone sitting on a release
    tag follows newer tags. Anything else is refused with what to run instead,
    and so is a branch with commits of its own: update fast-forwards, it never
    merges. The caller decides "nothing to do" by comparing sha with HEAD's.
    """
    if to == MAIN:
        upstream = f"{REMOTE}/{MAIN}"
        try:
            target = Target("branch", upstream, _sha(root, upstream), MAIN, MAIN)
        except UpdateError:
            raise UpdateError(f"{REMOTE} has no {MAIN} branch to follow") from None
        _refuse_own_commits(root, MAIN, upstream, "Push or move them first")
        return target
    if to:
        want = to if to.startswith("v") else f"v{to}"
        rel = next((r for r in releases if r.tag == want), None)
        if rel is None:
            names = ", ".join(r.tag for r in releases[-6:]) or "none"
            raise UpdateError(f"{to} is not {MAIN} or a release tag (recent releases: {names})")
        if read_at(root, rel.tag, ["framework/update.py"])["framework/update.py"] is None:
            raise UpdateError(
                f"{rel.tag} was released before paramify update existed, so you could not update or "
                f"roll back from it. To use it anyway: git switch --detach {rel.tag}"
            )
        return _release_target(root, rel)
    hint = f"Run paramify update --to {MAIN}, or --to <tag> to pin a release"
    branch, upstream = pos["branch"], pos["upstream"]
    if branch and upstream:
        _refuse_own_commits(root, branch, upstream, "Push or move them, or pin with --to <tag>")
        return Target("branch", upstream, _sha(root, upstream), branch, branch)
    if branch:
        raise UpdateError(f"{branch} does not follow a remote branch. {hint}")
    if pos["exact"] and releases and parse_release(pos["tag"] or ""):
        return _release_target(root, releases[-1])
    raise UpdateError(f"this clone is on a detached commit ({pos['short']}), not a branch or a release. {hint}")


# --------------------------------------------------------------------------- #
# Curated rows
# --------------------------------------------------------------------------- #

def repo_web_url(root: Path) -> str:
    """The GitHub page of the remote, for changelog links; the public repo when
    it isn't on GitHub (a private mirror elsewhere still has the same tags)."""
    try:
        url = git(root, "remote", "get-url", REMOTE, timeout=10).strip()
    except UpdateError:
        return PUBLIC_REPO
    m = re.match(r"^(?:https://github\.com/|git@[^:]*github[^:]*:|ssh://git@github\.com/)(.+?)(?:\.git)?/?$", url)
    return f"https://github.com/{m[1]}" if m else PUBLIC_REPO


def changelog_url(root: Path, target: "Target") -> str:
    """The CHANGELOG as it is at the target, on GitHub."""
    at = target.ref if target.channel == "release" else target.sha[:10]
    return f"{repo_web_url(root)}/blob/{at}/CHANGELOG.md"


def _day(value: Any) -> Optional[str]:
    """A release-file date as YYYY-MM-DD, or None for anything else."""
    if isinstance(value, datetime.datetime):
        return None
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return value
    return None


def release_files(root: Path, ref: str) -> Dict[str, dict]:
    """{version: {"date", "highlights", "fetchers"}} for every readable
    releases/*.yaml at `ref`.

    Read loosely on purpose: a highlight row needs only a tag and a title, a
    fetcher line only a name, version and note (all strings). The schema is
    enforced where the files are written (tests/test_release_highlights.py),
    not here, because a newer release may add a field this code doesn't know,
    and dropping its file would hide its breaking rows from an older clone. A
    missing directory or a file that isn't YAML contributes nothing.
    """
    try:
        listing = git(root, "ls-tree", "--name-only", ref, f"{HIGHLIGHTS_DIR}/").splitlines()
    except UpdateError:
        return {}
    out: Dict[str, dict] = {}
    for path, text in read_at(root, ref, [p for p in listing if p.endswith(".yaml")]).items():
        try:
            doc = yaml.safe_load(text or "")
        except yaml.YAMLError:
            continue
        rows = doc.get("highlights") if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            continue
        lines = doc.get("fetchers")
        date = doc.get("date")
        out[Path(path).stem] = {
            "date": _day(date),
            "highlights": [h for h in rows if isinstance(h, dict)
                           and isinstance(h.get("tag"), str) and isinstance(h.get("title"), str)],
            "fetchers": [f for f in lines if isinstance(f, dict)
                         and all(isinstance(f.get(k), str) for k in ("name", "version", "note"))]
            if isinstance(lines, list) else [],
        }
    return out


def _highlight_files(root: Path, ref: str) -> Dict[str, List[dict]]:
    """{version: rows}: the highlight rows of `release_files`."""
    return {v: d["highlights"] for v, d in release_files(root, ref).items()}


def _contained_tags(root: Path, ref: str) -> set:
    try:
        return set(git(root, "tag", "--merged", ref, "-l", "v*").split())
    except UpdateError:
        return set()


def fetcher_notes(root: Path, head: str, target: str) -> Dict[str, List[dict]]:
    """{fetcher: [{release, version, note}]} for the releases `target` has and
    `head` doesn't, newest release first. Unreleased files are never read: a
    note is only shown once its release is cut."""
    contained = _contained_tags(root, head)
    files = release_files(root, target)
    crossed = [r for r in (parse_release(f"v{v}") for v in files if v != UNRELEASED) if r and r.tag not in contained]
    out: Dict[str, List[dict]] = {}
    for r in sorted(crossed, key=lambda r: r.key, reverse=True):
        for line in files[r.version]["fetchers"]:
            out.setdefault(line["name"], []).append(
                {"release": r.version, "version": line["version"], "note": line["note"]})
    return out


def crossed_releases(root: Path, head: str, target: str) -> List[dict]:
    """[{version, date}] for the release tags in `target` and not in `head`,
    newest first. The date is the release file's, else the CHANGELOG heading's
    at `target`, else None."""
    found = (parse_release(t) for t in _contained_tags(root, target) - _contained_tags(root, head))
    crossed = sorted((r for r in found if r), key=lambda r: r.key, reverse=True)
    if not crossed:
        return []
    files = release_files(root, target)
    changelog = read_at(root, target, ["CHANGELOG.md"])["CHANGELOG.md"] or ""
    headings = {m["v"]: m["d"] for m in re.finditer(r"^## \[(?P<v>[^\]]+)\][^\n]*?(?P<d>\d{4}-\d{2}-\d{2})", changelog, re.M)}
    return [{"version": r.version, "date": (files.get(r.version) or {}).get("date") or headings.get(r.version)}
            for r in crossed]


def curated_rows(root: Path, head: str, target: str) -> List[dict]:
    """The highlight rows `target` has and `head` doesn't, each with its `release`.

    Rows are compared by tag and title across every releases/*.yaml, so a row
    that moves from unreleased.yaml into a release's file when that release is
    cut is not shown a second time. A release whose tag `head` already contains
    is skipped whole. Unreleased rows come first, then releases
    newest first; rows keep their order within a file.
    """
    have = {(h["tag"], h["title"]) for rows in _highlight_files(root, head).values() for h in rows}
    files = _highlight_files(root, target)

    contained = _contained_tags(root, head)
    released = [r for r in (parse_release(f"v{v}") for v in files if v != UNRELEASED) if r and r.tag not in contained]
    order = [UNRELEASED] * (UNRELEASED in files) + [r.version for r in sorted(released, key=lambda r: r.key, reverse=True)]
    out: List[dict] = []
    for version in order:
        out.extend({**h, "release": version} for h in files[version] if (h["tag"], h["title"]) not in have)
    return out


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


def blocking_changes(root: Path, target_sha: str) -> dict:
    """Local files that would stop git from moving to the target.

    A changed tracked file blocks only when the update changes it too, and an
    untracked path only when the target tracks a file there. Everything else
    rides along, as git allows.
    """
    status = worktree_status(root)
    tracked: List[str] = []
    if status["tracked"]:
        moving = set(git(root, "diff", "--name-only", "HEAD", target_sha).splitlines())
        tracked = [p for p in status["tracked"] if p in moving]
    untracked: List[str] = []
    if status["untracked"]:
        theirs = git(root, "ls-tree", "-r", "--name-only", target_sha).splitlines()
        for u in status["untracked"]:
            if any(t.startswith(u) for t in theirs) if u.endswith("/") else u in theirs:
                untracked.append(u)
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
    """Link the user's own fetcher dirs (untracked or ignored directories that
    hold a fetcher.yaml) into the temp tree; returns the ones linked.

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
        src, dst = root / rel, tree / rel
        # A stray .env or output/ inside a tracked fetcher is not a fetcher of the user's own.
        if not src.is_dir() or not any(src.rglob("fetcher.yaml")):
            continue
        if dst.exists():
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


def _fetcher_dirs(base: Path) -> Dict[str, Tuple[str, Optional[str]]]:
    """{fetcher dir relative to the repo: (name, version)} for one tree."""
    out = {}
    for f in (base / "fetchers").rglob("fetcher.yaml"):
        rel = f.parent.relative_to(base).as_posix()
        if any(part.startswith("_") for part in rel.split("/")[1:]):
            continue  # _template*, _lib: scaffolding, not fetchers anyone runs
        try:
            doc = yaml.safe_load(f.read_text()) or {}
        except (OSError, yaml.YAMLError):
            doc = {}
        version = doc.get("version") if isinstance(doc, dict) else None
        name = doc.get("name") if isinstance(doc, dict) else None
        out[rel] = (name or f.parent.name, str(version) if version is not None else None)
    return out


def fetcher_reason(name: str, subjects: Sequence[str]) -> Optional[str]:
    """Why a fetcher changed, from the newest commit subject that names it.

    Only `name: ...`, `name 1.2.0: ...` and `fix(name): ...` count. The newest
    commit on a fetcher is often a version bump, a docs pass or a type fix, and
    showing one of those as the reason would be worse than showing none.
    """
    n = re.escape(name)
    pattern = re.compile(rf"^(?:[a-z]+\({n}\)!?:\s*|{n}(?:\s+\d+\.\d+\.\d+)?:\s*)(?P<rest>\S.*)$")
    for subject in subjects:
        m = pattern.match(subject.strip())
        if m:
            return m["rest"].strip()
    return None


def _subjects_by_dir(root: Path, target_ref: str, dirs: Sequence[str]) -> Dict[str, List[str]]:
    """{fetcher dir: commit subjects that touched it in HEAD..target, newest first},
    from one `git log`. Empty when the target is not ahead of HEAD."""
    try:
        git(root, "merge-base", "--is-ancestor", "HEAD", target_ref)
        log = git(root, "log", "--no-merges", "--format=%x00%s", "--name-only", f"HEAD..{target_ref}", "--", "fetchers/")
    except UpdateError:
        return {}
    out: Dict[str, List[str]] = {}
    for chunk in log.split("\0")[1:]:
        subject, _, files = chunk.partition("\n")
        touched = {d for path in files.split() for d in dirs if path.startswith(d + "/")}
        for d in touched:
            out.setdefault(d, []).append(subject)
    return out


def fetcher_changes(root: Path, tree: Path, target_ref: str, manifests: Sequence[dict]) -> dict:
    """Which fetchers differ between HEAD and the target, split by whether the
    user's manifests use them. Theirs carry the version on each side and, when
    a commit names the fetcher, why it changed."""
    before, after = _fetcher_dirs(root), _fetcher_dirs(tree)
    try:
        changed_paths = git(root, "diff", "--name-only", "HEAD", target_ref, "--", "fetchers/").splitlines()
    except UpdateError:
        changed_paths = []
    dirs = sorted(set(before) | set(after), key=len, reverse=True)
    changed: set = set()
    for p in changed_paths:
        for d in dirs:
            if p.startswith(d + "/"):
                changed.add(d)
                break
    used: Dict[str, List[str]] = {}
    for m in manifests:
        for u in m["uses"]:
            used.setdefault(u, []).append(m["label"])
    subjects = _subjects_by_dir(root, target_ref, sorted(changed)) if changed else {}
    yours, others, added, removed = [], [], [], []
    for d in sorted(changed):
        name = (after.get(d) or before[d])[0]
        state = "added" if d not in before else "removed" if d not in after else "changed"
        if name in used:
            log = subjects.get(d, [])
            reason = fetcher_reason(name, log)
            yours.append({
                "name": name, "change": state, "manifests": used[name],
                "from": before[d][1] if d in before else None, "to": after[d][1] if d in after else None,
                "reason": reason, "more": len(log) - (1 if reason else 0),
            })
        elif state == "added":
            added.append(name)
        elif state == "removed":
            removed.append(name)
        else:
            others.append(name)
    return {"yours": yours, "others": sorted(others), "added": sorted(added), "removed": sorted(removed)}


def span(root: Path, head: str, target_ref: str) -> dict:
    """How far the target is ahead: commits, and whole days between the two
    commit dates, and how many release tags it adds. Zeros when the target is
    not ahead."""
    try:
        commits = int(git(root, "rev-list", "--count", f"{head}..{target_ref}").strip())
        if not commits:
            return {"commits": 0, "days": 0, "releases": 0}
        old, new = (int(git(root, "log", "-1", "--format=%ct", r).strip()) for r in (head, target_ref))
        tags = set(git(root, "tag", "--merged", target_ref, "-l", "v*").split())
        tags -= set(git(root, "tag", "--merged", head, "-l", "v*").split())
    except (UpdateError, ValueError):
        return {"commits": 0, "days": 0, "releases": 0}
    return {"commits": commits, "days": max(0, (new - old) // 86400),
            "releases": sum(parse_release(t) is not None for t in tags)}


def breaking_for(rows: Sequence[dict], manifests: Sequence[dict], has_local_fetchers: bool) -> List[dict]:
    """Every breaking row crossed, with whether and why it touches this clone.

    A row that lists fetchers touches clones whose manifests use one ("fetchers").
    A row marked custom_fetchers touches clones with fetchers of their own
    ("custom"). A row with neither is about everyone (a Python version, a CLI flag).
    """
    out = []
    for row in rows:
        if row.get("tag") != "breaking":
            continue
        named = []
        if row.get("fetchers"):
            named = [{"manifest": m["label"], "fetchers": hit} for m in manifests
                     if (hit := match_fetchers(row["fetchers"], m["uses"]))]
            why = "fetchers" if named else None
        elif row.get("custom_fetchers"):
            why = "custom" if has_local_fetchers else None
        else:
            why = "everyone"
        out.append({"title": row["title"], "fix": row.get("fix"), "release": row.get("release"),
                    "touches": why is not None, "why": why, "manifests": named})
    return out


def classify(ok: Optional[bool], manifest: dict) -> str:
    """A validate result against how the manifest validated before the update:
    `breaks` (passed, now fails), `still_failing` (failed before too, so not the
    update's fault), `fixed`, `ok`, or `unchecked` (validate could not run)."""
    if ok is None:
        return "unchecked"
    if ok:
        return "fixed" if manifest["errors_now"] else "ok"
    return "still_failing" if manifest["errors_now"] else "breaks"


def check_target(root: Path, target: Target, manifests: Sequence[dict], python: str = sys.executable) -> dict:
    """Validate every manifest with the target's own code, before moving.

    A manifest that validates today and fails on the target `breaks`; one that
    fails on both is `still_failing`, so the update isn't blamed for it.
    """
    results = []
    with temp_worktree(root, target.sha) as tree:
        linked = _mirror_local_fetchers(root, tree)
        too_old = _python_supported(tree)
        for m in manifests:
            res = run_validate(tree, m["path"], python)
            results.append({"manifest": m["label"], "path": m["path"], "status": classify(res["ok"], m),
                            "errors": res["errors"], "reason": res.get("reason")})
        changes = fetcher_changes(root, tree, target.sha, manifests)
    return {
        "ok": not too_old and not any(r["status"] == "breaks" for r in results),
        "python_required": too_old,
        "python": ".".join(map(str, sys.version_info[:3])),
        "manifests": results,
        "linked_local_fetchers": linked,
        "has_local_fetchers": bool(linked),
        "fetchers": changes,
    }


# --------------------------------------------------------------------------- #
# The plan: what an update would do, for the CLI to draw and the TUI to show
# --------------------------------------------------------------------------- #

MAX_NEW = 10  # non-breaking highlights a plan carries; the rest are counted


def try_fetch(root: Path) -> Tuple[bool, Optional[str]]:
    """(fetched, why not). Offline is not an error: the plan then compares
    against what the clone last fetched."""
    try:
        fetch(root)
        return True, None
    except UpdateError as e:
        return False, str(e)


def locate(root: Path, to: Optional[str] = None, *, fetched: bool = True) -> dict:
    """The quick half of a plan: where the clone is, where it would go, and
    what is in the way. Raises UpdateError when update refuses outright (a
    branch with commits of its own, a detached commit, an unknown --to).

    {current, target, channel, fetched, up_to_date, state} and, unless up to
    date, {blocking, manifests, rows, span, direction}. `state` is up_to_date,
    blocked (local files are in the way; nothing more is worked out) or ready. `manifests` are full records
    (path, label, uses, errors_now); the JSON names them by label.
    """
    pos = position(root)
    target = choose_target(root, pos, list_releases(root), to=to)
    doc: Dict[str, Any] = {
        "current": {**pos, "label": describe(pos)}, "target": target.to_json(), "channel": target.channel,
        "fetched": fetched, "up_to_date": is_current(target, pos),
    }
    if doc["up_to_date"]:
        doc["state"] = "up_to_date"
        return doc
    spanned = span(root, "HEAD", target.sha)
    doc.update(
        blocking=blocking_changes(root, target.sha),
        manifests=user_manifests(root),
        rows=curated_rows(root, "HEAD", target.sha),
        span=spanned,
        # Same commit, another branch (a detached clone moving onto main) is still forward.
        direction="forward" if spanned["commits"] or target.sha == pos["sha"] else "back",
    )
    blocked = doc["blocking"]["tracked"] or doc["blocking"]["untracked"]
    doc["state"] = "blocked" if blocked else "ready"
    return doc


def assess(root: Path, located: dict, python: str = sys.executable) -> dict:
    """The slow half: check the manifests on the target's own code, then say
    which breaking changes touch this clone, what is new, and what would stop
    an unattended run (`stops`), as `state` (ready, or unrunnable when the
    Python is too old) and `needs_allow_breaking`. Returns `located` with
    those added."""
    target = Target(**located["target"])
    manifests = located["manifests"]
    check = check_target(root, target, manifests, python)
    notes = fetcher_notes(root, "HEAD", target.sha)
    for row in check["fetchers"]["yours"]:
        row["notes"] = notes.get(row["name"], [])
    rows = located["rows"]
    breaking = breaking_for(rows, manifests, check["has_local_fetchers"])
    new = [r for r in rows if r["tag"] != "breaking"]
    stops = {
        "breaks": [m["manifest"] for m in check["manifests"] if m["status"] == "breaks"],
        "touching": [b["title"] for b in breaking if b["touches"]],
        "python_required": check["python_required"],
    }
    return {
        **located,
        "check": check,
        "fetchers": check["fetchers"],
        "breaking": breaking,
        "releases": crossed_releases(root, "HEAD", target.sha),
        "highlights": new[:MAX_NEW],
        "hidden_highlights": max(0, len(new) - MAX_NEW),
        "tries": [h["try"] for h in new if h.get("try")],
        "used": len({u for m in manifests for u in m["uses"]}),
        "changelog": changelog_url(root, target),
        "stops": stops,
        # Python too old for the target: shown, never applied. Breaking changes that touch this
        # clone, or manifests that would break: asked twice, or --allow-breaking when unattended.
        "state": "unrunnable" if stops["python_required"] else "ready",
        "needs_allow_breaking": bool(stops["breaks"] or stops["touching"]),
    }


def plan(root: Path, to: Optional[str] = None) -> dict:
    """The whole plan in one call, for a front-end that draws it afterwards:
    fetch, locate, assess. Raises UpdateError when update refuses."""
    fetched, _ = try_fetch(root)
    located = locate(root, to, fetched=fetched)
    return assess(root, located) if located["state"] == "ready" else located


def public(doc: dict) -> dict:
    """A plan as JSON shows it: manifests by label, without the raw rows."""
    out = {k: v for k, v in doc.items() if k != "rows"}
    if "manifests" in out:
        out["manifests"] = [m["label"] for m in out["manifests"]]
    return out


# --------------------------------------------------------------------------- #
# Switch, reinstall, validate
# --------------------------------------------------------------------------- #

def move(root: Path, target: Target) -> None:
    """Fast-forward the branch to its upstream, or detach at the release tag."""
    if target.branch is None:
        git(root, "switch", "--quiet", "--detach", target.ref)
        return
    if current_branch(root) != target.branch:
        try:
            git(root, "rev-parse", "--verify", "--quiet", f"refs/heads/{target.branch}")
            git(root, "switch", "--quiet", target.branch)
        except UpdateError:
            git(root, "switch", "--quiet", "-c", target.branch, "--track", target.ref)
    git(root, "merge", "--ff-only", "--quiet", target.sha)


def restore(root: Path, prev: dict) -> None:
    """Put the clone back where `prev` says it was. A branch is reset to its
    old commit and stays checked out, so the next update moves it forward again."""
    if prev.get("branch"):
        if current_branch(root) != prev["branch"]:
            git(root, "switch", "--quiet", prev["branch"])
        git(root, "reset", "--keep", "--quiet", prev["sha"])
    else:
        git(root, "switch", "--quiet", "--detach", prev["sha"])


def needs_reinstall(root: Path, old_sha: str, new_sha: str) -> bool:
    """The install is editable, so only a changed pyproject.toml (dependencies,
    extras, entry points) needs pip to run again."""
    try:
        return bool(git(root, "diff", "--name-only", old_sha, new_sha, "--", "pyproject.toml").strip())
    except UpdateError:
        return True


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


def install_extras(extras: Optional[List[str]]) -> List[str]:
    """The extras a reinstall asks for: those detected, or `all` (which the
    versioning guide uses) when there is no way to tell."""
    return ["all"] if extras is None else extras


def install_label(extras: Optional[List[str]]) -> str:
    chosen = install_extras(extras)
    return f".[{','.join(chosen)}]" if chosen else "the base install"


def install_command(root: Path, extras: Optional[List[str]], python: str = sys.executable) -> List[str]:
    """`pip install -e` for the same interpreter that is running. A uv-made
    venv has no pip, so fall back to `uv pip --python` there."""
    chosen = install_extras(extras)
    spec = f"{root}[{','.join(chosen)}]" if chosen else str(root)
    if importlib.util.find_spec("pip") is None and shutil.which("uv"):
        return ["uv", "pip", "install", "--quiet", "--python", python, "-e", spec]
    return [python, "-m", "pip", "install", "--quiet", "-e", spec]


def environment() -> dict:
    """The interpreter the reinstall targets, as --json reports it."""
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
        rows.append({"manifest": m["label"], "ok": res["ok"], "status": classify(res["ok"], m),
                     "errors": res["errors"], "reason": res.get("reason")})
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


@contextmanager
def recorded_move(root: Path, pos: dict, after_sha: str) -> Iterator[Optional[dict]]:
    """Record where the clone is before the body moves it to `after_sha`, so a
    move cut short can still be rolled back. If the body raises before the
    clone moved, the record it replaced is put back; if the clone did move
    (a switch that went through before a merge failed), the new record stays,
    pointing at where it actually is. Yields the replaced record, for a caller
    that undoes the move later (forget_previous(root, replaced))."""
    state = read_state(root)
    replaced = state.get("previous")
    record = {"branch": pos["branch"], "sha": pos["sha"], "after": after_sha, "describe": describe(pos)}
    state["previous"] = record
    write_state(root, state)
    try:
        yield replaced
    except BaseException:
        now = position(root)
        if (now["sha"], now["branch"]) == (pos["sha"], pos["branch"]):
            forget_previous(root, replaced)
        else:
            forget_previous(root, {**record, "after": now["sha"]})
        raise


def rollback_refusal(root: Path) -> Optional[str]:
    """Why --rollback would refuse here, or None when it can go back."""
    prev = read_state(root).get("previous")
    if not prev:
        return "nothing to roll back to: no update has been recorded here (or it was already rolled back)"
    pos = position(root)
    if prev.get("after") and pos["sha"] != prev["after"]:
        return (f"this clone has moved since the update (it is at {pos['short']}; the update left it at "
                f"{prev['after'][:7]}), so rolling back would discard that work. To go back anyway: "
                f"git switch --detach {prev['sha'][:7]}")
    return None


def forget_previous(root: Path, replaced: Optional[dict] = None) -> None:
    """Drop the rollback record, or put back the one it replaced."""
    state = read_state(root)
    if replaced:
        state["previous"] = replaced
    else:
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

def update_status(root: Path) -> dict:
    """Is there something for `paramify update` to move to? From local refs only.

    Raises UpdateError when the clone is in a state update would refuse (a
    branch with commits of its own, a detached commit), since then it can't say.
    """
    pos = position(root)
    target = choose_target(root, pos, list_releases(root))
    available = not is_current(target, pos)
    if not available:
        waiting = None
    elif target.channel == "branch":
        n = pos["behind"] or 0
        waiting = f"{n} new commit{'s' if n != 1 else ''} on {target.label}"
    else:
        waiting = f"{target.label} is out"
    return {"channel": target.channel, "current": describe(pos), "latest": target.label,
            "update_available": available, "waiting": waiting}


def _background_fetch(root: Path) -> None:
    """Start `git fetch` and don't wait for it. What it brings in is compared on
    the next check, so a slow or absent network never delays the command the
    user actually ran."""
    subprocess.Popen(
        ["git", *FETCH_ARGS], cwd=root, env=_git_env(),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def check_for_update(root: Path, *, now: Optional[float] = None) -> Optional[dict]:
    """update_status for a quiet notice: never slow, never an error.

    Fetches from origin at most once a day, in the background (the time is kept
    in .paramify/state.json), and compares what the clone already has. Returns
    None when PARAMIFY_NO_UPDATE_CHECK is set, when there is no git clone (the
    deploy image), when update could not tell, or when anything goes wrong.
    """
    if os.environ.get(NO_CHECK_ENV, "").strip() not in ("", "0") or is_container(root):
        return None
    now = time.time() if now is None else now
    try:
        state = read_state(root)
        cache = state.get("update_check") or {}
        last_fetch = cache.get("fetched_at")
        if last_fetch is None or now - float(last_fetch) >= CHECK_INTERVAL:
            try:
                _background_fetch(root)
            except OSError:
                pass
            state["update_check"] = {**cache, "fetched_at": now}
            write_state(root, state)
        return update_status(root)
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
