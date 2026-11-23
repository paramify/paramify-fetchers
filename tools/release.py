#!/usr/bin/env python3
"""Draft, check and publish a paramify-fetchers release.

    python tools/release.py draft [--base origin/main] [--version X.Y.Z-beta] [--no-push]
    python tools/release.py check [--ref HEAD]
    python tools/release.py publish --head-sha SHA --merge-sha SHA
    python tools/release.py notify-failure --url RUN_URL

`draft` builds (or rebuilds) the `release/next` branch and its pull request.
`check` says what to fix in the release file before it ships. `publish` tags
the reviewed commit and creates the GitHub Release. Exit code 0 means done or
nothing to do; 1 means refused or failed, with one line that says what to do.

This file is the I/O: git, gh, Slack and files. The decisions (versions, the
CHANGELOG cut, note drafting, rebuild and check rules) are pure functions in
`framework/release_notes.py`. See docs/releasing_guide.md.

Environment: SLACK_RELEASE_WEBHOOK (a Slack workflow webhook; without it the
message is printed), RELEASE_REVIEWER (default 21tmccauley) and
RELEASE_REMINDER=1 (the Thursday run: also remind when a PR is still open).
`draft` fetches `origin` first when the clone has that remote.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, NoReturn, Optional, Set, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from framework import release_notes  # noqa: E402
from framework.update import UpdateError, git, parse_release, read_at, repo_web_url  # noqa: E402

BRANCH = "release/next"
CHANGELOG = "CHANGELOG.md"
PYPROJECT = "pyproject.toml"
UNRELEASED = "releases/unreleased.yaml"
REVIEWER = "21tmccauley"
GUIDE = "docs/releasing_guide.md"

Notify = Callable[[str, str], None]


class ReleaseError(RuntimeError):
    """A refusal or failure, as one line that says what to do."""


# --------------------------------------------------------------------------- #
# Git facts
# --------------------------------------------------------------------------- #

def last_tag(root: Path, ref: str) -> str:
    return git(root, "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", ref).strip()


def _version_of(tag: str) -> str:
    rel = parse_release(tag)
    if rel is None:
        raise ReleaseError(f"{tag} is not a release tag (vX.Y.Z[-suffix])")
    return rel.version


def _fetchers_at(root: Path, ref: str) -> Dict[str, Tuple[str, str]]:
    """{name: (fetcher dir, version)} for every fetchers/**/fetcher.yaml at `ref`."""
    paths = [
        p for p in git(root, "ls-tree", "-r", "--name-only", ref, "--", "fetchers/").splitlines()
        if p.endswith("/fetcher.yaml") and not any(part.startswith("_") for part in p.split("/")[1:-1])
    ]
    out: Dict[str, Tuple[str, str]] = {}
    for path, text in read_at(root, ref, paths).items():
        try:
            doc = yaml.safe_load(text or "") or {}
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or doc.get("version") is None:
            continue
        d = path.rsplit("/", 1)[0]
        out[str(doc.get("name") or d.rsplit("/", 1)[1])] = (d, str(doc["version"]))
    return out


def fetcher_versions(root: Path, ref: str) -> Dict[str, str]:
    return {name: version for name, (_d, version) in _fetchers_at(root, ref).items()}


def changed_fetchers(root: Path, tag: str, ref: str) -> Tuple[Dict[str, str], Set[str]]:
    """({changed or added name: version at ref}, {added names}). Removed fetchers are in neither."""
    old, new = fetcher_versions(root, tag), fetcher_versions(root, ref)
    changed = {n: v for n, v in new.items() if old.get(n) != v}
    return changed, {n for n in changed if n not in old}


def _subjects_by_name(root: Path, tag: str, ref: str, names: Set[str]) -> Dict[str, List[str]]:
    """{fetcher name: commit subjects in tag..ref that touched it, newest first}, from one git log."""
    dirs = {d: n for n, (d, _v) in _fetchers_at(root, ref).items() if n in names}
    log = git(root, "log", "--no-merges", "--format=%x00%s", "--name-only", f"{tag}..{ref}", "--", "fetchers/")
    out: Dict[str, List[str]] = {}
    for chunk in log.split("\0")[1:]:
        subject, _, files = chunk.partition("\n")
        touched = {n for path in files.split() for d, n in dirs.items() if path.startswith(d + "/")}
        for n in touched:
            out.setdefault(n, []).append(subject)
    return out


def _rows(text: Optional[str]) -> List[dict]:
    doc = yaml.safe_load(text or "") or {}
    return list(doc.get("highlights") or []) if isinstance(doc, dict) else []


def _pending_release(root: Path, ref: str) -> Optional[Tuple[str, dict]]:
    """(path, doc) of the one releases/*.yaml at `ref` whose version has no tag yet."""
    paths = [
        p for p in git(root, "ls-tree", "--name-only", ref, "releases/").splitlines()
        if p.endswith(".yaml") and p != UNRELEASED
    ]
    tags = set(git(root, "tag", "-l", "v*").split())
    pending = []
    for path, text in read_at(root, ref, paths).items():
        doc = yaml.safe_load(text or "") or {}
        if isinstance(doc, dict) and f"v{doc.get('version')}" not in tags:
            pending.append((path, doc))
    if len(pending) > 1:
        raise ReleaseError(f"{len(pending)} release files have no tag: "
                           f"{', '.join(p for p, _ in pending)}; keep one and delete the others")
    return pending[0] if pending else None


def _release_base(root: Path, ref: str) -> Optional[str]:
    """The `Release-Base:` trailer of the newest draft commit on `ref` (hand edits may sit on top)."""
    log = git(root, "log", "-n", "50", "--format=%x00%(trailers:key=Release-Base,valueonly)", ref)
    for value in log.split("\0")[1:]:
        if value.strip():
            return value.strip()
    return None


def _key(row: dict) -> Tuple[object, object]:
    return row.get("tag"), row.get("title")


def _on_branch(root: Path, rows: List[dict]) -> Tuple[Optional[dict], List[dict]]:
    """(release file on origin/release/next, rows at base that arrived since that draft)."""
    ref = f"origin/{BRANCH}"
    found = _pending_release(root, ref)
    if found is None:
        return None, []
    previous = found[1]
    base = _release_base(root, ref)
    seen_rows = _rows(read_at(root, base, [UNRELEASED])[UNRELEASED]) if base else previous.get("highlights") or []
    seen = {_key(r) for r in seen_rows}
    return previous, [r for r in rows if _key(r) not in seen]


# --------------------------------------------------------------------------- #
# GitHub and Slack
# --------------------------------------------------------------------------- #

class GitHub:
    """The few `gh` calls the release needs, run in the repo so gh picks its remote."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _gh(self, *args: str) -> str:
        try:
            proc = subprocess.run(["gh", *args], cwd=self.root, capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            raise ReleaseError("gh is not installed or not on PATH") from None
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout).strip().splitlines()
            raise ReleaseError(f"gh {args[0]} {args[1]} failed: {msg[-1] if msg else proc.returncode}")
        return proc.stdout

    def open_release_pr(self) -> Optional[dict]:
        out = self._gh("pr", "list", "--head", BRANCH, "--state", "open", "--json", "number,url,title,body")
        prs = json.loads(out or "[]")
        return prs[0] if prs else None

    def create_pr(self, title: str, body: str, reviewer: str) -> str:
        out = self._gh("pr", "create", "--base", "main", "--head", BRANCH, "--title", title, "--body", body,
                       "--assignee", reviewer, "--reviewer", reviewer)
        return out.strip().splitlines()[-1]

    def edit_pr(self, number: int, title: str, body: str) -> None:
        self._gh("pr", "edit", str(number), "--title", title, "--body", body)

    def create_release(self, tag: str, title: str, notes: str, prerelease: bool) -> str:
        args = ["release", "create", tag, "--verify-tag", "--title", title, "--notes", notes]
        out = self._gh(*args, *(["--prerelease"] if prerelease else []))
        return out.strip().splitlines()[-1]


def notify(text: str, url: str) -> None:
    """Send a DM through the Slack workflow webhook, or print it when there is none. Never raises."""
    hook = os.environ.get("SLACK_RELEASE_WEBHOOK")
    if not hook:
        print(f"slack: {text} {url}")
        return
    req = urllib.request.Request(hook, data=json.dumps({"text": text, "url": url}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except (OSError, ValueError) as e:
        print(f"slack: could not send ({e}): {text} {url}")


def _run_url() -> str:
    env = os.environ
    if env.get("GITHUB_RUN_ID") and env.get("GITHUB_REPOSITORY"):
        server = env.get("GITHUB_SERVER_URL", "https://github.com")
        return f"{server}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
    return ""


# --------------------------------------------------------------------------- #
# draft
# --------------------------------------------------------------------------- #

def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _marks(doc: Optional[dict]) -> Tuple[int, int, int]:
    """(marked fetcher lines, marked non-breaking rows, marked breaking rows)."""
    doc = doc or {}
    rows = [h for h in doc.get("highlights") or [] if h.get("draft")]
    breaking = sum(1 for h in rows if h.get("tag") == "breaking")
    lines = sum(1 for f in doc.get("fetchers") or [] if f.get("draft"))
    return lines, len(rows) - breaking, breaking


def _to_read(doc: dict) -> str:
    lines, new, breaking = _marks(doc)
    parts = [_plural(n, w) for n, w in ((lines, "fetcher line"), (new, "new row"), (breaking, "breaking row")) if n]
    return f"{', '.join(parts)} to read" if parts else "nothing marked to read"


def _pr_body(root: Path, doc: dict, base_sha: str) -> str:
    todos = sum(1 for f in doc.get("fetchers") or [] if str(f.get("note", "")).startswith("TODO"))
    path = f"releases/{doc['version']}.yaml"
    todo_line = f" {_plural(todos, 'fetcher note')} still start with TODO." if todos else ""
    return (
        f"Release v{doc['version']}, drafted from `main` at {base_sha[:12]}.\n\n"
        f"In `{path}`: {_to_read(doc)}.{todo_line}\n\n"
        "Read each row and line marked `draft: true`, fix the text, and remove the mark. "
        "CI stays red while a mark is left.\n\n"
        f"How to review and publish: {repo_web_url(root)}/blob/main/{GUIDE}\n\n"
        f"A push to `main` redrafts this branch. It keeps your edits to `{path}`; "
        "edits to other files are lost, so fix the CHANGELOG on `main`.\n"
    )


def _header(text: Optional[str]) -> str:
    lines = []
    for line in (text or "").splitlines(keepends=True):
        if not line.startswith("#"):
            break
        lines.append(line)
    return "".join(lines)


def draft(root: Path, *, base: str, today: str, gh: GitHub, notify: Notify = notify, push: bool = True,
          version: Optional[str] = None, reviewer: str = REVIEWER, reminder: bool = False) -> str:
    """Build or rebuild release/next and its PR. Returns "nothing", "opened" or "rebuilt"."""
    if "origin" in git(root, "remote").split():
        git(root, "fetch", "--quiet", "--tags", "origin")
    base_sha = git(root, "rev-parse", f"{base}^{{commit}}").strip()
    tag = last_tag(root, base_sha)
    prev = _version_of(tag)
    changed, added = changed_fetchers(root, tag, base_sha)
    files = read_at(root, base_sha, [CHANGELOG, PYPROJECT, UNRELEASED])
    rows = _rows(files[UNRELEASED])
    if not rows and not changed:
        return "nothing"

    pr = gh.open_release_pr()
    previous, since = _on_branch(root, rows) if pr else (None, [])

    sections = release_notes.changelog_sections(files[CHANGELOG] or "")
    body = sections.get("Unreleased", {}).get("body", "")
    subjects = _subjects_by_name(root, tag, base_sha, set(changed))
    doc = release_notes.draft_release(
        "", today, rows, changed, lambda n: release_notes.draft_note(n, body, subjects.get(n, [])),
        previous=previous, rows_since_base=since,
    )
    if version is None:
        version = release_notes.next_version(prev, release_notes.required_bump(doc, added, _major(prev)))
        kept = str(previous["version"]) if previous else ""
        if kept and _base_version(kept) == _base_version(version):
            version = kept  # a suffix dropped by hand stays dropped
    doc["version"] = version

    git(root, "switch", "-q", "-C", BRANCH, base_sha)
    try:
        changelog = release_notes.cut_changelog(files[CHANGELOG] or "", version, today)
        pyproject = release_notes.set_pyproject_version(files[PYPROJECT] or "", version)
    except ValueError as e:
        raise ReleaseError(f"{e}; fix it on main and run draft again") from None
    (root / CHANGELOG).write_text(changelog)
    (root / PYPROJECT).write_text(pyproject)
    git(root, "rm", "-q", UNRELEASED)
    (root / "releases" / f"{version}.yaml").write_text(release_notes.dump_release(doc))
    (root / UNRELEASED).write_text(_header(files[UNRELEASED]) + "version: unreleased\nhighlights: []\n")
    git(root, "add", CHANGELOG, PYPROJECT, "releases/")
    git(root, "commit", "-q", "-m", f"chore(release): v{version}", "-m", f"Release-Base: {base_sha}")
    if push:
        git(root, "push", "--quiet", "--force-with-lease", "origin", BRANCH)

    title, pr_body = f"Release v{version}", _pr_body(root, doc, base_sha)
    if pr is None:
        url = gh.create_pr(title, pr_body, reviewer)
        notify(f"v{version} is ready to review: {_to_read(doc)}.", url)
        return "opened"
    url = pr["url"]
    gh.edit_pr(int(pr["number"]), title, pr_body)
    old = str(previous["version"]) if previous else version
    if old != version:
        notify(f"v{old} is now v{version}: {_to_read(doc)}.", url)
    elif sum(_marks(doc)) > sum(_marks(previous)):
        notify(f"v{version} has more to read: {_to_read(doc)}.", url)
    if reminder:
        notify(f"v{version} is still waiting for you.", url)
    return "rebuilt"


def _major(version: str) -> int:
    return int(version.split(".", 1)[0])


def _base_version(version: str) -> str:
    return version.split("-", 1)[0]


# --------------------------------------------------------------------------- #
# check and publish
# --------------------------------------------------------------------------- #

def check(root: Path, ref: str = "HEAD") -> List[str]:
    """What to fix in the release file at `ref` before it ships; [] when ready or there is none."""
    found = _pending_release(root, ref)
    if found is None:
        return []
    tag = last_tag(root, ref)
    changed, added = changed_fetchers(root, tag, ref)
    return release_notes.check_release(found[1], changed, added, _version_of(tag))


def render_release_body(doc: dict, changelog_body: str) -> str:
    """The GitHub Release text: Breaking, New, Fetchers, then the CHANGELOG section folded."""
    rows = doc.get("highlights") or []
    breaking = [f"- **{h['title']}**" + (f"\n  Fix: {h['fix']}" if h.get("fix") else "")
                for h in rows if h.get("tag") == "breaking"]
    new = [f"- {h['title']}" + (f" — {h['detail']}" if h.get("detail") else "")
           for h in rows if h.get("tag") != "breaking"]
    fetchers = [f"- `{f['name']}` {f['version']}: {f['note']}" for f in doc.get("fetchers") or []]
    parts = [f"## {head}\n\n" + "\n".join(items) for head, items in
             (("Breaking", breaking), ("New", new), ("Fetchers", fetchers)) if items]
    if changelog_body.strip():
        parts.append(f"<details><summary>Full changelog</summary>\n\n{changelog_body.strip()}\n\n</details>")
    return "\n\n".join(parts) + "\n"


def _refuse(notify: Notify, text: str) -> NoReturn:
    notify(text, _run_url())
    raise ReleaseError(text)


def _is_ancestor(root: Path, a: str, b: str) -> bool:
    try:
        git(root, "merge-base", "--is-ancestor", a, b)
    except UpdateError:
        return False
    return True


def publish(root: Path, *, head_sha: str, merge_sha: str, gh: GitHub, notify: Notify = notify) -> str:
    """Tag the commit that was reviewed, push the tag, create the GitHub Release. Returns the tag."""
    found = _pending_release(root, merge_sha)
    if found is None:
        _refuse(notify, f"Not published: {merge_sha[:12]} has no release file without a tag; "
                        "merge a release/next pull request first.")
    path, doc = found
    version = str(doc["version"])
    marks = sum(1 for x in (doc.get("highlights") or []) + (doc.get("fetchers") or []) if x.get("draft"))
    if marks:
        _refuse(notify, f"v{version} not published: {path} still has {_plural(marks, 'draft mark')}; "
                        "remove them in a pull request to main, then run publish on that merge.")
    if _is_ancestor(root, head_sha, merge_sha):
        target = head_sha
    elif git(root, "rev-parse", f"{merge_sha}^{{tree}}") == git(root, "rev-parse", f"{head_sha}^{{tree}}"):
        target = merge_sha
    else:
        _refuse(notify, f"v{version} not published: the tree of {merge_sha[:12]} on main differs from the "
                        f"reviewed {head_sha[:12]}; tag the right commit by hand ({GUIDE}).")
    tag = f"v{version}"
    git(root, "tag", "-a", tag, "-m", tag, target)
    git(root, "push", "--quiet", "origin", tag)
    sections = release_notes.changelog_sections(read_at(root, target, [CHANGELOG])[CHANGELOG] or "")
    notes = render_release_body(doc, sections.get(version, {}).get("body", ""))
    url = gh.create_release(tag, tag, notes, "-" in version)
    notify(f"{tag} is out.", url)
    return tag


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="tools/release.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draft", help="build or rebuild release/next and its pull request")
    d.add_argument("--base", default="origin/main")
    d.add_argument("--version", help="use this version instead of the one the rows call for")
    d.add_argument("--no-push", action="store_true", help="commit locally; do not push")
    c = sub.add_parser("check", help="say what to fix in the release file")
    c.add_argument("--ref", default="HEAD")
    pb = sub.add_parser("publish", help="tag the reviewed commit and create the GitHub Release")
    pb.add_argument("--head-sha", required=True, help="the release branch's last commit")
    pb.add_argument("--merge-sha", required=True, help="the commit the merge made on main")
    nf = sub.add_parser("notify-failure", help="DM that the release job failed")
    nf.add_argument("--url", required=True, help="the workflow run")
    args = p.parse_args(argv)

    root = REPO_ROOT
    try:
        if args.cmd == "draft":
            today = datetime.now(timezone.utc).date().isoformat()
            result = draft(root, base=args.base, today=today, gh=GitHub(root), push=not args.no_push,
                           version=args.version, reviewer=os.environ.get("RELEASE_REVIEWER") or REVIEWER,
                           reminder=os.environ.get("RELEASE_REMINDER") == "1")
            print("Nothing to release: no highlights rows and no fetcher changes." if result == "nothing"
                  else f"release/next {result}.")
        elif args.cmd == "check":
            problems = check(root, args.ref)
            for line in problems:
                print(line)
            if problems:
                return 1
            print("Release file: nothing to fix.")
        elif args.cmd == "publish":
            print(f"Published {publish(root, head_sha=args.head_sha, merge_sha=args.merge_sha, gh=GitHub(root))}.")
        else:
            notify("The weekly release job failed.", args.url)
    except (ReleaseError, UpdateError) as e:
        print(f"release: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
