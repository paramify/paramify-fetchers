#!/usr/bin/env python3
"""Accumulate GitHub traffic metrics past the API's 14-day retention window.

GitHub keeps repository traffic for **14 days**. Ask the API on any given day and
that is all you get; anything older is gone for good and cannot be recovered
after the fact. The only way to have a year of traffic history is to have been
writing it down all along.

That is what this does. `snapshot` reads the four traffic endpoints plus the
repo's headline counters and merges them into dated CSVs; run it daily (see
`.github/workflows/traffic.yml`) and the CSVs become the long window the API
refuses to keep. `report` reads those CSVs back and rolls them up.

    python tools/traffic_snapshot.py snapshot --data .metrics
    python tools/traffic_snapshot.py report --data .metrics

The data lives on the orphan `metrics` branch, not on main — a daily bot commit
is not something the public history needs. Check it out beside the code with:

    git worktree add .metrics metrics

Two shapes of data come back from GitHub, and they merge differently:

  views / clones     A per-day series. Keyed by date, so a later snapshot simply
                     replaces the row for a day it reports. The current day is
                     always partial; tomorrow's run overwrites it with the whole
                     day, so partials heal themselves.
  referrers / paths  NOT a series — each is a rolling 14-day *total* as of the
                     moment you asked. There is no way to split one into days,
                     so they are stored as dated observations and never summed
                     across dates.

Stdlib only, on purpose: the workflow then needs no pip step at all.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

API = "https://api.github.com"
UA = "paramify-fetchers-traffic-snapshot"

# One file per shape of data. The two daily series are keyed by `date`; the two
# rolling-window tables are keyed by the `observed` date they were taken on.
VIEWS_CSV = "views.csv"
CLONES_CSV = "clones.csv"
REFERRERS_CSV = "referrers.csv"
PATHS_CSV = "paths.csv"
REPO_CSV = "repo.csv"

DAILY_FIELDS = ["date", "count", "uniques", "observed"]
REFERRER_FIELDS = ["observed", "referrer", "count", "uniques"]
PATH_FIELDS = ["observed", "path", "title", "count", "uniques"]
REPO_FIELDS = ["date", "stars", "forks", "watchers", "open_issues"]


# --------------------------------------------------------------------------- #
# GitHub API
# --------------------------------------------------------------------------- #


class TrafficError(RuntimeError):
    """Anything that should stop the run with a readable message."""


def resolve_token(explicit: str | None) -> str:
    """Find a token that can read traffic.

    TRAFFIC_TOKEN comes first because it is the one that actually works in CI:
    the traffic endpoints need the Administration:read permission, and
    GITHUB_TOKEN cannot be granted it — `administration` is not a key the
    workflow `permissions:` block accepts. Locally, `gh auth token` is the
    friendliest fallback.
    """
    for candidate in (explicit, os.environ.get("TRAFFIC_TOKEN"), os.environ.get("GITHUB_TOKEN")):
        if candidate:
            return candidate
    try:
        out = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    raise TrafficError(
        "no token. Pass --token, set TRAFFIC_TOKEN, or run `gh auth login`.\n"
        "In CI use a fine-grained PAT with Administration:read — GITHUB_TOKEN "
        "cannot read the traffic endpoints."
    )


def resolve_repo(explicit: str | None) -> str:
    """owner/name, from the flag, the Actions env, or the origin remote."""
    if explicit:
        return explicit
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    try:
        url = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        url = ""
    if url:
        slug = url.removesuffix(".git").removeprefix("git@github.com:")
        slug = slug.removeprefix("https://github.com/")
        if slug.count("/") == 1:
            return slug
    raise TrafficError("could not determine the repo; pass --repo owner/name.")


def gh_get(path: str, token: str) -> Any:
    req = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {token}",
            "User-Agent": UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:400]
        if exc.code in (401, 403):
            raise TrafficError(
                f"{exc.code} on {path}. The traffic endpoints need push access and, "
                f"for a fine-grained token, the Administration:read permission. "
                f"GITHUB_TOKEN never has it.\n{body}"
            ) from exc
        raise TrafficError(f"HTTP {exc.code} on {path}: {body}") from exc
    except urllib.error.URLError as exc:
        raise TrafficError(f"network error on {path}: {exc.reason}") from exc


# --------------------------------------------------------------------------- #
# CSV store
# --------------------------------------------------------------------------- #


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_rows(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def merge_daily(
    path: Path, series: list[dict[str, Any]], observed: str
) -> tuple[int, int]:
    """Fold a 14-day series into the stored history. Returns (added, revised).

    A day the API still reports wins over what we stored: GitHub revises counts
    (spam filtering, late aggregation), and the current day is partial until it
    ends. Days that have aged out of the window are untouched — that is the
    whole point of the file.
    """
    stored = {row["date"]: row for row in read_rows(path)}
    added = revised = 0
    for point in series:
        day = point["timestamp"][:10]
        row = {
            "date": day,
            "count": str(point["count"]),
            "uniques": str(point["uniques"]),
            "observed": observed,
        }
        prev = stored.get(day)
        if prev is None:
            added += 1
        elif (prev["count"], prev["uniques"]) != (row["count"], row["uniques"]):
            revised += 1
        stored[day] = row
    write_rows(path, DAILY_FIELDS, [stored[d] for d in sorted(stored)])
    return added, revised


def replace_observation(
    path: Path, fields: list[str], rows: list[dict[str, str]], observed: str
) -> None:
    """Append today's rolling-window rows, replacing any already stored for today.

    Re-running the snapshot on the same day overwrites rather than duplicates.
    """
    kept = [r for r in read_rows(path) if r.get("observed") != observed]
    write_rows(path, fields, kept + rows)


# --------------------------------------------------------------------------- #
# snapshot
# --------------------------------------------------------------------------- #


def cmd_snapshot(args: argparse.Namespace) -> int:
    repo = resolve_repo(args.repo)
    token = resolve_token(args.token)
    observed = datetime.now(timezone.utc).date().isoformat()
    data = Path(args.data)

    views = gh_get(f"/repos/{repo}/traffic/views", token)
    clones = gh_get(f"/repos/{repo}/traffic/clones", token)
    referrers = gh_get(f"/repos/{repo}/traffic/popular/referrers", token)
    paths = gh_get(f"/repos/{repo}/traffic/popular/paths", token)
    meta = gh_get(f"/repos/{repo}", token)

    if args.dry_run:
        print(json.dumps(
            {"repo": repo, "observed": observed, "views": views, "clones": clones,
             "referrers": referrers, "paths": paths}, indent=2))
        return 0

    v_added, v_revised = merge_daily(data / VIEWS_CSV, views["views"], observed)
    c_added, c_revised = merge_daily(data / CLONES_CSV, clones["clones"], observed)

    replace_observation(
        data / REFERRERS_CSV,
        REFERRER_FIELDS,
        [
            {"observed": observed, "referrer": r["referrer"],
             "count": str(r["count"]), "uniques": str(r["uniques"])}
            for r in referrers
        ],
        observed,
    )
    replace_observation(
        data / PATHS_CSV,
        PATH_FIELDS,
        [
            {"observed": observed, "path": p["path"], "title": p["title"],
             "count": str(p["count"]), "uniques": str(p["uniques"])}
            for p in paths
        ],
        observed,
    )

    repo_rows = {r["date"]: r for r in read_rows(data / REPO_CSV)}
    repo_rows[observed] = {
        "date": observed,
        "stars": str(meta["stargazers_count"]),
        "forks": str(meta["forks_count"]),
        "watchers": str(meta["subscribers_count"]),
        "open_issues": str(meta["open_issues_count"]),
    }
    write_rows(data / REPO_CSV, REPO_FIELDS, [repo_rows[d] for d in sorted(repo_rows)])

    print(f"snapshot {repo} @ {observed} -> {data}")
    print(f"  views   {v_added} new day(s), {v_revised} revised")
    print(f"  clones  {c_added} new day(s), {c_revised} revised")
    print(f"  referrers {len(referrers)}, paths {len(paths)}")
    print(f"  stars {meta['stargazers_count']}  forks {meta['forks_count']}  "
          f"watchers {meta['subscribers_count']}")
    return 0


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

BLOCKS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    top = max(values)
    if top == 0:
        return BLOCKS[0] * len(values)
    return "".join(BLOCKS[min(len(BLOCKS) - 1, v * (len(BLOCKS) - 1) // top)] for v in values)


def load_daily(path: Path) -> dict[str, tuple[int, int]]:
    return {r["date"]: (int(r["count"]), int(r["uniques"])) for r in read_rows(path)}


def find_gaps(days: list[str]) -> list[tuple[str, str]]:
    """Runs of missing dates between the first and last day on record.

    A gap means the snapshot did not run for more than 14 days and that traffic
    is unrecoverable — worth saying out loud rather than quietly plotting over.
    """
    if not days:
        return []
    have = set(days)
    gaps: list[tuple[str, str]] = []
    cursor = date.fromisoformat(days[0])
    last = date.fromisoformat(days[-1])
    run_start: date | None = None
    while cursor <= last:
        iso = cursor.isoformat()
        if iso not in have:
            run_start = run_start or cursor
        elif run_start is not None:
            gaps.append((run_start.isoformat(), (cursor - timedelta(days=1)).isoformat()))
            run_start = None
        cursor += timedelta(days=1)
    if run_start is not None:
        gaps.append((run_start.isoformat(), last.isoformat()))
    return gaps


def build_report(data: Path, since: str | None) -> dict[str, Any]:
    views = load_daily(data / VIEWS_CSV)
    clones = load_daily(data / CLONES_CSV)
    if since:
        views = {d: v for d, v in views.items() if d >= since}
        clones = {d: v for d, v in clones.items() if d >= since}

    days = sorted(set(views) | set(clones))
    months: dict[str, dict[str, int]] = {}
    for day in days:
        m = months.setdefault(
            day[:7], {"views": 0, "view_uniques": 0, "clones": 0, "clone_uniques": 0, "days": 0}
        )
        vc, vu = views.get(day, (0, 0))
        cc, cu = clones.get(day, (0, 0))
        m["views"] += vc
        m["view_uniques"] += vu
        m["clones"] += cc
        m["clone_uniques"] += cu
        m["days"] += 1

    last_ref_date = max((r["observed"] for r in read_rows(data / REFERRERS_CSV)), default=None)
    referrers = [r for r in read_rows(data / REFERRERS_CSV) if r["observed"] == last_ref_date]
    last_path_date = max((r["observed"] for r in read_rows(data / PATHS_CSV)), default=None)
    paths = [r for r in read_rows(data / PATHS_CSV) if r["observed"] == last_path_date]

    repo_rows = read_rows(data / REPO_CSV)

    return {
        "days": days,
        "views": views,
        "clones": clones,
        "months": months,
        "gaps": find_gaps(days),
        "referrers": sorted(referrers, key=lambda r: -int(r["count"])),
        "referrers_observed": last_ref_date,
        "paths": sorted(paths, key=lambda r: -int(r["count"])),
        "paths_observed": last_path_date,
        "repo": repo_rows,
        "totals": {
            "views": sum(v for v, _ in views.values()),
            "view_unique_days": sum(u for _, u in views.values()),
            "clones": sum(c for c, _ in clones.values()),
            "clone_unique_days": sum(u for _, u in clones.values()),
        },
    }


def cmd_report(args: argparse.Namespace) -> int:
    data = Path(args.data)
    if not (data / VIEWS_CSV).exists():
        raise TrafficError(
            f"no data in {data}. Check out the metrics branch there first:\n"
            f"  git worktree add {data} metrics"
        )
    rep = build_report(data, args.since)
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
        return 0

    days = rep["days"]
    if not days:
        print("no days on record for that window.")
        return 0

    t = rep["totals"]
    span = (date.fromisoformat(days[-1]) - date.fromisoformat(days[0])).days + 1
    print(f"GitHub traffic — {days[0]} to {days[-1]}  ({span} days, {len(days)} recorded)")
    print()
    print(f"  {t['views']:>8,} views     {t['view_unique_days']:>7,} unique-days")
    print(f"  {t['clones']:>8,} clones    {t['clone_unique_days']:>7,} unique-days")
    print()
    print("  'unique-days' sums each day's unique count. GitHub dedupes visitors")
    print("  within a day but not across days, so it is an upper bound on people,")
    print("  not a headcount.")
    print()

    print("  Month      Views   Uniq-d    Clones   Uniq-d   Days")
    print("  " + "-" * 52)
    for month in sorted(rep["months"]):
        m = rep["months"][month]
        print(f"  {month}  {m['views']:>7,}  {m['view_uniques']:>7,}  "
              f"{m['clones']:>8,}  {m['clone_uniques']:>7,}   {m['days']:>3}")
    print()

    # Recorded days, not calendar days — with a gap in the store those differ,
    # and labelling it "last 30 days" over a 70-day span would be a lie.
    tail = days[-30:]
    print(f"  Last {len(tail)} recorded days")
    print(f"    views   {sparkline([rep['views'].get(d, (0, 0))[0] for d in tail])}")
    print(f"    clones  {sparkline([rep['clones'].get(d, (0, 0))[0] for d in tail])}")
    print(f"            {tail[0]} → {tail[-1]}")
    print()

    if rep["referrers"]:
        print(f"  Top referrers (rolling 14 days as of {rep['referrers_observed']})")
        for r in rep["referrers"][:10]:
            print(f"    {int(r['count']):>6,}  {int(r['uniques']):>5,}u  {r['referrer']}")
        print()
    if rep["paths"]:
        print(f"  Top paths (rolling 14 days as of {rep['paths_observed']})")
        for p in rep["paths"][:10]:
            print(f"    {int(p['count']):>6,}  {int(p['uniques']):>5,}u  {p['title']}")
        print()

    if rep["repo"]:
        first, last = rep["repo"][0], rep["repo"][-1]
        print(f"  Stars {last['stars']} ({int(last['stars']) - int(first['stars']):+d} "
              f"since {first['date']})   "
              f"Forks {last['forks']} ({int(last['forks']) - int(first['forks']):+d})   "
              f"Watchers {last['watchers']}")
        print()

    if rep["gaps"]:
        print("  ⚠ gaps — the snapshot did not run for >14 days; this traffic is gone:")
        for start, end in rep["gaps"]:
            print(f"    {start} .. {end}")
        print()

    newest = days[-1]
    if read_rows(data / VIEWS_CSV) and any(
        r["date"] == newest and r["observed"] == newest for r in read_rows(data / VIEWS_CSV)
    ):
        print(f"  note: {newest} is still partial — it was last observed on the same day.")
    return 0


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="traffic_snapshot",
        description="Accumulate GitHub traffic metrics past the 14-day API window.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    snap = sub.add_parser("snapshot", help="fetch today's traffic and merge it into the store")
    snap.add_argument("--repo", help="owner/name (default: $GITHUB_REPOSITORY or origin)")
    snap.add_argument("--data", default=".metrics", help="store directory (default: .metrics)")
    snap.add_argument("--token", help="token with Administration:read (default: $TRAFFIC_TOKEN, gh)")
    snap.add_argument("--dry-run", action="store_true", help="print the API payloads, write nothing")
    snap.set_defaults(func=cmd_snapshot)

    rep = sub.add_parser("report", help="roll up the accumulated history")
    rep.add_argument("--data", default=".metrics", help="store directory (default: .metrics)")
    rep.add_argument("--since", help="only include days on or after YYYY-MM-DD")
    rep.add_argument("--json", action="store_true", help="emit the rollup as JSON")
    rep.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except TrafficError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
