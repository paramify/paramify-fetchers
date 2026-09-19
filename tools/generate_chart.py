#!/usr/bin/env python3
"""Generate docs/coverage-over-time.svg — fetcher and service counts over time.

Both numbers are live data: every merged fetcher moves them, so a hand-drawn
chart is stale the day after it is drawn. We generate it from the repo's own git
history instead (the same "generate the rot-prone parts" pattern as
tools/gen_ksi_coverage.py), and .github/workflows/coverage-chart.yml re-runs
this and commits the result when a fetcher lands.

Walks first-parent history — `main` when the clone has it, else whatever is
checked out — and, at each commit, counts:

* **fetchers** — directories matching exactly `fetchers/<category>/<name>/fetcher.yaml`
  (`logos` and any `_`-prefixed path component excluded);
* **services** — the distinct `fetchers/<category>/` directories holding at least
  one of those. Adding Oracle Cloud bumps this by one; adding another AWS fetcher
  does not.

`demo` is sample data rather than a supported service, so it is excluded from
both counts — that keeps the chart in step with the README's supported-services
table, which omits it too. `--include-demo` counts it in both.

    python tools/generate_chart.py

Stdlib only, on purpose: this runs in CI on every fetcher merge, and the SVG is
emitted by hand with string templating rather than pulling a plotting stack into
a workflow that otherwise installs nothing.

Two files are written, light and dark, because GitHub serves README images
through its camo proxy, which strips the context an in-SVG
`@media (prefers-color-scheme: dark)` block needs — a dark-inked chart would
simply vanish on the dark theme. Every fill and stroke is set explicitly and the
dark file carries its own background, so neither depends on a viewer default.
The README picks between them with a <picture> element, the same way the service
logos do.
"""

from __future__ import annotations

import argparse
import datetime as dt
import math
import subprocess
from collections import Counter
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_LIGHT = REPO_ROOT / "docs" / "coverage-over-time.svg"
OUT_DARK = REPO_ROOT / "docs" / "coverage-over-time-dark.svg"

# Two selected themes rather than one flipped automatically: the dark steps are
# chosen for the dark surface, and every colour below is written into the file.
LIGHT = {
    "surface": "#fcfcfb",
    "ink": "#0b0b0b",
    "secondary": "#52514e",
    "muted": "#898781",
    "grid": "#e1e0d9",
    "axis": "#c3c2b7",
    "fetchers": "#2a78d6",
    "services": "#eb6834",
}
DARK = {
    "surface": "#1a1a19",
    "ink": "#ffffff",
    "secondary": "#c3c2b7",
    "muted": "#898781",
    "grid": "#2c2c2a",
    "axis": "#383835",
    "fetchers": "#3987e5",
    "services": "#d95926",
}

FONT = "system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
Series = list[tuple[dt.date, int]]


# --- history ---------------------------------------------------------------


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout


def ref() -> str:
    """`main` when it exists (CI checks it out), else whatever is checked out."""
    try:
        git("rev-parse", "--verify", "--quiet", "main^{commit}")
        return "main"
    except subprocess.CalledProcessError:
        return "HEAD"


def fetcher_category(path: str) -> str | None:
    """The category of `fetchers/<category>/<name>/fetcher.yaml`, else None."""
    parts = path.split("/")
    if len(parts) != 4 or parts[0] != "fetchers" or parts[3] != "fetcher.yaml":
        return None
    if parts[1] == "logos" or any(p.startswith("_") for p in parts):
        return None
    return parts[1]


def walk_history(branch: str) -> list[tuple[dt.date, Counter[str]]]:
    """(commit date, fetchers per category) per first-parent commit, oldest first."""
    raw = git("rev-list", "--first-parent", "--format=%cI", branch).splitlines()
    commits = [
        (raw[i].split()[1], dt.date.fromisoformat(raw[i + 1][:10]))
        for i in range(0, len(raw) - 1, 2)
        if raw[i].startswith("commit ")
    ]
    commits.reverse()

    history = []
    for sha, day in commits:
        tree = git("ls-tree", "-r", "--name-only", sha, "--", "fetchers/")
        history.append(
            (day, Counter(c for c in (fetcher_category(p) for p in tree.splitlines()) if c))
        )
    return history


def as_of(branch: str, fallback: dt.date) -> dt.date:
    """Right edge of the x axis: the last commit that touched the fetcher tree.

    Deliberately not "today" and not "the last commit": pinning it to the fetcher
    tree keeps the output a pure function of the data, so re-running the
    generator after an unrelated commit (including the workflow's own chart
    commit) produces a byte-identical file and the CI diff guard stays quiet.
    `git log` prints nothing if no commit ever touched the tree, hence the
    fallback.
    """
    stamp = git("log", "-1", "--first-parent", "--format=%cI", branch, "--", "fetchers/").strip()
    return dt.date.fromisoformat(stamp[:10]) if stamp else fallback


def change_points(series: Series) -> Series:
    """Collapse a per-commit series to the days the count actually moves."""
    by_day: dict[dt.date, int] = {}
    for day, count in series:
        by_day[day] = count
    points: Series = []
    for day in sorted(by_day):
        if not points or points[-1][1] != by_day[day]:
            points.append((day, by_day[day]))
    return points


# --- svg --------------------------------------------------------------------


def num(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


def text_el(x: float, y: float, s: str, *, fill: str, size: float = 11, weight: int = 400) -> str:
    return (
        f'<text x="{num(x)}" y="{num(y)}" font-family="{FONT}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="start">{s}</text>'
    )


def tick_el(x: float, y: float, s: str, *, fill: str, anchor: str) -> str:
    return (
        f'<text x="{num(x)}" y="{num(y)}" font-family="{FONT}" font-size="11" '
        f'font-weight="400" fill="{fill}" text-anchor="{anchor}">{s}</text>'
    )


def key_el(x: float, y: float, color: str, surface: str) -> str:
    """A short line + dot: identity for a panel, so no text wears the data colour."""
    return (
        f'<line x1="{num(x)}" y1="{num(y)}" x2="{num(x + 16)}" y2="{num(y)}" stroke="{color}" '
        f'stroke-width="2" stroke-linecap="round"/>'
        f'<circle cx="{num(x + 8)}" cy="{num(y)}" r="3.5" fill="{color}" '
        f'stroke="{surface}" stroke-width="1.5"/>'
    )


def nice_axis(peak: int) -> tuple[int, int]:
    """(axis max, tick step) on clean numbers, at most four intervals."""
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 500):
        top = int(math.ceil(peak / step) * step)
        if top / step <= 4:
            return max(top, step), step
    return peak, peak


def month_ticks(first: dt.date, last: dt.date, max_ticks: int = 8) -> list[dt.date]:
    months: list[dt.date] = []
    year, month = (first.year, first.month) if first.day == 1 else (
        (first.year + 1, 1) if first.month == 12 else (first.year, first.month + 1)
    )
    while dt.date(year, month, 1) <= last:
        months.append(dt.date(year, month, 1))
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    return months[:: max(1, math.ceil(len(months) / max_ticks))]


def step_path(
    points: Series,
    x: Callable[[dt.date], float],
    y: Callable[[float], float],
    x_end: float,
) -> str:
    """Stairs, not a smoothed line: the count holds flat between merges."""
    d = [f"M{num(x(points[0][0]))},{num(y(points[0][1]))}"]
    previous = points[0][1]
    for day, count in points[1:]:
        d.append(f"L{num(x(day))},{num(y(previous))}")
        d.append(f"L{num(x(day))},{num(y(count))}")
        previous = count
    d.append(f"L{num(x_end)},{num(y(previous))}")
    return " ".join(d)


def panel(
    out: list[str],
    theme: dict[str, str],
    *,
    box: tuple[float, float, float, float],
    first: dt.date,
    last: dt.date,
    points: Series,
    color: str,
    unit: str,
) -> None:
    """One plot area: gridlines, y ticks, the step line, dated x ticks, end label."""
    left, top, right, bottom = box
    span = max(1, (last - first).days)
    axis_max, step = nice_axis(max(count for _, count in points))

    def x(day: dt.date) -> float:
        return left + (day - first).days / span * (right - left)

    def y(count: float) -> float:
        return bottom - count / axis_max * (bottom - top)

    for value in range(0, axis_max + 1, step):
        gy = y(value)
        stroke = theme["axis"] if value == 0 else theme["grid"]
        out.append(
            f'<line x1="{num(left)}" y1="{num(gy)}" x2="{num(right)}" y2="{num(gy)}" '
            f'stroke="{stroke}" stroke-width="1"/>'
        )
        out.append(tick_el(left - 10, gy + 4, str(value), fill=theme["muted"], anchor="end"))

    ticks = month_ticks(first, last)
    for tick in ticks:
        label = f"{tick:%b %Y}" if tick.month == 1 or tick == ticks[0] else f"{tick:%b}"
        out.append(tick_el(x(tick), bottom + 20, label, fill=theme["muted"], anchor="middle"))

    line = step_path(points, x, y, x(last))
    out.append(
        f'<path d="{line} L{num(x(last))},{num(y(0))} L{num(x(points[0][0]))},{num(y(0))} Z" '
        f'fill="{color}" fill-opacity="0.10" stroke="none"/>'
    )
    out.append(
        f'<path d="{line}" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
    )

    end_x, end_y = x(last), y(points[-1][1])
    out.append(
        f'<circle cx="{num(end_x)}" cy="{num(end_y)}" r="4.5" fill="{color}" '
        f'stroke="{theme["surface"]}" stroke-width="2"/>'
    )
    out.append(text_el(end_x + 11, end_y + 2, str(points[-1][1]), fill=theme["ink"], size=17, weight=600))
    out.append(text_el(end_x + 11, end_y + 18, unit, fill=theme["muted"]))


def render(theme: dict[str, str], fetchers: Series, services: Series, last: dt.date) -> str:
    """Two stacked panels sharing one time axis.

    Small multiples rather than one plot with two y scales: 181 against 14 on a
    single pair of axes would invent a relationship between them that the data
    does not have.
    """
    width, height = 880, 448
    left, right = 54, width - 118
    alt = (
        f"Fetcher and service counts over time. Fetchers rise from {fetchers[0][1]} to "
        f"{fetchers[-1][1]}, and services from {services[0][1]} to {services[-1][1]}, "
        f"between {fetchers[0][0]:%B %Y} and {last:%B %Y}."
    )
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{alt}">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="{theme["surface"]}"/>',
        text_el(24, 32, "Coverage over time", fill=theme["ink"], size=16, weight=600),
    ]
    panels = (
        (theme["fetchers"], "Fetchers · fetcher.yaml directories", fetchers, "fetchers", 76, 206),
        (theme["services"], "Services · top-level categories", services, "services", 278, 408),
    )
    for color, caption, points, unit, top, bottom in panels:
        out.append(key_el(24, top - 20, color, theme["surface"]))
        out.append(text_el(48, top - 16, caption, fill=theme["secondary"], size=12))
        panel(
            out,
            theme,
            box=(left, top, right, bottom),
            first=fetchers[0][0],
            last=last,
            points=points,
            color=color,
            unit=unit,
        )
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + "\n".join(out) + "\n</svg>\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--include-demo",
        action="store_true",
        help="count the demo category in both totals (excluded by default)",
    )
    args = parser.parse_args()

    branch = ref()
    history = walk_history(branch)
    if not history:
        print("no first-parent history to walk — nothing written.")
        return 1

    skip: set[str] = set() if args.include_demo else {"demo"}
    fetchers = change_points(
        [(day, sum(n for cat, n in cats.items() if cat not in skip)) for day, cats in history]
    )
    services = change_points([(day, len(set(cats) - skip)) for day, cats in history])
    last = as_of(branch, history[-1][0])

    OUT_LIGHT.parent.mkdir(parents=True, exist_ok=True)
    OUT_LIGHT.write_text(render(LIGHT, fetchers, services, last), encoding="utf-8")
    OUT_DARK.write_text(render(DARK, fetchers, services, last), encoding="utf-8")
    print(
        f"{OUT_LIGHT.relative_to(REPO_ROOT)} + {OUT_DARK.relative_to(REPO_ROOT)} written: "
        f"{fetchers[-1][1]} fetchers, {services[-1][1]} services as of {last.isoformat()} "
        f"({len(history)} commits walked)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
