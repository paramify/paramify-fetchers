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
logos, which omit it too. `--include-demo` counts it in both.

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
# Each surface is GitHub's own page background for that theme, so the chart sits
# in the README rather than floating in a box. One accent: fetchers wear the
# Paramify brand blue, services plain ink.
LIGHT = {
    "surface": "#ffffff",
    "ink": "#1f2328",
    "secondary": "#59636e",
    "muted": "#8c959f",
    "grid": "#eef0f2",
    "axis": "#d1d9e0",
    "fetchers": "#2270ff",
    "services": "#1f2328",
}
DARK = {
    "surface": "#0d1117",
    "ink": "#f0f6fc",
    "secondary": "#9198a1",
    "muted": "#6e7681",
    "grid": "#1b2129",
    "axis": "#30363d",
    "fetchers": "#4d8bff",
    "services": "#c9d1d9",
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


def text_el(
    x: float,
    y: float,
    s: str,
    *,
    fill: str,
    size: float = 11,
    weight: int = 400,
    anchor: str = "start",
    spacing: str | None = None,
) -> str:
    tracking = f' letter-spacing="{spacing}"' if spacing else ""
    return (
        f'<text x="{num(x)}" y="{num(y)}" font-family="{FONT}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{tracking}>{s}</text>'
    )


def headline_el(x: float, y: float, theme: dict[str, str], totals: list[tuple[int, str, str]]) -> str:
    """The current totals as big numerals, each keyed by a dot in its line's colour.

    One <text> with tspans, so each group flows after the last at whatever width
    the viewer's system font gives the numerals — nothing here guesses glyph widths.
    """
    parts = []
    for i, (value, unit, color) in enumerate(totals):
        gap = ' dx="36"' if i else ""
        parts.append(
            f'<tspan{gap} font-size="44" font-weight="600" fill="{theme["ink"]}" '
            f'letter-spacing="-0.02em">{value}</tspan>'
            f'<tspan dx="10" font-size="11" fill="{color}">●</tspan>'
            f'<tspan dx="5" font-size="13" fill="{theme["secondary"]}">{unit}</tspan>'
        )
    return f'<text x="{num(x)}" y="{num(y)}" font-family="{FONT}">{"".join(parts)}</text>'


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
    x: Callable[[dt.date], float],
    last: dt.date,
    points: Series,
    color: str,
    shade: bool,
) -> None:
    """One plot area: dashed gridlines, y ticks in the gutter, the step line, an end dot."""
    left, top, right, bottom = box
    axis_max, step = nice_axis(max(count for _, count in points))

    def y(count: float) -> float:
        return bottom - count / axis_max * (bottom - top)

    for value in range(0, axis_max + 1, step):
        gy = y(value)
        dash = "" if value == 0 else ' stroke-dasharray="2 3"'
        stroke = theme["axis"] if value == 0 else theme["grid"]
        out.append(
            f'<line x1="{num(left)}" y1="{num(gy)}" x2="{num(right)}" y2="{num(gy)}" '
            f'stroke="{stroke}" stroke-width="1"{dash}/>'
        )
        out.append(text_el(left - 8, gy + 4, str(value), fill=theme["muted"], size=10, anchor="end"))

    line = step_path(points, x, y, x(last))
    if shade:
        out.append(
            f'<path d="{line} L{num(x(last))},{num(y(0))} L{num(x(points[0][0]))},{num(y(0))} Z" '
            f'fill="{color}" fill-opacity="0.07" stroke="none"/>'
        )
    out.append(
        f'<path d="{line}" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
    )
    out.append(f'<circle cx="{num(x(last))}" cy="{num(y(points[-1][1]))}" r="3.5" fill="{color}"/>')


def render(theme: dict[str, str], fetchers: Series, services: Series, last: dt.date) -> str:
    """The current totals as a headline, then two stacked panels sharing one time axis.

    Small multiples rather than one plot with two y scales: 181 against 14 on a
    single pair of axes would invent a relationship between them that the data
    does not have. Month hairlines run through both panels, and the month labels
    sit once, under the lower one.
    """
    width, height = 880, 432
    left, right = 48, width - 24
    first = fetchers[0][0]
    span = max(1, (last - first).days)
    alt = (
        f"Fetcher and service counts over time. Fetchers rise from {fetchers[0][1]} to "
        f"{fetchers[-1][1]}, and services from {services[0][1]} to {services[-1][1]}, "
        f"between {first:%B %Y} and {last:%B %Y}."
    )

    def x(day: dt.date) -> float:
        return left + (day - first).days / span * (right - left)

    gained = (
        f"since {first:%B %Y} · +{fetchers[-1][1] - fetchers[0][1]} fetchers, "
        f"+{services[-1][1] - services[0][1]} services"
    )
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{alt}">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="{theme["surface"]}"/>',
        text_el(24, 22, "COVERAGE OVER TIME", fill=theme["muted"], weight=600, spacing="0.08em"),
        headline_el(
            24,
            72,
            theme,
            [
                (fetchers[-1][1], "fetchers", theme["fetchers"]),
                (services[-1][1], "services", theme["services"]),
            ],
        ),
        text_el(right, 72, gained, fill=theme["muted"], size=12, anchor="end"),
    ]

    panels = (
        (fetchers, theme["fetchers"], 108, 236, True),
        (services, theme["services"], 268, 384, False),
    )
    top, bottom = panels[0][2], panels[-1][3]
    ticks = month_ticks(first, last)
    for tick in ticks:
        tx = x(tick)
        out.append(
            f'<line x1="{num(tx)}" y1="{top}" x2="{num(tx)}" y2="{bottom}" '
            f'stroke="{theme["grid"]}" stroke-width="1"/>'
        )
        if tx + 40 <= right:
            label = f"{tick:%b %Y}" if tick.month == 1 or tick == ticks[0] else f"{tick:%b}"
            out.append(text_el(tx + 4, bottom + 20, label, fill=theme["muted"]))

    for points, color, panel_top, panel_bottom, shade in panels:
        panel(
            out,
            theme,
            box=(left, panel_top, right, panel_bottom),
            x=x,
            last=last,
            points=points,
            color=color,
            shade=shade,
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
