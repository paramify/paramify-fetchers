"""Comparator inputs: which ones are valid, and the order a run takes.

A comparator declares `depends_on`. It runs after those fetchers, in the same
run, and reads the files they wrote. See docs/comparators.md.
"""

from collections import Counter
from typing import List, Mapping, Sequence

from framework.contract import Fetcher, ManifestEntry

# The kinds whose output is an enveloped JSON evidence file a comparator can read.
INPUT_KINDS = ("evidence", "inventory")


def problems(fetchers: Mapping[str, Fetcher]) -> List[str]:
    """Why the declared inputs can't run: unknown names, inputs that write no JSON evidence, cycles."""
    out: List[str] = []
    for name in sorted(fetchers):
        for dep in fetchers[name].depends_on:
            src = fetchers.get(dep)
            if src is None:
                out.append(f"{name}: depends_on names an unknown fetcher: {dep}")
            elif src.kind not in INPUT_KINDS or src.output_type != "json":
                out.append(
                    f"{name}: depends_on {dep}, which writes no JSON evidence "
                    f"(kind {src.kind}, output {src.output_type})"
                )
    return out + _cycles(fetchers)


def _cycles(fetchers: Mapping[str, Fetcher]) -> List[str]:
    visiting, done = set(), set()
    found: List[str] = []

    def visit(path: List[str]) -> None:
        name = path[-1]
        visiting.add(name)
        for dep in fetchers[name].depends_on:
            if dep not in fetchers or dep in done:
                continue
            if dep in visiting:
                cycle = path[path.index(dep):] + [dep]
                found.append("dependency cycle: " + " -> ".join(cycle))
            else:
                visit(path + [dep])
        visiting.discard(name)
        done.add(name)

    for name in sorted(fetchers):
        if name not in done:
            visit([name])
    return found


def order(entries: Sequence[ManifestEntry], fetchers: Mapping[str, Fetcher]) -> List[ManifestEntry]:
    """Manifest order, except that a comparator moves after every input the manifest holds."""
    left = Counter(e.use for e in entries)
    remaining = list(entries)
    out: List[ManifestEntry] = []
    while remaining:
        ready = next(
            (i for i, e in enumerate(remaining)
             if all(left[d] == 0 for d in _inputs(fetchers, e.use))),
            None,
        )
        if ready is None:
            # Only a cycle gets here; the completion check fails what is left.
            out.extend(remaining)
            break
        entry = remaining.pop(ready)
        left[entry.use] -= 1
        out.append(entry)
    return out


def unfinished(fetcher: Fetcher, pending: Mapping[str, int]) -> List[str]:
    """The inputs the manifest holds that haven't finished in this run yet."""
    return [d for d in fetcher.depends_on if pending.get(d, 0) > 0]


def _inputs(fetchers: Mapping[str, Fetcher], use: str) -> List[str]:
    f = fetchers.get(use)
    return list(f.depends_on) if f is not None else []
