"""Comparator inputs: which ones are valid, and the order a run takes.

A comparator declares `depends_on`. A run takes every fetcher first, then every
comparator, and a comparator reads the files its inputs wrote in that run. See
docs/comparators.md.
"""

from collections import Counter
from typing import Dict, List, Mapping, Sequence

from framework.contract import Fetcher, ManifestEntry

# The kinds whose output is an enveloped JSON evidence file a comparator can read.
INPUT_KINDS = ("evidence", "inventory")


def problems(fetchers: Mapping[str, Fetcher]) -> Dict[str, str]:
    """Each comparator that can't run, with why: an unknown input, one that writes no
    JSON evidence, or a cycle. `validate` and `run` report these on the entry."""
    out: Dict[str, str] = {}
    for name in sorted(fetchers):
        for dep in fetchers[name].depends_on:
            src = fetchers.get(dep)
            if src is None:
                out[name] = f"depends_on names an unknown fetcher: {dep}"
            elif src.kind not in INPUT_KINDS or src.output_type != "json":
                out[name] = (
                    f"depends_on {dep}, which writes no JSON evidence "
                    f"(kind {src.kind}, output {src.output_type})"
                )
            else:
                continue
            break
    for cycle in _cycles(fetchers):
        for name in cycle[:-1]:
            out.setdefault(name, "dependency cycle: " + " -> ".join(cycle))
    return out


def _cycles(fetchers: Mapping[str, Fetcher]) -> List[List[str]]:
    visiting, done = set(), set()
    found: List[List[str]] = []

    def visit(path: List[str]) -> None:
        name = path[-1]
        visiting.add(name)
        for dep in fetchers[name].depends_on:
            if dep not in fetchers or dep in done:
                continue
            if dep in visiting:
                found.append(path[path.index(dep):] + [dep])
            else:
                visit(path + [dep])
        visiting.discard(name)
        done.add(name)

    for name in sorted(fetchers):
        if name not in done:
            visit([name])
    return found


def order(entries: Sequence[ManifestEntry], fetchers: Mapping[str, Fetcher]) -> List[ManifestEntry]:
    """Two phases: every fetcher in manifest order, then every comparator, each after
    any comparator it reads and otherwise in manifest order."""
    def is_comparator(e: ManifestEntry) -> bool:
        return e.use in fetchers and fetchers[e.use].is_comparator

    out = [e for e in entries if not is_comparator(e)]
    comparators = [e for e in entries if is_comparator(e)]
    left = Counter(e.use for e in comparators)
    while comparators:
        ready = next(
            (i for i, e in enumerate(comparators)
             if all(left[d] == 0 for d in fetchers[e.use].depends_on)),
            None,
        )
        if ready is None:
            # Only a cycle gets here, and `run` skips every entry in one.
            out.extend(comparators)
            break
        entry = comparators.pop(ready)
        left[entry.use] -= 1
        out.append(entry)
    return out


def unfinished(fetcher: Fetcher, pending: Mapping[str, int]) -> List[str]:
    """The inputs the manifest holds that haven't finished in this run yet."""
    return [d for d in fetcher.depends_on if pending.get(d, 0) > 0]
