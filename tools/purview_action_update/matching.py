"""Joining Purview Improvement Actions to Paramify Solution Capabilities.

One Improvement Action is one Solution Capability, and the join key is the
name: a SolCap's `name` is byte-identical to the Purview Action Title. In this
program all 463 are unique on both sides, so the join should be total — which
makes any row that fails to match a data-quality finding worth surfacing, not a
row to quietly skip.

Exact matches are applied. Near matches — identical once case and surrounding
whitespace are normalized — are detected and REPORTED but not applied unless
explicitly accepted, because a near match means the two systems have drifted
and someone should decide which spelling is right rather than have this tool
pick one while writing into a live assessment.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional


def normalize(name: Any) -> str:
    """Casefold and collapse whitespace — the drifts that actually occur."""
    return re.sub(r"\s+", " ", str(name or "").strip()).casefold()


@dataclass
class MatchResult:
    exact: dict[str, dict[str, Any]] = field(default_factory=dict)
    near: dict[str, dict[str, Any]] = field(default_factory=dict)
    unmatched_actions: list[str] = field(default_factory=list)
    unmatched_capabilities: list[str] = field(default_factory=list)
    duplicate_action_names: dict[str, int] = field(default_factory=dict)
    duplicate_capability_names: dict[str, int] = field(default_factory=dict)
    ambiguous: list[str] = field(default_factory=list)

    def lookup(self, action_name: str, *, accept_near: bool) -> Optional[dict[str, Any]]:
        hit = self.exact.get(action_name)
        if hit is not None:
            return hit
        if accept_near:
            return self.near.get(action_name)
        return None


def build(action_names: list[str], capabilities: list[dict[str, Any]]) -> MatchResult:
    result = MatchResult()

    action_counts: dict[str, int] = defaultdict(int)
    for name in action_names:
        action_counts[name] += 1
    result.duplicate_action_names = {n: c for n, c in action_counts.items() if c > 1}

    by_name: dict[str, dict[str, Any]] = {}
    name_counts: dict[str, int] = defaultdict(int)
    for capability in capabilities:
        name = str(capability.get("name") or "")
        name_counts[name] += 1
        by_name.setdefault(name, capability)
    result.duplicate_capability_names = {n: c for n, c in name_counts.items() if c > 1}

    # A normalized key mapping to two different capabilities cannot be resolved
    # automatically, so it is excluded from near-matching entirely.
    normalized: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for name, capability in by_name.items():
        normalized[normalize(name)].append(capability)

    matched_names: set[str] = set()
    for action_name in dict.fromkeys(action_names):
        if action_name in by_name:
            result.exact[action_name] = by_name[action_name]
            matched_names.add(str(by_name[action_name].get("name") or ""))
            continue
        candidates = normalized.get(normalize(action_name), [])
        if len(candidates) == 1:
            result.near[action_name] = candidates[0]
            matched_names.add(str(candidates[0].get("name") or ""))
        elif len(candidates) > 1:
            result.ambiguous.append(action_name)
            result.unmatched_actions.append(action_name)
        else:
            result.unmatched_actions.append(action_name)

    result.unmatched_capabilities = sorted(
        name for name in by_name if name not in matched_names
    )
    return result
