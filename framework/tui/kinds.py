"""The kinds of fetcher, as the console names and groups them.

A fetcher asserts a configuration state (evidence), lists every asset of some
kind for Paramify's Inventory (an inventory — see docs/inventory_fetchers.md),
or hands over a report a scanner already produced (an issue report — see
docs/issue_report_fetchers.md). The kind, not the platform, decides where the output goes, whether it is
enveloped, and which key sends it, so everywhere the console lists fetchers it
groups by kind first and platform second.

The console calls the second kind **scan reports**, the word the guides use and
an operator recognises. `issue_report` stays the contract's word for it: it is
the `kind:` value in fetcher.yaml and the key the descriptors carry.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

EVIDENCE = "evidence"
INVENTORY = "inventory"
SCAN_REPORT = "issue_report"

# kind -> (section heading, singular noun), in display order.
_NAMES: Dict[str, Tuple[str, str]] = {
    EVIDENCE: ("Evidence", "evidence"),
    INVENTORY: ("Inventory", "inventory"),
    SCAN_REPORT: ("Scan reports", "scan report"),
}

Section = Tuple[str, List[Tuple[str, List[dict]]]]


def kind_of(fetcher: Optional[dict]) -> str:
    """A descriptor's kind; one without the key predates kinds, so it is evidence."""
    return (fetcher or {}).get("kind") or EVIDENCE


def heading(kind: str) -> str:
    """The section heading for a kind ("Scan reports")."""
    return _NAMES.get(kind, (kind, kind))[0]


def noun(kind: str) -> str:
    """The singular name for one fetcher of a kind ("scan report")."""
    return _NAMES.get(kind, (kind, kind))[1]


def sections(
    catalog_data: Optional[dict], keep: Optional[Callable[[dict], bool]] = None
) -> List[Section]:
    """The catalog grouped by kind, then platform: [(kind, [(category, [descriptor])])].

    Kinds come in display order (evidence first), categories and fetchers in the
    catalog's own order. A platform that ships both kinds appears under each, with
    only that kind's fetchers. Anything `keep` rejects is left out, and a category
    or kind left with nothing is dropped rather than shown empty.
    """
    by_kind: Dict[str, List[Tuple[str, List[dict]]]] = {}
    for cat in (catalog_data or {}).get("categories") or []:
        split: Dict[str, List[dict]] = {}
        for f in cat["fetchers"]:
            if keep is None or keep(f):
                split.setdefault(kind_of(f), []).append(f)
        for kind, fetchers in split.items():
            by_kind.setdefault(kind, []).append((cat["name"], fetchers))

    # Known kinds in their fixed order, then anything newer in first-seen order,
    # so a kind this module has not heard of still shows up rather than vanishing.
    order = [k for k in _NAMES if k in by_kind] + [k for k in by_kind if k not in _NAMES]
    return [(k, by_kind[k]) for k in order]
