#!/usr/bin/env python3
"""Vendor AWS Config rule-to-control mappings from official AWS documentation."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen


SOURCES = {
    "fedramp_low": {
        "title": "FedRAMP Low Baseline Controls",
        "url": "https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-fedramp-low.html",
    },
    "fedramp_moderate": {
        "title": "FedRAMP Moderate Baseline Controls",
        "url": "https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-fedramp-moderate.html",
    },
    "nist_800_53_rev_5": {
        "title": "NIST SP 800-53 Revision 5",
        "url": "https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist-800-53_rev_5.html",
    },
}

# AWS renamed several sample-template ConfigRuleName values without retaining
# the old names in the documentation mapping tables. Keep the aliases explicit
# so evidence generated from older vendored packs still maps to the same rule.
RULE_ALIASES = {
    "cloud-trail-enabled": "cloudtrail-enabled",
    "ec2-instance-managed-by-ssm": "ec2-instance-managed-by-systems-manager",
    "incoming-ssh-disabled": "restricted-ssh",
    "instances-in-vpc": "ec2-instances-in-vpc",
    "multi-region-cloud-trail-enabled": "multi-region-cloudtrail-enabled",
}


def _clean(value: str) -> str:
    return " ".join(value.split())


class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in {"th", "td"} and self._row is not None:
            self._cell = []

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"th", "td"} and self._cell is not None and self._row is not None:
            self._row.append(_clean(" ".join(self._cell)))
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            if self._row:
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None


def parse_mapping(html: str, framework: str, title: str, source_url: str) -> dict[str, object]:
    parser = _TableParser()
    parser.feed(html)

    mapping_rows: list[list[str]] | None = None
    for table in parser.tables:
        if not table:
            continue
        headers = [cell.casefold() for cell in table[0]]
        if headers[:3] == ["control id", "control description", "aws config rule"]:
            mapping_rows = table[1:]
            break
    if mapping_rows is None:
        raise ValueError(f"AWS control mapping table was not found for {framework}")

    rules: defaultdict[str, set[str]] = defaultdict(set)
    descriptions: dict[str, str] = {}
    for row in mapping_rows:
        if len(row) < 3:
            continue
        control_id = re.sub(r"\s+(?=\()", "", _clean(row[0]))
        description = _clean(row[1])
        rule_name = _clean(row[2]).lower()
        if not re.match(r"^[A-Z]{2,3}-\d", control_id) or not rule_name:
            continue
        rules[rule_name].add(control_id)
        descriptions.setdefault(control_id, description)

    if not rules:
        raise ValueError(f"AWS control mapping table was empty for {framework}")

    rule_index = {rule: sorted(controls) for rule, controls in sorted(rules.items())}
    control_index = {
        control: {
            "description": descriptions.get(control, ""),
            "config_rules": sorted(rule for rule, controls in rules.items() if control in controls),
        }
        for control in sorted(descriptions)
    }
    return {
        "framework": framework,
        "title": title,
        "source_url": source_url,
        "disclaimer": "AWS sample mappings do not guarantee compliance; validate applicability for your environment.",
        "rule_count": len(rule_index),
        "control_count": len(control_index),
        "aliases": {
            alias: canonical
            for alias, canonical in RULE_ALIASES.items()
            if canonical in rule_index
        },
        "rules": rule_index,
        "controls": control_index,
    }


def download(url: str) -> str:
    request = Request(url, headers={"User-Agent": "paramify-fetchers-control-mapping-sync/1.0"})
    with urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "control_mappings",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for framework, source in SOURCES.items():
        document = parse_mapping(download(source["url"]), framework, source["title"], source["url"])
        output = args.output_dir / f"{framework}.json"
        output.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        print(f"{framework}: {document['rule_count']} rules, {document['control_count']} controls -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
