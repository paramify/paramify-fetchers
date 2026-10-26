"""Contract gate: every fetcher.yaml and category file must satisfy its schema.

This is the merge gate the CI ``test`` job protects (SEC-36). Discovery
(``framework.config_loader``) validates every ``fetcher.yaml`` against
``fetcher_schema.json`` and every ``fetchers/_categories/*.yaml`` against
``category_schema.json``, and raises on any schema violation or duplicate
fetcher name. The public API surface *is* the contract (CLAUDE.md), so a change
that breaks a fetcher's declared shape must turn this suite red before it can
merge.

The per-file parametrized tests validate directly against the JSON Schema so a
failure names the offending file and field; the discovery tests exercise the
same path in aggregate (must not raise) and assert the duplicate-name and
on-disk/discovered-count invariants.

Run: ``pytest tests/test_contracts.py`` (needs an editable install:
``pip install -e .``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from framework.config_loader import discover_fetchers, discover_platforms
from framework.contract import DEFAULT_EVIDENCE_FREQUENCY, EVIDENCE_FREQUENCIES

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHERS_ROOT = REPO_ROOT / "fetchers"
SCHEMAS_ROOT = REPO_ROOT / "framework" / "schemas"


def _fetcher_yamls() -> list[Path]:
    """Every real fetcher.yaml, mirroring discover_fetchers' walk.

    category/<name>/fetcher.yaml, skipping any ``_``-prefixed dir (_shared,
    _categories, _template) at either level.
    """
    out: list[Path] = []
    for category_dir in sorted(FETCHERS_ROOT.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for fetcher_dir in sorted(category_dir.iterdir()):
            if not fetcher_dir.is_dir() or fetcher_dir.name.startswith("_"):
                continue
            yaml_path = fetcher_dir / "fetcher.yaml"
            if yaml_path.exists():
                out.append(yaml_path)
    return out


FETCHER_YAMLS = _fetcher_yamls()
CATEGORY_YAMLS = sorted((FETCHERS_ROOT / "_categories").glob("*.yaml"))


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMAS_ROOT / name).read_text())


def _rel_ids(paths: list[Path]) -> list[str]:
    return [str(p.relative_to(REPO_ROOT)) for p in paths]


def _format_errors(errors) -> str:
    return "\n".join(
        f"  {'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors
    )


def test_fetcher_yamls_discovered() -> None:
    """Sanity: the walk actually finds fetchers (guards an empty parametrize)."""
    assert FETCHER_YAMLS, "no fetcher.yaml files discovered under fetchers/"


@pytest.mark.parametrize("yaml_path", FETCHER_YAMLS, ids=_rel_ids(FETCHER_YAMLS))
def test_fetcher_yaml_matches_schema(yaml_path: Path) -> None:
    validator = Draft202012Validator(_load_schema("fetcher_schema.json"))
    data = yaml.safe_load(yaml_path.read_text())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    assert not errors, f"{yaml_path.name} violates fetcher_schema.json:\n{_format_errors(errors)}"


@pytest.mark.parametrize("yaml_path", CATEGORY_YAMLS, ids=_rel_ids(CATEGORY_YAMLS))
def test_category_yaml_matches_schema(yaml_path: Path) -> None:
    validator = Draft202012Validator(_load_schema("category_schema.json"))
    data = yaml.safe_load(yaml_path.read_text()) or {}
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    assert not errors, f"{yaml_path.name} violates category_schema.json:\n{_format_errors(errors)}"


def test_discovery_does_not_raise() -> None:
    """The aggregate gate: discovery validates + dedupes, raising on violations."""
    fetchers = discover_fetchers(REPO_ROOT)
    assert fetchers, "discover_fetchers returned nothing"
    discover_platforms(REPO_ROOT)  # must not raise on any category file


def test_fetcher_names_unique_and_complete() -> None:
    """Every fetcher.yaml on disk maps to exactly one discovered, uniquely named
    fetcher (discover_fetchers raises on a duplicate name before returning)."""
    fetchers = discover_fetchers(REPO_ROOT)
    assert len(fetchers) == len(FETCHER_YAMLS), (
        f"{len(FETCHER_YAMLS)} fetcher.yaml files on disk but "
        f"{len(fetchers)} discovered"
    )


# --------------------------------------------------------------------------- #
# Collection kinds. Both templates must satisfy the schema they teach against —
# a template that would be rejected at discovery teaches a shape that cannot run,
# and it is copied before anyone finds out.
# --------------------------------------------------------------------------- #

TEMPLATE_YAMLS = sorted(FETCHERS_ROOT.glob("_template*/fetcher.yaml"))


def test_templates_discovered() -> None:
    assert TEMPLATE_YAMLS, "no _template*/fetcher.yaml found"


@pytest.mark.parametrize("yaml_path", TEMPLATE_YAMLS, ids=_rel_ids(TEMPLATE_YAMLS))
def test_template_yaml_matches_schema(yaml_path: Path) -> None:
    """Placeholders like <category>_<short_name> are fine — the schema constrains
    structure, not naming, so this catches a template with a bad block."""
    validator = Draft202012Validator(_load_schema("fetcher_schema.json"))
    data = yaml.safe_load(yaml_path.read_text())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    assert not errors, f"{yaml_path} violates fetcher_schema.json:\n{_format_errors(errors)}"


def test_every_fetcher_declares_the_identity_its_kind_needs() -> None:
    """An evidence fetcher needs an evidence_set to reach an evidence set; an
    issue report needs an issue_report block to reach an assessment; an
    inventory needs an evidence_set for its pipeline to read. The schema
    enforces this per file — this asserts it across the discovered set, so a
    fetcher that would be silently ignored by both uploaders fails the suite.
    """
    missing: list[str] = []
    for name, f in discover_fetchers(REPO_ROOT).items():
        if f.is_issue_report:
            if f.issue_report is None or f.evidence_set is not None:
                missing.append(f"{name}: kind=issue_report but identity blocks are wrong")
        elif f.is_inventory:
            if f.evidence_set is None or f.issue_report is not None:
                missing.append(f"{name}: kind=inventory but identity blocks are wrong")
        elif f.is_discovery:
            if f.evidence_set is not None or f.issue_report is not None or f.ksis:
                missing.append(f"{name}: kind=discovery but declares an upload identity or ksis")
        elif f.issue_report is not None:
            missing.append(f"{name}: kind=evidence but declares an issue_report block")
    assert not missing, "\n".join(missing)


def test_every_evidence_fetcher_has_a_frequency() -> None:
    """A fetcher.yaml that omits evidence_set.frequency gets the default, so every
    evidence set the uploader creates carries one."""
    bad = [
        f"{name}: {f.evidence_set.frequency!r}"
        for name, f in discover_fetchers(REPO_ROOT).items()
        if f.evidence_set and f.evidence_set.frequency not in EVIDENCE_FREQUENCIES
    ]
    assert not bad, "\n".join(bad)


def _script_line(yaml_path: Path, spec: dict) -> str:
    return f"Script: {yaml_path.parent.parent.name}/{yaml_path.parent.name}/{spec['runtime']['entry']}"


def test_instructions_open_with_the_entry_path() -> None:
    """Instructions open with `Script: <category>/<short_name>/<entry>`, ended by a period or
    the end of the line, so a reader can find the code."""
    bad: list[str] = []
    for yaml_path in FETCHER_YAMLS:
        spec = yaml.safe_load(yaml_path.read_text())
        text = (spec.get("evidence_set") or {}).get("instructions") or ""
        expected = _script_line(yaml_path, spec)
        if text and not (text.startswith(expected + ".") or text.split("\n", 1)[0] == expected):
            bad.append(f"{yaml_path.parent.relative_to(FETCHERS_ROOT)}: want instructions to open with {expected!r}")
    assert not bad, "\n".join(bad)


# --------------------------------------------------------------------------- #
# Description and instructions text (docs/authoring_fetcher_guide.md). Paramify shows
# both as plain text, so the layout is checked here for each converted fetcher;
# add a category (or category/short_name) once its fetchers are converted.
# --------------------------------------------------------------------------- #

TEXT_FORMAT_FETCHERS = ("azure/alert_rules", "azure/monitor_fired_alerts", "oci")
MAX_DESCRIPTION_WORDS = 30
FIELD_LINE = re.compile(r"^- (\S+) — \S")
BREAKDOWN_LINE = re.compile(r"^  - \S+ \(\S.*\)$")
COMMAND_LINE = re.compile(r"^- \S.* — \S")


def _matches(yaml_path: Path, prefix: str) -> bool:
    rel = yaml_path.parent.relative_to(FETCHERS_ROOT).as_posix()
    return rel == prefix or rel.startswith(prefix + "/")


CONVERTED_YAMLS = [y for y in FETCHER_YAMLS if any(_matches(y, p) for p in TEXT_FORMAT_FETCHERS)]


def _description_problems(label: str, desc: str, name: str) -> list[str]:
    desc = " ".join(desc.split())
    problems = []
    if len(desc.split()) > MAX_DESCRIPTION_WORDS:
        problems.append(f"{label} has {len(desc.split())} words; at most {MAX_DESCRIPTION_WORDS}")
    if not desc.endswith(".") or re.search(r"(?<!e\.g)(?<!i\.e)[.!?]\s", desc):
        problems.append(f"{label} is not one sentence ending in a period")
    if name in desc:
        problems.append(f"{label} repeats the fetcher's name")
    return problems


def _text_format_problems(yaml_path: Path, spec: dict) -> list[str]:
    es = spec.get("evidence_set") or {}
    problems = _description_problems("description", spec.get("description") or "", spec["name"])
    if es.get("description"):
        problems += _description_problems("evidence_set.description", es["description"], spec["name"])
    if not es:
        return problems  # discovery fetchers and issue reports carry no evidence set

    text = es.get("instructions") or ""
    if "`" in text or "**" in text:
        problems.append("instructions use markdown (backticks or **); Paramify shows them as typed")
    blocks = [b.split("\n") for b in text.strip("\n").split("\n\n")]
    labels = [b[0] for b in blocks]
    if labels[0] != _script_line(yaml_path, spec):
        problems.append(f"instructions do not open with {_script_line(yaml_path, spec)!r} on a line of its own")
    order_ok = (
        len(labels) >= 4 and labels[1].startswith("Access: ")
        and labels[2] == "Commands Executed:" and labels[3].startswith("Output: ")
    )
    if not order_ok:
        problems.append("after Script come Access, then 'Commands Executed:' on its own line, then Output, "
                        f"each a blank line apart; got {[lab[:20] for lab in labels[1:4]]}")
        return problems
    if len(blocks[2]) < 2 or any(not COMMAND_LINE.match(ln) for ln in blocks[2][1:]):
        problems.append("each Commands Executed line must read '- <call> — <why>'")
    if len(blocks[3]) > 1 or " — " not in labels[3]:
        problems.append("Output must be one line: '<file> — <what it holds>'")
    rest = blocks[4:]
    if rest:
        if rest[0] != ["Summary fields:"] or len(rest) < 2:
            problems.append("after Output comes 'Summary fields:' on its own, then at least one question group")
            return problems
        seen: set[str] = set()
        for group in rest[1:]:
            if not group[0].endswith("?"):
                problems.append(f"summary group must start with a question: {group[0]!r}")
            lines = group[1:]
            # a breakdown's values sit on indented lines under a field line ending in ':'
            in_breakdown = [i > 0 and (lines[i - 1].rstrip().endswith(":") or bool(BREAKDOWN_LINE.match(lines[i - 1])))
                            for i in range(len(lines))]
            if not lines or any(
                not (FIELD_LINE.match(ln) or (in_breakdown[i] and BREAKDOWN_LINE.match(ln)))
                for i, ln in enumerate(lines)
            ):
                problems.append(f"each summary field line must read '- <field> — <meaning>', with any breakdown "
                                f"values under a line ending in ':' as '  - <value> (<meaning>)', under {group[0]!r}")
            if any(ln.rstrip().endswith(":") and not (i + 1 < len(lines) and BREAKDOWN_LINE.match(lines[i + 1]))
                   for i, ln in enumerate(lines)):
                problems.append(f"a summary field line ending in ':' needs its values below it, under {group[0]!r}")
            for ln in group[1:]:
                m = FIELD_LINE.match(ln)
                if m and m.group(1) in seen:
                    problems.append(f"summary field {m.group(1)} is listed twice")
                if m:
                    seen.add(m.group(1))
    return problems


def test_text_format_fetchers_exist() -> None:
    """Every TEXT_FORMAT_FETCHERS entry names real fetchers, so a typo can't switch the check off."""
    assert TEXT_FORMAT_FETCHERS
    missing = [p for p in TEXT_FORMAT_FETCHERS if not any(_matches(y, p) for y in FETCHER_YAMLS)]
    assert not missing, f"no fetcher matches {missing}"


@pytest.mark.parametrize("yaml_path", CONVERTED_YAMLS, ids=_rel_ids(CONVERTED_YAMLS))
def test_converted_fetcher_text_follows_the_format(yaml_path: Path) -> None:
    spec = yaml.safe_load(yaml_path.read_text())
    problems = _text_format_problems(yaml_path, spec)
    assert not problems, f"{yaml_path.parent.relative_to(FETCHERS_ROOT)}:\n  " + "\n  ".join(problems)


_ALERT_RULES_YAML = FETCHERS_ROOT / "azure" / "alert_rules" / "fetcher.yaml"
_GOOD_TEXT = """Script: azure/alert_rules/fetcher.py

Access: Reader on the subscription.

Commands Executed:
- GET Microsoft.Insights/metricAlerts — metric alert rules

Output: azure_alert_rules_<subscription>.json — each alert rule and whether it reaches a person.

Summary fields:

Which rules exist?
- total_rules — Number of alert rules
- rules_by_kind — Number of alert rules for each kind:
  - metric (a metric alert rule)
  - log (a log search alert rule)
"""
_BREAKDOWN = "for each kind:\n  - metric (a metric alert rule)\n  - log (a log search alert rule)"


@pytest.mark.parametrize(("old", "new", "es_description", "problem"), [
    (None, None, None, None),
    ("for each kind:\n", "for each kind: \n", None, None),
    ("- total_rules — Number", "- total_rules: Number", None, "each summary field line"),
    (_BREAKDOWN, "for each kind:", None, "needs its values below it"),
    (_BREAKDOWN, "for each kind: ", None, "needs its values below it"),
    ("  - metric", "- metric", None, "each summary field line"),
    ("alert rules\n- rules_by_kind", "alert rules\n  - extra (no parent)\n- rules_by_kind", None,
     "each summary field line"),
    ("- rules_by_kind — Number of alert rules for each kind:", "- total_rules — Number of rules for each kind:",
     None, "listed twice"),
    ("Script: azure/alert_rules/fetcher.py", "Script: fetcher.py", None, "do not open with"),
    ("metric alert rules\n", "`metric` alert rules\n", None, "markdown"),
    ("Which rules exist?", "Which rules exist", None, "must start with a question"),
    (None, None, "Shows rules. And more.", "evidence_set.description is not one sentence"),
])
def test_text_format_check_catches_each_break(old, new, es_description, problem) -> None:
    """The layout check itself, on a known-good text and one break at a time."""
    text = _GOOD_TEXT if old is None else _GOOD_TEXT.replace(old, new, 1)
    assert old is None or text != _GOOD_TEXT
    spec = {"name": "azure_alert_rules", "runtime": {"type": "python", "entry": "fetcher.py"},
            "description": "Shows every alert rule and whether it reaches a person.",
            "evidence_set": {"reference_id": "EVD-X", "name": "X", "instructions": text}}
    if es_description:
        spec["evidence_set"]["description"] = es_description
    problems = _text_format_problems(_ALERT_RULES_YAML, spec)
    if problem is None:
        assert problems == []
    else:
        assert any(problem in p for p in problems), problems


def test_frequency_enum_matches_the_contract() -> None:
    """The schema enum and the Python constant are two copies of Paramify's list;
    they must not drift."""
    schema = json.loads((SCHEMAS_ROOT / "fetcher_schema.json").read_text())
    freq = schema["properties"]["evidence_set"]["properties"]["frequency"]
    assert tuple(freq["enum"]) == EVIDENCE_FREQUENCIES
    assert freq["default"] == DEFAULT_EVIDENCE_FREQUENCY == "THREE_DAY"


def test_schema_rejects_an_unknown_frequency() -> None:
    validator = Draft202012Validator(json.loads((SCHEMAS_ROOT / "fetcher_schema.json").read_text()))
    doc = {
        "name": "x_y", "version": "0.1.0", "description": "d",
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "json", "path": "o.json"},
        "secrets": [],
        "evidence_set": {"reference_id": "EVD-X", "name": "X", "frequency": "EVERY_THREE_DAYS"},
    }
    assert list(validator.iter_errors(doc))
    doc["evidence_set"]["frequency"] = "THREE_DAY"
    assert not list(validator.iter_errors(doc))


def test_issue_report_template_varies_its_filename_per_target() -> None:
    """The template must derive its output filename from the fanout target.

    Every target of a fanout run writes into one issue-reports/ directory, and the
    runner detects outputs by diffing that directory around each invocation. A
    template that hardcodes the filename teaches a fetcher where target 2
    overwrites target 1 and is then recorded as having produced nothing — see
    tests/test_issue_reports.py::test_a_fixed_filename_collapses_a_fanout_run.
    Templates are copied before anyone finds out, so the convention is gated here.
    """
    src = (FETCHERS_ROOT / "_template_issue_report" / "fetcher.py").read_text()
    assert "def target_suffix(" in src, "the template dropped its target_suffix helper"
    assigns = [ln for ln in src.splitlines() if ln.strip().startswith("output_path =")]
    assert assigns, "the template no longer assigns output_path"
    assert all("target_suffix()" in ln for ln in assigns), (
        "the template builds output_path from a fixed name:\n  "
        + "\n  ".join(assigns)
    )


def test_issue_reports_declare_an_intakeable_format() -> None:
    """Paramify's assessment intake accepts only csv/json/xml/nessus, so any other
    format means a report that collects and can never be uploaded."""
    intakeable = {"csv", "json", "xml", "nessus"}
    bad = [
        f"{name}: output.type={f.output_type}"
        for name, f in discover_fetchers(REPO_ROOT).items()
        if f.is_issue_report and f.output_type not in intakeable
    ]
    assert not bad, "\n".join(bad)
