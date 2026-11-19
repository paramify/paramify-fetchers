"""resource_inclusions across the Azure adopters, through each resource_exclusions test's own run_* harness: an empty
inclusion list changes nothing, and a tag: inclusion leaves out, as not_included, what rg:rg-out took out."""

from __future__ import annotations

import importlib.util
import inspect
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

import tag_index  # noqa: E402
from azure_common import subscription_of  # noqa: E402
from resource_exclusions import INCLUSIONS_ENV  # noqa: E402

HARNESS_FILES = sorted(Path(__file__).parent.glob("test_azure_resource_exclusions_*.py"))


def _harnesses():
    found = []
    for path in HARNESS_FILES:
        spec = importlib.util.spec_from_file_location(f"{path.stem}_for_inclusions", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name, fn in sorted(vars(module).items()):
            if name.startswith("run_") and inspect.isfunction(fn) and fn.__module__ == module.__name__ \
                    and list(inspect.signature(fn).parameters)[:3] == ["monkeypatch", "tmp_path", "patterns"]:
                found.append(pytest.param(fn, id=f"{path.stem.removeprefix('test_azure_resource_exclusions_')}.{name}"))
    return found


HARNESSES = _harnesses()
# Reasons a resource that carries its own tags follows its parent out on an exclusion, but not on not_included.
DEPENDENT_REASONS = {"environment_matched", "subnet_matched", "virtual_network_matched", "scale_set_matched",
                     "gateway_matched", "hub_excluded", "virtual_wan_matched", "virtual_hub_matched"}


class TaggedOutsideRgOut:
    """Every resource carries Boundary=FedRAMP except those in rg-out; the index holds every id it is asked about."""

    def __init__(self, loader=None):
        self.failures = []

    def entries(self, subscription_id):
        return {}

    def held(self, resource_id):
        return True if subscription_of(resource_id) else None

    def tags_of(self, resource_id):
        if not subscription_of(resource_id):
            return None
        return {} if "/resourcegroups/rg-out/" in f"{resource_id.lower()}/" else {"boundary": "FedRAMP"}


def _evidence(result):
    """(exit code, evidence) with the run's own clock readings blanked, so two runs compare equal."""
    code, evidence = result[0], result[1]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    clock = rf'"(?:{today}T[0-9:.]+|\d{{4}}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{{6}})(?:\+00:00|Z)?"'
    text = re.sub(clock, '"<now>"', json.dumps(evidence, default=str))
    return code, json.loads(text)


def _run(fn, monkeypatch, tmp_path, name, patterns, inclusions=None):
    if inclusions is None:
        monkeypatch.delenv(INCLUSIONS_ENV, raising=False)
    else:
        monkeypatch.setenv(INCLUSIONS_ENV, inclusions)
    out = tmp_path / name
    out.mkdir()
    return _evidence(fn(monkeypatch, out, patterns))


def _entries(evidence, **match):
    return sorted((e["kind"], (e.get("id") or "").lower()) for e in (evidence.get("results") or {}).get("excluded") or []
                  if all(e.get(k) == v for k, v in match.items()))


def _reasons(evidence, pattern):
    return sorted((e["kind"], (e.get("id") or "").lower(), e["reason"])
                  for e in evidence["results"]["excluded"] if e.get("pattern") == pattern)


@pytest.mark.parametrize("run", HARNESSES)
def test_an_empty_inclusion_list_changes_nothing(run, monkeypatch, tmp_path):
    assert _run(run, monkeypatch, tmp_path, "unset", "rg:rg-out") == \
        _run(run, monkeypatch, tmp_path, "empty", "rg:rg-out", inclusions="")


@pytest.mark.parametrize("run", HARNESSES)
def test_a_tag_inclusion_leaves_out_what_rg_out_took_out(run, monkeypatch, tmp_path):
    monkeypatch.setattr(tag_index, "TagIndex", TaggedOutsideRgOut)
    base_code, base = _run(run, monkeypatch, tmp_path, "excluded", "rg:rg-out")
    code, tagged = _run(run, monkeypatch, tmp_path, "included", None, inclusions="tag:Boundary=FedRAMP")
    assert code == base_code
    taken = _entries(base, pattern="rg:rg-out")
    assert taken, "the harness has nothing in rg-out"
    not_included, listed = set(_entries(tagged, reason="not_included")), set(_entries(tagged))
    for kind, rid, reason in _reasons(base, "rg:rg-out"):
        if reason in DEPENDENT_REASONS and "/resourcegroups/rg-out/" not in rid:
            # It carries its own tags, so its parent's not_included doesn't take it out.
            assert (kind, rid) not in listed, (kind, rid, reason)
        else:
            assert (kind, rid) in not_included, (kind, rid, reason)
    assert not _entries(tagged, reason="scope_unknown")
    summary = tagged["summary"]
    assert summary["resource_inclusion_patterns"] == ["tag:Boundary=FedRAMP"]
    assert all(summary[f"not_included_{k.removeprefix('excluded_')}"] is not None
               for k in summary if k.startswith("excluded_") and summary[k] is not None
               and f"not_included_{k.removeprefix('excluded_')}" in summary)
