"""Pattern-list config fields (type: patterns): parsing, grammar, the runner's hand-off, validate and the CLI."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sys
from pathlib import Path

import pytest
from dotenv import load_dotenv
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from framework import api, patterns
from framework.cli import app
from framework.config_loader import discover_fetchers, discover_platforms
from framework.contract import (
    ConfigField,
    Fetcher,
    ManifestEntry,
    PlatformConfig,
    PlatformSpec,
    TargetField,
    TargetInstance,
)
from framework.envelope import wrap_outputs
from framework.runner.executor import (
    _apply_config,
    config_patterns,
    merged_config,
    run_entry,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

from scope_exclusions import parse_patterns  # noqa: E402

RESOURCE = ("rg", "location", "id")
runner = CliRunner()


def field(name="exclusions", env="EXCLUSIONS", prefixes=RESOURCE, bare=False) -> ConfigField:
    return ConfigField(name=name, type="patterns", env=env, prefixes=prefixes, bare=bare)


def fetcher(tmp_path, **schema) -> Fetcher:
    return Fetcher(name="t_fetcher", version="0.1.0", description="t", category="testcat", runtime_type="python",
                   runtime_entry="fetcher.py", runtime_timeout=None, output_type="json", output_path="out.json",
                   output_aggregation=None, secrets=[], supports_targets=False, target_schema={}, path=tmp_path,
                   config_schema=schema or {"exclusions": field()}, evidence_set=None)


# --------------------------------------------------------------------------- #
# parse / check / hand-off
# --------------------------------------------------------------------------- #

def test_a_list_holds_patterns_and_pattern_reason_pairs():
    items, problems = patterns.parse(["rg:rg-a", {"pattern": " location:eastus2 ", "reason": " Out of scope "},
                                      {"pattern": "id:/x", "reason": ""}])
    assert problems == []
    assert items == [patterns.Item("rg:rg-a"), patterns.Item("location:eastus2", "Out of scope"),
                     patterns.Item("id:/x")]


@pytest.mark.parametrize("value, problem", [
    ({"pattern": "rg:a"}, "expected a list of patterns, got dict"),
    ([3], "item 1 is int"),
    ([{"pattern": "rg:a", "note": "x"}], "item 1 has note; an item takes only pattern and reason"),
    ([{"reason": "x"}], "item 1 has no pattern"),
    ([{"pattern": "rg:a", "reason": 5}], "item 1's reason is int"),
    (["", "www"], "item 1 is empty"),
])
def test_a_badly_shaped_value_is_refused(value, problem):
    assert any(p.startswith(problem) for p in patterns.problems(value, RESOURCE, False))


@pytest.mark.parametrize("pattern, problem", [
    ("route:qa-*", "has the unknown prefix 'route:'; this field takes rg:, location:, id:"),
    ("eastus2", "needs one of the prefixes rg:, location:, id:"),
    ("rg:", "has nothing after its prefix"),
    ("location:Region East", "has a space or a comma"),
    ("rg:a,rg:b", "has a space or a comma"),
    ("rg:${env:X}", "${env:} references aren't read"),
])
def test_the_grammar_refuses_what_the_fetcher_would_fail_on(pattern, problem):
    [found] = patterns.check([patterns.Item(pattern)], RESOURCE, bare=False)
    assert problem in found


def test_prefixes_compare_without_case_and_duplicates_are_refused():
    assert patterns.check([patterns.Item("Location:eastus2")], RESOURCE, False) == []
    assert patterns.check([patterns.Item("rg:a"), patterns.Item("RG:A")], RESOURCE, False) == [
        "pattern 'RG:A' is listed twice"]


def test_a_field_with_no_prefixes_refuses_any_prefix():
    assert "this field takes no prefixes" in patterns.check([patterns.Item("route:qa")], (), True)[0]
    assert patterns.check([patterns.Item("www")], (), True) == []


@pytest.mark.parametrize("value", ["${env:AZURE_RESOURCE_EXCLUSIONS}", "rg:a ${env:MORE}"])
def test_an_env_reference_is_refused_as_the_whole_value_or_part_of_it(value):
    assert patterns.problems(value, RESOURCE, False) == [patterns.ENV_REF_REFUSAL]


@pytest.mark.parametrize("raw", [
    "rg:a, location:b", "rg:a location:b id:/subscriptions/0/resourceGroups/rg-c", " route: qa-*, Route:legacy ",
    "qa.*,dev.*", "www  *.example.com.",
])
def test_a_string_reads_as_the_fetchers_own_parser_reads_it(raw):
    assert [i.pattern for i in patterns.parse(raw)[0]] == parse_patterns(raw)
    assert parse_patterns(patterns.to_env(raw)) == parse_patterns(raw)


def test_a_list_reaches_the_fetcher_as_one_comma_separated_string():
    value = ["rg:a", {"pattern": "location:b", "reason": "why"}, "route:qa-*"]
    assert patterns.to_env(value) == "rg:a,location:b,route:qa-*"
    assert parse_patterns(patterns.to_env(value)) == ["rg:a", "location:b", "route:qa-*"]
    assert patterns.display(value) == "rg:a, location:b, route:qa-*"
    assert patterns.from_cli("rg:a, location:b") == ["rg:a", "location:b"]


# --------------------------------------------------------------------------- #
# runner
# --------------------------------------------------------------------------- #

def test_the_runner_injects_the_list_and_an_entry_list_replaces_the_platform_list(tmp_path):
    f = fetcher(tmp_path)
    platform = PlatformConfig(config={"exclusions": [{"pattern": "location:a", "reason": "boundary"}, "rg:b"]})
    env: dict = {}
    _apply_config(env, f, None, platform, ManifestEntry(use="x"))
    assert env["EXCLUSIONS"] == "location:a,rg:b"
    env = {}
    _apply_config(env, f, None, platform, ManifestEntry(use="x", config={"exclusions": ["rg:c"]}))
    assert env["EXCLUSIONS"] == "rg:c"
    env = {}
    _apply_config(env, f, None, platform, ManifestEntry(use="x", config={"exclusions": []}))
    assert env["EXCLUSIONS"] == ""


def test_an_invalid_pattern_stops_the_entry_before_the_fetcher_runs(tmp_path):
    with pytest.raises(RuntimeError, match="unknown prefix 'route:'"):
        _apply_config({}, fetcher(tmp_path), None, None, ManifestEntry(use="x", config={"exclusions": ["route:a"]}))


def test_an_env_reference_is_never_resolved_even_to_a_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_PATTERNS", "rg:a")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "leak-probe-aaaaaaaa")
    for var in ("MY_PATTERNS", "PARAMIFY_UPLOAD_API_TOKEN"):
        entry = ManifestEntry(use="x", config={"exclusions": f"${{env:{var}}}"})
        merged = merged_config(fetcher(tmp_path), None, None, entry)
        assert merged.errors == {"exclusions": f"config 'exclusions': {patterns.ENV_REF_REFUSAL}"}
        assert merged.referenced == {} and merged.values["exclusions"] == f"${{env:{var}}}"
        with pytest.raises(RuntimeError, match="aren't read for a pattern list"):
            _apply_config({}, fetcher(tmp_path), None, None, entry)


def test_a_list_for_a_field_that_is_not_patterns_fails_validate_and_the_run():
    # A category-wide list reaching a fetcher that declares the key a string.
    fetchers, platforms = discover_fetchers(REPO_ROOT), discover_platforms(REPO_ROOT)
    f = fetchers["azure_alert_rules"]
    string_field = dataclasses.replace(f.config_schema["resource_exclusions"], type="string", prefixes=(), bare=True)
    fetchers["azure_alert_rules"] = dataclasses.replace(
        f, config_schema={**f.config_schema, "resource_exclusions": string_field})
    boundary = [{"pattern": "rg:dev-*", "reason": "Outside the boundary"}]
    m = manifest("azure_alert_rules", "azure_key_vault_configuration", platform={"resource_exclusions": boundary})
    problem = ("config 'resource_exclusions' is a string field of azure_alert_rules, but platforms.azure.config "
               "gives it a list; only a `type: patterns` field takes a list")
    assert api.validate(m, REPO_ROOT, fetchers, platforms) == [f"azure_alert_rules: {problem}"]
    with pytest.raises(RuntimeError, match=re.escape(f"azure_alert_rules: {problem}")):
        _apply_config({}, fetchers["azure_alert_rules"], platforms["azure"],
                      PlatformConfig(config={"resource_exclusions": boundary}), ManifestEntry(use="azure_alert_rules"))


def test_a_map_for_a_field_that_is_not_patterns_is_refused(tmp_path):
    f = fetcher(tmp_path, n=ConfigField(name="n", type="integer", env="N"))
    merged = merged_config(f, None, None, ManifestEntry(use="x", config={"n": {"a": 1}}))
    assert merged.errors == {"n": "config 'n' is an integer field of t_fetcher, but t_fetcher.config gives it a map; "
                                  "only a `type: patterns` field takes a list"}


def test_an_unset_pattern_list_reaches_the_fetcher_empty_so_no_env_file_or_shell_fills_it(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCLUSIONS", "rg:from-the-shell")
    env: dict = {}
    f = fetcher(tmp_path, exclusions=field(), other=ConfigField(name="other", env="OTHER"))
    _apply_config(env, f, None, PlatformConfig(passthrough_env=["EXCLUSIONS"]), ManifestEntry(use="x"))
    assert env == {"EXCLUSIONS": ""}
    # What the fetcher's load_dotenv() does with it: a set variable, even an empty one, isn't overridden.
    monkeypatch.setenv("EXCLUSIONS", env["EXCLUSIONS"])
    (tmp_path / ".env").write_text("EXCLUSIONS=rg:prod-*\n")
    load_dotenv(tmp_path / ".env")
    assert os.environ["EXCLUSIONS"] == ""


def test_a_category_declared_patterns_field_reaches_its_fetchers(tmp_path):
    spec = PlatformSpec(category="testcat", config_schema={"exclusions": field()})
    f = fetcher(tmp_path, other=ConfigField(name="other"))
    env: dict = {}
    _apply_config(env, f, spec, PlatformConfig(config={"exclusions": ["rg:a"]}), ManifestEntry(use="x"))
    assert env["EXCLUSIONS"] == "rg:a"


# --------------------------------------------------------------------------- #
# metadata.config_patterns
# --------------------------------------------------------------------------- #

ENVELOPE_VALIDATOR = Draft202012Validator(json.loads((REPO_ROOT / "framework/schemas/envelope_schema.json").read_text()))
WRITES_ONE_FILE = "import os, json\njson.dump({'ok': True}, open(os.path.join(os.environ['EVIDENCE_DIR'], 'ev.json'), 'w'))\n"


def run_and_wrap(tmp_path, f, entry, platform=None) -> dict:
    (tmp_path / "fetcher.py").write_text(WRITES_ONE_FILE)
    out = tmp_path / f"out-{len(list(tmp_path.glob('out-*')))}"
    [result] = run_entry(f, entry, out, None, platform)
    assert result.exit_code == 0, result.stderr
    wrap_outputs(result, f, "run-1", out)
    envelope = json.loads((out / "ev.json").read_text())
    assert not list(ENVELOPE_VALIDATOR.iter_errors(envelope))
    return envelope


def test_each_pattern_reaches_the_envelope_with_its_reason_and_the_layer_that_set_it(tmp_path):
    f = fetcher(tmp_path)
    platform = PlatformConfig(config={"exclusions": [{"pattern": "location:a", "reason": "boundary"}, "rg:b"]})
    meta = run_and_wrap(tmp_path, f, ManifestEntry(use="x"), platform)["metadata"]
    assert meta["config_patterns"] == {"exclusions": [
        {"pattern": "location:a", "reason": "boundary", "source": "platform"},
        {"pattern": "rg:b", "reason": None, "source": "platform"}]}
    entry = ManifestEntry(use="x", config={"exclusions": "rg:c id:/d"})
    meta = run_and_wrap(tmp_path, f, entry, platform)["metadata"]
    assert meta["config_patterns"] == {"exclusions": [{"pattern": "rg:c", "reason": None, "source": "entry"},
                                                      {"pattern": "id:/d", "reason": None, "source": "entry"}]}


def test_a_run_with_no_patterns_writes_the_envelope_it_always_has(tmp_path):
    f = fetcher(tmp_path, exclusions=field(), other=ConfigField(name="other", env="OTHER"))
    platform = PlatformConfig(config={"exclusions": ["rg:b"], "other": "x"})
    for entry, plat in ((ManifestEntry(use="x"), None), (ManifestEntry(use="x", config={"exclusions": []}), platform)):
        meta = run_and_wrap(tmp_path, f, entry, plat)["metadata"]
        assert list(meta) == ["fetcher_name", "fetcher_version", "category", "run_id", "target", "collected_at",
                              "status", "exit_code"]


def test_only_pattern_lists_the_fetcher_receives_are_recorded(tmp_path):
    f = fetcher(tmp_path, exclusions=field(), unwired=field(name="unwired", env=None), other=ConfigField(name="other"))
    merged = merged_config(f, None, PlatformConfig(config={"unwired": ["rg:a"], "other": "rg:z"}),
                           ManifestEntry(use="x", config={"exclusions": ["route:a"]}))
    assert "exclusions" in merged.errors and config_patterns(merged) is None


def test_every_target_of_a_fanout_entry_carries_the_patterns(tmp_path):
    f = dataclasses.replace(fetcher(tmp_path), supports_targets=True,
                            target_schema={"sub": TargetField(name="sub", type="string", env="SUB")})
    (tmp_path / "fetcher.py").write_text(WRITES_ONE_FILE)
    entry = ManifestEntry(use="x", config={"exclusions": [{"pattern": "rg:a", "reason": "r"}]},
                          targets=[TargetInstance({"sub": "1"}, {}), TargetInstance({"sub": "2"}, {})])
    results = run_entry(f, entry, tmp_path / "out")
    assert [r.config_patterns for r in results] == [{"exclusions": [
        {"pattern": "rg:a", "reason": "r", "source": "entry"}]}] * 2


# --------------------------------------------------------------------------- #
# validate, notes, unknown keys
# --------------------------------------------------------------------------- #

def manifest(*uses, platform=None, entries=None) -> dict:
    m = api.init_manifest()
    for use in uses:
        api.add_entry(m, use)
        for k, v in ((entries or {}).get(use) or {}).items():
            api.set_fetcher_config(m, use, k, v)
    for k, v in (platform or {}).items():
        api.set_platform_config(m, "azure", k, v)
    return m


BOUNDARY = [{"pattern": "location:regioneast", "reason": "Region outside the boundary"},
            "location:regionwest", "rg:rg-out-of-scope"]


def test_a_platform_list_validates_and_the_note_names_who_takes_it():
    m = manifest("azure_key_vault_configuration", "azure_storage_encryption_status", "azure_defender_plans",
                 platform={"resource_exclusions": BOUNDARY},
                 entries={"azure_storage_encryption_status": {"resource_exclusions": ["rg:rg-other"]}})
    assert api.validate(m, REPO_ROOT) == []
    assert api.validate_notes(m, REPO_ROOT) == [
        "platforms.azure.config.resource_exclusions (3 patterns) applies to 1 of 3 azure entries: "
        "azure_key_vault_configuration; replaced by their own list in azure_storage_encryption_status; "
        "not a setting of azure_defender_plans"]


def test_a_pattern_one_fetcher_refuses_fails_validate_for_that_fetcher():
    m = manifest("azure_front_door_origins", "azure_dns_configuration", platform={"scope_exclusions": ["route:qa-*"]})
    assert api.validate(m, REPO_ROOT) == [
        "platforms.azure.config: config 'scope_exclusions': pattern 'route:qa-*' has the unknown prefix 'route:'; "
        "this field takes no prefixes (for azure_dns_configuration)"]


def test_a_bad_platform_list_is_one_error_and_its_reference_is_no_pattern():
    m = manifest("azure_key_vault_configuration", "azure_alert_rules",
                 platform={"resource_exclusions": "${env:AZURE_RESOURCE_EXCLUSIONS}"})
    assert api.validate(m, REPO_ROOT) == [
        f"platforms.azure.config: config 'resource_exclusions': {patterns.ENV_REF_REFUSAL} (for "
        "azure_key_vault_configuration, azure_alert_rules)"]
    [note] = api.validate_notes(m, REPO_ROOT)
    assert note.startswith("platforms.azure.config.resource_exclusions (a ${env:} reference, refused) applies")


def test_the_example_manifest_validates_and_notes_who_takes_the_platform_list():
    m = api.read_manifest(REPO_ROOT / "examples" / "azure_scope_exclusions.yaml")
    assert api.validate(m, REPO_ROOT) == []
    [note] = api.validate_notes(m, REPO_ROOT)
    assert "replaced by their own list in azure_resource_inventory" in note
    assert "not a setting of azure_defender_plans" in note


def test_unknown_config_keys_fail_validate_with_a_suggestion():
    m = manifest("azure_key_vault_configuration", platform={"resource_exclusion": ["rg:a"]},
                 entries={"azure_key_vault_configuration": {"resource_exclusionz": ["rg:a"]}})
    m["run"]["platforms"]["azurre"] = {"config": {"x": 1}}
    errors = api.validate(m, REPO_ROOT)
    assert "platforms.azure.config: no azure fetcher takes 'resource_exclusion' (did you mean " \
           "'resource_exclusions'?)" in errors
    assert "azure_key_vault_configuration: config 'resource_exclusionz' is not a setting of this fetcher (did you " \
           "mean 'resource_exclusions'?)" in errors
    assert "platforms.azurre: no fetcher category is named azurre (did you mean 'azure'?)" in errors


def test_unknown_config_keys_can_be_notes_instead(monkeypatch):
    monkeypatch.setattr(api, "UNKNOWN_CONFIG_KEYS_ARE_ERRORS", False)
    m = manifest("azure_key_vault_configuration", platform={"resource_exclusion": ["rg:a"]})
    assert api.validate(m, REPO_ROOT) == []
    assert any("no azure fetcher takes 'resource_exclusion'" in n for n in api.validate_notes(m, REPO_ROOT))


def test_issue_report_keys_are_not_unknown():
    m = manifest("wiz_issues_report", entries={"wiz_issues_report": {"assessment_id": "A-1",
                                                                     "close_cycle": "after_run"}})
    assert not [e for e in api.validate(m, REPO_ROOT) if "not a setting" in e]


# --------------------------------------------------------------------------- #
# add / remove and the fields a target takes
# --------------------------------------------------------------------------- #

def test_category_lists_exclude_fields_whose_prefixes_differ_between_fetchers():
    fetchers, platforms = api.discover_fetchers(REPO_ROOT), api.discover_platforms(REPO_ROOT)
    scope, fields, mixed = api.pattern_fields("azure", fetchers, platforms)
    assert (scope, list(fields), mixed) == ("platform", ["resource_exclusions"], ["scope_exclusions"])
    scope, fields, _ = api.pattern_fields("azure_front_door_origins", fetchers, platforms)
    assert (scope, list(fields)) == ("entry", ["scope_exclusions", "resource_exclusions"])
    # With two pattern lists on one entry, the prefix picks the list.
    assert api.pick_pattern_field(fields, "route:qa-*") == "scope_exclusions"
    assert api.pick_pattern_field(fields, "rg:rg-out") == "resource_exclusions"
    with pytest.raises(LookupError):
        api.pattern_fields("nope", fetchers, platforms)


def test_add_and_remove_keep_order_and_reasons():
    m = api.init_manifest()
    api.set_platform_config(m, "azure", "resource_exclusions", "rg:a location:b")
    assert api.add_pattern(m, "platform", "azure", "resource_exclusions", "id:/c", "why") == ("added", [])
    assert api.add_pattern(m, "platform", "azure", "resource_exclusions", "RG:A") == ("unchanged", [])
    assert api.add_pattern(m, "platform", "azure", "resource_exclusions", "rg:a", "boundary") == ("updated", [])
    held = m["run"]["platforms"]["azure"]["config"]
    assert held["resource_exclusions"] == [{"pattern": "rg:a", "reason": "boundary"}, "location:b",
                                           {"pattern": "id:/c", "reason": "why"}]
    assert api.remove_pattern(m, "platform", "azure", "resource_exclusions", "LOCATION:B") == 1
    assert api.remove_pattern(m, "platform", "azure", "resource_exclusions", "rg:zzz") is None
    assert api.remove_pattern(m, "platform", "azure", "resource_exclusions") == 2
    assert "resource_exclusions" not in held
    assert api.remove_pattern(m, "platform", "azure", "resource_exclusions") is None
    api.set_platform_config(m, "azure", "resource_exclusions", [])
    assert api.remove_pattern(m, "platform", "azure", "resource_exclusions") == 0


def test_a_fetchers_first_pattern_starts_from_its_categorys_list():
    m = api.init_manifest()
    api.add_entry(m, "azure_alert_rules")
    api.set_platform_config(m, "azure", "resource_exclusions", [{"pattern": "rg:a", "reason": "boundary"}, "rg:b"])
    outcome, copied = api.add_pattern(m, "entry", "azure_alert_rules", "resource_exclusions", "rg:x", None, "azure")
    assert (outcome, copied) == ("added", [patterns.Item("rg:a", "boundary"), patterns.Item("rg:b")])
    assert m["run"]["fetchers"][0]["config"]["resource_exclusions"] == [
        {"pattern": "rg:a", "reason": "boundary"}, "rg:b", "rg:x"]
    assert api.add_pattern(m, "entry", "azure_alert_rules", "resource_exclusions", "rg:y", None, "azure") == (
        "added", [])
    m2 = api.init_manifest()
    api.add_entry(m2, "azure_alert_rules")
    api.set_platform_config(m2, "azure", "resource_exclusions", ["rg:a"])
    assert api.add_pattern(m2, "entry", "azure_alert_rules", "resource_exclusions", "RG:A", None, "azure") == (
        "unchanged", [])
    assert "config" not in m2["run"]["fetchers"][0]


def test_grammars_that_differ_only_in_prefix_order_are_one_grammar(tmp_path):
    a = fetcher(tmp_path, exclusions=field(prefixes=("rg", "location")))
    b = fetcher(tmp_path, exclusions=field(prefixes=("location", "rg")))
    b.name = "t_other"
    _, fields, mixed = api.pattern_fields("testcat", {"t_fetcher": a, "t_other": b}, {})
    assert (list(fields), mixed) == (["exclusions"], [])


def test_add_refuses_a_field_holding_a_reference():
    m = api.init_manifest()
    api.add_entry(m, "azure_front_door_tls")
    api.set_fetcher_config(m, "azure_front_door_tls", "scope_exclusions", "${env:X}")
    with pytest.raises(ValueError, match="aren't read for a pattern list"):
        api.add_pattern(m, "entry", "azure_front_door_tls", "scope_exclusions", "route:qa")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

@pytest.fixture
def m_path(monkeypatch, tmp_path):
    monkeypatch.chdir(REPO_ROOT)
    path = str(tmp_path / "m.yaml")
    runner.invoke(app, ["manifest", "init", "-f", path])
    for use in ("azure_key_vault_configuration", "azure_front_door_origins"):
        runner.invoke(app, ["manifest", "add", use, "-f", path])
    return path


def cli(*args):
    r = runner.invoke(app, [*args, "--json"])
    return r.exit_code, json.loads(r.output)


def test_exclude_and_unexclude_write_the_manifest(m_path):
    code, out = cli("manifest", "exclude", "azure", "location:regioneast", "--reason", "Outside", "-f", m_path)
    assert (code, out["field"], out["outcome"], out["errors"]) == (0, "resource_exclusions", "added", [])
    assert cli("manifest", "exclude", "azure_front_door_origins", "route:qa-*", "-f", m_path)[0] == 0
    code, out = cli("manifest", "exclude", "azure", "route:qa-*", "-f", m_path)
    assert code == 1 and "set it on each fetcher" in out["errors"][0]
    code, out = cli("manifest", "exclude", "azure", "location:Region East", "-f", m_path)
    assert code == 1 and out["errors"] == [
        "resource_exclusions: pattern 'location:Region East' has a space or a comma; write each pattern as its own "
        "item, with no spaces"]
    shown = cli("manifest", "show", "-f", m_path)[1]
    assert shown["run"]["platforms"]["azure"]["config"]["resource_exclusions"] == [
        {"pattern": "location:regioneast", "reason": "Outside"}]
    assert cli("manifest", "unexclude", "azure_front_door_origins", "route:qa-*", "-f", m_path)[0] == 0
    assert cli("manifest", "unexclude", "azure_front_door_origins", "route:qa-*", "-f", m_path)[0] == 1
    code, out = cli("validate", m_path)
    assert code == 0 and out["notes"][0].startswith("platforms.azure.config.resource_exclusions (1 pattern) applies "
                                                    "to 2 of 2 azure entries: azure_key_vault_configuration, "
                                                    "azure_front_door_origins")


def test_exclude_on_a_fetcher_copies_the_platform_list_and_says_so(m_path):
    cli("manifest", "exclude", "azure", "rg:a", "--reason", "boundary", "-f", m_path)
    cli("manifest", "exclude", "azure", "rg:b", "-f", m_path)
    r = runner.invoke(app, ["manifest", "exclude", "azure_key_vault_configuration", "rg:x", "-f", m_path])
    assert r.exit_code == 0
    assert ("Copied 2 platform patterns from platforms.azure.config.resource_exclusions so "
            "azure_key_vault_configuration keeps them: rg:a, rg:b") in r.output
    shown = cli("manifest", "show", "-f", m_path)[1]
    assert next(e for e in shown["run"]["fetchers"] if e["use"] == "azure_key_vault_configuration")["config"] == {
        "resource_exclusions": [{"pattern": "rg:a", "reason": "boundary"}, "rg:b", "rg:x"]}
    assert cli("manifest", "exclude", "azure_key_vault_configuration", "rg:y", "-f", m_path)[1]["copied"] == []


def test_unexclude_of_a_fetchers_last_pattern_keeps_it_empty_while_its_category_lists_patterns(m_path):
    use = "azure_key_vault_configuration"

    def own():
        return next(e for e in cli("manifest", "show", "-f", m_path)[1]["run"]["fetchers"] if e["use"] == use).get(
            "config") or {}

    # The category has [rg:a]; the fetcher goes [rg:a, rg:b], [rg:b], then [], and rg:a doesn't come back.
    cli("manifest", "exclude", "azure", "rg:a", "-f", m_path)
    cli("manifest", "exclude", use, "rg:b", "-f", m_path)
    cli("manifest", "unexclude", use, "rg:a", "-f", m_path)
    r = runner.invoke(app, ["manifest", "unexclude", use, "rg:b", "-f", m_path])
    assert r.exit_code == 0
    assert (f"{use} keeps resource_exclusions: [], so platforms.azure.config.resource_exclusions still doesn't apply "
            f"to it (rg:a); to take it again, delete resource_exclusions from {use}'s config") in r.output
    assert own() == {"resource_exclusions": []}
    cli("manifest", "set-config", use, "resource_exclusions=rg:x", "-f", m_path)
    code, out = cli("manifest", "unexclude", use, "--field", "resource_exclusions", "--all", "-f", m_path)
    assert (code, out["removed"], out["kept_empty"], own()) == (0, 1, ["resource_exclusions"],
                                                               {"resource_exclusions": []})
    # With no category list to come back, the emptied field goes.
    cli("manifest", "unexclude", "azure", "rg:a", "-f", m_path)
    cli("manifest", "set-config", use, "resource_exclusions=rg:x", "-f", m_path)
    code, out = cli("manifest", "unexclude", use, "rg:x", "-f", m_path)
    assert (code, out["kept_empty"]) == (0, []) and "resource_exclusions" not in own()


def test_set_platform_config_writes_a_patterns_field_as_a_list(m_path):
    assert cli("manifest", "set-platform-config", "azure", "resource_exclusions=rg:a, location:b", "-f", m_path)[0] == 0
    shown = cli("manifest", "show", "-f", m_path)[1]
    assert shown["run"]["platforms"]["azure"]["config"]["resource_exclusions"] == ["rg:a", "location:b"]


def test_describe_shows_what_a_patterns_field_takes_and_not_its_env_var(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    out = runner.invoke(app, ["describe", "azure_key_vault_configuration"]).output
    [line] = [ln for ln in out.splitlines() if "resource_exclusions" in ln and "patterns" in ln]
    assert "takes=rg:, location: or id: patterns" in line and "AZURE_RESOURCE_EXCLUSIONS" not in line


def test_the_tui_detail_shows_a_list_as_its_patterns():
    pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")
    from rich.console import Console

    from framework.tui import render

    m = manifest("azure_key_vault_configuration", platform={"resource_exclusions": BOUNDARY})
    view = api.effective_config(m, ["azure_key_vault_configuration"], REPO_ROOT)["azure_key_vault_configuration"]
    console = Console(width=240, record=True)
    console.print(render.entry_detail({"name": "azure_key_vault_configuration", "secrets": [], "config": []},
                                      m["run"]["fetchers"][0], config_view=view))
    shown = console.export_text()
    assert "location:regioneast, location:regionwest, rg:rg-out-of-scope  (platforms.azure)" in shown
    assert "'pattern'" not in shown
