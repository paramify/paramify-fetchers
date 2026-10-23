"""Comparators: input checks, run order, the input handoff, `metadata.inputs`, and the shared reader's policy.

The run tests stage a small repo in tmp_path with real subprocess fetchers, the
real schemas and the real `_lib` helpers, so they assert what a comparator
actually received rather than what a mock was told.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from framework import api
from framework.cli import _human_run_printer, app
from framework.config_loader import discover_fetchers
from framework.contract import ManifestEntry
from framework.runner import dependency_graph

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "comparators" / "_lib"))

import comparator_inputs as ci  # noqa: E402

# --------------------------------------------------------------------------- #
# A staged repo
# --------------------------------------------------------------------------- #


def stage(root: Path) -> Path:
    (root / "framework" / "schemas").mkdir(parents=True, exist_ok=True)
    for src in (REPO_ROOT / "framework" / "schemas").glob("*.json"):
        (root / "framework" / "schemas" / src.name).write_bytes(src.read_bytes())
    if not (root / "fetchers" / "_lib").exists():
        shutil.copytree(REPO_ROOT / "fetchers" / "_lib", root / "fetchers" / "_lib")
        shutil.copytree(REPO_ROOT / "comparators" / "_lib", root / "comparators" / "_lib")
    return root


def input_fetcher(root: Path, short: str, *, results=({"id": "a"},), exit_code=0,
                  partial=False, write=True, raw=None, category="testcat", extra="") -> str:
    """A fetcher that writes a fixed payload (or `raw` text, or nothing) and exits `exit_code`."""
    stage(root)
    d = root / "fetchers" / category / short
    d.mkdir(parents=True, exist_ok=True)
    (d / "fetcher.yaml").write_text(
        f"name: {category}_{short}\nversion: 0.1.0\ndescription: d\ncategory: {category}\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        f"output:\n  type: json\n  path: {short}.json\n"
        "secrets: []\n"
        f"evidence_set:\n  reference_id: EVD-{short.upper()}\n  name: {short}\n" + extra
    )
    body = raw if raw is not None else json.dumps(
        {"metadata": {"partial_failure": partial, "api_failures": []}, "results": list(results)}
    )
    script = "import os, pathlib\n"
    if write:
        script += f"pathlib.Path(os.environ['EVIDENCE_DIR'], '{short}.json').write_text({body!r})\n"
    if exit_code:
        script += f"raise SystemExit({exit_code})\n"
    (d / "fetcher.py").write_text(script)
    return f"{category}_{short}"


def comparator(root: Path, short: str, depends_on, script: str, *, category="testcat",
               extra="") -> str:
    stage(root)
    d = root / "comparators" / category / short
    d.mkdir(parents=True, exist_ok=True)
    deps = "".join(f"  - {dep}\n" for dep in depends_on)
    (d / "fetcher.yaml").write_text(
        f"name: {category}_{short}\nversion: 0.1.0\ndescription: d\ncategory: {category}\n"
        f"depends_on:\n{deps}"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        f"output:\n  type: json\n  path: {short}.json\n"
        "secrets: []\n"
        f"evidence_set:\n  reference_id: EVD-{short.upper()}\n  name: {short}\n" + extra
    )
    (d / "fetcher.py").write_text(script.replace("OUTPUT", f"{short}.json"))
    return f"{category}_{short}"


# Dumps what it was given: its env var names and the input index.
PROBE = '''
import json, os, pathlib
path = os.environ["COMPARATOR_INPUTS"]
pathlib.Path(os.environ["EVIDENCE_DIR"], "OUTPUT").write_text(json.dumps({
    "env": sorted(os.environ), "environments": os.environ.get("CMP_ENVIRONMENTS"), "index_path": path,
    "index": json.loads(pathlib.Path(path).read_text()),
}))
'''

# A comparator's own setting, like the planned change-to-pipeline-run comparator's `environments`.
ENVIRONMENTS = "config_schema:\n  environments:\n    type: string\n    required: false\n    env: CMP_ENVIRONMENTS\n"


def template_comparator(root: Path, left: str, right: str) -> str:
    """comparators/_template, copied and filled in the way the guide says."""
    stage(root)
    d = root / "comparators" / "testcat" / "match"
    shutil.copytree(REPO_ROOT / "comparators" / "_template", d)
    for name in ("fetcher.yaml", "fetcher.py"):
        text = (d / name).read_text()
        for old, new in (
            ("<category>_<short_name>", "testcat_match"), ("<category>", "testcat"),
            ("<input_fetcher_a>", left), ("<input_fetcher_b>", right),
            ("<CATEGORY>-<SHORT-NAME>", "TESTCAT-MATCH"), ("<KSI-ID>", "KSI-CMT-VTD"),
        ):
            text = text.replace(old, new)
        (d / name).write_text(text)
    return "testcat_match"


def manifest(root: Path, *uses, **extra) -> dict:
    return {"run": {"output_dir": str(root / "out"),
                    "fetchers": [{"use": u} for u in uses], **extra}}


def run(root: Path, m: dict):
    events: list = []
    summary = api.run(m, root, on_event=events.append)
    return summary, Path(summary["run_dir"]), events


def envelope(run_dir: Path, name: str) -> dict:
    return json.loads((run_dir / name).read_text())


def started(events) -> list:
    return [e["fetcher"] for e in events if e["event"] == "fetcher_start"]


# --------------------------------------------------------------------------- #
# Order
# --------------------------------------------------------------------------- #


def _f(build_fetcher_fn, tmp_path, name, deps=(), **kw):
    return build_fetcher_fn(tmp_path, name=name, depends_on=list(deps), **kw)


def test_order_runs_every_fetcher_then_every_comparator(build_fetcher_fn, tmp_path):
    fx = {n: _f(build_fetcher_fn, tmp_path, n) for n in ("a", "b", "c")}
    fx["cmp1"] = _f(build_fetcher_fn, tmp_path, "cmp1", ["a", "b"])
    fx["cmp2"] = _f(build_fetcher_fn, tmp_path, "cmp2", ["c"])
    entries = [ManifestEntry(use=u) for u in ("cmp1", "a", "b", "cmp2", "c")]
    assert [e.use for e in dependency_graph.order(entries, fx)] == ["a", "b", "c", "cmp1", "cmp2"]


def test_order_moves_a_comparator_after_fetchers_listed_after_it(build_fetcher_fn, tmp_path):
    fx = {n: _f(build_fetcher_fn, tmp_path, n) for n in ("a", "x")}
    fx["c"] = _f(build_fetcher_fn, tmp_path, "c", ["a"])
    entries = [ManifestEntry(use=u) for u in ("a", "c", "x", "unknown")]
    assert [e.use for e in dependency_graph.order(entries, fx)] == ["a", "x", "unknown", "c"]


def test_order_chains_comparators_and_ignores_inputs_outside_the_manifest(build_fetcher_fn, tmp_path):
    fx = {"a": _f(build_fetcher_fn, tmp_path, "a")}
    fx["c1"] = _f(build_fetcher_fn, tmp_path, "c1", ["a", "absent"])
    fx["c2"] = _f(build_fetcher_fn, tmp_path, "c2", ["c1"])
    fx["absent"] = _f(build_fetcher_fn, tmp_path, "absent")
    entries = [ManifestEntry(use=u) for u in ("c2", "c1", "a")]
    assert [e.use for e in dependency_graph.order(entries, fx)] == ["a", "c1", "c2"]


def test_order_appends_a_cycle_rather_than_looping(build_fetcher_fn, tmp_path):
    fx = {"p": _f(build_fetcher_fn, tmp_path, "p", ["q"]), "q": _f(build_fetcher_fn, tmp_path, "q", ["p"]),
          "a": _f(build_fetcher_fn, tmp_path, "a")}
    entries = [ManifestEntry(use=u) for u in ("p", "q", "a")]
    assert [e.use for e in dependency_graph.order(entries, fx)] == ["a", "p", "q"]


# --------------------------------------------------------------------------- #
# Inputs a comparator can't run with
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind,output,ok", [
    ("evidence", "json", True), ("inventory", "json", True),
    ("issue_report", "csv", False), ("discovery", "json", False), ("evidence", "csv", False),
])
def test_problems_accepts_only_json_evidence_inputs(build_fetcher_fn, tmp_path, kind, output, ok):
    fx = {"src": _f(build_fetcher_fn, tmp_path, "src", kind=kind, output_type=output),
          "c": _f(build_fetcher_fn, tmp_path, "c", ["src"])}
    problems = dependency_graph.problems(fx)
    assert (problems == {}) is ok, problems


def test_problems_names_unknown_inputs_and_cycles_on_the_comparator_itself(build_fetcher_fn, tmp_path):
    fx = {name: _f(build_fetcher_fn, tmp_path, name, deps) for name, deps in {
        "c": ["nope"], "self": ["self"], "p": ["q"], "q": ["p"], "reader": ["c"], "fine": [],
    }.items()}
    # `reader` can run: c is a comparator that writes JSON evidence. If c is skipped, reader
    # finds it missing at run time and writes null counts.
    assert dependency_graph.problems(fx) == {
        "c": "depends_on names an unknown fetcher: nope",
        "self": "dependency cycle: self -> self",
        "p": "dependency cycle: p -> q -> p",
        "q": "dependency cycle: p -> q -> p",
    }


def test_discovery_finds_comparators_beside_fetchers(tmp_path):
    src = input_fetcher(tmp_path, "src")
    cmp = comparator(tmp_path, "cmp", [src], PROBE)
    found = discover_fetchers(tmp_path)
    assert found[cmp].is_comparator and found[cmp].depends_on == [src]
    assert not found[src].is_comparator


def test_discovery_keeps_a_comparator_with_an_unknown_input(tmp_path):
    src = input_fetcher(tmp_path, "src")
    cmp = comparator(tmp_path, "cmp", ["testcat_nope"], PROBE)
    reader = comparator(tmp_path, "reader", [cmp], PROBE)
    assert set(discover_fetchers(tmp_path)) == {src, cmp, reader}
    assert {f["name"] for c in api.catalog(tmp_path)["categories"] for f in c["fetchers"]} == {src, cmp, reader}


def _csv_fetcher(root: Path) -> str:
    name = input_fetcher(root, "csv")
    yaml_path = root / "fetchers" / "testcat" / "csv" / "fetcher.yaml"
    yaml_path.write_text(yaml_path.read_text().replace("type: json\n  path: csv.json", "type: csv\n  path: csv.csv"))
    return name


@pytest.mark.parametrize("make,why", [
    (lambda root: comparator(root, "cmp", ["testcat_nope"], PROBE),
     "depends_on names an unknown fetcher: testcat_nope"),
    (lambda root: comparator(root, "cmp", ["testcat_cmp"], PROBE),
     "dependency cycle: testcat_cmp -> testcat_cmp"),
    (lambda root: comparator(root, "cmp", [_csv_fetcher(root)], PROBE),
     "depends_on testcat_csv, which writes no JSON evidence (kind evidence, output csv)"),
], ids=["unknown", "cycle", "not-json"])
def test_validate_and_run_report_a_bad_input_on_that_entry_and_the_rest_still_runs(tmp_path, make, why):
    src = input_fetcher(tmp_path, "src")
    cmp = make(tmp_path)
    reader = comparator(tmp_path, "reader", [cmp], PROBE)
    m = manifest(tmp_path, src, cmp, reader)

    assert api.validate(m, tmp_path) == [f"{cmp}: {why}"]
    summary, run_dir, events = run(tmp_path, m)

    assert not summary["ok"]
    assert [(e["fetcher"], e["reason"]) for e in events if e["event"] == "fetcher_skip"] == [(cmp, why)]
    assert started(events) == [src, reader]
    assert not (run_dir / "cmp.json").exists()
    assert envelope(run_dir, "reader.json")["metadata"]["inputs"][0]["status"] == "missing"


def test_discovery_does_not_judge_which_tree_a_fetcher_is_in(tmp_path):
    """Where a comparator is filed is this repo's layout rule (tests/test_contracts.py)."""
    src = input_fetcher(tmp_path, "src")
    filed_as_fetcher = input_fetcher(tmp_path, "cmp", extra=f"depends_on:\n  - {src}\n")
    d = tmp_path / "comparators" / "testcat" / "plain"
    d.mkdir(parents=True)
    (d / "fetcher.yaml").write_text(
        (tmp_path / "fetchers" / "testcat" / "src" / "fetcher.yaml").read_text().replace("testcat_src", "testcat_plain")
    )
    found = discover_fetchers(tmp_path)
    assert found[filed_as_fetcher].is_comparator and not found["testcat_plain"].is_comparator


def test_a_duplicate_name_across_the_two_trees_stops_discovery(tmp_path):
    src = input_fetcher(tmp_path, "src")
    comparator(tmp_path, "src", [src], PROBE)
    with pytest.raises(ValueError, match="Duplicate fetcher name 'testcat_src'"):
        discover_fetchers(tmp_path)


def test_a_malformed_fetcher_yaml_still_stops_discovery(tmp_path):
    input_fetcher(tmp_path, "src")
    comparator(tmp_path, "cmp", ["testcat_src"], PROBE, extra="supports_targets: true\n")
    with pytest.raises(ValueError, match="schema validation failed"):
        discover_fetchers(tmp_path)


def test_catalog_gives_a_comparator_nothing_from_its_category(tmp_path):
    src = input_fetcher(tmp_path, "src")
    (tmp_path / "fetchers" / "_categories").mkdir(parents=True)
    for cat in ("cmpcat", "testcat"):
        (tmp_path / "fetchers" / "_categories" / f"{cat}.yaml").write_text(
            "secrets:\n  - name: token\n    env: TOKEN\n    required: false\n"
            "config_schema:\n  base_url:\n    type: string\n    env: URL\n"
        )
    alone = comparator(tmp_path, "alone", [src], PROBE, category="cmpcat")
    beside = comparator(tmp_path, "beside", [src], PROBE)
    cats = {c["name"]: c for c in api.catalog(tmp_path)["categories"]}

    assert cats["cmpcat"]["platform"] is None
    assert [f["name"] for f in cats["testcat"]["platform"]["config"]] == ["base_url"]
    described = {f["name"]: f for c in cats.values() for f in c["fetchers"]}
    assert described[alone]["secrets"] == described[beside]["secrets"] == []
    assert [s["name"] for s in described[src]["secrets"]] == ["token"]


def _comparator_doc(**over) -> dict:
    doc = {
        "name": "x_c", "version": "0.1.0", "description": "d", "depends_on": ["x_a"],
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "json", "path": "c.json"}, "secrets": [],
        "evidence_set": {"reference_id": "EVD-X-C", "name": "C"},
    }
    doc.update(over)
    return {k: v for k, v in doc.items() if v is not None}


@pytest.mark.parametrize("over", [
    {"secrets": [{"name": "t", "env": "T"}]},
    {"supports_targets": True},
    {"target_schema": {"id": {"type": "string"}}},
    {"kind": "inventory"},
    {"output": {"type": "csv", "path": "c.csv"}},
    {"evidence_set": None},
], ids=["secrets", "targets", "target_schema", "kind", "csv", "no-evidence-set"])
def test_schema_rejects_a_comparator_that_could_collect(over):
    validator = Draft202012Validator(json.loads((REPO_ROOT / "framework" / "schemas" / "fetcher_schema.json").read_text()))
    assert not list(validator.iter_errors(_comparator_doc()))
    assert list(validator.iter_errors(_comparator_doc(**over)))


# --------------------------------------------------------------------------- #
# A run
# --------------------------------------------------------------------------- #


def test_a_comparator_listed_first_runs_last(tmp_path):
    left = input_fetcher(tmp_path, "left", results=[{"id": "a"}, {"id": "b"}])
    right = input_fetcher(tmp_path, "right", results=[{"id": "a"}])
    cmp = template_comparator(tmp_path, left, right)

    summary, run_dir, events = run(tmp_path, manifest(tmp_path, cmp, left, right))

    assert summary["ok"], summary
    assert started(events) == [left, right, cmp]
    inv = {i["fetcher_name"]: i for i in summary["invocations"]}
    assert inv[cmp]["started_at"] >= max(inv[left]["completed_at"], inv[right]["completed_at"])

    payload = envelope(run_dir, "testcat_match.json")["payload"]
    assert payload["summary"] == {"records": 2, "matched": 1, "unmatched": 1,
                                  "percent_matched": 50, "inputs_complete": True}
    assert payload["results"] == [{"id": "a", "verdict": "matched"}, {"id": "b", "verdict": "unmatched"}]
    assert payload["metadata"]["partial_failure"] is False


def test_the_runner_records_the_inputs_in_the_envelope_and_run_metadata(tmp_path):
    src = input_fetcher(tmp_path, "src")
    cmp = comparator(tmp_path, "cmp", [src], PROBE)
    summary, run_dir, _ = run(tmp_path, manifest(tmp_path, src, cmp))

    rows = envelope(run_dir, "cmp.json")["metadata"]["inputs"]
    assert rows == [{
        "fetcher_name": src, "target": None, "run_id": summary["run_id"],
        "collected_at": rows[0]["collected_at"], "status": "success", "file": "src.json",
    }]
    meta = json.loads((run_dir / "_run_metadata.json").read_text())
    by_name = {i["fetcher_name"]: i for i in meta["invocations"]}
    assert by_name[cmp]["inputs"] == rows
    assert "inputs" not in by_name[src]

    schema = json.loads((REPO_ROOT / "framework" / "schemas" / "envelope_schema.json").read_text())
    assert not list(Draft202012Validator(schema).iter_errors(envelope(run_dir, "cmp.json")))


def test_the_comparator_gets_an_index_and_no_credentials(tmp_path, monkeypatch):
    src = input_fetcher(tmp_path, "src")
    (tmp_path / "fetchers" / "_categories").mkdir(parents=True)
    (tmp_path / "fetchers" / "_categories" / "cmpcat.yaml").write_text(
        "secrets:\n  - name: token\n    env: CMPCAT_TOKEN\n    required: false\n"
        "config_schema:\n  base_url:\n    type: string\n    required: true\n    env: CMPCAT_URL\n"
        "auth:\n  passthrough_env: [CMPCAT_AMBIENT]\n"
    )
    monkeypatch.setenv("CMPCAT_AMBIENT", "set")
    monkeypatch.setenv("CMPCAT_TOKEN_SOURCE", "set")
    cmp = comparator(tmp_path, "cmp", [src], PROBE, category="cmpcat", extra=ENVIRONMENTS)
    # The positive control: an ordinary fetcher in the same category, given the same entry secrets.
    plain = input_fetcher(tmp_path, "plain", category="cmpcat")
    (tmp_path / "fetchers" / "cmpcat" / "plain" / "fetcher.py").write_text(
        "import json, os, pathlib\n"
        "pathlib.Path(os.environ['EVIDENCE_DIR'], 'plain.json').write_text(json.dumps({'env': sorted(os.environ)}))\n"
    )
    m = manifest(tmp_path, cmp, src, plain,
                 platforms={"cmpcat": {"config": {"base_url": "https://example.invalid"}}})
    m["run"]["fetchers"][0]["config"] = {"environments": "production"}
    for i in (0, 2):
        m["run"]["fetchers"][i]["secrets"] = {"token": "${env:CMPCAT_TOKEN_SOURCE}"}

    assert api.validate(manifest(tmp_path, cmp, src), tmp_path) == []
    summary, run_dir, _ = run(tmp_path, m)
    probe = envelope(run_dir, "cmp.json")["payload"]

    credentials = {"CMPCAT_AMBIENT", "CMPCAT_TOKEN", "CMPCAT_URL"}
    assert credentials <= set(envelope(run_dir, "plain.json")["payload"]["env"])
    assert not credentials & set(probe["env"])
    assert {"COMPARATOR_INPUTS", "EVIDENCE_DIR", "FETCHER_STATUS_FILE", "CMP_ENVIRONMENTS"} <= set(probe["env"])
    assert probe["environments"] == "production"
    index_path = Path(probe["index_path"])
    assert run_dir not in index_path.parents and not index_path.exists()
    assert probe["index"] == {
        "run_id": summary["run_id"],
        "run_dir": str(run_dir),
        "inputs": {src: {"in_manifest": True, "invocations": [{
            "target": None, "status": "success", "exit_code": 0, "error": None,
            "error_code": None, "collected_at": probe["index"]["inputs"][src]["invocations"][0]["collected_at"],
            "files": [str(run_dir / "src.json")],
        }]}},
    }
    describe = next(f for c in api.catalog(tmp_path)["categories"] for f in c["fetchers"] if f["name"] == cmp)
    assert describe["secrets"] == [] and describe["depends_on"] == [src]


def test_a_failed_input_is_compared_and_the_comparator_reports_input_failed(tmp_path):
    left = input_fetcher(tmp_path, "left", results=[{"id": "a"}], exit_code=1)
    right = input_fetcher(tmp_path, "right", results=[{"id": "a"}])
    cmp = template_comparator(tmp_path, left, right)
    summary, run_dir, events = run(tmp_path, manifest(tmp_path, cmp, left, right))

    assert started(events)[-1] == cmp, "a failed input must not skip the comparator"
    env = envelope(run_dir, "testcat_match.json")
    assert env["metadata"]["status"] == "failed"
    assert env["metadata"]["error_code"] == "input_failed"
    assert left in env["metadata"]["error"]
    payload = env["payload"]
    assert payload["summary"]["matched"] == 1 and payload["summary"]["inputs_complete"] is False
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"][0]["type"] == "input_failed"
    assert [r["status"] for r in env["metadata"]["inputs"]] == ["failed", "success"]


def test_a_missing_input_nulls_every_count(tmp_path):
    left = input_fetcher(tmp_path, "left")
    right = input_fetcher(tmp_path, "right")
    cmp = template_comparator(tmp_path, left, right)
    m = manifest(tmp_path, cmp, left)

    assert api.validate(m, tmp_path) == [
        f"{cmp}: reads {right}, which is not in the manifest (fix: paramify manifest add {right})"
    ]
    _, run_dir, _ = run(tmp_path, m)
    env = envelope(run_dir, "testcat_match.json")
    assert env["payload"]["summary"] == {"records": None, "matched": None, "unmatched": None,
                                         "percent_matched": None, "inputs_complete": False}
    assert env["payload"]["results"] == []
    assert env["metadata"]["error_code"] == "input_failed"
    assert env["metadata"]["inputs"][1] == {"fetcher_name": right, "target": None, "run_id": None,
                                            "collected_at": None, "status": "missing", "file": None}


def test_an_input_that_could_not_start_is_missing(tmp_path):
    left = input_fetcher(tmp_path, "left", extra="config_schema:\n  url:\n    type: string\n    required: true\n    env: LEFT_URL\n")
    right = input_fetcher(tmp_path, "right")
    cmp = template_comparator(tmp_path, left, right)
    _, run_dir, events = run(tmp_path, manifest(tmp_path, cmp, left, right))

    assert any(e["event"] == "fetcher_error" and e["fetcher"] == left for e in events)
    env = envelope(run_dir, "testcat_match.json")
    assert env["payload"]["summary"]["matched"] is None
    assert "wrote no file" in env["metadata"]["error"]


def test_a_half_written_input_is_missing_not_compared(tmp_path):
    left = input_fetcher(tmp_path, "left", raw='{"metadata": {"partial_')
    right = input_fetcher(tmp_path, "right")
    cmp = template_comparator(tmp_path, left, right)
    _, run_dir, _ = run(tmp_path, manifest(tmp_path, left, right, cmp))

    env = envelope(run_dir, "testcat_match.json")
    assert env["payload"]["summary"]["records"] is None
    assert "cannot be read as JSON" in env["metadata"]["error"]


@pytest.mark.parametrize("payload,state,reason", [
    ({"data": [], "records_included": True}, "partial", "it holds no records"),
    ({"data": [], "records_included": False}, "missing", "withholds its records"),
])
def test_an_inventory_input_the_runner_marked_incomplete_is_not_complete(tmp_path, payload, state, reason):
    left = input_fetcher(tmp_path, "left")
    right = input_fetcher(tmp_path, "right", raw=json.dumps(payload), extra="kind: inventory\n")
    cmp = template_comparator(tmp_path, left, right)
    _, run_dir, _ = run(tmp_path, manifest(tmp_path, left, right, cmp))

    assert envelope(run_dir, "right.json")["metadata"]["status"] == "success"
    assert envelope(run_dir, "right.json")["metadata"]["inventory"]["complete"] is False
    env = envelope(run_dir, "testcat_match.json")
    assert env["metadata"]["error_code"] == "input_failed" and reason in env["metadata"]["error"]
    p = env["payload"]
    assert p["metadata"]["api_failures"][0]["type"] == f"input_{state}"
    assert p["summary"]["inputs_complete"] is False
    assert p["summary"]["unmatched"] == (1 if state == "partial" else None)


def test_a_failed_input_whose_payload_is_not_an_object_is_missing(tmp_path):
    left = input_fetcher(tmp_path, "left", raw='["error: 403"]', exit_code=1)
    right = input_fetcher(tmp_path, "right")
    cmp = template_comparator(tmp_path, left, right)
    _, run_dir, _ = run(tmp_path, manifest(tmp_path, left, right, cmp))

    env = envelope(run_dir, "testcat_match.json")
    assert env["metadata"]["error_code"] == "input_failed"
    assert "holds a payload that is not a JSON object" in env["metadata"]["error"]
    assert env["payload"]["summary"]["records"] is None


NULL_SUMMARY = {"records": None, "matched": None, "unmatched": None, "percent_matched": None, "inputs_complete": False}


@pytest.mark.parametrize("raw", [
    json.dumps({"metadata": {}, "results": None}),
    json.dumps({"metadata": {}, "results": [{"name": "no id"}]}),
])
def test_a_comparison_that_raises_still_writes_the_file(tmp_path, raw):
    left = input_fetcher(tmp_path, "left", raw=raw, exit_code=1)
    right = input_fetcher(tmp_path, "right")
    cmp = template_comparator(tmp_path, left, right)
    _, run_dir, _ = run(tmp_path, manifest(tmp_path, left, right, cmp))

    env = envelope(run_dir, "testcat_match.json")
    assert env["metadata"]["error_code"] == "internal_error"
    assert "cannot compare the inputs" in env["metadata"]["error"]
    assert env["payload"]["results"] == [] and env["payload"]["summary"] == NULL_SUMMARY
    assert [f["type"] for f in env["payload"]["metadata"]["api_failures"]] == ["input_failed", "internal_error"]


def test_the_demo_still_writes_its_file_when_its_check_raises(tmp_path):
    hello = input_fetcher(tmp_path, "hello", category="demo", raw=json.dumps({"results": ["not a policy"]}), exit_code=1)
    shutil.copytree(REPO_ROOT / "comparators" / "demo" / "policy_check", tmp_path / "comparators" / "demo" / "policy_check")
    _, run_dir, _ = run(tmp_path, manifest(tmp_path, hello, "demo_policy_check"))

    env = envelope(run_dir, "demo_policy_check.json")
    assert env["metadata"]["error_code"] == "internal_error"
    assert env["payload"]["summary"]["policies"] is None


def test_a_comparators_required_config_points_at_its_own_entry(tmp_path):
    src = input_fetcher(tmp_path, "src")
    cmp = comparator(tmp_path, "cmp", [src], PROBE, extra=ENVIRONMENTS.replace("required: false", "required: true"))
    m = manifest(tmp_path, src, cmp, platforms={"testcat": {"config": {"environments": "production"}}})
    hint = (f"set it on this entry: paramify manifest set-config {cmp} environments=<value>; "
            "a comparator ignores platforms.testcat.config")

    assert api.validate(m, tmp_path) == [f"{cmp}: required config 'environments' not set ({hint})"]
    _, _, events = run(tmp_path, m)
    error = next(e["error"] for e in events if e["event"] == "fetcher_error" and e["fetcher"] == cmp)
    assert hint in error
    assert [f["value"] for f in api.effective_config(m, [cmp], tmp_path)[cmp]] == [None]

    m["run"]["fetchers"][1]["config"] = {"environments": "production"}
    assert api.validate(m, tmp_path) == []


def test_demo_comparator_runs_after_demo_hello(tmp_path):
    m = api.read_manifest(REPO_ROOT / "examples" / "demo_comparator.yaml")
    m["run"]["output_dir"] = str(tmp_path / "out")
    assert api.validate(m, REPO_ROOT) == []
    summary, run_dir, events = run(REPO_ROOT, m)

    assert summary["ok"], summary
    assert started(events) == ["demo_hello", "demo_policy_check"]
    payload = envelope(run_dir, "demo_policy_check.json")["payload"]
    assert payload["summary"]["policies_enforced"] == 2 and payload["summary"]["inputs_complete"]


# --------------------------------------------------------------------------- #
# Front-ends
# --------------------------------------------------------------------------- #


def test_effective_config_gives_a_comparator_only_its_own_fields(tmp_path):
    src = input_fetcher(tmp_path, "src")
    (tmp_path / "fetchers" / "_categories").mkdir(parents=True)
    (tmp_path / "fetchers" / "_categories" / "cmpcat.yaml").write_text(
        "config_schema:\n  base_url:\n    type: string\n    required: true\n    env: CMPCAT_URL\n"
    )
    cmp = comparator(tmp_path, "cmp", [src], PROBE, category="cmpcat", extra=ENVIRONMENTS)
    m = manifest(tmp_path, cmp, src, platforms={"cmpcat": {"config": {"base_url": "https://example.invalid"}}})
    m["run"]["fetchers"][0]["config"] = {"environments": "production"}

    fields = api.effective_config(m, [cmp], tmp_path)[cmp]
    assert [(f["name"], f["value"], f["source"]) for f in fields] == [("environments", "production", "entry")]


def test_doctor_leaves_out_a_comparators_category(tmp_path):
    src = input_fetcher(tmp_path, "src")
    (tmp_path / "fetchers" / "_categories").mkdir(parents=True)
    (tmp_path / "fetchers" / "_categories" / "cmpcat.yaml").write_text("requires:\n  tools:\n    - cmpcat-cli\n")
    cmp = comparator(tmp_path, "cmp", [src], PROBE, category="cmpcat")
    path = tmp_path / "m.yaml"
    path.write_text(json.dumps(manifest(tmp_path, src, cmp)))

    report = api.doctor(tmp_path, path)
    assert report["categories"] == ["testcat"]
    assert "cmpcat-cli" not in {t["name"] for t in report["tools"]}
    assert report["manifest"]["errors"] == []


def test_add_entry_adds_a_comparators_inputs_and_theirs(build_fetcher_fn, tmp_path):
    fx = {n: _f(build_fetcher_fn, tmp_path, n) for n in ("a", "b")}
    fx["c1"] = _f(build_fetcher_fn, tmp_path, "c1", ["a", "unknown"])
    fx["c2"] = _f(build_fetcher_fn, tmp_path, "c2", ["c1", "b", "c2"])
    m = api.init_manifest()
    api.add_entry(m, "b")

    assert api.add_entry(m, "c2", fx) == {"c2": None, "c1": "c2", "a": "c1"}
    assert [e["use"] for e in m["run"]["fetchers"]] == ["b", "c2", "c1", "a"]
    assert api.add_entry(m, "c2", fx) == {}


def test_add_entry_completes_a_comparator_already_in_the_manifest(build_fetcher_fn, tmp_path):
    fx = {"a": _f(build_fetcher_fn, tmp_path, "a"), "c": _f(build_fetcher_fn, tmp_path, "c", ["a"])}
    m = api.init_manifest()
    api.add_entry(m, "c")
    assert api.add_entry(m, "c", fx) == {"a": "c"}


def test_manifest_add_adds_the_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    path = tmp_path / "m.yaml"
    api.dump_manifest(api.init_manifest(), path, REPO_ROOT)

    result = CliRunner().invoke(app, ["manifest", "add", "demo_policy_check", "-f", str(path)])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[:2] == ["added demo_policy_check", "added demo_hello (input of demo_policy_check)"]
    assert [e["use"] for e in api.read_manifest(path)["run"]["fetchers"]] == ["demo_policy_check", "demo_hello"]
    assert api.validate(api.read_manifest(path), REPO_ROOT) == []

    again = CliRunner().invoke(app, ["manifest", "add", "demo_policy_check", "-f", str(path), "--json"])
    assert json.loads(again.output)["added"] == []


def test_list_and_describe_show_a_comparators_inputs(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    listed = CliRunner().invoke(app, ["list"])
    assert listed.exit_code == 0
    assert "reads=demo_hello" in next(line for line in listed.output.splitlines() if "demo_policy_check" in line)

    described = CliRunner().invoke(app, ["describe", "demo_policy_check"])
    assert described.exit_code == 0
    assert "depends_on: demo_hello  (a comparator: runs after these in the same run)" in described.output


def test_the_run_output_shows_a_comparators_inputs(capsys):
    _human_run_printer()({"event": "fetcher_start", "fetcher": "c", "fanout": False, "depends_on": ["a", "b"]})
    assert "RUN   c  (reads a, b)" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# The shared reader's policy
# --------------------------------------------------------------------------- #


def _envelope_file(path: Path, name="t_src", run_id="r1", payload=None, status="success", inventory=None) -> str:
    meta = {"fetcher_name": name, "run_id": run_id, "status": status}
    if inventory is not None:
        meta["inventory"] = inventory
    path.write_text(json.dumps({
        "schema_version": "1.0",
        "metadata": meta,
        "payload": payload if payload is not None else {"metadata": {"partial_failure": False}, "results": []},
    }))
    return str(path)


def _index(tmp_path, *invocations, in_manifest=True) -> Path:
    path = tmp_path / "index.json"
    path.write_text(json.dumps({"run_id": "r1", "inputs": {"t_src": {
        "in_manifest": in_manifest, "invocations": list(invocations)}}}))
    return path


def _inv(files, status="success", target=None, error=None):
    return {"target": target, "status": status, "exit_code": 0 if status == "success" else 1,
            "error": error, "error_code": None, "files": files}


def test_reader_complete(tmp_path):
    inputs = ci.load_inputs(_index(tmp_path, _inv([_envelope_file(tmp_path / "a.json")])))
    assert inputs["t_src"].state == ci.COMPLETE and inputs.complete and inputs.exit_code == 0
    assert inputs["t_src"].payloads == [{"metadata": {"partial_failure": False}, "results": []}]
    assert inputs.failures == [] and inputs.reason() == ""


def test_reader_partial(tmp_path):
    f = _envelope_file(tmp_path / "a.json", payload={"metadata": {"partial_failure": True}})
    inputs = ci.load_inputs(_index(tmp_path, _inv([f])))
    assert inputs["t_src"].state == ci.PARTIAL and not inputs.complete and inputs.exit_code == 1
    assert inputs.failures == [{"operation": "read input t_src", "type": "input_partial",
                                "message": "a.json records partial_failure"}]


def test_reader_failed_with_a_file_is_compared(tmp_path):
    f = _envelope_file(tmp_path / "a.json", status="failed")
    inputs = ci.load_inputs(_index(tmp_path, _inv([f], status="failed", error="403 Forbidden")))
    assert inputs["t_src"].state == ci.FAILED and inputs["t_src"].files
    assert inputs.reason() == "input t_src failed: collection failed: 403 Forbidden"


@pytest.mark.parametrize("inventory,state,reason", [
    ({"complete": True, "records": 1, "records_included": True}, ci.COMPLETE, None),
    ({"complete": False, "records": 0, "records_included": True, "incomplete_because": ["it holds no records"]},
     ci.PARTIAL, "a.json is an incomplete inventory: it holds no records"),
    ({"complete": False, "records": 2, "records_included": True,
      "incomplete_because": ["the payload breaks the inventory contract"]},
     ci.PARTIAL, "a.json is an incomplete inventory: the payload breaks the inventory contract"),
    ({"complete": False, "records": 0, "records_included": False,
      "incomplete_because": ["the fetcher withheld its records (records_included: false)"]},
     ci.MISSING, "a.json withholds its records (records_included: false)"),
])
def test_reader_follows_the_runners_inventory_verdict(tmp_path, inventory, state, reason):
    f = _envelope_file(tmp_path / "a.json", inventory=inventory)
    inputs = ci.load_inputs(_index(tmp_path, _inv([f])))
    assert inputs["t_src"].state == state and inputs["t_src"].reason == reason


@pytest.mark.parametrize("case,expect", [
    ("not_in_manifest", "not in the manifest"),
    ("did_not_run", "did not run"),
    ("no_file", "wrote no file: boom"),
    ("half_written", "cannot be read as JSON"),
    ("not_an_envelope", "is not a complete evidence envelope"),
    ("not_an_object", "holds a payload that is not a JSON object"),
    ("other_fetcher", "is not t_src's evidence from this run"),
    ("other_run", "is not t_src's evidence from this run"),
    ("one_target_missing", "wrote no file (target {\"sub\": \"two\"})"),
])
def test_reader_missing(tmp_path, case, expect):
    good = _envelope_file(tmp_path / "good.json")
    bad = tmp_path / "bad.json"
    if case == "not_in_manifest":
        index = _index(tmp_path, in_manifest=False)
    elif case == "did_not_run":
        index = _index(tmp_path)
    elif case == "no_file":
        index = _index(tmp_path, _inv([], status="failed", error="boom"))
    elif case == "one_target_missing":
        index = _index(tmp_path, _inv([good], target={"sub": "one"}), _inv([], target={"sub": "two"}))
    else:
        if case == "half_written":
            bad.write_text('{"schema_version": "1.0", "meta')
        elif case == "not_an_envelope":
            bad.write_text(json.dumps({"results": []}))
        elif case == "not_an_object":
            _envelope_file(bad, payload=["error: 403"], status="failed")
        elif case == "other_fetcher":
            _envelope_file(bad, name="t_other")
        else:
            _envelope_file(bad, run_id="r0")
        index = _index(tmp_path, _inv([str(bad)]))

    inputs = ci.load_inputs(index)
    assert inputs["t_src"].state == ci.MISSING
    assert expect in inputs["t_src"].reason
    assert inputs.missing == ["t_src"] and inputs.exit_code == 1


def test_build_payload_nulls_the_summary_when_an_input_is_missing(tmp_path):
    inputs = ci.load_inputs(_index(tmp_path, in_manifest=False))
    payload = ci.build_payload(inputs, [{"id": "x"}], {"matched": 0, "percent": 0})
    assert payload["results"] == []
    assert payload["summary"] == {"matched": None, "percent": None, "inputs_complete": False}
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"][0]["type"] == "input_missing"


def test_build_payload_records_a_comparison_that_raised(tmp_path):
    inputs = ci.load_inputs(_index(tmp_path, _inv([_envelope_file(tmp_path / "a.json")])))
    payload = ci.build_payload(inputs, [{"id": "x"}], {"matched": 1}, "cannot compare the inputs: KeyError: 'id'")
    assert payload["results"] == [] and payload["summary"] == {"matched": None, "inputs_complete": True}
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"] == [{"operation": "compare inputs", "type": "internal_error",
                                                    "message": "cannot compare the inputs: KeyError: 'id'"}]


@pytest.fixture
def comparator_env(tmp_path, monkeypatch):
    """The env `run` reads, outside the runner; returns (evidence dir, status file)."""
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    return tmp_path / "evidence", tmp_path / "status.json"


def _written(evidence_dir: Path, status: Path):
    return json.loads((evidence_dir / "out.json").read_text()), json.loads(status.read_text())


def test_run_compares_and_writes_the_file(tmp_path, monkeypatch, comparator_env):
    monkeypatch.setenv(ci.INPUTS_ENV, str(_index(tmp_path, _inv([_envelope_file(tmp_path / "a.json")]))))
    code = ci.run(lambda inputs: ([{"id": "a"}], {"records": 1}), output="out.json", summary_keys=("records",))
    payload = json.loads((comparator_env[0] / "out.json").read_text())
    assert code == 0 and payload["summary"] == {"records": 1, "inputs_complete": True}
    assert not comparator_env[1].exists()


def test_run_does_not_call_check_when_an_input_is_missing(tmp_path, monkeypatch, comparator_env):
    monkeypatch.setenv(ci.INPUTS_ENV, str(_index(tmp_path, in_manifest=False)))
    called = []
    code = ci.run(lambda inputs: called.append(1), output="out.json", summary_keys=("records",))
    payload, status = _written(*comparator_env)
    assert code == 1 and not called
    assert payload["summary"] == {"records": None, "inputs_complete": False}
    assert status["code"] == "input_failed" and "not in the manifest" in status["error"]


def test_run_still_writes_the_file_when_the_index_cannot_be_read(tmp_path, monkeypatch, comparator_env):
    monkeypatch.setenv(ci.INPUTS_ENV, str(tmp_path / "gone.json"))
    code = ci.run(lambda inputs: ([], {}), output="out.json", summary_keys=("records", "matched"))
    payload, status = _written(*comparator_env)
    assert code == 1
    assert payload["results"] == [] and payload["summary"] == {"records": None, "matched": None, "inputs_complete": False}
    assert payload["metadata"]["api_failures"][0]["type"] == "internal_error"
    assert status["code"] == "internal_error" and "cannot read the comparator input index" in status["error"]


def test_run_writes_a_whole_file_when_the_result_is_not_json(tmp_path, monkeypatch, comparator_env):
    monkeypatch.setenv(ci.INPUTS_ENV, str(_index(tmp_path, _inv([_envelope_file(tmp_path / "a.json")]))))
    code = ci.run(lambda inputs: ([{"seen": {"a set"}}], {"records": 1}), output="out.json", summary_keys=("records",))
    payload, status = _written(*comparator_env)
    assert code == 1
    assert payload["results"] == [] and payload["summary"] == {"records": None, "inputs_complete": True}
    assert status["code"] == "internal_error" and "cannot write the comparison: TypeError" in status["error"]


def test_reader_needs_the_index(monkeypatch):
    monkeypatch.delenv(ci.INPUTS_ENV, raising=False)
    with pytest.raises(RuntimeError, match="COMPARATOR_INPUTS"):
        ci.load_inputs()
