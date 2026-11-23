"""`run.parallel_categories`: entries of different categories run at once.

Entries of one category still run one after another. Whatever the timing, a
run comes out as a run in manifest order leaves it: the same events in the
same order, the same _run_metadata.json order, and the same overwrite failures.

The tests stage a small repo in tmp_path with real subprocess fetchers in two
categories.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from framework import api
from framework.runner import manifest_loader
from framework.runner.executor import _Running

REPO_ROOT = Path(__file__).resolve().parent.parent

# Sleeps for its `pause` config, then writes `<file>` holding when it started and ended.
TIMED = (
    "import json, os, time\n"
    "start = time.time()\n"
    "print('working', flush=True)\n"
    "time.sleep(float(os.environ['PAUSE']))\n"
    "body = {'metadata': {'partial_failure': False, 'api_failures': []},\n"
    "        'results': [{'start': start, 'end': time.time(), 'by': os.environ['WHO']}]}\n"
    "open(os.path.join(os.environ['EVIDENCE_DIR'], os.environ['FILE']), 'w').write(json.dumps(body))\n"
)


def _fetcher(root: Path, category: str, short: str, *, pause: float, file: str = "", extra: str = "",
             kind: str = "", output_type: str = "json") -> str:
    name = f"{category}_{short}"
    d = root / "fetchers" / category / short
    d.mkdir(parents=True)
    (d / "fetcher.yaml").write_text(
        f"name: {name}\nversion: 0.1.0\ndescription: d\ncategory: {category}\n"
        + (f"kind: {kind}\n" if kind else "")
        + "runtime:\n  type: python\n  entry: fetcher.py\n"
        f"output:\n  type: {output_type}\n  path: {file or short + '.json'}\n"
        "secrets: []\n"
        + ("" if kind else f"evidence_set:\n  reference_id: EVD-{short.upper()}\n  name: {short}\n")
        + "config_schema:\n"
        f"  pause:\n    type: string\n    required: false\n    default: '{pause}'\n    env: PAUSE\n"
        f"  file:\n    type: string\n    required: false\n    default: '{file or short + '.json'}'\n    env: FILE\n"
        f"  who:\n    type: string\n    required: false\n    default: '{name}'\n    env: WHO\n"
        + extra
    )
    (d / "fetcher.py").write_text(TIMED)
    return name


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / "framework" / "schemas").mkdir(parents=True)
    for src in (REPO_ROOT / "framework" / "schemas").glob("*.json"):
        (tmp_path / "framework" / "schemas" / src.name).write_bytes(src.read_bytes())
    shutil.copytree(REPO_ROOT / "fetchers" / "_lib", tmp_path / "fetchers" / "_lib")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _manifest(root: Path, uses, parallel=True) -> dict:
    run = {"output_dir": str(root / "out"), "fetchers": [{"use": u} for u in uses]}
    if parallel is not None:
        run["parallel_categories"] = parallel
    return {"run": run}


def _times(run_dir: Path, name: str) -> dict:
    payload = json.loads((run_dir / name).read_text())
    return payload["results"][0] if "results" in payload else payload["payload"]["results"][0]


def _run(root: Path, manifest: dict):
    events: list = []
    summary = api.run(manifest, root, on_event=events.append)
    return summary, events


def test_a_slow_category_does_not_hold_up_another(repo):
    slow = _fetcher(repo, "alpha", "slow", pause=0.8)
    after = _fetcher(repo, "alpha", "after", pause=0.0)
    fast = _fetcher(repo, "beta", "fast", pause=0.0)

    summary, _ = _run(repo, _manifest(repo, [slow, after, fast]))

    run_dir = Path(summary["run_dir"])
    t = {n: _times(run_dir, f"{n}.json") for n in ("slow", "after", "fast")}
    assert summary["ok"] is True
    # The other category started while the slow entry ran...
    assert t["fast"]["start"] < t["slow"]["end"]
    # ...but the next entry of the slow one's own category waited for it.
    assert t["after"]["start"] >= t["slow"]["end"]


def test_without_the_setting_every_entry_runs_one_after_another(repo):
    slow = _fetcher(repo, "alpha", "slow", pause=0.3)
    fast = _fetcher(repo, "beta", "fast", pause=0.0)

    summary, _ = _run(repo, _manifest(repo, [slow, fast], parallel=None))

    run_dir = Path(summary["run_dir"])
    assert _times(run_dir, "fast.json")["start"] >= _times(run_dir, "slow.json")["end"]


def _shape(events):
    """The events with what varies between runs (timing, paths, ids) left out."""
    keep = ("event", "fetcher", "exit_code", "target", "outputs", "reason", "error", "note", "line")
    return [{k: v for k, v in e.items() if k in keep} for e in events if e["event"] not in ("run_start", "run_complete")]


def test_events_metadata_and_summary_keep_manifest_order(repo):
    # The first entry is the slowest, so a later category finishes first.
    slow = _fetcher(repo, "alpha", "slow", pause=0.5)
    fast = _fetcher(repo, "beta", "fast", pause=0.0)
    needs = _fetcher(repo, "beta", "needs", pause=0.0,
                     extra="  url:\n    type: string\n    required: true\n    env: NEEDS_URL\n")
    last = _fetcher(repo, "alpha", "last", pause=0.0)
    uses = [slow, fast, "beta_ghost", needs, last]

    serial, serial_events = _run(repo, _manifest(repo, uses, parallel=False))
    parallel, parallel_events = _run(repo, _manifest(repo, uses))

    assert _shape(parallel_events) == _shape(serial_events)
    for summary in (serial, parallel):
        assert [i["fetcher_name"] for i in summary["invocations"]] == [slow, fast, last]
        assert [s["fetcher"] for s in summary["skipped"]] == ["beta_ghost"]
        assert [s["fetcher"] for s in summary["setup_errors"]] == [needs]
        assert summary["ok"] is False
    metadata = json.loads(Path(parallel["metadata_path"]).read_text())
    assert [i["fetcher_name"] for i in metadata["invocations"]] == [slow, fast, last]
    # Envelopes are written into the run dir; no staging dir is left behind.
    run_dir = Path(parallel["run_dir"])
    assert sorted(p.name for p in run_dir.iterdir()) == ["_run_metadata.json", "fast.json", "last.json", "slow.json"]
    assert "payload" in json.loads((run_dir / "fast.json").read_text())


def test_a_file_name_two_categories_share_fails_the_later_entry_even_if_it_finishes_first(repo):
    earlier = _fetcher(repo, "alpha", "earlier", pause=0.4, file="shared.json")
    later = _fetcher(repo, "beta", "later", pause=0.0, file="shared.json")

    summary, events = _run(repo, _manifest(repo, [earlier, later]))

    first, second = summary["invocations"]
    assert (first["fetcher_name"], first["exit_code"]) == (earlier, 0)
    assert (second["fetcher_name"], second["exit_code"], second["error_code"]) == (later, 1, "output_overwritten")
    assert second["overwritten"] == ["shared.json"] and second["outputs"] == []
    # As a serial run leaves it: the later entry's data, left raw.
    body = json.loads((Path(summary["run_dir"]) / "shared.json").read_text())
    assert body["results"][0]["by"] == later and "payload" not in body
    assert summary["ok"] is False


def test_issue_reports_land_in_the_run_dirs_subdir(repo):
    report = _fetcher(repo, "alpha", "report", pause=0.0, file="report.csv", kind="issue_report",
                      output_type="csv",
                      extra="issue_report:\n  assessment_type: VULNERABILITY\n  title: Report\n")
    evidence = _fetcher(repo, "beta", "ev", pause=0.0)

    summary, _ = _run(repo, _manifest(repo, [report, evidence]))

    by_name = {i["fetcher_name"]: i for i in summary["invocations"]}
    assert by_name[report]["outputs"] == ["issue-reports/report.csv"]
    assert (Path(summary["run_dir"]) / "issue-reports" / "report.csv").is_file()
    assert summary["issue_reports"] == 1


def test_the_head_entry_streams_its_lines_live(repo):
    slow = _fetcher(repo, "alpha", "slow", pause=0.5)
    fast = _fetcher(repo, "beta", "fast", pause=0.0)
    seen: list = []

    def on_event(e):
        seen.append((e["event"], e.get("fetcher"), time.time()))

    summary = api.run(_manifest(repo, [slow, fast]), repo, on_event=on_event)

    line_at = next(t for ev, f, t in seen if ev == "log_line" and f == slow)
    assert line_at < _times(Path(summary["run_dir"]), "slow.json")["end"]
    assert [(ev, f) for ev, f, _ in seen if ev in ("fetcher_start", "fetcher_result")] == [
        ("fetcher_start", slow), ("fetcher_result", slow), ("fetcher_start", fast), ("fetcher_result", fast)]


@pytest.mark.parametrize("value, ok", [(True, True), (False, True), ("yes", False), (1, False)])
def test_manifest_schema_takes_a_boolean(value, ok):
    m = {"run": {"fetchers": [{"use": "demo_hello"}], "parallel_categories": value}}

    assert (manifest_loader.schema_errors(m, REPO_ROOT) == []) is ok


def test_parse_manifest_reads_the_setting():
    on = manifest_loader.parse_manifest({"run": {"fetchers": [], "parallel_categories": True}})
    off = manifest_loader.parse_manifest({"run": {"fetchers": []}})

    assert (on.parallel_categories, off.parallel_categories) == (True, False)


def test_validate_notes_a_setting_with_one_category(tmp_path):
    one = {"run": {"output_dir": str(tmp_path), "parallel_categories": True, "fetchers": [
        {"use": "aws_acm_certificate_status"}, {"use": "aws_iam_password_policy"}]}}
    two = {"run": {"output_dir": str(tmp_path), "parallel_categories": True, "fetchers": [
        {"use": "aws_acm_certificate_status"}, {"use": "demo_hello"}]}}

    assert "parallel_categories has no effect; every fetcher entry is in one category" in api.validate_notes(one, REPO_ROOT)
    assert not any("parallel_categories" in n for n in api.validate_notes(two, REPO_ROOT))


def test_stopping_the_run_group_stops_a_fan_outs_processes():
    run_group = _Running()
    fan_out = _Running(run_group)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    try:
        fan_out.add(proc)
        run_group.stop()
        assert proc.wait(timeout=5) != 0
        assert fan_out.stopped
    finally:
        if proc.poll() is None:
            proc.kill()


def test_stopping_a_fan_out_leaves_the_rest_of_the_run_running():
    run_group = _Running()
    fan_out, sibling = _Running(run_group), _Running(run_group)
    procs = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
             for _ in range(2)]
    try:
        fan_out.add(procs[0])
        sibling.add(procs[1])
        fan_out.stop()
        assert procs[0].wait(timeout=5) != 0
        assert procs[1].poll() is None and not sibling.stopped
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
