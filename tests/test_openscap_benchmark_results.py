"""openscap_benchmark_results over hand-built XCCDF 1.2 and ARF 1.1 files shaped like oscap output: no oscap, no Azure.

node-a was scanned twice: an older scan with five high failures and the latest with one high and one medium failure,
a not-applicable rule and a waived rule. node-b's ARF report (gzipped) passes everything. An OVAL results file holds
no XCCDF TestResult.
"""

import importlib.util
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "openscap_benchmark_results"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
spec = importlib.util.spec_from_file_location("openscap_benchmark_results_under_test",
                                              REPO_ROOT / "fetchers" / "openscap" / "benchmark_results" / "fetcher.py")
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
CONTAINER = "https://acct.blob.core.windows.net/scan-results"
ENV = ("OPENSCAP_RESULTS_CONTAINER_URL", "OPENSCAP_RESULTS_DIR", "OPENSCAP_RESULTS_PREFIX", "OPENSCAP_EXPECTED_TARGETS",
       "OPENSCAP_MAX_AGE_DAYS")


@pytest.fixture
def results_dir(tmp_path):
    d = tmp_path / "results" / "scans"
    d.mkdir(parents=True)
    for f in FIXTURES.iterdir():
        if f.name != "README.txt":
            shutil.copy(f, d / f.name)
    return tmp_path / "results"


class Response:
    def __init__(self, status, content=b""):
        self.status_code, self.content = status, content
        self.text = content.decode(errors="replace")


class Blob:
    """A fake requests.Session answering List Blobs (two pages) and Get Blob for the fixture files."""

    def __init__(self, files, status=None):
        self.files, self.status, self.calls = files, status or {}, []

    def get(self, url, params=None, headers=None, timeout=None, allow_redirects=None):
        self.calls.append((url, dict(params or {}), dict(headers or {})))
        name = url[len(CONTAINER) + 1:] if url != CONTAINER else None
        if (name or "list") in self.status:
            return Response(self.status[name or "list"], b"<Error><Code>AuthorizationPermissionMismatch</Code></Error>")
        if name is None:
            names = sorted(self.files)
            page = names[:2] if not params.get("marker") else names[2:]
            blobs = "".join(f"<Blob><Name>{n}</Name><Properties><Content-Length>{len(self.files[n])}</Content-Length>"
                            f"</Properties></Blob>" for n in page)
            marker = "" if params.get("marker") else "<NextMarker>page2</NextMarker>"
            return Response(200, f'<?xml version="1.0"?><EnumerationResults ContainerName="{CONTAINER}"><Blobs>{blobs}'
                                 f'</Blobs>{marker}</EnumerationResults>'.encode())
        return Response(200, self.files[name])


def blob_files(extra=None):
    files = {f"scans/{f.name}": f.read_bytes() for f in FIXTURES.iterdir() if f.name != "README.txt"}
    files["other/notes.txt"] = b"not a result"
    files.update(extra or {})
    return files


@pytest.fixture
def run(monkeypatch, tmp_path):
    def go(session=None, **env):
        for key in ENV:
            monkeypatch.delenv(key, raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        out = tmp_path / "out"
        monkeypatch.setenv("EVIDENCE_DIR", str(out))
        monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
        monkeypatch.setattr(fx, "load_dotenv", lambda *a, **k: None)
        monkeypatch.setattr(fx.time, "sleep", lambda s: None)
        monkeypatch.setattr(fx, "_storage_token", lambda: (lambda: "storage-token"))
        monkeypatch.setattr(fx.requests, "Session", lambda: session)
        real = fx.collect
        monkeypatch.setattr(fx, "collect", lambda *a, **k: real(*a, now=NOW))
        code = fx.main()
        status = tmp_path / "status.json"
        return code, json.loads((out / "openscap_benchmark_results.json").read_text()), \
            json.loads(status.read_text()) if status.exists() else None
    return go


def test_latest_scan_per_target_from_a_directory(run, results_dir, assert_summary_documented):
    code, ev, _ = run(OPENSCAP_RESULTS_DIR=str(results_dir))
    s = ev["summary"]
    assert code == 0 and (s["results_source"], s["files_found"], s["files_without_test_results"]) == ("directory", 4, 1)
    assert (s["test_results_read"], s["targets_scanned"], s["profiles"]) == (3, 2, ["xccdf_org.ssgproject.content_profile_stig"])
    # node-a's older scan (five high failures) is superseded by its latest.
    assert (s["rules_failed"], s["rules_failed_by_severity"]) == (2, {"high": 1, "medium": 1, "low": 0, "info": 0, "unknown": 0})
    assert (s["targets_with_failures"], s["targets_with_failures_names"], s["targets_with_errors"]) == (1, ["node-a"], 0)
    assert (s["rules_waived"], s["all_targets_pass"], s["oldest_latest_scan_age_days"]) == (1, False, 2.2)
    # Nothing adopted: expected targets and maximum age are not judged.
    assert (s["expected_targets_missing"], s["targets_scan_older_than_max_age"]) == (None, None)
    assert_summary_documented("openscap/benchmark_results", s)


def test_target_records_keep_ids_and_results_not_rule_text(run, results_dir):
    _, ev, _ = run(OPENSCAP_RESULTS_DIR=str(results_dir))
    by = {t["target"]: t for t in ev["results"]["targets"]}
    a = by["node-a"]
    assert (a["file"], a["end_time"], a["score"]) == ("scans/xccdf-node-a-2026-11-19.xml", "2026-11-19T06:04:10Z", 71.4)
    assert a["rule_results"]["notapplicable"] == 1 and a["failed_rules"][0] == {
        "rule": "xccdf_org.ssgproject.content_rule_sshd_use_approved_ciphers", "severity": "high"}
    assert a["waived_rules"] == [{"rule": "xccdf_org.ssgproject.content_rule_grub2_password", "old_result": "fail", "new_result": "pass"}]
    assert by["node-b"]["file"] == "scans/arf-node-b-2026-11-18.arf.gz" and by["node-b"]["rule_results"]["pass"] == 3
    assert "SECRET-RULE-TEXT" not in json.dumps(ev) and "POA&M" not in json.dumps(ev)


def test_expected_targets_and_maximum_age(run, results_dir, assert_summary_documented):
    code, ev, _ = run(OPENSCAP_RESULTS_DIR=str(results_dir), OPENSCAP_EXPECTED_TARGETS="NODE-A, node-b, node-c",
                      OPENSCAP_MAX_AGE_DAYS="2")
    s = ev["summary"]
    assert code == 0 and (s["expected_targets"], s["expected_targets_missing"], s["expected_targets_missing_names"]) == (["NODE-A", "node-b", "node-c"], 1, ["node-c"])
    # node-b's latest scan is 2.25 days old.
    assert (s["max_age_days"], s["targets_scan_older_than_max_age"]) == (2, 1)
    assert_summary_documented("openscap/benchmark_results", s)


def test_every_target_passing(run, results_dir):
    for f in results_dir.joinpath("scans").glob("xccdf-node-a-*"):
        f.unlink()
    code, ev, _ = run(OPENSCAP_RESULTS_DIR=str(results_dir), OPENSCAP_MAX_AGE_DAYS="7")
    s = ev["summary"]
    assert code == 0 and (s["all_targets_pass"], s["rules_failed"], s["targets_scan_older_than_max_age"]) == (True, 0, 0)


def test_a_container_read_page_by_page_with_the_storage_token(run):
    session = Blob(blob_files())
    code, ev, _ = run(session=session, OPENSCAP_RESULTS_CONTAINER_URL=CONTAINER + "/", OPENSCAP_RESULTS_PREFIX="scans/")
    s = ev["summary"]
    assert code == 0 and (s["results_source"], s["files_found"], s["targets_scanned"]) == ("container", 4, 2)
    lists = [c for c in session.calls if c[0] == CONTAINER]
    assert len(lists) == 2 and lists[0][1]["prefix"] == "scans/" and lists[1][1]["marker"] == "page2"
    assert all(c[2]["Authorization"] == "Bearer storage-token" and c[0].startswith(CONTAINER) for c in session.calls)
    assert ev["metadata"]["results_location"] == CONTAINER


def test_an_unparseable_file_leaves_the_judgement_null(run, results_dir, assert_summary_documented):
    results_dir.joinpath("scans", "truncated.xml").write_text('<?xml version="1.0"?><Benchmark xmlns="http://checklists')
    code, ev, status = run(OPENSCAP_RESULTS_DIR=str(results_dir), OPENSCAP_EXPECTED_TARGETS="node-a")
    s = ev["summary"]
    assert code == 1 and s["files_unreadable"] == 1 and status["code"] == "partial_failure"
    for k in ("targets_scanned", "rules_failed", "rules_failed_by_severity", "all_targets_pass", "expected_targets_missing",
              "targets_with_failures"):
        assert s[k] is None, k
    assert ev["metadata"]["api_failures"][0]["operation"] == "read scans/truncated.xml"
    assert_summary_documented("openscap/benchmark_results", s)


def test_xml_entity_expansion_is_refused(run, results_dir):
    bomb = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;">]>'
            '<x>&b;</x>')
    results_dir.joinpath("scans", "bomb.xml").write_text(bomb)
    code, ev, _ = run(OPENSCAP_RESULTS_DIR=str(results_dir))
    assert code == 1 and ev["summary"]["files_unreadable"] == 1


def test_a_refused_container_is_not_authorized(run):
    code, ev, status = run(session=Blob(blob_files(), status={"list": 403}), OPENSCAP_RESULTS_CONTAINER_URL=CONTAINER)
    assert code == 1 and status["code"] == "not_authorized"
    assert (ev["summary"]["files_found"], ev["summary"]["all_targets_pass"]) == (None, None)


def test_an_empty_location_scans_nothing(run, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    code, ev, _ = run(OPENSCAP_RESULTS_DIR=str(empty))
    s = ev["summary"]
    assert code == 0 and (s["files_found"], s["targets_scanned"], s["all_targets_pass"]) == (0, 0, None)


@pytest.mark.parametrize("env", [{},
                                 {"OPENSCAP_RESULTS_DIR": "/x", "OPENSCAP_RESULTS_CONTAINER_URL": CONTAINER},
                                 {"OPENSCAP_RESULTS_CONTAINER_URL": "http://acct.blob.core.windows.net/c"},
                                 {"OPENSCAP_RESULTS_CONTAINER_URL": "https://acct.blob.core.windows.net/c/sub"},
                                 {"OPENSCAP_RESULTS_DIR": "/x", "OPENSCAP_MAX_AGE_DAYS": "a week"}])
def test_bad_settings_fail_as_bad_config(run, env):
    code, ev, status = run(session=Blob({}), **env)
    assert code == 1 and status["code"] == "bad_config" and ev["metadata"]["api_failures"][0]["operation"].startswith("config")
