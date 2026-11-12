"""Tests for the legacy evidence uploader script (uploaders/paramify_evidence/uploader.py).

The script is a thin, deprecated wrapper: `upload_run` and `main` hand the run to
the sync engine (framework/api.upload_run). The engine has its own tests
(test_api_upload_engine.py, test_sync_*.py, test_validator_sync.py); these cover
what the wrapper itself promises: the legacy signature and summary keys, a
config dict passed through without touching disk, token and base URL arguments,
the deprecation notice, and the flags of `main`.

The module is not an importable package (schedules load it by path), so it is
loaded the same way here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tests.test_api_upload_engine import fake, no_env  # noqa: F401  (fixtures)

REPO_ROOT = Path(__file__).resolve().parent.parent
_UPLOADER_PATH = REPO_ROOT / "uploaders" / "paramify_evidence" / "uploader.py"
_spec = importlib.util.spec_from_file_location("uploader_under_test", _UPLOADER_PATH)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)

LEGACY = {"uploaded", "skipped_duplicate", "skipped_failed", "errors", "ok"}
URL = "https://api.example.test"


def write_evidence(run_dir, name, *, reference_id="EVD-1", set_name="Set",
                   status="success", run_id="RID", target=None, enveloped=True,
                   category=None):
    if not enveloped:
        (run_dir / name).write_text(json.dumps({"just": "data"}))
        return
    env = {
        "schema_version": "1.0",
        "metadata": {
            "fetcher_name": "f", "fetcher_version": "0.1.0", "run_id": run_id,
            "collected_at": "2026-01-01T00:00:00Z", "status": status,
            "exit_code": 0 if status == "success" else 1,
            "evidence_set": {"reference_id": reference_id, "name": set_name},
        },
        "payload": {"k": 1},
    }
    if target:
        env["metadata"]["target"] = target
    if category:
        env["metadata"]["category"] = category
    (run_dir / name).write_text(json.dumps(env))


def _run(tmp_path, *names, **kw):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    for n in names or ("a.json",):
        write_evidence(run_dir, n, **kw)
    return run_dir


# --------------------------------------------------------------------------- #
# upload_run: legacy signature, engine behind it
# --------------------------------------------------------------------------- #

def test_upload_run_returns_the_legacy_keys_and_log(fake, tmp_path):  # noqa: F811
    run_dir = _run(tmp_path, "a.json", "b.json")
    events = []
    summary = uploader.upload_run(run_dir, config={}, on_event=events.append)
    assert LEGACY <= set(summary) and {"results", "tags", "log_path", "files"} <= set(summary)
    assert (summary["uploaded"], summary["errors"], summary["ok"]) == (2, 0, True)
    assert [e["event"] for e in events if e["event"].startswith("upload_")][0] == "upload_start"
    log = json.loads((run_dir / "upload_log.json").read_text())
    assert "deprecations" not in log  # only main() adds it


def test_a_second_upload_of_the_same_run_changes_nothing(fake, tmp_path):  # noqa: F811
    run_dir = _run(tmp_path)
    uploader.upload_run(run_dir)
    again = uploader.upload_run(run_dir)
    assert again["uploaded"] == 0 and again["skipped_duplicate"] == 1 and again["ok"] is True


def test_config_dict_is_used_and_nothing_is_written_beside_the_run(fake, tmp_path):  # noqa: F811
    run_dir = _run(tmp_path, status="failed")
    summary = uploader.upload_run(run_dir, config={"skip_failed": True})
    assert summary["skipped_failed"] == 1 and summary["uploaded"] == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == ["run-x"]


def test_failed_status_uploads_by_default(fake, tmp_path):  # noqa: F811
    summary = uploader.upload_run(_run(tmp_path, status="failed"))
    assert summary["uploaded"] == 1


def test_unenveloped_file_is_an_error_and_the_rest_upload(fake, tmp_path):  # noqa: F811
    run_dir = _run(tmp_path, "ok.json")
    write_evidence(run_dir, "raw.json", enveloped=False)
    summary = uploader.upload_run(run_dir)
    assert summary["uploaded"] == 1 and summary["errors"] == 1 and summary["ok"] is False
    [raw] = [r for r in summary["results"] if r["file"] == "raw.json"]
    assert raw["outcome"] == "error" and "not envelope-wrapped" in raw["reason"]


def test_https_guard_rejects_http_remote(tmp_path):
    with pytest.raises(ValueError, match="https"):
        uploader.upload_run(_run(tmp_path), token="tok", base_url="http://evil.example.com", dry_run=True)


def test_https_guard_allows_localhost_http(tmp_path):
    summary = uploader.upload_run(_run(tmp_path), base_url="http://localhost:8080", dry_run=True)
    assert summary["dry_run"] is True and summary["files"] == 1


def test_empty_run_dir_raises(tmp_path):
    run_dir = tmp_path / "run-empty"
    run_dir.mkdir()
    with pytest.raises(ValueError, match="no evidence files"):
        uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0", dry_run=True)


def test_missing_token_is_a_setup_error(no_env, tmp_path):  # noqa: F811
    with pytest.raises(ValueError, match="PARAMIFY_UPLOAD_API_TOKEN"):
        uploader.upload_run(_run(tmp_path))


def test_token_and_base_url_arguments_win_over_the_environment(no_env, tmp_path, monkeypatch):  # noqa: F811
    from framework.sync import upload as upload_mod

    seen = {}

    class Stop(Exception):
        pass

    def spy(token, base_url, **kw):
        seen.update(token=token, base_url=base_url)
        raise Stop

    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "env-tok")
    monkeypatch.setattr(upload_mod, "Client", spy)
    with pytest.raises(Stop):
        uploader.upload_run(_run(tmp_path), token="arg-tok", base_url="https://arg.example.test")
    assert seen == {"token": "arg-tok", "base_url": "https://arg.example.test"}


def test_dry_run_plans_tags_and_makes_no_call(no_env, tmp_path):  # noqa: F811
    run_dir = _run(tmp_path, reference_id="EVD-A", category="aws")
    summary = uploader.upload_run(run_dir, dry_run=True)
    assert summary["results"][0]["outcome"] == "would_upload"
    assert summary["results"][0]["tags"] == ["Automated by Paramify Fetchers", "AWS"]
    assert summary["tags"]["applied"] == 0 and not (run_dir / "upload_log.json").exists()


def test_no_tags_switch_turns_tags_off(fake, tmp_path):  # noqa: F811
    summary = uploader.upload_run(_run(tmp_path), custom_tags=False)
    assert summary["tags"]["enabled"] is False and "tags" not in summary["results"][0]


def test_the_summary_no_longer_carries_per_file_ids(fake, tmp_path):  # noqa: F811
    summary = uploader.upload_run(_run(tmp_path))
    for r in summary["results"]:
        assert not {"evidence_id", "artifact_id", "channel_id"} & set(r)


# --------------------------------------------------------------------------- #
# main: every flag still works; the deprecation is stated and logged
# --------------------------------------------------------------------------- #

def test_main_prints_the_deprecation_and_logs_it(fake, tmp_path, capsys):  # noqa: F811
    run_dir = _run(tmp_path)
    assert uploader.main([str(run_dir)]) == 0
    assert uploader.DEPRECATION in capsys.readouterr().err
    assert uploader.DEPRECATION == "paramify_evidence/uploader.py is deprecated; use 'paramify upload'"
    log = json.loads((run_dir / "upload_log.json").read_text())
    assert log["deprecations"] == [uploader.DEPRECATION] and log["uploaded"] == 1


def test_main_dry_run_and_config_flags(no_env, tmp_path, capsys):  # noqa: F811
    run_dir = _run(tmp_path, status="failed")
    cfg = tmp_path / "up.yaml"
    cfg.write_text("skip_failed: true\n")
    assert uploader.main([str(run_dir), "--dry-run", "--config", str(cfg)]) == 0
    assert not (run_dir / "upload_log.json").exists()


def test_main_picks_the_latest_run_under_output_dir(fake, tmp_path):  # noqa: F811
    out = tmp_path / "evidence"
    for name in ("run-2026-01-01", "run-2026-02-01"):
        d = out / name
        d.mkdir(parents=True)
        write_evidence(d, "a.json")
    assert uploader.main(["--output-dir", str(out)]) == 0
    assert (out / "run-2026-02-01" / "upload_log.json").exists()
    assert not (out / "run-2026-01-01" / "upload_log.json").exists()


def test_main_returns_1_without_a_run_dir(tmp_path):
    assert uploader.main(["--output-dir", str(tmp_path / "nope")]) == 1


def test_main_returns_1_on_a_setup_error(no_env, tmp_path):  # noqa: F811
    assert uploader.main([str(_run(tmp_path))]) == 1  # no token


def test_main_returns_1_when_an_entry_is_refused(fake, tmp_path):  # noqa: F811
    run_dir = _run(tmp_path)
    (run_dir / "a.json").write_text((run_dir / "a.json").read_text().replace('"k": 1', '"k": "/bin/sh -c x"'))
    assert uploader.main([str(run_dir)]) == 1


def test_main_returns_1_when_a_file_is_not_an_envelope(fake, tmp_path):  # noqa: F811
    run_dir = _run(tmp_path, "ok.json")
    write_evidence(run_dir, "raw.json", enveloped=False)
    assert uploader.main([str(run_dir)]) == 1


def test_main_names_the_exception_type_for_an_unexpected_error(no_env, tmp_path, monkeypatch, caplog):  # noqa: F811
    def boom(*a, **k):
        raise KeyError("x")

    monkeypatch.setattr(uploader, "_upload", boom)
    assert uploader.main([str(_run(tmp_path))]) == 1
    assert "KeyError: " in caplog.text
