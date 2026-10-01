"""wiz_issues_report: the project a report is scoped to is part of its identity."""

import logging
from pathlib import Path

from fake_wiz import load_fetcher, run_main

FETCHER = Path(__file__).resolve().parents[1] / "fetcher.py"
PROJECT = "96a0d4ea-88bf-486c-8461-5952b83b4ad4"


def run(fake, monkeypatch, tmp_path, **env):
    mod = load_fetcher(FETCHER, "wiz_issues_fetcher_scoping")
    return run_main(mod, monkeypatch, tmp_path, {**fake.env(), **env})


def test_all_projects_keeps_the_original_default_name(fake, monkeypatch, tmp_path):
    result = run(fake, monkeypatch, tmp_path)
    assert result["rc"] == 0
    assert fake.creates[0]["name"] == "Paramify-Wiz-Issues"
    assert fake.creates[0]["projectId"] == "*"


def test_a_project_scopes_the_default_report_name(fake, monkeypatch, tmp_path):
    result = run(fake, monkeypatch, tmp_path, WIZ_PROJECT_ID=PROJECT)
    assert result["rc"] == 0
    assert fake.creates[0]["name"] == "Paramify-Wiz-Issues-96a0d4ea"
    assert fake.creates[0]["projectId"] == PROJECT


def test_changing_project_creates_a_new_report_instead_of_reusing(fake, monkeypatch, tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    run(fake, monkeypatch, tmp_path / "a")
    run(fake, monkeypatch, tmp_path / "b", WIZ_PROJECT_ID=PROJECT)
    assert [c["projectId"] for c in fake.creates] == ["*", PROJECT]
    assert len({c["name"] for c in fake.creates}) == 2


def test_an_explicit_report_name_is_used_as_given(fake, monkeypatch, tmp_path):
    run(fake, monkeypatch, tmp_path, WIZ_PROJECT_ID=PROJECT, WIZ_REPORT_NAME="Mine")
    assert fake.creates[0]["name"] == "Mine"


def test_the_log_line_records_the_effective_project(fake, monkeypatch, tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="wiz_issues_report"):
        run(fake, monkeypatch, tmp_path, WIZ_PROJECT_ID=PROJECT)
    saved = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Saved")]
    assert saved and f"project_id={PROJECT}" in saved[0]


def test_the_log_line_says_all_projects_when_unscoped(fake, monkeypatch, tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="wiz_issues_report"):
        run(fake, monkeypatch, tmp_path)
    saved = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Saved")]
    assert saved and "project_id=*" in saved[0]
