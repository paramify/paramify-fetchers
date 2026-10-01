"""wiz_issues_report against a local fake Wiz (no real network)."""

from pathlib import Path

import pytest
import requests
from fake_wiz import load_fetcher, run_main

FETCHER = Path(__file__).resolve().parents[1] / "fetcher.py"
CSV = "wiz_issues_report.csv"


@pytest.fixture
def run(fake, monkeypatch, tmp_path):
    def _run(**env):
        mod = load_fetcher(FETCHER, "wiz_issues_fetcher")
        return run_main(mod, monkeypatch, tmp_path, {**fake.env(), **env})
    return _run


def test_success_writes_the_report_byte_for_byte(fake, run):
    result = run()
    assert result["rc"] == 0
    assert result["files"] == [CSV]          # no .part left behind
    assert (result["out"] / CSV).read_bytes() == fake.issues_csv().encode()
    assert result["status"] is None
    assert fake.downloads == 1
    # The presigned URL must never receive the Wiz bearer token.
    assert fake.download_auth_headers == [None]


def test_report_failed_three_times_gives_up_and_writes_nothing(fake, run):
    fake.report_fail_runs = 9
    result = run()
    assert result["rc"] == 1
    assert result["files"] == []
    assert result["status"]["code"] == "partial_failure"
    assert "three times" in result["status"]["error"]
    assert fake.downloads == 0


def test_report_failing_fewer_than_three_times_recovers(fake, run):
    fake.report_fail_runs = 2
    result = run()
    assert result["rc"] == 0 and result["files"] == [CSV]


def test_stale_last_run_is_not_downloaded(fake, run):
    """A COMPLETED run whose runAt predates this fetch is last time's report."""
    fake.stale_polls = 2
    result = run()
    assert result["rc"] == 0
    assert fake.polls >= 3                    # kept polling past the stale answers
    assert fake.downloads == 1                # and fetched only the fresh run


def test_header_only_report_is_refused(fake, run):
    fake.issues_rows = 0
    result = run()
    assert result["rc"] == 1
    assert result["files"] == []              # file removed, nothing to upload
    assert result["status"]["code"] == "partial_failure"
    assert "no rows" in result["status"]["error"]


def test_allow_empty_accepts_a_header_only_report(fake, run):
    fake.issues_rows = 0
    result = run(WIZ_ALLOW_EMPTY="true")
    assert result["rc"] == 0 and result["files"] == [CSV]
    assert (result["out"] / CSV).read_text() == fake.issues_csv()


def test_bad_auth_url_is_refused_with_zero_network_calls(fake, run, monkeypatch):
    calls = []
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send",
                        lambda *a, **k: calls.append(a) or pytest.fail("network call made"))
    result = run(WIZ_AUTH_URL="https://attacker.example/oauth/token")
    assert result["rc"] == 1
    assert result["status"]["code"] == "bad_config"
    assert calls == [] and fake.log == []


def test_non_wiz_api_endpoint_is_refused_with_zero_network_calls(fake, run, monkeypatch):
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send",
                        lambda *a, **k: pytest.fail("network call made"))
    result = run(WIZ_API_ENDPOINT="https://api.wiz.io.attacker.example/graphql")
    assert result["rc"] == 1 and result["status"]["code"] == "bad_config"
    assert fake.log == []


def test_wrong_secret_is_an_auth_failure(fake, run):
    result = run(WIZ_CLIENT_SECRET="wrong")
    assert result["rc"] == 1
    assert result["status"]["code"] == "auth_failed"
    assert "wrong" not in result["status"]["error"]
