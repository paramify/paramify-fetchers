"""Where a stage talks to Paramify and with what token: one resolution for every stage."""

from __future__ import annotations

import pytest

from framework.paramify.connection import connect, settings


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for name in ("PARAMIFY_UPLOAD_API_TOKEN", "PARAMIFY_API_TOKEN", "PARAMIFY_API_BASE_URL"):
        monkeypatch.delenv(name, raising=False)


def test_the_read_token_is_the_fallback_for_every_stage(monkeypatch):
    """A single-token setup worked for some stages and failed others while each
    resolved the token itself."""
    monkeypatch.setenv("PARAMIFY_API_TOKEN", "read-tok")
    resolved, client = connect()
    assert (resolved.token, resolved.token_source) == ("read-tok", "PARAMIFY_API_TOKEN")
    assert client is not None and client.session.headers["Authorization"] == "Bearer read-tok"


def test_config_base_url_wins_then_the_argument_then_the_environment(monkeypatch):
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", "https://env.example.test")
    assert settings().base_url == "https://env.example.test"
    assert settings(base_url="https://arg.example.test").base_url == "https://arg.example.test"
    assert settings(base_url="https://arg.example.test").base_url_source == "argument"
    cfg = {"paramify": {"base_url": "https://cfg.example.test"}}
    winner = settings(cfg, base_url="https://arg.example.test")
    assert (winner.base_url, winner.base_url_source) == ("https://cfg.example.test", "config")


def test_plain_http_is_refused_except_on_localhost():
    with pytest.raises(ValueError, match="https"):
        connect(base_url="http://app.example.test", token="t")
    assert connect(base_url="http://localhost:8080", token="t")[1] is not None


def test_a_missing_token_names_both_variables():
    with pytest.raises(ValueError, match="PARAMIFY_UPLOAD_API_TOKEN.*PARAMIFY_API_TOKEN"):
        connect()


def test_a_dry_run_needs_no_token_and_gets_no_client():
    resolved, client = connect(need_token=False)
    assert client is None and resolved.token is None


def test_a_preflight_lists_every_problem_without_raising():
    problems = settings(base_url="http://app.example.test").errors(need_token=True)
    assert len(problems) == 2 and "https" in problems[0] and "PARAMIFY_UPLOAD_API_TOKEN" in problems[1]
