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


def test_open_workspace_logs_only_to_a_logger_it_is_given(caplog):
    """The CLI and TUI print the error themselves; a stray log line would print it
    twice, and in the TUI land on the screen."""
    from framework.paramify.connection import open_workspace
    with pytest.raises(ValueError), caplog.at_level("ERROR"):
        open_workspace()
    assert caplog.records == []


def test_open_workspace_returns_a_given_endpoint_object_without_a_token():
    from framework.paramify.connection import open_workspace
    given = object()
    assert open_workspace(use=given)[1] is given


def test_reads_prefer_the_read_token_and_name_it_when_missing(monkeypatch):
    """Each side prefers its own name and falls back to the other, so a workspace
    with two tokens uses the right one for each."""
    monkeypatch.setenv("PARAMIFY_API_TOKEN", "read-tok")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "upload-tok")
    assert settings(read=True).token == "read-tok"
    assert settings().token == "upload-tok"
    monkeypatch.delenv("PARAMIFY_API_TOKEN")
    monkeypatch.delenv("PARAMIFY_UPLOAD_API_TOKEN")
    assert "read scope" in settings(read=True).errors(need_token=True)[0]


def test_each_read_builds_its_client_in_one_place_with_its_own_token(monkeypatch, tmp_path):
    """Patching connection.Client reaches every read, and with both tokens set
    each command uses its side's: workspace reads the read token, stacks (an
    upload concern) the upload token."""
    from framework import api
    from framework.paramify import connection

    built = []

    class Stop(Exception):
        pass

    def spy(token, base_url, **kw):
        built.append(token)
        raise Stop

    monkeypatch.setattr(connection, "Client", spy)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("PARAMIFY_API_TOKEN", "read-tok")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "upload-tok")
    for read in (api.list_programs, lambda: api.list_stacks(tmp_path)):
        with pytest.raises(Stop):
            read()
    assert built == ["read-tok", "upload-tok"]


def test_doctor_accepts_a_local_stub_like_every_other_stage(monkeypatch, tmp_path):
    from framework import api
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "tok")
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", "http://localhost:8080/api/v0")
    assert api.upload_readiness(tmp_path)["ok"]
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", "http://app.example.test/api/v0")
    assert "https" in api.upload_readiness(tmp_path)["errors"][0]


# --------------------------------------------------------------------------- #
# Workspace reads: every failure is one RuntimeError a CLI prints verbatim
# --------------------------------------------------------------------------- #

class _Reply:
    headers: dict = {}

    def __init__(self, status, text):
        self.status_code, self.text = status, text

    def json(self):
        import json
        return json.loads(self.text)


@pytest.fixture
def read_env(monkeypatch):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("PARAMIFY_API_TOKEN", "tok")
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", "https://api.example.test")


def _answer(monkeypatch, reply):
    from tests.paramify_fake import reads_through

    def fake_get(url, headers=None, params=None, timeout=None):
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr("framework.paramify.client.requests.Session", lambda: reads_through(fake_get))


@pytest.mark.parametrize("reply, expected", [
    (_Reply(401, "no"), r"rejected the token \(HTTP 401\).*read scope"),
    (_Reply(500, "boom"), r"failed \(HTTP 500\): boom"),
    (_Reply(200, "<html>login</html>"), r"non-JSON body: <html>login</html>"),
    (_Reply(200, ""), r"non-JSON body: \(empty\)"),
])
def test_a_failed_read_is_one_printable_error(read_env, monkeypatch, reply, expected):
    from framework import api
    _answer(monkeypatch, reply)
    with pytest.raises(RuntimeError, match=expected):
        api.list_programs()


def test_an_unreachable_workspace_says_so_without_claiming_a_retry(read_env, monkeypatch):
    import requests

    from framework import api
    _answer(monkeypatch, requests.ConnectionError("dns failed"))
    with pytest.raises(RuntimeError, match="could not reach https://api.example.test/projects") as e:
        api.list_programs()
    assert "after retrying" not in str(e.value)


def test_the_https_error_names_the_setting_the_user_set(monkeypatch):
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", "http://app.example.test")
    assert settings().errors(need_token=False)[0].startswith("PARAMIFY_API_BASE_URL must be https")
    cfg = {"paramify": {"base_url": "http://app.example.test"}}
    assert settings(cfg).errors(need_token=False)[0].startswith("base_url must be https")
