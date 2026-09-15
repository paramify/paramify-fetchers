"""The shared scaffolding in conftest.py has to work, or every test built on it
inherits the bug. These are cheap and they run in milliseconds.

Note the absence of imports from conftest: pyproject sets
--import-mode=importlib, so conftest is never on sys.path and everything
arrives as a fixture.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def test_repo_root_points_at_the_repo(repo_root):
    assert (repo_root / "pyproject.toml").is_file()
    assert (repo_root / "framework").is_dir()


def test_make_fetcher_roots_at_tmp_path(make_fetcher, tmp_path):
    f = make_fetcher()
    assert f.path == tmp_path
    assert f.supports_targets is False


def test_make_fetcher_overrides_win(make_fetcher):
    f = make_fetcher(name="okta_thing", category="okta", supports_targets=True)
    assert (f.name, f.category, f.supports_targets) == ("okta_thing", "okta", True)


def test_make_fetcher_accepts_an_explicit_path(make_fetcher):
    assert make_fetcher(path=Path("/elsewhere")).path == Path("/elsewhere")


def test_make_result_defaults_to_success(make_result):
    assert make_result().exit_code == 0
    assert make_result(exit_code=124).exit_code == 124


def test_fake_response_json_and_raise_for_status(fake_response):
    assert fake_response(200, {"id": "x"}).json() == {"id": "x"}
    fake_response(200).raise_for_status()
    with pytest.raises(RuntimeError, match="HTTP 500"):
        fake_response(500).raise_for_status()


def test_fake_response_can_model_a_non_json_body(fake_response):
    """A proxy's HTML error page is a shape the uploaders have actually hit."""
    with pytest.raises(ValueError):
        fake_response(502, fake_response.RAISES, text="<html>bad gateway</html>").json()


def test_fake_session_replays_in_order_then_falls_back(fake_session, fake_response):
    fake_session.queue("get", fake_response(404), fake_response(200, {"id": "e1"}))

    assert fake_session.get("https://api/evidence").status_code == 404
    assert fake_session.get("https://api/evidence").json() == {"id": "e1"}
    # Queue exhausted: an unscripted call is a bare 200, so a test only has to
    # script the requests it is actually asserting on.
    assert fake_session.get("https://api/other").status_code == 200


def test_fake_session_records_what_was_sent(fake_session):
    fake_session.post("https://api/artifacts", json={"title": "t"}, timeout=30)

    assert fake_session.urls_for("post") == ["https://api/artifacts"]
    method, url, kwargs = fake_session.calls[0]
    assert (method, url) == ("post", "https://api/artifacts")
    assert (kwargs["json"]["title"], kwargs["timeout"]) == ("t", 30)
