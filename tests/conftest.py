"""Shared test scaffolding.

This file is deliberately ADDITIVE. It exists so a new test does not have to
retype a sixteen-field Fetcher to assert one thing, not to deduplicate what is
already here — a survey of the existing modules found much less real
duplication than a grep suggests:

  * The four `make_fetcher` copies have all diverged, and only in cosmetic
    values (name, description, category). Rewriting their call sites to a
    shared default would change what those tests assert on for no gain.
  * The four CrowdStrike server fixtures are four *different* setups, not four
    copies. test_crowdstrike_resilience uses ThreadingHTTPServer for a
    documented keep-alive deadlock under retries; folding them into one
    parameterised fixture would add complexity and erase that.
  * The two FakeResponse classes diverged on purpose — the issues one carries a
    default artifacts payload and a sentinel whose json() raises.
  * REPO_ROOT is one line in 24 files. Importing it would be one line in 24
    files. That is churn, not a saving.

So: use these when writing something new. Leave the existing local copies where
they are until the module they test is being changed for another reason.

Everything here reaches a test as a FIXTURE. pyproject sets
--import-mode=importlib, which never puts conftest on sys.path, so
`from conftest import ...` raises ModuleNotFoundError.
"""

from __future__ import annotations

import functools
import importlib.util
import json
import os
import shutil
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from framework.contract import Fetcher, InvocationResult

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


# --------------------------------------------------------------------------- #
# --fail-on-skip: the tui job's guard against a missing textual passing as skips.
# --------------------------------------------------------------------------- #

def pytest_addoption(parser):
    parser.addoption(
        "--fail-on-skip", action="store_true",
        help="fail the run if any test or test module is skipped or xfailed",
    )


def _not_run(config) -> list:
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    stats = reporter.stats if reporter else {}
    return stats.get("skipped", []) + stats.get("xfailed", [])


def pytest_sessionfinish(session, exitstatus):
    if session.config.getoption("--fail-on-skip") and exitstatus == 0 and _not_run(session.config):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if config.getoption("--fail-on-skip") and _not_run(config):
        terminalreporter.write_line(
            f"--fail-on-skip: {len(_not_run(config))} skipped or xfailed, so the run fails"
            " (-rsx lists why)",
            red=True,
        )


# --------------------------------------------------------------------------- #
# Contract object factories
#
# Every field is spelled out rather than defaulted in Fetcher itself: a new
# required field on the dataclass should break these loudly, so the tests get
# updated deliberately instead of silently constructing a half-built fetcher.
# --------------------------------------------------------------------------- #

def build_fetcher(path: Path, **overrides: Any) -> Fetcher:
    """A minimal valid Fetcher rooted at `path`. Override any field by keyword."""
    defaults: Dict[str, Any] = dict(
        name="t_fetcher",
        version="0.1.0",
        description="test fetcher",
        category="testcat",
        runtime_type="python",
        runtime_entry="fetcher.py",
        runtime_timeout=None,
        output_type="json",
        output_path="out.json",
        output_aggregation=None,
        secrets=[],
        supports_targets=False,
        target_schema={},
        path=path,
        config_schema={},
        evidence_set=None,
    )
    defaults.update(overrides)
    return Fetcher(**defaults)


def build_result(**overrides: Any) -> InvocationResult:
    """A minimal successful InvocationResult. Override any field by keyword."""
    defaults: Dict[str, Any] = dict(
        fetcher_name="t_fetcher",
        fetcher_version="0.1.0",
        target=None,
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        duration_sec=1.0,
        exit_code=0,
        stdout="",
        stderr="",
        outputs=["out.json"],
    )
    defaults.update(overrides)
    return InvocationResult(**defaults)


@pytest.fixture
def make_fetcher(tmp_path):
    """build_fetcher pre-rooted at tmp_path."""
    def _make(**overrides: Any) -> Fetcher:
        return build_fetcher(overrides.pop("path", tmp_path), **overrides)
    return _make


@pytest.fixture
def make_result():
    return build_result


# --------------------------------------------------------------------------- #
# requests test doubles
#
# For new uploader tests. The uploaders hold a requests.Session, so a fake with
# the four attributes they read is enough and avoids a real socket.
# --------------------------------------------------------------------------- #

class FakeResponse:
    """Stands in for a requests.Response.

    `json_data=RAISES` makes json() raise ValueError, which is how a real
    response behaves when the body is not JSON — an HTML error page from a
    proxy, say, which is a shape the uploaders have hit in production.
    """

    RAISES = object()

    def __init__(self, status_code: int = 200, json_data: Any = None, text: str = ""):
        self.status_code = status_code
        self._json = {} if json_data is None else json_data
        self.text = text

    def json(self) -> Any:
        if self._json is FakeResponse.RAISES:
            raise ValueError("response body is not JSON")
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Records every call and replays a queued response per HTTP verb.

    Queue responses with `queue("get", FakeResponse(...))`; calls are recorded
    on `.calls` as (method, url, kwargs) so a test can assert on what was sent
    as well as what came back. A verb with an empty queue returns a bare 200,
    so a test only has to script the requests it actually cares about.
    """

    def __init__(self) -> None:
        self.headers: Dict[str, str] = {}
        self.calls: list = []
        self._queues: Dict[str, list] = {}

    def queue(self, method: str, *responses: FakeResponse) -> "FakeSession":
        self._queues.setdefault(method.lower(), []).extend(responses)
        return self

    def _dispatch(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        q = self._queues.get(method, [])
        return q.pop(0) if q else FakeResponse(200)

    def get(self, url: str, **kw: Any) -> FakeResponse:
        return self._dispatch("get", url, **kw)

    def post(self, url: str, **kw: Any) -> FakeResponse:
        return self._dispatch("post", url, **kw)

    def patch(self, url: str, **kw: Any) -> FakeResponse:
        return self._dispatch("patch", url, **kw)

    def put(self, url: str, **kw: Any) -> FakeResponse:
        return self._dispatch("put", url, **kw)

    def urls_for(self, method: str) -> list:
        """Every URL this session saw for one verb, in order."""
        return [u for m, u, _ in self.calls if m == method.lower()]


@pytest.fixture
def fake_session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def fake_response():
    """The FakeResponse *class*, so a test can build as many as it needs."""
    return FakeResponse


@pytest.fixture
def build_fetcher_fn():
    """build_fetcher itself, for a test that needs an explicit path."""
    return build_fetcher


# --------------------------------------------------------------------------- #
# Offline demo workspace (TUI snapshot and e2e tests): demo fetcher only, one pinned run.
# --------------------------------------------------------------------------- #

DEMO_RUN_ID = "2026-01-01T00-00-00Z"
# Smallest (cols, rows) with nothing cut: 242 fits the missing-token error, 58 the scripts preview.
TUI_SIZE = (242, 58)


@pytest.fixture(scope="session")
def tui_size() -> tuple:
    """The terminal size every TUI snapshot, pilot and pty test runs at."""
    return TUI_SIZE


@functools.cache
def _cli():
    spec = importlib.util.spec_from_file_location("cli_goldens", REPO_ROOT / "tools" / "cli_goldens.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def cli_tools():
    """tools/cli_goldens.py, for its paramify(), offline_env() and normalise()."""
    return _cli()


def _pin(value: Any, roots: list) -> Any:
    """Strip run ids, timestamps, durations and the root path from run output."""
    if isinstance(value, dict):
        return {k: 0.05 if k == "duration_sec" else _pin(v, roots) for k, v in value.items()}
    if isinstance(value, list):
        return [_pin(v, roots) for v in value]
    if isinstance(value, str):
        return _cli().normalise(value, [r + "/" for r in roots], root="", run_id=DEMO_RUN_ID,
                                timestamp="2026-01-01T00:00:00Z", asctime="2026-01-01 00:00:00,000")
    return value


def _offline(mp: pytest.MonkeyPatch) -> None:
    """Make os.environ match offline_env(): no .env, and no PARAMIFY_* or AZURE_* values."""
    env = _cli().offline_env()
    for name in set(os.environ) - set(env):
        mp.delenv(name)
    for name, value in env.items():
        if os.environ.get(name) != value:
            mp.setenv(name, value)


@pytest.fixture(scope="session")
def _demo_template(tmp_path_factory):
    from framework import api

    root = tmp_path_factory.mktemp("demo-root")
    no_cache = shutil.ignore_patterns("__pycache__")
    # The real package, so `python -m framework.tui` run from this root imports it, not a namespace.
    (root / "framework").symlink_to(REPO_ROOT / "framework", target_is_directory=True)
    shutil.copytree(REPO_ROOT / "fetchers" / "demo", root / "fetchers" / "demo", ignore=no_cache)
    (root / "fetchers" / "_categories").mkdir()
    shutil.copy(REPO_ROOT / "fetchers" / "_categories" / "demo.yaml", root / "fetchers" / "_categories")
    (root / "uploaders").symlink_to(REPO_ROOT / "uploaders", target_is_directory=True)
    (root / "manifests").mkdir()
    manifest = root / "manifests" / "demo.yaml"
    shutil.copy(REPO_ROOT / "examples" / "demo.yaml", manifest)

    events: list = []
    with pytest.MonkeyPatch.context() as mp:
        _offline(mp)
        mp.chdir(root)
        api.run(api.read_manifest(manifest), root, on_event=events.append, manifest_path=manifest)

    roots = sorted({str(root), str(root.resolve())}, key=len, reverse=True)
    run_dir = next((root / "evidence").glob("run-*"))
    pinned = run_dir.rename(run_dir.with_name(f"run-{DEMO_RUN_ID}"))
    for path in pinned.glob("*.json"):
        path.write_text(json.dumps(_pin(json.loads(path.read_text()), roots), indent=2))
    return root, _pin(events, roots)


@pytest.fixture
def demo_workspace(_demo_template, tmp_path, monkeypatch):
    """A fresh, offline copy of the demo root as the cwd; `.run_events` replay its pinned run."""
    template, events = _demo_template
    root = tmp_path / "demo"
    shutil.copytree(template, root, symlinks=True)
    _offline(monkeypatch)
    monkeypatch.chdir(root)
    return SimpleNamespace(root=root, run_events=events)


@pytest.fixture
def no_network(monkeypatch):
    """Refuse name lookups, connects and sendto, and fail at teardown if any were tried."""
    attempts: list = []

    def refuse(*args, **kwargs):
        where = [a for a in args if not isinstance(a, socket.socket)]
        attempts.append(where)
        raise AssertionError(f"test touched the network: {where!r}")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, refuse)
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, refuse)
    yield attempts
    assert not attempts, f"network attempts (the app may have swallowed the error): {attempts}"
