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

from pathlib import Path
from typing import Any, Dict

import pytest

from framework.contract import Fetcher, InvocationResult

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


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
