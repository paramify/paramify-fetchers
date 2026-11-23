"""Test support for the per-fetcher tests under fetchers/crowdstrike/*/tests/.

`falcon` is an offline stand-in for the Falcon API at the HTTP layer: it replaces
`requests.post` (the token exchange) and `requests.request` (every API call), so
the shared client's real retry, pagination and failure tracking run unchanged.
A test registers a handler per path; each handler gets the query params and the
JSON body and returns (status, body). The fixture also carries the helpers a
test needs (envelope, load_fetcher, load_fixture, status), because pytest's
importlib mode does not make this module importable by name.

Run: pytest fetchers/crowdstrike/host_inventory/tests fetchers/crowdstrike/spotlight_vulnerability_report/tests
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import pytest

CATEGORY = Path(__file__).resolve().parent
REPO_ROOT = CATEGORY.parents[1]
BASE_URL = "http://falcon.test"

Handler = Callable[[Dict[str, Any], Optional[Dict[str, Any]]], Tuple[int, Dict[str, Any]]]


class FakeResponse:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body
        self.headers: Dict[str, str] = {}
        self.text = json.dumps(body)

    def json(self) -> Any:
        return self._body

    def raise_for_status(self) -> None:
        import requests

        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} error", response=self)


def envelope(resources: List[Any], pagination: Optional[Dict[str, Any]] = None, errors: Any = None) -> Dict[str, Any]:
    """A Falcon response body: resources, meta.pagination and errors."""
    return {"meta": {"pagination": pagination or {}}, "resources": resources, "errors": errors or []}


class FakeFalcon:
    def __init__(self, tmp_path: Path) -> None:
        self.routes: Dict[str, Handler] = {}
        self.calls: List[Tuple[str, str, Dict[str, Any], Any]] = []
        self.token_status = 200
        self.tmp_path = tmp_path
        self.output_dir = tmp_path / "run" / "out"

    def route(self, path: str, handler: Handler) -> None:
        self.routes[path] = handler

    def post(self, url: str, data: Any = None, headers: Any = None, timeout: Any = None) -> FakeResponse:
        assert urlparse(url).path == "/oauth2/token", f"unexpected POST {url}"
        if self.token_status != 200:
            return FakeResponse(self.token_status, {"errors": [{"code": self.token_status, "message": "access denied"}]})
        return FakeResponse(200, {"access_token": "synthetic-token", "expires_in": 1799})

    def request(self, method: str, url: str, headers: Any = None, params: Any = None,
                json: Any = None, timeout: Any = None) -> FakeResponse:
        path = urlparse(url).path
        self.calls.append((method, path, dict(params or {}), json))
        if path not in self.routes:
            return FakeResponse(404, {"errors": [{"code": 404, "message": f"no route {path}"}]})
        status, body = self.routes[path](dict(params or {}), json)
        return FakeResponse(status, body)

    envelope = staticmethod(envelope)

    @staticmethod
    def load_fetcher(short_name: str) -> Any:
        """Import fetchers/crowdstrike/<short_name>/fetcher.py by path; fetchers are scripts, not a package."""
        path = CATEGORY / short_name / "fetcher.py"
        spec = importlib.util.spec_from_file_location(f"crowdstrike_{short_name}_under_test", path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # A developer's .env must not leak into a test run.
        module.load_dotenv = lambda *a, **k: None
        return module

    @staticmethod
    def load_fixture(short_name: str, name: str) -> Any:
        return json.loads((CATEGORY / short_name / "tests" / "fixtures" / name).read_text())

    def status(self) -> Dict[str, Any]:
        """What the fetcher reported through report_failure ({} when it reported nothing)."""
        path = self.tmp_path / "status.json"
        return json.loads(path.read_text()) if path.exists() else {}


@pytest.fixture
def falcon(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeFalcon:
    """The fake Falcon API, the env a run needs, and no sleeping between retries."""
    fake = FakeFalcon(tmp_path)
    monkeypatch.syspath_prepend(str(CATEGORY / "_shared"))
    import falcon_client  # type: ignore

    monkeypatch.setattr(falcon_client.requests, "post", fake.post)
    monkeypatch.setattr(falcon_client.requests, "request", fake.request)
    monkeypatch.setattr(falcon_client.time, "sleep", lambda _s: None)
    for name in ("CROWDSTRIKE_CLOUD_REGION", "CROWDSTRIKE_SPOTLIGHT_ALLOW_EMPTY", "CROWDSTRIKE_HTTP_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CROWDSTRIKE_API_BASE_URL", BASE_URL)
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "synthetic-id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "synthetic-secret")
    monkeypatch.setenv("EVIDENCE_DIR", str(fake.output_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    return fake
