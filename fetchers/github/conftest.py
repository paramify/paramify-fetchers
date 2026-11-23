"""Test scaffolding for the GitHub alert reports (fetchers/github/*_report/tests), driven without GitHub.

The `gh` fixture holds everything a report test needs, because pytest's importlib mode makes a conftest
unimportable. `gh.run` runs one report fetcher against a fake organization and returns what it left behind: the
exit code, the CSV rows (None when no report was written), the failure status and every call made. Routes copy
the category's test vocabulary (tests/test_github_fetchers.py): path -> list (paged by Link), dict, or
(status, body).
"""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
import requests
from requests.structures import CaseInsensitiveDict

GITHUB = Path(__file__).resolve().parent
API = "https://api.github.test"
ORG = "acme"


def response(status, body=None, headers=None):
    resp = requests.Response()
    resp.status_code = status
    resp._content = b"" if body is None else json.dumps(body).encode()
    resp.headers = CaseInsensitiveDict({"Content-Type": "application/json", "X-RateLimit-Remaining": "4999",
                                        **(headers or {})})
    return resp


class FakeGitHub:
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, timeout=None):
        parsed = urlparse(url)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        query.update({k: str(v) for k, v in (params or {}).items()})
        path = parsed.path.removeprefix("/")
        self.calls.append((path, query))
        route = self.routes.get(path)
        if callable(route):
            route = route(query)
        if route is None:
            return response(404, {"message": "Not Found"})
        if isinstance(route, tuple):
            return response(*route)
        if isinstance(route, list):
            per_page, page = int(query.get("per_page", 30)), int(query.get("page", 1))
            headers = {}
            if page * per_page < len(route):
                headers["Link"] = f'<{API}/{path}?{urlencode({**query, "page": page + 1})}>; rel="next"'
            return response(200, route[(page - 1) * per_page: page * per_page], headers)
        return response(200, route)

    def post(self, url, json=None, timeout=None):
        raise AssertionError("an alert report makes no GraphQL calls")


def repo(name, id_, **kw):
    return {"id": id_, "name": name, "full_name": f"{ORG}/{name}", "default_branch": "main", "visibility": "private",
            "archived": False, **kw}


def org_routes(repos):
    return {f"orgs/{ORG}": {"login": ORG, "public_repos": 0, "total_private_repos": len(repos)},
            f"orgs/{ORG}/repos": repos}


def load_fetcher(name):
    spec = importlib.util.spec_from_file_location(f"github_{name}_report_test", GITHUB / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(test_file, name):
    """A JSON fixture from the tests/fixtures directory beside `test_file`."""
    return json.loads((Path(test_file).parent / "fixtures" / name).read_text())


@pytest.fixture
def gh(monkeypatch, tmp_path):
    def run(name, routes, **env):
        module = load_fetcher(name)
        gc = sys.modules["github_client"]
        fake = FakeGitHub(routes)
        monkeypatch.setattr(gc.requests, "Session", lambda: fake)
        monkeypatch.setattr(gc.time, "sleep", lambda s: None)
        out = tmp_path / "issue-reports"
        for key, value in {"GITHUB_ORG": ORG, "GITHUB_TOKEN": "test-token", "GITHUB_API_URL": API,
                           "EVIDENCE_DIR": str(out), "FETCHER_STATUS_FILE": str(tmp_path / "status.json"),
                           **env}.items():
            monkeypatch.setenv(key, value)
        code = module.run_report(module.NAME, module.KIND, module.list_alerts, module.row, module.COLUMNS)
        files = sorted(out.glob("*")) if out.exists() else []
        text = None
        if files:
            with files[0].open(newline="") as fh:
                text = fh.read()
        status = tmp_path / "status.json"
        return SimpleNamespace(
            code=code, files=files, text=text, module=module, calls=fake.calls,
            rows=None if text is None else list(csv.DictReader(io.StringIO(text, newline=""))),
            header=None if text is None else next(csv.reader(io.StringIO(text, newline=""))),
            status=json.loads(status.read_text()) if status.exists() else None,
            # Staging files go beside the output directory; none may be left behind.
            leftovers=[p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")],
        )

    def inventory_asset_id(repository):
        """The repository inventory's own unique_asset_identifier, to compare a report's Asset ID with."""
        inventory = load_fetcher("repository_inventory")
        client = sys.modules["github_client"].GitHubClient(API, "t")
        return inventory.record(client, repository, {})["unique_asset_identifier"]

    return SimpleNamespace(run=run, repo=repo, org_routes=org_routes, fixture=fixture, response=response,
                           inventory_asset_id=inventory_asset_id, API=API, ORG=ORG)
