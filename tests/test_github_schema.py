"""Every field the GitHub fetchers read exists in GitHub's OpenAPI description (tools/github_schema_check.py)."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("github_schema_check", ROOT / "tools" / "github_schema_check.py")
gsc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gsc)


def test_every_field_read_exists_in_the_spec_and_no_object_is_read_as_a_flag():
    import json
    assert gsc.check(json.loads(gsc.SNAPSHOT.read_text())) == []


def test_every_github_fetcher_is_registered_with_the_schemas_it_reads():
    assert gsc.unregistered() == []


def test_the_check_catches_a_field_the_spec_does_not_define(tmp_path, monkeypatch):
    import json
    src = (gsc.FETCHERS / "dependabot_alerts/fetcher.py").read_text()
    bad = tmp_path / "github"
    (bad / "dependabot_alerts").mkdir(parents=True)
    (bad / "dependabot_alerts/fetcher.py").write_text(src.replace('advisory.get("cve_id")', 'advisory.get("cve")'))
    monkeypatch.setattr(gsc, "FETCHERS", bad)
    monkeypatch.setattr(gsc, "REGISTRY", {"dependabot_alerts/fetcher.py": gsc.REGISTRY["dependabot_alerts/fetcher.py"]})
    assert any("'cve'" in p for p in gsc.check(json.loads(gsc.SNAPSHOT.read_text())))


def test_the_check_catches_a_graphql_read_the_query_does_not_select(tmp_path, monkeypatch):
    import json
    src = (gsc.FETCHERS / "pull_request_checks/fetcher.py").read_text()
    bad = tmp_path / "github"
    (bad / "pull_request_checks").mkdir(parents=True)
    (bad / "pull_request_checks/fetcher.py").write_text(src.replace('node.get("mergedBy")', 'node.get("mergedByUser")'))
    monkeypatch.setattr(gsc, "FETCHERS", bad)
    monkeypatch.setattr(gsc, "REGISTRY",
                        {"pull_request_checks/fetcher.py": gsc.REGISTRY["pull_request_checks/fetcher.py"]})
    assert any("'mergedByUser'" in p for p in gsc.check(json.loads(gsc.SNAPSHOT.read_text())))
