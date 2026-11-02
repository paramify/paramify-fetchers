"""resource_exclusions in the AI fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace as NS

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
ML = "providers/Microsoft.MachineLearningServices/workspaces"
CS = "providers/Microsoft.CognitiveServices/accounts"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hub_fetcher = _load("ai_hub_configuration")
services_fetcher = _load("ai_services_configuration")


def _set_patterns(monkeypatch, patterns):
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


def _common(monkeypatch, m, tmp_path):
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(m, "monitor_client", lambda sub, cred: "monitor")
    monkeypatch.setattr(m, "list_diagnostic_settings", lambda monitor, rid: [])
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))


# --- ai_hub_configuration ---

def _ws(rg, name, kind, location="eastus", hub=None, pna=None):
    props = {"hubResourceId": hub} if hub else {}
    if pna:
        props["publicNetworkAccess"] = pna
    return {"id": f"{SUB}/resourceGroups/{rg}/{ML}/{name}", "name": name, "kind": kind, "location": location,
            "properties": props}


def _hub_id(rg, name):
    return f"{SUB}/resourceGroups/{rg}/{ML}/{name}"


def run_hub(monkeypatch, tmp_path, patterns, workspaces=None, connections=None):
    """Returns (exit code, evidence, paths read)."""
    workspaces = workspaces if workspaces is not None else [
        _ws("rg-in", "hub-in", "Hub"),
        _ws("rg-out", "hub-out", "Hub", pna="Disabled"),
        _ws("rg-in", "proj-in", "Project", hub=_hub_id("rg-in", "hub-in")),
        _ws("rg-out", "proj-out", "Project", hub=_hub_id("rg-out", "hub-out")),
        _ws("rg-in", "proj-east", "Project", location="regioneast", hub=_hub_id("rg-in", "hub-in")),
        _ws("rg-in", "classic", "Default"),
    ]
    connections = connections or {}
    paths: list = []

    def list_all(client, path, version):
        paths.append(path)
        if path.endswith(ML):
            return {"items": workspaces, "pages": 1}
        return {"items": connections.get(path, []), "pages": 1}

    m = hub_fetcher
    _common(monkeypatch, m, tmp_path)
    monkeypatch.setattr(m, "arm_rest_client", lambda cred: "rest")
    monkeypatch.setattr(m, "list_all", list_all)
    _set_patterns(monkeypatch, patterns)
    code = m.main()
    return code, json.loads((tmp_path / "azure_ai_hub_configuration_s1.json").read_text()), paths


def _kind_names(evidence):
    return sorted((e["kind"], e["name"], e["pattern"]) for e in evidence["results"]["excluded"])


def test_hub_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, _ = run_hub(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert summary["total_workspaces"] == 6 and summary["hubs"] == 2 and summary["projects"] == 3
    assert {k: v for k, v in summary.items() if k.startswith(("resource_exclusion", "excluded_", "in_scope_"))} == {
        "resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
        "excluded_hubs": 0, "excluded_projects": 0, "excluded_other_workspaces": 0,
        "in_scope_hubs": 2, "in_scope_projects": 3, "in_scope_other_workspaces": 1,
    }


def test_hub_excludes_by_group_and_region_and_skips_their_reads(monkeypatch, tmp_path):
    code, evidence, paths = run_hub(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary = evidence["summary"]
    assert code == 0
    assert sorted(w["name"] for w in evidence["results"]["workspaces"]) == ["classic", "hub-in", "proj-in"]
    assert _kind_names(evidence) == [
        ("hub", "hub-out", "rg:rg-out"), ("project", "proj-east", "location:regioneast"),
        ("project", "proj-out", "rg:rg-out")]
    assert (summary["total_workspaces"], summary["hubs"], summary["projects"]) == (3, 1, 1)
    assert (summary["excluded_hubs"], summary["excluded_projects"], summary["excluded_other_workspaces"]) == (1, 2, 0)
    assert (summary["in_scope_hubs"], summary["in_scope_projects"], summary["in_scope_other_workspaces"]) == (1, 1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert not [p for p in paths if "hub-out" in p or "proj-out" in p or "proj-east" in p]


def test_hub_excludes_other_workspaces_by_id(monkeypatch, tmp_path):
    _, evidence, _ = run_hub(monkeypatch, tmp_path, f"id:{_hub_id('rg-in', 'classic')}")
    assert [(e["kind"], e["name"]) for e in evidence["results"]["excluded"]] == [("other_workspace", "classic")]
    assert (evidence["summary"]["excluded_other_workspaces"], evidence["summary"]["in_scope_other_workspaces"]) == (1, 0)


def test_hub_project_in_the_hubs_group_leaves_with_an_excluded_hub(monkeypatch, tmp_path):
    hub_id = _hub_id("rg-in", "hub-in")
    _, evidence, _ = run_hub(monkeypatch, tmp_path, f"id:{hub_id}")
    entries = {e["name"]: e for e in evidence["results"]["excluded"]}
    assert sorted(entries) == ["hub-in", "proj-east", "proj-in"]
    assert entries["proj-in"]["reason"] == "hub_excluded" and entries["proj-in"]["hub_id"] == hub_id
    assert entries["proj-in"]["pattern"] == entries["hub-in"]["pattern"]
    assert sorted(w["name"] for w in evidence["results"]["workspaces"]) == ["classic", "hub-out", "proj-out"]


def test_hub_project_elsewhere_keeps_its_verdicts_and_repeats_when_the_hub_is_excluded(monkeypatch, tmp_path):
    hub_id = _hub_id("rg-hub", "hub-x")
    workspaces = [_ws("rg-hub", "hub-x", "Hub", pna="Disabled"), _ws("rg-in", "proj-x", "Project", hub=hub_id)]
    conn = lambda ws: {"id": f"{ws}/connections/aoai", "name": "aoai",  # noqa: E731
                       "properties": {"authType": "ApiKey", "category": "AzureOpenAI"}}
    connections = {f"{hub_id}/connections": [conn(hub_id)],
                   f"{_hub_id('rg-in', 'proj-x')}/connections": [conn(_hub_id("rg-in", "proj-x"))]}
    _, plain, _ = run_hub(monkeypatch, tmp_path, None, workspaces, connections)
    code, evidence, paths = run_hub(monkeypatch, tmp_path, "rg:rg-hub", workspaces, connections)
    assert code == 0
    [project] = evidence["results"]["workspaces"]
    [plain_project] = [w for w in plain["results"]["workspaces"] if w["name"] == "proj-x"]
    assert project == plain_project
    assert project["network_exposure"] == "private" and "network_access" in project["inherited_from_hub"]
    assert project["connections"][0]["repeats_hub_connection"] is True
    assert evidence["summary"]["distinct_connections"] == 0
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["hub-x"]
    # Only the hub's connection names are read, nothing else of it.
    assert [p for p in paths if "hub-x" in p] == [f"{hub_id}/connections"]


def test_hub_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _ = run_hub(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_workspaces"] == 6


# --- ai_services_configuration ---

def _account(rg, name, location="eastus", kind="AIServices"):
    return NS(id=f"{SUB}/resourceGroups/{rg}/{CS}/{name}", name=name, kind=kind, sku=NS(name="S0"), location=location,
              tags=None, identity=None, properties=NS())


def _search(rg, name, location="eastus"):
    return {"id": f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Search/searchServices/{name}", "name": name,
            "location": location, "properties": {}}


class _Calls:
    def __init__(self, calls, name, rows=()):
        self.calls, self.name, self.rows = calls, name, rows

    def list(self, rg, account):
        self.calls.append((self.name, account))
        return list(self.rows)


def run_services(monkeypatch, tmp_path, patterns):
    accounts = [_account("rg-in", "acct-in"), _account("rg-out", "acct-out"),
                _account("rg-in", "acct-east", location="regioneast"), _account("rg-in", "speech", kind="SpeechServices")]
    search = [_search("rg-in", "srch-in"), _search("rg-out", "srch-out"), _search("rg-in", "srch-east", "regioneast")]
    calls: list = []
    client = NS(accounts=NS(list=lambda: accounts), deployments=_Calls(calls, "deployments"),
                rai_policies=_Calls(calls, "rai_policies"), projects=_Calls(calls, "projects"))
    module = types.ModuleType("azure.mgmt.cognitiveservices")
    module.CognitiveServicesManagementClient = lambda **k: client
    monkeypatch.setitem(sys.modules, "azure.mgmt.cognitiveservices", module)

    def list_all(rest, path, version):
        return {"items": search if path.endswith("searchServices") else [], "pages": 1}

    m = services_fetcher
    _common(monkeypatch, m, tmp_path)
    monkeypatch.setattr(m, "arm_rest_client", lambda cred: "rest")
    monkeypatch.setattr(m, "list_all", list_all)
    _set_patterns(monkeypatch, patterns)
    code = m.main()
    return code, json.loads((tmp_path / "azure_ai_services_configuration_s1.json").read_text()), calls


def test_services_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, _ = run_services(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert (summary["total_accounts"], summary["total_search_services"]) == (4, 3)
    assert {k: v for k, v in summary.items() if k.startswith(("resource_exclusion", "excluded_", "in_scope_"))} == {
        "resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
        "excluded_accounts": 0, "excluded_search_services": 0, "in_scope_accounts": 4, "in_scope_search_services": 3,
    }


def test_services_exclude_by_group_and_region_and_skip_account_reads(monkeypatch, tmp_path):
    code, evidence, calls = run_services(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert sorted(a["name"] for a in results["accounts"]) == ["acct-in", "speech"]
    assert [s["name"] for s in results["search_services"]] == ["srch-in"]
    assert _kind_names(evidence) == [
        ("account", "acct-east", "location:regioneast"), ("account", "acct-out", "rg:rg-out"),
        ("search_service", "srch-east", "location:regioneast"), ("search_service", "srch-out", "rg:rg-out")]
    assert (summary["total_accounts"], summary["in_scope_accounts"], summary["excluded_accounts"]) == (2, 2, 2)
    assert (summary["total_search_services"], summary["in_scope_search_services"],
            summary["excluded_search_services"]) == (1, 1, 2)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert {account for _, account in calls} == {"acct-in"}


def test_services_id_pattern_takes_out_one_account(monkeypatch, tmp_path):
    target = _account("rg-in", "acct-in").id
    _, evidence, _ = run_services(monkeypatch, tmp_path, f"id:{target}")
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["acct-in"]
    assert evidence["summary"]["in_scope_accounts"] == 3


def test_services_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _ = run_services(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_accounts"] == 4
