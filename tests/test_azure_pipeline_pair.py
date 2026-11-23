"""azure_asset_inventory and azure_defender_vulnerability_report: the inventory contract, the report's columns,
every page read with no cap, the all-or-nothing failure paths, and the asset-ID match between the two. No SDK or
network: a fake Resource Graph client pages the fixture rows through the real resource_graph.query_all.

Fixtures live beside each fetcher: fetchers/azure/asset_inventory/tests/resources.json and
fetchers/azure/defender_vulnerability_report/tests/open_subassessments.json (synthetic ids only).
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml

from framework import inventory

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inv = _load("asset_inventory")
rep = _load("defender_vulnerability_report")

SUB = "00000000-0000-0000-0000-000000000000"
RESOURCES = json.loads((AZURE / "asset_inventory" / "tests" / "resources.json").read_text())["rows"]
FINDINGS = json.loads((AZURE / "defender_vulnerability_report" / "tests" / "open_subassessments.json").read_text())["rows"]
ACR = f"/subscriptions/{SUB}/resourcegroups/rg-app/providers/microsoft.containerregistry/registries/acrcontoso"
VM = f"/subscriptions/{SUB}/resourcegroups/rg-app/providers/microsoft.compute/virtualmachines/vm-runner"


class FakeGraph:
    """Pages rows `page_size` at a time by skip token, for the inventory (Resources) and the report (securityresources).

    fail_page raises on that page (1-based); truncate and overcount break the result the way query_all checks for.
    """

    def __init__(self, rows, page_size=1000, fail_page=None, truncate=False, overcount=False):
        self.rows, self.page_size = rows, page_size
        self.fail_page, self.truncate, self.overcount = fail_page, truncate, overcount
        self.pages = 0

    def resources(self, request):
        self.pages += 1
        if self.pages == self.fail_page:
            raise RuntimeError("(429) TooManyRequests")
        start = int(request.options.skip_token or 0)
        end = start + self.page_size
        return SimpleNamespace(total_records=len(self.rows) + (1 if self.overcount else 0),
                               result_truncated="true" if self.truncate else "false",
                               data=self.rows[start:end], skip_token=str(end) if end < len(self.rows) else None)


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    models = ModuleType("azure.mgmt.resourcegraph.models")
    models.QueryRequest = lambda **kw: SimpleNamespace(**kw)
    models.QueryRequestOptions = lambda **kw: SimpleNamespace(**kw)
    monkeypatch.setitem(sys.modules, "azure.mgmt.resourcegraph.models", models)
    for module in (inv, rep):
        monkeypatch.setattr(module, "resolve_subscription",
                            lambda c: {"subscription_id": SUB, "subscription_source": "target"})
        monkeypatch.setattr(module, "credential", lambda: object())
        monkeypatch.setattr(module, "load_dotenv", lambda *a, **k: False)
    for name in ("AZURE_RESOURCE_EXCLUSIONS", "AZURE_VULN_REPORT_ALLOW_EMPTY", "AZURE_VULN_MAX_FINDINGS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))


def status(tmp_path):
    path = tmp_path / "status.json"
    return json.loads(path.read_text()) if path.exists() else None


def run_inventory(monkeypatch, tmp_path, graph):
    monkeypatch.setattr(inv, "resource_graph_client", lambda cred: graph)
    out = tmp_path / "evidence"
    monkeypatch.setenv("EVIDENCE_DIR", str(out))
    code = inv.main()
    return code, json.loads((out / f"azure_asset_inventory_{SUB}.json").read_text())


def run_report(monkeypatch, tmp_path, graph):
    monkeypatch.setattr(rep, "resource_graph_client", lambda cred: graph)
    out = tmp_path / "run" / "issue-reports"
    monkeypatch.setenv("EVIDENCE_DIR", str(out))
    code = rep.main()
    path = out / f"azure_defender_vulnerability_report_{SUB}.csv"
    if not path.exists():
        return code, None
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return code, {"header": reader.fieldnames, "rows": list(reader)}


def assert_withheld(code, payload, tmp_path):
    assert code == 1
    assert payload["records_included"] is False and payload["data"] == []
    assert payload["metadata"]["partial_failure"] is True
    assert inventory.check(payload, code)["complete"] is False
    assert "records withheld" in status(tmp_path)["error"]


# --- azure_asset_inventory ----------------------------------------------------------------------------------------

def test_inventory_records_follow_the_contract(monkeypatch, tmp_path):
    code, payload = run_inventory(monkeypatch, tmp_path, FakeGraph(RESOURCES))
    assert code == 0 and status(tmp_path) is None
    verdict = inventory.check(payload, code)
    assert verdict["complete"] is True, verdict
    assert verdict["by_asset_type"]["microsoft.compute/virtualmachines"] == 1
    data = payload["data"]
    assert len(data) == len(RESOURCES) == payload["record_count"]
    assert len({frozenset(r) for r in data}) == 1, "every record must have the same keys"
    vm = next(r for r in data if r["asset_type"] == "microsoft.compute/virtualmachines")
    assert vm["unique_asset_identifier"] == VM
    assert vm["resource_id"] == RESOURCES[1]["id"]  # Azure's own casing is kept beside the key
    assert (vm["subscription_id"], vm["resource_group"], vm["tags"], vm["sku_name"], vm["kind"]) == (
        SUB, "rg-app", {}, None, None)
    sa = next(r for r in data if r["name"] == "salegacy")
    assert (sa["sku_name"], sa["sku_tier"], sa["kind"]) == ("Standard_LRS", "Standard", "StorageV2")
    assert all(r["unique_asset_identifier"] == r["resource_id"].lower() for r in data)
    assert payload["results"]["asset_id_normalization"] == "lowercase"


def test_inventory_runs_the_resource_inventory_query():
    twin = _load("resource_inventory")
    assert inv.INVENTORY_QUERY == twin.INVENTORY_QUERY


def test_inventory_reads_every_page(monkeypatch, tmp_path):
    graph = FakeGraph(RESOURCES, page_size=1)
    code, payload = run_inventory(monkeypatch, tmp_path, graph)
    assert code == 0 and graph.pages == len(RESOURCES)
    assert payload["results"]["pages_read"] == len(RESOURCES) and len(payload["data"]) == len(RESOURCES)


@pytest.mark.parametrize("graph", [
    FakeGraph(RESOURCES, page_size=1, fail_page=3),
    FakeGraph(RESOURCES, truncate=True),
    FakeGraph(RESOURCES, overcount=True),
], ids=["failed-page", "truncated", "short-count"])
def test_inventory_incomplete_collection_withholds_every_record(monkeypatch, tmp_path, graph):
    code, payload = run_inventory(monkeypatch, tmp_path, graph)
    assert_withheld(code, payload, tmp_path)
    assert payload["results"]["pages_read"] is None


def test_inventory_failed_page_reports_its_code(monkeypatch, tmp_path):
    run_inventory(monkeypatch, tmp_path, FakeGraph(RESOURCES, page_size=1, fail_page=2))
    assert status(tmp_path)["code"] == "rate_limited"


def test_inventory_row_without_id_withholds_every_record(monkeypatch, tmp_path):
    rows = RESOURCES + [{**RESOURCES[0], "id": None, "name": "ghost"}]
    code, payload = run_inventory(monkeypatch, tmp_path, FakeGraph(rows))
    assert_withheld(code, payload, tmp_path)


def test_inventory_ids_that_differ_only_in_case_are_one_resource_and_withhold(monkeypatch, tmp_path):
    rows = RESOURCES + [{**RESOURCES[0], "id": RESOURCES[0]["id"].upper()}]
    code, payload = run_inventory(monkeypatch, tmp_path, FakeGraph(rows))
    assert_withheld(code, payload, tmp_path)
    assert "more than once" in payload["metadata"]["api_failures"][0]["message"]


def test_inventory_exclusions_leave_out_a_resource_group(monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:RG-LEGACY")
    code, payload = run_inventory(monkeypatch, tmp_path, FakeGraph(RESOURCES))
    assert code == 0
    assert "salegacy" not in {r["name"] for r in payload["data"]}
    assert [e["name"] for e in payload["results"]["excluded"]] == ["salegacy"]
    assert (payload["summary"]["excluded_resources"], payload["summary"]["in_scope_resources"]) == (1, 3)


def test_inventory_invalid_exclusion_fails_before_any_query(monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "legacy")
    graph = FakeGraph(RESOURCES)
    code, payload = run_inventory(monkeypatch, tmp_path, graph)
    assert_withheld(code, payload, tmp_path)
    assert graph.pages == 0
    assert status(tmp_path)["code"] == "bad_config"


# --- azure_defender_vulnerability_report --------------------------------------------------------------------------

def test_report_columns_and_rows(monkeypatch, tmp_path):
    code, report = run_report(monkeypatch, tmp_path, FakeGraph(FINDINGS))
    assert code == 0 and status(tmp_path) is None
    assert report["header"] == list(rep.COLUMNS)
    rows = report["rows"]
    assert len(rows) == len(FINDINGS)
    assert len({r["ID"] for r in rows}) == len(rows)
    assert all(r["ID"] == r["ID"].lower() and r["Asset ID"] == r["Asset ID"].lower() for r in rows)
    assert all(r["ID"].startswith(r["Asset ID"] + "/providers/microsoft.security/assessments/") for r in rows)
    # The same CVE on two images in one registry, and on a machine: three rows, two assets.
    cve = [r for r in rows if r["CVE ID"] == "CVE-2026-10001"]
    assert sorted(r["Image Digest"][:8] for r in cve) == ["", "sha256:a", "sha256:b"]
    assert {r["Asset ID"] for r in cve} == {ACR, VM}
    vm = next(r for r in rows if r["Asset ID"] == VM)
    assert (vm["Subscription ID"], vm["Resource Group"], vm["Resource Name"], vm["Finding Kind"]) == (
        SUB, "rg-app", "vm-runner", "server")
    assert (vm["Severity"], vm["Status"], vm["CVSS"], vm["Exploit Steps Published"]) == (
        "Critical", "Unhealthy", "9.8", "true")
    image = next(r for r in rows if r["Repository"] == "app/api")
    assert (image["Fix Available"], image["Fixed Version"], image["Package"], image["Finding Kind"]) == (
        "true", "3.0.15", "openssl", "container_image")
    qid = next(r for r in rows if r["Vulnerability ID"] == "376012")
    assert (qid["CVE ID"], qid["CVSS"], qid["Fix Available"], qid["Published At"]) == ("", "", "false", "")


def test_report_has_no_cap_and_reads_every_page(monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_VULN_MAX_FINDINGS", "1")  # the evidence fetcher's cap; the report ignores it
    graph = FakeGraph(FINDINGS, page_size=1)
    code, report = run_report(monkeypatch, tmp_path, graph)
    assert code == 0 and graph.pages == len(FINDINGS)
    assert len(report["rows"]) == len(FINDINGS)


@pytest.mark.parametrize("graph", [
    FakeGraph(FINDINGS, page_size=1, fail_page=2),
    FakeGraph(FINDINGS, truncate=True),
    FakeGraph(FINDINGS, overcount=True),
], ids=["failed-page", "truncated", "short-count"])
def test_report_incomplete_collection_writes_nothing(monkeypatch, tmp_path, graph):
    code, report = run_report(monkeypatch, tmp_path, graph)
    assert code == 1 and report is None
    assert "no issue report written" in status(tmp_path)["error"]
    assert not list(tmp_path.rglob("*.csv"))
    assert not list(tmp_path.rglob(".*.tmp"))


def test_report_repeated_finding_id_writes_nothing(monkeypatch, tmp_path):
    rows = FINDINGS + [{**FINDINGS[0], "id": FINDINGS[0]["id"].upper()}]
    code, report = run_report(monkeypatch, tmp_path, FakeGraph(rows))
    assert code == 1 and report is None
    assert "more than once" in status(tmp_path)["error"]


def test_report_zero_findings_fails_unless_allowed(monkeypatch, tmp_path):
    code, report = run_report(monkeypatch, tmp_path, FakeGraph([]))
    assert code == 1 and report is None
    assert status(tmp_path)["code"] == "bad_config"
    (tmp_path / "status.json").unlink()
    monkeypatch.setenv("AZURE_VULN_REPORT_ALLOW_EMPTY", "true")
    code, report = run_report(monkeypatch, tmp_path, FakeGraph([]))
    assert code == 0 and report == {"header": list(rep.COLUMNS), "rows": []}


def test_report_invalid_allow_empty_is_bad_config(monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_VULN_REPORT_ALLOW_EMPTY", "yes")
    graph = FakeGraph(FINDINGS)
    code, report = run_report(monkeypatch, tmp_path, graph)
    assert code == 1 and report is None and graph.pages == 0
    assert status(tmp_path)["code"] == "bad_config"


def test_report_formula_cells_are_quoted(monkeypatch, tmp_path):
    _, report = run_report(monkeypatch, tmp_path, FakeGraph(FINDINGS))
    vm = next(r for r in report["rows"] if r["Asset ID"] == VM)
    assert vm["Title"].startswith("'=HYPERLINK")
    assert vm["Package"] == "'@example/agent"
    assert rep.cell("  -1") == "'  -1" and rep.cell(None) == "" and rep.cell(False) == "false"


def test_report_exclusions_leave_out_findings_under_the_resource(monkeypatch, tmp_path):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "id:*/registries/ACRCONTOSO")
    code, report = run_report(monkeypatch, tmp_path, FakeGraph(FINDINGS))
    assert code == 0
    assert ACR not in {r["Asset ID"] for r in report["rows"]} and len(report["rows"]) == 2


def test_report_runs_the_evidence_fetchers_findings_query():
    twin = _load("defender_vulnerability_findings")
    assert rep.FINDINGS_QUERY == twin.findings_query()


def test_report_declares_its_asset_id_column():
    spec = yaml.safe_load((AZURE / "defender_vulnerability_report" / "fetcher.yaml").read_text())
    inventory_spec = yaml.safe_load((AZURE / "asset_inventory" / "fetcher.yaml").read_text())
    assert spec["pipeline"]["asset_id_field"] == rep.ASSET_ID_COLUMN
    assert rep.ASSET_ID_COLUMN in rep.COLUMNS
    assert spec["pipeline"]["id_scheme"] == inventory_spec["pipeline"]["id_scheme"] == "azure-resource-id"


# --- the pair -----------------------------------------------------------------------------------------------------

def test_every_report_asset_id_is_an_inventory_id(monkeypatch, tmp_path):
    """Defender's casing differs from Resource Graph's in the fixtures; both sides lowercase, so every row links."""
    assert any(r["parentId"] != r["parentId"].lower() for r in FINDINGS)
    assert all(r["id"] != r["id"].lower() for r in RESOURCES[:2])
    _, payload = run_inventory(monkeypatch, tmp_path, FakeGraph(RESOURCES))
    _, report = run_report(monkeypatch, tmp_path, FakeGraph(FINDINGS))
    inventory_ids = {r["unique_asset_identifier"] for r in payload["data"]}
    assert {r["Asset ID"] for r in report["rows"]} <= inventory_ids
