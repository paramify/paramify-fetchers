"""The solution capability mapping and its importer.

tools/import_solcap_mapping.py turns the mapping sheet's "20x Mapping" tab into
mappings/solution_capabilities.yaml, checks the rows for sheet mistakes, and
writes the report the weekly refresh PR carries
(.github/workflows/solcap-mapping-refresh.yml). The workflow runs this file
itself, because a PR opened by a workflow does not trigger CI.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator

from framework import yaml_io
from framework.config_loader import discover_fetchers

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mapping_importer = _load("import_solcap_mapping", "tools/import_solcap_mapping.py")


def _sheet_row(cap_id, name, ksi, fetcher, platform=""):
    return {"Sol Cap ID": cap_id, "Sol Cap": name, "KSI": ksi, "Fetcher Name": fetcher, "Platform": platform}


SHEET_FETCHERS = {
    "gcp_kms_keys": SimpleNamespace(category="gcp"),
    "betterstack_status": SimpleNamespace(category="betterstack"),
    "azure_key_vault": SimpleNamespace(category="azure"),
}


def test_repo_mapping_is_valid_and_names_real_fetchers():
    data = yaml_io.load_path(REPO_ROOT / mapping_importer.MAPPING_PATH)
    assert data and data.get("mappings"), "mappings/solution_capabilities.yaml is missing or empty"
    schema = json.loads(mapping_importer.SCHEMA_PATH.read_text())
    errors = [e.message for e in Draft202012Validator(schema).iter_errors(data)]
    assert not errors, errors
    unknown = sorted({m["fetcher"] for m in data["mappings"]} - set(discover_fetchers(REPO_ROOT)))
    assert not unknown, f"mapping names fetchers this repo does not have: {unknown}"


def test_build_groups_rows_and_unescapes():
    rows = [
        _sheet_row("RS-02-03-01", "Alternate Processing Sites", "KSI-CNA-OFA", "aws\\_backup\\_validation"),
        _sheet_row("RS-02-03-01", "Alternate Processing Sites", "KSI-RPL-ABO", "aws_backup_validation"),
        _sheet_row("RS-09-01-01", "Uncovered", "KSI-X", ""),
    ]
    doc = mapping_importer.build(rows, "2026-10-12")
    assert doc["mappings"] == [{
        "fetcher": "aws_backup_validation",
        "solution_capability": {"id": "RS-02-03-01", "name": "Alternate Processing Sites"},
        "ksis": ["KSI-CNA-OFA", "KSI-RPL-ABO"],
    }]


def test_build_leaves_out_fetchers_the_repo_lacks():
    rows = [
        _sheet_row("RS-01-01-01", "A", "KSI-1", "gcp_kms_keys"),
        _sheet_row("RS-01-01-01", "A", "KSI-1", "planned_fetcher"),
    ]
    doc = mapping_importer.build(rows, "2026-10-15", known_fetchers=SHEET_FETCHERS)
    assert [m["fetcher"] for m in doc["mappings"]] == ["gcp_kms_keys"]


def test_check_reports_sheet_problems():
    rows = [
        _sheet_row("RS-01-01-01", "Key Management", "KSI-1", "gcp_kms_keys", "GCP"),   # row 2: fine
        _sheet_row("RP-09-01-03", "Crypto", "KSI-1", "gcp_kms_keys", "GCP"),           # 3: bad id
        _sheet_row("RS-01-01-01", "Key Mgmt", "KSI-2", "gcp_kms_keys", "Azure"),       # 4: id_names + platform
        _sheet_row("RS-01-01-01", "Key Management", "KSI-1", "gcp_kms_keys", "GCP"),   # 5: duplicate of 2
        _sheet_row("RS-02-02-02", "Uptime", "KSI-3", "planned_fetcher"),               # 6: unknown fetcher
        _sheet_row("", "Status Page", "KSI-3", "betterstack_status", "Better Stack"),  # 7: no id; platform OK
        _sheet_row("RS-03-03-03", "Key Management", "KSI-4", "gcp_kms_keys", "S3"),    # 8: name_ids; S3 not a category
        _sheet_row("RS-09-09-09", "Uncovered", "KSI-9", ""),                           # 9: no fetcher, not checked
    ]
    problems = {(p.kind, tuple(p.rows)) for p in mapping_importer.check(rows, SHEET_FETCHERS)}
    assert problems == {
        ("bad_id", (3,)),
        ("id_names", (2, 4, 5)),
        ("name_ids", (2, 5, 8)),
        ("platform", (4,)),
        ("duplicate", (5,)),
        ("unknown_fetcher", (6,)),
        ("missing_id", (7,)),
    }


def test_diff_and_report():
    old = {"mappings": [
        {"fetcher": "f", "solution_capability": {"id": "RS-01-01-01", "name": "A"}, "ksis": ["K1"]},
        {"fetcher": "f", "solution_capability": {"id": "RS-02-02-02", "name": "B"}},
    ]}
    new = mapping_importer.build([
        _sheet_row("RS-01-01-01", "A", "K2", "f"),
        _sheet_row("RS-03-03-03", "C", "K3", "f"),
    ], "2026-10-15")
    changes = mapping_importer.diff(old, new)
    assert changes == {
        "added": [("f", "RS-03-03-03", "C")],
        "removed": [("f", "RS-02-02-02", "B")],
        "ksis": [("f", "RS-01-01-01", "A")],
    }
    problems = [mapping_importer.Problem("bad_id", "`RP-1`", [3, 4, 5, 9])]
    text = mapping_importer.report(new, changes, problems, 2)
    assert "1 added, 1 removed, 1 with different KSIs." in text
    assert "| `RP-1` | 3–5, 9 |" in text
    assert "No mapping changed." in mapping_importer.report(new, mapping_importer.diff(new, new), [], 2)


def test_main_writes_only_on_change_and_check_reports_drift(tmp_path):
    csv_path = tmp_path / "sheet.csv"
    fetcher = next(iter(discover_fetchers(REPO_ROOT)))
    csv_path.write_text(f"Sol Cap ID,Sol Cap,KSI,Fetcher Name\nRS-01-01-01,A,KSI-1,{fetcher}\n")
    out = tmp_path / "mapping.yaml"
    report = tmp_path / "report.md"

    assert mapping_importer.main([str(csv_path), "--out", str(out), "--check"]) == 1
    assert not out.exists()
    assert mapping_importer.main([str(csv_path), "--out", str(out), "--report", str(report)]) == 0
    assert "1 added" in report.read_text()
    first = out.read_text()
    assert mapping_importer.main([str(csv_path), "--out", str(out), "--check"]) == 0
    assert mapping_importer.main([str(csv_path), "--out", str(out)]) == 0
    assert out.read_text() == first


def test_main_rejects_a_csv_without_the_columns(tmp_path):
    csv_path = tmp_path / "sheet.csv"
    csv_path.write_text("Sol Cap,Fetcher Name\nA,f\n")
    assert mapping_importer.main([str(csv_path), "--out", str(tmp_path / "m.yaml")]) == 2
