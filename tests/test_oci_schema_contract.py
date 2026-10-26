"""The OCI fetchers' field reads, checked against Oracle's generated models.

Runs `tools/oci_schema_check.py` under pytest. That tool is the independent
source of truth this category needs: the `oci` SDK's model classes are generated
from the same OpenAPI spec that serves the API, so `swagger_types` is the real
wire contract, and it is already a declared dependency — no download, no
committed snapshot, offline by construction.

The check is not circular. The field names come from AST-walking the fetchers'
own source, and the types come from the vendor's SDK, so the two sides are
independent and adding a `.get()` to a fetcher extends the check automatically.

Verified to fail: a non-existent field name, a real field misspelled the way
`step_status_counts` originally was, and truthiness on a nested object. All
three were introduced by mutation and all three were caught.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "oci_schema_check.py"

pytest.importorskip("oci", reason="the oci SDK is what this test checks against")


def _load_tool():
    """Import the tool by path — `tools/` is not a package."""
    spec = importlib.util.spec_from_file_location("oci_schema_check", TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["oci_schema_check"] = module
    spec.loader.exec_module(module)
    return module


def test_every_field_the_oci_fetchers_read_exists_on_a_generated_model():
    """No fetcher reads a field name Oracle's own models do not declare.

    A miss here is a field that would read None on every real response while
    every other test passed, because a hand-written double is built from the
    same assumption as the fetcher.
    """
    findings = _load_tool().check()
    assert findings == [], "OCI schema check findings:\n  " + "\n  ".join(findings)


def test_the_check_covers_every_record_function_in_the_category():
    """Every `*_record` transform is mapped to a model, so none escapes checking.

    Without this, adding a fetcher and forgetting to register its record
    functions would leave them unverified while the suite stayed green — the
    check would pass by having nothing to check.
    """
    tool = _load_tool()
    mapped = {(fetcher, func) for fetcher, func in tool.FUNCTION_MODELS}

    unmapped: list[str] = []
    for fetcher_dir in sorted((REPO_ROOT / "fetchers" / "oci").iterdir()):
        # `fetchers/oci/tests/` holds cassette data, not a fetcher.
        if not fetcher_dir.is_dir() or fetcher_dir.name.startswith("_"):
            continue
        if not (fetcher_dir / "fetcher.py").exists():
            continue
        source = (fetcher_dir / "fetcher.py").read_text()
        import ast

        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not node.name.endswith("_record"):
                continue
            if (fetcher_dir.name, node.name) not in mapped:
                unmapped.append(f"{fetcher_dir.name}.{node.name}")

    assert unmapped == [], (
        "record functions not registered in FUNCTION_MODELS, so their field "
        "reads are unverified:\n  " + "\n  ".join(unmapped)
    )
