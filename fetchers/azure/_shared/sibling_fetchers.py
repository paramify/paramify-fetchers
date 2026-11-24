"""Load another Azure fetcher's module, so a pipeline fetcher reuses the query and record code of its evidence twin.

azure_asset_inventory reads the same Resource Graph rows as azure_resource_inventory, and
azure_defender_vulnerability_report the same sub-assessments as azure_defender_vulnerability_findings.
Each loads its twin's fetcher.py instead of keeping a copy of the KQL and the row projection, so a fix to
either query reaches both outputs. Every fetcher module is named fetcher.py, so each one loads under its own
module name.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

CATEGORY_DIR = Path(__file__).resolve().parents[1]


def load(short_name: str) -> ModuleType:
    """fetchers/azure/<short_name>/fetcher.py as module azure_<short_name>_fetcher; loaded once per process."""
    module_name = f"azure_{short_name}_fetcher"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, CATEGORY_DIR / short_name / "fetcher.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"no Azure fetcher named {short_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module
