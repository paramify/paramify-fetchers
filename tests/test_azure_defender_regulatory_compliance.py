"""azure_defender_regulatory_compliance: the summary fields the instructions list match what the code writes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location(
    "azure_defender_regulatory_compliance_under_test", AZURE / "defender_regulatory_compliance" / "fetcher.py"
)
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)


def _assessment(name, state, failed=0):
    return {"name": name, "state": state, "failed_resources": failed}


def _standards():
    control = rc.control_record(
        {"name": "NS-1", "state": "Failed"},
        [_assessment("a1", "Failed", 2), _assessment("a2", "Passed")],
    )
    ok = rc.control_record({"name": "NS-2", "state": "Passed"}, [_assessment("a3", "Passed")])
    return [rc.standard_record({"name": "microsoft-cloud-security-benchmark", "state": "Failed"}, [control, ok])]


def test_summary_documents_every_field(assert_summary_documented):
    summary = rc.summarize(_standards(), rc.AVAILABLE, rc.REGISTERED)
    assert summary["failed_controls"] == 1 and summary["mcsb_failed_control_names"] == ["NS-1"]
    assert summary["failed_resources"] == 2
    assert_summary_documented("azure/defender_regulatory_compliance", summary)


def test_summary_when_regulatory_compliance_is_not_offered(assert_summary_documented):
    summary = rc.summarize([], rc.NOT_AVAILABLE_FREE_TIER, rc.REGISTERED)
    assert summary["mcsb_standard_present"] is False and summary["mcsb_state"] is None
    assert_summary_documented("azure/defender_regulatory_compliance", summary)
