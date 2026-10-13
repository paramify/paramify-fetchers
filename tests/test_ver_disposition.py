"""finalDisposition follows FedRAMP's definitions, not a loose reading of "closed".

FedRAMP defines a remediated vulnerability as no longer detected and a fully
mitigated one as still detected with negligible impact, and does not use the two
terms interchangeably. A closed Paramify issue is no longer detected, so it is
Remediated. These tests pin that mapping and keep every emitted value inside the
FedRAMP VER JSON schema's finalDisposition enum.

ver_common lives under fetchers/ and is loaded by path: fetchers are scripts the
runner exec's, not an importable package, so there is no `from fetchers...`
import to make. This mirrors how the runner puts _shared on sys.path.

Run: ``pytest tests/test_ver_disposition.py``
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_VER_COMMON = REPO_ROOT / "fetchers" / "paramify" / "_shared" / "ver_common.py"

# finalDisposition enum from the FedRAMP VER JSON schema (v0.1.1).
SCHEMA_DISPOSITIONS = {"Fully Mitigated", "Partially Mitigated", "Remediated", "False Positive"}


def _load_ver_common():
    spec = importlib.util.spec_from_file_location("ver_common_under_test", _VER_COMMON)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def vc():
    return _load_ver_common()


def _deviation(dev_type: str, status: str = "ACCEPTED") -> dict:
    return {"type": dev_type, "deviationMetadata": {"status": status}}


def _issue(status: str, deviations=(), milestones=()) -> dict:
    return {"status": status, "deviations": list(deviations), "milestones": list(milestones)}


def test_closed_issue_is_remediated(vc):
    assert vc._final_disposition(_issue("CLOSED")) == "Remediated"


def test_closed_issue_with_accepted_false_positive_is_false_positive(vc):
    issue = _issue("CLOSED", deviations=[_deviation("FALSE_POSITIVE")])
    assert vc._final_disposition(issue) == "False Positive"


def test_open_issue_with_accepted_risk_adjustment_is_partially_mitigated(vc):
    issue = _issue("OPEN", deviations=[_deviation("RISK_ADJUSTMENT")])
    assert vc._final_disposition(issue) == "Partially Mitigated"


def test_open_issue_with_nothing_has_no_disposition(vc):
    assert vc._final_disposition(_issue("OPEN")) is None


def test_detail_counts_files_closed_issue_under_remediated(vc):
    details = [{"finalDisposition": vc._final_disposition(_issue("CLOSED"))}]
    dispositions = vc._detail_counts(details)["dispositions"]
    assert dispositions["remediated"] == 1
    assert dispositions["fullyMitigated"] == 0


@pytest.mark.parametrize(
    "issue",
    [
        _issue("CLOSED"),
        _issue("CLOSED", deviations=[_deviation("FALSE_POSITIVE")]),
        _issue("CLOSED", deviations=[_deviation("RISK_ADJUSTMENT")]),
        _issue("OPEN"),
        _issue("OPEN", deviations=[_deviation("FALSE_POSITIVE")]),
        _issue("OPEN", deviations=[_deviation("FALSE_POSITIVE", status="PENDING")]),
        _issue("OPEN", deviations=[_deviation("RISK_ADJUSTMENT")]),
        _issue("OPEN", milestones=[{"description": "patch"}]),
        _issue("UNKNOWN"),
        {},
    ],
)
def test_disposition_is_within_schema_enum(vc, issue):
    assert vc._final_disposition(issue) in SCHEMA_DISPOSITIONS | {None}
