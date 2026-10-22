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


def test_open_issue_with_milestone_is_partially_mitigated(vc):
    issue = _issue("OPEN", milestones=[{"description": "patch"}])
    assert vc._final_disposition(issue) == "Partially Mitigated"


@pytest.mark.parametrize("issue", [_issue("UNKNOWN"), _issue("IN_PROGRESS"), {}])
def test_only_closed_status_is_remediated(vc, issue):
    # Remediated is for CLOSED only, not for every status that is not OPEN.
    assert vc._final_disposition(issue) is None


@pytest.mark.parametrize(
    "deviation",
    [
        _deviation("FALSE_POSITIVE", status="PENDING"),
        _deviation("FALSE_POSITIVE", status="REJECTED"),
        _deviation("RISK_ADJUSTMENT", status="PENDING"),
        _deviation("RISK_ADJUSTMENT", status="REJECTED"),
    ],
)
def test_unaccepted_deviation_on_open_issue_has_no_disposition(vc, deviation):
    assert vc._final_disposition(_issue("OPEN", deviations=[deviation])) is None


def test_unaccepted_false_positive_on_closed_issue_is_remediated(vc):
    issue = _issue("CLOSED", deviations=[_deviation("FALSE_POSITIVE", status="PENDING")])
    assert vc._final_disposition(issue) == "Remediated"


def test_detail_counts_files_closed_issue_under_remediated(vc):
    details = [{"finalDisposition": vc._final_disposition(_issue("CLOSED"))}]
    dispositions = vc._detail_counts(details)["dispositions"]
    assert dispositions["remediated"] == 1
    assert dispositions["fullyMitigated"] == 0


def test_detail_counts_over_mixed_dispositions(vc):
    issues = [
        _issue("CLOSED"),
        _issue("CLOSED"),
        _issue("CLOSED", deviations=[_deviation("FALSE_POSITIVE")]),
        _issue("OPEN", deviations=[_deviation("RISK_ADJUSTMENT")]),
        _issue("OPEN"),
    ]
    details = []
    for issue in issues:
        disposition = vc._final_disposition(issue)
        details.append({"finalDisposition": disposition} if disposition else {})
    dispositions = vc._detail_counts(details)["dispositions"]
    assert dispositions == {
        "fullyMitigated": 0,
        "remediated": 2,
        "partiallyMitigated": 1,
        "falsePositive": 1,
        "inProgress": 1,
    }
    assert sum(dispositions.values()) == len(details)


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


def test_detail_counts_keeps_fully_mitigated_separate(vc):
    # Fully Mitigated and Remediated are different FedRAMP states; the counts
    # must not merge them.
    details = [{"finalDisposition": "Fully Mitigated"}, {"finalDisposition": "Remediated"}]
    dispositions = vc._detail_counts(details)["dispositions"]
    assert dispositions["fullyMitigated"] == 1
    assert dispositions["remediated"] == 1


# --- PAIN rating: currentRating and Fully Mitigated -------------------------
# FedRAMP "Fully Mitigated": still detected, impact negligible. Only N0 meets
# that bar; N1 still has minimal customer effects.


def _rated(status: str, pain=None, level=None, deviations=(), milestones=()) -> dict:
    issue = _issue(status, deviations=deviations, milestones=milestones)
    if pain is not None:
        issue["painRating"] = pain
    if level is not None:
        issue["level"] = level
    return issue


def test_open_n0_is_fully_mitigated_with_rating_zero(vc):
    issue = _rated("OPEN", pain="N0")
    assert vc._final_disposition(issue) == "Fully Mitigated"
    assert vc._current_nrating(issue) == 0


def test_open_n1_is_not_fully_mitigated_and_pain_beats_level(vc):
    issue = _rated("OPEN", pain="N1", level="CRITICAL")
    assert vc._final_disposition(issue) is None
    assert vc._current_nrating(issue) == 1


def test_open_n1_with_milestone_is_partially_mitigated(vc):
    issue = _rated("OPEN", pain="N1", milestones=[{"description": "patch"}])
    assert vc._final_disposition(issue) == "Partially Mitigated"


def test_open_n2_with_critical_level_reports_pain(vc):
    issue = _rated("OPEN", pain="N2", level="CRITICAL")
    assert vc._final_disposition(issue) is None
    assert vc._current_nrating(issue) == 2


def test_level_fallback_when_no_pain_rating(vc):
    assert vc._current_nrating(_rated("OPEN", level="HIGH")) == 4


def test_pain_rating_used_when_level_not_set(vc):
    assert vc._current_nrating(_rated("OPEN", pain="N2", level="NOT_SET")) == 2


def test_messy_pain_value_is_normalized(vc):
    issue = _rated("OPEN", pain=" n0 ")
    assert vc._final_disposition(issue) == "Fully Mitigated"
    assert vc._current_nrating(issue) == 0


@pytest.mark.parametrize("pain", ["N9", "", "high", 3])
def test_unknown_pain_value_falls_back_to_level(vc, pain):
    issue = _rated("OPEN", pain=pain, level="LOW")
    assert vc._current_nrating(issue) == 2
    assert vc._final_disposition(issue) is None


def test_no_pain_and_no_level_has_no_rating(vc):
    assert vc._current_nrating(_rated("OPEN")) is None
    assert "currentRating" not in vc.map_vulnerability_detail(_rated("OPEN"))


def test_closed_n0_is_remediated(vc):
    # No longer detected wins over a negligible rating.
    assert vc._final_disposition(_rated("CLOSED", pain="N0")) == "Remediated"


def test_open_n0_false_positive_is_false_positive(vc):
    issue = _rated("OPEN", pain="N0", deviations=[_deviation("FALSE_POSITIVE")])
    assert vc._final_disposition(issue) == "False Positive"


def test_open_n0_with_milestone_is_fully_mitigated(vc):
    issue = _rated("OPEN", pain="N0", milestones=[{"description": "patch"}])
    assert vc._final_disposition(issue) == "Fully Mitigated"


def test_map_vulnerability_detail_carries_pain_and_disposition(vc):
    detail = vc.map_vulnerability_detail(_rated("OPEN", pain="N0", level="HIGH"))
    assert detail["currentRating"] == 0
    assert detail["finalDisposition"] == "Fully Mitigated"


def test_detail_counts_files_n0_and_n1(vc):
    details = []
    for issue in (_rated("OPEN", pain="N0"), _rated("OPEN", pain="N1")):
        disposition = vc._final_disposition(issue)
        details.append({"finalDisposition": disposition} if disposition else {})
    dispositions = vc._detail_counts(details)["dispositions"]
    assert dispositions["fullyMitigated"] == 1
    assert dispositions["inProgress"] == 1


@pytest.mark.parametrize("pain", [None, "N0", "N1", "N2", "N3", "N4", "N5", "N9"])
@pytest.mark.parametrize("level", [None, "NOT_SET", "CHILL", "LOW", "MODERATE", "HIGH", "CRITICAL"])
@pytest.mark.parametrize("status", ["OPEN", "CLOSED"])
def test_rating_and_disposition_stay_in_schema(vc, pain, level, status):
    issue = _rated(status, pain=pain, level=level)
    assert vc._final_disposition(issue) in SCHEMA_DISPOSITIONS | {None}
    rating = vc._current_nrating(issue)
    assert rating is None or rating in range(0, 6)
