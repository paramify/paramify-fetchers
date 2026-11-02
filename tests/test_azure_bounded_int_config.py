"""Shared bounded_int_config: a bad value fails the run as bad_config, one past the maximum is capped, and the number
asked for is kept."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

from azure_common import Collector, classify_failure_code  # noqa: E402
from azure_rest import bounded_int_config  # noqa: E402

ENV = "TEST_WINDOW_DAYS"


def _collector():
    return Collector(logging.getLogger("test_bounded_int_config"))


@pytest.mark.parametrize("raw, used, requested", [
    (None, 30, 30), ("", 30, 30), ("7", 7, 7), (" 90 ", 90, 90), ("90", 90, 90), ("91", 90, 91), ("3650", 90, 3650),
])
def test_a_good_value_is_used_and_one_past_the_maximum_is_capped(monkeypatch, raw, used, requested):
    if raw is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, raw)
    collector = _collector()
    assert bounded_int_config(collector, ENV, 30, 90) == (used, requested)
    assert collector.ok


@pytest.mark.parametrize("raw, requested", [("9O", None), ("0", 0), ("-5", -5), ("30d", None), ("1.5", None)])
def test_a_bad_value_fails_as_bad_config_and_keeps_what_was_asked(monkeypatch, raw, requested):
    monkeypatch.setenv(ENV, raw)
    collector = _collector()
    assert bounded_int_config(collector, ENV, 30, 90) == (30, requested)
    assert [f["operation"] for f in collector.failures] == [f"config {ENV}"]
    assert repr(raw) in collector.failures[0]["message"]
    assert classify_failure_code(collector.failures) == "bad_config"
