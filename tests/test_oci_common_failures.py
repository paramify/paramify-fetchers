"""Failure classification and instant comparison in `oci_common` — stdlib only."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "_shared"))
import oci_common  # noqa: E402

NOW = datetime(2026, 10, 22, 20, 0, tzinfo=timezone.utc)


def _failure(**parts):
    return {"operation": "x", "type": "ServiceError", "message": "", **parts}


def test_the_http_status_decides_the_category_not_the_message_text():
    """An opc-request-id or docs URL can contain "401"; it must not reclassify a 404."""
    denied = _failure(status="404", code="NotAuthorizedOrNotFound",
                      message="Authorization failed. opc-request-id: 7A401F3E/9500B")
    assert oci_common._failure_code(denied) == "bad_config"
    assert oci_common._failure_code(_failure(status="401", code="NotAuthenticated")) == "auth_failed"
    assert oci_common._failure_code(_failure(status="403", code="NotAuthorized")) == "not_authorized"
    assert oci_common._failure_code(_failure(status="429", code="TooManyRequests")) == "rate_limited"
    assert oci_common._failure_code(_failure(status="503", code="ServiceUnavailable")) == "target_unreachable"
    assert oci_common._failure_code(_failure(status="500", code="InternalServerError")) == "internal_error"


def test_a_failure_without_a_status_falls_back_to_its_text():
    assert oci_common._failure_code({"operation": "x", "type": "ConnectTimeout", "message": "timed out"}) == "target_unreachable"
    assert oci_common._failure_code({"operation": "x", "type": "InvalidPrivateKey", "message": "bad pem"}) == "auth_failed"
    # The 404 shape is named before the bare "notauthorized" it contains.
    assert oci_common._failure_code({"operation": "x", "type": "ServiceError",
                                     "message": "NotAuthorizedOrNotFound"}) == "bad_config"
    assert oci_common._failure_code({"operation": "x", "type": "RuntimeError", "message": "?"}) == "internal_error"


def test_a_unanimous_cause_is_reported_as_itself():
    collector = oci_common.Collector(__import__("logging").getLogger("t"))
    for _ in range(2):
        collector.failures.append(_failure(status="404", code="NotAuthorizedOrNotFound"))
    assert collector.failure_report()[1] == "bad_config"
    collector.failures.append(_failure(status="429", code="TooManyRequests"))
    assert collector.failure_report()[1] == "partial_failure"


def test_is_past_compares_instants_not_whole_days():
    assert oci_common.is_past(NOW - timedelta(hours=1), now=NOW) is True
    assert oci_common.is_past(NOW + timedelta(hours=1), now=NOW) is False
    assert oci_common.is_past("2026-10-22T19:00:00Z", now=NOW) is True
    assert oci_common.is_past("2026-10-22T21:00:00+00:00", now=NOW) is False
    assert oci_common.is_past(None, now=NOW) is None
    assert oci_common.is_past("not a date", now=NOW) is None
    # The whole-day number stays whole-day: both of these are "0 days ago".
    assert oci_common.age_in_days(NOW - timedelta(hours=1), now=NOW) == 0
