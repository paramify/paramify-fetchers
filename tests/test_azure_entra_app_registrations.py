"""azure_entra_app_registrations: issued credential lifetime."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_app_registrations" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_app_registrations_under_test", FETCHER)
apps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apps)

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def _cred(start, end, kind="password", key="k"):
    return {"credential_type": kind, "key_id": key, "start_date_time": start, "end_date_time": end}


def _app(*creds):
    return apps.application_record({"id": "a", "credentials": list(creds)}, NOW)


def test_lifetime_is_end_minus_start_for_both_credential_types():
    app = _app(
        _cred("2026-01-01T00:00:00Z", "2026-12-27T00:00:00Z", "password", "p"),
        _cred("2026-01-01T00:00:00Z", "2029-01-01T00:00:00Z", "certificate", "c"),
    )
    by_key = {c["key_id"]: c for c in app["credentials"]}
    assert by_key["p"]["lifetime_days"] == 360
    assert by_key["p"]["issued_beyond_approved_lifetime"] is False
    assert by_key["c"]["lifetime_days"] == 1096
    assert by_key["c"]["issued_beyond_approved_lifetime"] is True


def test_exactly_the_interval_is_within_it():
    c = apps.credential_record(_cred("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"), NOW)
    assert c["lifetime_days"] == 365 and c["issued_beyond_approved_lifetime"] is False


def test_missing_start_or_end_is_unknown_not_zero():
    for cred in (_cred(None, "2027-01-01T00:00:00Z"), _cred("2026-01-01T00:00:00Z", None), _cred("junk", "2027-01-01T00:00:00Z")):
        c = apps.credential_record(cred, NOW)
        assert c["lifetime_days"] is None and c["issued_beyond_approved_lifetime"] is None


def test_summary_counts_credentials_beyond_the_interval():
    s = apps.summarize([_app(
        _cred("2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z", key="a"),
        _cred("2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z", key="b"),
    )])
    assert s["credentials_issued_beyond_approved_lifetime"] == 1
    assert s["credentials_without_lifetime"] == 0 and s["approved_lifetime_days"] == 365


def test_summary_count_is_null_while_any_lifetime_is_unknown():
    s = apps.summarize([_app(
        _cred("2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z", key="a"),
        _cred(None, "2027-01-01T00:00:00Z", key="b"),
    )])
    assert s["credentials_issued_beyond_approved_lifetime"] is None
    assert s["credentials_without_lifetime"] == 1


def test_no_credentials_counts_zero():
    assert apps.summarize([_app()])["credentials_issued_beyond_approved_lifetime"] == 0


def test_interval_comes_from_the_environment(monkeypatch):
    assert apps.approved_lifetime_days() == 365
    monkeypatch.setenv("AZURE_ENTRA_APPROVED_CREDENTIAL_DAYS", "90")
    assert apps.approved_lifetime_days() == 90
    for bad in ("0", "abc", "-5"):
        monkeypatch.setenv("AZURE_ENTRA_APPROVED_CREDENTIAL_DAYS", bad)
        assert apps.approved_lifetime_days() == 365
    monkeypatch.setenv("AZURE_ENTRA_APPROVED_CREDENTIAL_DAYS", "90")
    rec = apps.application_record({"id": "a", "credentials": [_cred("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")]}, NOW, 90)
    s = apps.summarize([rec], 90)
    assert s["credentials_issued_beyond_approved_lifetime"] == 1


def test_summary_is_documented(assert_summary_documented):
    assert_summary_documented("azure/entra_app_registrations", apps.summarize([_app(_cred("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"))]))
