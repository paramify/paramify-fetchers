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
    for cred in (_cred(None, "2027-01-01T00:00:00Z"), _cred("junk", "2027-01-01T00:00:00Z")):
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


def test_interval_comes_from_the_environment(monkeypatch, tmp_path):
    import logging

    from azure_common import Collector, classify_failure_code

    def read(value=None):
        if value is None:
            monkeypatch.delenv(apps.APPROVED_LIFETIME_ENV, raising=False)
        else:
            monkeypatch.setenv(apps.APPROVED_LIFETIME_ENV, value)
        collector = Collector(logging.getLogger("t"))
        return apps.bounded_int_config(collector, apps.APPROVED_LIFETIME_ENV, 365, 3650)[0], collector

    assert read()[0] == 365
    assert read("90")[0] == 90
    value, collector = read("99999999999999999999")
    assert value == 3650 and collector.ok
    for bad in ("0", "abc", "-5", "180d", "\u00b2"):
        value, collector = read(bad)
        assert value == 365 and classify_failure_code(collector.failures) == "bad_config"


def test_interval_applies_to_the_summary():
    rec = apps.application_record(
        {"id": "a", "credentials": [_cred("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")]}, NOW, 90
    )
    assert apps.summarize([rec], 90)["credentials_issued_beyond_approved_lifetime"] == 1


def test_one_year_credential_across_a_leap_day_is_within_the_interval():
    c = apps.credential_record(_cred("2027-06-01T00:00:00Z", "2028-06-01T00:00:00Z"), NOW)
    assert c["lifetime_days"] == 366 and c["issued_beyond_approved_lifetime"] is False
    c = apps.credential_record(_cred("2027-06-01T00:00:00Z", "2028-06-02T00:00:00Z"), NOW)
    assert c["lifetime_days"] == 367 and c["issued_beyond_approved_lifetime"] is True
    # A span that stops short of 29 February gets no allowance.
    c = apps.credential_record(_cred("2028-03-01T00:00:00Z", "2029-03-02T00:00:00Z"), NOW)
    assert c["lifetime_days"] == 366 and c["issued_beyond_approved_lifetime"] is True


def test_no_end_date_counts_as_beyond_the_interval():
    c = apps.credential_record(_cred("2026-01-01T00:00:00Z", None), NOW)
    assert c["lifetime_days"] is None and c["issued_beyond_approved_lifetime"] is True
    s = apps.summarize([_app(_cred("2026-01-01T00:00:00Z", None))])
    assert s["credentials_issued_beyond_approved_lifetime"] == 1 and s["credentials_without_lifetime"] == 1


def test_end_before_start_is_unknown():
    c = apps.credential_record(_cred("2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z"), NOW)
    assert c["lifetime_days"] is None and c["issued_beyond_approved_lifetime"] is None


SETTINGS = {"approved_lifetime_days", "rotation_threshold_days"}


def _only_settings_known(summary):
    assert {k for k, v in summary.items() if v is not None} == SETTINGS
    assert len(summary) - len(SETTINGS) == 18  # every count and figure, so a new field gets a decision


def test_failed_or_partial_read_makes_every_count_null():
    _only_settings_known(apps.summarize([], read_complete=False))
    partial = apps.summarize([_app(_cred("2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z"))], read_complete=False)
    _only_settings_known(partial)
    assert partial["approved_lifetime_days"] == 365 and partial["rotation_threshold_days"] == 30


def test_complete_read_has_no_null_counts():
    s = apps.summarize([], read_complete=True)
    assert s["total_app_registrations"] == 0 and s["total_credentials"] == 0 and s["healthy_credentials"] == 0
    assert s["credential_rotation_compliance_percentage"] == 0


def _run(monkeypatch, tmp_path, graph_get, applications=None):
    import json
    from types import ModuleType
    from types import SimpleNamespace as ns

    class Query:
        def __init__(self, **kw):
            pass

    builders = ModuleType("msgraph.generated.applications.applications_request_builder")
    builders.ApplicationsRequestBuilder = type("B", (), {"ApplicationsRequestBuilderGetQueryParameters": Query})
    config = ModuleType("kiota_abstractions.base_request_configuration")
    config.RequestConfiguration = lambda query_parameters=None: ns(query_parameters=query_parameters)
    monkeypatch.setitem(sys.modules, builders.__name__, builders)
    monkeypatch.setitem(sys.modules, config.__name__, config)

    async def fake_with_graph_client(collector, cred, work, default=None):
        return await work(ns(applications=applications or ns(get=graph_get)))

    async def fake_resolve(collector, client):
        return {"tenant_id": "t", "tenant_source": "env"}

    monkeypatch.setattr(apps, "with_graph_client", fake_with_graph_client)
    monkeypatch.setattr(apps, "resolve_tenant", fake_resolve)
    monkeypatch.setattr(apps, "credential", lambda: object())
    monkeypatch.setattr(apps, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    code = apps.main()
    out = next(tmp_path.glob("azure_entra_app_registrations_*.json"))
    return code, json.loads(out.read_text())


def _application(secret_start, secret_end):
    from types import SimpleNamespace as ns
    cred = ns(display_name="s", key_id="k", start_date_time=secret_start, end_date_time=secret_end, usage=None, type=None)
    return ns(id="a", app_id="b", display_name="App", created_date_time=None, sign_in_audience="AzureADMyOrg",
              password_credentials=[cred], key_credentials=[])


def test_main_denied_read_nulls_every_count(monkeypatch, tmp_path):
    async def denied(request_configuration=None):
        raise Exception("Insufficient privileges (status 403)")

    code, evidence = _run(monkeypatch, tmp_path, denied)
    summary = (evidence.get("payload") or evidence)["summary"]
    assert code == 1
    _only_settings_known(summary)
    assert evidence["metadata"]["partial_failure"] is True


def test_main_failed_read_nulls_every_count(monkeypatch, tmp_path):
    async def failed(request_configuration=None):
        raise Exception("Service unavailable (status 503)")

    code, evidence = _run(monkeypatch, tmp_path, failed)
    assert code == 1
    _only_settings_known((evidence.get("payload") or evidence)["summary"])


def test_main_page_failing_midway_nulls_every_count(monkeypatch, tmp_path):
    from types import SimpleNamespace as ns
    first = ns(value=[_application("2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z")], odata_next_link="https://next")

    async def fail(request_configuration=None):
        raise Exception("Service unavailable (status 503)")

    class Builder:
        async def get(self, request_configuration=None):
            return first

        def with_url(self, url):
            return ns(get=fail)

    code, evidence = _run(monkeypatch, tmp_path, None, applications=Builder())
    summary = (evidence.get("payload") or evidence)["summary"]
    assert code == 1
    # The first page was read, but a short count would read as the real one.
    assert summary["total_credentials"] is None
    _only_settings_known(summary)


def test_main_complete_read_counts(monkeypatch, tmp_path, assert_summary_documented):
    from types import SimpleNamespace as ns

    async def get(request_configuration=None):
        return ns(value=[_application("2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z")], odata_next_link=None)

    code, evidence = _run(monkeypatch, tmp_path, get)
    summary = (evidence.get("payload") or evidence)["summary"]
    assert code == 0
    assert summary["credentials_issued_beyond_approved_lifetime"] == 1
    assert summary["credentials_without_lifetime"] == 0
    assert_summary_documented("azure/entra_app_registrations", summary)


def test_summary_is_documented(assert_summary_documented):
    assert_summary_documented("azure/entra_app_registrations", apps.summarize([_app(_cred("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"))]))
