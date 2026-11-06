"""defender_plans 0.3.0: Defender for Cloud security contacts, read over raw ARM. No network.

The fixtures use the shape Azure Government actually returned on a live run
(2026-11-05, api-version 2020-01-01-preview): a bare JSON list of contacts, each with
etag, id, location, name, properties and type, and properties holding emails, phone,
alertNotifications {state, minimalSeverity} and notificationsByRole {state, roles}.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load():
    path = REPO_ROOT / "fetchers" / "azure" / "defender_plans" / "fetcher.py"
    spec = importlib.util.spec_from_file_location("dp_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dp = _load()
Collector = sys.modules["azure_common"].Collector
SUB = "00000000-0000-0000-0000-000000000000"


def contact(name="default", emails="secops@contoso.com; ciso@contoso.com", phone="+1-555-0100",
            state="On", severity="High", role_state="On", roles=("Owner",)):
    return {
        "id": f"/subscriptions/{SUB}/providers/Microsoft.Security/securityContacts/{name}",
        "name": name, "type": "Microsoft.Security/securityContacts", "etag": "x", "location": "West Europe",
        "properties": {"emails": emails, "phone": phone,
                       "alertNotifications": {"state": state, "minimalSeverity": severity},
                       "notificationsByRole": {"state": role_state, "roles": list(roles)}},
    }


def record(c):
    return dp.security_contact_record(dp.project_security_contact(c))


def test_contact_record_splits_emails_and_reads_states():
    r = record(contact())
    assert r["emails"] == ["ciso@contoso.com", "secops@contoso.com"] and r["email_count"] == 2
    assert r["phone_set"] is True and r["alert_notifications_on"] is True and r["notifications_by_role_on"] is True
    assert r["alert_notifications_minimal_severity"] == "High" and r["notifications_by_role_roles"] == ["Owner"]


def test_contact_without_notification_blocks_reads_unknown():
    r = record({"name": "default", "properties": {}})
    assert r["emails"] == [] and r["phone_set"] is False
    assert r["alert_notifications_on"] is None and r["notifications_by_role_on"] is None
    assert record({"name": "x", "properties": None})["email_count"] == 0
    assert record("not-a-dict")["name"] is None


def test_emails_given_as_a_list_are_kept_as_separate_addresses():
    r = dp.security_contact_record({"emails": ["b@contoso.com", " a@contoso.com "], "phone": None})
    assert r["emails"] == ["a@contoso.com", "b@contoso.com"] and r["email_count"] == 2


def test_summary_null_when_unread_and_zero_when_empty():
    assert dp.summarize_security_contacts(None)["security_contacts"] is None
    assert dp.summarize_security_contacts([])["security_contacts"] == 0
    s = dp.summarize_security_contacts([record(contact()), record(contact(name="b", state="Off", role_state="Off", emails="a@contoso.com"))])
    assert s["security_contacts"] == 2 and s["security_contacts_with_alert_notifications_on"] == 1
    assert s["security_contact_emails"] == 3 and s["alert_notification_minimal_severities"] == ["High"]


def test_both_response_shapes_are_accepted():
    assert dp.security_contact_items([contact()]) == [contact()]
    assert dp.security_contact_items({"value": [contact()]}) == [contact()]
    import pytest
    with pytest.raises(ValueError):
        dp.security_contact_items("garbage")


def _run(monkeypatch, responses):
    """Serve get_json from a dict of url -> body (or exception)."""
    calls = []

    def fake_get_json(client, url):
        calls.append(url)
        body = responses[url]
        if isinstance(body, Exception):
            raise body
        return body
    monkeypatch.setattr(dp, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(dp, "get_json", fake_get_json)
    collector = Collector(logging.getLogger("t"))
    return dp.collect_security_contacts(SUB, object(), collector), collector, calls


URL = f"/subscriptions/{SUB}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"


def test_collect_reads_the_bare_list_azure_government_returns(monkeypatch):
    out, collector, calls = _run(monkeypatch, {URL: [contact(name="z"), contact(name="a")]})
    assert collector.ok and [c["name"] for c in out] == ["a", "z"]
    assert calls == [URL], "pinned to 2020-01-01-preview, the newest version Azure Government offers"


def test_collect_follows_next_link_on_a_value_page(monkeypatch):
    nxt = "https://management.usgovcloudapi.net/next"
    out, collector, calls = _run(monkeypatch, {URL: {"value": [contact(name="a")], "nextLink": nxt},
                                               nxt: {"value": [contact(name="b")]}})
    assert collector.ok and [c["name"] for c in out] == ["a", "b"] and calls == [URL, nxt]


def test_collect_failure_is_none_and_recorded(monkeypatch):
    out, collector, _ = _run(monkeypatch, {URL: RuntimeError("(403) AuthorizationFailed")})
    assert out is None and not collector.ok


def test_unexpected_shape_is_a_recorded_failure(monkeypatch):
    out, collector, _ = _run(monkeypatch, {URL: "not json"})
    assert out is None and not collector.ok


def test_unregistered_provider_is_empty_not_a_failure(monkeypatch):
    out, collector, _ = _run(monkeypatch, {URL: RuntimeError("(409) MissingSubscriptionRegistration: subscription not registered")})
    assert out == [] and collector.ok
