"""defender_plans 0.3.0: Defender for Cloud security contacts. No network."""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace as NS

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


def contact(name="default", emails="secops@contoso.com; ciso@contoso.com", phone="+1-555-0100", state="On",
            severity="High", role_state="On", roles=("Owner",)):
    return NS(name=name, emails=emails, phone=phone,
              alert_notifications=NS(state=state, minimal_severity=severity),
              notifications_by_role=NS(state=role_state, roles=list(roles)))


def test_contact_record_splits_emails_and_reads_states():
    r = dp.security_contact_record(dp.project_security_contact(contact()))
    assert r["emails"] == ["ciso@contoso.com", "secops@contoso.com"] and r["email_count"] == 2
    assert r["phone_set"] is True and r["alert_notifications_on"] is True and r["notifications_by_role_on"] is True
    assert r["alert_notifications_minimal_severity"] == "High" and r["notifications_by_role_roles"] == ["Owner"]


def test_contact_without_notification_blocks_reads_unknown():
    bare = NS(name="default", emails=None, phone=None, alert_notifications=None, notifications_by_role=None)
    r = dp.security_contact_record(dp.project_security_contact(bare))
    assert r["emails"] == [] and r["phone_set"] is False
    assert r["alert_notifications_on"] is None and r["notifications_by_role_on"] is None


def test_summary_null_when_unread_and_zero_when_empty():
    assert dp.summarize_security_contacts(None)["security_contacts"] is None
    assert dp.summarize_security_contacts([])["security_contacts"] == 0
    recs = [dp.security_contact_record(dp.project_security_contact(contact())),
            dp.security_contact_record(dp.project_security_contact(contact(name="b", state="Off", role_state="Off", emails="a@contoso.com")))]
    s = dp.summarize_security_contacts(recs)
    assert s["security_contacts"] == 2 and s["security_contacts_with_alert_notifications_on"] == 1
    assert s["security_contact_emails"] == 3 and s["alert_notification_minimal_severities"] == ["High"]


class _Contacts:
    def __init__(self, items=None, exc=None):
        self.items, self.exc = items or [], exc

    def list(self):
        if self.exc:
            raise self.exc
        return iter(self.items)


def _run(monkeypatch, contacts_op):
    import types
    fake = types.ModuleType("azure.mgmt.security")
    fake.SecurityCenter = lambda **k: NS(security_contacts=contacts_op)
    monkeypatch.setitem(sys.modules, "azure", types.ModuleType("azure"))
    monkeypatch.setitem(sys.modules, "azure.mgmt", types.ModuleType("azure.mgmt"))
    monkeypatch.setitem(sys.modules, "azure.mgmt.security", fake)
    collector = Collector(logging.getLogger("t"))
    return dp.collect_security_contacts("sub", object(), collector), collector


def test_collect_returns_records(monkeypatch):
    out, collector = _run(monkeypatch, _Contacts([contact(name="z"), contact(name="a")]))
    assert collector.ok and [c["name"] for c in out] == ["a", "z"]


def test_collect_failure_is_none_and_recorded(monkeypatch):
    out, collector = _run(monkeypatch, _Contacts(exc=RuntimeError("HTTP 403")))
    assert out is None and not collector.ok


def test_emails_given_as_a_list_are_kept_as_separate_addresses():
    r = dp.security_contact_record({"emails": ["b@contoso.com", " a@contoso.com "], "phone": None})
    assert r["emails"] == ["a@contoso.com", "b@contoso.com"] and r["email_count"] == 2
