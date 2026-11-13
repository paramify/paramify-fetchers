"""azure_defender_plans: the summary fields the instructions list match what the code writes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location(
    "azure_defender_plans_under_test", AZURE / "defender_plans" / "fetcher.py"
)
dp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dp)


def _plan(name, **kw):
    return dp.pricing_record({"id": f"/p/{name}", "name": name, "pricing_tier": "Free", **kw})


def _plans():
    return [
        _plan("VirtualMachines", pricing_tier="Standard", sub_plan="P2", resources_coverage_status="PartiallyCovered",
              enforce="True", inherited="True", inherited_from="/providers/Microsoft.Management/managementGroups/mg",
              extensions=[{"name": "AgentlessVmScanning", "is_enabled": "True"}]),
        _plan("Arm", pricing_tier="Standard", deprecated=True, replaced_by=["Api"]),
        _plan("KeyVaults"),
    ]


def test_summary_documents_every_field(assert_summary_documented):
    contacts = [dp.security_contact_record({"name": "default", "emails": "a@example.com;b@example.com",
                                            "alert_notifications_state": "On",
                                            "alert_notifications_minimal_severity": "High",
                                            "notifications_by_role_state": "On"})]
    summary = {**dp.summarize(_plans(), dp.REGISTERED), **dp.summarize_security_contacts(contacts)}
    assert summary["enabled_plans_not_fully_covered"] == {"Arm": "unknown", "VirtualMachines": "PartiallyCovered"}
    assert summary["security_contact_emails"] == 2
    assert_summary_documented("azure/defender_plans", summary)


def test_summary_when_the_contacts_could_not_be_read(assert_summary_documented):
    summary = {**dp.summarize([], dp.NOT_REGISTERED), **dp.summarize_security_contacts(None)}
    assert summary["security_contacts"] is None
    assert_summary_documented("azure/defender_plans", summary)
