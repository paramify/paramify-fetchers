"""Defender plan observations, nullable flags and documented summary fields."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

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


# These regressions catch lost SDK observations and unknown flags reported as false.
def test_pricing_record_retains_projected_configuration_before_normalization():
    projected = {
        "id": "/p/VirtualMachines",
        "name": "VirtualMachines",
        "pricing_tier": "Standard",
        "sub_plan": "",
        "enforce": "FutureFlag",
        "inherited": None,
        "inherited_from": "Null",
        "extensions": [{"name": "AgentlessVmScanning", "is_enabled": "FutureFlag"}],
    }
    record = dp.pricing_record(projected)
    assert record["observed_configuration"] == {
        "id": "/p/VirtualMachines",
        "name": "VirtualMachines",
        "pricing_tier": "Standard",
        "sub_plan": "",
        "enforce": "FutureFlag",
        "inherited": None,
        "inherited_from": "Null",
        "extensions": [{"name": "AgentlessVmScanning", "is_enabled": "FutureFlag"}],
    }
    assert record["sub_plan"] is None
    assert record["inherited_from"] is None


def test_sdk_extension_properties_survive_projection_and_record_normalization():
    models = pytest.importorskip("azure.mgmt.security.models")

    pricing = models.Pricing(
        pricing_tier=models.PricingTier.STANDARD,
        extensions=[models.Extension(
            name="AgentlessVmScanning",
            is_enabled=models.IsEnabled.TRUE,
            additional_extension_properties={
                "ExclusionTags": '[{"Key":"environment","Value":"test"}]',
                "FutureOption": {"mode": "observe"},
            },
        )],
    )
    projected = dp.project_pricing(pricing)
    assert projected["extensions"] == [{
        "name": "AgentlessVmScanning",
        "is_enabled": "True",
        "additional_extension_properties": {
            "ExclusionTags": '[{"Key":"environment","Value":"test"}]',
            "FutureOption": {"mode": "observe"},
        },
    }]
    observed = dp.pricing_record(projected)["observed_configuration"]
    assert observed["pricing_tier"] == "Standard"
    assert observed["extensions"][0]["additional_extension_properties"]["ExclusionTags"] == (
        '[{"Key":"environment","Value":"test"}]'
    )


@pytest.mark.parametrize("fields", [{}, {"is_enabled": None}, {"is_enabled": ""},
                                    {"is_enabled": "Unknown"}, {"is_enabled": "FutureFlag"}])
def test_missing_or_unknown_extension_flags_stay_unknown(fields):
    record = _plan("VirtualMachines", extensions=[{"name": "AgentlessVmScanning", **fields}])
    assert record["extensions"] == {"AgentlessVmScanning": None}


@pytest.mark.parametrize("value,expected", [(True, True), (False, False), ("True", True),
                                             ("False", False), ("Enabled", True), ("Disabled", False)])
def test_known_extension_flags_keep_their_boolean_meaning(value, expected):
    record = _plan("VirtualMachines", extensions=[{"name": "AgentlessVmScanning", "is_enabled": value}])
    assert record["extensions"] == {"AgentlessVmScanning": expected}


def test_omitted_sdk_extension_flag_and_properties_stay_unknown():
    pricing = SimpleNamespace(extensions=[SimpleNamespace(name="AgentlessVmScanning")])
    record = dp.pricing_record(dp.project_pricing(pricing))
    assert record["extensions"] == {"AgentlessVmScanning": None}
    assert record["observed_configuration"]["extensions"] == [{
        "name": "AgentlessVmScanning", "is_enabled": None, "additional_extension_properties": None,
    }]


def test_unknown_plan_flags_are_not_reported_as_disabled():
    record = _plan("VirtualMachines", enforce="FutureFlag", inherited="Unknown")
    assert record["enforce"] is None
    assert record["inherited"] is None


def test_summary_counts_only_explicitly_enabled_extensions():
    plans = [
        _plan("VirtualMachines", extensions=[
            {"name": "enabled", "is_enabled": "True"},
            {"name": "disabled", "is_enabled": "False"},
            {"name": "unknown", "is_enabled": "FutureFlag"},
        ]),
        _plan("StorageAccounts", extensions=[{"name": "unread"}]),
    ]
    summary = dp.summarize(plans, dp.REGISTERED)
    assert summary["plans_with_enabled_extensions"] == 1
    assert summary["total_enabled_extensions"] == 1
