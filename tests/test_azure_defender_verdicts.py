"""Defender for Cloud plan records and summary: sub-plans, enablement, deprecation, inheritance. Pure functions, no SDK or network."""

from __future__ import annotations

import enum
import importlib.util
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dp = _load("defender_plans")
Collector = sys.modules["azure_common"].Collector

SUB_ID = "00000000-0000-0000-0000-000000000000"
SUB = f"/subscriptions/{SUB_ID}"
MG = "/providers/Microsoft.Management/managementGroups/mg-example"


class Tier(str, enum.Enum):
    FREE = "Free"
    STANDARD = "Standard"


class Flag(str, enum.Enum):
    TRUE = "True"
    FALSE = "False"


def pricing(name, tier=Tier.STANDARD, **fields):
    defaults = dict(
        sub_plan=None, free_trial_remaining_time=timedelta(0), enablement_time=None,
        enforce=Flag.FALSE, inherited=None, inherited_from=None,
        resources_coverage_status=None, deprecated=None, replaced_by=None, extensions=None,
    )
    defaults.update(fields)
    return SimpleNamespace(
        id=f"{SUB}/providers/Microsoft.Security/pricings/{name}", name=name, pricing_tier=tier, **defaults
    )


def record(*args, **kwargs):
    return dp.pricing_record(dp.project_pricing(pricing(*args, **kwargs)))


def test_sub_plan_and_enablement_time_are_recorded():
    r = record(
        "StorageAccounts", sub_plan="DefenderForStorageV2",
        enablement_time=datetime(2026, 3, 1, 12, 42, 42, 192110, tzinfo=timezone.utc),
        resources_coverage_status="FullyCovered",
    )
    assert (r["enabled"], r["sub_plan"], r["enablement_time"], r["resources_coverage_status"]) == (
        True, "DefenderForStorageV2", "2026-03-01T12:42:42Z", "FullyCovered")


def test_naive_enablement_time_reads_as_utc():
    assert record("Arm", enablement_time=datetime(2026, 1, 2, 3, 4, 5))["enablement_time"] == "2026-01-02T03:04:05Z"


def test_free_plan_is_not_enabled_and_has_no_sub_plan():
    r = record("VirtualMachines", tier=Tier.FREE, sub_plan="")
    assert (r["enabled"], r["sub_plan"], r["enablement_time"]) == (False, None, None)


def test_string_enums_become_real_booleans():
    r = record("KeyVaults", enforce=Flag.TRUE, inherited=Flag.FALSE)
    assert (r["enforce"], r["inherited"]) == (True, False)


def test_inheritance_left_out_stays_unknown():
    r = record("CloudPosture", enforce=None)
    assert (r["enforce"], r["inherited"], r["inherited_from"], r["inherited_from_scope"]) == (None, None, None, None)


def test_deprecated_plan_lists_its_replacements():
    r = record("KubernetesService", tier=Tier.FREE, deprecated=True, replaced_by=["Containers"])
    assert (r["deprecated"], r["replaced_by"]) == (True, ["Containers"])


@pytest.mark.parametrize("scope,expected", [
    (MG, "management_group"),
    (SUB, "subscription"),
    (f"{SUB}/", "subscription"),
    (f"{SUB}/resourceGroups/rg1", "resource_group"),
    (f"{SUB}/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1", "resource"),
    ("/tenants/t1", "other"),
])
def test_inherited_from_scope_type(scope, expected):
    r = record("VirtualMachines", inherited=Flag.TRUE, inherited_from=scope)
    assert (r["inherited_from"], r["inherited_from_scope"]) == (scope, expected)


@pytest.mark.parametrize("value", [None, "", "Null", "null"])
def test_documented_null_inherited_from_is_none(value):
    r = record("VirtualMachines", inherited=Flag.FALSE, inherited_from=value)
    assert (r["inherited_from"], r["inherited_from_scope"]) == (None, None)


def _serverless_plans():
    return [
        record("AppServices", enablement_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
               resources_coverage_status="FullyCovered"),
        record("StorageAccounts", sub_plan="DefenderForStorageV2", resources_coverage_status="PartiallyCovered",
               extensions=[SimpleNamespace(name="OnUploadMalwareScanning", is_enabled=Flag.TRUE)]),
        record("KeyVaults", sub_plan="PerKeyVault", enforce=Flag.TRUE,
               inherited=Flag.TRUE, inherited_from=MG),
        record("Dns", deprecated=True, replaced_by=["DNS"]),
        record("VirtualMachines", tier=Tier.FREE, resources_coverage_status="NotCovered"),
        record("ContainerRegistry", tier=Tier.FREE, deprecated=True, replaced_by=["Containers"]),
        record("Containers", tier=Tier.FREE, inherited=Flag.TRUE, inherited_from=SUB),
    ]


def test_summary_lists_enabled_plans_with_sub_plans_and_times():
    s = dp.summarize(_serverless_plans(), dp.REGISTERED)
    assert s["enabled_plans"] == ["AppServices", "Dns", "KeyVaults", "StorageAccounts"]
    assert s["enabled_plan_sub_plans"] == {
        "AppServices": None, "Dns": None, "KeyVaults": "PerKeyVault", "StorageAccounts": "DefenderForStorageV2"}
    assert s["enabled_plan_enablement_times"]["AppServices"] == "2026-02-01T00:00:00Z"
    assert (s["standard_tier_plans"], s["free_tier_plans"], s["standard_tier_percentage"]) == (4, 3, 57)


def test_summary_keeps_deprecated_plans_out_of_not_enabled():
    s = dp.summarize(_serverless_plans(), dp.REGISTERED)
    assert s["plans_not_enabled"] == ["Containers", "VirtualMachines"]
    assert s["deprecated_plans"] == ["ContainerRegistry", "Dns"]
    assert s["deprecated_plans_enabled"] == {"Dns": ["DNS"]}


def test_summary_flags_enabled_plans_that_miss_resources():
    s = dp.summarize(_serverless_plans(), dp.REGISTERED)
    assert s["enabled_plans_not_fully_covered"] == {"StorageAccounts": "PartiallyCovered"}


def test_summary_separates_management_group_inheritance():
    s = dp.summarize(_serverless_plans(), dp.REGISTERED)
    assert s["inherited_plans"] == ["Containers", "KeyVaults"]
    assert s["plans_inherited_from_management_group"] == ["KeyVaults"]
    assert s["plans_reporting_inheritance"] == 2
    assert s["enforced_plans"] == ["KeyVaults"]


def test_summary_of_unregistered_subscription_is_empty():
    s = dp.summarize([], dp.NOT_REGISTERED)
    assert (s["total_plans"], s["enabled_plans"], s["enabled_plan_sub_plans"], s["plans_not_enabled"]) == (
        0, [], {}, [])


def test_collect_reads_every_plan_from_one_list_call(monkeypatch):
    calls = []

    class FakeSecurityCenter:
        def __init__(self, credential, subscription_id, **kwargs):
            self.pricings = SimpleNamespace(list=lambda scope_id: calls.append(scope_id) or SimpleNamespace(
                value=[pricing("VirtualMachines", sub_plan="P2"), pricing("Api", sub_plan="P1")]))

    fake = ModuleType("azure.mgmt.security")
    fake.SecurityCenter = FakeSecurityCenter
    monkeypatch.setitem(sys.modules, "azure.mgmt.security", fake)
    plans, status = dp.collect_pricings(SUB_ID, object(), Collector(logging.getLogger("test")))
    assert calls == [f"subscriptions/{SUB_ID}"]
    assert status == dp.REGISTERED
    assert [(p["resource_name"], p["sub_plan"]) for p in plans] == [("Api", "P1"), ("VirtualMachines", "P2")]
