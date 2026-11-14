"""Summary fields of four Azure logging fetchers match what their instructions list."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_text_a", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ala = _load("activity_log_alerts")
ds = _load("diagnostic_settings")
lsi = _load("log_storage_immutability")
rds = _load("resource_diagnostic_settings")
azure_common = sys.modules["azure_common"]
resource_exclusions = sys.modules["resource_exclusions"]

SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg1"


@pytest.fixture(autouse=True)
def _no_exclusions(monkeypatch):
    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)


def test_activity_log_alerts_summary_is_documented(assert_summary_documented):
    alert = ala.alert_record({
        "id": f"{RG}/providers/microsoft.insights/activityLogAlerts/a1", "name": "a1", "location": "global",
        "enabled": True, "scopes": [SUB], "action_groups": [],
        "condition": {"all_of": [{"field": "operationName", "equals": "Microsoft.Network/networkSecurityGroups/write"}]},
    })
    alerts = [ala.with_routing(alert, {}, [])]
    exclusions = resource_exclusions.ResourceExclusions.from_env()
    counts = exclusions.summary([], ala.KINDS, {"activity_log_alerts": 1, "action_groups": 0, "processing_rules": 0})
    summary = {**ala.summarize(alerts), "provider_registration_status": "registered", **counts}
    assert_summary_documented("azure/activity_log_alerts", summary)


def test_diagnostic_settings_summary_is_documented(assert_summary_documented):
    setting = ds.diagnostic_setting_record({
        "id": f"{SUB}/providers/microsoft.insights/diagnosticSettings/d1", "workspace_id": f"{RG}/workspaces/w",
        "logs": [{"category": "Administrative", "enabled": True}],
    })
    summary = {**ds.summarize([setting]), "provider_registration_status": "registered"}
    assert_summary_documented("azure/diagnostic_settings", summary)


class FakeArm:
    def __init__(self, containers):
        self.containers = containers
        self.account = {"id": f"{RG}/providers/Microsoft.Storage/storageAccounts/sa", "name": "sa", "location": "eastus",
                        "kind": "StorageV2", "properties": {}}

    def list(self, path, api):
        return [self.account] if path.endswith("/storageAccounts") else self.containers

    def get(self, path, api):
        return {"properties": {"isVersioningEnabled": True, "deleteRetentionPolicy": {"enabled": True, "days": 7}}}


def test_log_storage_immutability_summary_is_documented(assert_summary_documented):
    containers = [{"name": "insights-logs-x", "properties": {
        "hasImmutabilityPolicy": True, "immutabilityPolicy": {"properties": {
            "state": "Locked", "immutabilityPeriodSinceCreationInDays": 365}}}}]
    collector = azure_common.Collector(logging.getLogger("t"))
    _, summary = lsi.collect(FakeArm(containers), "s1", collector)
    assert collector.ok
    assert_summary_documented("azure/log_storage_immutability", summary)


def test_resource_diagnostic_settings_summary_is_documented(assert_summary_documented):
    base = {"id": f"{RG}/providers/Microsoft.KeyVault/vaults/kv1", "name": "kv1", "type": "microsoft.keyvault/vaults",
            "kind": None, "location": "eastus", "resource_group": "rg1", "parent_id": None, "synthesized_child": False}
    categories = [{"name": "AuditEvent", "category_type": "Logs", "category_groups": ["audit", "allLogs"]}]
    setting = {"id": "/x/s", "name": "s", "storage_account_id": None, "workspace_id": f"{RG}/workspaces/w",
               "event_hub_name": None, "event_hub_authorization_rule_id": None, "marketplace_partner_id": None,
               "log_analytics_destination_type": None, "logs": [{"category": None, "category_group": "allLogs", "enabled": True}]}
    record = rds.with_ingestion(rds.resource_record(base, rds.STATUS_ASSESSED, categories, [setting]), {}, ["w"])
    destinations = rds.destination_records({}, [record], ["w"])
    exclusions = resource_exclusions.ResourceExclusions.from_env()
    summary = {
        **rds.summarize([record], 1, 1, 1),
        "provider_registration_status": "registered",
        **rds.summarize_ingestion([record], destinations, 7, 0, ["w"]),
        **exclusions.summary([], ("resource",), {"resources": 1}),
    }
    assert_summary_documented("azure/resource_diagnostic_settings", summary)
