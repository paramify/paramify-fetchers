"""Azure SQL Managed Instance fetchers, driven by a fake SqlManagementClient.

Pins the two ways these fetchers could state something Azure never said: a
failover group counted once per region it spans, and a failed call read as
"off". No SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backups = _load("sql_managed_instance_backups")
configuration = _load("sql_managed_instance_configuration")
encryption = _load("sql_managed_instance_encryption")

SUB = "00000000-0000-0000-0000-000000000001"
MI_EAST = f"/subscriptions/{SUB}/resourceGroups/rg-east/providers/Microsoft.Sql/managedInstances/mi-east"
MI_WEST = f"/subscriptions/{SUB}/resourceGroups/rg-west/providers/Microsoft.Sql/managedInstances/mi-west"
DENIED = Exception("(AuthorizationFailed) The client does not have authorization")


class ResourceNotFoundError(Exception):
    pass


def call(table):
    def fn(*args, **kwargs):
        value = table[args or tuple(kwargs.values())]
        if isinstance(value, Exception):
            raise value
        return value

    return fn


def instance(resource_id, location):
    return ns(id=resource_id, name=resource_id.rsplit("/", 1)[1], location=location, state="Ready",
              current_backup_storage_redundancy="Geo", requested_backup_storage_redundancy="Geo",
              public_data_endpoint_enabled=False, minimal_tls_version="1.2")


def database(instance_id, name):
    return ns(id=f"{instance_id}/databases/{name}", name=name, status="Online")


def failover_view(rg, location, role):
    return ns(
        id=f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Sql/locations/{location}"
           "/instanceFailoverGroups/fog",
        name="fog", replication_role=role, replication_state="CATCH_UP", secondary_type="Geo",
        read_write_endpoint=ns(failover_policy="Automatic", failover_with_data_loss_grace_period_minutes=60),
        managed_instance_pairs=[ns(primary_managed_instance_id=MI_EAST, partner_managed_instance_id=MI_WEST)],
        partner_regions=[ns(location="westus" if location == "eastus" else "eastus", replication_role="Secondary")],
    )


def sql_client(*, failover=None, retention=None, ltr=None, databases=None, tde=None, admins=None):
    week = ns(weekly_retention="P4W", monthly_retention="PT0S", yearly_retention="PT0S", week_of_year=0)
    dbs = {("rg-east", "mi-east"): [database(MI_EAST, "app")], ("rg-west", "mi-west"): [database(MI_WEST, "app")]}
    dbs.update(databases or {})
    keys = [("rg-east", "mi-east", "app"), ("rg-west", "mi-west", "app")]
    return ns(
        managed_instances=ns(list=lambda: [instance(MI_EAST, "eastus"), instance(MI_WEST, "westus")]),
        managed_databases=ns(list_by_instance=call(dbs)),
        managed_backup_short_term_retention_policies=ns(get=call(
            {(*k, "default"): ns(retention_days=7) for k in keys} | (retention or {}))),
        managed_instance_long_term_retention_policies=ns(get=call(
            {(*k, "default"): week for k in keys} | (ltr or {}))),
        instance_failover_groups=ns(list_by_location=call(failover or {
            ("rg-east", "eastus"): [failover_view("rg-east", "eastus", "Primary")],
            ("rg-west", "westus"): [failover_view("rg-west", "westus", "Secondary")],
        })),
        managed_instance_encryption_protectors=ns(get=call(
            {(rg, mi, "current"): ns(server_key_type="ServiceManaged") for rg, mi, _ in keys})),
        managed_database_transparent_data_encryption=ns(get=call(
            {(*k, "current"): ns(state="Enabled") for k in keys} | (tde or {}))),
        managed_instance_administrators=ns(list_by_instance=call(admins or {
            (rg, mi): [ns(administrator_type="ActiveDirectory", login="dba")] for rg, mi, _ in keys})),
        managed_instance_azure_ad_only_authentications=ns(list_by_instance=call(
            {(rg, mi): [ns(azure_ad_only_authentication=True)] for rg, mi, _ in keys})),
    )


def run_backups(monkeypatch, client):
    monkeypatch.setattr(backups, "sql_client", lambda *a: client)
    collector = backups.Collector(logging.getLogger("test"))
    instances, groups, unlisted = backups.collect(SUB, object(), collector)
    return {i["name"]: i for i in instances}, groups, backups.summarize(instances, groups, not unlisted), collector


def test_failover_group_seen_from_two_regions_counts_once(monkeypatch):
    instances, groups, summary, collector = run_backups(monkeypatch, sql_client())
    assert collector.ok
    assert len(groups) == 1
    assert groups[0]["replication_role"] == "Primary"
    assert [v["location"] for v in groups[0]["regional_views"]] == ["eastus", "westus"]
    assert summary["total_instance_failover_groups"] == 1
    assert summary["instances_in_failover_group"] == 2
    assert all(i["failover_groups"] == ["fog"] for i in instances.values())


def test_failed_retention_calls_read_null_not_false(monkeypatch):
    client = sql_client(retention={("rg-east", "mi-east", "app", "default"): DENIED},
                        ltr={("rg-east", "mi-east", "app", "default"): DENIED})
    instances, _, summary, collector = run_backups(monkeypatch, client)
    db = instances["mi-east"]["databases"][0]
    assert not collector.ok
    assert db["short_term_retention_policy_found"] is None
    assert db["short_term_retention_at_least_7_days"] is None
    assert db["long_term_retention"]["policy_found"] is None
    assert db["long_term_retention"]["configured"] is None
    assert summary["databases_retention_unknown"] == 1
    assert summary["databases_retention_below_7_days"] == 0
    assert summary["databases_long_term_retention_unknown"] == 1


def test_missing_retention_policy_is_a_known_absence(monkeypatch):
    gone = ResourceNotFoundError("(ResourceNotFound) policy not found")
    client = sql_client(retention={("rg-east", "mi-east", "app", "default"): gone},
                        ltr={("rg-east", "mi-east", "app", "default"): gone})
    instances, _, summary, collector = run_backups(monkeypatch, client)
    db = instances["mi-east"]["databases"][0]
    assert collector.ok
    assert db["short_term_retention_at_least_7_days"] is False
    assert db["long_term_retention"]["policy_found"] is False
    assert db["long_term_retention"]["configured"] is False
    assert summary["databases_missing_retention_policy"] == 1
    assert summary["databases_retention_unknown"] == 0


def test_failed_failover_group_list_reads_null_unless_another_region_answers(monkeypatch):
    client = sql_client(failover={("rg-east", "eastus"): DENIED, ("rg-west", "westus"): []})
    instances, groups, summary, _ = run_backups(monkeypatch, client)
    assert instances["mi-east"]["in_failover_group"] is None
    assert instances["mi-west"]["in_failover_group"] is False
    assert summary["total_instance_failover_groups"] is None
    assert summary["instances_failover_group_unknown"] == 1

    client = sql_client(failover={("rg-east", "eastus"): DENIED,
                                  ("rg-west", "westus"): [failover_view("rg-west", "westus", "Secondary")]})
    instances, _, _, _ = run_backups(monkeypatch, client)
    assert instances["mi-east"]["in_failover_group"] is True


def test_failed_database_list_leaves_totals_null(monkeypatch):
    client = sql_client(databases={("rg-east", "mi-east"): DENIED})
    instances, _, summary, _ = run_backups(monkeypatch, client)
    assert instances["mi-east"]["databases_collected"] is False
    assert instances["mi-east"]["total_user_databases"] is None
    assert instances["mi-east"]["databases_below_7_days"] is None
    assert summary["total_user_databases"] is None


@pytest.mark.parametrize("flags,expected", [
    ([True, True], True),
    ([True, None], None),
    ([False, None], False),
    ([], None),
])
def test_all_user_databases_tde_enabled_is_three_valued(flags, expected):
    assert encryption.all_enabled(flags) is expected


def test_failed_tde_call_is_unknown_not_unencrypted(monkeypatch):
    client = sql_client(tde={("rg-east", "mi-east", "app", "current"): DENIED})
    monkeypatch.setattr(encryption, "sql_client", lambda *a: client)
    collector = encryption.Collector(logging.getLogger("test"))
    instances = {i["name"]: i for i in encryption.collect(SUB, object(), collector)}
    summary = encryption.summarize(list(instances.values()))
    assert instances["mi-east"]["databases"][0]["tde_enabled"] is None
    assert instances["mi-east"]["all_user_databases_tde_enabled"] is None
    assert instances["mi-west"]["all_user_databases_tde_enabled"] is True
    assert summary["tde_unknown_user_databases"] == 1
    assert summary["tde_disabled_user_databases"] == 0


def run_configuration(monkeypatch, client, settings):
    monitor = ns(diagnostic_settings=ns(list=call(settings)))
    monkeypatch.setattr(configuration, "sql_client", lambda *a: client)
    monkeypatch.setattr(configuration, "monitor_client", lambda *a: monitor)
    collector = configuration.Collector(logging.getLogger("test"))
    return {i["name"]: i for i in configuration.collect(SUB, object(), collector)}


def audit_setting(**destination):
    return ns(id="ds", name="ds", logs=[ns(category="SQLSecurityAuditEvents", enabled=True)], **destination)


def test_failed_admin_and_diagnostic_calls_read_null(monkeypatch):
    client = sql_client(admins={("rg-east", "mi-east"): DENIED, ("rg-west", "mi-west"): []})
    settings = {(MI_EAST.lstrip("/"),): DENIED, (MI_WEST.lstrip("/"),): []}
    instances = run_configuration(monkeypatch, client, settings)
    east, west = instances["mi-east"], instances["mi-west"]
    assert east["entra_administrator_configured"] is None
    assert east["audit_logs_exported"] is None
    assert east["audit_log_destinations"] is None
    assert west["entra_administrator_configured"] is False
    assert west["audit_logs_exported"] is False
    assert west["audit_log_destinations"] == []


def test_event_hub_without_hub_name_is_still_a_destination(monkeypatch):
    rule = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns/authorizationRules/send"
    settings = {(MI_EAST.lstrip("/"),): [audit_setting(event_hub_authorization_rule_id=rule)],
                (MI_WEST.lstrip("/"),): []}
    instances = run_configuration(monkeypatch, sql_client(), settings)
    assert instances["mi-east"]["audit_logs_exported"] is True
    assert instances["mi-east"]["audit_log_destinations"] == [rule]
