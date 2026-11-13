"""azure_resource_locks: lock scopes, which locks cover a resource, protected-type judgement, failure semantics. Synthetic payloads, no SDK or network."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_resource_locks_under_test", AZURE / "resource_locks" / "fetcher.py")
rl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rl)
azure_rest = sys.modules["azure_rest"]
Collector = sys.modules["azure_common"].Collector
ResourceExclusions = sys.modules["resource_exclusions"].ResourceExclusions

SUB = "/subscriptions/s1"
RG_LOGS = f"{SUB}/resourceGroups/rg-logs"
RG_APP = f"{SUB}/resourceGroups/rg-app"
LAW = f"{RG_LOGS}/providers/Microsoft.OperationalInsights/workspaces/law"
VAULT = f"{RG_APP}/providers/Microsoft.DataProtection/backupVaults/bv1"
KV = f"{RG_APP}/providers/Microsoft.KeyVault/vaults/kv1"
SA = f"{RG_APP}/providers/Microsoft.Storage/storageAccounts/sa1"
VM = f"{RG_APP}/providers/Microsoft.Compute/virtualMachines/vm1"


def raw_lock(scope, name, level, notes=None):
    return {"id": f"{scope}/providers/Microsoft.Authorization/locks/{name}", "name": name,
            "properties": {"level": level, "notes": notes, "owners": [{"applicationId": "app-1"}] if notes else []}}


def raw_resource(rid, kind):
    return {"id": rid, "name": rid.rsplit("/", 1)[-1], "type": kind, "location": "usgovvirginia"}


RESOURCES = [raw_resource(LAW, "Microsoft.OperationalInsights/workspaces"),
             raw_resource(VAULT, "Microsoft.DataProtection/backupVaults"),
             raw_resource(KV, "Microsoft.KeyVault/vaults"),
             raw_resource(SA, "Microsoft.Storage/storageAccounts"),
             raw_resource(VM, "Microsoft.Compute/virtualMachines")]


# --- scopes ---

@pytest.mark.parametrize("scope, kind", [
    (SUB, rl.SUBSCRIPTION), (RG_LOGS, rl.RESOURCE_GROUP), (LAW, rl.RESOURCE),
    (f"{SA}/blobServices/default/containers/logs", rl.RESOURCE),
])
def test_lock_scope_and_kind(scope, kind) -> None:
    lock = rl.lock_record(raw_lock(scope, "lk", "CanNotDelete", "keep"))
    assert lock["scope"] == scope.lower() and lock["scope_kind"] == kind and lock["level"] == "cannotdelete"
    assert lock["owners"] == ["app-1"] and lock["notes"] == "keep"
    assert lock["resource_group"] == (None if kind == rl.SUBSCRIPTION else "rg-logs" if "rg-logs" in scope else "rg-app")


def test_a_lock_covers_its_scope_and_children_not_parents() -> None:
    assert rl.covers(RG_APP.lower(), KV) and rl.covers(SUB.lower(), KV) and rl.covers(KV.lower(), KV)
    assert not rl.covers(f"{SA}/blobServices/default".lower(), SA)
    assert not rl.covers(RG_LOGS.lower(), KV)
    assert not rl.covers(f"{RG_APP}-2".lower(), KV)  # a prefix of the name is not a parent
    # a sibling whose name only starts with the scope's name is not covered
    assert not rl.covers(KV.lower(), KV.replace("kv1", "kv10"))
    assert not rl.covers(RG_APP.lower(), KV.replace("rg-app", "rg-app2"))
    assert rl.covers(RG_APP.upper().replace("/SUBSCRIPTIONS", "/subscriptions").lower(), KV)
    assert not rl.covers("", KV)


def test_resource_record_collects_every_covering_lock() -> None:
    locks = [rl.lock_record(raw_lock(RG_APP, "rg-lock", "CanNotDelete")),
             rl.lock_record(raw_lock(KV, "kv-lock", "ReadOnly")),
             rl.lock_record(raw_lock(f"{SA}/blobServices/default/containers/logs", "child", "CanNotDelete"))]
    kv = rl.resource_record(raw_resource(KV, "Microsoft.KeyVault/vaults"), locks, list(rl.DEFAULT_PROTECTED_TYPES))
    assert kv["protected_type"] is True and kv["lock_levels"] == ["cannotdelete", "readonly"]
    assert [lk["name"] for lk in kv["locks"]] == ["rg-lock", "kv-lock"] and kv["read_only"] is True
    sa = rl.resource_record(raw_resource(SA, "Microsoft.Storage/storageAccounts"), locks, list(rl.DEFAULT_PROTECTED_TYPES))
    assert [lk["name"] for lk in sa["locks"]] == ["rg-lock"] and sa["delete_locked"] is True and sa["read_only"] is False
    law = rl.resource_record(raw_resource(LAW, "Microsoft.OperationalInsights/workspaces"), locks, list(rl.DEFAULT_PROTECTED_TYPES))
    assert law["locks"] == [] and law["delete_locked"] is False
    vm = rl.resource_record(raw_resource(VM, "Microsoft.Compute/virtualMachines"), locks, list(rl.DEFAULT_PROTECTED_TYPES))
    assert vm["protected_type"] is False and vm["delete_locked"] is True


def test_resource_record_with_unread_locks_reads_null() -> None:
    kv = rl.resource_record(raw_resource(KV, "Microsoft.KeyVault/vaults"), None, list(rl.DEFAULT_PROTECTED_TYPES))
    assert kv["locks"] is None and kv["delete_locked"] is None and kv["read_only"] is None


def test_protected_types_from_env(monkeypatch) -> None:
    monkeypatch.delenv(rl.PROTECTED_TYPES_ENV, raising=False)
    assert rl.protected_types() == list(rl.DEFAULT_PROTECTED_TYPES)
    monkeypatch.setenv(rl.PROTECTED_TYPES_ENV, " Microsoft.KeyVault/vaults, microsoft.compute/virtualmachines ")
    assert rl.protected_types() == ["microsoft.compute/virtualmachines", "microsoft.keyvault/vaults"]
    monkeypatch.setenv(rl.PROTECTED_TYPES_ENV, "   ")
    assert rl.protected_types() == list(rl.DEFAULT_PROTECTED_TYPES)
    collector = Collector(logging.getLogger("test"))
    monkeypatch.setenv(rl.PROTECTED_TYPES_ENV, "storageaccounts, Microsoft.Storage/, a/b/c, microsoft.keyvault/vaults")
    assert rl.protected_types(collector) == ["a/b/c", "microsoft.keyvault/vaults", "microsoft.storage/", "storageaccounts"]
    assert len(collector.failures) == 1 and "invalid setting" in collector.failures[0]["message"]
    assert "2 entry(ies)" in collector.failures[0]["message"] and "storageaccounts" not in collector.failures[0]["message"]


def test_nested_resource_types_are_accepted(monkeypatch) -> None:
    collector = Collector(logging.getLogger("test"))
    monkeypatch.setenv(rl.PROTECTED_TYPES_ENV, "Microsoft.Sql/servers/databases")
    assert rl.protected_types(collector) == ["microsoft.sql/servers/databases"] and collector.ok


@pytest.mark.parametrize("raw", [",", " , ,", ";", ",,/"])
def test_a_setting_with_no_usable_entry_fails_instead_of_judging_nothing(monkeypatch, raw) -> None:
    collector = Collector(logging.getLogger("test"))
    monkeypatch.setenv(rl.PROTECTED_TYPES_ENV, raw)
    rl.protected_types(collector)
    assert not collector.ok and "invalid setting" in collector.failures[0]["message"]


# --- summary ---

def _records(locks_raw):
    locks = [rl.lock_record(raw) for raw in locks_raw]
    resources = [rl.resource_record(raw, locks, list(rl.DEFAULT_PROTECTED_TYPES)) for raw in RESOURCES]
    return locks, resources


def test_summary_counts_locks_and_protected_coverage() -> None:
    locks, resources = _records([raw_lock(RG_APP, "rg-lock", "CanNotDelete"), raw_lock(LAW, "law", "ReadOnly"),
                                 raw_lock(f"{SA}/blobServices/default/containers/x", "child", "CanNotDelete")])
    summary = rl.summarize(locks, resources, ["rg-app", "rg-logs"], list(rl.DEFAULT_PROTECTED_TYPES))
    assert summary["locks"] == 3 and summary["locks_by_level"] == {"cannotdelete": 2, "readonly": 1, "unknown": 0}
    assert summary["locks_by_scope_kind"] == {"resource": 2, "resource_group": 1, "subscription": 0}
    assert summary["subscription_delete_locked"] is False and summary["subscription_lock_levels"] == []
    assert summary["resource_groups"] == 2 and summary["resource_groups_delete_locked"] == 1
    assert summary["resources"] == 5 and summary["resources_delete_locked"] == 5 and summary["resources_read_only"] == 1
    assert summary["protected_resources"] == 4 and summary["protected_resources_delete_locked"] == 4
    assert summary["protected_resources_unlocked"] == 0 and summary["protected_resource_lock_percentage"] == 100
    assert summary["all_protected_resources_locked"] is True
    assert summary["protected_resources_by_type"]["microsoft.keyvault/vaults"] == {"resources": 1, "delete_locked": 1}
    assert summary["protected_resources_by_type"]["microsoft.recoveryservices/vaults"] == {"resources": 0, "delete_locked": 0}


def test_summary_with_a_subscription_lock_and_an_unlocked_vault() -> None:
    locks, resources = _records([raw_lock(SUB, "sub", "CanNotDelete")])
    summary = rl.summarize(locks, resources, ["rg-app", "rg-logs"], list(rl.DEFAULT_PROTECTED_TYPES))
    assert summary["subscription_delete_locked"] is True and summary["locks_by_scope_kind"] == {"resource": 0, "resource_group": 0, "subscription": 1}
    assert summary["protected_resources_delete_locked"] == 4 and summary["resource_groups_delete_locked"] == 0
    locks, resources = _records([raw_lock(LAW, "law", "CanNotDelete")])
    summary = rl.summarize(locks, resources, None, list(rl.DEFAULT_PROTECTED_TYPES))
    assert summary["protected_resources_delete_locked"] == 1 and summary["protected_resources_unlocked"] == 3
    assert summary["protected_resource_lock_percentage"] == 25 and summary["all_protected_resources_locked"] is False
    assert summary["resource_groups"] is None


def test_summary_nulls_when_a_list_was_not_read() -> None:
    _, resources = _records([])
    unread_locks = rl.summarize(None, [rl.resource_record(r, None, list(rl.DEFAULT_PROTECTED_TYPES)) for r in RESOURCES],
                                ["rg-app"], list(rl.DEFAULT_PROTECTED_TYPES))
    assert unread_locks["locks"] is None and unread_locks["locks_by_level"] is None
    assert unread_locks["subscription_delete_locked"] is None and unread_locks["resource_groups_delete_locked"] is None
    assert unread_locks["protected_resources"] == 4 and unread_locks["protected_resources_delete_locked"] is None
    assert unread_locks["protected_resource_lock_percentage"] is None and unread_locks["all_protected_resources_locked"] is None
    assert unread_locks["protected_resources_by_type"]["microsoft.keyvault/vaults"] == {"resources": None, "delete_locked": None}
    unread_resources = rl.summarize([], None, ["rg-app"], list(rl.DEFAULT_PROTECTED_TYPES))
    assert unread_resources["locks"] == 0 and unread_resources["resources"] is None
    assert unread_resources["protected_resources"] is None and unread_resources["all_protected_resources_locked"] is None
    empty = rl.summarize([], [], [], list(rl.DEFAULT_PROTECTED_TYPES))
    assert empty["protected_resource_lock_percentage"] == 0 and empty["all_protected_resources_locked"] is None


# --- collection through a fake ARM ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


class _Arm:
    def __init__(self, *, locks_fail=False, resources_fail=False, groups_fail=False):
        self.locks_fail, self.resources_fail, self.groups_fail = locks_fail, resources_fail, groups_fail
        self.urls: list[str] = []

    def get(self, url, params=None, headers=None, timeout=None):
        path = urlparse(url).path
        self.urls.append(path + "?" + "&".join(f"{k}={v}" for k, v in sorted((params or {}).items())))
        if path.endswith("/providers/Microsoft.Authorization/locks"):
            if self.locks_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            if "skip" in url:
                return _Resp(200, {"value": [raw_lock(LAW, "law", "CanNotDelete", "logs")]})
            return _Resp(200, {"value": [raw_lock(RG_APP, "rg", "CanNotDelete")],
                               "nextLink": f"https://arm{path}?api-version={params['api-version']}&$skiptoken=skip"})
        if path.endswith("/resources"):
            if self.resources_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": RESOURCES})
        if path.endswith("/resourcegroups"):
            if self.groups_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": [{"name": "rg-app"}, {"name": "rg-logs"}]})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


def _collect(arm, exclusions=None, protected=None):
    client = azure_rest.AzureRestClient(_Cred(), session=arm)
    collector = Collector(logging.getLogger("test"))
    results, summary = rl.collect(client, "s1", collector, exclusions, protected)
    return results, summary, collector


def test_collect_pages_locks_and_judges_each_resource(assert_summary_documented) -> None:
    arm = _Arm()
    results, summary, collector = _collect(arm)
    assert collector.ok, collector.failures
    assert_summary_documented("azure/resource_locks", summary)
    assert [lk["name"] for lk in results["locks"]] == ["rg", "law"]
    assert [r["name"] for r in results["protected_resources"]] == ["bv1", "kv1", "sa1", "law"]
    assert all(r["delete_locked"] for r in results["protected_resources"])
    assert [r["name"] for r in results["other_locked_resources"]] == ["vm1"]
    assert summary["protected_resource_lock_percentage"] == 100 and summary["resource_groups"] == 2
    assert summary["locks_by_scope_kind"] == {"resource": 1, "resource_group": 1, "subscription": 0}
    assert any(u.endswith("/locks?api-version=" + rl.LOCKS_API) for u in arm.urls)


def test_failed_lock_list_nulls_every_lock_field_and_fails() -> None:
    results, summary, collector = _collect(_Arm(locks_fail=True))
    assert not collector.ok and results["locks"] is None and results["other_locked_resources"] is None
    assert summary["locks_read"] is False and summary["protected_resources"] == 4
    assert summary["protected_resources_delete_locked"] is None and summary["all_protected_resources_locked"] is None
    assert all(r["delete_locked"] is None for r in results["protected_resources"])


def test_failed_resource_list_nulls_every_resource_field_and_fails() -> None:
    results, summary, collector = _collect(_Arm(resources_fail=True))
    assert not collector.ok and results["protected_resources"] is None
    assert summary["resources_read"] is False and summary["locks"] == 2 and summary["protected_resources"] is None
    assert summary["in_scope_resources"] is None and summary["excluded_resources"] is None


def test_failed_resource_group_list_only_nulls_the_group_count() -> None:
    results, summary, collector = _collect(_Arm(groups_fail=True))
    assert not collector.ok and results["resource_groups"] is None and summary["resource_groups"] is None
    assert summary["protected_resource_lock_percentage"] == 100 and summary["resource_groups_delete_locked"] == 1


def test_bad_protected_types_setting_fails_as_bad_config(monkeypatch) -> None:
    monkeypatch.setenv(rl.PROTECTED_TYPES_ENV, "vaults")
    client = azure_rest.AzureRestClient(_Cred(), session=_Arm())
    collector = Collector(logging.getLogger("test"))
    rl.collect(client, "s1", collector, ResourceExclusions())
    assert not collector.ok and "invalid setting" in collector.failures[0]["message"]
    assert sys.modules["azure_common"].classify_failure_code(collector.failures) == "bad_config"


def test_custom_protected_types_and_exclusions() -> None:
    results, summary, collector = _collect(_Arm(), ResourceExclusions(["rg:rg-logs"]),
                                           ["microsoft.compute/virtualmachines"])
    assert collector.ok
    assert [r["name"] for r in results["protected_resources"]] == ["vm1"]
    assert summary["protected_resource_types"] == ["microsoft.compute/virtualmachines"]
    assert summary["resources"] == 4 and summary["excluded_resources"] == 1 and summary["in_scope_resources"] == 4
    assert summary["protected_resources_delete_locked"] == 1
    assert [r["name"] for r in results["other_locked_resources"]] == ["bv1", "kv1", "sa1"]


def test_a_mistyped_protected_type_is_reported_as_unmatched() -> None:
    _, summary, collector = _collect(_Arm(), None, ["microsoft.keyvault/vault", "microsoft.keyvault/vaults"])
    assert collector.ok
    assert summary["protected_resource_types_unmatched"] == ["microsoft.keyvault/vault"]
    assert summary["protected_resources"] == 1
    _, unread, _ = _collect(_Arm(resources_fail=True))
    assert unread["protected_resource_types_unmatched"] is None


def test_a_readonly_subscription_lock_counts_as_delete_locked() -> None:
    locks = [rl.lock_record(raw_lock(SUB, "ro", "ReadOnly"))]
    summary = rl.summarize(locks, [rl.resource_record(raw_resource(KV, "Microsoft.KeyVault/vaults"), locks,
                                                      list(rl.DEFAULT_PROTECTED_TYPES))], [], list(rl.DEFAULT_PROTECTED_TYPES))
    assert summary["subscription_delete_locked"] is True and summary["subscription_lock_levels"] == ["readonly"]
    assert summary["protected_resources_delete_locked"] == 1 and summary["resources_read_only"] == 1


def test_per_type_counts_separate_locked_from_unlocked_and_a_missing_level_is_unknown() -> None:
    locks = [rl.lock_record(raw_lock(SA, "keep", "CanNotDelete")),
             rl.lock_record({"id": f"{SUB}/providers/Microsoft.Authorization/locks/blank", "name": "blank", "properties": {}})]
    other = SA.replace("sa1", "sa2")
    protected = list(rl.DEFAULT_PROTECTED_TYPES)
    records = [rl.resource_record(raw_resource(i, "Microsoft.Storage/storageAccounts"), locks, protected) for i in (SA, other)]
    summary = rl.summarize(locks, records, ["rg-app"], protected)
    assert summary["protected_resources_by_type"]["microsoft.storage/storageaccounts"] == {"resources": 2, "delete_locked": 1}
    assert locks[1]["level"] == "unknown" and summary["locks_by_level"] == {"cannotdelete": 1, "readonly": 0, "unknown": 1}
    assert records[1]["delete_locked"] is False


def test_resources_and_groups_are_paged_and_resource_group_names_are_case_insensitive() -> None:
    class Paged(_Arm):
        def get(self, url, params=None, headers=None, timeout=None):
            path = urlparse(url).path
            if path.endswith("/resources"):
                if "page2" in url:
                    return _Resp(200, {"value": [raw_resource(SA, "Microsoft.Storage/storageAccounts")]})
                return _Resp(200, {"value": [raw_resource(KV, "Microsoft.KeyVault/vaults")],
                                   "nextLink": f"https://arm{path}?api-version={params['api-version']}&page2=1"})
            if path.endswith("/providers/Microsoft.Authorization/locks"):
                return _Resp(200, {"value": [raw_lock(RG_APP.replace("rg-app", "RG-APP"), "rg", "CanNotDelete")]})
            return super().get(url, params, headers, timeout)

    _, summary, collector = _collect(Paged())
    assert collector.ok and summary["resources"] == 2 and summary["protected_resources_delete_locked"] == 2
    assert summary["resource_groups_delete_locked"] == 1


def test_unmatched_patterns_are_null_when_the_resource_list_was_refused(caplog) -> None:
    _, summary, _ = _collect(_Arm(resources_fail=True), ResourceExclusions(["rg:typo"]))
    assert summary["resource_exclusion_patterns_unmatched"] is None
    assert "matched nothing" not in caplog.text
    _, summary, _ = _collect(_Arm(), ResourceExclusions(["rg:typo"]))
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_an_invalid_exclusion_pattern_fails_the_run() -> None:
    _, _, collector = _collect(_Arm(), ResourceExclusions(["not-a-pattern"]))
    assert not collector.ok
