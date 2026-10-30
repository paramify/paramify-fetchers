"""resource_exclusions in the Azure Key Vault, Storage and Backup fetchers: excluded resources leave every count and
stay listed under excluded; except in key rotation, nothing past the list call is read for them."""

from __future__ import annotations

import copy
import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
PATTERNS = "rg:rg-out, location:regioneast, rg:typo"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


config = _load("key_vault_configuration")
rotation = _load("key_vault_key_rotation")
storage = _load("storage_encryption_status")
backup = _load("backup_recovery_status")
Collector = sys.modules["azure_common"].Collector


def _json(value):
    return json.loads(json.dumps(value, default=str))


def _unfiltered(collect):
    """What the collection returns when no exclusions are handed to it."""
    return collect("s1", object(), Collector(logging.getLogger("test_exclusions_data")))


def _refuse(name, fail):
    if name in fail:
        raise RuntimeError(f"(AuthorizationFailed) no read access to {name}")


def _run(module, monkeypatch, tmp_path, patterns, filename, **collectors):
    monkeypatch.setattr(module, "load_dotenv", lambda: None)
    monkeypatch.setattr(module, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(module, "credential", lambda: object())
    monkeypatch.setattr(module, "provider_registration_status", lambda *a: "registered")
    for name, fake in collectors.items():
        monkeypatch.setattr(module, name, fake)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)
    code = module.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _no_exclusions(**in_scope):
    return {"resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
            **{f"excluded_{kind}s": 0 for kind in in_scope}, **{f"in_scope_{kind}s": n for kind, n in in_scope.items()}}


def _entries(evidence):
    return sorted((e["kind"], e["name"], e["pattern"], e["id"]) for e in evidence["results"]["excluded"])


# --- azure_key_vault_configuration ---

def _vault_id(rg, name):
    return f"{rg}/providers/Microsoft.KeyVault/vaults/{name}"


KEY_VAULTS = [(IN_RG, "kv-in", "regionwest"), (OUT_RG, "kv-out", "regionwest"), (IN_RG, "kv-east", "Region East")]


def run_config(monkeypatch, tmp_path, patterns, fail=()):
    read: list = []

    def diagnostic_settings(resource_uri):
        name = resource_uri.rsplit("/", 1)[-1]
        read.append(("diagnostic_settings", name))
        _refuse(name, fail)
        return []

    vaults = [ns(id=_vault_id(rg, name), name=name, location=location, properties=ns(enable_rbac_authorization=True))
              for rg, name, location in KEY_VAULTS]
    keyvault = ns(vaults=ns(list_by_subscription=lambda: iter(vaults)))
    monitor = ns(diagnostic_settings=ns(list=diagnostic_settings))
    monkeypatch.setitem(sys.modules, "azure.mgmt.keyvault", ns(KeyVaultManagementClient=lambda **_: keyvault))
    monkeypatch.setitem(sys.modules, "azure.mgmt.monitor", ns(MonitorManagementClient=lambda **_: monitor))
    return (*_run(config, monkeypatch, tmp_path, patterns, "azure_key_vault_configuration"), read)


def test_key_vault_configuration_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, read = run_config(monkeypatch, tmp_path, None)
    assert code == 0 and len(read) == 3
    vaults = _unfiltered(config.collect_key_vaults)
    assert evidence["results"] == _json({"key_vaults": vaults, "provider_registration_status": "registered",
                                         "excluded": []})
    assert evidence["summary"] == _json({**config.summarize(vaults), "provider_registration_status": "registered",
                                         **_no_exclusions(key_vault=3)})


def test_key_vault_configuration_excludes_by_group_and_region(monkeypatch, tmp_path):
    code, evidence, _ = run_config(monkeypatch, tmp_path, PATTERNS)
    summary = evidence["summary"]
    assert code == 0
    assert [v["name"] for v in evidence["results"]["key_vaults"]] == ["kv-in"]
    assert _entries(evidence) == [
        ("key_vault", "kv-east", "location:regioneast", _vault_id(IN_RG, "kv-east")),
        ("key_vault", "kv-out", "rg:rg-out", _vault_id(OUT_RG, "kv-out")),
    ]
    assert (summary["total_key_vaults"], summary["rbac_authorization_vaults"], summary["rbac_authorization_percentage"],
            summary["vaults_without_audit_logging"]) == (1, 1, 100, 1)
    assert (summary["excluded_key_vaults"], summary["in_scope_key_vaults"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


# --- azure_key_vault_key_rotation ---

def _rotation_vault(rg, name, location, cert, auto_renew, extra_keys=()):
    vault_id = _vault_id(rg, name)
    keys = [rotation.key_record({"id": f"{vault_id}/keys/k1", "name": "k1", "location": location},
                               "management_plane", True)]
    # A key only the data plane returned has no ARM id.
    keys += [rotation.key_record({"name": key}) for key in extra_keys]
    policy = {"lifetime_actions": [{"action": "AutoRenew" if auto_renew else "EmailContacts"}]}
    return rotation.vault_record({
        "id": vault_id, "name": name, "location": location, "vault_uri": f"https://{name}.vault.example/",
        "data_plane_status": "accessible", "certificates_status": "accessible", "keys": keys,
        "secrets": [rotation.secret_record({"id": f"{vault_id}/secrets/s1", "name": "s1", "location": location})],
        "certificates": [rotation.certificate_record(
            {"id": f"https://{name}.vault.example/certificates/{cert}/v1", "name": cert}, policy, True, NOW)],
    })


ROTATION_VAULTS = [
    _rotation_vault(IN_RG, "kv-in", "regionwest", "api", False, extra_keys=("dp-only",)),
    _rotation_vault(OUT_RG, "kv-out", "regionwest", "web", True, extra_keys=("dp-only",)),
    _rotation_vault(IN_RG, "kv-east", "regioneast", "web", True),
]
APP_CERTIFICATES = [
    # Synced from the excluded vault's certificate: its auto-renew answer must survive the exclusion.
    {"id": f"{IN_RG}/providers/Microsoft.Web/certificates/app-in", "name": "app-in", "location": "regionwest",
     "key_vault_id": _vault_id(OUT_RG, "kv-out"), "key_vault_secret_name": "web", "key_vault_secret_status": "Succeeded"},
    {"id": f"{OUT_RG}/providers/Microsoft.Web/certificates/app-out", "name": "app-out", "location": "regionwest"},
]


def _app_certificates(subscription_id, cred, collector, vaults, now):
    index = rotation.key_vault_auto_renew_index(vaults)
    return [rotation.app_service_certificate_record(c, now, index) for c in APP_CERTIFICATES]


def run_rotation(monkeypatch, tmp_path, patterns):
    return _run(rotation, monkeypatch, tmp_path, patterns, "azure_key_vault_key_rotation",
                collect_key_vaults=lambda *a: copy.deepcopy(ROTATION_VAULTS),
                collect_app_service_certificates=_app_certificates)


def test_key_vault_key_rotation_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_rotation(monkeypatch, tmp_path, None)
    app = _app_certificates(None, None, None, ROTATION_VAULTS, NOW)
    results, summary = rotation.evidence_sections(ROTATION_VAULTS, "registered", app, "registered")
    assert code == 0
    assert evidence["results"] == _json({**results, "excluded": []})
    assert evidence["summary"] == _json({**summary, **_no_exclusions(
        key_vault=3, key=5, secret=3, certificate=3, app_service_certificate=2)})


def test_key_vault_key_rotation_children_leave_with_their_vault(monkeypatch, tmp_path):
    code, evidence = run_rotation(monkeypatch, tmp_path, PATTERNS)
    summary, results = evidence["summary"], evidence["results"]
    out_id, east_id = _vault_id(OUT_RG, "kv-out"), _vault_id(IN_RG, "kv-east")
    assert code == 0
    assert [v["name"] for v in results["key_vaults"]] == ["kv-in"]
    assert [k["name"] for k in results["key_vaults"][0]["keys"]] == ["k1", "dp-only"]
    assert _entries(evidence) == [
        ("app_service_certificate", "app-out", "rg:rg-out", f"{OUT_RG}/providers/Microsoft.Web/certificates/app-out"),
        # A certificate, or a key with no ARM id, is matched by its vault's id.
        ("certificate", "web", "location:regioneast", east_id),
        ("certificate", "web", "rg:rg-out", out_id),
        ("key", "dp-only", "rg:rg-out", out_id),
        ("key", "k1", "location:regioneast", f"{east_id}/keys/k1"),
        ("key", "k1", "rg:rg-out", f"{out_id}/keys/k1"),
        ("key_vault", "kv-east", "location:regioneast", east_id),
        ("key_vault", "kv-out", "rg:rg-out", out_id),
        ("secret", "s1", "location:regioneast", f"{east_id}/secrets/s1"),
        ("secret", "s1", "rg:rg-out", f"{out_id}/secrets/s1"),
    ]
    assert [c["name"] for c in results["app_service_certificates"]] == ["app-in"]
    assert results["app_service_certificates"][0]["key_vault_certificate_auto_renew"] is True
    assert (summary["total_key_vaults"], summary["total_keys"], summary["total_secrets"], summary["total_certificates"],
            summary["total_app_service_certificates"], summary["certificates_with_auto_renew"]) == (1, 2, 1, 1, 1, 0)
    assert {k: summary[f"excluded_{k}s"] for k in rotation.EXCLUSION_KINDS} == {
        "key_vault": 2, "key": 3, "secret": 2, "certificate": 2, "app_service_certificate": 1}
    assert {k: summary[f"in_scope_{k}s"] for k in rotation.EXCLUSION_KINDS} == {
        "key_vault": 1, "key": 2, "secret": 1, "certificate": 1, "app_service_certificate": 1}
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_key_vault_key_rotation_id_pattern_takes_the_vaults_data_plane_children(monkeypatch, tmp_path):
    in_id = _vault_id(IN_RG, "kv-in")
    code, evidence = run_rotation(monkeypatch, tmp_path, f"id:{in_id}")
    assert code == 0
    assert [v["name"] for v in evidence["results"]["key_vaults"]] == ["kv-out", "kv-east"]
    assert [(kind, name, entry_id) for kind, name, _, entry_id in _entries(evidence)] == [
        ("certificate", "api", in_id), ("key", "dp-only", in_id), ("key", "k1", f"{in_id}/keys/k1"),
        ("key_vault", "kv-in", in_id), ("secret", "s1", f"{in_id}/secrets/s1")]


# --- azure_storage_encryption_status ---

def _account_id(rg, name):
    return f"{rg}/providers/Microsoft.Storage/storageAccounts/{name}"


# (resource group, name, region, SKU, containers); None: the account has no blob endpoint.
STORAGE_ACCOUNTS = [
    (IN_RG, "sa-in", "regionwest", "Standard_RAGRS", ("c1", "c2")),
    (IN_RG, "sa-files", "regionwest", "Standard_LRS", None),
    (OUT_RG, "sa-out", "regionwest", "Standard_GRS", ("c1",)),
    (IN_RG, "sa-east", "regioneast", "Standard_LRS", ("c1",)),
]


def run_storage(monkeypatch, tmp_path, patterns, fail=()):
    read: list = []
    groups = {name: (rg, containers) for rg, name, _, _, containers in STORAGE_ACCOUNTS}

    def reader(operation, answer):
        def call(group, name, **_):
            read.append((operation, name))
            _refuse(name, fail)
            return answer(name)
        return call

    def containers(name):
        rg, names = groups[name]
        if names is None:
            raise RuntimeError("Blob is not supported for the account.")
        return [ns(id=f"{_account_id(rg, name)}/blobServices/default/containers/{c}", name=c, public_access="Blob")
                for c in names]

    accounts = [ns(id=_account_id(rg, name), name=name, location=location, sku=ns(name=sku),
                   encryption=ns(key_source="Microsoft.Storage")) for rg, name, location, sku, _ in STORAGE_ACCOUNTS]
    client = ns(
        storage_accounts=ns(list=lambda: iter(accounts),
                            get_properties=reader("geo_replication_stats", lambda name: ns(geo_replication_stats=None))),
        blob_services=ns(get_service_properties=reader("blob_properties", lambda name: ns())),
        file_services=ns(get_service_properties=reader("file_service_properties", lambda name: ns())),
        blob_containers=ns(list=reader("containers", containers)),
    )
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", ns(StorageManagementClient=lambda **_: client))
    return (*_run(storage, monkeypatch, tmp_path, patterns, "azure_storage_encryption_status"), read)


def test_storage_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, read = run_storage(monkeypatch, tmp_path, None)
    assert code == 0 and len(read) == 14
    accounts = _unfiltered(storage.collect_storage_accounts)
    assert evidence["results"] == _json({"storage_accounts": accounts, "provider_registration_status": "registered",
                                         "excluded": []})
    assert evidence["summary"] == _json({**storage.summarize(accounts), "provider_registration_status": "registered",
                                         **_no_exclusions(storage_account=4, container=4)})


def test_storage_excluded_accounts_take_their_unread_containers_and_an_id_pattern_takes_one(monkeypatch, tmp_path):
    c2 = f"{_account_id(IN_RG, 'sa-in')}/blobServices/default/containers/c2"
    code, evidence, _ = run_storage(monkeypatch, tmp_path, f"{PATTERNS} id:{c2}")
    summary, accounts = evidence["summary"], evidence["results"]["storage_accounts"]
    assert code == 0
    assert [(a["name"], a["containers"] and [c["name"] for c in a["containers"]]) for a in accounts] == [
        ("sa-files", None), ("sa-in", ["c1"])]
    # An excluded account's containers are never listed, so the id: match is the only container entry.
    assert _entries(evidence) == [
        ("container", "c2", f"id:{c2}", c2),
        ("storage_account", "sa-east", "location:regioneast", _account_id(IN_RG, "sa-east")),
        ("storage_account", "sa-out", "rg:rg-out", _account_id(OUT_RG, "sa-out")),
    ]
    assert (summary["total_storage_accounts"], summary["total_containers"],
            summary["containers_with_public_access_level"]) == (2, 1, 1)
    assert (summary["excluded_storage_accounts"], summary["excluded_containers"]) == (2, 1)
    assert (summary["in_scope_storage_accounts"], summary["in_scope_containers"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


# --- azure_backup_recovery_status ---

def _vm_id(rg, name):
    return f"{rg}/providers/Microsoft.Compute/virtualMachines/{name}"


def _recovery_vault_id(rg, name):
    return f"{rg}/providers/Microsoft.RecoveryServices/vaults/{name}"


# (resource group, vault, region, [(protected VM, its resource group)])
RECOVERY_VAULTS = [
    (IN_RG, "rsv-in", "regionwest", [("vm-a", IN_RG), ("vm-b", OUT_RG)]),
    # Protects only a resource in an excluded group, so it stays in scope protecting nothing.
    (IN_RG, "rsv-only-out", "regionwest", [("vm-c", OUT_RG)]),
    (OUT_RG, "rsv-out", "regionwest", [("vm-d", IN_RG)]),
    (IN_RG, "rsv-east", "regioneast", [("vm-e", IN_RG)]),
]


def run_backup(monkeypatch, tmp_path, patterns, fail=()):
    read: list = []
    vault_ids = {name: _recovery_vault_id(rg, name) for rg, name, _, _ in RECOVERY_VAULTS}
    protects = {name: items for _, name, _, items in RECOVERY_VAULTS}

    def reader(operation, answer):
        def call(vault_name, resource_group_name):
            read.append((operation, vault_name))
            _refuse(vault_name, fail)
            return answer(vault_ids[vault_name], protects[vault_name])
        return call

    def policies(vault_id, _):
        retention = ns(daily_schedule=ns(retention_duration=ns(count=30, duration_type="Days")))
        return [ns(id=f"{vault_id}/backupPolicies/daily", name="daily", properties=ns(retention_policy=retention))]

    def items(vault_id, protected):
        return [ns(id=f"{vault_id}/backupFabrics/Azure/protectionContainers/c/protectedItems/{vm}", name=vm,
                   properties=ns(source_resource_id=_vm_id(rg, vm), policy_id=f"{vault_id}/backupPolicies/daily",
                                 protection_state="Protected", last_backup_status="Completed", workload_type="VM"))
                for vm, rg in protected]

    vaults = [ns(id=vault_ids[name], name=name, location=location,
                 properties=ns(security_settings=ns(soft_delete_settings=ns(soft_delete_state="Enabled"))))
              for _, name, location, _ in RECOVERY_VAULTS]
    recovery = ns(vaults=ns(list_by_subscription_id=lambda: iter(vaults)))
    client = ns(backup_policies=ns(list=reader("backup_policies", policies)),
                backup_protected_items=ns(list=reader("protected_items", items)))
    monkeypatch.setitem(sys.modules, "azure.mgmt.recoveryservices", ns(RecoveryServicesClient=lambda **_: recovery))
    monkeypatch.setitem(sys.modules, "azure.mgmt.recoveryservicesbackup",
                        ns(RecoveryServicesBackupClient=lambda **_: client))
    return (*_run(backup, monkeypatch, tmp_path, patterns, "azure_backup_recovery_status"), read)


def test_backup_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, read = run_backup(monkeypatch, tmp_path, None)
    assert code == 0 and len(read) == 8
    vaults = _unfiltered(backup.collect_vaults)
    assert evidence["results"] == _json({"recovery_services_vaults": vaults,
                                         "provider_registration_status": "registered", "excluded": []})
    assert evidence["summary"] == _json({**backup.summarize(vaults), "provider_registration_status": "registered",
                                         **_no_exclusions(recovery_services_vault=4, protected_item=5)})


def test_backup_items_leave_with_the_resource_they_protect_and_excluded_vaults_items_are_not_listed(
        monkeypatch, tmp_path):
    code, evidence, _ = run_backup(monkeypatch, tmp_path, PATTERNS)
    summary, vaults = evidence["summary"], evidence["results"]["recovery_services_vaults"]
    assert code == 0
    assert [(v["name"], [i["name"] for i in v["backup_protected_items"]], v["total_protected_items"])
            for v in vaults] == [("rsv-in", ["vm-a"], 1), ("rsv-only-out", [], 0)]
    # Matched through the protected resource: the entry carries that resource's id.
    assert _entries(evidence) == [
        ("protected_item", "vm-b", "rg:rg-out", _vm_id(OUT_RG, "vm-b")),
        ("protected_item", "vm-c", "rg:rg-out", _vm_id(OUT_RG, "vm-c")),
        ("recovery_services_vault", "rsv-east", "location:regioneast", _recovery_vault_id(IN_RG, "rsv-east")),
        ("recovery_services_vault", "rsv-out", "rg:rg-out", _recovery_vault_id(OUT_RG, "rsv-out")),
    ]
    assert (summary["total_recovery_services_vaults"], summary["vaults_with_protected_items"],
            summary["vaults_without_protected_items"], summary["total_backup_policies"],
            summary["total_protected_items"], summary["retention_threshold_percentage"]) == (2, 1, 1, 2, 1, 100)
    assert (summary["excluded_recovery_services_vaults"], summary["excluded_protected_items"]) == (2, 2)
    assert (summary["in_scope_recovery_services_vaults"], summary["in_scope_protected_items"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_backup_id_pattern_on_a_protected_resource_takes_only_that_item(monkeypatch, tmp_path):
    vm = _vm_id(IN_RG, "vm-a")
    code, evidence, read = run_backup(monkeypatch, tmp_path, f"id:{vm}")
    summary, vaults = evidence["summary"], evidence["results"]["recovery_services_vaults"]
    assert code == 0 and len(read) == 8
    assert [(v["name"], [i["name"] for i in v["backup_protected_items"]]) for v in vaults] == [
        ("rsv-east", ["vm-e"]), ("rsv-in", ["vm-b"]), ("rsv-only-out", ["vm-c"]), ("rsv-out", ["vm-d"])]
    assert evidence["results"]["excluded"] == [{
        "kind": "protected_item", "name": "vm-a", "pattern": f"id:{vm}", "reason": "resource_matched", "id": vm,
        "resource_group": "rg-in", "location": None}]
    assert (summary["excluded_recovery_services_vaults"], summary["excluded_protected_items"]) == (0, 1)
    assert (summary["total_protected_items"], summary["in_scope_protected_items"]) == (4, 4)
    assert summary["resource_exclusion_patterns_unmatched"] == []


# --- every fetcher ---

@pytest.mark.parametrize("run, total", [
    (run_config, "total_key_vaults"), (run_rotation, "total_key_vaults"),
    (run_storage, "total_storage_accounts"), (run_backup, "total_recovery_services_vaults"),
])
def test_bare_pattern_fails_the_run(monkeypatch, tmp_path, run, total):
    code, evidence = run(monkeypatch, tmp_path, "rg-out")[:2]
    assert code == 1
    assert evidence["results"]["excluded"] == [] and evidence["summary"][total] > 1
    assert any(f["operation"] == f"config {ENV}" for f in evidence["metadata"]["api_failures"])


@pytest.mark.parametrize("run, reads", [
    (run_config, [("diagnostic_settings", "kv-in")]),
    (run_storage, [(op, "sa-in") for op in ("blob_properties", "file_service_properties", "geo_replication_stats",
                                            "containers")]
     + [(op, "sa-files") for op in ("blob_properties", "file_service_properties", "containers")]),
    (run_backup, [(op, vault) for vault in ("rsv-in", "rsv-only-out") for op in ("backup_policies", "protected_items")]),
])
def test_excluded_resources_are_not_read_past_the_list(monkeypatch, tmp_path, run, reads):
    code, _, read = run(monkeypatch, tmp_path, PATTERNS)
    assert code == 0 and read == reads


@pytest.mark.parametrize("run, refused", [
    (run_config, ("kv-out", "kv-east")), (run_storage, ("sa-out", "sa-east")), (run_backup, ("rsv-out", "rsv-east")),
])
def test_a_refused_read_on_an_excluded_resource_leaves_the_run_passing(monkeypatch, tmp_path, run, refused):
    # With nothing excluded, the same refusals fail the run.
    assert run(monkeypatch, tmp_path, None, fail=refused)[0] == 1
    code, evidence, _ = run(monkeypatch, tmp_path, PATTERNS, fail=refused)
    assert code == 0 and evidence["metadata"]["api_failures"] == []
