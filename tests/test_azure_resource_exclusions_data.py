"""resource_exclusions in the Azure Key Vault, Storage and Backup fetchers: excluded resources leave every count and
stay listed under excluded."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

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


def _json(value):
    return json.loads(json.dumps(value, default=str))


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

def _config_vault(rg, name, location):
    record = config.vault_record({"id": f"{rg}/providers/Microsoft.KeyVault/vaults/{name}", "name": name,
                                  "location": location, "enable_rbac_authorization": True})
    return config.with_audit_logging(record, [])


CONFIG_VAULTS = [_config_vault(IN_RG, "kv-in", "regionwest"), _config_vault(OUT_RG, "kv-out", "regionwest"),
                 _config_vault(IN_RG, "kv-east", "Region East")]


def run_config(monkeypatch, tmp_path, patterns):
    return _run(config, monkeypatch, tmp_path, patterns, "azure_key_vault_configuration",
                collect_key_vaults=lambda *a: copy.deepcopy(CONFIG_VAULTS))


def test_key_vault_configuration_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_config(monkeypatch, tmp_path, None)
    assert code == 0
    assert evidence["results"] == _json({"key_vaults": CONFIG_VAULTS, "provider_registration_status": "registered",
                                         "excluded": []})
    assert evidence["summary"] == _json({**config.summarize(CONFIG_VAULTS), "provider_registration_status": "registered",
                                         **_no_exclusions(key_vault=3)})


def test_key_vault_configuration_excludes_by_group_and_region(monkeypatch, tmp_path):
    code, evidence = run_config(monkeypatch, tmp_path, PATTERNS)
    summary = evidence["summary"]
    assert code == 0
    assert [v["name"] for v in evidence["results"]["key_vaults"]] == ["kv-in"]
    assert _entries(evidence) == [
        ("key_vault", "kv-east", "location:regioneast", f"{IN_RG}/providers/Microsoft.KeyVault/vaults/kv-east"),
        ("key_vault", "kv-out", "rg:rg-out", f"{OUT_RG}/providers/Microsoft.KeyVault/vaults/kv-out"),
    ]
    assert (summary["total_key_vaults"], summary["rbac_authorization_vaults"], summary["rbac_authorization_percentage"],
            summary["vaults_without_audit_logging"]) == (1, 1, 100, 1)
    assert (summary["excluded_key_vaults"], summary["in_scope_key_vaults"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


# --- azure_key_vault_key_rotation ---

def _vault_id(rg, name):
    return f"{rg}/providers/Microsoft.KeyVault/vaults/{name}"


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

def _account(rg, name, location, containers=("c1",)):
    account_id = f"{rg}/providers/Microsoft.Storage/storageAccounts/{name}"
    record = storage.account_record({"id": account_id, "name": name, "location": location,
                                     "replication_settings": "Standard_LRS", "encryption_type": "Microsoft.Storage"},
                                    NOW)
    if containers is not None:
        record["containers_status"] = "collected"
        record["containers"] = [storage.container_record(
            {"id": f"{account_id}/blobServices/default/containers/{c}", "name": c, "public_access": "Blob"}, True)
            for c in containers]
    return record


ACCOUNTS = [_account(IN_RG, "sa-in", "regionwest", ("c1", "c2")), _account(IN_RG, "sa-files", "regionwest", None),
            _account(OUT_RG, "sa-out", "regionwest"), _account(IN_RG, "sa-east", "regioneast")]


def run_storage(monkeypatch, tmp_path, patterns):
    return _run(storage, monkeypatch, tmp_path, patterns, "azure_storage_encryption_status",
                collect_storage_accounts=lambda *a: copy.deepcopy(ACCOUNTS))


def test_storage_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_storage(monkeypatch, tmp_path, None)
    assert code == 0
    assert evidence["results"] == _json({"storage_accounts": ACCOUNTS, "provider_registration_status": "registered",
                                         "excluded": []})
    assert evidence["summary"] == _json({**storage.summarize(ACCOUNTS), "provider_registration_status": "registered",
                                         **_no_exclusions(storage_account=4, container=4)})


def test_storage_containers_leave_with_their_account(monkeypatch, tmp_path):
    in_id = f"{IN_RG}/providers/Microsoft.Storage/storageAccounts/sa-in"
    code, evidence = run_storage(monkeypatch, tmp_path, f"{PATTERNS} id:{in_id}/blobServices/default/containers/c2")
    summary, accounts = evidence["summary"], evidence["results"]["storage_accounts"]
    assert code == 0
    assert [(a["name"], a["containers"] and [c["name"] for c in a["containers"]]) for a in accounts] == [
        ("sa-in", ["c1"]), ("sa-files", None)]
    assert [(kind, name, pattern.split(":")[0]) for kind, name, pattern, _ in _entries(evidence)] == [
        ("container", "c1", "location"), ("container", "c1", "rg"), ("container", "c2", "id"),
        ("storage_account", "sa-east", "location"), ("storage_account", "sa-out", "rg")]
    assert (summary["total_storage_accounts"], summary["total_containers"],
            summary["containers_with_public_access_level"]) == (2, 1, 1)
    assert (summary["excluded_storage_accounts"], summary["excluded_containers"]) == (2, 3)
    assert (summary["in_scope_storage_accounts"], summary["in_scope_containers"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


# --- azure_backup_recovery_status ---

def _vm_id(rg, name):
    return f"{rg}/providers/Microsoft.Compute/virtualMachines/{name}"


def _recovery_vault(rg, name, location, items):
    vault_id = f"{rg}/providers/Microsoft.RecoveryServices/vaults/{name}"
    policy = backup.backup_policy_record({
        "id": f"{vault_id}/backupPolicies/daily", "name": "daily",
        "retention_policy": {"daily_schedule": {"retention_duration": {"count": 30, "duration_type": "Days"}}}})
    return backup.vault_record({
        "id": vault_id, "name": name, "location": location, "soft_delete_state": "Enabled",
        "backup_policies": [policy],
        "backup_protected_items": [backup.protected_item_record({
            "id": f"{vault_id}/backupFabrics/Azure/protectionContainers/c/protectedItems/{vm}", "name": vm,
            "source_resource_id": _vm_id(source_rg, vm), "backup_policy_id": policy["id"],
            "protection_state": "Protected", "last_backup_status": "Completed", "workload_type": "VM",
        }, {policy["id"]: policy}) for vm, source_rg in items],
    })


RECOVERY_VAULTS = [
    _recovery_vault(IN_RG, "rsv-in", "regionwest", [("vm-a", IN_RG), ("vm-b", OUT_RG)]),
    # Protects only a resource in an excluded group, so it stays in scope protecting nothing.
    _recovery_vault(IN_RG, "rsv-only-out", "regionwest", [("vm-c", OUT_RG)]),
    _recovery_vault(OUT_RG, "rsv-out", "regionwest", [("vm-d", IN_RG)]),
    _recovery_vault(IN_RG, "rsv-east", "regioneast", [("vm-e", IN_RG)]),
]


def run_backup(monkeypatch, tmp_path, patterns):
    return _run(backup, monkeypatch, tmp_path, patterns, "azure_backup_recovery_status",
                collect_vaults=lambda *a: copy.deepcopy(RECOVERY_VAULTS))


def test_backup_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_backup(monkeypatch, tmp_path, None)
    assert code == 0
    assert evidence["results"] == _json({"recovery_services_vaults": RECOVERY_VAULTS,
                                         "provider_registration_status": "registered", "excluded": []})
    assert evidence["summary"] == _json({**backup.summarize(RECOVERY_VAULTS), "provider_registration_status": "registered",
                                         **_no_exclusions(recovery_services_vault=4, protected_item=5)})


def test_backup_items_leave_with_their_vault_or_the_resource_they_protect(monkeypatch, tmp_path):
    code, evidence = run_backup(monkeypatch, tmp_path, PATTERNS)
    summary, vaults = evidence["summary"], evidence["results"]["recovery_services_vaults"]
    assert code == 0
    assert [(v["name"], [i["name"] for i in v["backup_protected_items"]], v["total_protected_items"])
            for v in vaults] == [("rsv-in", ["vm-a"], 1), ("rsv-only-out", [], 0)]
    out_item = f"{OUT_RG}/providers/Microsoft.RecoveryServices/vaults/rsv-out/backupFabrics/Azure/protectionContainers/c"
    east_vault = f"{IN_RG}/providers/Microsoft.RecoveryServices/vaults/rsv-east"
    assert _entries(evidence) == [
        # Matched through the protected resource: the entry carries that resource's id.
        ("protected_item", "vm-b", "rg:rg-out", _vm_id(OUT_RG, "vm-b")),
        ("protected_item", "vm-c", "rg:rg-out", _vm_id(OUT_RG, "vm-c")),
        ("protected_item", "vm-d", "rg:rg-out", f"{out_item}/protectedItems/vm-d"),
        ("protected_item", "vm-e", "location:regioneast",
         f"{east_vault}/backupFabrics/Azure/protectionContainers/c/protectedItems/vm-e"),
        ("recovery_services_vault", "rsv-east", "location:regioneast", east_vault),
        ("recovery_services_vault", "rsv-out", "rg:rg-out", f"{OUT_RG}/providers/Microsoft.RecoveryServices/vaults/rsv-out"),
    ]
    assert (summary["total_recovery_services_vaults"], summary["vaults_with_protected_items"],
            summary["vaults_without_protected_items"], summary["total_backup_policies"],
            summary["total_protected_items"], summary["retention_threshold_percentage"]) == (2, 1, 1, 2, 1, 100)
    assert (summary["excluded_recovery_services_vaults"], summary["excluded_protected_items"]) == (2, 4)
    assert (summary["in_scope_recovery_services_vaults"], summary["in_scope_protected_items"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


# --- every fetcher ---

@pytest.mark.parametrize("run, total", [
    (run_config, "total_key_vaults"), (run_rotation, "total_key_vaults"),
    (run_storage, "total_storage_accounts"), (run_backup, "total_recovery_services_vaults"),
])
def test_bare_pattern_fails_the_run(monkeypatch, tmp_path, run, total):
    code, evidence = run(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["results"]["excluded"] == [] and evidence["summary"][total] > 1
    assert any(f["operation"] == f"config {ENV}" for f in evidence["metadata"]["api_failures"])
