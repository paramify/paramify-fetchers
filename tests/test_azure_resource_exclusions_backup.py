"""resource_exclusions and resource_inclusions in azure_backup_vault_protection: a backup leaves on an exclusion of
itself, its vault or the resource it protects, and only that resource brings it in. Synthetic payloads, no network."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

import tag_index  # noqa: E402
from azure_common import subscription_of  # noqa: E402
from resource_exclusions import ENV, INCLUSIONS_ENV  # noqa: E402
from tag_index import TagIndex  # noqa: E402

_spec = importlib.util.spec_from_file_location("azure_backup_vault_protection_exclusions_under_test",
                                               AZURE / "backup_vault_protection" / "fetcher.py")
bv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bv)
azure_rest = sys.modules["azure_rest"]

SUB = "/subscriptions/s1"
API = "2025-07-01"
POINT_TIME = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")


def vault_id(rg, name):
    return f"{SUB}/resourceGroups/{rg}/providers/Microsoft.DataProtection/backupVaults/{name}"


def disk_id(rg, name):
    return f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Compute/disks/{name}"


CONTOSO, EXAMPLE = vault_id("rg-backup", "bv-contoso"), vault_id("rg-out", "bv-example")
DISK_APP, DISK_OUT, DISK_OLD = disk_id("rg-app", "disk-app"), disk_id("rg-out", "disk-out"), disk_id("rg-out", "disk-old")
REGIONS = {CONTOSO: "eastus", EXAMPLE: "westus", DISK_APP: "eastus", DISK_OUT: "westus", DISK_OLD: "westus"}
# Each vault's backups, by name, and the disk each protects.
BACKUPS = {CONTOSO: {"bi-app": DISK_APP, "bi-out": DISK_OUT}, EXAMPLE: {"bi-old": DISK_OLD}}


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


class _Arm:
    def __init__(self, refused=()):
        self.refused, self.paths = tuple(refused), []

    def get(self, url, params=None, headers=None, timeout=None):
        path = urlparse(url).path
        self.paths.append(path)
        if any(path.endswith(suffix) for suffix in self.refused):
            return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
        if path.endswith("/providers/Microsoft.DataProtection"):
            return _Resp(200, {"registrationState": "Registered",
                               "resourceTypes": [{"resourceType": "backupVaults", "apiVersions": [API]}]})
        if path.endswith("/backupVaults"):
            return _Resp(200, {"value": [{"id": v, "name": v.rsplit("/", 1)[-1], "location": REGIONS[v],
                                          "properties": {"provisioningState": "Succeeded"}} for v in BACKUPS]})
        if path.endswith("/backupPolicies"):
            return _Resp(200, {"value": []})
        if path.endswith("/backupInstances"):
            vault = path.removesuffix("/backupInstances")
            return _Resp(200, {"value": [
                {"id": f"{vault}/backupInstances/{name}", "name": name,
                 "properties": {"dataSourceInfo": {"datasourceType": "Microsoft.Compute/disks", "resourceID": disk,
                                                   "resourceType": "Microsoft.Compute/disks",
                                                   "resourceName": disk.rsplit("/", 1)[-1],
                                                   "resourceLocation": REGIONS[disk]},
                                "currentProtectionState": "ProtectionConfigured"}}
                for name, disk in BACKUPS[vault].items()]})
        if path.endswith("/recoveryPoints"):
            return _Resp(200, {"value": [{"id": f"{path}/rp1", "properties": {
                "recoveryPointTime": POINT_TIME, "recoveryPointType": "Full", "recoveryPointState": "Completed"}}]})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


class DiskAppTagged:
    """Only disk-app carries Boundary=FedRAMP; the vaults and backups carry no tags."""

    def __init__(self, loader=None):
        self.failures = []

    def entries(self, subscription_id):
        return {}

    def held(self, resource_id):
        return True if subscription_of(resource_id) else None

    def tags_of(self, resource_id):
        return {"boundary": "FedRAMP"} if resource_id.lower() == DISK_APP.lower() else {}


def _serve(monkeypatch, tmp_path, patterns, refused=()):
    session = _Arm(refused)
    monkeypatch.setattr("requests.Session", lambda: session)
    monkeypatch.setattr(azure_rest, "pinned_credential",
                        lambda sub: type("C", (), {"get_token": lambda s, *a: namedtuple("T", "token expires_on")(
                            "tok", 9_999_999_999)})())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    for env, value in (("AZURE_SUBSCRIPTION_ID", "s1"), ("EVIDENCE_DIR", str(tmp_path)),
                       ("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))):
        monkeypatch.setenv(env, value)
    for env in ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", bv.RPO_ENV, bv.WINDOW_ENV,
                bv.LOOKBACK_ENV, bv.RETENTION_THRESHOLD_ENV):
        monkeypatch.delenv(env, raising=False)
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)
    return session


def run_backups(monkeypatch, tmp_path, patterns, refused=()):
    session = _serve(monkeypatch, tmp_path, patterns, refused)
    code = bv.main()
    [path] = tmp_path.glob("azure_backup_vault_protection_s1.json")
    return code, json.loads(path.read_text()), session


def _in_scope(evidence):
    return {v["name"]: [i["name"] for i in v["backup_instances"]] for v in evidence["results"]["backup_vaults"]}


def _out(evidence):
    return sorted((e["kind"], e["id"].rsplit("/", 1)[-1], e["pattern"] or e["reason"])
                  for e in evidence["results"]["excluded"])


def test_rg_out_takes_out_a_vault_and_a_backup_of_a_resource_in_it(monkeypatch, tmp_path):
    monkeypatch.delenv(INCLUSIONS_ENV, raising=False)
    code, evidence, session = run_backups(monkeypatch, tmp_path, "rg:rg-out")
    assert code == 0
    assert _in_scope(evidence) == {"bv-contoso": ["bi-app"]}
    # The backup's entry names the resource whose match took it out.
    assert _out(evidence) == [("backup_instance", "disk-out", "rg:rg-out"), ("backup_vault", "bv-example", "rg:rg-out")]
    assert not any("bv-example" in p or "bi-out/recoveryPoints" in p for p in session.paths)


@pytest.mark.parametrize("inclusion", ["tag:Boundary=FedRAMP", "rg:rg-app", "location:eastus", "id:*/disks/disk-app"])
def test_a_backup_is_in_scope_when_the_resource_it_protects_is(monkeypatch, tmp_path, inclusion):
    monkeypatch.setattr(tag_index, "TagIndex", DiskAppTagged)
    monkeypatch.setenv(INCLUSIONS_ENV, inclusion)
    code, evidence, session = run_backups(monkeypatch, tmp_path, None)
    assert code == 0
    assert _in_scope(evidence) == {"bv-contoso": ["bi-app"]}
    assert _out(evidence) == [("backup_instance", "disk-old", "not_included"),
                              ("backup_instance", "disk-out", "not_included"),
                              ("backup_vault", "bv-example", "not_included")]
    summary = evidence["summary"]
    assert (summary["total_backup_vaults"], summary["total_backup_instances"],
            summary["backup_instances_recovery_points_read"]) == (1, 1, 1)
    assert (summary["not_included_backup_vaults"], summary["not_included_backup_instances"]) == (1, 2)
    assert [p for p in session.paths if p.endswith("/recoveryPoints")] == [
        urlparse(f"https://x{CONTOSO}/backupInstances/bi-app/recoveryPoints").path]


def test_a_vault_named_by_an_inclusion_keeps_only_backups_of_included_resources(monkeypatch, tmp_path):
    monkeypatch.setenv(INCLUSIONS_ENV, "id:*/backupVaults/bv-contoso")
    code, evidence, _ = run_backups(monkeypatch, tmp_path, None)
    assert code == 0
    assert _in_scope(evidence) == {"bv-contoso": []}
    assert evidence["summary"]["vaults_without_backup_instances"] == 1


def test_an_exclusion_of_the_backup_or_its_vault_still_wins(monkeypatch, tmp_path):
    monkeypatch.setattr(tag_index, "TagIndex", DiskAppTagged)
    monkeypatch.setenv(INCLUSIONS_ENV, "tag:Boundary=FedRAMP")
    _, evidence, _ = run_backups(monkeypatch, tmp_path, "id:*/backupInstances/bi-app")
    assert ("backup_instance", "bi-app", "id:*/backupInstances/bi-app") in _out(evidence)
    assert _in_scope(evidence) == {}
    (tmp_path / "vault").mkdir()
    _, evidence, session = run_backups(monkeypatch, tmp_path / "vault", "id:*/backupVaults/bv-contoso")
    assert ("backup_vault", "bv-contoso", "id:*/backupVaults/bv-contoso") in _out(evidence)
    assert not any("bv-contoso/" in p for p in session.paths)


def test_a_vault_no_inclusion_names_stays_when_its_backups_couldnt_be_listed(monkeypatch, tmp_path):
    monkeypatch.setattr(tag_index, "TagIndex", DiskAppTagged)
    monkeypatch.setenv(INCLUSIONS_ENV, "tag:Boundary=FedRAMP")
    code, evidence, _ = run_backups(monkeypatch, tmp_path, None, refused=("bv-example/backupInstances",))
    assert code == 1
    assert _in_scope(evidence) == {"bv-contoso": ["bi-app"], "bv-example": []}
    summary = evidence["summary"]
    assert summary["total_backup_instances"] is None and summary["resource_inclusion_patterns_unmatched"] is None


def test_a_failed_tag_read_writes_no_evidence_and_fails_the_run(monkeypatch, tmp_path):
    def broken(sub):
        raise PermissionError("(AuthorizationFailed) (403) no read on Microsoft.ResourceGraph")

    monkeypatch.setattr(tag_index, "TagIndex", lambda: TagIndex(broken))
    monkeypatch.setenv(INCLUSIONS_ENV, "tag:Boundary=FedRAMP")
    _serve(monkeypatch, tmp_path, None)
    assert bv.main() == 1
    assert list(tmp_path.glob("azure_*.json")) == []
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
