"""resource_exclusions in azure_resource_locks and azure_policy_assignments, through run_* harnesses the cross-adopter
inclusion tests also drive. Synthetic payloads, no network."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_locks_policy_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rl = _load("resource_locks")
pa = _load("policy_assignments")
azure_rest = sys.modules["azure_rest"]

SUB = "/subscriptions/s1"
RG_APP, RG_OUT = f"{SUB}/resourceGroups/rg-app", f"{SUB}/resourceGroups/rg-out"
KV_APP = f"{RG_APP}/providers/Microsoft.KeyVault/vaults/kv-app"
KV_OUT = f"{RG_OUT}/providers/Microsoft.KeyVault/vaults/kv-out"


def _patterns(monkeypatch, patterns):
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


# --- resource_locks ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


def _lock(scope, name):
    return {"id": f"{scope}/providers/Microsoft.Authorization/locks/{name}", "name": name,
            "properties": {"level": "CanNotDelete", "notes": None, "owners": []}}


class _LocksArm:
    def get(self, url, params=None, headers=None, timeout=None):
        path = urlparse(url).path
        if path.endswith("/providers/Microsoft.Authorization/locks"):
            return _Resp(200, {"value": [_lock(KV_APP, "kv-app-lock"), _lock(RG_OUT, "rg-out-lock")]})
        if path.endswith("/resources"):
            return _Resp(200, {"value": [{"id": rid, "name": rid.rsplit("/", 1)[-1], "type": "Microsoft.KeyVault/vaults",
                                          "location": "regionwest"} for rid in (KV_APP, KV_OUT)]})
        if path.endswith("/resourcegroups"):
            return _Resp(200, {"value": [{"name": "rg-app"}, {"name": "rg-out"}]})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


def run_locks(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr("requests.Session", _LocksArm)
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: type("C", (), {
        "get_token": lambda s, *a: namedtuple("T", "token expires_on")("tok", 9_999_999_999)})())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    for env, value in (("AZURE_SUBSCRIPTION_ID", "s1"), ("EVIDENCE_DIR", str(tmp_path)),
                       ("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))):
        monkeypatch.setenv(env, value)
    for env in ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", rl.PROTECTED_TYPES_ENV):
        monkeypatch.delenv(env, raising=False)
    _patterns(monkeypatch, patterns)
    code = rl.main()
    return code, json.loads((tmp_path / "azure_resource_locks_s1.json").read_text())


def test_locks_rg_out_takes_out_its_resources_but_not_its_lock(monkeypatch, tmp_path):
    code, evidence = run_locks(monkeypatch, tmp_path, "rg:rg-out")
    assert code == 0
    assert [r["name"] for r in evidence["results"]["protected_resources"]] == ["kv-app"]
    assert [(e["kind"], e["name"], e["pattern"]) for e in evidence["results"]["excluded"]] == [
        ("resource", "kv-out", "rg:rg-out")]
    assert (evidence["summary"]["in_scope_resources"], evidence["summary"]["excluded_resources"]) == (1, 1)


# --- policy_assignments ---

EXEMPT = "/providers/Microsoft.Authorization/policyExemptions"


def _exemption(scope, name):
    return pa.project_policy_exemption({
        "id": f"{scope}{EXEMPT}/{name}", "name": name, "type": "Microsoft.Authorization/policyExemptions",
        "properties": {"policyAssignmentId": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/a1",
                       "policyDefinitionReferenceIds": [], "exemptionCategory": "Waiver", "displayName": name,
                       "description": "approved", "expiresOn": None, "metadata": {}},
        "systemData": {"createdBy": "user@example.com", "createdByType": "User", "createdAt": "2026-05-01T00:00:00Z"},
    })


def run_policy_assignments(monkeypatch, tmp_path, patterns):
    exemptions = [_exemption(KV_APP, "e-app"), _exemption(RG_OUT, "e-rg-out"), _exemption(KV_OUT, "e-kv-out")]
    monkeypatch.setattr(pa, "load_dotenv", lambda: None)
    monkeypatch.setattr(pa, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(pa, "credential", lambda: object())
    monkeypatch.setattr(pa, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(pa, "collect_policy_assignments", lambda sub, cred, collector: [])
    monkeypatch.setattr(pa, "collect_policy_exemptions", lambda sub, cred, collector: (exemptions, pa.EXEMPTIONS_READ))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    _patterns(monkeypatch, patterns)
    code = pa.main()
    return code, json.loads((tmp_path / "azure_policy_assignments_s1.json").read_text())


def test_policy_exemptions_leave_with_the_scope_they_were_made_at(monkeypatch, tmp_path):
    code, evidence = run_policy_assignments(monkeypatch, tmp_path, "rg:rg-out")
    assert code == 0
    assert [e["name"] for e in evidence["results"]["policy_exemptions"]] == ["e-app"]
    assert sorted(e["name"] for e in evidence["results"]["excluded"]) == ["e-kv-out", "e-rg-out"]
