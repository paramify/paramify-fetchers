"""resource_exclusions in the compute, container and app-platform fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
ADDED = ("resource_exclusion_patterns", "resource_exclusion_patterns_unmatched")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_compute_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


aks = _load("aks_cluster_configuration")
acr = _load("container_registry_configuration")
workloads = _load("container_workloads_configuration")
functions = _load("function_app_configuration")
vms = _load("vm_hardening_status")
disks = _load("disk_encryption_status")
apim = _load("api_management_configuration")
identities = _load("managed_identity_configuration")


def _fake_module(monkeypatch, name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)


def _run(m, monkeypatch, tmp_path, patterns, filename):
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)
    code = m.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _added(summary: dict) -> dict:
    return {k: v for k, v in summary.items() if k.startswith(ADDED) or k.startswith(("excluded_", "in_scope_"))}


def _rest(summary: dict) -> dict:
    return {k: v for k, v in summary.items() if k not in _added(summary)}


def _excluded(evidence) -> list:
    return sorted((e["kind"], e["name"], e["pattern"], e["reason"]) for e in evidence["results"]["excluded"])


def _refuse(monkeypatch, m, operation):
    """Answers one guarded call with a 403, as Azure does for a list the identity may not read."""
    class Refusing(m.Collector):
        def guard(self, op, fn, default=None):
            if op == operation:
                self.record(op, PermissionError("(AuthorizationFailed) 403"))
                return default
            return super().guard(op, fn, default)

    monkeypatch.setattr(m, "Collector", Refusing)


def _empty(*kinds_and_totals) -> dict:
    """The fields a run without patterns adds: (plural, total) pairs."""
    out: dict = {"resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": []}
    for plural, _ in kinds_and_totals:
        out[f"excluded_{plural}"] = 0
    for plural, total in kinds_and_totals:
        out[f"in_scope_{plural}"] = total
    return out


# --- aks_cluster_configuration ---

def _cluster(rg, name, location="regionwest", private=False):
    profile = NS(enable_private_cluster=True) if private else None
    return NS(id=f"{SUB}/resourceGroups/{rg}/providers/Microsoft.ContainerService/managedClusters/{name}", name=name,
              location=location, api_server_access_profile=profile,
              agent_pool_profiles=[NS(name="pool1"), NS(name="pool2")])


def run_aks(monkeypatch, tmp_path, patterns):
    clusters = [_cluster("rg-in", "aks-in"), _cluster("rg-out", "aks-out", private=True),
                _cluster("rg-in", "aks-east", "regioneast", private=True)]
    client = NS(managed_clusters=NS(list=lambda: clusters))
    _fake_module(monkeypatch, "azure.mgmt.containerservice", ContainerServiceClient=lambda **k: client)
    return _run(aks, monkeypatch, tmp_path, patterns, "azure_aks_cluster_configuration")


def test_aks_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_aks(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert _added(summary) == _empty(("clusters", 3))
    assert _rest(summary) == {**aks.summarize(evidence["results"]["clusters"]), "provider_registration_status": "registered"}
    assert summary["private_clusters"] == 2 and summary["total_agent_pools"] == 6


def test_aks_excludes_by_group_and_region_and_recounts(monkeypatch, tmp_path):
    code, evidence = run_aks(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary = evidence["summary"]
    assert code == 0
    assert [c["name"] for c in evidence["results"]["clusters"]] == ["aks-in"]
    assert _excluded(evidence) == [("cluster", "aks-east", "location:regioneast", "resource_matched"),
                                   ("cluster", "aks-out", "rg:rg-out", "resource_matched")]
    assert (summary["total_clusters"], summary["private_clusters"], summary["total_agent_pools"]) == (1, 0, 2)
    assert summary["private_cluster_percentage"] == 0
    assert (summary["excluded_clusters"], summary["in_scope_clusters"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_aks_id_pattern_takes_out_one_cluster(monkeypatch, tmp_path):
    _, evidence = run_aks(monkeypatch, tmp_path, f"id:{_cluster('rg-in', 'aks-in').id}")
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["aks-in"]
    assert evidence["summary"]["in_scope_clusters"] == 2


# --- container_registry_configuration ---

def _registry(rg, name, location="regionwest", admin=False):
    return NS(id=f"{SUB}/resourceGroups/{rg}/providers/Microsoft.ContainerRegistry/registries/{name}", name=name,
              location=location, admin_user_enabled=admin, sku=NS(name="Premium"))


def run_acr(monkeypatch, tmp_path, patterns):
    registries = [_registry("rg-in", "acr-in"), _registry("rg-out", "acr-out", admin=True),
                  _registry("rg-in", "acr-east", "regioneast", admin=True)]
    reads: list = []
    client = NS(registries=NS(list=lambda: registries))
    monitor = NS(diagnostic_settings=NS(list=lambda resource_uri: reads.append(resource_uri) or []))
    _fake_module(monkeypatch, "azure.mgmt.containerregistry", ContainerRegistryManagementClient=lambda **k: client)
    _fake_module(monkeypatch, "azure.mgmt.monitor", MonitorManagementClient=lambda **k: monitor)
    code, evidence = _run(acr, monkeypatch, tmp_path, patterns, "azure_container_registry_configuration")
    return code, evidence, reads


def test_acr_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path, assert_summary_documented):
    code, evidence, _ = run_acr(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert_summary_documented("azure/container_registry_configuration", evidence["summary"])
    assert _added(summary) == _empty(("registries", 3))
    assert _rest(summary) == {**acr.summarize(evidence["results"]["registries"]), "provider_registration_status": "registered"}
    assert summary["admin_user_enabled_registries"] == 2


def test_acr_excludes_by_group_and_region_and_skips_their_reads(monkeypatch, tmp_path):
    code, evidence, reads = run_acr(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary = evidence["summary"]
    assert code == 0
    assert [r["name"] for r in evidence["results"]["registries"]] == ["acr-in"]
    assert _excluded(evidence) == [("registry", "acr-east", "location:regioneast", "resource_matched"),
                                   ("registry", "acr-out", "rg:rg-out", "resource_matched")]
    assert (summary["total_registries"], summary["admin_user_enabled_registries"]) == (1, 0)
    assert (summary["excluded_registries"], summary["in_scope_registries"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert len(reads) == 1 and reads[0].endswith("acr-in")


# --- container_workloads_configuration ---

APP = "providers/Microsoft.App"
ENV_IN = f"{IN_RG}/{APP}/managedEnvironments/env-in"
ENV_OUT = f"{OUT_RG}/{APP}/managedEnvironments/env-out"


def _env(rg, name, location="regionwest", internal=False):
    return NS(id=f"{SUB}/resourceGroups/{rg}/{APP}/managedEnvironments/{name}", name=name, location=location,
              vnet_configuration=NS(internal=internal, infrastructure_subnet_id="sn"),
              app_logs_configuration=NS(destination="log-analytics"))


def _workload(rg, name, env_id, location="regionwest", external=True, kind="containerApps"):
    config = NS(ingress=NS(external=external)) if kind == "containerApps" else NS(trigger_type="Manual")
    return NS(id=f"{SUB}/resourceGroups/{rg}/{APP}/{kind}/{name}", name=name, location=location, environment_id=env_id,
              configuration=config)


def _group(rg, name, location="regionwest", public=True):
    ip = NS(type="Public" if public else "Private")
    return NS(id=f"{SUB}/resourceGroups/{rg}/providers/Microsoft.ContainerInstance/containerGroups/{name}", name=name,
              location=location, ip_address=ip)


def run_workloads(monkeypatch, tmp_path, patterns, extra_envs=(), extra_apps=()):
    environments = [_env("rg-in", "env-in"), _env("rg-out", "env-out"), *extra_envs]
    apps = [_workload("rg-in", "app-in", ENV_IN), _workload("rg-in", "app-east", ENV_IN, "regioneast"),
            _workload("rg-in", "app-moved", ENV_OUT), _workload("rg-out", "app-out", ENV_IN), *extra_apps]
    jobs = [_workload("rg-in", "job-in", ENV_IN, kind="jobs"), _workload("rg-in", "job-moved", ENV_OUT, kind="jobs")]
    groups = [_group("rg-in", "cg-in"), _group("rg-out", "cg-out"), _group("rg-in", "cg-east", "regioneast")]
    auth_reads: list = []
    apps_client = NS(
        managed_environments=NS(list_by_subscription=lambda: environments),
        container_apps=NS(list_by_subscription=lambda: apps),
        jobs=NS(list_by_subscription=lambda: jobs),
        container_apps_auth_configs=NS(list_by_container_app=lambda rg, name: auth_reads.append(name) or []))
    aci = NS(container_groups=NS(list=lambda: groups))
    _fake_module(monkeypatch, "azure.mgmt.appcontainers", ContainerAppsAPIClient=lambda **k: apps_client)
    _fake_module(monkeypatch, "azure.mgmt.containerinstance", ContainerInstanceManagementClient=lambda **k: aci)
    diag_reads: list = []
    monkeypatch.setattr(workloads, "monitor_client", lambda sub, cred: "monitor")
    monkeypatch.setattr(workloads, "list_diagnostic_settings", lambda monitor, rid: diag_reads.append(rid) or [])
    code, evidence = _run(workloads, monkeypatch, tmp_path, patterns, "azure_container_workloads_configuration")
    return code, evidence, auth_reads, diag_reads


def test_workloads_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path, assert_summary_documented):
    code, evidence, _, _ = run_workloads(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert_summary_documented("azure/container_workloads_configuration", evidence["summary"])
    assert _added(summary) == {
        "resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
        "excluded_environments": 0, "excluded_container_apps": 0, "excluded_jobs": 0, "excluded_container_groups": 0,
        "in_scope_environments": 2, "in_scope_container_apps": 4, "in_scope_jobs": 2, "in_scope_container_groups": 3}
    expected = workloads.summarize(results["environments"], results["container_apps"], results["jobs"],
                                   results["container_groups"])
    assert _rest(summary) == {**expected, **{k: v for k, v in summary.items() if k.startswith("provider_registration")}}
    assert (summary["total_container_apps"], summary["container_groups_public_ip"]) == (4, 3)


def test_workloads_exclude_by_group_and_region_and_skip_their_reads(monkeypatch, tmp_path):
    code, evidence, auth_reads, diag_reads = run_workloads(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [e["name"] for e in results["environments"]] == ["env-in"]
    assert [a["name"] for a in results["container_apps"]] == ["app-in"]
    assert [j["name"] for j in results["jobs"]] == ["job-in"]
    assert [g["name"] for g in results["container_groups"]] == ["cg-in"]
    assert _excluded(evidence) == [
        ("container_app", "app-east", "location:regioneast", "resource_matched"),
        ("container_app", "app-moved", "rg:rg-out", "environment_matched"),
        ("container_app", "app-out", "rg:rg-out", "resource_matched"),
        ("container_group", "cg-east", "location:regioneast", "resource_matched"),
        ("container_group", "cg-out", "rg:rg-out", "resource_matched"),
        ("environment", "env-out", "rg:rg-out", "resource_matched"),
        ("job", "job-moved", "rg:rg-out", "environment_matched")]
    moved = next(e for e in results["excluded"] if e["name"] == "app-moved")
    assert moved["matched_id"] == ENV_OUT and moved["id"].endswith("containerApps/app-moved")
    assert (summary["total_environments"], summary["total_container_apps"], summary["total_jobs"],
            summary["total_container_groups"]) == (1, 1, 1, 1)
    assert (summary["excluded_environments"], summary["excluded_container_apps"], summary["excluded_jobs"],
            summary["excluded_container_groups"]) == (1, 3, 1, 2)
    assert summary["container_apps_internet_facing"] == 1
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert auth_reads == ["app-in"]
    assert sorted(d.rsplit("/", 1)[-1] for d in diag_reads) == ["cg-in", "env-in"]


def test_workloads_app_leaves_with_an_environment_named_by_id(monkeypatch, tmp_path):
    _, evidence, _, _ = run_workloads(monkeypatch, tmp_path, f"id:{ENV_IN}")
    entries = {e["name"]: e for e in evidence["results"]["excluded"]}
    assert sorted(entries) == ["app-east", "app-in", "app-out", "env-in", "job-in"]
    assert entries["app-in"]["reason"] == "environment_matched" and entries["app-in"]["matched_id"] == ENV_IN
    assert entries["app-in"]["pattern"] == entries["env-in"]["pattern"] == f"id:{ENV_IN}"
    assert [a["name"] for a in evidence["results"]["container_apps"]] == ["app-moved"]


# --- function_app_configuration ---

def _site(rg, name, location="regionwest", public=None):
    return NS(id=f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{name}", name=name, location=location,
              kind="functionapp,linux", public_network_access=public)


def run_functions(monkeypatch, tmp_path, patterns):
    sites = [_site("rg-in", "fn-in"), _site("rg-out", "fn-out"), _site("rg-in", "fn-east", "regioneast"),
             _site("rg-in", "web-site", public="Disabled")]
    sites[3].kind = "app"
    reads: list = []

    def call(what):
        return lambda resource_group_name, name: reads.append((what, name)) or NS(properties={}, master_key=None)

    client = NS(web_apps=NS(list=lambda: sites, get_configuration=call("config"), list_host_keys=call("keys"),
                            list_application_settings=call("settings")))
    _fake_module(monkeypatch, "azure.mgmt.web", WebSiteManagementClient=lambda **k: client)
    code, evidence = _run(functions, monkeypatch, tmp_path, patterns, "azure_function_app_configuration")
    return code, evidence, reads


def test_functions_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path, assert_summary_documented):
    code, evidence, _ = run_functions(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert_summary_documented("azure/function_app_configuration", evidence["summary"])
    assert _added(summary) == _empty(("function_apps", 3))
    assert _rest(summary) == {**functions.summarize(evidence["results"]["function_apps"]),
                              "provider_registration_status": "registered"}
    assert summary["total_function_apps"] == 3


def test_functions_exclude_by_group_and_region_and_skip_their_reads(monkeypatch, tmp_path):
    code, evidence, reads = run_functions(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary = evidence["summary"]
    assert code == 0
    assert [a["name"] for a in evidence["results"]["function_apps"]] == ["fn-in"]
    assert _excluded(evidence) == [("function_app", "fn-east", "location:regioneast", "resource_matched"),
                                   ("function_app", "fn-out", "rg:rg-out", "resource_matched")]
    assert (summary["total_function_apps"], summary["excluded_function_apps"], summary["in_scope_function_apps"]) == (1, 2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert {name for _, name in reads} == {"fn-in"}


def test_functions_slots_are_not_listed_so_a_slot_pattern_matches_nothing(monkeypatch, tmp_path):
    _, evidence, _ = run_functions(monkeypatch, tmp_path, f"id:{_site('rg-in', 'fn-in').id}/slots/*")
    assert evidence["results"]["excluded"] == []
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] == [f"id:{_site('rg-in', 'fn-in').id}/slots/*"]


# --- vm_hardening_status ---

COMPUTE = "providers/Microsoft.Compute"


def _vm(rg, name, location="regionwest", trusted=False):
    profile = NS(encryption_at_host=True) if trusted else None
    return NS(id=f"{SUB}/resourceGroups/{rg}/{COMPUTE}/virtualMachines/{name}", name=name, location=location,
              security_profile=profile)


def _scale_set(rg, name, location="regionwest"):
    return NS(id=f"{SUB}/resourceGroups/{rg}/{COMPUTE}/virtualMachineScaleSets/{name}", name=name, location=location)


def run_vms(monkeypatch, tmp_path, patterns, extra=()):
    machines = [_vm("rg-in", "vm-in"), _vm("rg-out", "vm-out", trusted=True),
                _vm("rg-in", "vm-east", "regioneast", trusted=True), *extra]
    sets = [_scale_set("rg-in", "vmss-in"), _scale_set("rg-out", "vmss-out"), _scale_set("rg-in", "vmss-east", "regioneast")]
    reads: list = []
    client = NS(
        virtual_machines=NS(list_all=lambda: machines),
        virtual_machine_extensions=NS(list=lambda rg, name: reads.append(name) or NS(value=[])),
        virtual_machine_scale_sets=NS(list_all=lambda: sets),
        virtual_machine_scale_set_vms=NS(list=lambda rg, name: reads.append(name) or []))
    _fake_module(monkeypatch, "azure.mgmt.compute", ComputeManagementClient=lambda **k: client)
    code, evidence = _run(vms, monkeypatch, tmp_path, patterns, "azure_vm_hardening_status")
    return code, evidence, reads


def test_vms_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, _ = run_vms(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert _added(summary) == _empty(("virtual_machines", 3), ("scale_sets", 3))
    assert _rest(summary) == {**vms.summarize(results["virtual_machines"], results["virtual_machine_scale_sets"]),
                              "provider_registration_status": "registered"}
    assert summary["encryption_at_host_vms"] == 2


def test_vms_exclude_by_group_and_region_and_recount(monkeypatch, tmp_path):
    code, evidence, reads = run_vms(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [v["name"] for v in results["virtual_machines"]] == ["vm-in"]
    assert [s["name"] for s in results["virtual_machine_scale_sets"]] == ["vmss-in"]
    assert _excluded(evidence) == [
        ("scale_set", "vmss-east", "location:regioneast", "resource_matched"),
        ("scale_set", "vmss-out", "rg:rg-out", "resource_matched"),
        ("virtual_machine", "vm-east", "location:regioneast", "resource_matched"),
        ("virtual_machine", "vm-out", "rg:rg-out", "resource_matched")]
    assert (summary["total_virtual_machines"], summary["encryption_at_host_vms"], summary["total_scale_sets"]) == (1, 0, 1)
    assert (summary["excluded_virtual_machines"], summary["excluded_scale_sets"]) == (2, 2)
    assert (summary["in_scope_virtual_machines"], summary["in_scope_scale_sets"]) == (1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert sorted(reads) == ["vm-in", "vmss-in"]


def test_vms_id_pattern_takes_out_one_machine(monkeypatch, tmp_path):
    _, evidence, _ = run_vms(monkeypatch, tmp_path, f"id:{_vm('rg-in', 'vm-in').id}")
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["vm-in"]
    assert evidence["summary"]["in_scope_virtual_machines"] == 2


def test_vms_a_scale_set_member_leaves_with_its_scale_set_from_another_group(monkeypatch, tmp_path):
    vmss_out = _scale_set("rg-out", "vmss-out").id
    member, outsider = _vm("rg-in", "vm-member"), _vm("rg-in", "vm-other-set")
    member.virtual_machine_scale_set = NS(id=vmss_out)
    outsider.virtual_machine_scale_set = NS(id=_scale_set("rg-in", "vmss-in").id)
    _, evidence, reads = run_vms(monkeypatch, tmp_path, f"id:{vmss_out}", extra=[member, outsider])
    out = {e["name"]: e for e in evidence["results"]["excluded"]}
    assert set(out) == {"vmss-out", "vm-member"}
    assert (out["vm-member"]["reason"], out["vm-member"]["pattern"], out["vm-member"]["matched_id"]) == (
        "scale_set_matched", f"id:{vmss_out}", vmss_out)
    assert "vm-member" not in reads and "vm-other-set" in reads
    assert (evidence["summary"]["vms_in_scale_sets"], evidence["summary"]["excluded_virtual_machines"]) == (1, 1)


def test_workloads_an_excluded_environment_without_an_id_takes_no_app_without_one(monkeypatch, tmp_path):
    env = _env("rg-in", "env-no-id", "regioneast")
    env.id = None
    extra = dict(extra_envs=[env], extra_apps=[_workload("rg-in", "app-no-env", None)])
    _, evidence, _, _ = run_workloads(monkeypatch, tmp_path, "location:regioneast", **extra)
    assert ("environment", "env-no-id") in {(e["kind"], e["name"]) for e in evidence["results"]["excluded"]}
    assert "app-no-env" in [a["name"] for a in evidence["results"]["container_apps"]]


# --- disk_encryption_status ---

DES = f"{OUT_RG}/{COMPUTE}/diskEncryptionSets/des-out"


def _disk(rg, name, location="regionwest", encryption=None, des=None):
    enc = NS(type=encryption, disk_encryption_set_id=des) if encryption else None
    return NS(id=f"{SUB}/resourceGroups/{rg}/{COMPUTE}/disks/{name}", name=name, location=location, encryption=enc)


def run_disks(monkeypatch, tmp_path, patterns):
    cmk = "EncryptionAtRestWithCustomerKey"
    managed = [_disk("rg-in", "disk-in", encryption=cmk, des=DES), _disk("rg-out", "disk-out", encryption=cmk, des=DES),
               _disk("rg-in", "disk-east", "regioneast"), _disk("rg-in", "disk-plain")]
    client = NS(disks=NS(list=lambda: managed))
    _fake_module(monkeypatch, "azure.mgmt.compute", ComputeManagementClient=lambda **k: client)
    return _run(disks, monkeypatch, tmp_path, patterns, "azure_disk_encryption_status")


def test_disks_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_disks(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert _added(summary) == _empty(("disks", 4))
    assert _rest(summary) == {**disks.summarize(evidence["results"]["disks"]), "provider_registration_status": "registered"}
    assert (summary["total_disks"], summary["customer_managed_key_disks"]) == (4, 2)


def test_disks_exclude_by_group_and_region_and_keep_the_encryption_set_reference(monkeypatch, tmp_path):
    code, evidence = run_disks(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary = evidence["summary"]
    assert code == 0
    assert sorted(d["name"] for d in evidence["results"]["disks"]) == ["disk-in", "disk-plain"]
    assert _excluded(evidence) == [("disk", "disk-east", "location:regioneast", "resource_matched"),
                                   ("disk", "disk-out", "rg:rg-out", "resource_matched")]
    assert (summary["total_disks"], summary["customer_managed_key_disks"], summary["cmk_percentage"]) == (2, 1, 50)
    assert (summary["excluded_disks"], summary["in_scope_disks"]) == (2, 2)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    in_scope = next(d for d in evidence["results"]["disks"] if d["name"] == "disk-in")
    assert in_scope["customer_managed_key"] is True and in_scope["disk_encryption_set_id"] == DES


def test_disks_id_pattern_takes_out_one_disk(monkeypatch, tmp_path):
    _, evidence = run_disks(monkeypatch, tmp_path, f"id:{_disk('rg-in', 'disk-plain').id}")
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["disk-plain"]
    assert evidence["summary"]["in_scope_disks"] == 3


# --- api_management_configuration ---

APIM = "providers/Microsoft.ApiManagement/service"


def _service(rg, name, location="regionwest", apis=1, public="Enabled"):
    return NS(id=f"{SUB}/resourceGroups/{rg}/{APIM}/{name}", name=name, location=location, public_network_access=public,
              api_count=apis)


def run_apim(monkeypatch, tmp_path, patterns):
    services = [_service("rg-in", "apim-in", public="Disabled"), _service("rg-out", "apim-out", apis=3),
                _service("rg-in", "apim-east", "regioneast", apis=2)]
    client = NS(api_management_service=NS(list=lambda: services))
    _fake_module(monkeypatch, "azure.mgmt.apimanagement", ApiManagementClient=lambda **k: client)
    _fake_module(monkeypatch, "azure.mgmt.monitor", MonitorManagementClient=lambda **k: NS(diagnostic_settings=NS(list=lambda **kw: [])))
    reads: list = []
    counts = {s.name: s.api_count for s in services}

    def collect_service(client, monitor, service, collector, now):
        reads.append(service["name"])
        apis = [{"name": f"api{i}", "access_control": True, "accepts_http": False} for i in range(counts[service["name"]])]
        empty = dict.fromkeys(("products", "subscriptions", "backends", "named_values", "certificates"), [])
        return {**service, **empty, "apis": apis, "audit_logs_exported": None, "diagnostic_settings": None,
                "developer_portal_sign_up": None}

    monkeypatch.setattr(apim, "collect_service", collect_service)
    monkeypatch.setattr(apim, "monitor_client", lambda sub, cred: "monitor")
    code, evidence = _run(apim, monkeypatch, tmp_path, patterns, "azure_api_management_configuration")
    return code, evidence, reads


def test_apim_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path, assert_summary_documented):
    code, evidence, _ = run_apim(monkeypatch, tmp_path, None)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    assert_summary_documented("azure/api_management_configuration", evidence["summary"])
    assert _added(summary) == _empty(("services", 3))
    assert _rest(summary) == {**apim.summarize(evidence["results"]["services"]), "provider_registration_status": "registered"}
    assert (summary["total_services"], summary["total_apis"]) == (3, 6)


def test_apim_exclude_by_group_and_region_and_apis_follow_the_service(monkeypatch, tmp_path):
    code, evidence, reads = run_apim(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary = evidence["summary"]
    assert code == 0
    assert [s["name"] for s in evidence["results"]["services"]] == ["apim-in"]
    assert _excluded(evidence) == [("service", "apim-east", "location:regioneast", "resource_matched"),
                                   ("service", "apim-out", "rg:rg-out", "resource_matched")]
    assert (summary["total_services"], summary["total_apis"]) == (1, 1)
    assert (summary["excluded_services"], summary["in_scope_services"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert reads == ["apim-in"]


def test_apim_id_pattern_takes_out_one_service(monkeypatch, tmp_path):
    _, evidence, reads = run_apim(monkeypatch, tmp_path, f"id:{_service('rg-in', 'apim-in').id}")
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["apim-in"]
    assert sorted(reads) == ["apim-east", "apim-out"]


# --- managed_identity_configuration ---

MSI = "providers/Microsoft.ManagedIdentity/userAssignedIdentities"
VM_IN = f"{IN_RG}/{COMPUTE}/virtualMachines/vm-in"
VM_OUT = f"{OUT_RG}/{COMPUTE}/virtualMachines/vm-out"
VM_EAST = f"{IN_RG}/{COMPUTE}/virtualMachines/vm-east"


def _uai(rg, name, location="regionwest", principal=None):
    return NS(id=f"{SUB}/resourceGroups/{rg}/{MSI}/{name}", name=name, location=location, tags=None,
              principal_id=principal or f"p-{name}", client_id="c", isolation_scope=None)


def _holder(resource_id, principal, location="regionwest", uai=()):
    kind = "SystemAssigned, UserAssigned" if uai else "SystemAssigned"
    return {"id": resource_id, "name": resource_id.rsplit("/", 1)[-1], "type": "microsoft.compute/virtualmachines",
            "location": location,
            "identity": {"type": kind, "principalId": principal, "userAssignedIdentities": {u: {} for u in uai}}}


def run_identities(monkeypatch, tmp_path, patterns, extra_assignments=(), extra_users=()):
    users = [_uai("rg-in", "id-in"), _uai("rg-out", "id-out"), _uai("rg-in", "id-east", "regioneast"), *extra_users]
    rows = [_holder(VM_IN, "ps-in", uai=[users[0].id.lower()]), _holder(VM_OUT, "ps-out", uai=[users[0].id.lower()]),
            _holder(VM_EAST, "ps-east", "regioneast")]
    msi = NS(user_assigned_identities=NS(list_by_subscription=lambda: users))
    # id-in holds a Reader assignment at the excluded group's scope: its own access, still listed.
    assignment = NS(principal_id="p-id-in", role_definition_id="/x/roles/r1", scope=OUT_RG, condition=None)
    authorization = NS(role_definitions=NS(list=lambda scope: [NS(id="/x/roles/r1", role_name="Reader", permissions=[])]),
                       role_assignments=NS(list_for_subscription=lambda: [assignment, *extra_assignments]))
    _fake_module(monkeypatch, "azure.mgmt.msi", ManagedServiceIdentityClient=lambda **k: msi)
    _fake_module(monkeypatch, "azure.mgmt.authorization", AuthorizationManagementClient=lambda **k: authorization)
    monkeypatch.setattr(identities, "arm_rest_client", lambda cred: "rest")
    monkeypatch.setattr(identities, "resource_graph_client", lambda cred: "graph")
    monkeypatch.setattr(identities, "query_all", lambda client, sub, query: {"rows": rows, "total_records": 3, "pages": 1})
    fic_reads: list = []
    monkeypatch.setattr(identities, "list_federated_credentials", lambda rest, identity_id: fic_reads.append(identity_id) or [])
    graph_reads: list = []

    async def read_graph_roles(collector, cred, principal_ids):
        graph_reads.extend(principal_ids)
        return {}, "read"

    monkeypatch.setattr(identities, "read_graph_roles", read_graph_roles)
    code, evidence = _run(identities, monkeypatch, tmp_path, patterns, "azure_managed_identity_configuration")
    return code, evidence, fic_reads, graph_reads


def test_identities_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, _, _ = run_identities(monkeypatch, tmp_path, None)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert _added(summary) == {
        "resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
        "excluded_user_assigned_identities": 0, "excluded_system_assigned_identities": 0,
        "in_scope_user_assigned_identities": 3, "in_scope_system_assigned_identities": 3}
    expected = identities.summarize(results["user_assigned_identities"], results["system_assigned_identities"],
                                    summary["graph_access"])
    assert _rest(summary) == {**expected, "provider_registration_status": "registered"}
    assert summary["total_identities"] == 6


def test_identities_exclude_by_group_and_region_and_system_identities_follow_their_resource(monkeypatch, tmp_path):
    code, evidence, fic_reads, graph_reads = run_identities(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [i["name"] for i in results["user_assigned_identities"]] == ["id-in"]
    assert [i["resource_name"] for i in results["system_assigned_identities"]] == ["vm-in"]
    assert _excluded(evidence) == [
        ("system_assigned_identity", "vm-east", "location:regioneast", "resource_matched"),
        ("system_assigned_identity", "vm-out", "rg:rg-out", "resource_matched"),
        ("user_assigned_identity", "id-east", "location:regioneast", "resource_matched"),
        ("user_assigned_identity", "id-out", "rg:rg-out", "resource_matched")]
    assert (summary["total_user_assigned_identities"], summary["total_system_assigned_identities"]) == (1, 1)
    assert (summary["excluded_user_assigned_identities"], summary["excluded_system_assigned_identities"]) == (2, 2)
    assert (summary["in_scope_user_assigned_identities"], summary["in_scope_system_assigned_identities"]) == (1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert fic_reads == [_uai("rg-in", "id-in").id]
    assert sorted(graph_reads) == ["p-id-in", "ps-in"]


def test_identities_in_scope_identity_keeps_roles_at_an_excluded_scope_and_attachments(monkeypatch, tmp_path):
    _, plain, _, _ = run_identities(monkeypatch, tmp_path, None)
    _, evidence, _, _ = run_identities(monkeypatch, tmp_path, "rg:rg-out")
    [identity] = [i for i in evidence["results"]["user_assigned_identities"] if i["name"] == "id-in"]
    [before] = [i for i in plain["results"]["user_assigned_identities"] if i["name"] == "id-in"]
    assert identity == before
    assert [r["scope"] for r in identity["role_assignments"]] == [OUT_RG]
    assert sorted(r["resource_id"] for r in identity["attached_resources"]) == [VM_IN, VM_OUT]


def test_identities_system_identity_matches_by_resource_id(monkeypatch, tmp_path):
    _, evidence, _, _ = run_identities(monkeypatch, tmp_path, f"id:{VM_IN}")
    assert [(e["kind"], e["name"], e["id"]) for e in evidence["results"]["excluded"]] == [
        ("system_assigned_identity", "vm-in", VM_IN)]
    assert evidence["summary"]["in_scope_system_assigned_identities"] == 2


def test_identities_a_matched_identity_holding_an_in_scope_role_stays_in_scope(monkeypatch, tmp_path):
    def grant(principal, scope):
        return NS(principal_id=principal, role_definition_id="/x/roles/r1", scope=scope, condition=None)

    # id-out reaches an in-scope group and vm-out's identity the subscription; id-east holds a role only in the
    # excluded group, so it still leaves.
    extra = [grant("p-id-out", IN_RG), grant("ps-out", SUB), grant("p-id-east", OUT_RG)]
    code, evidence, fic_reads, graph_reads = run_identities(
        monkeypatch, tmp_path, "rg:rg-out, location:regioneast", extra)
    results, summary = evidence["results"], evidence["summary"]
    assert code == 0
    assert sorted(i["name"] for i in results["user_assigned_identities"]) == ["id-in", "id-out"]
    assert sorted(i["resource_name"] for i in results["system_assigned_identities"]) == ["vm-in", "vm-out"]
    assert _excluded(evidence) == [
        ("system_assigned_identity", "vm-east", "location:regioneast", "resource_matched"),
        ("user_assigned_identity", "id-east", "location:regioneast", "resource_matched")]
    assert (summary["in_scope_user_assigned_identities"], summary["excluded_user_assigned_identities"]) == (2, 1)
    assert _uai("rg-out", "id-out").id in fic_reads and {"p-id-out", "ps-out"} <= set(graph_reads)
    assert summary["resource_exclusion_patterns_unmatched"] == []
    marks = {i["name"]: i.get("kept_by_identity_rule") for i in results["user_assigned_identities"]}
    assert marks == {"id-in": None, "id-out": "rg:rg-out"}
    marks = {i["resource_name"]: i.get("kept_by_identity_rule") for i in results["system_assigned_identities"]}
    assert marks == {"vm-in": None, "vm-out": "rg:rg-out"}


def test_identities_a_chain_of_identities_reaching_in_stays_whole(monkeypatch, tmp_path):
    def grant(principal, scope):
        return NS(principal_id=principal, role_definition_id="/x/roles/r1", scope=scope, condition=None)

    out, out2, idle = (_uai("rg-out", n) for n in ("id-out", "id-out2", "id-idle"))
    # id-out reaches rg-in, id-out2 can act as id-out, and vm-out's identity as id-out2. id-east can act only as
    # id-idle, which reaches nothing, so both of them leave.
    extra = [grant("p-id-out", IN_RG), grant("p-id-out2", out.id), grant("ps-out", out2.id), grant("p-id-east", idle.id)]
    code, evidence, _, _ = run_identities(monkeypatch, tmp_path, "rg:rg-out, location:regioneast", extra, [out2, idle])
    results = evidence["results"]
    assert code == 0
    marks = {i["name"]: i.get("kept_by_identity_rule") for i in results["user_assigned_identities"]}
    assert marks == {"id-in": None, "id-out": "rg:rg-out", "id-out2": "rg:rg-out"}
    marks = {i["resource_name"]: i.get("kept_by_identity_rule") for i in results["system_assigned_identities"]}
    assert marks == {"vm-in": None, "vm-out": "rg:rg-out"}
    assert _excluded(evidence) == [
        ("system_assigned_identity", "vm-east", "location:regioneast", "resource_matched"),
        ("user_assigned_identity", "id-east", "location:regioneast", "resource_matched"),
        ("user_assigned_identity", "id-idle", "rg:rg-out", "resource_matched")]


def test_identities_in_a_loop_stay_only_when_one_of_them_reaches_in(monkeypatch, tmp_path):
    def grant(principal, scope):
        return NS(principal_id=principal, role_definition_id="/x/roles/r1", scope=scope, condition=None)

    a, b, c, d = (_uai("rg-out", n) for n in ("id-a", "id-b", "id-c", "id-d"))
    # id-a and id-b can act as each other, and id-b reaches rg-in; id-c and id-d can act only as each other.
    extra = [grant("p-id-a", b.id), grant("p-id-b", a.id), grant("p-id-b", IN_RG),
             grant("p-id-c", d.id), grant("p-id-d", c.id)]
    code, evidence, _, _ = run_identities(monkeypatch, tmp_path, "rg:rg-out", extra, [a, b, c, d])
    assert code == 0
    marks = {i["name"]: i.get("kept_by_identity_rule") for i in evidence["results"]["user_assigned_identities"]}
    assert marks == {"id-in": None, "id-east": None, "id-a": "rg:rg-out", "id-b": "rg:rg-out"}
    assert sorted(e["name"] for e in evidence["results"]["excluded"]) == ["id-c", "id-d", "id-out", "vm-out"]


def test_identities_a_refused_role_list_keeps_every_matched_identity(monkeypatch, tmp_path):
    _refuse(monkeypatch, identities, "authorization.role_assignments.list_for_subscription")
    code, evidence, fic_reads, graph_reads = run_identities(monkeypatch, tmp_path, "rg:rg-out")
    results = evidence["results"]
    # Which identities reach in is unknown, so none leaves; the run still fails.
    assert code == 1 and results["excluded"] == []
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None
    marks = {i["name"]: i.get("kept_by_identity_rule") for i in results["user_assigned_identities"]}
    assert marks == {"id-in": None, "id-out": "rg:rg-out", "id-east": None}
    marks = {i["resource_name"]: i.get("kept_by_identity_rule") for i in results["system_assigned_identities"]}
    assert marks == {"vm-in": None, "vm-out": "rg:rg-out", "vm-east": None}
    assert _uai("rg-out", "id-out").id in fic_reads and {"p-id-out", "ps-out"} <= set(graph_reads)


# --- a list that wasn't read ---

@pytest.mark.parametrize("runner, module, operation, plural", [
    (run_aks, aks, "containerservice.managed_clusters.list", "clusters"),
    (run_acr, acr, "containerregistry.registries.list", "registries"),
    (run_workloads, workloads, "appcontainers.managed_environments.list_by_subscription", "environments"),
    (run_workloads, workloads, "appcontainers.container_apps.list_by_subscription", "container_apps"),
    (run_workloads, workloads, "appcontainers.jobs.list_by_subscription", "jobs"),
    (run_workloads, workloads, "containerinstance.container_groups.list", "container_groups"),
    (run_functions, functions, "web.web_apps.list", "function_apps"),
    (run_vms, vms, "compute.virtual_machines.list_all", "virtual_machines"),
    (run_vms, vms, "compute.virtual_machine_scale_sets.list_all", "scale_sets"),
    (run_disks, disks, "compute.disks.list", "disks"),
    (run_apim, apim, "apimanagement.api_management_service.list", "services"),
    (run_identities, identities, "msi.user_assigned_identities.list_by_subscription", "user_assigned_identities"),
    (run_identities, identities, "resourcegraph.resources(identity)", "system_assigned_identities"),
], ids=["clusters", "registries", "environments", "container_apps", "jobs", "container_groups", "function_apps",
        "virtual_machines", "scale_sets", "disks", "services", "user_assigned", "system_assigned"])
def test_a_refused_list_leaves_its_exclusion_counts_null(runner, module, operation, plural, monkeypatch, tmp_path,
                                                         caplog):
    _refuse(monkeypatch, module, operation)
    code, evidence = runner(monkeypatch, tmp_path, "rg:rg-out")[:2]
    summary = evidence["summary"]
    assert code == 1
    assert summary["resource_exclusion_patterns_unmatched"] is None
    assert "matched nothing" not in caplog.text
    assert (summary[f"in_scope_{plural}"], summary[f"excluded_{plural}"]) == (None, None)
    # The other lists were read, so their counts stay numbers.
    assert all(v is not None for k, v in summary.items() if k.startswith(("in_scope_", "excluded_")) and
               not k.endswith(f"_{plural}"))


@pytest.mark.parametrize("runner, module, operation", [
    (run_aks, aks, "containerservice.ContainerServiceClient (init)"),
    (run_acr, acr, "containerregistry.ContainerRegistryManagementClient (init)"),
    (run_workloads, workloads, "container clients (init)"),
    (run_functions, functions, "web.WebSiteManagementClient (init)"),
    (run_vms, vms, "compute.ComputeManagementClient (init)"),
    (run_disks, disks, "compute.ComputeManagementClient (init)"),
    (run_apim, apim, "apimanagement.ApiManagementClient (init)"),
    (run_identities, identities, "managed identity clients (init)"),
], ids=["aks", "acr", "workloads", "functions", "vms", "disks", "apim", "identities"])
def test_a_client_that_couldnt_be_built_leaves_every_exclusion_count_null(runner, module, operation, monkeypatch,
                                                                          tmp_path, caplog):
    _refuse(monkeypatch, module, operation)
    code, evidence = runner(monkeypatch, tmp_path, "rg:rg-out")[:2]
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None
    assert "matched nothing" not in caplog.text
    counts = {k: v for k, v in evidence["summary"].items() if k.startswith(("in_scope_", "excluded_"))}
    assert code == 1 and counts and set(counts.values()) == {None}


# --- a bare pattern fails the run ---

def test_a_bare_pattern_fails_every_fetcher_in_the_family(monkeypatch, tmp_path):
    runs = [
        (run_aks, "total_clusters", 3), (run_acr, "total_registries", 3), (run_workloads, "total_container_apps", 4),
        (run_functions, "total_function_apps", 3), (run_vms, "total_virtual_machines", 3), (run_disks, "total_disks", 4),
        (run_apim, "total_services", 3), (run_identities, "total_user_assigned_identities", 3),
    ]
    for runner, key, total in runs:
        code, evidence = runner(monkeypatch, tmp_path, "rg-out")[:2]
        assert code == 1, runner.__name__
        assert evidence["summary"][key] == total, runner.__name__
        assert evidence["results"]["excluded"] == [], runner.__name__

