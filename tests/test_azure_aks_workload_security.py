"""azure_aks_workload_security: container security contexts, workload grouping, network policy coverage, Pod Security Admission labels, failure semantics. Synthetic payloads, no SDK, cluster or network."""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_aks_workload_security_under_test",
                                               AZURE / "aks_workload_security" / "fetcher.py")
aks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(aks)
azure_rest = sys.modules["azure_rest"]
azure_common = sys.modules["azure_common"]
Collector = azure_common.Collector
ResourceExclusions = sys.modules["resource_exclusions"].ResourceExclusions

SUB = "/subscriptions/s1"
CLUSTER = f"{SUB}/resourceGroups/rg-aks/providers/Microsoft.ContainerService/managedClusters/aks-app"
OTHER = f"{SUB}/resourceGroups/rg-aks/providers/Microsoft.ContainerService/managedClusters/aks-old"
SERVER = "https://aks-app.hcp.usgovvirginia.cx.aks.containerservice.azure.us:443"
SETTINGS = {"system_namespaces": sorted(aks.DEFAULT_SYSTEM_NAMESPACES), "max_rows": 500}
HARDENED = {"runAsNonRoot": True, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}}


def raw_cluster(cid=CLUSTER, *, entra=True, engine="calico", power="Running", policy_addon=True):
    props = {"kubernetesVersion": "1.31.2", "powerState": {"code": power},
             "apiServerAccessProfile": {"enablePrivateCluster": True},
             "networkProfile": {"networkPlugin": "azure", "networkDataplane": "azure"},
             "disableLocalAccounts": True, "addonProfiles": {"azurepolicy": {"enabled": policy_addon}}}
    if engine:
        props["networkProfile"]["networkPolicy"] = engine
    if entra:
        props["aadProfile"] = {"managed": True, "enableAzureRBAC": True}
    return {"id": cid, "name": cid.rsplit("/", 1)[-1], "location": "usgovvirginia", "properties": props}


def container(name="app", **ctx):
    return {"name": name, "image": "registry.example/app:1", "securityContext": ctx} if ctx else {"name": name}


def raw_pod(name, namespace="app", *, containers=None, init=None, pod_ctx=None, owner=("ReplicaSet", "web-7d9f"),
            labels=None, phase="Running", **spec):
    labels = labels if labels is not None else {"app": "web", "pod-template-hash": "7d9f"}
    meta = {"name": name, "namespace": namespace, "labels": labels}
    if owner:
        meta["ownerReferences"] = [{"kind": owner[0], "name": owner[1], "controller": True}]
    body = {"containers": containers if containers is not None else [container(**HARDENED)], **spec}
    if init:
        body["initContainers"] = init
    if pod_ctx:
        body["securityContext"] = pod_ctx
    return {"metadata": meta, "spec": body, "status": {"phase": phase}}


def raw_policy(name, namespace="app", *, selector=None, types=None, ingress=None, egress=None):
    spec = {"podSelector": selector or {}}
    if types is not None:
        spec["policyTypes"] = types
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"metadata": {"name": name, "namespace": namespace}, "spec": spec}


def raw_namespace(name, **labels):
    return {"metadata": {"name": name, "labels": {f"pod-security.kubernetes.io/{k}": v for k, v in labels.items()}}}


def kubeconfig(server=SERVER, ca="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", user=True):
    config = {"clusters": [{"name": "aks-app", "cluster": {
        "server": server, "certificate-authority-data": base64.b64encode(ca.encode()).decode()}}]}
    if user:
        config["users"] = [{"name": "clusterUser", "user": {"token": "not-read"}}]
    return base64.b64encode(yaml.safe_dump(config).encode()).decode()


# --- containers ---

def test_a_hardened_container_and_what_each_missing_setting_costs() -> None:
    full = aks.container_record(container(**HARDENED), {}, False)
    assert full["hardened"] and full["non_root_enforced"] and full["drops_all_capabilities"] and not full["init_container"]
    for missing in HARDENED:
        ctx = {k: v for k, v in HARDENED.items() if k != missing}
        assert aks.container_record(container(**ctx), {}, False)["hardened"] is False, missing
    bare = aks.container_record(container(), {}, True)
    assert bare["init_container"] and not bare["hardened"] and not bare["privilege_escalation_disabled"]
    assert bare["seccomp_profile"] is None and bare["added_capabilities"] == []


def test_explicit_false_and_weaker_values_are_not_read_as_safe() -> None:
    loose = aks.container_record(container(runAsNonRoot=False, allowPrivilegeEscalation=True, readOnlyRootFilesystem=False,
                                           capabilities={"drop": ["NET_RAW"], "add": ["net_admin"]}, privileged=True), {}, False)
    assert not loose["non_root_enforced"] and not loose["privilege_escalation_disabled"]
    assert not loose["read_only_root_filesystem"] and not loose["drops_all_capabilities"]
    assert loose["privileged"] and loose["added_capabilities"] == ["NET_ADMIN"] and not loose["hardened"]
    added = aks.container_record(container(**{**HARDENED, "capabilities": {"drop": ["all"], "add": ["NET_BIND_SERVICE"]}}), {}, False)
    assert added["drops_all_capabilities"] and added["hardened"] is False


def test_pod_level_settings_apply_unless_the_container_overrides_them() -> None:
    pod_ctx = {"runAsNonRoot": True, "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}}
    inherited = aks.container_record(container(allowPrivilegeEscalation=False), pod_ctx, False)
    assert inherited["non_root_enforced"] and inherited["run_as_user"] == 1000 and inherited["seccomp_profile"] == "runtimedefault"
    overridden = aks.container_record(container(runAsNonRoot=False, runAsUser=0), pod_ctx, False)
    assert overridden["non_root_enforced"] is False and overridden["run_as_user"] == 0
    by_uid = aks.container_record(container(runAsUser=1001), {}, False)
    assert by_uid["non_root_enforced"] and by_uid["run_as_non_root"] is False
    root_uid = aks.container_record(container(runAsUser=0), {}, False)
    assert root_uid["non_root_enforced"] is False
    # allowPrivilegeEscalation and readOnlyRootFilesystem exist only on the container, never on the pod
    pod_only = aks.container_record(container(), {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}, False)
    assert not pod_only["privilege_escalation_disabled"] and not pod_only["read_only_root_filesystem"]


# --- workloads ---

def test_pods_are_grouped_by_what_runs_them() -> None:
    assert aks.workload_of(raw_pod("web-7d9f-abc")) == ("Deployment", "web")
    assert aks.workload_of(raw_pod("x", owner=("ReplicaSet", "web-7d9f"), labels={})) == ("ReplicaSet", "web-7d9f")
    assert aks.workload_of(raw_pod("db-0", owner=("StatefulSet", "db"))) == ("StatefulSet", "db")
    assert aks.workload_of(raw_pod("solo", owner=None)) == ("Pod", "solo")
    pods = [aks.pod_record(raw_pod(f"web-7d9f-{i}")) for i in "abc"] + [aks.pod_record(raw_pod("db-0", owner=("StatefulSet", "db")))]
    workloads = aks.workload_records(pods, [], SETTINGS["system_namespaces"])
    assert [(w["kind"], w["name"], w["pods"]) for w in workloads] == [("Deployment", "web", 3), ("StatefulSet", "db", 1)]
    assert all(w["hardened"] and "labels" not in w for w in workloads)


def test_host_access_init_containers_and_windows_decide_hardening() -> None:
    def one(**kwargs):
        return aks.workload_records([aks.pod_record(raw_pod("p", **kwargs))], [], SETTINGS["system_namespaces"])[0]
    assert one()["hardened"] is True
    assert one(hostNetwork=True)["hardened"] is False and one(hostNetwork=True)["uses_host_namespaces"]
    assert one(hostPID=True)["uses_host_namespaces"] and one(hostIPC=True)["uses_host_namespaces"]
    mounted = one(volumes=[{"name": "h", "hostPath": {"path": "/var/run"}}, {"name": "e", "emptyDir": {}}])
    assert mounted["host_path_volumes"] == ["/var/run"] and mounted["hardened"] is False
    assert one(init=[container("setup")])["hardened"] is False  # an init container counts like any other
    windows = one(os={"name": "windows"})
    assert windows["windows"] and windows["hardened"] is None
    system = one(namespace="kube-system", hostNetwork=True)
    assert system["system_namespace"] is True
    assert one(containers=[])["hardened"] is False


# --- network policies ---

@pytest.mark.parametrize("selector, labels, expected", [
    ({}, {"a": "1"}, True), (None, {}, True),
    ({"matchLabels": {"app": "web"}}, {"app": "web", "x": "y"}, True),
    ({"matchLabels": {"app": "web"}}, {"app": "api"}, False),
    ({"matchLabels": {"app": "web", "tier": "fe"}}, {"app": "web"}, False),
    ({"matchExpressions": [{"key": "app", "operator": "In", "values": ["web", "api"]}]}, {"app": "api"}, True),
    ({"matchExpressions": [{"key": "app", "operator": "In", "values": ["web"]}]}, {}, False),
    ({"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["web"]}]}, {"app": "web"}, False),
    ({"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["web"]}]}, {}, True),
    ({"matchExpressions": [{"key": "app", "operator": "Exists"}]}, {"app": ""}, True),
    ({"matchExpressions": [{"key": "app", "operator": "Exists"}]}, {}, False),
    ({"matchExpressions": [{"key": "app", "operator": "DoesNotExist"}]}, {"app": "x"}, False),
    ({"matchExpressions": [{"key": "app", "operator": "Gt", "values": ["1"]}]}, {"app": "2"}, False),
])
def test_label_selectors(selector, labels, expected) -> None:
    assert aks.selector_matches(selector, labels) is expected


def test_default_deny_needs_every_pod_the_direction_and_no_rule() -> None:
    deny = aks.network_policy_record(raw_policy("deny", types=["Ingress", "Egress"]))
    assert deny["default_deny_ingress"] and deny["default_deny_egress"] and deny["selects_all_pods"]
    implicit = aks.network_policy_record(raw_policy("implicit"))  # no policyTypes: Ingress only
    assert implicit["policy_types"] == ["ingress"] and implicit["default_deny_ingress"] and not implicit["default_deny_egress"]
    scoped = aks.network_policy_record(raw_policy("scoped", selector={"matchLabels": {"app": "web"}}, types=["Ingress"]))
    assert not scoped["default_deny_ingress"] and not scoped["selects_all_pods"]
    allowing = aks.network_policy_record(raw_policy("allow", types=["Ingress"], ingress=[{"from": []}]))
    assert not allowing["default_deny_ingress"] and allowing["ingress_rules"] == 1
    egress_rules = aks.network_policy_record(raw_policy("eg", egress=[{"to": []}]))
    assert egress_rules["policy_types"] == ["egress", "ingress"] and not egress_rules["default_deny_egress"]


def test_a_workload_is_covered_only_when_every_pod_is_selected_in_its_own_namespace() -> None:
    policies = [aks.network_policy_record(raw_policy("web", selector={"matchLabels": {"app": "web"}})),
                aks.network_policy_record(raw_policy("all", namespace="other"))]
    pods = [aks.pod_record(raw_pod("web-7d9f-a")),
            aks.pod_record(raw_pod("web-7d9f-b", labels={"app": "canary", "pod-template-hash": "7d9f"})),
            aks.pod_record(raw_pod("api-1", owner=("StatefulSet", "api"), labels={"app": "web"})),
            aks.pod_record(raw_pod("job-1", owner=("Job", "job"), labels={"app": "job"}))]
    by_name = {w["name"]: w for w in aks.workload_records(pods, policies, [])}
    assert by_name["web"]["selected_by_network_policy"] is False  # one replica is outside the policy
    assert by_name["api"]["selected_by_network_policy"] is True
    assert by_name["job"]["selected_by_network_policy"] is False  # the other namespace's policy does not reach it
    unread = aks.workload_records(pods, None, [])
    assert all(w["selected_by_network_policy"] is None for w in unread)


def test_namespace_records_read_pod_security_labels_and_policy_coverage() -> None:
    policies = [aks.network_policy_record(raw_policy("deny", types=["Ingress"]))]
    workloads = aks.workload_records([aks.pod_record(raw_pod("web-7d9f-a"))], policies, SETTINGS["system_namespaces"])
    listed = [raw_namespace("app", enforce="Restricted", warn="baseline"), raw_namespace("empty"), raw_namespace("kube-system")]
    by_name = {n["name"]: n for n in aks.namespace_records(listed, workloads, policies, SETTINGS["system_namespaces"])}
    assert by_name["app"]["pod_security_enforce"] == "restricted" and by_name["app"]["pod_security_warn"] == "baseline"
    assert by_name["app"]["pod_security_audit"] == "none" and by_name["app"]["default_deny_ingress"] is True
    assert by_name["app"]["workloads"] == 1 and by_name["app"]["pods"] == 1 and by_name["app"]["network_policies"] == 1
    assert by_name["empty"]["network_policies"] == 0 and by_name["empty"]["default_deny_ingress"] is False
    assert by_name["kube-system"]["system_namespace"] is True
    derived = aks.namespace_records(None, workloads, policies, SETTINGS["system_namespaces"])
    assert [n["name"] for n in derived] == ["app"] and derived[0]["pod_security_enforce"] is None


def test_kubeconfig_gives_the_server_and_ca_and_rejects_one_without_them() -> None:
    server, ca = aks.parse_kubeconfig(kubeconfig())
    assert server == SERVER and ca.startswith("-----BEGIN CERTIFICATE-----")
    with pytest.raises(ValueError):
        aks.parse_kubeconfig(base64.b64encode(b"clusters: []").decode())
    with pytest.raises(ValueError):
        aks.parse_kubeconfig("")


def test_settings_from_env(monkeypatch) -> None:
    monkeypatch.delenv(aks.SYSTEM_NAMESPACES_ENV, raising=False)
    assert aks.settings_from_env()["system_namespaces"] == sorted(aks.DEFAULT_SYSTEM_NAMESPACES)
    monkeypatch.setenv(aks.SYSTEM_NAMESPACES_ENV, " Kube-System, istio-system ")
    assert aks.settings_from_env()["system_namespaces"] == ["istio-system", "kube-system"]
    collector = Collector(logging.getLogger("test"))
    monkeypatch.setenv(aks.SYSTEM_NAMESPACES_ENV, " , ")
    aks.settings_from_env(collector)
    assert not collector.ok and azure_common.classify_failure_code(collector.failures) == "bad_config"


# --- collection through a fake ARM and a fake Kubernetes API ---

class _Resp:
    def __init__(self, status, body, reason=""):
        self.status_code, self._body, self.reason = status, body, reason
        self.text = json.dumps(body) if not isinstance(body, str) else body
        self.headers: dict = {}

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


PODS = [
    raw_pod("web-7d9f-a"), raw_pod("web-7d9f-b"),
    raw_pod("api-0", owner=("StatefulSet", "api"), labels={"app": "api"}, containers=[container(runAsNonRoot=True)]),
    raw_pod("agent-x", namespace="kube-system", owner=("DaemonSet", "agent"), labels={"k8s-app": "agent"},
            containers=[container(privileged=True)], hostNetwork=True),
    raw_pod("migrate-1", owner=("Job", "migrate"), labels={"job": "migrate"}, phase="Succeeded", containers=[container()]),
    raw_pod("batch-1", namespace="batch", owner=("Job", "batch"), labels={"job": "batch"}, containers=[container(privileged=True)]),
]
POLICIES = [raw_policy("deny-all", types=["Ingress", "Egress"]),
            raw_policy("web", selector={"matchLabels": {"app": "web"}}, types=["Ingress"], ingress=[{"from": []}]),
            raw_policy("sys", namespace="kube-system")]
NAMESPACES = [raw_namespace("app", enforce="restricted"), raw_namespace("batch"), raw_namespace("kube-system"),
              raw_namespace("idle", enforce="baseline")]


class _Api:
    """ARM and one cluster's Kubernetes API behind one fake session."""

    def __init__(self, *, clusters=None, list_fail=False, credential_status=200, forbid=(), unreachable=False,
                 registered=True, page=None):
        self.clusters = clusters if clusters is not None else [raw_cluster()]
        self.list_fail, self.credential_status, self.forbid = list_fail, credential_status, set(forbid)
        self.unreachable, self.registered, self.page = unreachable, registered, page
        self.calls: list[tuple] = []

    def post(self, url, params=None, headers=None, timeout=None):
        path = urlparse(url).path
        self.calls.append(("POST", path, headers["Authorization"], None))
        if self.credential_status != 200:
            return _Resp(self.credential_status, {"error": {"code": "AuthorizationFailed", "message": "the action is not allowed"}})
        return _Resp(200, {"kubeconfigs": [{"name": "clusterUser", "value": kubeconfig()}]})

    def get(self, url, params=None, headers=None, timeout=None, verify=None):
        parsed = urlparse(url)
        self.calls.append(("GET", parsed.path, headers["Authorization"], verify))
        if parsed.netloc.startswith("aks-app.hcp"):
            return self._kube(parsed.path, params or {}, verify)
        if parsed.path.endswith("/providers/Microsoft.ContainerService/managedClusters"):
            if not self.registered:
                return _Resp(409, {"error": {"code": "MissingSubscriptionRegistration", "message": "not registered"}})
            if self.list_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": self.clusters})
        return _Resp(404, {"error": {"code": "NotFound", "message": parsed.path}})

    def _kube(self, path, params, verify):
        if self.unreachable:
            raise requests.ConnectionError("Failed to establish a new connection: name or service not known")
        assert verify and Path(verify).read_text().startswith("-----BEGIN CERTIFICATE-----")
        kind = path.rsplit("/", 1)[-1]
        if kind in self.forbid:
            return _Resp(403, {"kind": "Status", "message": f"{kind} is forbidden: User cannot list resource", "code": 403})
        items = {"pods": PODS, "networkpolicies": POLICIES, "namespaces": NAMESPACES}[kind]
        if self.page and kind == "pods":
            start = int(params.get("continue") or 0)
            chunk = items[start:start + self.page]
            more = start + self.page < len(items)
            return _Resp(200, {"items": chunk, "metadata": {"continue": str(start + self.page)} if more else {}})
        return _Resp(200, {"items": items, "metadata": {}})


class _Cred:
    def __init__(self):
        self.scopes: list[str] = []

    def get_token(self, scope):
        self.scopes.append(scope)
        return namedtuple("T", "token expires_on")(f"tok:{scope}", 9_999_999_999)


def _collect(api, exclusions=None, settings=None, cred=None):
    client = azure_rest.AzureRestClient(cred or _Cred(), session=api)
    collector = Collector(logging.getLogger("test"))
    results, summary = aks.collect(client, "s1", collector, exclusions, settings or SETTINGS)
    return results, summary, collector


def test_collect_reads_a_cluster_and_judges_only_workload_namespaces(assert_summary_documented, monkeypatch) -> None:
    monkeypatch.setattr(azure_rest.time, "sleep", lambda s: None)
    api, cred = _Api(), _Cred()
    results, summary, collector = _collect(api, cred=cred)
    assert collector.ok, collector.failures
    assert_summary_documented("azure/aks_workload_security", summary)
    cluster = results["clusters"][0]
    assert cluster["kubernetes_api_read"] and cluster["api_server"] == SERVER and cluster["network_policy_engine"] == "calico"
    assert cluster["pods_running"] == 5 and cluster["pods_finished_skipped"] == 1
    assert summary["clusters_with_kubernetes_api_read"] == 1 and summary["clusters_enforcing_network_policies"] == 1
    assert summary["pods"] == 5 and summary["pods_finished_skipped"] == 1
    assert summary["system_workloads"] == 1 and summary["workloads"] == 3 and summary["containers"] == 3
    assert summary["workloads_hardened"] == 1 and summary["workloads_not_hardened"] == 2
    assert summary["workload_hardening_percentage"] == 33
    assert summary["containers_non_root_enforced"] == 2 and summary["privileged_containers"] == 1  # kube-system's is not counted
    assert summary["workloads_using_host_namespaces"] == 0
    assert summary["namespaces"] == 3 and summary["namespaces_enforcing_pod_security"] == 2
    assert summary["namespaces_enforcing_restricted_pod_security"] == 1 and summary["namespaces_without_pod_security_enforcement"] == 1
    assert summary["network_policies"] == 2 and summary["namespaces_with_network_policy"] == 1
    assert summary["namespaces_without_network_policy"] == 2
    assert summary["namespaces_with_default_deny_ingress"] == 1 and summary["namespaces_with_default_deny_egress"] == 1
    assert summary["workloads_selected_by_network_policy"] == 2 and summary["workloads_without_network_policy"] == 1
    # least hardened first, system namespaces last
    assert [(w["namespace"], w["name"]) for w in cluster["workloads"]] == [
        ("app", "api"), ("batch", "batch"), ("app", "web"), ("kube-system", "agent")]
    # ARM is called with an ARM token, the cluster with a token for the AKS server application and the cluster's CA
    kube = [c for c in api.calls if c[1].startswith(("/api/", "/apis/"))]
    assert len(kube) == 3 and all(c[2] == f"Bearer tok:{aks.AKS_SERVER_APP}/.default" and c[3] for c in kube)
    assert not Path(kube[0][3]).exists()  # the CA file is gone once the cluster is read
    arm = [c for c in api.calls if not c[1].startswith(("/api/", "/apis/"))]
    assert all(aks.AKS_SERVER_APP not in c[2] for c in arm)
    assert "not-read" not in json.dumps(results)


def test_pods_are_paged(monkeypatch) -> None:
    _, summary, collector = _collect(_Api(page=2))
    assert collector.ok and summary["pods"] == 5 and summary["workloads"] == 3


def test_a_forbidden_list_nulls_only_what_depends_on_it_and_fails() -> None:
    results, summary, collector = _collect(_Api(forbid={"pods"}))
    assert not collector.ok and azure_common.classify_failure_code(collector.failures) == "not_authorized"
    assert results["clusters"][0]["workloads"] is None and results["clusters"][0]["kubernetes_api_read"] is False
    assert summary["workloads"] is None and summary["workloads_hardened"] is None and summary["pods"] is None
    assert summary["workload_hardening_percentage"] is None and summary["workloads_without_network_policy"] is None
    assert summary["network_policies"] == 2 and summary["namespaces"] == 3 and summary["clusters_with_kubernetes_api_unread"] == 1

    results, summary, collector = _collect(_Api(forbid={"networkpolicies"}))
    assert not collector.ok and summary["network_policies"] is None and summary["namespaces_without_network_policy"] is None
    assert summary["workloads"] == 3 and summary["workloads_selected_by_network_policy"] is None
    assert all(w["selected_by_network_policy"] is None for w in results["clusters"][0]["workloads"])

    results, summary, collector = _collect(_Api(forbid={"namespaces"}))
    assert not collector.ok and summary["namespaces"] is None and summary["namespaces_enforcing_pod_security"] is None
    assert summary["namespaces_without_network_policy"] is None and summary["workloads"] == 3
    assert {n["name"] for n in results["clusters"][0]["namespaces"]} == {"app", "batch", "kube-system"}
    assert any("namespace list was not read" in note for note in results["clusters"][0]["notes"])


def test_an_unreachable_private_api_server_is_tried_once_and_fails_as_unreachable(monkeypatch) -> None:
    monkeypatch.setattr(azure_rest.time, "sleep", lambda s: None)
    api = _Api(unreachable=True)
    results, summary, collector = _collect(api)
    assert len(collector.failures) == 1 and azure_common.classify_failure_code(collector.failures) == "target_unreachable"
    assert {c[1] for c in api.calls if c[1].startswith(("/api/", "/apis/"))} == {"/api/v1/pods"}
    cluster = results["clusters"][0]
    assert cluster["kubernetes_api_read"] is False and any("did not answer" in n for n in cluster["notes"])
    assert summary["workloads"] is None and summary["network_policies"] is None and summary["namespaces"] is None


def test_a_refused_credential_call_and_a_cluster_without_entra_leave_the_cluster_unread() -> None:
    results, summary, collector = _collect(_Api(credential_status=403))
    assert not collector.ok and azure_common.classify_failure_code(collector.failures) == "not_authorized"
    assert results["clusters"][0]["kubernetes_api_read"] is False and summary["workloads"] is None

    api = _Api(clusters=[raw_cluster(entra=False)])
    results, summary, collector = _collect(api)
    assert not collector.ok and "no AKS-managed Microsoft Entra integration" in collector.failures[0]["message"]
    assert summary["clusters_without_entra_integration"] == 1 and summary["workloads"] is None
    assert not [c for c in api.calls if c[0] == "POST"]  # no credential is requested for a cluster it cannot read


def test_a_stopped_cluster_reads_as_running_nothing() -> None:
    api = _Api(clusters=[raw_cluster(power="Stopped")])
    results, summary, collector = _collect(api)
    assert collector.ok and summary["clusters_stopped"] == 1 and summary["workloads"] == 0 and summary["namespaces"] == 0
    assert summary["workload_hardening_percentage"] == 0 and summary["clusters_with_kubernetes_api_read"] == 1
    assert len(api.calls) == 1


def test_no_policy_engine_is_counted_and_noted() -> None:
    results, summary, collector = _collect(_Api(clusters=[raw_cluster(engine=None, policy_addon=False)]))
    assert collector.ok and summary["clusters_without_network_policy_engine"] == 1
    assert summary["clusters_enforcing_network_policies"] == 0 and summary["clusters_with_azure_policy_addon"] == 0
    assert any("no network policy engine" in n for n in results["clusters"][0]["notes"])


def test_failed_cluster_list_an_unregistered_provider_and_exclusions() -> None:
    _, summary, collector = _collect(_Api(list_fail=True))
    assert not collector.ok and summary["clusters_read"] is False and summary["workloads"] is None
    assert summary["in_scope_clusters"] is None and summary["excluded_clusters"] is None

    _, summary, collector = _collect(_Api(registered=False))
    assert collector.ok and summary["clusters"] == 0 and summary["workloads"] == 0

    api = _Api(clusters=[raw_cluster(), raw_cluster(OTHER, entra=False)])
    results, summary, collector = _collect(api, ResourceExclusions(["id:*/aks-old"]))
    assert collector.ok and summary["clusters"] == 1 and summary["excluded_clusters"] == 1
    assert [e["name"] for e in results["excluded"]] == ["aks-old"]

    _, _, collector = _collect(_Api(), ResourceExclusions(["aks-old"]))
    assert not collector.ok and azure_common.classify_failure_code(collector.failures) == "bad_config"


def test_row_cap_keeps_the_unhardened_workloads_and_every_count() -> None:
    results, summary, collector = _collect(_Api(), settings={**SETTINGS, "max_rows": 2})
    assert collector.ok and summary["workload_rows_truncated"] is True and summary["workloads"] == 3
    assert [w["name"] for w in results["clusters"][0]["workloads"]] == ["api", "batch"]
    assert results["clusters"][0]["workloads_truncated"] is True


def test_main_writes_evidence(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: _Cred())
    monkeypatch.setattr(requests, "Session", lambda: _Api())
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "s1")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv(aks.SYSTEM_NAMESPACES_ENV, raising=False)
    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)
    assert aks.main() == 0
    evidence = json.loads((tmp_path / "azure_aks_workload_security_s1.json").read_text())
    assert evidence["metadata"]["partial_failure"] is False and evidence["summary"]["workloads"] == 3


def test_a_refused_cluster_token_is_recorded_once_and_not_called_unreachable() -> None:
    class Refusing(_Cred):
        def get_token(self, scope):
            if scope.startswith(aks.AKS_SERVER_APP):
                raise RuntimeError("AADSTS53003: access blocked by Conditional Access")
            return super().get_token(scope)

    results, summary, collector = _collect(_Api(), cred=Refusing())
    assert len(collector.failures) == 1 and azure_common.classify_failure_code(collector.failures) == "auth_failed"
    assert results["clusters"][0]["notes"] == [] and summary["workloads"] is None


def test_a_rollout_shows_the_least_restricted_pod_template_whichever_pod_comes_first() -> None:
    old = raw_pod("web-aaa-1", owner=("ReplicaSet", "web-aaa"), labels={"app": "web", "pod-template-hash": "aaa"})
    new = raw_pod("web-bbb-1", owner=("ReplicaSet", "web-bbb"), labels={"app": "web", "pod-template-hash": "bbb"},
                  containers=[container(privileged=True)], hostNetwork=True)
    for order in ([old, new], [new, old], [old, new, old]):
        workload, = aks.workload_records([aks.pod_record(p) for p in order], [], SETTINGS["system_namespaces"])
        assert workload["name"] == "web" and workload["pods"] == len(order) and workload["pod_templates"] == 2
        assert workload["hardened"] is False and workload["uses_host_namespaces"] is True
        assert workload["containers"][0]["privileged"] is True
    same, = aks.workload_records([aks.pod_record(old), aks.pod_record(old)], [], SETTINGS["system_namespaces"])
    assert same["pod_templates"] == 1 and same["hardened"] is True


def test_a_root_uid_is_root_whatever_run_as_non_root_says() -> None:
    assert aks.container_record(container(runAsNonRoot=True, runAsUser=0), {}, False)["non_root_enforced"] is False
    assert aks.container_record(container(runAsNonRoot=True), {"runAsUser": 0}, False)["non_root_enforced"] is False
    assert aks.container_record(container(runAsUser=True), {}, False)["non_root_enforced"] is False  # not a uid
    assert aks.container_record(container(runAsUser=65534), {"runAsNonRoot": False}, False)["non_root_enforced"] is True


@pytest.mark.parametrize("spec", [{"os": {"name": "Windows"}}, {"nodeSelector": {"kubernetes.io/os": "windows"}},
                                  {"nodeSelector": {"beta.kubernetes.io/os": "windows"}}])
def test_a_windows_pod_is_recognised_by_os_or_node_selector(spec) -> None:
    workload, = aks.workload_records([aks.pod_record(raw_pod("w", containers=[container()], **spec))], [], [])
    assert workload["windows"] is True and workload["hardened"] is None
    linux, = aks.workload_records([aks.pod_record(raw_pod("l", nodeSelector={"kubernetes.io/os": "linux"}))], [], [])
    assert linux["windows"] is False and linux["hardened"] is True


def test_no_token_is_sent_to_an_api_server_that_is_not_https() -> None:
    with pytest.raises(ValueError, match="not https"):
        aks.parse_kubeconfig(kubeconfig(server="http://aks-app.hcp.example"))

    class Plain(_Api):
        def post(self, url, params=None, headers=None, timeout=None):
            return _Resp(200, {"kubeconfigs": [{"name": "clusterUser", "value": kubeconfig(server="http://aks-app.hcp.example")}]})

    api = Plain()
    _, summary, collector = _collect(api)
    assert not collector.ok and summary["workloads"] is None
    assert not [c for c in api.calls if c[1].startswith(("/api/", "/apis/"))]


def test_a_privileged_container_is_never_hardened_and_an_egress_only_policy_denies_no_ingress() -> None:
    assert aks.container_record(container(**HARDENED, privileged=True), {}, False)["hardened"] is False
    egress_only = aks.network_policy_record(raw_policy("eg", types=["Egress"]))
    assert egress_only["default_deny_egress"] is True and egress_only["default_deny_ingress"] is False


def _summary(pods, namespaces=(), policies=()):
    workloads = aks.workload_records([aks.pod_record(p) for p in pods], [aks.network_policy_record(p) for p in policies],
                                     SETTINGS["system_namespaces"])
    cluster = {**aks.cluster_identity(raw_cluster()), "kubernetes_api_read": True, "namespaces_read": True, "pods_read": True,
               "network_policies_read": True, "workloads": workloads, "workloads_truncated": False,
               "network_policies": [aks.network_policy_record(p) for p in policies], "pods_running": len(pods),
               "pods_finished_skipped": 0,
               "namespaces": aks.namespace_records(list(namespaces), workloads, [], SETTINGS["system_namespaces"])}
    return aks.summarize([cluster], True, SETTINGS)


def test_windows_workloads_unconfined_seccomp_and_the_privileged_psa_level_are_not_counted_as_restricted() -> None:
    summary = _summary(
        [raw_pod("win-1", owner=("DaemonSet", "win"), containers=[container(privileged=True)], os={"name": "windows"}),
         raw_pod("a-1", owner=("StatefulSet", "a"), containers=[container(**HARDENED, seccompProfile={"type": "Unconfined"})]),
         raw_pod("b-1", owner=("StatefulSet", "b"), containers=[container(**HARDENED, seccompProfile={"type": "RuntimeDefault"})]),
         raw_pod("c-1", owner=("StatefulSet", "c"), pod_ctx={"seccompProfile": {"type": "Localhost"}})],
        [raw_namespace("app", enforce="privileged"), raw_namespace("strict", enforce="baseline"), raw_namespace("open")])
    assert summary["windows_workloads"] == 1 and summary["workloads"] == 3 and summary["containers"] == 3
    assert summary["privileged_containers"] == 0 and summary["workloads_hardened"] == 3  # the Windows pod is not judged
    assert summary["containers_with_seccomp_profile"] == 2
    assert summary["namespaces"] == 3 and summary["namespaces_enforcing_pod_security"] == 1
    assert summary["namespaces_without_pod_security_enforcement"] == 2


def test_legacy_or_unmanaged_entra_profiles_are_not_entra_integrated() -> None:
    legacy = raw_cluster()
    legacy["properties"]["aadProfile"] = {"managed": False, "clientAppID": "x"}
    assert aks.cluster_identity(legacy)["entra_integrated"] is False
    assert aks.cluster_identity(raw_cluster())["entra_integrated"] is True
    assert aks.cluster_identity(raw_cluster(entra=False))["azure_rbac_enabled"] is False
