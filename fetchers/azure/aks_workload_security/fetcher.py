#!/usr/bin/env python3
"""AKS workload security: pod and container security contexts, Pod Security Admission labels and network policies, read from each cluster's Kubernetes API with an Entra token."""

import base64
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_id_key,
    coverage_percentage,
    dig,
    resource_group_from_id,
)
from azure_rest import ArmError, int_config, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_aks_workload_security"
logger = logging.getLogger(NAME)

AKS_API = "2024-09-01"
# The AKS Microsoft Entra server application: the token audience of every Entra-integrated cluster, in every cloud.
AKS_SERVER_APP = "6dae42f8-4368-4678-94ff-3960e28e3630"
PAGE_SIZE = "500"
SYSTEM_NAMESPACES_ENV = "AKS_SYSTEM_NAMESPACES"
MAX_ROWS_ENV = "AKS_WORKLOAD_MAX_ROWS"
DEFAULT_MAX_ROWS = 500
# Namespaces AKS and its add-ons run in; their pods need host access and are counted apart from the workloads.
DEFAULT_SYSTEM_NAMESPACES = (
    "kube-system", "kube-public", "kube-node-lease", "gatekeeper-system", "calico-system", "tigera-operator",
    "app-routing-system", "aks-command",
)
PSA_PREFIX = "pod-security.kubernetes.io/"
PSA_ENFORCING = ("baseline", "restricted")
SECCOMP_CONFINED = ("runtimedefault", "localhost")
FINISHED_PHASES = ("succeeded", "failed")
NO_POLICY_ENGINE = ("", "none")
STOPPED = "stopped"


class KubeError(Exception):
    """A Kubernetes API refusal; the status sits in the message the way classify_failure_code reads it."""

    def __init__(self, status: int, message: str):
        super().__init__(f"({status}) {message}")
        self.status = status


def _lower(value: Any) -> str:
    return str(value or "").lower()


def settings_from_env(collector: Optional[Collector] = None) -> Dict[str, Any]:
    raw = os.environ.get(SYSTEM_NAMESPACES_ENV)
    names = sorted({n.strip().lower() for n in (raw or "").replace(",", " ").split() if n.strip()})
    if raw is not None and raw.strip() and not names and collector is not None:
        collector.record(f"config {SYSTEM_NAMESPACES_ENV}", ValueError(
            f"invalid setting {SYSTEM_NAMESPACES_ENV}: it names no namespace"))
    return {
        "system_namespaces": names if (raw is not None and raw.strip()) else sorted(DEFAULT_SYSTEM_NAMESPACES),
        "max_rows": int_config(MAX_ROWS_ENV, DEFAULT_MAX_ROWS),
    }


# --- label selectors ---

def selector_matches(selector: Optional[Dict[str, Any]], labels: Dict[str, str]) -> bool:
    """A Kubernetes label selector against a pod's labels; an empty selector matches every pod."""
    selector = selector or {}
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, values = expr.get("key"), _lower(expr.get("operator")), expr.get("values") or []
        if op == "in" and labels.get(key) not in values:
            return False
        if op == "notin" and key in labels and labels[key] in values:
            return False
        if op == "exists" and key not in labels:
            return False
        if op == "doesnotexist" and key in labels:
            return False
        if op not in ("in", "notin", "exists", "doesnotexist"):
            return False  # an operator this fetcher does not know selects nothing, so no pod reads as covered by it
    return True


def selector_is_empty(selector: Optional[Dict[str, Any]]) -> bool:
    selector = selector or {}
    return not (selector.get("matchLabels") or {}) and not (selector.get("matchExpressions") or [])


# --- containers and workloads ---

def container_record(raw: Dict[str, Any], pod_context: Dict[str, Any], init: bool) -> Dict[str, Any]:
    """One container's effective security context: its own setting, else the pod's where the pod can set it."""
    ctx = raw.get("securityContext") or {}

    def effective(key: str) -> Any:
        return ctx[key] if ctx.get(key) is not None else pod_context.get(key)

    capabilities = ctx.get("capabilities") or {}
    dropped = [str(c).upper() for c in capabilities.get("drop") or []]
    added = sorted(str(c).upper() for c in capabilities.get("add") or [])
    run_as_user = effective("runAsUser")
    uid = run_as_user if isinstance(run_as_user, int) and not isinstance(run_as_user, bool) else None
    seccomp = _lower(dig(ctx, "seccompProfile", "type") or dig(pod_context, "seccompProfile", "type")) or None
    record = {
        "name": raw.get("name"),
        "init_container": init,
        "run_as_non_root": effective("runAsNonRoot") is True,
        "run_as_user": run_as_user,
        # A runAsUser decides the user outright, so 0 is root whatever runAsNonRoot says; with no runAsUser,
        # runAsNonRoot makes the kubelet refuse an image that would run as root.
        "non_root_enforced": uid > 0 if uid is not None else effective("runAsNonRoot") is True,
        "privilege_escalation_disabled": ctx.get("allowPrivilegeEscalation") is False,
        "read_only_root_filesystem": ctx.get("readOnlyRootFilesystem") is True,
        "drops_all_capabilities": "ALL" in dropped,
        "added_capabilities": added,
        "privileged": ctx.get("privileged") is True,
        "seccomp_profile": seccomp,
    }
    record["hardened"] = (record["non_root_enforced"] and record["privilege_escalation_disabled"]
                          and record["read_only_root_filesystem"] and record["drops_all_capabilities"]
                          and not record["privileged"] and not added)
    return record


def workload_of(pod: Dict[str, Any]) -> Tuple[str, str]:
    """(kind, name) of what runs the pod: its controller, with a ReplicaSet read back to its Deployment."""
    meta = pod.get("metadata") or {}
    owner = next((o for o in meta.get("ownerReferences") or [] if o.get("controller")), None) \
        or next(iter(meta.get("ownerReferences") or []), None)
    if owner is None:
        return "Pod", str(meta.get("name"))
    kind, name = str(owner.get("kind")), str(owner.get("name"))
    template_hash = (meta.get("labels") or {}).get("pod-template-hash")
    if kind == "ReplicaSet" and template_hash and name.endswith(f"-{template_hash}"):
        return "Deployment", name[: -len(template_hash) - 1]
    return kind, name


def pod_record(pod: Dict[str, Any]) -> Dict[str, Any]:
    meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
    pod_context = spec.get("securityContext") or {}
    containers = [container_record(c, pod_context, False) for c in spec.get("containers") or []] \
        + [container_record(c, pod_context, True) for c in spec.get("initContainers") or []]
    kind, name = workload_of(pod)
    host_paths = sorted({str(dig(v, "hostPath", "path")) for v in spec.get("volumes") or [] if v.get("hostPath")})
    return {
        "namespace": meta.get("namespace"),
        "name": meta.get("name"),
        "labels": {str(k): str(v) for k, v in (meta.get("labels") or {}).items()},
        "workload_kind": kind,
        "workload_name": name,
        # Older manifests name the OS only through the node selector.
        "windows": "windows" in (_lower(dig(spec, "os", "name")), _lower((spec.get("nodeSelector") or {}).get("kubernetes.io/os")),
                                 _lower((spec.get("nodeSelector") or {}).get("beta.kubernetes.io/os"))),
        "host_network": spec.get("hostNetwork") is True,
        "host_pid": spec.get("hostPID") is True,
        "host_ipc": spec.get("hostIPC") is True,
        "host_path_volumes": host_paths,
        "containers": containers,
    }


def network_policy_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    meta, spec = raw.get("metadata") or {}, raw.get("spec") or {}
    ingress, egress = spec.get("ingress") or [], spec.get("egress") or []
    # Unset policyTypes means Ingress, plus Egress when the policy has egress rules.
    types = [_lower(t) for t in spec.get("policyTypes") or []] or (["ingress"] + (["egress"] if egress else []))
    everyone = selector_is_empty(spec.get("podSelector"))
    return {
        "namespace": meta.get("namespace"),
        "name": meta.get("name"),
        "pod_selector": spec.get("podSelector") or {},
        "selects_all_pods": everyone,
        "policy_types": sorted(types),
        "ingress_rules": len(ingress),
        "egress_rules": len(egress),
        # Every pod selected, the direction named, and no rule allowing anything.
        "default_deny_ingress": everyone and "ingress" in types and not ingress,
        "default_deny_egress": everyone and "egress" in types and not egress,
    }


def workload_records(pods: List[Dict[str, Any]], policies: Optional[List[Dict[str, Any]]],
                     system: Iterable[str]) -> List[Dict[str, Any]]:
    """Pods grouped by what runs them; the containers are those of the workload's least restricted pod template."""
    system = set(system)
    by_namespace: Dict[str, List[Dict[str, Any]]] = {}
    for policy in policies or []:
        by_namespace.setdefault(str(policy["namespace"]), []).append(policy)
    groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    templates: Dict[Tuple[str, str, str], set] = {}
    for pod in pods:
        key = (str(pod["namespace"]), pod["workload_kind"], pod["workload_name"])
        selected = None if policies is None else any(
            selector_matches(p["pod_selector"], pod["labels"]) for p in by_namespace.get(str(pod["namespace"]), []))
        containers = pod["containers"]
        host_namespaces = pod["host_network"] or pod["host_pid"] or pod["host_ipc"]
        # Linux security contexts do not apply to a Windows pod, so it is listed but never judged.
        hardened = None if pod["windows"] else (bool(containers) and all(c["hardened"] for c in containers)
                                                and not host_namespaces and not pod["host_path_volumes"])
        template = json.dumps([containers, pod["host_network"], pod["host_pid"], pod["host_ipc"], pod["host_path_volumes"],
                               pod["windows"]], sort_keys=True, default=str)
        templates.setdefault(key, set()).add(template)
        group = groups.get(key)
        # During a rollout one workload runs two pod templates; the row shows the least restricted one, so a
        # hardened old replica never hides what the new one runs.
        if group is None or (hardened is False and group["hardened"] is not False):
            group = groups[key] = {
                "namespace": pod["namespace"],
                "kind": pod["workload_kind"],
                "name": pod["workload_name"],
                "system_namespace": str(pod["namespace"]).lower() in system,
                "windows": pod["windows"],
                "pods": group["pods"] if group else 0,
                "pod_templates": 0,
                "host_network": pod["host_network"],
                "host_pid": pod["host_pid"],
                "host_ipc": pod["host_ipc"],
                "host_path_volumes": pod["host_path_volumes"],
                "uses_host_namespaces": host_namespaces,
                "containers": containers,
                "hardened": hardened,
                "selected_by_network_policy": selected if group is None else group["selected_by_network_policy"],
            }
        group["pods"] += 1
        group["pod_templates"] = len(templates[key])
        # One replica outside every policy leaves the workload uncovered.
        if selected is False:
            group["selected_by_network_policy"] = False
    return [groups[k] for k in sorted(groups)]


def namespace_records(namespaces: Optional[List[Dict[str, Any]]], workloads: Optional[List[Dict[str, Any]]],
                      policies: Optional[List[Dict[str, Any]]], system: Iterable[str]) -> List[Dict[str, Any]]:
    """One record per namespace; the names come from the namespace list, else from the pods and policies read."""
    system = set(system)
    labels: Dict[str, Optional[Dict[str, str]]] = {}
    if namespaces is not None:
        for ns in namespaces:
            labels[str(dig(ns, "metadata", "name"))] = {str(k): str(v) for k, v in (dig(ns, "metadata", "labels") or {}).items()}
    else:
        for item in (workloads or []) + (policies or []):
            labels.setdefault(str(item["namespace"]), None)
    out = []
    for name in sorted(labels):
        ns_labels = labels[name]
        of_ns = [p for p in policies or [] if p["namespace"] == name]
        mine = [w for w in workloads or [] if w["namespace"] == name]

        def psa(mode: str) -> Optional[str]:
            return None if ns_labels is None else (ns_labels.get(f"{PSA_PREFIX}{mode}") or "none").lower()

        out.append({
            "name": name,
            "system_namespace": name.lower() in system,
            "pod_security_enforce": psa("enforce"),
            "pod_security_audit": psa("audit"),
            "pod_security_warn": psa("warn"),
            "workloads": len(mine) if workloads is not None else None,
            "pods": sum(w["pods"] for w in mine) if workloads is not None else None,
            "network_policies": len(of_ns) if policies is not None else None,
            "default_deny_ingress": any(p["default_deny_ingress"] for p in of_ns) if policies is not None else None,
            "default_deny_egress": any(p["default_deny_egress"] for p in of_ns) if policies is not None else None,
        })
    return out


# --- the Kubernetes API ---

def parse_kubeconfig(value: str) -> Tuple[str, str]:
    """(API server URL, CA certificate PEM) from a base64 kubeconfig; the user entry, which may hold a credential, is not read."""
    import yaml  # lazy

    config = yaml.safe_load(base64.b64decode(value)) or {}
    cluster = dig((config.get("clusters") or [{}])[0], "cluster") or {}
    server, ca = cluster.get("server"), cluster.get("certificate-authority-data")
    if not server or not ca:
        raise ValueError("the cluster's kubeconfig names no API server or no certificate authority")
    if not str(server).lower().startswith("https://"):
        raise ValueError("the cluster's kubeconfig names an API server that is not https, so no token is sent to it")
    return str(server).rstrip("/"), base64.b64decode(ca).decode()


def kube_list(client, server: str, ca_path: str, path: str) -> List[Dict[str, Any]]:
    """Every page of one Kubernetes list."""
    items: List[Dict[str, Any]] = []
    params = {"limit": PAGE_SIZE}
    while True:
        response = client.get_url(f"{server}{path}", AKS_SERVER_APP, params, ca_path)
        if response.status_code >= 400:
            try:
                message = str(response.json().get("message") or response.reason)
            except ValueError:
                message = str(response.reason or response.text[:200])
            raise KubeError(response.status_code, message)
        body = response.json()
        items.extend(body.get("items") or [])
        token = dig(body, "metadata", "continue")
        if not token:
            return items
        params = {"limit": PAGE_SIZE, "continue": token}


def cluster_identity(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    aad = props.get("aadProfile") or {}
    engine = _lower(dig(props, "networkProfile", "networkPolicy")) or "none"
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "kubernetes_version": props.get("kubernetesVersion"),
        "power_state": dig(props, "powerState", "code"),
        "private_cluster": dig(props, "apiServerAccessProfile", "enablePrivateCluster") is True,
        "entra_integrated": aad.get("managed") is True,
        "azure_rbac_enabled": aad.get("enableAzureRBAC") is True,
        "local_accounts_disabled": props.get("disableLocalAccounts") is True,
        "network_plugin": dig(props, "networkProfile", "networkPlugin"),
        "network_dataplane": dig(props, "networkProfile", "networkDataplane"),
        # NetworkPolicy objects do nothing unless an engine enforces them.
        "network_policy_engine": engine,
        "network_policies_enforced": engine not in NO_POLICY_ENGINE,
        "azure_policy_addon_enabled": dig(props, "addonProfiles", "azurepolicy", "enabled") is True,
    }


def collect_cluster(client, raw: Dict[str, Any], settings: Dict[str, Any], collector: Collector) -> Dict[str, Any]:
    """One cluster's record; a list that could not be read leaves its fields null and the failure recorded."""
    record: Dict[str, Any] = {**cluster_identity(raw), "kubernetes_api_read": False, "notes": [],
                              "namespaces_read": None, "pods_read": None, "network_policies_read": None,
                              "namespaces": None, "network_policies": None, "workloads": None,
                              "workloads_truncated": None, "pods_running": None, "pods_finished_skipped": None}
    name = record["name"]
    if _lower(record["power_state"]) == STOPPED:
        # A stopped cluster has no API server and runs nothing, so there is nothing to read and nothing unread.
        record.update({"kubernetes_api_read": True, "namespaces_read": True, "pods_read": True, "network_policies_read": True,
                       "namespaces": [], "network_policies": [], "workloads": [], "workloads_truncated": False,
                       "pods_running": 0, "pods_finished_skipped": 0})
        record["notes"].append("the cluster is stopped, so it runs no workload")
        return record
    if not record["entra_integrated"]:
        collector.record(f"kubernetes({name})", PermissionError(
            f"cluster {name} has no AKS-managed Microsoft Entra integration, so its Kubernetes API cannot be read with an Entra token"))
        return record

    def _kubeconfig():
        body = client.post(f"{raw['id']}/listClusterUserCredential", AKS_API)
        return parse_kubeconfig(((body.get("kubeconfigs") or [{}])[0]).get("value") or "")

    endpoint = collector.guard(f"containerservice.managedClusters.listClusterUserCredential({name})", _kubeconfig)
    if endpoint is None:
        return record
    server, ca = endpoint
    record["api_server"] = server
    # The CA certificate is public material; requests reads a CA bundle from a file path.
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as ca_file:
        ca_file.write(ca)
        ca_file.flush()

        import requests  # lazy

        unreachable = gave_up = False

        def _list(path: str, operation: str) -> Optional[List[Dict[str, Any]]]:
            nonlocal unreachable, gave_up
            if gave_up:
                return None  # one failure is recorded; repeating the same timeout or token error on every list adds nothing
            try:
                return kube_list(client, server, ca_file.name, path)
            except KubeError as exc:  # the API server answered and refused this list; the others may still be allowed
                collector.record(f"kubernetes.{operation}.list({name})", exc)
            except requests.RequestException as exc:  # no answer: a private API server out of reach, DNS, TLS
                unreachable = gave_up = True
                collector.record(f"kubernetes.{operation}.list({name})", exc)
            except Exception as exc:  # noqa: BLE001 -- such as a token the tenant refused to issue for the cluster
                gave_up = True
                collector.record(f"kubernetes.{operation}.list({name})", exc)
            return None

        raw_pods = _list("/api/v1/pods", "pods")
        raw_policies = _list("/apis/networking.k8s.io/v1/networkpolicies", "networkpolicies")
        raw_namespaces = _list("/api/v1/namespaces", "namespaces")
    if unreachable:
        record["notes"].append("the Kubernetes API server did not answer; a private cluster's API is reachable only from "
                               "its virtual network or a network peered with it")

    policies = sorted((network_policy_record(p) for p in raw_policies), key=lambda p: (str(p["namespace"]), str(p["name"]))) \
        if raw_policies is not None else None
    workloads = None
    if raw_pods is not None:
        live = [p for p in raw_pods if _lower(dig(p, "status", "phase")) not in FINISHED_PHASES]
        workloads = workload_records([pod_record(p) for p in live], policies, settings["system_namespaces"])
        record["pods_running"] = len(live)
        record["pods_finished_skipped"] = len(raw_pods) - len(live)
    record.update({
        "kubernetes_api_read": raw_pods is not None and raw_policies is not None and raw_namespaces is not None,
        "namespaces_read": raw_namespaces is not None,
        "pods_read": raw_pods is not None,
        "network_policies_read": raw_policies is not None,
        "namespaces": namespace_records(raw_namespaces, workloads, policies, settings["system_namespaces"]),
        "network_policies": policies,
        "workloads": workloads,
    })
    if raw_namespaces is None and not gave_up:
        record["notes"].append("the namespace list was not read, so namespaces come from the pods and policies read "
                               "and their Pod Security Admission labels are unknown")
    if policies and not record["network_policies_enforced"]:
        record["notes"].append("the cluster has NetworkPolicy objects but no network policy engine, so nothing enforces them")
    return record


# --- summary ---

def summarize(clusters: List[Dict[str, Any]], clusters_read: bool, settings: Dict[str, Any]) -> Dict[str, Any]:
    pods_known = clusters_read and all(c["pods_read"] for c in clusters)
    policies_known = clusters_read and all(c["network_policies_read"] for c in clusters)
    namespaces_known = clusters_read and all(c["namespaces_read"] for c in clusters)
    workloads = [w for c in clusters for w in c["workloads"] or []]
    # Judged: Linux workloads outside the system namespaces.
    judged = [w for w in workloads if not w["system_namespace"] and not w["windows"]]
    containers = [k for w in judged for k in w["containers"]]
    namespaces = [n for c in clusters for n in c["namespaces"] or [] if not n["system_namespace"]]
    hardened = sum(1 for w in judged if w["hardened"])

    def pod_count(value) -> Optional[int]:
        return value if pods_known else None

    def policy_count(value) -> Optional[int]:
        return value if policies_known else None

    def namespace_policy_count(value) -> Optional[int]:
        # Without the namespace list a namespace holding no pod and no policy would be missed.
        return value if (policies_known and namespaces_known) else None

    def containers_where(key: str) -> Optional[int]:
        return pod_count(sum(1 for k in containers if k[key]))

    return {
        "clusters_read": clusters_read,
        "clusters": len(clusters),
        "clusters_with_kubernetes_api_read": sum(1 for c in clusters if c["kubernetes_api_read"]),
        "clusters_with_kubernetes_api_unread": sum(1 for c in clusters if not c["kubernetes_api_read"]),
        "clusters_stopped": sum(1 for c in clusters if _lower(c["power_state"]) == STOPPED),
        "clusters_without_entra_integration": sum(1 for c in clusters if not c["entra_integrated"]),
        "clusters_enforcing_network_policies": sum(1 for c in clusters if c["network_policies_enforced"]),
        "clusters_without_network_policy_engine": sum(1 for c in clusters if not c["network_policies_enforced"]),
        "clusters_with_azure_policy_addon": sum(1 for c in clusters if c["azure_policy_addon_enabled"]),
        "system_namespaces": list(settings["system_namespaces"]),
        "namespaces": len(namespaces) if namespaces_known else None,
        "namespaces_enforcing_pod_security": (sum(1 for n in namespaces if n["pod_security_enforce"] in PSA_ENFORCING)
                                              if namespaces_known else None),
        "namespaces_enforcing_restricted_pod_security": (sum(1 for n in namespaces if n["pod_security_enforce"] == "restricted")
                                                         if namespaces_known else None),
        "namespaces_without_pod_security_enforcement": (sum(1 for n in namespaces if n["pod_security_enforce"] not in PSA_ENFORCING)
                                                        if namespaces_known else None),
        "network_policies": policy_count(sum(len([p for p in c["network_policies"] or []
                                                  if str(p["namespace"]).lower() not in settings["system_namespaces"]])
                                             for c in clusters)),
        "namespaces_with_network_policy": namespace_policy_count(sum(1 for n in namespaces if n["network_policies"])),
        "namespaces_without_network_policy": namespace_policy_count(sum(1 for n in namespaces if not n["network_policies"])),
        "namespaces_with_default_deny_ingress": namespace_policy_count(sum(1 for n in namespaces if n["default_deny_ingress"])),
        "namespaces_with_default_deny_egress": namespace_policy_count(sum(1 for n in namespaces if n["default_deny_egress"])),
        "pods": pod_count(sum(c["pods_running"] or 0 for c in clusters)),
        "pods_finished_skipped": pod_count(sum(c["pods_finished_skipped"] or 0 for c in clusters)),
        "system_workloads": pod_count(sum(1 for w in workloads if w["system_namespace"])),
        "windows_workloads": pod_count(sum(1 for w in workloads if w["windows"] and not w["system_namespace"])),
        "workloads": pod_count(len(judged)),
        "containers": pod_count(len(containers)),
        "containers_non_root_enforced": containers_where("non_root_enforced"),
        "containers_privilege_escalation_disabled": containers_where("privilege_escalation_disabled"),
        "containers_read_only_root_filesystem": containers_where("read_only_root_filesystem"),
        "containers_dropping_all_capabilities": containers_where("drops_all_capabilities"),
        "containers_with_added_capabilities": containers_where("added_capabilities"),
        "privileged_containers": containers_where("privileged"),
        "containers_with_seccomp_profile": pod_count(sum(1 for k in containers if k["seccomp_profile"] in SECCOMP_CONFINED)),
        "workloads_using_host_namespaces": pod_count(sum(1 for w in judged if w["uses_host_namespaces"])),
        "workloads_with_host_path_volumes": pod_count(sum(1 for w in judged if w["host_path_volumes"])),
        "workloads_hardened": pod_count(hardened),
        "workloads_not_hardened": pod_count(len(judged) - hardened),
        "workload_hardening_percentage": pod_count(coverage_percentage(hardened, len(judged))),
        "workloads_selected_by_network_policy": (sum(1 for w in judged if w["selected_by_network_policy"])
                                                 if (pods_known and policies_known) else None),
        "workloads_without_network_policy": (sum(1 for w in judged if w["selected_by_network_policy"] is False)
                                             if (pods_known and policies_known) else None),
        "workload_rows_truncated": any(c["workloads_truncated"] for c in clusters),
    }


# --- collection ---

def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None,
            settings: Optional[Dict[str, Any]] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    settings = settings if settings is not None else settings_from_env(collector)

    def _clusters():
        try:
            return client.list(f"/subscriptions/{subscription_id}/providers/Microsoft.ContainerService/managedClusters", AKS_API)
        except ArmError as exc:
            if exc.code.lower() == "missingsubscriptionregistration":
                return []  # a subscription that never registered the provider has no cluster
            raise

    listed = collector.guard("containerservice.managedClusters.list", _clusters)
    kept, excluded = exclusions.split(listed or [], "cluster")
    exclusions.record_invalid(collector)
    exclusions.warn_unmatched(logger)

    clusters = []
    for raw in sorted(kept, key=lambda c: arm_id_key(c.get("id"))):
        record = collector.guard(f"collect({raw.get('name')})", lambda raw=raw: collect_cluster(client, raw, settings, collector))
        if record is None:
            record = {**cluster_identity(raw), "kubernetes_api_read": False, "notes": [], "namespaces_read": None,
                      "pods_read": None, "network_policies_read": None, "namespaces": None, "network_policies": None,
                      "workloads": None, "workloads_truncated": None, "pods_running": None, "pods_finished_skipped": None}
        clusters.append(record)

    summary = {**summarize(clusters, listed is not None, settings),
               **exclusions.summary(excluded, ("cluster",), {"clusters": len(clusters) if listed is not None else None})}
    # The counts above cover every workload; the rows are cut only afterwards, least hardened first kept.
    for cluster in clusters:
        rows = cluster["workloads"]
        if rows is not None:
            cluster["workloads_truncated"] = len(rows) > settings["max_rows"]
            ordered = sorted(rows, key=lambda w: (w["system_namespace"], w["hardened"] is not False,
                                                  str(w["namespace"]), w["kind"], w["name"]))
            cluster["workloads"] = ordered[: settings["max_rows"]]
    summary["workload_rows_truncated"] = any(c["workloads_truncated"] for c in clusters)
    results = {"clusters": clusters, "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id")))}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
