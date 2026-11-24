"""Kubernetes workload resilience: replicas, PodDisruptionBudgets, zone spread and health probes for every Deployment
and StatefulSet, and where their ready pods actually run. GET and LIST through the Kubernetes API only.

Zone spread is judged from placement as well as configuration: the scheduler spreads pods across zones by default
even without an explicit constraint, so the evidence reports workloads whose ready pods all run in one zone, read
from the pods and their nodes' zone labels. A workload's pods are the ones it controls, followed through owner
references (pod, ReplicaSet, Deployment; or pod, StatefulSet), not every pod its selector matches. A ready pod whose
zone or owner can't be found makes the workload's placement unknown, never a pass.

Collection-failure convention (docs/authoring_fetcher_guide.md, step 3): a refused or failed call is recorded in
`api_failures` and leaves the fields that depend on it null; the run exits non-zero when `api_failures` is non-empty.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

NAME = "kubernetes_workload_resilience"
OUTPUT = "kubernetes_workload_resilience.json"
PAGE = 500
TIMEOUT = (10, 60)  # seconds to connect and to read; the client has no default, so a silent API server would hang the run
DEFAULT_EXCLUDED = "kube-system,kube-public,kube-node-lease"
DEFAULT_ZONE_LABEL = "topology.kubernetes.io/zone"
UNRESOLVED = "unresolved"  # a pod's controller is a ReplicaSet the ReplicaSet list didn't hold
CODES = {401: "auth_failed", 403: "not_authorized"}
NEEDS = {
    "deployments": "list deployments.apps (cluster-wide)",
    "statefulsets": "list statefulsets.apps (cluster-wide)",
    "poddisruptionbudgets": "list poddisruptionbudgets.policy (cluster-wide)",
    "horizontalpodautoscalers": "list horizontalpodautoscalers.autoscaling (cluster-wide)",
    "replicasets": "list replicasets.apps (cluster-wide)",
    "pods": "list pods (cluster-wide)",
    "nodes": "list nodes",
}

logger = logging.getLogger(NAME)


# --- pure transforms ---

def selector_matches(selector: Optional[Dict[str, Any]], labels: Dict[str, str]) -> bool:
    """Kubernetes label selector semantics (matchLabels and matchExpressions). An empty selector matches everything;
    a missing one matches nothing."""
    if selector is None:
        return False
    if any(labels.get(k) != v for k, v in (selector.get("matchLabels") or {}).items()):
        return False
    for e in selector.get("matchExpressions") or []:
        key, op, values = e.get("key"), e.get("operator"), e.get("values") or []
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def _meta(o: Dict[str, Any]) -> Dict[str, Any]:
    return o.get("metadata") or {}


def _ref(kind: str, o: Dict[str, Any]) -> str:
    return f"{_meta(o).get('namespace')}/{kind}/{_meta(o).get('name')}"


def _ready(pod: Dict[str, Any]) -> bool:
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in (pod.get("status") or {}).get("conditions") or [])


def spreads_by_config(template_spec: Dict[str, Any], zone_label: str) -> bool:
    """An explicit zone topology spread constraint, or pod anti-affinity across zones."""
    if any(c.get("topologyKey") == zone_label for c in template_spec.get("topologySpreadConstraints") or []):
        return True
    anti = (template_spec.get("affinity") or {}).get("podAntiAffinity") or {}
    terms = list(anti.get("requiredDuringSchedulingIgnoredDuringExecution") or [])
    terms += [t.get("podAffinityTerm") or {} for t in anti.get("preferredDuringSchedulingIgnoredDuringExecution") or []]
    return any(t.get("topologyKey") == zone_label for t in terms)


def _controller_ref(o: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return next((r for r in _meta(o).get("ownerReferences") or [] if r.get("controller")), None)


def _group(api_version: Any) -> Optional[str]:
    """The API group of an apiVersion: "apps/v1" is apps and "v1" is the core group (""). None when unset."""
    return str(api_version).rpartition("/")[0] if api_version else None


def hpa_targets(hpa: Dict[str, Any], kind: str, name: Any) -> bool:
    """An autoscaler whose scaleTargetRef names this apps-group workload, in any version of the group. A same-named
    Deployment custom resource in another group is a different object."""
    ref = (hpa.get("spec") or {}).get("scaleTargetRef") or {}
    return ref.get("kind") == kind and ref.get("name") == name and _group(ref.get("apiVersion")) == "apps"


def pod_controller(pod: Dict[str, Any], replicasets: Optional[Dict[str, Dict[str, Any]]]) -> Optional[str]:
    """The UID of the workload that controls a pod, followed through controller owner references: pod, ReplicaSet,
    Deployment; or pod, StatefulSet. A ReplicaSet that no Deployment controls is itself the workload. None for a pod
    with no controller; UNRESOLVED when the pod's ReplicaSet wasn't read (the list was refused, or the ReplicaSet was
    created after it was read)."""
    ref = _controller_ref(pod)
    if ref is None:
        return None
    if ref.get("kind") == "ReplicaSet" and _group(ref.get("apiVersion")) == "apps":
        rs = (replicasets or {}).get(str(ref.get("uid")))
        if rs is None:
            return UNRESOLVED
        top = _controller_ref(rs)
        if top is not None and top.get("kind") == "Deployment" and _group(top.get("apiVersion")) == "apps":
            return str(top.get("uid"))
    return str(ref.get("uid"))


def _percent(value: Any) -> Optional[int]:
    text = str(value).strip()
    return int(text[:-1]) if text.endswith("%") and text[:-1].isdigit() else None


def budget_blocks_drains(pdb: Dict[str, Any], pods: Optional[List[Tuple[Dict[str, Any], Optional[str]]]],
                         scale: Dict[str, int]) -> Optional[bool]:
    """Whether a budget allows no voluntary eviction even with every pod healthy, which blocks node drains (and so
    node patching). Judged once per budget, over every pod it selects, as the disruption controller counts them: an
    integer minAvailable against the number of selected pods; a percentage against the summed replicas of their
    controllers, rounded up. `pods` are the budget namespace's pods with their controller UIDs. None when the
    population can't be established."""
    spec = pdb.get("spec") or {}
    if spec.get("maxUnavailable") is not None:
        # Rounded up, any maxUnavailable above zero allows at least one eviction.
        return str(spec["maxUnavailable"]).strip() in ("0", "0%")
    minimum = spec.get("minAvailable")
    if minimum is None:
        return False
    if pods is None:
        return None
    selected = [owner for p, owner in pods if selector_matches(spec.get("selector"), _meta(p).get("labels") or {})]
    if isinstance(minimum, int):
        expected, desired = len(selected), minimum
    else:
        pct, controllers = _percent(minimum), set(selected)
        if pct is None or any(c is None or c not in scale for c in controllers):
            return None
        expected = sum(scale[str(c)] for c in controllers)
        desired = -(-pct * expected // 100)
    return expected > 0 and desired >= expected


def _any_known(values: List[Optional[bool]]) -> Optional[bool]:
    """True if any value is True; otherwise None if any is unknown; otherwise False."""
    return True if any(v is True for v in values) else None if any(v is None for v in values) else False


def workload_records(workloads: List[Tuple[str, Dict[str, Any]]], pdbs: Optional[List[Dict[str, Any]]],
                     hpas: Optional[List[Dict[str, Any]]], pods: Optional[List[Dict[str, Any]]],
                     replicasets: Optional[List[Dict[str, Any]]], zones: Optional[Dict[str, Optional[str]]],
                     zone_label: str) -> List[Dict[str, Any]]:
    """One record per Deployment or StatefulSet: replicas (with any autoscaler minimum), budgets, spread, probes, and
    its own ready pods (by controller, not by label) and the zones they run in. A budget selects pods in its own
    namespace only, and namespaces are excluded whole, so `workloads` holds every controller a budget can count.
    Fields that depend on an unread list are None."""
    rs_by_uid = {str(_meta(r).get("uid")): r for r in replicasets} if replicasets is not None else None
    scale = {str(_meta(o).get("uid")): (o.get("spec") or {}).get("replicas", 1)
             for o in [w for _, w in workloads] + list(replicasets or [])}
    by_ns: Dict[Any, List[Tuple[Dict[str, Any], Optional[str]]]] = {}
    for p in pods or []:
        by_ns.setdefault(_meta(p).get("namespace"), []).append((p, pod_controller(p, rs_by_uid)))
    budgets = {id(b): budget_blocks_drains(b, by_ns.get(_meta(b).get("namespace"), []) if pods is not None else None, scale)
               for b in pdbs or []}
    out = []
    for kind, w in workloads:
        m, spec = _meta(w), w.get("spec") or {}
        ns, name, uid = m.get("namespace"), m.get("name"), str(m.get("uid"))
        template = spec.get("template") or {}
        tspec, tlabels = template.get("spec") or {}, (template.get("metadata") or {}).get("labels") or {}
        hpa = next((h for h in hpas or [] if _meta(h).get("namespace") == ns and hpa_targets(h, kind, name)), None)
        replicas = spec.get("replicas", 1)
        effective = ((hpa.get("spec") or {}).get("minReplicas") or 1) if hpa else replicas
        mine = [p for p in pdbs or [] if _meta(p).get("namespace") == ns and selector_matches((p.get("spec") or {}).get("selector"), tlabels)]
        containers = tspec.get("containers") or []
        # A Deployment's pods are found through its ReplicaSets; a StatefulSet controls its pods directly.
        attributed = pods is not None and (kind == "StatefulSet" or rs_by_uid is not None)
        local = [(p, o) for p, o in by_ns.get(ns, []) if _ready(p)]
        owned = [p for p, o in local if o == uid]
        unattributed = [p for p, o in local if o == UNRESOLVED and kind == "Deployment"
                        and selector_matches(spec.get("selector"), _meta(p).get("labels") or {})]
        pod_zones = [(zones or {}).get(str((p.get("spec") or {}).get("nodeName") or "")) for p in owned]
        placed = attributed and zones is not None
        out.append({
            "workload": _ref(kind, w), "kind": kind, "replicas": replicas, "autoscaled": hpa is not None,
            "effective_min_replicas": effective,
            "pdbs": sorted(str(_meta(p).get("name")) for p in mine) if pdbs is not None else None,
            "pdb_blocks_disruption": _any_known([budgets[id(p)] for p in mine]) if pdbs is not None else None,
            "zone_spread_configured": spreads_by_config(tspec, zone_label),
            "containers_without_readiness_probe": sorted(c.get("name") for c in containers if not c.get("readinessProbe")),
            "containers_without_liveness_probe": sorted(c.get("name") for c in containers if not c.get("livenessProbe")),
            "ready_pods": len(owned) if attributed else None,
            "ready_pods_unattributed": len(unattributed) if attributed else None,
            "ready_pod_zones": sorted({z for z in pod_zones if z}) if placed else None,
            "ready_pods_without_zone": sum(1 for z in pod_zones if not z) if placed else None,
        })
    return out


def placement(w: Dict[str, Any]) -> str:
    """spread (ready pods in two or more known zones), one_zone, none (no ready pods), or unknown: a ready pod's zone
    or owner couldn't be found and the known zones don't already show a spread."""
    known = len(w["ready_pod_zones"])
    if known >= 2:
        return "spread"
    if w["ready_pods_without_zone"] or w["ready_pods_unattributed"]:
        return "unknown"
    return "one_zone" if known == 1 else "none"


def summarize(records: Optional[List[Dict[str, Any]]], zones: Optional[Dict[str, Optional[str]]],
              read: Dict[str, bool]) -> Dict[str, Any]:
    """Counts and names over the in-scope workloads. A workload at zero replicas is counted apart and not judged.
    The autoscaler minimum decides single replica; budgets, spread and placement are judged for every workload that
    runs two or more replicas now."""
    rs: List[Dict[str, Any]] = records or []
    zs: Dict[str, Optional[str]] = zones or {}
    active = [w for w in rs if w["replicas"] != 0]
    multi = [w for w in active if w["replicas"] >= 2]

    def names(items: List[Dict[str, Any]]) -> List[str]:
        return sorted(w["workload"] for w in items)

    wl = records is not None
    hpa, pdb = wl and read["horizontalpodautoscalers"], wl and read["poddisruptionbudgets"]
    pods = wl and read["pods"] and read["replicasets"]
    nodes, placed = zones is not None, pods and zones is not None
    pdb_unknown = names([w for w in active if w["pdb_blocks_disruption"] is None]) if pdb else []
    zone_unknown = names([w for w in multi if placement(w) == "unknown"]) if placed else []
    return {
        "workloads": len(rs) if wl else None,
        "workloads_scaled_to_zero": sum(1 for w in rs if w["replicas"] == 0) if wl else None,
        "workloads_autoscaled": sum(1 for w in active if w["autoscaled"]) if hpa else None,
        "workloads_single_replica": sum(1 for w in active if w["effective_min_replicas"] < 2) if hpa else None,
        "workloads_single_replica_names": names([w for w in active if w["effective_min_replicas"] < 2]) if hpa else None,
        "workloads_without_pdb": names([w for w in multi if not w["pdbs"]]) if pdb else None,
        "workloads_with_pdb_blocking_drains": names([w for w in active if w["pdb_blocks_disruption"]]) if pdb and not pdb_unknown else None,
        "workloads_with_pdb_effect_unknown": pdb_unknown if pdb else None,
        "workloads_without_zone_spread_config": names([w for w in multi if not w["zone_spread_configured"]]) if wl else None,
        "workloads_ready_pods_in_one_zone": names([w for w in multi if placement(w) == "one_zone"]) if placed and not zone_unknown else None,
        "workloads_ready_pod_zones_unknown": zone_unknown if placed else None,
        "workloads_without_ready_pods": names([w for w in active if w["ready_pods"] == 0 and w["ready_pods_unattributed"] == 0]) if pods else None,
        "workloads_without_readiness_probe": names([w for w in active if w["containers_without_readiness_probe"]]) if wl else None,
        "workloads_without_liveness_probe": names([w for w in active if w["containers_without_liveness_probe"]]) if wl else None,
        "zones": len({z for z in zs.values() if z}) if nodes else None,
        "nodes_without_zone": sorted(n for n, z in zs.items() if not z) if nodes else None,
    }


# --- collection ---

class ClusterReader:
    """LIST through the Kubernetes API, page by page; every failure is recorded and leaves its read None."""

    def __init__(self, apps: Any, core: Any, policy: Any, autoscaling: Any):
        self.apps, self.core, self.policy, self.autoscaling = apps, core, policy, autoscaling
        self.api_failures: List[Dict[str, Any]] = []
        self.codes: List[str] = []

    def pages(self, operation: str, call: Callable[..., Any], ser: Callable[[Any], Any]) -> Optional[List[Dict[str, Any]]]:
        items: List[Dict[str, Any]] = []
        token = None
        while True:
            try:
                page = ser(call(limit=PAGE, _continue=token, _request_timeout=TIMEOUT))
            except Exception as exc:  # noqa: BLE001 - boundary: record, don't crash the run
                status = getattr(exc, "status", None)
                detail = f"needs: {NEEDS.get(operation, operation)}" if status == 403 else str(getattr(exc, "reason", None) or exc)[:300]
                self.api_failures.append({"operation": operation, "type": f"HTTP {status}" if status else type(exc).__name__,
                                          "message": str(detail)})
                self.codes.append(CODES.get(int(status), "partial_failure") if status else "target_unreachable")
                logger.error("%s failed: %s", operation, status or type(exc).__name__)
                return None
            items.extend(page.get("items") or [])
            token = (page.get("metadata") or {}).get("continue")
            if not token:
                return items


def collect(reader: ClusterReader, excluded: Set[str], zone_label: str) -> Dict[str, Any]:
    def ser(api: Any) -> Callable[[Any], Any]:
        return api.api_client.sanitize_for_serialization

    data = {
        "deployments": reader.pages("deployments", reader.apps.list_deployment_for_all_namespaces, ser(reader.apps)),
        "statefulsets": reader.pages("statefulsets", reader.apps.list_stateful_set_for_all_namespaces, ser(reader.apps)),
        "poddisruptionbudgets": reader.pages("poddisruptionbudgets", reader.policy.list_pod_disruption_budget_for_all_namespaces, ser(reader.policy)),
        "horizontalpodautoscalers": reader.pages("horizontalpodautoscalers",
                                                 reader.autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces, ser(reader.autoscaling)),
        "replicasets": reader.pages("replicasets", reader.apps.list_replica_set_for_all_namespaces, ser(reader.apps)),
        "pods": reader.pages("pods", reader.core.list_pod_for_all_namespaces, ser(reader.core)),
        "nodes": reader.pages("nodes", reader.core.list_node, ser(reader.core)),
    }
    zones: Optional[Dict[str, Optional[str]]] = (
        {str(_meta(n).get("name")): (_meta(n).get("labels") or {}).get(zone_label) for n in data["nodes"]}
        if data["nodes"] is not None else None)

    def in_scope(o: Dict[str, Any]) -> bool:
        return _meta(o).get("namespace") not in excluded

    records = None
    if data["deployments"] is not None and data["statefulsets"] is not None:
        workloads = [("Deployment", d) for d in data["deployments"] if in_scope(d)] + [("StatefulSet", s) for s in data["statefulsets"] if in_scope(s)]
        records = workload_records(workloads, data["poddisruptionbudgets"], data["horizontalpodautoscalers"], data["pods"],
                                   data["replicasets"], zones, zone_label)
    read = {k: v is not None for k, v in data.items()}
    return {"results": {"workloads": records, "excluded_namespaces": sorted(excluded), "zone_label": zone_label},
            "summary": summarize(records, zones, read)}


def clients(context: Optional[str]) -> Tuple[Any, Any, Any, Any]:
    """Kubernetes API clients from the kubeconfig (KUBECONFIG, or ~/.kube/config), or the in-cluster service account."""
    from kubernetes import (  # lazy: keeps tests and discovery free of cluster access
        client,
        config,
    )

    try:
        config.load_kube_config(context=context or None)
    except config.ConfigException:
        if context:
            raise
        config.load_incluster_config()
    return client.AppsV1Api(), client.CoreV1Api(), client.PolicyV1Api(), client.AutoscalingV2Api()


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = os.environ.get("KUBERNETES_EXCLUDED_NAMESPACES")
    excluded = {n.strip() for n in (DEFAULT_EXCLUDED if raw is None else raw).split(",") if n.strip()}
    zone_label = (os.environ.get("KUBERNETES_ZONE_LABEL") or DEFAULT_ZONE_LABEL).strip()
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api_failures": []}
    evidence: Dict[str, Any] = {"results": {}, "summary": summarize(None, None, dict.fromkeys(NEEDS, False))}
    code = None
    try:
        reader = ClusterReader(*clients(os.environ.get("KUBERNETES_CONTEXT")))
    except Exception as exc:  # noqa: BLE001 - no kubeconfig, a missing context, or not in a cluster
        metadata["api_failures"] = [{"operation": "kubernetes config", "type": type(exc).__name__, "message": str(exc)[:300]}]
        code = "bad_config"
    else:
        evidence = collect(reader, excluded, zone_label)
        metadata["api_failures"] = reader.api_failures
        code = reader.codes[0] if reader.codes else None
    metadata["partial_failure"] = bool(metadata["api_failures"])
    path = out_dir / OUTPUT
    path.write_text(json.dumps({"metadata": metadata, **evidence}, indent=2, sort_keys=True))
    logger.info("Evidence saved to %s", path)
    if metadata["api_failures"]:
        first = metadata["api_failures"][0]
        report_failure(f"Kubernetes {first['operation']} failed: {first['type']}", code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
