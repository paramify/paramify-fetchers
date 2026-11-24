"""Kubernetes workload resilience: replicas, PodDisruptionBudgets, zone spread and health probes for every Deployment
and StatefulSet, and where their ready pods actually run. GET and LIST through the Kubernetes API only.

Zone spread is judged from placement as well as configuration: the scheduler spreads pods across zones by default
even without an explicit constraint, so the evidence reports workloads whose ready pods all run in one zone, read
from the pods and their nodes' zone labels.

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
CODES = {401: "auth_failed", 403: "not_authorized"}
NEEDS = {
    "deployments": "list deployments.apps (cluster-wide)",
    "statefulsets": "list statefulsets.apps (cluster-wide)",
    "poddisruptionbudgets": "list poddisruptionbudgets.policy (cluster-wide)",
    "horizontalpodautoscalers": "list horizontalpodautoscalers.autoscaling (cluster-wide)",
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


def blocks_disruption(pdb: Dict[str, Any], replicas: Optional[int]) -> bool:
    """A budget that never allows a voluntary eviction, which blocks node drains (and so node patching)."""
    spec = pdb.get("spec") or {}
    if "maxUnavailable" in spec:
        return str(spec["maxUnavailable"]).strip() in ("0", "0%")
    minimum = spec.get("minAvailable")
    if minimum is None:
        return False
    if str(minimum).strip() == "100%":
        return True
    return isinstance(minimum, int) and replicas is not None and minimum >= replicas


def workload_records(workloads: List[Tuple[str, Dict[str, Any]]], pdbs: Optional[List[Dict[str, Any]]],
                     hpas: Optional[List[Dict[str, Any]]], pods: Optional[List[Dict[str, Any]]],
                     zones: Optional[Dict[str, Optional[str]]], zone_label: str) -> List[Dict[str, Any]]:
    """One record per Deployment or StatefulSet: replicas (with any autoscaler minimum), budget, spread, probes and the
    zones its ready pods run in. Fields that depend on an unread list are None."""
    out = []
    for kind, w in workloads:
        m, spec = _meta(w), w.get("spec") or {}
        ns, name = m.get("namespace"), m.get("name")
        template = spec.get("template") or {}
        tspec, tlabels = template.get("spec") or {}, (template.get("metadata") or {}).get("labels") or {}
        hpa = next((h for h in hpas or [] if _meta(h).get("namespace") == ns
                    and ((h.get("spec") or {}).get("scaleTargetRef") or {}).get("kind") == kind
                    and ((h.get("spec") or {}).get("scaleTargetRef") or {}).get("name") == name), None)
        replicas = spec.get("replicas", 1)
        effective = ((hpa.get("spec") or {}).get("minReplicas") or 1) if hpa else replicas
        mine = [p for p in pdbs or [] if _meta(p).get("namespace") == ns and selector_matches((p.get("spec") or {}).get("selector"), tlabels)]
        containers = tspec.get("containers") or []
        ready_pods = [p for p in pods or [] if _meta(p).get("namespace") == ns and _ready(p)
                      and selector_matches(spec.get("selector"), _meta(p).get("labels") or {})]
        pod_zones = sorted({z for z in ((zones or {}).get(str((p.get("spec") or {}).get("nodeName") or "")) for p in ready_pods) if z})
        out.append({
            "workload": _ref(kind, w), "kind": kind, "replicas": replicas, "autoscaled": hpa is not None,
            "effective_min_replicas": effective,
            "pdbs": sorted(str(_meta(p).get("name")) for p in mine) if pdbs is not None else None,
            "pdb_blocks_disruption": any(blocks_disruption(p, replicas) for p in mine) if pdbs is not None else None,
            "zone_spread_configured": spreads_by_config(tspec, zone_label),
            "containers_without_readiness_probe": sorted(c.get("name") for c in containers if not c.get("readinessProbe")),
            "containers_without_liveness_probe": sorted(c.get("name") for c in containers if not c.get("livenessProbe")),
            "ready_pods": len(ready_pods) if pods is not None else None,
            "ready_pod_zones": pod_zones if pods is not None and zones is not None else None,
        })
    return out


def summarize(records: Optional[List[Dict[str, Any]]], zones: Optional[Dict[str, Optional[str]]],
              read: Dict[str, bool]) -> Dict[str, Any]:
    """Counts and names over the in-scope workloads. A workload at zero replicas is counted apart and not judged."""
    r = records
    rs: List[Dict[str, Any]] = records or []
    zs: Dict[str, Optional[str]] = zones or {}
    active = [w for w in rs if w["replicas"] != 0]
    multi = [w for w in active if w["effective_min_replicas"] >= 2]

    def names(items: List[Dict[str, Any]]) -> List[str]:
        return sorted(w["workload"] for w in items)

    wl, pdb, pods, nodes = r is not None, read["poddisruptionbudgets"] and r is not None, read["pods"] and r is not None, zones is not None
    one_zone = [w for w in multi if w["ready_pod_zones"] is not None and len(w["ready_pod_zones"]) == 1]
    return {
        "workloads": len(rs) if wl else None,
        "workloads_scaled_to_zero": sum(1 for w in rs if w["replicas"] == 0) if wl else None,
        "workloads_autoscaled": sum(1 for w in active if w["autoscaled"]) if wl and read["horizontalpodautoscalers"] else None,
        "workloads_single_replica": len(active) - len(multi) if wl and read["horizontalpodautoscalers"] else None,
        "workloads_single_replica_names": names([w for w in active if w not in multi]) if wl and read["horizontalpodautoscalers"] else None,
        "workloads_without_pdb": names([w for w in multi if not w["pdbs"]]) if pdb else None,
        "workloads_with_pdb_blocking_drains": names([w for w in active if w["pdb_blocks_disruption"]]) if pdb else None,
        "workloads_without_zone_spread_config": names([w for w in multi if not w["zone_spread_configured"]]) if wl else None,
        "workloads_ready_pods_in_one_zone": names(one_zone) if pods and nodes else None,
        "workloads_without_ready_pods": names([w for w in active if w["ready_pods"] == 0]) if pods else None,
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
        records = workload_records(workloads, data["poddisruptionbudgets"], data["horizontalpodautoscalers"], data["pods"], zones, zone_label)
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
