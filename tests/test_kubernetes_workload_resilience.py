"""kubernetes_workload_resilience, against raw responses captured from a real kube-apiserver v1.35.0
(tests/fixtures/kubernetes_workload_resilience). Three nodes in three zones; a resilient Deployment, one whose two
ready pods share a zone with no budget and no liveness probe, a single replica, a StatefulSet with a drain-blocking
budget, no readiness probe and one unready pod, one scaled to zero, one held at three by an autoscaler, and system
workloads. IDs are placeholders.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "kubernetes_workload_resilience"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
spec = importlib.util.spec_from_file_location("kubernetes_workload_resilience_under_test",
                                              REPO_ROOT / "fetchers" / "kubernetes" / "workload_resilience" / "fetcher.py")
wr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wr)

EXCLUDED = {"kube-system", "kube-public", "kube-node-lease"}
ZONE = "topology.kubernetes.io/zone"


def fx(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


class ApiError(Exception):
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status, self.reason = status, "Forbidden"


class _Serializer:
    @staticmethod
    def sanitize_for_serialization(obj):
        return obj


class _Api:
    """The four Kubernetes clients over the captured responses; `refused` names lists that answer 403."""

    api_client = _Serializer()

    def __init__(self, refused=(), page_size=None):
        self.refused, self.page_size, self.calls = set(refused), page_size, []

    def _list(self, what, cont):
        self.calls.append((what, cont))
        if what in self.refused:
            raise ApiError(403)
        body = fx(what)
        if not self.page_size:
            return body
        start = int(cont or 0)
        more = start + self.page_size < len(body["items"])
        return {**body, "items": body["items"][start:start + self.page_size], "metadata": {"continue": str(start + self.page_size) if more else None}}

    def list_deployment_for_all_namespaces(self, limit=None, _continue=None):
        return self._list("deployments", _continue)

    def list_stateful_set_for_all_namespaces(self, limit=None, _continue=None):
        return self._list("statefulsets", _continue)

    def list_pod_disruption_budget_for_all_namespaces(self, limit=None, _continue=None):
        return self._list("poddisruptionbudgets", _continue)

    def list_horizontal_pod_autoscaler_for_all_namespaces(self, limit=None, _continue=None):
        return self._list("horizontalpodautoscalers", _continue)

    def list_pod_for_all_namespaces(self, limit=None, _continue=None):
        return self._list("pods", _continue)

    def list_node(self, limit=None, _continue=None):
        return self._list("nodes", _continue)


def _collect(excluded=EXCLUDED, **kw):
    api = _Api(**kw)
    reader = wr.ClusterReader(api, api, api, api)
    return wr.collect(reader, excluded, ZONE), reader, api


def test_real_cluster_gives_every_judgment(assert_summary_documented):
    ev, reader, _ = _collect()
    s = ev["summary"]
    assert reader.api_failures == []
    assert (s["workloads"], s["workloads_scaled_to_zero"], s["workloads_autoscaled"], s["zones"], s["nodes_without_zone"]) == (7, 1, 1, 3, [])
    assert s["workloads_single_replica_names"] == ["istio-system/Deployment/istiod", "reports/Deployment/worker"]
    assert s["workloads_without_pdb"] == ["billing/Deployment/api", "web/Deployment/frontend"]
    assert s["workloads_with_pdb_blocking_drains"] == ["warehouse/StatefulSet/db"]
    # frontend has no spread configuration, yet its ready pods run in all three zones: placement, not config, decides.
    assert s["workloads_without_zone_spread_config"] == ["billing/Deployment/api", "web/Deployment/frontend"]
    assert s["workloads_ready_pods_in_one_zone"] == ["billing/Deployment/api"]
    assert s["workloads_without_readiness_probe"] == ["istio-system/Deployment/istiod", "warehouse/StatefulSet/db"]
    assert s["workloads_without_liveness_probe"] == ["billing/Deployment/api", "istio-system/Deployment/istiod"]
    assert all("kube-system/" not in w["workload"] for w in ev["results"]["workloads"])
    assert_summary_documented("kubernetes/workload_resilience", s)


@pytest.mark.parametrize("selector, labels, matches", [
    ({"matchLabels": {"app": "a"}}, {"app": "a", "tier": "x"}, True), ({"matchLabels": {"app": "a"}}, {"app": "b"}, False),
    ({"matchExpressions": [{"key": "tier", "operator": "In", "values": ["x", "y"]}]}, {"tier": "y"}, True),
    ({"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["x"]}]}, {"tier": "x"}, False),
    ({"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["x"]}]}, {}, True),
    ({"matchExpressions": [{"key": "tier", "operator": "Exists"}]}, {}, False),
    ({"matchExpressions": [{"key": "tier", "operator": "DoesNotExist"}]}, {}, True),
    ({}, {"anything": "1"}, True), (None, {"app": "a"}, False)])
def test_label_selectors_follow_kubernetes_semantics(selector, labels, matches):
    assert wr.selector_matches(selector, labels) is matches


@pytest.mark.parametrize("spec, replicas, blocks", [
    ({"maxUnavailable": 0}, 3, True), ({"maxUnavailable": "0%"}, 3, True), ({"maxUnavailable": 1}, 3, False),
    ({"minAvailable": 3}, 3, True), ({"minAvailable": 2}, 3, False), ({"minAvailable": "100%"}, 3, True),
    ({"minAvailable": "50%"}, 3, False), ({}, 3, False)])
def test_a_budget_blocks_drains_only_when_it_never_allows_an_eviction(spec, replicas, blocks):
    assert wr.blocks_disruption({"spec": spec}, replicas) is blocks


def test_an_autoscaler_minimum_decides_single_replica():
    [frontend] = [w for w in _collect()[0]["results"]["workloads"] if w["workload"] == "web/Deployment/frontend"]
    assert (frontend["autoscaled"], frontend["effective_min_replicas"]) == (True, 3)


def test_spread_by_anti_affinity_counts_as_configured():
    [db] = [w for w in _collect()[0]["results"]["workloads"] if w["workload"] == "warehouse/StatefulSet/db"]
    assert db["zone_spread_configured"] is True and db["ready_pod_zones"] == ["zone-1", "zone-2"]


def test_lists_are_read_page_by_page():
    ev, _, api = _collect(page_size=3)
    assert ev["summary"]["workloads"] == 7
    assert [c for w, c in api.calls if w == "pods"][:3] == [None, "3", "6"]


def test_refused_pods_leave_only_placement_null_and_name_the_permission():
    ev, reader, _ = _collect(refused={"pods"})
    s = ev["summary"]
    assert (s["workloads_ready_pods_in_one_zone"], s["workloads_without_ready_pods"]) == (None, None)
    assert s["workloads_with_pdb_blocking_drains"] == ["warehouse/StatefulSet/db"]
    assert reader.api_failures[0]["message"] == "needs: list pods (cluster-wide)" and reader.codes == ["not_authorized"]


def test_refused_workload_lists_leave_every_workload_field_null():
    ev, _, _ = _collect(refused={"statefulsets"})
    s = ev["summary"]
    assert all(s[k] is None for k in s if k not in ("zones", "nodes_without_zone"))
    assert s["zones"] == 3


def test_no_excluded_namespaces_includes_system_workloads():
    ev, _, _ = _collect(excluded=set())
    assert ev["summary"]["workloads"] == 8
    assert any(w["workload"] == "kube-system/Deployment/coredns" for w in ev["results"]["workloads"])


def test_without_a_kubeconfig_or_a_cluster_the_run_is_bad_config(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "missing-kubeconfig"))
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in ("KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT", "KUBERNETES_CONTEXT"):
        monkeypatch.delenv(name, raising=False)
    assert wr.main() == 1
    ev = json.loads((tmp_path / "kubernetes_workload_resilience.json").read_text())
    assert ev["metadata"]["api_failures"][0]["operation"] == "kubernetes config"
    assert all(v is None for v in ev["summary"].values())
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"
