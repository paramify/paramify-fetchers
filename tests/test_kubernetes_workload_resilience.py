"""kubernetes_workload_resilience, against raw responses captured from a real kube-apiserver v1.35.0
(tests/fixtures/kubernetes_workload_resilience). Three nodes in three zones; a resilient Deployment, one whose two
ready pods share a zone with no budget and no liveness probe, a single replica, a StatefulSet with a drain-blocking
budget, no readiness probe and one unready pod, one scaled to zero, one held at three by an autoscaler, and system
workloads. IDs are placeholders. The capture had no controllers running, so the pods' owner references and the
ReplicaSet list were added by hand, in the shape the API returns them.

The small clusters further down are built in code, one per review case: shared budgets, owners, zones, autoscalers.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from urllib3.exceptions import MaxRetryError, NewConnectionError

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


def unreachable(what):
    """What the Kubernetes client raises when nothing answers: urllib3's MaxRetryError, whose reason is an exception."""
    return MaxRetryError(None, f"/{what}", reason=NewConnectionError(None, "Failed to establish a new connection: [Errno 61] Connection refused"))


class _Api:
    """The four Kubernetes clients over the captured responses; `refused` names lists that answer 403, and
    `unreachable` makes every list fail as an API server that can't be reached does."""

    api_client = _Serializer()

    def __init__(self, refused=(), page_size=None, unreachable=False, data=None):
        self.refused, self.page_size, self.unreachable, self.calls, self.timeouts = set(refused), page_size, unreachable, [], []
        self.data = data

    def _list(self, what, cont, timeout):
        self.calls.append((what, cont))
        self.timeouts.append(timeout)
        if self.unreachable:
            raise unreachable(what)
        if what in self.refused:
            raise ApiError(403)
        body = {"items": self.data.get(what, []), "metadata": {}} if self.data is not None else fx(what)
        if not self.page_size:
            return body
        start = int(cont or 0)
        more = start + self.page_size < len(body["items"])
        return {**body, "items": body["items"][start:start + self.page_size], "metadata": {"continue": str(start + self.page_size) if more else None}}

    def list_deployment_for_all_namespaces(self, limit=None, _continue=None, _request_timeout=None):
        return self._list("deployments", _continue, _request_timeout)

    def list_stateful_set_for_all_namespaces(self, limit=None, _continue=None, _request_timeout=None):
        return self._list("statefulsets", _continue, _request_timeout)

    def list_pod_disruption_budget_for_all_namespaces(self, limit=None, _continue=None, _request_timeout=None):
        return self._list("poddisruptionbudgets", _continue, _request_timeout)

    def list_horizontal_pod_autoscaler_for_all_namespaces(self, limit=None, _continue=None, _request_timeout=None):
        return self._list("horizontalpodautoscalers", _continue, _request_timeout)

    def list_replica_set_for_all_namespaces(self, limit=None, _continue=None, _request_timeout=None):
        return self._list("replicasets", _continue, _request_timeout)

    def list_pod_for_all_namespaces(self, limit=None, _continue=None, _request_timeout=None):
        return self._list("pods", _continue, _request_timeout)

    def list_node(self, limit=None, _continue=None, _request_timeout=None):
        return self._list("nodes", _continue, _request_timeout)


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


def _owned(n, owner="dep-uid", labels=None):
    """n pods in namespace ns, controlled by `owner`, as budget_blocks_drains takes them."""
    return [({"metadata": {"namespace": "ns", "labels": labels or {"app": "a"}}}, owner) for _ in range(n)]


@pytest.mark.parametrize("spec, pods, blocks", [
    ({"maxUnavailable": 0}, 3, True), ({"maxUnavailable": "0%"}, 3, True), ({"maxUnavailable": 1}, 3, False),
    ({"maxUnavailable": "1%"}, 3, False),  # rounded up to one eviction
    ({"minAvailable": 3}, 3, True), ({"minAvailable": 2}, 3, False), ({"minAvailable": "100%"}, 3, True),
    ({"minAvailable": "90%"}, 3, True),  # 2.7 rounds up to 3, all of them
    ({"minAvailable": "67%"}, 3, True), ({"minAvailable": "66%"}, 3, False),  # 2.01 rounds to 3; 1.98 rounds to 2
    ({"minAvailable": "50%"}, 7, False),  # 3.5 rounds up to 4 of 7
    ({"minAvailable": "50%"}, 3, False), ({}, 3, False)])
def test_a_budget_blocks_drains_only_when_it_never_allows_an_eviction(spec, pods, blocks):
    budget = {"metadata": {"namespace": "ns"}, "spec": {"selector": {"matchLabels": {"app": "a"}}, **spec}}
    assert wr.budget_blocks_drains(budget, _owned(pods), {"dep-uid": pods}) is blocks


def test_a_percentage_budget_is_taken_of_the_controllers_replicas_not_the_pods_now_running():
    budget = {"metadata": {"namespace": "ns"}, "spec": {"selector": {"matchLabels": {"app": "a"}}, "minAvailable": "50%"}}
    # Two of four replicas run now. 50% is taken of the four: two must stay, fewer than four, so the budget allows evictions.
    assert wr.budget_blocks_drains(budget, _owned(2), {"dep-uid": 4}) is False
    budget["spec"]["minAvailable"] = 2
    # An integer is compared with the pods selected now, as the disruption controller does.
    assert wr.budget_blocks_drains(budget, _owned(2), {"dep-uid": 4}) is True


@pytest.mark.parametrize("pods, scale", [
    (None, {}),  # pods unread
    (_owned(3, owner=None), {}),  # a bare pod: no controller to take the percentage of
    (_owned(3, owner=wr.UNRESOLVED), {}),  # its ReplicaSet wasn't read
    (_owned(3, owner="job-uid"), {}),  # a controller whose replicas aren't read
])
def test_a_percentage_budget_whose_population_is_unknown_is_unknown(pods, scale):
    budget = {"metadata": {"namespace": "ns"}, "spec": {"selector": {"matchLabels": {"app": "a"}}, "minAvailable": "90%"}}
    assert wr.budget_blocks_drains(budget, pods, scale) is None


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


def test_refused_pods_leave_placement_and_counted_budgets_unknown_and_name_the_permission():
    ev, reader, _ = _collect(refused={"pods"})
    s = ev["summary"]
    assert (s["workloads_ready_pods_in_one_zone"], s["workloads_ready_pod_zones_unknown"], s["workloads_without_ready_pods"]) == (None, None, None)
    # storefront's minAvailable 2 is counted against the pods it selects, so with no pods it can't be judged.
    assert (s["workloads_with_pdb_blocking_drains"], s["workloads_with_pdb_effect_unknown"]) == (None, ["storefront/Deployment/web"])
    assert s["workloads_without_pdb"] == ["billing/Deployment/api", "web/Deployment/frontend"]
    assert reader.api_failures[0]["message"] == "needs: list pods (cluster-wide)" and reader.codes == ["not_authorized"]


def test_refused_replicasets_leave_deployment_placement_null_and_name_the_permission():
    ev, reader, _ = _collect(refused={"replicasets"})
    s, by = ev["summary"], {w["workload"]: w for w in ev["results"]["workloads"]}
    assert (s["workloads_ready_pods_in_one_zone"], s["workloads_without_ready_pods"]) == (None, None)
    assert by["billing/Deployment/api"]["ready_pods"] is None and by["billing/Deployment/api"]["ready_pod_zones"] is None
    # A StatefulSet controls its pods directly, so it doesn't need the ReplicaSets.
    assert by["warehouse/StatefulSet/db"]["ready_pods"] == 2
    assert reader.api_failures[0]["message"] == "needs: list replicasets.apps (cluster-wide)"


def test_nodes_without_zone_labels_leave_placement_unknown_not_passed():
    """The reviewed reproduction: no zone labels on the nodes gave an empty one-zone list, so a zone check passed."""
    nodes = fx("nodes")["items"]
    for n in nodes:
        n["metadata"]["labels"].pop(ZONE)
    data = {w: fx(w)["items"] for w in ("deployments", "statefulsets", "poddisruptionbudgets", "horizontalpodautoscalers", "replicasets", "pods")}
    ev, _, _ = _collect(data={**data, "nodes": nodes})
    s = ev["summary"]
    assert s["workloads_ready_pods_in_one_zone"] is None
    assert s["workloads_ready_pod_zones_unknown"] == ["billing/Deployment/api", "storefront/Deployment/web",
                                                      "warehouse/StatefulSet/db", "web/Deployment/frontend"]
    assert s["nodes_without_zone"] == ["node-a", "node-b", "node-c"]


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


def test_every_list_call_has_a_timeout():
    _, _, api = _collect()
    assert api.timeouts and all(t == wr.TIMEOUT for t in api.timeouts)


def test_an_unreachable_api_server_still_writes_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    api = _Api(unreachable=True)
    monkeypatch.setattr(wr, "clients", lambda context: (api, api, api, api))
    assert wr.main() == 1
    ev = json.loads((tmp_path / "kubernetes_workload_resilience.json").read_text())
    first = ev["metadata"]["api_failures"][0]
    assert first["type"] == "MaxRetryError" and "Connection refused" in first["message"]
    assert all(v is None for v in ev["summary"].values())
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "target_unreachable"


# --- small clusters built in code ---

def _uid(kind, name):
    return f"{kind}-{name}-uid"


def _deployment(name, replicas, labels, ns="ns"):
    return {"metadata": {"name": name, "namespace": ns, "uid": _uid("Deployment", name)},
            "spec": {"replicas": replicas, "selector": {"matchLabels": {"app": labels["app"]}},
                     "template": {"metadata": {"labels": labels}, "spec": {"containers": [{"name": "app"}]}}}}


def _replicaset(name, owner=None, ns="ns", replicas=1):
    refs = [{"apiVersion": "apps/v1", "kind": "Deployment", "name": owner, "uid": _uid("Deployment", owner), "controller": True}] if owner else []
    return {"metadata": {"name": name, "namespace": ns, "uid": _uid("ReplicaSet", name), "ownerReferences": refs}, "spec": {"replicas": replicas}}


def _pod(name, labels, node, owner=None, ns="ns", ready=True):
    kind, owner_name = owner or (None, None)
    refs = [{"apiVersion": "apps/v1", "kind": kind, "name": owner_name, "uid": _uid(kind, owner_name), "controller": True}] if owner else []
    return {"metadata": {"name": name, "namespace": ns, "labels": labels, "ownerReferences": refs},
            "spec": {"nodeName": node}, "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}}


def _node(name, zone=None):
    return {"metadata": {"name": name, "labels": {ZONE: zone} if zone else {}}}


def _budget(name, selector, ns="ns", **spec):
    return {"metadata": {"name": name, "namespace": ns}, "spec": {"selector": {"matchLabels": selector}, **spec}}


def _hpa(target, min_replicas, api_version="apps/v1", ns="ns"):
    return {"metadata": {"name": f"{target}-hpa", "namespace": ns},
            "spec": {"minReplicas": min_replicas, "scaleTargetRef": {"apiVersion": api_version, "kind": "Deployment", "name": target}}}


NODES = [_node("n1", "zone-1"), _node("n2", "zone-2"), _node("n3", "zone-3")]


def _cluster(deployments=(), replicasets=(), pods=(), nodes=NODES, pdbs=(), hpas=(), statefulsets=(), excluded=()):
    data = {"deployments": list(deployments), "statefulsets": list(statefulsets), "replicasets": list(replicasets),
            "pods": list(pods), "nodes": list(nodes), "poddisruptionbudgets": list(pdbs), "horizontalpodautoscalers": list(hpas)}
    ev, reader, _ = _collect(excluded=set(excluded), data=data)
    assert reader.api_failures == []
    return ev["summary"], {w["workload"]: w for w in ev["results"]["workloads"]}


def _app(name, replicas, nodes, labels=None, ns="ns"):
    """A Deployment, its ReplicaSet, and one ready pod per node named."""
    labels = labels or {"app": name}
    pods = [_pod(f"{name}-{i}", labels, n, ("ReplicaSet", f"{name}-rs"), ns) for i, n in enumerate(nodes)]
    return [_deployment(name, replicas, labels, ns)], [_replicaset(f"{name}-rs", name, ns, replicas)], pods


def test_ready_pods_on_nodes_without_a_zone_are_unknown_placement():
    d, r, p = _app("a", 2, ["bare-1", "bare-2"])
    s, by = _cluster(d, r, p, nodes=NODES + [_node("bare-1"), _node("bare-2")])
    assert (by["ns/Deployment/a"]["ready_pod_zones"], by["ns/Deployment/a"]["ready_pods_without_zone"]) == ([], 2)
    assert (s["workloads_ready_pods_in_one_zone"], s["workloads_ready_pod_zones_unknown"]) == (None, ["ns/Deployment/a"])


def test_a_ready_pod_on_a_node_that_is_not_listed_is_unknown_placement():
    d, r, p = _app("a", 2, ["n1", "gone"])
    s, by = _cluster(d, r, p)
    assert (by["ns/Deployment/a"]["ready_pod_zones"], by["ns/Deployment/a"]["ready_pods_without_zone"]) == (["zone-1"], 1)
    assert (s["workloads_ready_pods_in_one_zone"], s["workloads_ready_pod_zones_unknown"]) == (None, ["ns/Deployment/a"])


def test_two_known_zones_are_a_spread_even_with_a_pod_of_unknown_zone():
    d, r, p = _app("a", 3, ["n1", "n2", "bare"])
    d2, r2, p2 = _app("b", 2, ["n1", "n1"])
    s, _ = _cluster(d + d2, r + r2, p + p2, nodes=NODES + [_node("bare")])
    assert (s["workloads_ready_pods_in_one_zone"], s["workloads_ready_pod_zones_unknown"]) == (["ns/Deployment/b"], [])


def test_ready_pods_are_counted_by_controller_not_by_matching_labels():
    """A Deployment with no pods of its own, and another workload's pods carrying the labels its selector matches."""
    d, r, _ = _app("a", 2, [])
    stray = [_replicaset("other-rs")]  # a ReplicaSet no Deployment controls
    pods = [_pod(f"other-{i}", {"app": "a"}, n, ("ReplicaSet", "other-rs")) for i, n in enumerate(["n1", "n2"])]
    s, by = _cluster(d, r + stray, pods)
    assert (by["ns/Deployment/a"]["ready_pods"], by["ns/Deployment/a"]["ready_pod_zones"]) == (0, [])
    assert s["workloads_without_ready_pods"] == ["ns/Deployment/a"] and s["workloads_ready_pods_in_one_zone"] == []


def test_a_pod_whose_replicaset_was_not_listed_is_unattributed_and_leaves_placement_unknown():
    d, r, p = _app("a", 2, ["n1"])
    late = _pod("a-new", {"app": "a"}, "n1", ("ReplicaSet", "a-rs-created-after-the-list"))
    s, by = _cluster(d, r, p + [late])
    assert (by["ns/Deployment/a"]["ready_pods"], by["ns/Deployment/a"]["ready_pods_unattributed"]) == (1, 1)
    assert (s["workloads_ready_pods_in_one_zone"], s["workloads_ready_pod_zones_unknown"]) == (None, ["ns/Deployment/a"])


def test_a_shared_budget_is_judged_once_over_every_pod_it_selects():
    a = _app("a", 3, ["n1", "n2", "n3"], {"app": "a", "budget": "shared"})
    b = _app("b", 3, ["n1", "n2", "n3"], {"app": "b", "budget": "shared"})
    parts = [x + y for x, y in zip(a, b)]
    s, by = _cluster(*parts, pdbs=[_budget("shared", {"budget": "shared"}, minAvailable=3)])
    # Six pods, three must stay: three evictions allowed. Against each Deployment's three replicas it looked blocked.
    assert by["ns/Deployment/a"]["pdbs"] == ["shared"] and s["workloads_with_pdb_blocking_drains"] == []
    s, _ = _cluster(*parts, pdbs=[_budget("shared", {"budget": "shared"}, minAvailable=6)])
    assert s["workloads_with_pdb_blocking_drains"] == ["ns/Deployment/a", "ns/Deployment/b"]
    s, _ = _cluster(*parts, pdbs=[_budget("shared", {"budget": "shared"}, minAvailable="90%")])
    assert s["workloads_with_pdb_blocking_drains"] == ["ns/Deployment/a", "ns/Deployment/b"]  # 5.4 of six rounds up to six
    s, _ = _cluster(*parts, pdbs=[_budget("shared", {"budget": "shared"}, minAvailable="50%")])
    assert s["workloads_with_pdb_blocking_drains"] == []


def test_a_budget_whose_population_is_unknown_makes_the_drain_list_unknown():
    d, r, _ = _app("a", 2, [])
    bare = [_pod(f"a-{i}", {"app": "a"}, n) for i, n in enumerate(["n1", "n2"])]  # no controller: no replicas to take 50% of
    s, by = _cluster(d, r, bare, pdbs=[_budget("pdb", {"app": "a"}, minAvailable="50%")])
    assert by["ns/Deployment/a"]["pdb_blocks_disruption"] is None
    assert (s["workloads_with_pdb_blocking_drains"], s["workloads_with_pdb_effect_unknown"]) == (None, ["ns/Deployment/a"])


def test_the_autoscaler_floor_decides_single_replica_only():
    """Three ready replicas in one zone, no budget, and an autoscaler minimum of one: every check sees it."""
    d, r, p = _app("a", 3, ["n1", "n1", "n1"])
    s, by = _cluster(d, r, p, hpas=[_hpa("a", 1)])
    assert (by["ns/Deployment/a"]["autoscaled"], by["ns/Deployment/a"]["effective_min_replicas"]) == (True, 1)
    assert s["workloads_single_replica_names"] == ["ns/Deployment/a"]
    assert s["workloads_without_pdb"] == ["ns/Deployment/a"]
    assert s["workloads_ready_pods_in_one_zone"] == ["ns/Deployment/a"]
    assert s["workloads_without_zone_spread_config"] == ["ns/Deployment/a"]


@pytest.mark.parametrize("api_version, applies", [
    ("apps/v1", True), ("apps/v1beta2", True),  # any version of the apps group
    ("example.com/v1", False),  # a same-named Deployment custom resource
    (None, False)])  # no group: the autoscaler can't resolve its target either
def test_an_autoscaler_applies_only_to_a_target_in_the_apps_group(api_version, applies):
    d, r, p = _app("a", 3, ["n1", "n2", "n3"])
    hpa = _hpa("a", 5, api_version)
    s, by = _cluster(d, r, p, hpas=[hpa])
    assert (by["ns/Deployment/a"]["autoscaled"], by["ns/Deployment/a"]["effective_min_replicas"]) == ((True, 5) if applies else (False, 3))
