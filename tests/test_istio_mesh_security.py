"""istio_mesh_security, against raw responses captured from a real kube-apiserver v1.35.0 with Istio 1.32.0's CRDs
(tests/fixtures/istio_mesh_security). The API server validated every Istio object against Istio's schemas. The mesh
has mesh-wide STRICT mTLS with a namespace PERMISSIVE override and a port-level DISABLE, default deny in two of four
in-mesh namespaces, an allow-all rule, a plaintext and a TLS 1.0 gateway server, a DestinationRule turning TLS off,
REGISTRY_ONLY egress, a generated root certificate and istiod's DEFAULT_WORKLOAD_CERT_TTL at 12h. IDs are placeholders.
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "istio_mesh_security"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
spec = importlib.util.spec_from_file_location("istio_mesh_security_under_test",
                                              REPO_ROOT / "fetchers" / "istio" / "mesh_security" / "fetcher.py")
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)

NOW = datetime(2026, 11, 18, 18, 0, tzinfo=timezone.utc)
ROOT = "istio-system"


def fx(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


class ApiError(Exception):
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status, self.reason = status, "Forbidden" if status == 403 else "Error"


class _Serializer:
    @staticmethod
    def sanitize_for_serialization(obj):
        return obj


class _Api:
    """The three Kubernetes clients over the captured responses; `refused` names reads that answer 403."""

    api_client = _Serializer()

    def __init__(self, refused=(), page_size=None, istiod=None):
        self.refused, self.page_size, self.calls = set(refused), page_size, []
        self.istiod_fixture = istiod

    def _page(self, what, body, cont):
        self.calls.append((what, cont))
        if what in self.refused:
            raise ApiError(403)
        if not self.page_size:
            return body
        start = int(cont or 0)
        items = body["items"][start:start + self.page_size]
        more = start + self.page_size < len(body["items"])
        return {**body, "items": items, "metadata": {"continue": str(start + self.page_size) if more else None}}

    # CoreV1Api
    def list_namespace(self, limit=None, _continue=None):
        return self._page("namespaces", fx("namespaces"), _continue)

    def read_namespaced_config_map(self, name, namespace):
        what = {"istio": "mesh config", "istio-ca-root-cert": "root certificate"}[name]
        return self._page(what, fx("configmap-istio" if name == "istio" else "configmap-root-cert"), None)

    # AppsV1Api
    def list_namespaced_deployment(self, namespace, label_selector=None, limit=None, _continue=None):
        body = self.istiod_fixture if self.istiod_fixture is not None else fx("deployments-istiod")
        return self._page("istiod", body, _continue)

    # CustomObjectsApi
    def list_cluster_custom_object(self, group, version, plural, limit=None, _continue=None):
        return self._page(plural, fx(plural), _continue)


def _reader(**kw):
    api = _Api(**kw)
    return im.MeshReader(api, api, api), api


def _summary(**kw):
    reader, api = _reader(**kw)
    return im.collect(reader, ROOT, NOW), reader, api


def test_real_mesh_gives_every_judgment(assert_summary_documented):
    ev, reader, _ = _summary()
    s = ev["summary"]
    assert reader.api_failures == []
    assert (s["namespaces"], s["namespaces_in_mesh"], s["namespaces_not_in_mesh"]) == (6, 4, ["default", "legacy"])
    assert (s["mesh_mtls_mode"], s["strict_mtls_everywhere"]) == ("STRICT", False)
    assert s["mtls_weaker_overrides_names"] == ["monitoring/scrape PERMISSIVE", "payments/metrics-port:9090 DISABLE"]
    assert (s["authorization_policies"], s["mesh_default_deny"], s["namespaces_in_mesh_with_default_deny"]) == (5, False, 2)
    assert s["namespaces_in_mesh_without_default_deny"] == ["ingress", "monitoring"]
    assert (s["authorization_policies_allowing_all"], s["authorization_deny_policies"]) == (["monitoring/allow-everything"], 1)
    assert (s["gateways"], s["gateway_servers"]) == (2, 4)
    # The HTTP server with an HTTPS redirect is not plaintext; the one without is.
    assert (s["gateway_servers_plaintext"], s["gateway_servers_weak_tls"]) == (["ingress/legacy-admin:8080"], ["ingress/legacy-admin:8443"])
    assert (s["destination_rules_tls_disabled"], s["outbound_traffic_policy"], s["virtual_services_on_gateways"]) == (["legacy/legacy-db"], "REGISTRY_ONLY", 1)
    assert (s["root_certificates"], s["root_certificate_expires"][:4]) == (1, "2036")
    assert (s["workload_cert_ttl"], s["workload_cert_ttl_hours"], s["workload_cert_ttl_source"]) == ("12h", 12.0, "setting")
    assert_summary_documented("istio/mesh_security", s)


def test_no_mesh_wide_policy_is_reported_as_none_never_strict():
    pas = [p for p in fx("peerauthentications")["items"] if p["metadata"]["namespace"] != ROOT]
    assert im.mesh_mtls_mode(pas, ROOT) == "NONE"   # Istio applies PERMISSIVE
    assert im.mesh_mtls_mode([{"metadata": {"namespace": ROOT}, "spec": {}}], ROOT) == "UNSET"


def test_a_mesh_wide_default_deny_covers_every_in_mesh_namespace():
    data = {k: fx(k)["items"] for k in ("namespaces", "peerauthentications", "gateways", "virtualservices", "destinationrules")}
    data["authorizationpolicies"] = [{"metadata": {"namespace": ROOT, "name": "deny-all"}, "spec": {}}]
    s = im.summarize(data, None, None, None, ROOT, NOW)
    assert (s["mesh_default_deny"], s["namespaces_in_mesh_with_default_deny"], s["namespaces_in_mesh_without_default_deny"]) == (True, 4, [])


@pytest.mark.parametrize("policy, deny, allow_all", [
    ({}, True, False), ({"action": "ALLOW"}, True, False), ({"action": "DENY"}, False, False),
    ({"selector": {"matchLabels": {"app": "x"}}}, False, False), ({"rules": [{}]}, False, True),
    ({"action": "ALLOW", "rules": [{"from": [{"source": {"namespaces": ["a"]}}]}]}, False, False)])
def test_default_deny_and_allow_all_follow_istio_semantics(policy, deny, allow_all):
    p = {"metadata": {"namespace": "ns", "name": "p"}, "spec": policy}
    assert (im.is_default_deny(p), im.allows_all(p)) == (deny, allow_all)


def test_a_plaintext_server_on_any_non_tls_protocol_is_reported():
    gws = fx("gateways")["items"]
    gws[1]["spec"]["servers"] += [{"hosts": ["*"], "port": {"name": "grpc", "number": 9000, "protocol": "GRPC"}},
                                  {"hosts": ["*"], "port": {"name": "mongo", "number": 27017, "protocol": "MONGO"}}]
    servers = im.gateway_servers(gws)
    assert len(servers) == 6
    assert sorted(s["server"] for s in servers if s["plaintext"]) == ["ingress/legacy-admin:8080", "ingress/public:27017",
                                                                      "ingress/public:9000"]


@pytest.mark.parametrize("protocol, tls, plaintext", [
    ("HTTP", None, True), ("HTTP", {"httpsRedirect": True}, False),
    # Istio never terminates TLS on an HTTP-family port, so a tls mode there does not make it encrypted.
    ("HTTP", {"mode": "SIMPLE"}, True), ("GRPC", None, True), ("GRPC-WEB", None, True), ("HTTP2", None, True),
    ("TCP", None, True), ("MONGO", None, True), ("MYSQL", None, True), ("REDIS", None, True),
    # A non-HTTP server with a tls block is a TLS server (PASSTHROUGH when no mode is set).
    ("TCP", {"mode": "SIMPLE"}, False), ("TCP", {}, False),
    ("HTTPS", {"mode": "SIMPLE"}, False), ("TLS", {"mode": "PASSTHROUGH"}, False)])
def test_plaintext_follows_istio_gateway_semantics(protocol, tls, plaintext):
    assert im.is_plaintext(protocol, tls) is plaintext


def test_lists_are_read_page_by_page():
    ev, _, api = _summary(page_size=2)
    assert ev["summary"]["namespaces"] == 6 and ev["summary"]["authorization_policies"] == 5
    assert [c for w, c in api.calls if w == "namespaces"][:2] == [None, "2"]


def test_a_refused_read_names_its_permission_and_leaves_only_its_fields_null():
    ev, reader, _ = _summary(refused={"authorizationpolicies", "root certificate"})
    s = ev["summary"]
    assert (s["authorization_policies"], s["mesh_default_deny"], s["namespaces_in_mesh_without_default_deny"]) == (None, None, None)
    assert (s["root_certificates"], s["root_certificate_expires"]) == (None, None)
    assert (s["mesh_mtls_mode"], s["gateways"]) == ("STRICT", 2)
    needs = {f["operation"]: f["message"] for f in reader.api_failures}
    assert needs["authorizationpolicies"] == "needs: list authorizationpolicies.security.istio.io (cluster-wide)"
    assert needs["root certificate"] == "needs: get configmaps in the root namespace"
    assert reader.codes == ["not_authorized", "not_authorized"]


def test_a_missing_istiod_is_said_rather_than_left_blank():
    ev, _, _ = _summary(istiod={"items": [], "metadata": {}})
    s = ev["summary"]
    assert (s["workload_cert_ttl"], s["workload_cert_ttl_source"]) == (None, "istiod_not_found")


def test_istiod_without_the_setting_uses_istios_default():
    d = fx("deployments-istiod")
    for c in d["items"][0]["spec"]["template"]["spec"]["containers"]:
        c["env"] = []
    assert im.workload_cert_ttl(d["items"]) == ("24h", "default")


@pytest.mark.parametrize("value, hours", [("24h", 24.0), ("90m", 1.5), ("1h30m", 1.5), ("2160h", 2160.0), ("", None), ("1d", None), ("12", None)])
def test_go_durations(value, hours):
    assert im.go_duration_hours(value) == hours


def test_outbound_policy_defaults_to_allow_any():
    assert im.outbound_policy({"data": {"mesh": "defaultConfig: {}\n"}}) == "ALLOW_ANY"
    assert im.outbound_policy(None) is None


def test_without_a_kubeconfig_or_a_cluster_the_run_is_bad_config(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "missing-kubeconfig"))
    for name in ("KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT", "ISTIO_KUBE_CONTEXT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert im.main() == 1
    ev = json.loads((tmp_path / "istio_mesh_security.json").read_text())
    assert ev["metadata"]["api_failures"][0]["operation"] == "kubernetes config"
    assert all(v is None for v in ev["summary"].values())
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"
