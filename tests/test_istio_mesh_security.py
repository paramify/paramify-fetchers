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

    def __init__(self, refused=(), page_size=None, istiod=None, configmaps=None, missing=()):
        self.refused, self.page_size, self.calls = set(refused), page_size, []
        self.istiod_fixture, self.configmaps, self.missing = istiod, configmaps or {}, set(missing)

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
        what = "root certificate" if name == "istio-ca-root-cert" else "mesh config"
        self.calls.append(("configmap", f"{namespace}/{name}"))
        if (namespace, name) in self.missing:
            raise ApiError(404)
        body = self.configmaps.get(name) or fx("configmap-root-cert" if name == "istio-ca-root-cert" else "configmap-istio")
        return self._page(what, body, None)

    # AppsV1Api
    def list_namespaced_deployment(self, namespace, label_selector=None, limit=None, _continue=None):
        self.calls.append(("deployments", namespace))
        body = self.istiod_fixture if self.istiod_fixture is not None else fx("deployments-istiod")
        return self._page("istiod", body, _continue)

    # CustomObjectsApi
    def list_cluster_custom_object(self, group, version, plural, limit=None, _continue=None):
        return self._page(plural, fx(plural), _continue)


def _reader(**kw):
    api = _Api(**kw)
    return im.MeshReader(api, api, api), api


def _summary(collect_kw=None, **kw):
    reader, api = _reader(**kw)
    return im.collect(reader, now=NOW, **(collect_kw or {})), reader, api


def test_real_mesh_gives_every_judgment(assert_summary_documented):
    ev, reader, _ = _summary()
    s = ev["summary"]
    assert reader.api_failures == []
    assert (s["namespaces"], s["namespaces_in_mesh"], s["namespaces_not_in_mesh"]) == (6, 4, ["default", "legacy"])
    assert (s["mesh_mtls_mode"], s["strict_mtls_everywhere"]) == ("STRICT", False)
    assert (s["mesh_mtls_policy"], s["mtls_policies_ignored"], s["authorization_policies_dry_run"]) == ("istio-system/default", [], [])
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
    assert im.mesh_mtls(pas, ROOT) == ("NONE", None)   # Istio applies PERMISSIVE
    assert im.mesh_mtls([{"metadata": {"namespace": ROOT, "name": "d"}, "spec": {}}], ROOT) == ("UNSET", f"{ROOT}/d")


def _pa(name, mode, created, ns=ROOT, **spec):
    meta = {"namespace": ns, "name": name, **({"creationTimestamp": created} if created else {})}
    return {"metadata": meta, "spec": {"mtls": {"mode": mode}, **spec}}


OLD_PERMISSIVE = _pa("old", "PERMISSIVE", "2026-01-01T00:00:00Z")
NEW_STRICT = _pa("new", "STRICT", "2026-06-01T00:00:00Z")


@pytest.mark.parametrize("order", [[NEW_STRICT, OLD_PERMISSIVE], [OLD_PERMISSIVE, NEW_STRICT]])
def test_the_oldest_mesh_wide_peer_authentication_wins_whatever_the_list_order(order):
    data = {k: fx(k)["items"] for k in ("namespaces", "authorizationpolicies", "gateways", "virtualservices", "destinationrules")}
    data["peerauthentications"] = order
    s = im.summarize(data, None, None, None, ROOT, NOW)
    assert (s["mesh_mtls_mode"], s["mesh_mtls_policy"]) == ("PERMISSIVE", f"{ROOT}/old")
    assert (s["strict_mtls_everywhere"], s["mtls_policies_ignored"]) == (False, [f"{ROOT}/new STRICT"])


def test_same_second_duplicates_are_ordered_by_name_as_istio_does():
    a, b = _pa("b-strict", "STRICT", "2026-01-01T00:00:00Z"), _pa("a-permissive", "PERMISSIVE", "2026-01-01T00:00:00Z")
    assert im.mesh_mtls([a, b], ROOT) == ("PERMISSIVE", f"{ROOT}/a-permissive")


def test_duplicates_without_creation_times_are_a_conflict_never_strict():
    data = {k: fx(k)["items"] for k in ("namespaces", "authorizationpolicies", "gateways", "virtualservices", "destinationrules")}
    data["peerauthentications"] = [_pa("x", "STRICT", None), _pa("y", "PERMISSIVE", None)]
    s = im.summarize(data, None, None, None, ROOT, NOW)
    assert (s["mesh_mtls_mode"], s["mesh_mtls_policy"], s["strict_mtls_everywhere"]) == ("CONFLICT", None, False)
    assert s["mtls_policies_ignored"] == []


def test_an_ignored_namespace_duplicate_is_not_an_override_but_the_one_in_effect_is():
    pas = [NEW_STRICT, _pa("old-weak", "PERMISSIVE", "2026-01-01T00:00:00Z", ns="shop"),
           _pa("new-strict", "STRICT", "2026-06-01T00:00:00Z", ns="shop"),
           _pa("new-weak", "DISABLE", "2026-07-01T00:00:00Z", ns="payments"),
           _pa("old-strict", "STRICT", "2026-02-01T00:00:00Z", ns="payments")]
    assert im.mtls_overrides(pas, ROOT) == ["shop/old-weak PERMISSIVE"]


def test_an_empty_selector_is_namespace_wide():
    assert im.mesh_mtls([_pa("d", "STRICT", None, selector={"matchLabels": {}})], ROOT) == ("STRICT", f"{ROOT}/d")


def test_a_mesh_wide_default_deny_covers_every_in_mesh_namespace():
    data = {k: fx(k)["items"] for k in ("namespaces", "peerauthentications", "gateways", "virtualservices", "destinationrules")}
    data["authorizationpolicies"] = [{"metadata": {"namespace": ROOT, "name": "deny-all"}, "spec": {}}]
    s = im.summarize(data, None, None, None, ROOT, NOW)
    assert (s["mesh_default_deny"], s["namespaces_in_mesh_with_default_deny"], s["namespaces_in_mesh_without_default_deny"]) == (True, 4, [])


@pytest.mark.parametrize("policy, deny, allow_all", [
    ({}, True, False), ({"action": "ALLOW"}, True, False), ({"action": "DENY"}, False, False),
    ({"selector": {"matchLabels": {"app": "x"}}}, False, False), ({"selector": {"matchLabels": {}}}, True, False),
    ({"rules": [{}]}, False, True),
    ({"action": "ALLOW", "rules": [{"from": [{"source": {"namespaces": ["a"]}}]}]}, False, False)])
def test_default_deny_and_allow_all_follow_istio_semantics(policy, deny, allow_all):
    p = {"metadata": {"namespace": "ns", "name": "p"}, "spec": policy}
    assert (im.is_default_deny(p), im.allows_all(p)) == (deny, allow_all)


@pytest.mark.parametrize("value, simulated", [("true", True), ("True", True), ("1", True), ("t", True),
                                              ("false", False), ("yes", False), (None, False)])
def test_a_dry_run_policy_is_never_enforced(value, simulated):
    annotations = {"istio.io/dry-run": value} if value is not None else {}
    for spec in ({}, {"rules": [{}]}):
        p = {"metadata": {"namespace": ROOT, "name": "p", "annotations": annotations}, "spec": spec}
        assert im.dry_run(p) is simulated
        assert (im.is_default_deny(p) or im.allows_all(p)) is not simulated


def test_a_dry_run_allow_nothing_is_not_mesh_wide_default_deny():
    data = {k: fx(k)["items"] for k in ("namespaces", "peerauthentications", "gateways", "virtualservices", "destinationrules")}
    simulated = {"metadata": {"namespace": ROOT, "name": "deny-all", "annotations": {"istio.io/dry-run": "true"}}, "spec": {}}
    data["authorizationpolicies"] = fx("authorizationpolicies")["items"] + [simulated]
    s = im.summarize(data, None, None, None, ROOT, NOW)
    assert (s["mesh_default_deny"], s["namespaces_in_mesh_with_default_deny"]) == (False, 2)
    assert s["namespaces_in_mesh_without_default_deny"] == ["ingress", "monitoring"]
    assert (s["authorization_policies"], s["authorization_policies_dry_run"]) == (6, [f"{ROOT}/deny-all"])


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


def _rule(subset_policy):
    return {"metadata": {"namespace": "payments", "name": "ledger"},
            "spec": {"host": "ledger", "trafficPolicy": {"tls": {"mode": "ISTIO_MUTUAL"}},
                     "subsets": [{"name": "v1", "labels": {"version": "v1"}},
                                 {"name": "v2", "labels": {"version": "v2"}, "trafficPolicy": subset_policy}]}}


@pytest.mark.parametrize("subset_policy, found", [
    ({"tls": {"mode": "DISABLE"}}, ["payments/ledger subset v2"]),
    ({"portLevelSettings": [{"port": {"number": 8443}, "tls": {"mode": "DISABLE"}}]}, ["payments/ledger:8443 subset v2"]),
    ({"tls": {"mode": "ISTIO_MUTUAL"}}, [])])
def test_a_subset_that_turns_tls_off_is_reported(subset_policy, found):
    assert im.tls_disabled([_rule(subset_policy)]) == found
    assert im.tls_disabled(fx("destinationrules")["items"] + [_rule(subset_policy)]) == ["legacy/legacy-db"] + found


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
    assert needs["root certificate"] == "needs: get configmaps in the control-plane namespace"
    assert reader.codes == ["not_authorized", "not_authorized"]


def test_a_revisioned_install_reads_its_own_mesh_config():
    ev, reader, api = _summary(collect_kw={"mesh_configmap": "istio-canary"}, missing={(ROOT, "istio")})
    assert reader.api_failures == [] and ev["summary"]["outbound_traffic_policy"] == "REGISTRY_ONLY"
    assert ("configmap", f"{ROOT}/istio-canary") in api.calls


def test_the_policy_root_comes_from_the_mesh_config_not_the_control_plane_namespace():
    """istiod and its ConfigMaps in istio-system, mesh-wide policy in policy-root (meshConfig.rootNamespace)."""
    mesh = {"data": {"mesh": "rootNamespace: policy-root\noutboundTrafficPolicy:\n  mode: REGISTRY_ONLY\n"}}
    reader, api = _reader(configmaps={"istio": mesh})
    reader.namespaces = lambda: fx("namespaces")["items"] + [{"metadata": {"name": "policy-root", "labels": {}}}]
    pas = [{"metadata": {"namespace": "policy-root", "name": "default"}, "spec": {"mtls": {"mode": "STRICT"}}}]
    aps = [{"metadata": {"namespace": "policy-root", "name": "deny-all"}, "spec": {}}]
    lists = {"peerauthentications": pas, "authorizationpolicies": aps}
    reader.custom_list = lambda group, plural: lists.get(plural, fx(plural)["items"])
    ev = im.collect(reader, control_plane=ROOT, root_setting="istio-system", now=NOW)
    s, r = ev["summary"], ev["results"]
    assert (r["root_namespace"], r["root_namespace_source"], r["control_plane_namespace"]) == ("policy-root", "mesh config", ROOT)
    assert (s["mesh_mtls_mode"], s["strict_mtls_everywhere"], s["mesh_default_deny"]) == ("STRICT", True, True)
    # The policy root is not a workload namespace, and the ConfigMaps and istiod are still read in the control plane.
    assert s["namespaces"] == 6 and s["workload_cert_ttl"] == "12h"
    assert ("configmap", f"{ROOT}/istio") in api.calls and ("deployments", ROOT) in api.calls


@pytest.mark.parametrize("mesh, setting, expected", [
    ({"root_namespace": "policy-root"}, None, ("policy-root", "mesh config")),
    ({"root_namespace": "policy-root"}, "other", ("policy-root", "mesh config")),
    (None, "other", ("other", "setting")),
    (None, None, ("cp", "control-plane namespace"))])
def test_policy_root_precedence(mesh, setting, expected):
    assert im.policy_root(mesh, setting, "cp") == expected


def test_a_mesh_config_without_root_namespace_uses_istios_default():
    assert im.mesh_settings({"data": {"mesh": "defaultConfig: {}\n"}})["root_namespace"] == "istio-system"


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
    assert im.mesh_settings({"data": {"mesh": "defaultConfig: {}\n"}})["outbound_traffic_policy"] == "ALLOW_ANY"
    assert im.mesh_settings({"data": {}})["outbound_traffic_policy"] == "ALLOW_ANY"


@pytest.mark.parametrize("configmaps, failed, null_fields", [
    ({"istio": {"data": {"mesh": "outboundTrafficPolicy: [unclosed"}}}, "mesh config", ["outbound_traffic_policy"]),
    ({"istio": {"data": {"mesh": "just a string"}}}, "mesh config", ["outbound_traffic_policy"]),
    ({"istio-ca-root-cert": {"data": {"root-cert.pem": "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"}}},
     "root certificate", ["root_certificates", "root_certificate_expires", "root_certificate_days_remaining"])])
def test_unparseable_content_is_a_recorded_failure_not_a_crash(configmaps, failed, null_fields):
    ev, reader, _ = _summary(configmaps=configmaps)
    s = ev["summary"]
    assert [f["operation"] for f in reader.api_failures] == [failed]
    assert reader.api_failures[0]["type"].startswith("unparseable") and reader.codes == ["partial_failure"]
    assert all(s[k] is None for k in null_fields)
    # Every other read still counts.
    assert (s["mesh_mtls_mode"], s["gateways"], s["workload_cert_ttl"]) == ("STRICT", 2, "12h")
    assert (s["outbound_traffic_policy"] is None) == (failed == "mesh config")
    assert (s["root_certificates"] is None) == (failed == "root certificate")


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
