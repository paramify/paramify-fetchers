"""Istio mesh security: mTLS policy, authorization policies, ingress gateways, destination rules, mesh configuration
and the mesh root certificate, read through the Kubernetes API (GET and LIST only).

Judgments follow Istio's documented semantics. With no mesh-wide PeerAuthentication, Istio's default (PERMISSIVE)
applies, so an absent policy is never reported as strict. An AuthorizationPolicy with no rules and no selector is
Istio's "allow nothing" (a default deny); an ALLOW rule that is empty matches every request. The root certificate is
read from the public istio-ca-root-cert ConfigMap, which holds no private key.

Collection-failure convention (docs/authoring_fetcher_guide.md, step 3): a refused or failed call is recorded in
`api_failures` and leaves the fields that depend on it null; the run exits non-zero when `api_failures` is non-empty.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml
from cryptography import x509
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

NAME = "istio_mesh_security"
OUTPUT = "istio_mesh_security.json"
PAGE = 500
# Seconds to connect and to wait for each response, so an unreachable API server fails the read instead of holding
# the run until the runner's own limit.
REQUEST_TIMEOUT = (10, 60)
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
WEAK_MTLS = frozenset({"PERMISSIVE", "DISABLE"})
OLD_TLS = frozenset({"TLSV1_0", "TLSV1_1"})
# Istio's HTTP-family protocols (protocol.IsHTTP): a server with one of these never terminates TLS, whatever its tls
# block says; only tls.httpsRedirect changes what it does. Istio's validation rejects any other TLS setting on them.
HTTP_PROTOCOLS = frozenset({"HTTP", "HTTP2", "HTTP_PROXY", "GRPC", "GRPC-WEB"})
TLS_PROTOCOLS = frozenset({"HTTPS", "TLS"})
DEFAULT_WORKLOAD_CERT_TTL = "24h"  # istiod's default when DEFAULT_WORKLOAD_CERT_TTL is not set
ISTIO_SYSTEM = "istio-system"  # Istio's default for both the control-plane namespace and meshConfig.rootNamespace
DEFAULT_MESH_CONFIGMAP = "istio"  # istio-<revision> for a revisioned install
CODES = {401: "auth_failed", 403: "not_authorized"}
# What each read needs, so a refusal names the exact permission.
NEEDS = {
    "namespaces": "list namespaces (cluster-wide)",
    "peerauthentications": "list peerauthentications.security.istio.io (cluster-wide)",
    "authorizationpolicies": "list authorizationpolicies.security.istio.io (cluster-wide)",
    "gateways": "list gateways.networking.istio.io (cluster-wide)",
    "virtualservices": "list virtualservices.networking.istio.io (cluster-wide)",
    "destinationrules": "list destinationrules.networking.istio.io (cluster-wide)",
    "mesh config": "get the mesh config ConfigMap in the control-plane namespace",
    "root certificate": "get configmaps in the control-plane namespace",
    "istiod": "list deployments in the control-plane namespace",
}

logger = logging.getLogger(NAME)


# --- pure transforms ---

def _ref(o: Dict[str, Any]) -> str:
    m = o.get("metadata") or {}
    return f"{m.get('namespace')}/{m.get('name')}"


def in_mesh(ns: Dict[str, Any]) -> bool:
    """A namespace is in the mesh when it is in ambient mode (istio.io/dataplane-mode=ambient) or sidecar injection is
    on for it: istio-injection=enabled, or an istio.io/rev label with no istio-injection label, which takes precedence
    (Istio's injection webhooks match the revision label only where istio-injection does not exist)."""
    labels = (ns.get("metadata") or {}).get("labels") or {}
    return (labels.get("istio.io/dataplane-mode") == "ambient" or labels.get("istio-injection") == "enabled"
            or (bool(labels.get("istio.io/rev")) and "istio-injection" not in labels))


def _selects_workloads(spec: Dict[str, Any]) -> bool:
    """True when a policy's selector names labels. Istio treats a missing or empty selector as the whole namespace."""
    return bool((spec.get("selector") or {}).get("matchLabels"))


def _created(p: Dict[str, Any]) -> Optional[datetime]:
    value = (p.get("metadata") or {}).get("creationTimestamp")
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def namespace_wide_policies(policies: List[Dict[str, Any]]) -> Tuple[Dict[str, Optional[Dict[str, Any]]], List[Dict[str, Any]]]:
    """The selector-less PeerAuthentication Istio applies in each namespace, and the ones it ignores.

    Istio uses one per namespace: the oldest by creationTimestamp, then by name (pilot/pkg/model/authentication.go).
    When a namespace has more than one and a timestamp is missing, the one in effect can't be told: it maps to None
    and none of them is listed as ignored.
    """
    by_ns: Dict[str, List[Dict[str, Any]]] = {}
    for p in policies:
        if not _selects_workloads(p.get("spec") or {}):
            by_ns.setdefault((p.get("metadata") or {}).get("namespace") or "", []).append(p)
    effective: Dict[str, Optional[Dict[str, Any]]] = {}
    ignored: List[Dict[str, Any]] = []
    for ns, found in by_ns.items():
        if len(found) > 1 and any(_created(p) is None for p in found):
            effective[ns] = None
            continue
        found = sorted(found, key=lambda p: (_created(p) or datetime.min.replace(tzinfo=timezone.utc),
                                             (p.get("metadata") or {}).get("name") or ""))
        effective[ns], ignored = found[0], ignored + found[1:]
    return effective, ignored


def _mtls_mode(p: Dict[str, Any]) -> str:
    return (((p.get("spec") or {}).get("mtls") or {}).get("mode") or "UNSET").upper()


def mtls_overrides(policies: List[Dict[str, Any]], root: str) -> List[str]:
    """Namespace-, workload- and port-level PeerAuthentication settings weaker than STRICT, named down to the port.
    A namespace-wide policy that Istio ignores (a newer duplicate) is not an override."""
    effective, ignored = namespace_wide_policies(policies)
    skip = {id(p) for p in ignored}
    out = []
    for p in policies:
        if id(p) in skip:
            continue
        spec = p.get("spec") or {}
        mode = _mtls_mode(p)
        mesh_wide = (p.get("metadata") or {}).get("namespace") == root and not _selects_workloads(spec)
        if not mesh_wide and mode in WEAK_MTLS:
            out.append(f"{_ref(p)} {mode}")
        for port, setting in sorted((spec.get("portLevelMtls") or {}).items()):
            port_mode = ((setting or {}).get("mode") or "").upper()
            if port_mode in WEAK_MTLS:
                out.append(f"{_ref(p)}:{port} {port_mode}")
    return sorted(out)


def mesh_mtls(policies: List[Dict[str, Any]], root: str) -> Tuple[str, Optional[str]]:
    """The mesh-wide mTLS mode and the policy that sets it: the root namespace's selector-less PeerAuthentication in
    effect. NONE when there is none (Istio then applies PERMISSIVE); CONFLICT when there are several and the one in
    effect can't be told."""
    effective, _ = namespace_wide_policies(policies)
    if root not in effective:
        return "NONE", None
    p = effective[root]
    return ("CONFLICT", None) if p is None else (_mtls_mode(p), _ref(p))


def dry_run(p: Dict[str, Any]) -> bool:
    """An AuthorizationPolicy annotated istio.io/dry-run is only simulated, never enforced. Istio reads the value with
    Go's strconv.ParseBool."""
    value = ((p.get("metadata") or {}).get("annotations") or {}).get("istio.io/dry-run")
    return str(value) in ("1", "t", "T", "true", "TRUE", "True")


def is_default_deny(p: Dict[str, Any]) -> bool:
    """Istio's allow-nothing policy: ALLOW (the default action) with no rules and no selector or target, and enforced
    (not dry-run)."""
    spec = p.get("spec") or {}
    return ((spec.get("action") or "ALLOW").upper() == "ALLOW" and not spec.get("rules") and not _selects_workloads(spec)
            and not spec.get("targetRef") and not spec.get("targetRefs") and not spec.get("provider") and not dry_run(p))


def allows_all(p: Dict[str, Any]) -> bool:
    """An enforced ALLOW policy with an empty rule, which matches every request to the workloads it selects."""
    spec = p.get("spec") or {}
    return ((spec.get("action") or "ALLOW").upper() == "ALLOW" and any(r == {} for r in spec.get("rules") or [])
            and not dry_run(p))


def is_plaintext(protocol: str, tls: Optional[Dict[str, Any]]) -> bool:
    """Whether a Gateway server takes traffic without TLS, by Istio's rules (pkg/config/gateway):
    HTTPS and TLS servers use TLS; an HTTP-family server (HTTP, HTTP2, GRPC, GRPC-WEB) is plaintext unless it redirects
    to HTTPS; any other protocol (TCP, MONGO, MYSQL, REDIS) is plaintext unless it has a tls block."""
    if protocol in TLS_PROTOCOLS:
        return False
    if protocol in HTTP_PROTOCOLS:
        return not (tls or {}).get("httpsRedirect")
    return tls is None


def gateway_servers(gateways: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each Gateway server: plaintext by is_plaintext; weak TLS when its minimum is below TLS 1.2."""
    out = []
    for g in gateways:
        for s in (g.get("spec") or {}).get("servers") or []:
            port = s.get("port") or {}
            tls = s.get("tls") or {}
            protocol = (port.get("protocol") or "").upper()
            out.append({"server": f"{_ref(g)}:{port.get('number')}", "protocol": protocol, "tls_mode": tls.get("mode"),
                        "https_redirect": bool(tls.get("httpsRedirect")), "min_tls_version": tls.get("minProtocolVersion"),
                        "plaintext": is_plaintext(protocol, s.get("tls")),
                        "weak_tls": (tls.get("minProtocolVersion") or "").upper() in OLD_TLS})
    return out


def tls_disabled(rules: List[Dict[str, Any]]) -> List[str]:
    """DestinationRules that turn TLS off (tls.mode DISABLE) for a host or a port, in the rule's trafficPolicy or in a
    subset's, which overrides the rule's for traffic routed to that subset."""
    out = []
    for r in rules:
        spec = r.get("spec") or {}
        policies = [("", spec.get("trafficPolicy"))]
        policies += [(f" subset {s.get('name')}", s.get("trafficPolicy")) for s in spec.get("subsets") or []]
        for subset, policy in policies:
            policy = policy or {}
            if ((policy.get("tls") or {}).get("mode") or "").upper() == "DISABLE":
                out.append(f"{_ref(r)}{subset}")
            for p in policy.get("portLevelSettings") or []:
                if ((p.get("tls") or {}).get("mode") or "").upper() == "DISABLE":
                    out.append(f"{_ref(r)}:{(p.get('port') or {}).get('number')}{subset}")
    return sorted(out)


def mesh_settings(configmap: Dict[str, Any]) -> Dict[str, Any]:
    """The settings read from the mesh config's `mesh` YAML. Raises ValueError (or a YAML error) when it isn't a mapping."""
    mesh = yaml.safe_load((configmap.get("data") or {}).get("mesh") or "") or {}
    if not isinstance(mesh, dict):
        raise ValueError(f"mesh is a YAML {type(mesh).__name__}, not a mapping")
    outbound = mesh.get("outboundTrafficPolicy") or {}
    if not isinstance(outbound, dict):
        raise ValueError("mesh outboundTrafficPolicy is not a mapping")
    root = mesh.get("rootNamespace")
    if root is not None and not isinstance(root, str):
        raise ValueError("mesh rootNamespace is not a string")
    # Istio's defaults: ALLOW_ANY when the mode isn't set, istio-system when rootNamespace isn't.
    return {"outbound_traffic_policy": str(outbound.get("mode") or "ALLOW_ANY").upper(),
            "root_namespace": root or ISTIO_SYSTEM}


def policy_root(mesh: Optional[Dict[str, Any]], setting: Optional[str], control_plane: str) -> Tuple[str, str]:
    """The root namespace for mesh-wide policy, and where it came from. The mesh config is what Istio uses, so it wins
    when it was read. Without it, the root_namespace setting, else the control-plane namespace."""
    if mesh is not None:
        if setting and setting != mesh["root_namespace"]:
            logger.warning("root_namespace %s ignored: the mesh config sets %s", setting, mesh["root_namespace"])
        return mesh["root_namespace"], "mesh config"
    return (setting, "setting") if setting else (control_plane, "control-plane namespace")


def root_certificates(configmap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Each certificate in istio-ca-root-cert (more than one during a rotation): subject and expiry. Public data only.
    Raises ValueError when the PEM can't be parsed."""
    pem = ((configmap.get("data") or {}).get("root-cert.pem") or "").encode()
    certs = x509.load_pem_x509_certificates(pem) if pem.strip() else []
    return [{"subject": c.subject.rfc4514_string(), "not_after": c.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")} for c in certs]


def go_duration_hours(value: Optional[str]) -> Optional[float]:
    """A Go duration such as 24h, 90m or 1h30m, in hours; None when it isn't one."""
    parts = re.findall(r"(\d+(?:\.\d+)?)(h|m|s)", value or "")
    if not parts or "".join(n + u for n, u in parts) != (value or "").strip():
        return None
    return round(sum(float(n) * {"h": 1, "m": 1 / 60, "s": 1 / 3600}[u] for n, u in parts), 3)


def istiod_cert_ttls(deployments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each istiod Deployment (one per revision) with its workload certificate lifetime and where it came from."""
    out = []
    for d in deployments:
        value = None
        for c in (((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []:
            for e in c.get("env") or []:
                if e.get("name") == "DEFAULT_WORKLOAD_CERT_TTL" and e.get("value"):
                    value = e["value"]
        out.append({"deployment": _ref(d), "revision": ((d.get("metadata") or {}).get("labels") or {}).get("istio.io/rev"),
                    "workload_cert_ttl": value or DEFAULT_WORKLOAD_CERT_TTL, "source": "setting" if value else "default"})
    return out


def workload_cert_ttl(deployments: Optional[List[Dict[str, Any]]]) -> Tuple[Optional[str], Optional[str]]:
    """The longest workload certificate lifetime any istiod revision issues, and where it came from (setting or
    default); (None, None) when unread. A value that is not a Go duration can't be compared, so it is the one reported."""
    if deployments is None:
        return None, None
    if not deployments:
        # No istiod in the control-plane namespace (such as a managed control plane elsewhere): say so.
        return None, "istiod_not_found"

    def length(r: Dict[str, Any]) -> Tuple[bool, float, bool]:
        hours = go_duration_hours(r["workload_cert_ttl"])
        return hours is None, hours or 0.0, r["source"] == "setting"

    longest = max(istiod_cert_ttls(deployments), key=length)
    return longest["workload_cert_ttl"], longest["source"]


def summarize(data: Dict[str, Optional[List[Dict[str, Any]]]], mesh: Optional[Dict[str, Any]],
              certs: Optional[List[Dict[str, Any]]], istiod: Optional[List[Dict[str, Any]]], root: str,
              now: datetime, control_plane: str = ISTIO_SYSTEM) -> Dict[str, Any]:
    """What is configured, never a verdict beyond Istio's own rules. Each group is null when the read behind it failed."""
    ns, pas, aps, gws, vss, drs = (data.get(k) for k in ("namespaces", "peerauthentications", "authorizationpolicies",
                                                           "gateways", "virtualservices", "destinationrules"))
    istio_namespaces = SYSTEM_NAMESPACES | {root, control_plane}
    workload = [n for n in ns or [] if (n.get("metadata") or {}).get("name") not in istio_namespaces]
    meshed = [n for n in workload if in_mesh(n)]
    names = {(n.get("metadata") or {}).get("name") for n in meshed}
    deny_ns = {(p.get("metadata") or {}).get("namespace") for p in aps or [] if is_default_deny(p)}
    mode, mode_policy = mesh_mtls(pas, root) if pas is not None else (None, None)
    ignored_pas = namespace_wide_policies(pas)[1] if pas is not None else None
    weaker = mtls_overrides(pas, root) if pas is not None else None
    servers = gateway_servers(gws) if gws is not None else None
    earliest = min((c["not_after"] for c in certs), default=None) if certs else None
    ttl, ttl_source = workload_cert_ttl(istiod)
    return {
        # Mesh membership
        "namespaces": len(workload) if ns is not None else None,
        "namespaces_in_mesh": len(meshed) if ns is not None else None,
        "namespaces_not_in_mesh": sorted(set(n["metadata"]["name"] for n in workload) - names) if ns is not None else None,
        # mTLS
        "mesh_mtls_mode": mode,
        "mesh_mtls_policy": mode_policy,
        "mtls_policies_ignored": sorted(f"{_ref(p)} {_mtls_mode(p)}" for p in ignored_pas) if ignored_pas is not None else None,
        "mtls_weaker_overrides": len(weaker) if weaker is not None else None,
        "mtls_weaker_overrides_names": weaker,
        "strict_mtls_everywhere": (mode == "STRICT" and not weaker) if pas is not None else None,
        # Authorization
        "authorization_policies": len(aps) if aps is not None else None,
        "mesh_default_deny": (root in deny_ns) if aps is not None else None,
        "namespaces_in_mesh_with_default_deny": (len(names & deny_ns) if root not in deny_ns else len(names))
        if aps is not None and ns is not None else None,
        "namespaces_in_mesh_without_default_deny": (sorted(names - deny_ns) if root not in deny_ns else [])
        if aps is not None and ns is not None else None,
        "authorization_policies_allowing_all": sorted(_ref(p) for p in aps if allows_all(p)) if aps is not None else None,
        "authorization_deny_policies": sum(1 for p in aps if ((p.get("spec") or {}).get("action") or "").upper() == "DENY"
                                           and not dry_run(p)) if aps is not None else None,
        "authorization_policies_dry_run": sorted(_ref(p) for p in aps if dry_run(p)) if aps is not None else None,
        # Ingress
        "gateways": len(gws) if gws is not None else None,
        "gateway_servers": len(servers) if servers is not None else None,
        "gateway_servers_plaintext": sorted(s["server"] for s in servers if s["plaintext"]) if servers is not None else None,
        "gateway_servers_weak_tls": sorted(s["server"] for s in servers if s["weak_tls"]) if servers is not None else None,
        "virtual_services_on_gateways": sum(1 for v in vss if (v.get("spec") or {}).get("gateways")) if vss is not None else None,
        # Traffic policy
        "destination_rules_tls_disabled": tls_disabled(drs) if drs is not None else None,
        "outbound_traffic_policy": mesh["outbound_traffic_policy"] if mesh is not None else None,
        # Certificates
        "root_certificates": len(certs) if certs is not None else None,
        "root_certificate_expires": earliest,
        "root_certificate_days_remaining": (datetime.fromisoformat(earliest.replace("Z", "+00:00")) - now).days if earliest else None,
        "workload_cert_ttl": ttl,
        "workload_cert_ttl_hours": go_duration_hours(ttl),
        "workload_cert_ttl_source": ttl_source,
    }


# --- collection ---

class MeshReader:
    """GET and LIST through the Kubernetes API; every failure is recorded and leaves its read None."""

    def __init__(self, core: Any, apps: Any, custom: Any):
        self.core, self.apps, self.custom = core, apps, custom
        self.api_failures: List[Dict[str, Any]] = []
        self.codes: List[str] = []

    def _call(self, operation: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - boundary: record, don't crash the run
            status = getattr(exc, "status", None)
            detail = f"needs: {NEEDS.get(operation, operation)}" if status == 403 else (getattr(exc, "reason", None) or str(exc))[:300]
            self.api_failures.append({"operation": operation, "type": f"HTTP {status}" if status else type(exc).__name__,
                                      "message": str(detail)})
            self.codes.append(CODES.get(int(status), "partial_failure") if status else "target_unreachable")
            logger.error("%s failed: %s", operation, status or type(exc).__name__)
            return None

    def parse(self, operation: str, fn: Callable[[], Any]) -> Any:
        """Parse what a read returned; content that can't be parsed is recorded like a failed read and leaves None."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - boundary: one bad value must not lose every other read
            self.api_failures.append({"operation": operation, "type": f"unparseable ({type(exc).__name__})",
                                      "message": str(exc)[:300]})
            self.codes.append("partial_failure")
            logger.error("%s could not be parsed: %s", operation, type(exc).__name__)
            return None

    def _pages(self, operation: str, fetch: Callable[[Optional[str]], Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        items: List[Dict[str, Any]] = []
        token = None
        while True:
            page = self._call(operation, lambda: fetch(token))
            if page is None:
                return None
            items.extend(page.get("items") or [])
            token = (page.get("metadata") or {}).get("continue")
            if not token:
                return items

    def namespaces(self) -> Optional[List[Dict[str, Any]]]:
        ser = self.core.api_client.sanitize_for_serialization
        return self._pages("namespaces", lambda t: ser(self.core.list_namespace(limit=PAGE, _continue=t,
                                                                                _request_timeout=REQUEST_TIMEOUT)))

    def custom_list(self, group: str, plural: str) -> Optional[List[Dict[str, Any]]]:
        return self._pages(plural, lambda t: self.custom.list_cluster_custom_object(
            group, "v1", plural, limit=PAGE, _continue=t, _request_timeout=REQUEST_TIMEOUT))

    def configmap(self, operation: str, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        ser = self.core.api_client.sanitize_for_serialization
        return self._call(operation, lambda: ser(self.core.read_namespaced_config_map(name, namespace,
                                                                                      _request_timeout=REQUEST_TIMEOUT)))

    def istiod(self, namespace: str) -> Optional[List[Dict[str, Any]]]:
        ser = self.apps.api_client.sanitize_for_serialization
        return self._pages("istiod", lambda t: ser(self.apps.list_namespaced_deployment(
            namespace, label_selector="app=istiod", limit=PAGE, _continue=t, _request_timeout=REQUEST_TIMEOUT)))


def collect(reader: MeshReader, control_plane: str = ISTIO_SYSTEM, mesh_configmap: str = DEFAULT_MESH_CONFIGMAP,
            root_setting: Optional[str] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    data = {"namespaces": reader.namespaces()}
    for group, plural in (("security.istio.io", "peerauthentications"), ("security.istio.io", "authorizationpolicies"),
                          ("networking.istio.io", "gateways"), ("networking.istio.io", "virtualservices"),
                          ("networking.istio.io", "destinationrules")):
        data[plural] = reader.custom_list(group, plural)
    mesh_config = reader.configmap("mesh config", mesh_configmap, control_plane)
    mesh = reader.parse("mesh config", lambda: mesh_settings(mesh_config)) if mesh_config is not None else None
    root, root_source = policy_root(mesh, root_setting, control_plane)
    root_cert = reader.configmap("root certificate", "istio-ca-root-cert", control_plane)
    certs = reader.parse("root certificate", lambda: root_certificates(root_cert)) if root_cert is not None else None
    istiod = reader.istiod(control_plane)
    results = {
        "root_namespace": root,
        "root_namespace_source": root_source,
        "control_plane_namespace": control_plane,
        "mesh_config": f"{control_plane}/{mesh_configmap}",
        "peer_authentications": [{"ref": _ref(p), "selector": _selects_workloads(p.get("spec") or {}),
                                  "created": (p.get("metadata") or {}).get("creationTimestamp"),
                                  "mode": ((p.get("spec") or {}).get("mtls") or {}).get("mode"),
                                  "port_level": (p.get("spec") or {}).get("portLevelMtls")} for p in data["peerauthentications"]]
        if data["peerauthentications"] is not None else None,
        "authorization_policies": [{"ref": _ref(p), "action": (p.get("spec") or {}).get("action") or "ALLOW",
                                    "rules": len((p.get("spec") or {}).get("rules") or []), "dry_run": dry_run(p),
                                    "default_deny": is_default_deny(p),
                                    "allows_all": allows_all(p)} for p in data["authorizationpolicies"]]
        if data["authorizationpolicies"] is not None else None,
        "gateway_servers": gateway_servers(data["gateways"]) if data["gateways"] is not None else None,
        "root_certificates": certs,
        "istiod": istiod_cert_ttls(istiod) if istiod is not None else None,
    }
    return {"results": results, "summary": summarize(data, mesh, certs, istiod, root, now, control_plane)}


def clients(context: Optional[str]) -> Tuple[Any, Any, Any]:
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
    return client.CoreV1Api(), client.AppsV1Api(), client.CustomObjectsApi()


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    control_plane = (os.environ.get("ISTIO_CONTROL_PLANE_NAMESPACE") or "").strip() or ISTIO_SYSTEM
    mesh_configmap = (os.environ.get("ISTIO_MESH_CONFIGMAP") or "").strip() or DEFAULT_MESH_CONFIGMAP
    root_setting = (os.environ.get("ISTIO_ROOT_NAMESPACE") or "").strip() or None
    now = datetime.now(timezone.utc)
    metadata: Dict[str, Any] = {"datetime": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "control_plane_namespace": control_plane,
                                "root_namespace": root_setting or control_plane, "api_failures": []}
    evidence: Dict[str, Any] = {"results": {}, "summary": summarize({}, None, None, None, metadata["root_namespace"], now)}
    code = None
    try:
        reader = MeshReader(*clients(os.environ.get("ISTIO_KUBE_CONTEXT")))
    except Exception as exc:  # noqa: BLE001 - no kubeconfig, a missing context, or not in a cluster
        metadata["api_failures"] = [{"operation": "kubernetes config", "type": type(exc).__name__, "message": str(exc)[:300]}]
        code = "bad_config"
    else:
        evidence = collect(reader, control_plane, mesh_configmap, root_setting, now)
        metadata["root_namespace"] = evidence["results"]["root_namespace"]
        metadata["api_failures"] = reader.api_failures
        code = reader.codes[0] if reader.codes else None
    metadata["partial_failure"] = bool(metadata["api_failures"])
    path = out_dir / OUTPUT
    path.write_text(json.dumps({"metadata": metadata, **evidence}, indent=2, sort_keys=True))
    logger.info("Evidence saved to %s", path)
    if metadata["api_failures"]:
        first = metadata["api_failures"][0]
        report_failure(f"Istio {first['operation']} failed: {first['type']}", code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
