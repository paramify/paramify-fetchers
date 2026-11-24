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
SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
WEAK_MTLS = frozenset({"PERMISSIVE", "DISABLE"})
OLD_TLS = frozenset({"TLSV1_0", "TLSV1_1"})
# Istio's HTTP-family protocols (protocol.IsHTTP): a server with one of these never terminates TLS, whatever its tls
# block says; only tls.httpsRedirect changes what it does. Istio's validation rejects any other TLS setting on them.
HTTP_PROTOCOLS = frozenset({"HTTP", "HTTP2", "HTTP_PROXY", "GRPC", "GRPC-WEB"})
TLS_PROTOCOLS = frozenset({"HTTPS", "TLS"})
DEFAULT_WORKLOAD_CERT_TTL = "24h"  # istiod's default when DEFAULT_WORKLOAD_CERT_TTL is not set
CODES = {401: "auth_failed", 403: "not_authorized"}
# What each read needs, so a refusal names the exact permission.
NEEDS = {
    "namespaces": "list namespaces (cluster-wide)",
    "peerauthentications": "list peerauthentications.security.istio.io (cluster-wide)",
    "authorizationpolicies": "list authorizationpolicies.security.istio.io (cluster-wide)",
    "gateways": "list gateways.networking.istio.io (cluster-wide)",
    "virtualservices": "list virtualservices.networking.istio.io (cluster-wide)",
    "destinationrules": "list destinationrules.networking.istio.io (cluster-wide)",
    "mesh config": "get configmaps in the root namespace",
    "root certificate": "get configmaps in the root namespace",
    "istiod": "list deployments in the root namespace",
}

logger = logging.getLogger(NAME)


# --- pure transforms ---

def _ref(o: Dict[str, Any]) -> str:
    m = o.get("metadata") or {}
    return f"{m.get('namespace')}/{m.get('name')}"


def in_mesh(ns: Dict[str, Any]) -> bool:
    """A namespace is in the mesh when sidecar injection is enabled for it, by label or by revision."""
    labels = (ns.get("metadata") or {}).get("labels") or {}
    return labels.get("istio-injection") == "enabled" or bool(labels.get("istio.io/rev"))


def mtls_overrides(policies: List[Dict[str, Any]], root: str) -> List[str]:
    """Namespace-, workload- and port-level PeerAuthentication settings weaker than STRICT, named down to the port."""
    out = []
    for p in policies:
        spec = p.get("spec") or {}
        mode = ((spec.get("mtls") or {}).get("mode") or "").upper()
        mesh_wide = (p.get("metadata") or {}).get("namespace") == root and not spec.get("selector")
        if not mesh_wide and mode in WEAK_MTLS:
            out.append(f"{_ref(p)} {mode}")
        for port, setting in sorted((spec.get("portLevelMtls") or {}).items()):
            port_mode = ((setting or {}).get("mode") or "").upper()
            if port_mode in WEAK_MTLS:
                out.append(f"{_ref(p)}:{port} {port_mode}")
    return sorted(out)


def mesh_mtls_mode(policies: List[Dict[str, Any]], root: str) -> str:
    """The root namespace's selector-less PeerAuthentication mode; NONE when there is none (Istio then applies PERMISSIVE)."""
    for p in policies:
        spec = p.get("spec") or {}
        if (p.get("metadata") or {}).get("namespace") == root and not spec.get("selector"):
            return ((spec.get("mtls") or {}).get("mode") or "UNSET").upper()
    return "NONE"


def is_default_deny(p: Dict[str, Any]) -> bool:
    """Istio's allow-nothing policy: ALLOW (the default action) with no rules and no selector or target."""
    spec = p.get("spec") or {}
    return ((spec.get("action") or "ALLOW").upper() == "ALLOW" and not spec.get("rules") and not spec.get("selector")
            and not spec.get("targetRef") and not spec.get("targetRefs") and not spec.get("provider"))


def allows_all(p: Dict[str, Any]) -> bool:
    """An ALLOW policy with an empty rule, which matches every request to the workloads it selects."""
    spec = p.get("spec") or {}
    return (spec.get("action") or "ALLOW").upper() == "ALLOW" and any(r == {} for r in spec.get("rules") or [])


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
    """DestinationRules that turn TLS off for a host or a port (trafficPolicy.tls.mode DISABLE)."""
    out = []
    for r in rules:
        policy = (r.get("spec") or {}).get("trafficPolicy") or {}
        if ((policy.get("tls") or {}).get("mode") or "").upper() == "DISABLE":
            out.append(_ref(r))
        for p in policy.get("portLevelSettings") or []:
            if ((p.get("tls") or {}).get("mode") or "").upper() == "DISABLE":
                out.append(f"{_ref(r)}:{(p.get('port') or {}).get('number')}")
    return sorted(out)


def outbound_policy(configmap: Optional[Dict[str, Any]]) -> Optional[str]:
    """outboundTrafficPolicy.mode from the mesh config; Istio's default is ALLOW_ANY when it isn't set."""
    if configmap is None:
        return None
    mesh = yaml.safe_load((configmap.get("data") or {}).get("mesh") or "") or {}
    return ((mesh.get("outboundTrafficPolicy") or {}).get("mode") or "ALLOW_ANY").upper()


def root_certificates(configmap: Optional[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
    """Each certificate in istio-ca-root-cert (more than one during a rotation): subject and expiry. Public data only."""
    if configmap is None:
        return None
    pem = ((configmap.get("data") or {}).get("root-cert.pem") or "").encode()
    certs = x509.load_pem_x509_certificates(pem) if pem.strip() else []
    return [{"subject": c.subject.rfc4514_string(), "not_after": c.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")} for c in certs]


def go_duration_hours(value: Optional[str]) -> Optional[float]:
    """A Go duration such as 24h, 90m or 1h30m, in hours; None when it isn't one."""
    parts = re.findall(r"(\d+(?:\.\d+)?)(h|m|s)", value or "")
    if not parts or "".join(n + u for n, u in parts) != (value or "").strip():
        return None
    return round(sum(float(n) * {"h": 1, "m": 1 / 60, "s": 1 / 3600}[u] for n, u in parts), 3)


def workload_cert_ttl(deployments: Optional[List[Dict[str, Any]]]) -> Tuple[Optional[str], Optional[str]]:
    """istiod's workload certificate lifetime and where it came from (setting or default); (None, None) when unread."""
    if deployments is None:
        return None, None
    for d in deployments:
        for c in (((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []:
            for e in c.get("env") or []:
                if e.get("name") == "DEFAULT_WORKLOAD_CERT_TTL" and e.get("value"):
                    return e["value"], "setting"
    # No istiod in the root namespace (such as a managed control plane elsewhere): say so rather than leave it blank.
    return (DEFAULT_WORKLOAD_CERT_TTL, "default") if deployments else (None, "istiod_not_found")


def summarize(data: Dict[str, Optional[List[Dict[str, Any]]]], mesh_config: Optional[Dict[str, Any]],
              root_cert: Optional[Dict[str, Any]], istiod: Optional[List[Dict[str, Any]]], root: str,
              now: datetime) -> Dict[str, Any]:
    """What is configured, never a verdict beyond Istio's own rules. Each group is null when the read behind it failed."""
    ns, pas, aps, gws, vss, drs = (data.get(k) for k in ("namespaces", "peerauthentications", "authorizationpolicies",
                                                           "gateways", "virtualservices", "destinationrules"))
    workload = [n for n in ns or [] if (n.get("metadata") or {}).get("name") not in SYSTEM_NAMESPACES | {root}]
    meshed = [n for n in workload if in_mesh(n)]
    names = {(n.get("metadata") or {}).get("name") for n in meshed}
    deny_ns = {(p.get("metadata") or {}).get("namespace") for p in aps or [] if is_default_deny(p)}
    mode = mesh_mtls_mode(pas, root) if pas is not None else None
    weaker = mtls_overrides(pas, root) if pas is not None else None
    servers = gateway_servers(gws) if gws is not None else None
    certs = root_certificates(root_cert)
    earliest = min((c["not_after"] for c in certs), default=None) if certs else None
    ttl, ttl_source = workload_cert_ttl(istiod)
    return {
        # Mesh membership
        "namespaces": len(workload) if ns is not None else None,
        "namespaces_in_mesh": len(meshed) if ns is not None else None,
        "namespaces_not_in_mesh": sorted(set(n["metadata"]["name"] for n in workload) - names) if ns is not None else None,
        # mTLS
        "mesh_mtls_mode": mode,
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
        "authorization_deny_policies": sum(1 for p in aps if ((p.get("spec") or {}).get("action") or "").upper() == "DENY")
        if aps is not None else None,
        # Ingress
        "gateways": len(gws) if gws is not None else None,
        "gateway_servers": len(servers) if servers is not None else None,
        "gateway_servers_plaintext": sorted(s["server"] for s in servers if s["plaintext"]) if servers is not None else None,
        "gateway_servers_weak_tls": sorted(s["server"] for s in servers if s["weak_tls"]) if servers is not None else None,
        "virtual_services_on_gateways": sum(1 for v in vss if (v.get("spec") or {}).get("gateways")) if vss is not None else None,
        # Traffic policy
        "destination_rules_tls_disabled": tls_disabled(drs) if drs is not None else None,
        "outbound_traffic_policy": outbound_policy(mesh_config),
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
        return self._pages("namespaces", lambda t: ser(self.core.list_namespace(limit=PAGE, _continue=t)))

    def custom_list(self, group: str, plural: str) -> Optional[List[Dict[str, Any]]]:
        return self._pages(plural, lambda t: self.custom.list_cluster_custom_object(group, "v1", plural, limit=PAGE, _continue=t))

    def configmap(self, operation: str, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        ser = self.core.api_client.sanitize_for_serialization
        return self._call(operation, lambda: ser(self.core.read_namespaced_config_map(name, namespace)))

    def istiod(self, namespace: str) -> Optional[List[Dict[str, Any]]]:
        ser = self.apps.api_client.sanitize_for_serialization
        return self._pages("istiod", lambda t: ser(self.apps.list_namespaced_deployment(namespace, label_selector="app=istiod",
                                                                                         limit=PAGE, _continue=t)))


def collect(reader: MeshReader, root: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    data = {"namespaces": reader.namespaces()}
    for group, plural in (("security.istio.io", "peerauthentications"), ("security.istio.io", "authorizationpolicies"),
                          ("networking.istio.io", "gateways"), ("networking.istio.io", "virtualservices"),
                          ("networking.istio.io", "destinationrules")):
        data[plural] = reader.custom_list(group, plural)
    mesh_config = reader.configmap("mesh config", "istio", root)
    root_cert = reader.configmap("root certificate", "istio-ca-root-cert", root)
    istiod = reader.istiod(root)
    results = {
        "root_namespace": root,
        "peer_authentications": [{"ref": _ref(p), "selector": bool((p.get("spec") or {}).get("selector")),
                                  "mode": ((p.get("spec") or {}).get("mtls") or {}).get("mode"),
                                  "port_level": (p.get("spec") or {}).get("portLevelMtls")} for p in data["peerauthentications"]]
        if data["peerauthentications"] is not None else None,
        "authorization_policies": [{"ref": _ref(p), "action": (p.get("spec") or {}).get("action") or "ALLOW",
                                    "rules": len((p.get("spec") or {}).get("rules") or []), "default_deny": is_default_deny(p),
                                    "allows_all": allows_all(p)} for p in data["authorizationpolicies"]]
        if data["authorizationpolicies"] is not None else None,
        "gateway_servers": gateway_servers(data["gateways"]) if data["gateways"] is not None else None,
        "root_certificates": root_certificates(root_cert),
    }
    return {"results": results, "summary": summarize(data, mesh_config, root_cert, istiod, root, now)}


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
    root = (os.environ.get("ISTIO_ROOT_NAMESPACE") or "istio-system").strip()
    now = datetime.now(timezone.utc)
    metadata: Dict[str, Any] = {"datetime": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "root_namespace": root, "api_failures": []}
    evidence: Dict[str, Any] = {"results": {}, "summary": summarize({}, None, None, None, root, now)}
    code = None
    try:
        reader = MeshReader(*clients(os.environ.get("ISTIO_KUBE_CONTEXT")))
    except Exception as exc:  # noqa: BLE001 - no kubeconfig, a missing context, or not in a cluster
        metadata["api_failures"] = [{"operation": "kubernetes config", "type": type(exc).__name__, "message": str(exc)[:300]}]
        code = "bad_config"
    else:
        evidence = collect(reader, root, now)
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
