#!/usr/bin/env python3
"""
GCP Load Balancer TLS Configuration

Transport-encryption posture of every internet-facing HTTPS/SSL load balancer
front end in one project: each target HTTPS proxy and target SSL proxy, the SSL
policy attached to it, and each policy's minimum TLS version, profile and resolved
cipher list. A proxy with no SSL policy silently runs GCP's permissive default of
TLS 1.0 / COMPATIBLE, so every proxy carries an effective minimum version and
profile that names that default rather than leaving a null — the finding this
evidence exists to surface.

NOT ported from Prowler: its GCP provider reads no SSL policies or target proxies,
so the field list comes from the Compute Engine v1 resources directly.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    basename,
    build_payload,
    coverage_percentage,
    credentials,
    first,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_load_balancer_tls_configuration")

# What GCP applies when a target proxy has no SSL policy attached.
DEFAULT_MIN_TLS_VERSION = "TLS_1_0"
DEFAULT_PROFILE = "COMPATIBLE"

# Weakest first, so "at least TLS 1.2" is an index comparison, not string parsing.
TLS_VERSION_ORDER = ("TLS_1_0", "TLS_1_1", "TLS_1_2", "TLS_1_3")

# The floor this evidence measures against. TLS 1.0/1.1 are deprecated
# (RFC 8996); FedRAMP and CIS both want 1.2 or better.
MINIMUM_ACCEPTABLE_TLS_VERSION = "TLS_1_2"

# Re-admits out-of-date cipher suites whatever the version floor says — weak in itself.
PERMISSIVE_PROFILE = "COMPATIBLE"


# --- pure transforms ---

def tls_at_least(version, floor: str = MINIMUM_ACCEPTABLE_TLS_VERSION) -> bool:
    """True when `version` is at or above `floor`; unknown or absent reads as below.

    This drives a compliance-relevant count, so an unrecognized value must not pass.
    """
    try:
        return TLS_VERSION_ORDER.index(str(version)) >= TLS_VERSION_ORDER.index(floor)
    except ValueError:
        return False


def is_weak_tls(min_tls_version, profile) -> bool:
    """The one derived verdict: below the TLS floor, or the permissive profile."""
    return not tls_at_least(min_tls_version) or str(profile) == PERMISSIVE_PROFILE


def scope_of(resource: dict) -> str:
    """"global" or the region name, from the resource's own `region` field.

    Not the aggregatedList key: it spells the global scope "global" in one API and ""
    in another. Global resources have no `region`; regional ones carry a region URL.
    """
    region = first(resource, "region")
    return basename(region) if region else "global"


def ssl_policy_record(policy: dict) -> dict:
    """Normalize one SSL policy into an evidence record."""
    min_tls = first(policy, "minTlsVersion", "min_tls_version")
    profile = first(policy, "profile")
    # enabled_features is the API's resolved cipher list (output-only);
    # custom_features is the operator's input, and only set when profile=CUSTOM.
    enabled_features = sorted(first(policy, "enabledFeatures", "enabled_features") or [])
    custom_features = sorted(first(policy, "customFeatures", "custom_features") or [])
    return {
        "name": first(policy, "name"),
        "id": first(policy, "id"),
        "scope": scope_of(policy),
        "description": first(policy, "description"),
        "min_tls_version": min_tls,
        "profile": profile,
        "enabled_ciphers": enabled_features,
        "enabled_cipher_count": len(enabled_features),
        "custom_ciphers": custom_features,
        "post_quantum_key_exchange": first(
            policy, "postQuantumKeyExchange", "post_quantum_key_exchange"
        ),
        "meets_tls_floor": tls_at_least(min_tls),
        "permissive_profile": str(profile) == PERMISSIVE_PROFILE,
        "weak_tls": is_weak_tls(min_tls, profile),
        "creation_timestamp": first(policy, "creationTimestamp", "creation_timestamp"),
    }


def proxy_record(proxy: dict, proxy_type: str, policies_by_name: dict) -> dict:
    """Normalize one target HTTPS / SSL proxy, resolving its SSL policy.

    The proxy stores its policy as a self-link, so `policies_by_name` is joined on the
    basename. A proxy whose policy could not be read keeps `ssl_policy_resolved:
    false` rather than silently reading as the GCP default.
    """
    policy_name = basename(first(proxy, "sslPolicy", "ssl_policy")) or None
    policy = policies_by_name.get(policy_name) if policy_name else None
    uses_default = policy_name is None

    if uses_default:
        effective_min_tls = DEFAULT_MIN_TLS_VERSION
        effective_profile = DEFAULT_PROFILE
    elif policy:
        effective_min_tls = policy["min_tls_version"]
        effective_profile = policy["profile"]
    else:
        effective_min_tls = None
        effective_profile = None

    certificates = first(proxy, "sslCertificates", "ssl_certificates") or []
    return {
        "name": first(proxy, "name"),
        "id": first(proxy, "id"),
        "type": proxy_type,
        "scope": scope_of(proxy),
        # --- SSL policy attachment ---
        "ssl_policy": policy_name,
        "uses_default_ssl_policy": uses_default,
        "ssl_policy_resolved": uses_default or policy is not None,
        "effective_min_tls_version": effective_min_tls,
        "effective_profile": effective_profile,
        "meets_tls_floor": tls_at_least(effective_min_tls),
        "weak_tls": is_weak_tls(effective_min_tls, effective_profile),
        # --- certificates and back end ---
        "ssl_certificate_count": len(certificates),
        "ssl_certificates": sorted(basename(c) for c in certificates),
        # Google-managed certificate map, an alternative to sslCertificates.
        "certificate_map": basename(first(proxy, "certificateMap", "certificate_map")),
        "url_map": basename(first(proxy, "urlMap", "url_map")),
        "backend_service": basename(first(proxy, "service")),
        "quic_override": first(proxy, "quicOverride", "quic_override"),
        "tls_early_data": first(proxy, "tlsEarlyData", "tls_early_data"),
        # mTLS / Traffic Director policy; presence only — it is a separate resource.
        "server_tls_policy": basename(first(proxy, "serverTlsPolicy", "server_tls_policy")),
        "proxy_header": first(proxy, "proxyHeader", "proxy_header"),
        "creation_timestamp": first(proxy, "creationTimestamp", "creation_timestamp"),
    }


def summarize(
    policies: list[dict], proxies: list[dict], *, api_readable: bool = True
) -> dict:
    compliant = sum(1 for p in proxies if p["meets_tls_floor"])
    return {
        # False when compute.googleapis.com is disabled (recorded in skipped_calls) or
        # a list call failed — "no load balancers" is not the same as "could not look".
        "compute_api_readable": api_readable,
        "tls_floor": MINIMUM_ACCEPTABLE_TLS_VERSION,
        "default_min_tls_version_when_no_policy": DEFAULT_MIN_TLS_VERSION,
        "total_ssl_policies": len(policies),
        "weak_ssl_policies": sum(1 for p in policies if p["weak_tls"]),
        "permissive_profile_ssl_policies": sum(1 for p in policies if p["permissive_profile"]),
        "ssl_policy_min_tls_versions": sorted(
            {str(p["min_tls_version"]) for p in policies if p["min_tls_version"]}
        ),
        "ssl_policy_profiles": sorted({str(p["profile"]) for p in policies if p["profile"]}),
        "total_proxies": len(proxies),
        "https_proxies": sum(1 for p in proxies if p["type"] == "target_https_proxy"),
        "ssl_proxies": sum(1 for p in proxies if p["type"] == "target_ssl_proxy"),
        "proxies_with_ssl_policy": sum(1 for p in proxies if not p["uses_default_ssl_policy"]),
        # The finding: a front end on Google's default policy — TLS 1.0, COMPATIBLE.
        "proxies_on_default_ssl_policy": sum(
            1 for p in proxies if p["uses_default_ssl_policy"]
        ),
        "proxies_meeting_tls_floor": compliant,
        "tls_floor_percentage": coverage_percentage(compliant, len(proxies)),
        "proxies_with_weak_tls": sum(1 for p in proxies if p["weak_tls"]),
        # Non-zero: a proxy names a policy this run could not read — unknown, not default.
        "proxies_with_unresolved_ssl_policy": sum(
            1 for p in proxies if not p["ssl_policy_resolved"]
        ),
        "proxies_with_certificate_map": sum(1 for p in proxies if p["certificate_map"]),
        "proxies_with_server_tls_policy": sum(1 for p in proxies if p["server_tls_policy"]),
    }


# --- collection ---

def collect_ssl_policies(project, creds, collector: Collector) -> list[dict] | None:
    """Every SSL policy (global + regional), or None when Compute couldn't be listed."""
    from google.cloud import compute_v1

    def _list():
        client = compute_v1.SslPoliciesClient(credentials=creds)
        out = []
        # aggregatedList covers the global scope plus every region in one paged call.
        for _scope, scoped in client.aggregated_list(project=project):
            for policy in getattr(scoped, "ssl_policies", []) or []:
                out.append(ssl_policy_record(compute_v1.SslPolicy.to_dict(policy)))
        return out

    records = collector.guard(
        "compute.sslPolicies.aggregatedList", _list, tolerate=service_disabled
    )
    if records is None:
        return None
    return sorted(records, key=lambda r: (r.get("scope") or "", r.get("name") or ""))


def collect_proxies(
    project, creds, collector: Collector, policies_by_name: dict
) -> list[dict] | None:
    """Every target HTTPS + target SSL proxy, or None when neither could be listed."""
    from google.cloud import compute_v1

    def _https():
        client = compute_v1.TargetHttpsProxiesClient(credentials=creds)
        out = []
        for _scope, scoped in client.aggregated_list(project=project):
            for proxy in getattr(scoped, "target_https_proxies", []) or []:
                out.append(
                    proxy_record(
                        compute_v1.TargetHttpsProxy.to_dict(proxy),
                        "target_https_proxy",
                        policies_by_name,
                    )
                )
        return out

    def _ssl():
        client = compute_v1.TargetSslProxiesClient(credentials=creds)
        # Target SSL proxies are a global-only resource — no aggregatedList exists.
        return [
            proxy_record(
                compute_v1.TargetSslProxy.to_dict(proxy), "target_ssl_proxy", policies_by_name
            )
            for proxy in client.list(project=project)
        ]

    https = collector.guard(
        "compute.targetHttpsProxies.aggregatedList", _https, tolerate=service_disabled
    )
    ssl = collector.guard("compute.targetSslProxies.list", _ssl, tolerate=service_disabled)
    if https is None and ssl is None:
        return None
    records = (https or []) + (ssl or [])
    return sorted(
        records,
        key=lambda r: (r.get("type") or "", r.get("scope") or "", r.get("name") or ""),
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    policies: list[dict] | None = None
    proxies: list[dict] | None = None
    if project and creds is not None:
        policies = collect_ssl_policies(project, creds, collector)
        policies_by_name = {p["name"]: p for p in (policies or []) if p["name"]}
        proxies = collect_proxies(project, creds, collector, policies_by_name)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"ssl_policies": policies or [], "proxies": proxies or []},
        summary=summarize(
            policies or [],
            proxies or [],
            api_readable=policies is not None and proxies is not None,
        ),
    )

    filename = (
        f"gcp_load_balancer_tls_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
