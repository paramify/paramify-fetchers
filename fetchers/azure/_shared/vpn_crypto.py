"""IPsec/IKE policy projection and weak-algorithm detection shared by the VPN fetchers."""

from __future__ import annotations

from typing import Any, Dict, List

from azure_common import model_attr

WEAK_ALGORITHMS = {"des", "des3", "md5", "sha1", "dhgroup1", "dhgroup2", "pfs1", "pfs2", "none"}

_POLICY_ALGORITHM_KEYS = (
    "ike_encryption", "ike_integrity", "dh_group", "ipsec_encryption", "ipsec_integrity", "pfs_group",
)


def project_ipsec_policy(policy: Any) -> Dict[str, Any]:
    return {
        "ike_encryption": model_attr(policy, "ike_encryption"),
        "ike_integrity": model_attr(policy, "ike_integrity"),
        "dh_group": model_attr(policy, "dh_group"),
        "ipsec_encryption": model_attr(policy, "ipsec_encryption"),
        "ipsec_integrity": model_attr(policy, "ipsec_integrity"),
        "pfs_group": model_attr(policy, "pfs_group"),
        "sa_life_time_seconds": model_attr(policy, "sa_life_time_seconds"),
        "sa_data_size_kilobytes": model_attr(policy, "sa_data_size_kilobytes"),
    }


def weak_algorithms(policies: List[Dict[str, Any]]) -> List[str]:
    """Sorted `key=value` for every weak algorithm across the given projected policies."""
    found = set()
    for policy in policies:
        for key in _POLICY_ALGORITHM_KEYS:
            value = str(policy.get(key) or "")
            if value.lower() in WEAK_ALGORITHMS:
                found.add(f"{key}={value}")
    return sorted(found)


# Weak proposals in Azure's default policy, which applies when a connection has no custom policy.
# https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-compliance-crypto
VPN_GATEWAY_DEFAULT_WEAK = ("dh_group=DHGroup2",)
# https://learn.microsoft.com/en-us/azure/virtual-wan/virtual-wan-ipsec
VIRTUAL_WAN_DEFAULT_WEAK = ("dh_group=DHGroup2", "ike_integrity=SHA1", "ipsec_integrity=SHA1", "pfs_group=None")

POLICY_SOURCE_CUSTOM = "custom"
POLICY_SOURCE_AZURE_DEFAULT = "azure_default"


def ike_is_v2(protocol: Any):
    """True for IKEv2, False for IKEv1, None when Azure returned no protocol (unknown)."""
    if not protocol:
        return None
    return str(protocol).lower() == "ikev2"


def policy_source(policies: List[Dict[str, Any]]) -> str:
    return POLICY_SOURCE_CUSTOM if policies else POLICY_SOURCE_AZURE_DEFAULT


def effective_weak_algorithms(policies: List[Dict[str, Any]], default_weak: tuple) -> List[str]:
    """Weak algorithms in the custom policy, or in Azure's default when there is none."""
    if policies:
        return weak_algorithms(policies)
    return sorted(f"{weak} ({POLICY_SOURCE_AZURE_DEFAULT})" for weak in default_weak)
