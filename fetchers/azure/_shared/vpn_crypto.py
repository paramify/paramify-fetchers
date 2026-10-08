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
