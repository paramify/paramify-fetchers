#!/usr/bin/env python3
"""
Wiz Tenant Security Settings

Reads the security settings of the Wiz tenant itself: the IP allowlists for
users, service accounts and SCIM, and the portal inactivity timeout.

Scope, stated plainly: this is evidence about how the organization has secured
its own Wiz tenant (a leveraged security tool). It shows that Wiz exposes its
security settings through an API, but it is NOT evidence that the
organization's own cloud service lets its customers view or adjust security
settings (FedRAMP SCG-ENH-*). That has to come from the organization's product.

Requires read:security_settings. Queries follow Wiz's published Get IP
Restrictions and Get Portal Inactivity Timeout references.

Speaks to KSI-IAM-SNU and KSI-CNA-RNT.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizClient,
    collect_guarded,
    env_list,
    evidence,
    run_fetcher,
)

logger = logging.getLogger("wiz_tenant_security_settings")

IP_QUERY = """
query WizIpRestrictions {
  ipRestrictions {
    userIPAllowlist { value description }
    serviceAccountIPAllowlist { value description }
    scimIPAllowlist { value description }
  }
}
"""

TIMEOUT_QUERY = """
query WizPortalInactivityTimeout {
  portalInactivityTimeoutSettings { isEnabled inactivityTimeoutMinutes }
}
"""

LISTS = [("userIPAllowlist", "users"), ("serviceAccountIPAllowlist", "service_accounts"), ("scimIPAllowlist", "scim")]


def summarize(ip: Dict[str, Any], timeout: Dict[str, Any], include_values: bool) -> Dict[str, Any]:
    allowlists: Dict[str, Any] = {}
    for key, label in LISTS:
        entries = ip.get(key) or []
        allowlists[label] = {
            "restricted": bool(entries),
            "entry_count": len(entries),
            "entries": [{"value": e.get("value"), "description": e.get("description")} for e in entries]
            if include_values else [],
        }
    return {
        "ip_allowlists": allowlists,
        "unrestricted_access_paths": [label for label, v in allowlists.items() if not v["restricted"]],
        "portal_inactivity_timeout_enabled": timeout.get("isEnabled"),
        "portal_inactivity_timeout_minutes": timeout.get("inactivityTimeoutMinutes"),
        "scope_note": "Settings of the Wiz tenant (a leveraged tool). Not evidence of security-settings "
                      "tooling in the organization's own service for its customers (SCG-ENH).",
    }


def body(client: WizClient) -> Dict[str, Any]:
    include = env_list("WIZ_INCLUDE_RAW_FINDINGS", ["TRUE"])[0] not in {"FALSE", "0", "NO"}
    ip_data = client.graphql("ipRestrictions", IP_QUERY)
    to_data = client.graphql("portalInactivityTimeoutSettings", TIMEOUT_QUERY)
    ip = (ip_data or {}).get("ipRestrictions") or {}
    timeout = (to_data or {}).get("portalInactivityTimeoutSettings") or {}
    records: List[Dict[str, Any]] = []
    if ip_data is not None or to_data is not None:
        records = [{"setting": "ip_restrictions", "read": ip_data is not None},
                   {"setting": "portal_inactivity_timeout", "read": to_data is not None}]
    return evidence(
        client=client,
        operations=["ipRestrictions", "portalInactivityTimeoutSettings"],
        records=records,
        analysis=summarize(ip, timeout, include),
        empty_message="Wiz returned no security settings; check read:security_settings.",
        include_records=True,
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_tenant_security_settings.json", logger))
