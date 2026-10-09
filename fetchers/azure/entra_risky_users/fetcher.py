#!/usr/bin/env python3
"""Entra ID Protection risky users, joined to directory roles: which privileged accounts are at risk and what was done about it."""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import ArmError, parse_time, run_tenant  # noqa: E402
from entra_graph import (  # noqa: E402
    GLOBAL_ADMINISTRATOR_TEMPLATE_ID,
    PRIVILEGED_ROLE_NAMES,
)

NAME = "azure_entra_risky_users"
OPEN_STATES = frozenset({"atRisk", "confirmedCompromised"})
CLOSED_STATES = frozenset({"remediated", "dismissed", "confirmedSafe"})

logger = logging.getLogger(NAME)


def not_licensed(exc: BaseException) -> bool:
    """Identity Protection needs Entra ID P2; without it Graph refuses the call, which is a state, not a failure."""
    return isinstance(exc, ArmError) and exc.status == 403 and "licens" in str(exc).lower()


def is_privileged(role: Dict[str, Any]) -> bool:
    return role.get("displayName") in PRIVILEGED_ROLE_NAMES or (
        str(role.get("roleTemplateId") or "").lower() == GLOBAL_ADMINISTRATOR_TEMPLATE_ID
    )


def directory_roles(client) -> Dict[str, List[Dict[str, Any]]]:
    """Principal id -> the activated directory roles it holds directly, each flagged privileged or not."""
    held: Dict[str, List[Dict[str, Any]]] = {}
    for role in client.graph_list("/directoryRoles"):
        # $expand=members on the collection caps at 20 members per role, so each role's members are paged.
        for member in client.graph_list(f"/directoryRoles/{role.get('id')}/members", {"$select": "id"}):
            held.setdefault(member.get("id"), []).append(
                {"name": role.get("displayName"), "privileged": is_privileged(role)}
            )
    return held


def project_user(user: Dict[str, Any], roles: Dict[str, List[Dict[str, Any]]], now: datetime) -> Dict[str, Any]:
    updated = parse_time(user.get("riskLastUpdatedDateTime"))
    held = roles.get(user.get("id"), [])
    return {
        "id": user.get("id"),
        "user_principal_name": user.get("userPrincipalName"),
        "display_name": user.get("userDisplayName"),
        "risk_level": user.get("riskLevel"),
        "risk_state": user.get("riskState"),
        "risk_detail": user.get("riskDetail"),
        "risk_last_updated": user.get("riskLastUpdatedDateTime"),
        "days_since_risk_update": round((now - updated).total_seconds() / 86400, 1) if updated else None,
        "is_deleted": user.get("isDeleted"),
        "directory_roles": sorted(r["name"] for r in held),
        "privileged_roles": sorted(r["name"] for r in held if r["privileged"]),
    }


def account_enabled(client, user_id: str) -> Optional[bool]:
    return client.graph_get(f"/users/{user_id}", {"$select": "id,accountEnabled"}).get("accountEnabled")


def collect(client, collector) -> tuple:
    try:
        raw = client.graph_list("/identityProtection/riskyUsers", {"$top": "500"})
    except Exception as exc:  # noqa: BLE001
        if not_licensed(exc):
            return {"identity_protection_available": False, "reason": str(exc), "risky_users": None}, {
                "identity_protection_available": False
            }
        collector.record("graph.identityProtection.riskyUsers.list", exc)
        return {"risky_users": None}, {}
    roles = collector.guard("graph.directoryRoles.members.list", lambda: directory_roles(client)) or {}

    now = datetime.now(timezone.utc)
    users = sorted((project_user(u, roles, now) for u in raw), key=lambda u: (u["user_principal_name"] or "").lower())
    for user in users:
        if user["privileged_roles"] and user["risk_state"] in OPEN_STATES:
            user["account_enabled"] = collector.guard(
                f"graph.users.get({user['id']})", lambda u=user: account_enabled(client, u["id"])
            )

    open_ = [u for u in users if u["risk_state"] in OPEN_STATES]
    privileged_open = [u for u in open_ if u["privileged_roles"]]
    by_state: Dict[str, int] = {}
    for user in users:
        by_state[user["risk_state"] or "unknown"] = by_state.get(user["risk_state"] or "unknown", 0) + 1
    ages = [u["days_since_risk_update"] for u in open_ if u["days_since_risk_update"] is not None]
    summary = {
        "identity_protection_available": True,
        "risky_users_total": len(users),
        "by_risk_state": dict(sorted(by_state.items())),
        "open_risk_users": len(open_),
        "open_high_risk_users": sum(1 for u in open_ if u["risk_level"] == "high"),
        "privileged_open_risk_users": len(privileged_open),
        "privileged_open_risk_users_enabled": sum(1 for u in privileged_open if u.get("account_enabled") is not False),
        "oldest_open_risk_days": max(ages) if ages else None,
        "privileged_principals": sum(1 for held in roles.values() if any(r["privileged"] for r in held)),
    }
    return {"identity_protection_available": True, "risky_users": users}, summary


def main() -> int:
    return run_tenant(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
