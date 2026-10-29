#!/usr/bin/env python3
"""Entra ID Protection risky users, joined to directory roles, risk history and the alerts naming them: which accounts are at risk and what was done about it."""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import ArmError, parse_time, run_tenant  # noqa: E402
from entra_graph import is_privileged_role  # noqa: E402

NAME = "azure_entra_risky_users"
OPEN_STATES = frozenset({"atRisk", "confirmedCompromised"})
CLOSED_STATES = frozenset({"remediated", "dismissed", "confirmedSafe"})
ALERTS_FILTER = "serviceSource eq 'azureAdIdentityProtection'"

logger = logging.getLogger(NAME)


def not_licensed(exc: BaseException) -> bool:
    """Identity Protection needs Entra ID P2; without it Graph refuses the call, which is a state, not a failure."""
    return isinstance(exc, ArmError) and exc.status == 403 and "licens" in str(exc).lower()


Roles = Dict[str, List[Dict[str, Any]]]


def directory_roles(client) -> Tuple[Roles, Dict[str, Any]]:
    """Principal id -> the activated directory roles it holds directly, each flagged privileged or not; and group id -> name."""
    held: Roles = {}
    groups: Dict[str, Any] = {}
    for role in client.graph_list("/directoryRoles"):
        members = f"/directoryRoles/{role.get('id')}/members"
        # $expand=members on the collection caps at 20 members per role, so each role's members are paged.
        ids = {m.get("id") for m in client.graph_list(members, params={"$select": "id"})}
        # The v1.0 members list leaves out service principals; the servicePrincipal cast returns them.
        ids |= {m.get("id") for m in client.graph_list(f"{members}/microsoft.graph.servicePrincipal", params={"$select": "id"})}
        # Role-assignable groups; their members aren't expanded, as that needs GroupMember.Read.All.
        for group in client.graph_list(f"{members}/microsoft.graph.group", params={"$select": "id,displayName"}):
            groups[group.get("id")] = group.get("displayName")
            ids.add(group.get("id"))
        privileged = is_privileged_role({"display_name": role.get("displayName"), "role_template_id": role.get("roleTemplateId")})
        for member_id in sorted(i for i in ids if i):
            held.setdefault(member_id, []).append({"name": role.get("displayName"), "privileged": privileged})
    return held, groups


def privileged_groups(roles: Roles, groups: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for group_id, name in groups.items():
        names = sorted(r["name"] for r in roles.get(group_id, []) if r["privileged"])
        if names:
            out.append({"id": group_id, "display_name": name, "privileged_roles": names})
    return sorted(out, key=lambda g: ((g["display_name"] or "").lower(), g["id"]))


def project_user(user: Dict[str, Any], roles: Optional[Roles], now: datetime) -> Dict[str, Any]:
    updated = parse_time(user.get("riskLastUpdatedDateTime"))
    held = None if roles is None else roles.get(cast(str, user.get("id")), [])
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
        "directory_roles": None if held is None else sorted(r["name"] for r in held),
        "privileged_roles": None if held is None else sorted(r["name"] for r in held if r["privileged"]),
    }


def followed_up(user: Dict[str, Any]) -> bool:
    return user["risk_state"] in OPEN_STATES or user["risk_level"] == "high"


def project_history(item: Dict[str, Any]) -> Dict[str, Any]:
    activity = item.get("activity") or {}
    return {
        "risk_last_updated": item.get("riskLastUpdatedDateTime"),
        "risk_level": item.get("riskLevel"),
        "risk_state": item.get("riskState"),
        "risk_detail": item.get("riskDetail"),
        "activity_detail": activity.get("detail"),
        "risk_event_types": sorted(activity.get("riskEventTypes") or []),
        "initiated_by": item.get("initiatedBy"),
    }


def risk_history(client, user_id: str) -> List[Dict[str, Any]]:
    items = (project_history(i) for i in client.graph_list(f"/identityProtection/riskyUsers/{user_id}/history"))
    return sorted(items, key=lambda i: i["risk_last_updated"] or "")


def last_closed_risk(history: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    closed = [h for h in history or [] if h["risk_state"] in CLOSED_STATES]
    return closed[-1] if closed else None


def project_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": alert.get("id"),
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
        "classification": alert.get("classification"),
        "determination": alert.get("determination"),
        "assigned_to": alert.get("assignedTo"),
        "incident_id": alert.get("incidentId"),
        "created": alert.get("createdDateTime"),
        "resolved": alert.get("resolvedDateTime"),
    }


def alerts_by_user(alerts: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Lower-cased user object id or UPN -> the alerts whose user evidence names it, by alert id."""
    named: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for alert in alerts:
        for evidence in alert.get("evidence") or []:
            if not str(evidence.get("@odata.type") or "").endswith("userEvidence"):
                continue
            account = evidence.get("userAccount") or {}
            for key in (account.get("azureAdUserId"), account.get("userPrincipalName")):
                if key:
                    named.setdefault(str(key).lower(), {})[str(alert.get("id"))] = project_alert(alert)
    return named


def user_alerts(named: Dict[str, Dict[str, Dict[str, Any]]], user: Dict[str, Any]) -> List[Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}
    for key in (user["id"], user["user_principal_name"]):
        found.update(named.get(str(key or "").lower(), {}))
    return sorted(found.values(), key=lambda a: a["created"] or "")


def account_enabled(client, user_id: str) -> Optional[bool]:
    """None when Graph refuses the read: User.Read.All is optional, so that is unknown, not a failed run."""
    try:
        return client.graph_get(f"/users/{user_id}", {"$select": "id,accountEnabled"}).get("accountEnabled")
    except ArmError as exc:
        if exc.status == 403:
            return None
        raise


def collect(client, collector) -> tuple:
    try:
        raw = client.graph_list("/identityProtection/riskyUsers", params={"$top": "500"})
    except Exception as exc:  # noqa: BLE001
        if not_licensed(exc):
            return {"identity_protection_available": False, "reason": str(exc), "risky_users": None}, {
                "identity_protection_available": False
            }
        collector.record("graph.identityProtection.riskyUsers.list", exc)
        return {"risky_users": None}, {}
    # None when the roles can't be read, so the privileged figures read unknown rather than 0.
    read = collector.guard("graph.directoryRoles.members.list", lambda: directory_roles(client))
    roles, groups = read if read is not None else (None, {})
    held_by_groups = None if roles is None else privileged_groups(roles, groups)

    now = datetime.now(timezone.utc)
    users = sorted((project_user(u, roles, now) for u in raw), key=lambda u: (u["user_principal_name"] or "").lower())
    for user in users:
        if user["privileged_roles"] and user["risk_state"] in OPEN_STATES:
            user["account_enabled"] = collector.guard(
                f"graph.users.get({user['id']})", lambda u=user: account_enabled(client, u["id"])
            )

    followed = [u for u in users if followed_up(u)]
    for user in followed:
        user["risk_history"] = collector.guard(
            f"graph.identityProtection.riskyUsers.history({user['id']})", lambda u=user: risk_history(client, u["id"])
        )
        user["last_closed_risk"] = last_closed_risk(user["risk_history"])
    raw_alerts = collector.guard(
        "graph.security.alerts_v2.list", lambda: client.graph_list("/security/alerts_v2", params={"$filter": ALERTS_FILTER})
    )
    named = alerts_by_user(raw_alerts) if raw_alerts is not None else None
    for user in followed:
        user["alerts"] = user_alerts(named, user) if named is not None else None
    alerts = list({a["id"]: a for u in followed for a in u["alerts"] or []}.values())

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
        "privileged_open_risk_users": None if roles is None else len(privileged_open),
        "privileged_open_risk_users_enabled": None if roles is None else sum(
            1 for u in privileged_open if u.get("account_enabled") is not False
        ),
        "oldest_open_risk_days": max(ages) if ages else None,
        "privileged_principals": None if roles is None else sum(
            1 for held in roles.values() if any(r["privileged"] for r in held)
        ),
        # Members of these groups hold the role too but aren't in privileged_open_risk_users.
        "privileged_role_groups": None if held_by_groups is None else len(held_by_groups),
        "open_or_high_risk_users": len(followed),
        "risk_histories_read": sum(1 for u in followed if u["risk_history"] is not None),
        "identity_protection_alerts": len(raw_alerts) if raw_alerts is not None else None,
        "open_high_risk_users_without_alert": None if named is None else sum(
            1 for u in open_ if u["risk_level"] == "high" and not u["alerts"]
        ),
        "alerts_for_open_or_high_risk_users": None if named is None else len(alerts),
        "alerts_without_owner": None if named is None else sum(1 for a in alerts if not a["assigned_to"]),
        "alerts_without_incident": None if named is None else sum(1 for a in alerts if not a["incident_id"]),
    }
    return {"identity_protection_available": True, "risky_users": users, "privileged_role_groups": held_by_groups}, summary


def main() -> int:
    return run_tenant(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
