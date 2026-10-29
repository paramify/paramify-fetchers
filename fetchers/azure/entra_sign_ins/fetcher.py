#!/usr/bin/env python3
"""Microsoft Entra ID interactive sign-ins over a lookback: MFA, methods, Conditional Access and risk, per user and app."""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    report_failure,
    sorted_counts,
    write_evidence,
)
from azure_rest import AzureRestClient, int_config  # noqa: E402
from entra_graph import (  # noqa: E402
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
)

NAME = "azure_entra_sign_ins"
LOOKBACK_ENV = "ENTRA_SIGN_IN_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 7
# Entra keeps sign-in logs for 30 days with P1 or P2.
MAX_LOOKBACK_DAYS = 30
# A runaway guard: the figures stay exact up to here and the run says it stopped.
SIGN_IN_LIMIT = 200_000
EXCEPTION_LIMIT = 1000
# The error code of the 403 Graph sends a tenant with no Entra ID P1/P2 for sign-in logs.
NOT_LICENSED_CODE = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"

SINGLE_FACTOR = "singleFactorAuthentication"
MULTI_FACTOR = "multiFactorAuthentication"
CA_NOT_APPLIED = "notApplied"
CA_FAILURE = "failure"
RISK_LEVELS = ("low", "medium", "high")
RISKY_STATES = ("atRisk", "confirmedCompromised")
HIDDEN = "hidden"

# authenticationMethod strings that are phishing-resistant whenever they satisfy a step.
PHISHING_RESISTANT_MARKERS = ("fido2", "passkey", "windows hello", "platform credential")
# A certificate counts only as multifactor CBA: MFA required and no weaker method beside it.
CERTIFICATE_MARKERS = ("x.509", "certificate")
# Step results that reuse an earlier authentication rather than naming a method.
NOT_A_METHOD = frozenset({"previously satisfied", "satisfied by token"})
# Microsoft's sign-in workbook rule: every clientAppUsed but these is legacy authentication.
MODERN_CLIENTS = frozenset({"browser", "mobile apps and desktop clients", "modern clients"})
# Graph's "Unknown" isn't a legacy protocol: real tenants show it on Azure portal and passkey sign-ins.
NOT_LEGACY = MODERN_CLIENTS | {"unknown"}
# The "Windows Sign In" app: a logon to a Windows device, counted apart from sign-ins to apps.
WINDOWS_SIGN_IN_APP_ID = "38aa3b87-a06d-4817-b275-7a316988d93b"

logger = logging.getLogger(NAME)


# --- one sign-in (a Graph JSON dict in, a flat record out) ---

def sign_in_record(s: Dict[str, Any]) -> Dict[str, Any]:
    status = s.get("status") or {}
    succeeded = (status.get("errorCode") or 0) == 0
    requirement = s.get("authenticationRequirement")
    steps = [d for d in s.get("authenticationDetails") or [] if d.get("succeeded")]
    methods = sorted({
        d.get("authenticationMethod") for d in steps
        if d.get("authenticationMethod") and d["authenticationMethod"].lower() not in NOT_A_METHOD
    })
    lowered = [m.lower() for m in methods]
    strong = [m for m in lowered if any(k in m for k in PHISHING_RESISTANT_MARKERS)]
    certificates = [m for m in lowered if any(k in m for k in CERTIFICATE_MARKERS)]
    weaker = [m for m in lowered if m not in strong and m not in certificates]
    # A reused earlier factor could be anything, so it rules a certificate out like a weaker method would.
    reused = any((d.get("authenticationMethod") or "").lower() in NOT_A_METHOD for d in steps)
    phishing_resistant = bool(strong) or (
        requirement == MULTI_FACTOR and bool(certificates) and not weaker and not reused
    )
    level = s.get("riskLevelDuringSignIn")
    state = s.get("riskState")
    client = s.get("clientAppUsed") or ""
    policies = s.get("appliedConditionalAccessPolicies")
    device_logon = (s.get("appId") or "").lower() == WINDOWS_SIGN_IN_APP_ID
    reasons = []
    if succeeded and requirement == SINGLE_FACTOR and not device_logon:
        # No policy required MFA either way, but a passkey alone isn't a password alone.
        reasons.append("single_factor_phishing_resistant" if phishing_resistant else "single_factor")
    if succeeded and s.get("conditionalAccessStatus") == CA_NOT_APPLIED and not device_logon:
        reasons.append("no_conditional_access")
    if level in RISK_LEVELS or state in RISKY_STATES:
        reasons.append("risky")
    return {
        "id": s.get("id"),
        "created_date_time": s.get("createdDateTime"),
        "user_id": s.get("userId"),
        "user_principal_name": s.get("userPrincipalName"),
        "app_id": s.get("appId"),
        "app_display_name": s.get("appDisplayName"),
        # Kept only where a risky sign-in needs tracing; no figure uses it.
        "ip_address": s.get("ipAddress") if "risky" in reasons else None,
        "client_app_used": s.get("clientAppUsed"),
        "windows_device_logon": device_logon,
        "succeeded": succeeded,
        "error_code": status.get("errorCode"),
        "authentication_requirement": requirement,
        "methods": methods,
        "phishing_resistant": succeeded and phishing_resistant,
        "legacy_authentication": bool(client) and client.lower() not in NOT_LEGACY,
        "conditional_access_status": s.get("conditionalAccessStatus"),
        # Graph leaves the property out without Policy.Read.ConditionalAccess; absent isn't "none applied".
        "applied_conditional_access_policies": None if policies is None else sorted(
            p.get("displayName") or p.get("id") or ""
            for p in policies
            if p.get("result") in ("success", "failure")
        ),
        "risk_level_during_sign_in": level,
        "risk_state": state,
        "risk_event_types": sorted(s.get("riskEventTypes_v2") or []),
        "exception_reasons": reasons,
    }


# --- aggregation over the whole window ---

class Tally:
    """Running counts per tenant, user and app, plus the sign-ins listed one by one."""

    def __init__(self):
        self.total = 0
        self.counts: Counter = Counter()
        self.methods: Counter = Counter()
        self.levels: Counter = Counter()
        self.states: Counter = Counter()
        self.users: Dict[str, Dict[str, Any]] = {}
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.exceptions: List[Dict[str, Any]] = []
        self.exceptions_total = 0
        # Risky by its state alone with the level hidden: listed only if the run shows risk is known.
        self.state_only_risky: List[Dict[str, Any]] = []
        self.state_only_risky_total = 0
        self.risk_hidden = 0

    def add(self, r: Dict[str, Any]) -> None:
        self.total += 1
        ok = r["succeeded"]
        # A Windows device logon counts in the totals and on its own, never as a single-factor,
        # multi-factor or no-Conditional-Access sign-in to an app.
        app_ok = ok and not r["windows_device_logon"]
        flags = {
            "successful": ok,
            "failed": not ok,
            "successful_windows_device": ok and r["windows_device_logon"],
            "successful_single_factor": app_ok and r["authentication_requirement"] == SINGLE_FACTOR,
            "successful_multi_factor": app_ok and r["authentication_requirement"] == MULTI_FACTOR,
            "successful_unknown_requirement": app_ok
            and r["authentication_requirement"] not in (SINGLE_FACTOR, MULTI_FACTOR),
            "successful_without_conditional_access": app_ok and r["conditional_access_status"] == CA_NOT_APPLIED,
            "conditional_access_failures": r["conditional_access_status"] == CA_FAILURE,
            "successful_phishing_resistant": r["phishing_resistant"],
            "successful_legacy_authentication": ok and r["legacy_authentication"],
            "risky": "risky" in r["exception_reasons"],
        }
        self.counts.update(k for k, v in flags.items() if v)
        if ok:
            self.methods.update(r["methods"])
        if r["risk_level_during_sign_in"] == HIDDEN:
            self.risk_hidden += 1
        if flags["risky"]:
            level = r["risk_level_during_sign_in"]
            self.levels[level if level in RISK_LEVELS else "none"] += 1
            self.states[r["risk_state"] or "none"] += 1
        # No user id (an attempt at a name that doesn't exist): tenant totals only, never a user row.
        if r["user_id"]:
            user = self.users.setdefault(r["user_id"], {
                "user_id": r["user_id"], "user_principal_name": r["user_principal_name"],
                "counts": Counter(), "methods": Counter(),
            })
            user["counts"].update(k for k, v in flags.items() if v)
            user["counts"]["sign_ins"] += 1
            if ok:
                user["methods"].update(r["methods"])
        app = self.apps.setdefault(r["app_id"] or "", {
            "app_id": r["app_id"], "app_display_name": r["app_display_name"], "counts": Counter(),
        })
        app["counts"].update(k for k, v in flags.items() if v)
        app["counts"]["sign_ins"] += 1
        if r["exception_reasons"]:
            if r["exception_reasons"] == ["risky"] and r["risk_level_during_sign_in"] == HIDDEN:
                self.state_only_risky_total += 1
                if len(self.state_only_risky) < EXCEPTION_LIMIT:
                    self.state_only_risky.append(r)
            else:
                self.exceptions_total += 1
                if len(self.exceptions) < EXCEPTION_LIMIT:
                    self.exceptions.append(r)


COUNT_KEYS = (
    "sign_ins", "successful", "failed", "successful_single_factor", "successful_multi_factor",
    "successful_without_conditional_access", "conditional_access_failures",
    "successful_phishing_resistant", "successful_legacy_authentication", "risky", "successful_windows_device",
)


def _row(entry: dict, keys, risk_known: bool) -> dict:
    counts = entry["counts"]
    return {**{k: v for k, v in entry.items() if k not in ("counts", "methods")},
            **{k: counts.get(k, 0) if risk_known or k != "risky" else None for k in keys},
            **({"methods": sorted_counts(entry["methods"])} if "methods" in entry else {})}


def _without_risk(r: Dict[str, Any]) -> Dict[str, Any]:
    if "risky" not in r["exception_reasons"]:
        return r
    return {**r, "exception_reasons": [x for x in r["exception_reasons"] if x != "risky"], "ip_address": None}


def results_and_summary(tally: Tally, window: Dict[str, Any], status: str, complete: bool, truncated: bool):
    risk_levels_available = None if tally.total == 0 else tally.risk_hidden < tally.total
    # Without P2 every level reads hidden, so "no risky sign-ins" is unknown, not 0.
    risk_known = risk_levels_available is not False
    users = sorted((_row(u, COUNT_KEYS, risk_known) for u in tally.users.values()),
                   key=lambda u: ((u["user_principal_name"] or "").lower(), u["user_id"] or ""))
    apps = sorted((_row(a, COUNT_KEYS, risk_known) for a in tally.apps.values()),
                  key=lambda a: ((a["app_display_name"] or "").lower(), a["app_id"] or ""))
    # One row per user runs to tens of MB in a large tenant, so only users with an exception are listed;
    # every figure above still counts all of them.
    listed_users = [u for u in users if u["successful_single_factor"] or u["successful_without_conditional_access"]
                    or u["risky"]]
    if risk_known:
        exceptions = tally.exceptions + tally.state_only_risky
        exceptions_total = tally.exceptions_total + tally.state_only_risky_total
    else:
        # Without P2 risk is unknown (risky_sign_ins is null), so no sign-in is listed as risky.
        exceptions = [_without_risk(r) for r in tally.exceptions]
        exceptions_total = tally.exceptions_total
    exceptions = sorted(
        exceptions, key=lambda r: (r["created_date_time"] or "", r["id"] or ""), reverse=True
    )[:EXCEPTION_LIMIT]
    c = tally.counts
    app_successful = c["successful"] - c["successful_windows_device"]
    readable = status == "read"

    def when(value):
        return value if readable else None

    def risk(value):
        return when(value) if risk_known else None

    summary = {
        # --- what was checked ---
        "sign_in_logs": status,
        "lookback_days": window["lookback_days"],
        "window_start": window["start"],
        "window_end": window["end"],
        "sign_ins_complete": readable and complete and not truncated,
        "sign_ins_truncated": truncated,
        "total_sign_ins": when(tally.total),
        "successful_sign_ins": when(c["successful"]),
        "failed_sign_ins": when(c["failed"]),
        "users_signing_in": when(len(users)),
        "apps_signed_in_to": when(len(apps)),
        # --- did each sign-in require and pass MFA ---
        "successful_single_factor_sign_ins": when(c["successful_single_factor"]),
        "successful_multi_factor_sign_ins": when(c["successful_multi_factor"]),
        "successful_sign_ins_with_unknown_requirement": when(c["successful_unknown_requirement"]),
        "successful_windows_device_sign_ins": when(c["successful_windows_device"]),
        "multi_factor_percentage": when(
            coverage_percentage(c["successful_multi_factor"], app_successful) if app_successful else None
        ),
        "users_with_single_factor_sign_ins": when(sum(1 for u in users if u["successful_single_factor"])),
        "apps_with_single_factor_sign_ins": when(sum(1 for a in apps if a["successful_single_factor"])),
        "successful_legacy_authentication_sign_ins": when(c["successful_legacy_authentication"]),
        # --- which methods were used ---
        "methods_used": when(sorted_counts(tally.methods)),
        "successful_phishing_resistant_sign_ins": when(c["successful_phishing_resistant"]),
        "users_using_phishing_resistant_methods": when(
            sum(1 for u in users if u["successful_phishing_resistant"])
        ),
        # --- did Conditional Access apply ---
        "successful_sign_ins_without_conditional_access": when(c["successful_without_conditional_access"]),
        "users_with_sign_ins_without_conditional_access": when(
            sum(1 for u in users if u["successful_without_conditional_access"])
        ),
        "conditional_access_failures": when(c["conditional_access_failures"]),
        # --- which sign-ins Entra rated risky ---
        "risk_levels_available": when(risk_levels_available),
        "risky_sign_ins": risk(c["risky"]),
        "risky_sign_ins_by_level": risk(sorted_counts(tally.levels)),
        "risky_sign_ins_by_state": risk(sorted_counts(tally.states)),
        "users_with_risky_sign_ins": risk(sum(1 for u in users if u["risky"])),
        # --- the sign-ins listed one by one ---
        "exception_sign_ins": when(exceptions_total),
        "exception_sign_ins_listed": when(len(exceptions)),
        "users_listed": when(len(listed_users)),
    }
    results = {
        "users": listed_users,
        "apps": apps,
        "exception_sign_ins": exceptions,
    }
    return results, summary


# --- collection ---

def resolve_tenant(client: AzureRestClient, collector: Collector) -> Dict[str, Any]:
    """The organization read first, AZURE_TENANT_ID second; provenance, so a denied read only warns."""
    env_tenant = (os.environ.get("AZURE_TENANT_ID") or "").strip() or None
    try:
        orgs = client.graph_list("/organization?$select=id,displayName,verifiedDomains")
    except Exception as exc:  # noqa: BLE001 — provenance, not evidence
        logger.warning("organization read failed (%s); using AZURE_TENANT_ID", type(exc).__name__)
        orgs = []
    if orgs:
        domains = orgs[0].get("verifiedDomains") or []
        default = next((d.get("name") for d in domains if d.get("isDefault")), None)
        return {"tenant_id": orgs[0].get("id") or env_tenant, "tenant_name": orgs[0].get("displayName"),
                "tenant_domain": default, "tenant_source": "organization"}
    if env_tenant:
        return {"tenant_id": env_tenant, "tenant_name": None, "tenant_domain": None, "tenant_source": "environment"}
    collector.record("resolve_tenant", RuntimeError("could not identify the tenant (organization read failed "
                                                    "and AZURE_TENANT_ID is unset)"))
    return {"tenant_id": None, "tenant_name": None, "tenant_domain": None, "tenant_source": "unresolved"}


def lookback_window(now: datetime) -> Dict[str, Any]:
    days = min(int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS), MAX_LOOKBACK_DAYS)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"lookback_days": days, "start": start, "end": now.strftime("%Y-%m-%dT%H:%M:%SZ")}


def collect(client: AzureRestClient, collector: Collector, window: Dict[str, Any]):
    start = window["start"]
    # beta: v1.0 has no authenticationRequirement or authenticationDetails. Interactive sign-ins only.
    path = f"/auditLogs/signIns?$filter=createdDateTime ge {start}&$top=1000"
    tally, complete, truncated, status = Tally(), True, False, "read"
    pages = 0
    try:
        for page in client.graph_pages(path, "beta"):
            pages += 1
            for s in page:
                tally.add(sign_in_record(s))
            if tally.total >= SIGN_IN_LIMIT:
                truncated = True
                break
    except Exception as exc:  # noqa: BLE001 — boundary: record, keep the pages read
        complete = False
        # No P1/P2 is the tenant's state, not a failed read: the figures stay null and the run succeeds.
        if pages == 0 and getattr(exc, "status", None) == 403 and getattr(exc, "code", None) == NOT_LICENSED_CODE:
            logger.warning("Sign-in logs need Entra ID P1 or P2: %s", exc)
            status = "not_licensed"
        else:
            collector.record("graph.auditLogs.signIns.get(beta)", exc)
            if tally.total == 0:
                status = "not_read"
    if truncated:
        collector.record("graph.auditLogs.signIns.get(beta)", RuntimeError(
            f"stopped after {SIGN_IN_LIMIT} sign-ins; shorten {LOOKBACK_ENV}"))
    logger.info("Read %d sign-in(s) since %s", tally.total, start)
    return results_and_summary(tally, window, status, complete, truncated)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    for noisy in ("azure", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    window = lookback_window(datetime.now(timezone.utc))

    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    tenant: Dict[str, Any] = {"tenant_source": "unresolved"}
    if cred is not None:
        client = AzureRestClient(cred)
        tenant = resolve_tenant(client, collector)
        results, summary = collect(client, collector, window)
    else:
        results, summary = results_and_summary(Tally(), window, "not_read", False, False)

    scoping = tenant_scoping()
    evidence = tenant_payload(
        build_payload,
        tenant=tenant,
        subscription_id=scoping["subscription_id"],
        subscription_source=scoping["subscription_source"],
        collector=collector,
        results=results,
        summary=summary,
    )
    path = write_evidence(output_dir, f"{NAME}_{tenant_filename_key(tenant)}.json", evidence)
    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
