#!/usr/bin/env python3
"""Entra ID access reviews: how each review series is set up, whether it runs, and what its last cycle decided and applied."""

import asyncio
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    write_evidence,
)
from entra_graph import (  # noqa: E402
    graph_attr,
    paginate,
    resolve_tenant,
    tenant_filename_key,
    tenant_payload,
    tenant_scoping,
    with_graph_client,
)

NAME = "azure_entra_access_reviews"
# Without Entra ID P2 (or ID Governance) Graph refuses with this code, a state not a failure; reported on a 400 as well as a 403.
LICENCE_ERROR_CODE = "AadPremiumLicenseRequired"
LICENCE_STATUSES = (400, 403)
ENDED_DEFINITION = {"Completed", "AutoReviewed", "Applied"}
# Completing and AutoReviewing follow the end of a run's review period, so a run in either has ended.
ENDED_INSTANCE = {"Completing", "Completed", "AutoReviewing", "AutoReviewed", "Applying", "Applied"}
PERIOD_DAYS = {"daily": 1, "weekly": 7, "absoluteMonthly": 30, "relativeMonthly": 30, "absoluteYearly": 365, "relativeYearly": 365}
APPLIED = {"AppliedSuccessfully", "AppliedSuccessfullyButObjectNotFound"}
DECISIONS = ("Approve", "Deny", "NotReviewed", "DontKnow")
SCOPE_TYPES = ("group_membership", "application", "entra_role", "access_package", "other")
READ_CONCURRENCY = 8
# Eight decision reads at once drew 429s that the client's own quick retries didn't clear; two at a time.
DECISION_CONCURRENCY = 2
# Seconds before reading a list again while Graph still throttles it after those retries; a longer Retry-After wins.
THROTTLE_WAITS = (5, 15, 45)
# Graph pages these lists 100 at a time and documents $top/$skip; a full page with no nextLink means ask for more.
PAGE_SIZE = 100
PAGE_LIMIT = 1000
# A reviewer's justification is free text with no limit; longer ones are cut, and the cut is marked.
JUSTIFICATION_CHARS = 500
# Graph's reviewedBy/appliedBy on a decision no one reviewed or applied.
NOBODY = "00000000-0000-0000-0000-000000000000"

logger = logging.getLogger(NAME)
# The probe that sorts licence refusals from failures logs nothing itself; _read logs what it decides.
_probe_log = logging.getLogger(f"{NAME}.probe")
_probe_log.disabled = True


# --- projections: the only code here that touches a Graph model ---

def _kind(model) -> Optional[str]:
    tail = str(graph_attr(model, "odata_type") or "").rsplit(".", 1)[-1]
    return tail or None


def _duration(value: Any) -> Any:
    """kiota parses ISO-8601 durations into timedelta; render whole days back as PnD."""
    return f"P{value.days}D" if isinstance(value, timedelta) else value


def project_query(scope) -> Optional[Dict[str, Any]]:
    if scope is None:
        return None
    projected = {
        "type": _kind(scope),
        "query": graph_attr(scope, "query"),
        "query_type": graph_attr(scope, "query_type"),
        "query_root": graph_attr(scope, "query_root"),
        "inactive_duration": _duration(getattr(scope, "inactive_duration", None)),
        "principal_scopes": [project_query(s) for s in getattr(scope, "principal_scopes", None) or []] or None,
        "resource_scopes": [project_query(s) for s in getattr(scope, "resource_scopes", None) or []] or None,
    }
    return {k: v for k, v in projected.items() if v is not None}


def project_recurrence(recurrence) -> Optional[Dict[str, Any]]:
    pattern = getattr(recurrence, "pattern", None)
    if pattern is None:
        return None
    span = getattr(recurrence, "range", None)
    return {
        "pattern_type": graph_attr(pattern, "type"),
        "interval": graph_attr(pattern, "interval"),
        "range_type": graph_attr(span, "type"),
        "start_date": graph_attr(span, "start_date"),
        "end_date": graph_attr(span, "end_date"),
        "number_of_occurrences": graph_attr(span, "number_of_occurrences"),
    }


def project_definition(definition) -> Dict[str, Any]:
    settings = getattr(definition, "settings", None)
    created_by = getattr(definition, "created_by", None)
    return {
        "id": graph_attr(definition, "id"),
        "display_name": graph_attr(definition, "display_name"),
        "status": graph_attr(definition, "status"),
        "created_date_time": graph_attr(definition, "created_date_time"),
        "last_modified_date_time": graph_attr(definition, "last_modified_date_time"),
        "created_by": graph_attr(created_by, "user_principal_name") or graph_attr(created_by, "display_name"),
        "scope": project_query(getattr(definition, "scope", None)),
        "instance_enumeration_scope": project_query(getattr(definition, "instance_enumeration_scope", None)),
        "reviewers": [project_query(r) for r in getattr(definition, "reviewers", None) or []],
        "fallback_reviewers": [project_query(r) for r in getattr(definition, "fallback_reviewers", None) or []],
        "stages": [
            {
                "stage_id": graph_attr(stage, "stage_id"),
                "depends_on": graph_attr(stage, "depends_on") or [],
                "duration_in_days": graph_attr(stage, "duration_in_days"),
                "reviewers": [project_query(r) for r in getattr(stage, "reviewers", None) or []],
                "fallback_reviewers": [project_query(r) for r in getattr(stage, "fallback_reviewers", None) or []],
            }
            for stage in getattr(definition, "stage_settings", None) or []
        ],
        "settings": None if settings is None else {
            "recurrence": project_recurrence(getattr(settings, "recurrence", None)),
            "instance_duration_in_days": graph_attr(settings, "instance_duration_in_days"),
            "default_decision_enabled": graph_attr(settings, "default_decision_enabled"),
            "default_decision": graph_attr(settings, "default_decision"),
            "auto_apply_decisions_enabled": graph_attr(settings, "auto_apply_decisions_enabled"),
            "apply_actions": [_kind(a) for a in getattr(settings, "apply_actions", None) or []],
            "justification_required_on_approval": graph_attr(settings, "justification_required_on_approval"),
            "mail_notifications_enabled": graph_attr(settings, "mail_notifications_enabled"),
            "reminder_notifications_enabled": graph_attr(settings, "reminder_notifications_enabled"),
            "recommendations_enabled": graph_attr(settings, "recommendations_enabled"),
        },
    }


def project_instance(instance) -> Dict[str, Any]:
    return {
        "id": graph_attr(instance, "id"),
        "status": graph_attr(instance, "status"),
        "start_date_time": graph_attr(instance, "start_date_time"),
        "end_date_time": graph_attr(instance, "end_date_time"),
        "scope": project_query(getattr(instance, "scope", None)),
    }


def _identity(model) -> Optional[Dict[str, Any]]:
    if model is None or graph_attr(model, "id") == NOBODY:
        return None
    projected = {
        "id": graph_attr(model, "id"),
        "type": _kind(model),
        "display_name": graph_attr(model, "display_name"),
        "user_principal_name": graph_attr(model, "user_principal_name"),
    }
    return {k: v for k, v in projected.items() if v is not None}


def _capped(text: Optional[str]) -> Optional[str]:
    if not text or len(text) <= JUSTIFICATION_CHARS:
        return text
    return f"{text[:JUSTIFICATION_CHARS]} …[truncated, {len(text)} characters]"


def project_decision(item) -> Dict[str, Any]:
    resource = getattr(item, "resource", None)
    return {
        "id": graph_attr(item, "id"),
        "decision": graph_attr(item, "decision"),
        "recommendation": graph_attr(item, "recommendation"),
        "justification": _capped(graph_attr(item, "justification")),
        "reviewed_by": _identity(getattr(item, "reviewed_by", None)),
        "reviewed_date_time": graph_attr(item, "reviewed_date_time"),
        "apply_result": graph_attr(item, "apply_result"),
        "applied_by": _identity(getattr(item, "applied_by", None)),
        "applied_date_time": graph_attr(item, "applied_date_time"),
        "principal": _identity(getattr(item, "principal", None)),
        "resource": None if resource is None else {
            "id": graph_attr(resource, "id"),
            "display_name": graph_attr(resource, "display_name"),
            "type": graph_attr(resource, "type"),
        },
    }


# --- pure transforms ---

def _queries(scope: Optional[Dict[str, Any]]) -> List[str]:
    if not scope:
        return []
    nested = [q for s in (scope.get("principal_scopes") or []) + (scope.get("resource_scopes") or []) for q in _queries(s)]
    return [scope.get("query") or "", *nested]


def scope_type(definition: Dict[str, Any]) -> str:
    """What kind of access the series reviews, read from its scope queries."""
    text = " ".join(_queries(definition.get("scope")) + _queries(definition.get("instance_enumeration_scope"))).lower()
    if "/rolemanagement/directory/" in text:
        return "entra_role"
    if "accesspackageassignments" in text or "entitlementmanagement" in text:
        return "access_package"
    if "/privilegedaccess/group/" in text:
        return "group_membership"
    if "/serviceprincipals/" in text:
        return "application"
    if "/groups" in text or "/teams" in text:
        return "group_membership"
    return "other"


def recurrence_period_days(recurrence: Optional[Dict[str, Any]]) -> Optional[int]:
    if not recurrence or recurrence.get("pattern_type") not in PERIOD_DAYS:
        return None
    return PERIOD_DAYS[recurrence["pattern_type"]] * (recurrence.get("interval") or 1)


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def last_cycle(instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The latest cycle whose runs have all ended; a cycle is the runs that started at the same time, one per group."""
    cycles: Dict[datetime, List[Dict[str, Any]]] = {}
    for instance in instances:
        start = _parse(instance.get("start_date_time"))
        if start is not None:
            cycles.setdefault(start, []).append(instance)
    for start in sorted(cycles, reverse=True):
        runs = cycles[start]
        if all(i.get("status") in ENDED_INSTANCE and _parse(i.get("end_date_time")) for i in runs):
            return sorted(runs, key=lambda i: i.get("id") or "")
    return []


def decision_counts(decisions: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    if decisions is None:
        return None
    by_result = {d: 0 for d in DECISIONS}
    for item in decisions:
        key = item.get("decision") or "NotReviewed"
        by_result[key] = by_result.get(key, 0) + 1
    denied = [d for d in decisions if d.get("decision") == "Deny"]
    return {
        "decisions": len(decisions),
        "decisions_by_result": by_result,
        "denied_decisions_applied": sum(1 for d in denied if d.get("apply_result") in APPLIED),
        "denied_decisions_not_applied": sum(1 for d in denied if d.get("apply_result") not in APPLIED),
    }


def definition_record(definition: Dict[str, Any], read_instances: Optional[List[Dict[str, Any]]],
                      decisions: Dict[str, Optional[List[Dict[str, Any]]]], now: datetime) -> Dict[str, Any]:
    instances = read_instances or []
    settings = definition.get("settings") or {}
    stages = definition.get("stages") or []
    recurrence = settings.get("recurrence")
    period = recurrence_period_days(recurrence)
    at_least_monthly = period is not None and period <= 31
    default_deny = settings.get("default_decision_enabled") is True and settings.get("default_decision") == "Deny"
    auto_apply = settings.get("auto_apply_decisions_enabled") is True
    cycle = last_cycle(instances)
    # last_cycle keeps only runs whose end time parses; `or now` is for the type checker.
    latest = max(cycle, key=lambda i: _parse(i["end_date_time"]) or now, default=None)
    cycle_end = None if latest is None else _parse(latest["end_date_time"])
    # None where an instance's decisions weren't read: an ended series' are skipped, a failed read is unknown.
    read = [decisions.get(i["id"]) for i in cycle]
    cycle_records = [{**i, "decision_counts": decision_counts(items), "decision_items": items} for i, items in zip(cycle, read)]
    return {
        **definition,
        "scope_type": scope_type(definition),
        "active": definition.get("status") not in ENDED_DEFINITION,
        "recurring": recurrence is not None,
        "recurrence_period_days": period,
        "recurs_at_least_monthly": at_least_monthly,
        "default_decision_deny": default_deny,
        "auto_applies_decisions": auto_apply,
        "auto_removal": default_deny and auto_apply,
        "monthly_auto_removal": at_least_monthly and default_deny and auto_apply,
        # Graph ignores the top-level reviewers once a series has stages; each stage names its own.
        "self_review": not any(st["reviewers"] for st in stages) if stages else not definition.get("reviewers"),
        "instances_read": None if read_instances is None else len(instances),
        "instances_in_progress": sum(1 for i in instances if i.get("status") not in ENDED_INSTANCE | {"NotStarted"}),
        "last_completed_cycle_end": None if latest is None else latest["end_date_time"],
        "days_since_last_completed_cycle": None if cycle_end is None else max(0, (now - cycle_end).days),
        "last_cycle": None if None in read else decision_counts([d for items in read for d in items or []]),
        "last_cycle_instances": cycle_records,
    }


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    active = [r for r in records if r["active"]]
    recurring = [r for r in active if r["recurring"]]
    meeting = [r for r in active if r["monthly_auto_removal"]]
    periods = [r["recurrence_period_days"] for r in active]
    by_result = {d: 0 for d in DECISIONS}
    for r in active:
        for key, n in r["last_cycle"]["decisions_by_result"].items():
            by_result[key] = by_result.get(key, 0) + n

    def names(rows):
        return sorted(r["display_name"] or r["id"] or "" for r in rows)

    return {
        "access_reviews_available": True,
        "review_definitions": len(records),
        "active_review_definitions": len(active),
        "active_definitions_by_scope_type": {t: sum(1 for r in active if r["scope_type"] == t) for t in SCOPE_TYPES},
        "active_definitions_recurring_at_least_monthly": sum(1 for r in active if r["recurs_at_least_monthly"]),
        "active_definitions_default_deny": sum(1 for r in active if r["default_decision_deny"]),
        "active_definitions_auto_applying": sum(1 for r in active if r["auto_applies_decisions"]),
        "active_definitions_monthly_auto_removal": len(meeting),
        "monthly_auto_removal_percentage": coverage_percentage(len(meeting), len(active)),
        "active_definitions_without_monthly_auto_removal": names(r for r in active if not r["monthly_auto_removal"]),
        "all_active_definitions_monthly_auto_removal": bool(active) and len(meeting) == len(active),
        # The KSIs set no cadence: these two let a validator choose its own bar instead of monthly.
        "all_active_definitions_auto_removal": bool(active) and all(r["auto_removal"] for r in active),
        "max_active_recurrence_period_days": None if not active or None in periods else max(periods),
        "active_self_review_definitions": names(r for r in active if r["self_review"]),
        "active_recurring_definitions_without_completed_cycle": names(
            r for r in recurring if r["last_completed_cycle_end"] is None
        ),
        "max_days_since_last_completed_cycle": max(
            (r["days_since_last_completed_cycle"] for r in recurring if r["days_since_last_completed_cycle"] is not None),
            default=None,
        ),
        "last_cycle_decisions": sum(r["last_cycle"]["decisions"] for r in active),
        "last_cycle_decisions_by_result": by_result,
        "last_cycle_denied_decisions_applied": sum(r["last_cycle"]["denied_decisions_applied"] for r in active),
        "last_cycle_denied_decisions_not_applied": sum(r["last_cycle"]["denied_decisions_not_applied"] for r in active),
    }


def build(definitions, instances, decisions, unlicensed, now: datetime) -> tuple:
    complete = (
        not unlicensed
        and definitions is not None
        and all(instances.get(d["id"]) is not None for d in definitions)
        and None not in decisions.values()
    )
    available = False if unlicensed else (True if complete else None)
    records = None if definitions is None else sorted(
        (definition_record(d, instances.get(d["id"]), decisions, now) for d in definitions),
        key=lambda r: ((r["display_name"] or "").lower(), r["id"] or ""),
    )
    results: Dict[str, Any] = {"access_reviews_available": available, "review_definitions": records}
    if unlicensed:
        results["notes"] = ["Access reviews are not available in this tenant (Entra ID P2 or ID Governance is required)", *unlicensed]
    # A failed read would turn into reviews that never ran, so no figures are given unless every read succeeded.
    if not complete or records is None:
        return results, {"access_reviews_available": available, "collection_complete": False}
    return results, {"collection_complete": True, **summarize(records)}


# --- collection (lazy msgraph imports) ---

def _query(builder, **params):
    from kiota_abstractions.base_request_configuration import RequestConfiguration

    parameters = getattr(type(builder), f"{type(builder).__name__}GetQueryParameters")
    return RequestConfiguration(query_parameters=parameters(**params))


async def _page(probe: Collector, operation: str, builder) -> List[Any]:
    """Every item: nextLinks are followed, and a full page without one asks for the next with $skip. A failed request raises."""
    items: List[Any] = []
    seen: set = set()
    for page in range(PAGE_LIMIT):
        batch = await paginate(
            probe, operation, builder, _query(builder, top=PAGE_SIZE, skip=page * PAGE_SIZE), raise_on_error=True
        )
        ids = [getattr(i, "id", None) for i in batch]
        if seen.intersection(i for i in ids if i):
            probe.record(operation, RuntimeError("$skip returned items already read; refusing to keep paging"))
            break
        seen.update(i for i in ids if i)
        items.extend(batch)
        if probe.failures or len(batch) != PAGE_SIZE:
            break
    else:
        probe.record(operation, RuntimeError(f"stopped after {PAGE_LIMIT} full pages; refusing to keep paging"))
    return items


def licence_refused(exc: BaseException) -> bool:
    """Graph's licence refusal, told by its error code; a permission failure never counts, whatever its text."""
    code = getattr(getattr(exc, "error", None), "code", None)
    return getattr(exc, "response_status_code", None) in LICENCE_STATUSES and code == LICENCE_ERROR_CODE


def retry_after(exc: BaseException) -> float:
    """Graph's Retry-After in seconds; 0 when it sent none or not a number."""
    headers = getattr(exc, "response_headers", None) or {}
    value = next((v for k, v in headers.items() if str(k).lower() == "retry-after"), "")
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


async def _read(collector: Collector, operation: str, builder, unlicensed: Optional[List[str]] = None) -> Optional[List[Any]]:
    """`_page`, read again after a wait while Graph throttles it; None when the read failed.

    Only a read given `unlicensed` notes a licence refusal there instead of failing.
    """
    for wait in (*THROTTLE_WAITS, None):
        probe = Collector(_probe_log)
        try:
            items = await _page(probe, operation, builder)
        except Exception as exc:  # noqa: BLE001 — boundary: a licence refusal or a failure, never a crash
            if unlicensed is not None and licence_refused(exc):
                unlicensed.append(f"{operation}: {exc}")
                logger.info("Access reviews unavailable: %s (%s)", operation, exc)
                return None
            if wait is not None and getattr(exc, "response_status_code", None) == 429:
                seconds = max(float(wait), retry_after(exc))
                logger.warning("%s throttled (429); reading it again in %.0fs", operation, seconds)
                await asyncio.sleep(seconds)
                continue
            probe.record(operation, exc)
        break
    for failure in probe.failures:
        collector.failures.append(failure)
        logger.error("API call failed: %s (%s: %s)", operation, failure.get("type"), failure.get("message"))
    return None if probe.failures else items


async def _collect(collector: Collector, cred) -> tuple:
    async def _work(client):
        tenant = await resolve_tenant(collector, client)
        unlicensed: List[str] = []
        root = client.identity_governance.access_reviews.definitions
        # Only the first read can show the tenant is unlicensed; a refusal after it is a failure.
        raw = await _read(collector, "graph.identityGovernance.accessReviews.definitions.get", root, unlicensed)
        definitions = None if raw is None else [project_definition(d) for d in raw]
        instances: Dict[str, Optional[List[Dict[str, Any]]]] = {}
        decisions: Dict[str, Optional[List[Dict[str, Any]]]] = {}
        if not definitions or unlicensed:
            return tenant, definitions, instances, decisions, unlicensed

        gate = asyncio.Semaphore(READ_CONCURRENCY)

        async def read_instances(definition_id: str):
            async with gate:
                items = await _read(
                    collector, f"graph.identityGovernance.accessReviews.definitions.instances.get ({definition_id})",
                    root.by_access_review_schedule_definition_id(definition_id).instances,
                )
            instances[definition_id] = None if items is None else [project_instance(i) for i in items]

        await asyncio.gather(*(read_instances(d["id"]) for d in definitions))
        decision_gate = asyncio.Semaphore(DECISION_CONCURRENCY)

        async def read_decisions(definition_id: str, instance_id: str):
            async with decision_gate:
                items = await _read(
                    collector,
                    f"graph.identityGovernance.accessReviews.definitions.instances.decisions.get ({instance_id})",
                    root.by_access_review_schedule_definition_id(definition_id)
                    .instances.by_access_review_instance_id(instance_id).decisions,
                )
            decisions[instance_id] = None if items is None else [project_decision(i) for i in items]

        # Decisions only for each active series' latest completed cycle: enough to show it ran and acted, and bounded.
        await asyncio.gather(*(
            read_decisions(d["id"], i["id"])
            for d in definitions
            if d.get("status") not in ENDED_DEFINITION
            for i in last_cycle(instances.get(d["id"]) or [])
        ))
        return tenant, definitions, instances, decisions, unlicensed

    result = await with_graph_client(collector, cred, _work, default=None)
    return result if result is not None else ({"tenant_source": "unresolved"}, None, {}, {}, [])


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for noisy in ("azure", "msgraph", "kiota", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    if cred is None:
        tenant: Dict[str, Any] = {"tenant_source": "unresolved"}
        results: Dict[str, Any] = {"access_reviews_available": None, "review_definitions": None}
        summary: Dict[str, Any] = {"access_reviews_available": None, "collection_complete": False}
    else:
        tenant, definitions, instances, decisions, unlicensed = asyncio.run(_collect(collector, cred))
        results, summary = build(definitions, instances, decisions, unlicensed, datetime.now(timezone.utc))

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
