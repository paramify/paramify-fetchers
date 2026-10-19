#!/usr/bin/env python3
"""
Training-completion evidence shared by every cornerstone training fetcher.

Each fetcher measures one training group that KSI-CED-RAT names (general
security awareness, role-based training for high-risk roles, secure software
development, incident response / disaster recovery). They differ only in which
courses they measure and how the group is described, so the collection and the
summary live here.

How a run works:

1. Resolve each configured course name in ``vw_rpt_training`` by exact title,
   training reference number, course code, or object id. A name can match more
   than one catalog entry (versions, language copies); all matches are kept and
   listed in the evidence.
2. Read every transcript row for the matched trainings from
   ``vw_rpt_transcript``, all registrations, so an earlier completion is still
   visible when an annual re-assignment opened a new one.
3. Optionally read the user population (``vw_rpt_user`` with a filter the
   customer supplies, e.g. active employees), so users who were never assigned
   the course show up as ``not_assigned`` instead of silently missing.
4. Summarize per course and overall.

Rules carried over from the knowbe4 category, because they are load-bearing:

- **null means "not measured", 0 means "measured, and it is zero".** A course
  name that matches nothing in the catalog reports every metric as null and
  ``config_resolution`` names what did not resolve. It exits 0: a config typo is
  self-diagnosing in the evidence, not a red nightly run.
- **No fetcher decides pass or fail.** The summary reports counts and rates;
  whether they are acceptable is decided downstream in Paramify.

Personal data: users are identified only by Cornerstone's internal numeric
``user_id``. No names or email addresses are requested from any view.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from csod_client import (
    CsodClient,
    CsodConfigError,
    current_timestamp,
    days_between,
    env_int,
    env_names,
    odata_string,
    parse_ts,
    provenance,
)

TRAINING_VIEW = "vw_rpt_training"
TRANSCRIPT_VIEW = "vw_rpt_transcript"
USER_VIEW = "vw_rpt_user"

# Columns from the Training and Transcript RTDW technical spec v26.03.
TRAINING_SELECT = [
    "object_id", "lo_title", "lo_type", "lo_object_type", "lo_version", "lo_active", "lo_status",
    "lo_create_dt", "lo_modified_dt", "training_version_effective_dt", "is_latest_training_version",
    "course_code", "lo_training_ref",
]
TRAINING_KEY = ["object_id"]
TRANSCRIPT_SELECT = [
    "transc_user_id", "transc_object_id", "reg_num", "user_lo_status_id", "user_lo_create_dt",
    "user_lo_assigned_dt", "user_lo_reg_dt", "user_lo_start_dt", "user_lo_comp_dt", "user_lo_min_due_date",
    "user_lo_pct_complete", "user_lo_pass", "is_removed", "archived", "exempt_dt", "is_assigned",
    "is_required", "is_latest_reg_num", "user_lo_last_modified_dt",
]
TRANSCRIPT_KEY = ["transc_user_id", "transc_object_id", "reg_num"]
USER_SELECT = ["user_id"]
USER_KEY = ["user_id"]

# Keep each OData $filter well under the 2,083-character URL limit Cornerstone warns about.
# 25 ids plus the $select list measured 1,919 characters; 15 leaves a wide margin.
_OBJECTS_PER_QUERY = 15
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

STATUSES = ("completed", "exempt", "in_progress", "not_started", "overdue", "not_assigned")


def scopes(with_population: bool) -> List[str]:
    """The OAuth scopes a run needs: one ``<view>:read`` per view it reads."""
    wanted = [f"{TRAINING_VIEW}:read", f"{TRANSCRIPT_VIEW}:read"]
    if with_population:
        wanted.append(f"{USER_VIEW}:read")
    return wanted


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "y", "yes"}
    return False


def _iso(ts: Optional[datetime]) -> Optional[str]:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def _chunks(items: Sequence[str], size: int) -> List[List[str]]:
    return [list(items[i:i + size]) for i in range(0, len(items), size)]


def _course_filter(name: str) -> str:
    clauses = [f"lo_title eq {odata_string(name)}", f"lo_training_ref eq {odata_string(name)}",
               f"course_code eq {odata_string(name)}"]
    if _GUID.match(name):
        clauses.append(f"object_id eq {name.lower()}")
    return " or ".join(clauses)


def _status_of(row: Dict[str, Any], now: datetime) -> str:
    if parse_ts(row.get("exempt_dt")):
        return "exempt"
    if parse_ts(row.get("user_lo_comp_dt")):
        return "completed"
    due = parse_ts(row.get("user_lo_min_due_date"))
    if due and due < now:
        return "overdue"
    pct = row.get("user_lo_pct_complete")
    started = parse_ts(row.get("user_lo_start_dt")) or (isinstance(pct, (int, float)) and pct > 0)
    return "in_progress" if started else "not_started"


def _registration_order(row: Dict[str, Any]) -> Tuple[Any, ...]:
    anchor = (parse_ts(row.get("user_lo_create_dt")) or parse_ts(row.get("user_lo_reg_dt"))
              or parse_ts(row.get("user_lo_assigned_dt")) or datetime.min.replace(tzinfo=timezone.utc))
    reg = row.get("reg_num") if isinstance(row.get("reg_num"), int) else 0
    return (anchor, reg)


def _user_record(user_id: Any, rows: List[Dict[str, Any]], now: datetime, retrain_days: int) -> Dict[str, Any]:
    latest = max(rows, key=_registration_order)
    status = _status_of(latest, now)
    completions = [ts for ts in (parse_ts(r.get("user_lo_comp_dt")) for r in rows) if ts]
    last_completed = max(completions) if completions else None
    since = days_between(last_completed, now)
    exempt = status == "exempt"
    current = exempt or (since is not None and since <= retrain_days)
    due = parse_ts(latest.get("user_lo_min_due_date"))
    return {
        "user_id": user_id,
        "status": status,
        "current": current,
        "needs_retraining": not current,
        "last_completed_at": _iso(last_completed),
        "days_since_last_completion": since,
        "latest_registration": {
            "training_object_id": latest.get("transc_object_id"),
            "reg_num": latest.get("reg_num"),
            # Cornerstone's own status code, unmapped, so a reviewer can check
            # the derived status against it (e.g. Withdrawn, Failed, Equivalent).
            "cornerstone_status_id": latest.get("user_lo_status_id"),
            "assigned_at": _iso(parse_ts(latest.get("user_lo_assigned_dt"))),
            "due_at": _iso(due),
            "days_overdue": (now - due).days if status == "overdue" and due else None,
            "completed_at": _iso(parse_ts(latest.get("user_lo_comp_dt"))),
            "passed": latest.get("user_lo_pass"),
            "required": latest.get("is_required"),
            "assigned": latest.get("is_assigned"),
            "archived": _truthy(latest.get("archived")),
            "exempt_at": _iso(parse_ts(latest.get("exempt_dt"))),
        },
        "registrations": len(rows),
    }


def _not_assigned(user_id: Any) -> Dict[str, Any]:
    return {"user_id": user_id, "status": "not_assigned", "current": False, "needs_retraining": True,
            "last_completed_at": None, "days_since_last_completion": None, "latest_registration": None,
            "registrations": 0}


def _summary(users: List[Dict[str, Any]], measurable: bool) -> Dict[str, Any]:
    def metric(value: Any) -> Any:
        return value if measurable else None

    counts = {s: sum(1 for u in users if u["status"] == s) for s in STATUSES}
    total = len(users)
    current = sum(1 for u in users if u["current"])
    overdue_days = [u["latest_registration"]["days_overdue"] for u in users
                    if u["latest_registration"] and u["latest_registration"]["days_overdue"] is not None]
    return {
        "users_in_scope": metric(total),
        **{s: metric(counts[s]) for s in STATUSES},
        "current": metric(current),
        "needs_retraining": metric(total - current),
        "completion_rate_pct": (None if not measurable or total == 0 else round(current * 100.0 / total, 2)),
        "max_days_overdue": metric(max(overdue_days) if overdue_days else 0),
    }


def collect_training_group(
    client: CsodClient,
    *,
    group: Dict[str, str],
    courses_env: str,
    population_env: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Collect and summarize one training group. ``group`` describes it for the
    evidence: ``key``, ``title`` and ``ksi_clause`` (the part of KSI-CED-RAT it
    speaks to).
    """
    now = datetime.now(timezone.utc)
    names = env_names(courses_env)
    if not names:
        raise CsodConfigError(f"{courses_env} is required: name the course(s) to measure, comma-separated")
    retrain_days = env_int("CSOD_RETRAINING_INTERVAL_DAYS", 365, minimum=1)
    review_days = env_int("CSOD_CONTENT_REVIEW_INTERVAL_DAYS", 365, minimum=1)
    population_filter = (population_env and os.environ.get(population_env, "").strip()) or None
    collection: List[Dict[str, Any]] = []

    # 1. Resolve courses.
    resolved: Dict[str, List[Dict[str, Any]]] = {}
    for name in names:
        rows, stats = client.read_view(TRAINING_VIEW, TRAINING_SELECT, TRAINING_KEY, _course_filter(name))
        collection.append({**stats, "purpose": f"resolve course {name!r}"})
        if rows is None:
            return _finish(client, group, names, retrain_days, review_days, population_filter,
                           None, collection, now)
        resolved[name] = sorted(rows, key=lambda r: str(r.get("object_id")))

    object_ids = sorted({str(r["object_id"]) for rows in resolved.values() for r in rows if r.get("object_id")})
    # Server-supplied ids go into the next $filter unquoted (OData v4 Guid
    # literals), so anything that is not a plain GUID is refused, not sent.
    bad_ids = [oid for oid in object_ids if not _GUID.match(oid)]
    if bad_ids:
        client._record(TRAINING_VIEW, "UnexpectedResponse",
                       f"{len(bad_ids)} training object_id value(s) were not GUIDs; not used in a filter", 200)
        return _finish(client, group, names, retrain_days, review_days, population_filter,
                       None, collection, now)

    # 2. Transcript rows for every matched training, all registrations.
    transcript: List[Dict[str, Any]] = []
    for chunk in _chunks(object_ids, _OBJECTS_PER_QUERY):
        flt = " or ".join(f"transc_object_id eq {oid}" for oid in chunk)
        rows, stats = client.read_view(TRANSCRIPT_VIEW, TRANSCRIPT_SELECT, TRANSCRIPT_KEY, flt)
        collection.append({**stats, "purpose": f"transcripts for {len(chunk)} training object(s)"})
        if rows is None:
            return _finish(client, group, names, retrain_days, review_days, population_filter,
                           None, collection, now)
        transcript.extend(rows)

    # 3. Optional population.
    population: Optional[List[Any]] = None
    if population_filter:
        rows, stats = client.read_view(USER_VIEW, USER_SELECT, USER_KEY, population_filter)
        collection.append({**stats, "purpose": "user population"})
        if rows is None:
            return _finish(client, group, names, retrain_days, review_days, population_filter,
                           None, collection, now)
        population = sorted({r.get("user_id") for r in rows if r.get("user_id") is not None},
                            key=lambda v: (str(type(v)), v))

    data = {"resolved": resolved, "transcript": transcript, "population": population}
    return _finish(client, group, names, retrain_days, review_days, population_filter, data, collection, now)


def _course_entry(name: str, trainings: List[Dict[str, Any]], transcript: List[Dict[str, Any]],
                  population: Optional[List[Any]], now: datetime, retrain_days: int,
                  review_days: int) -> Tuple[Dict[str, Any], Dict[Any, Dict[str, Any]]]:
    ids = {str(t.get("object_id")) for t in trainings}
    measurable = bool(trainings)
    by_user: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    removed = 0
    for row in transcript:
        if str(row.get("transc_object_id")) not in ids:
            continue
        if _truthy(row.get("is_removed")):
            removed += 1
            continue
        by_user[row.get("transc_user_id")].append(row)

    # Keyed by str(user_id): the transcript and user views both document an int,
    # but a portal that serializes one as a string must not turn every user
    # into not_assigned. The original value is kept in the record.
    users: Dict[str, Dict[str, Any]] = {str(uid): _user_record(uid, rows, now, retrain_days)
                                         for uid, rows in by_user.items()}
    outside = 0
    if not measurable:
        # An unresolved course measures nobody; listing the population as
        # not_assigned would give a validator real-looking counts under null metrics.
        users = {}
    elif population is not None:
        in_pop = {str(uid) for uid in population}
        outside = sum(1 for key in users if key not in in_pop)
        users = {str(uid): users.get(str(uid)) or _not_assigned(uid) for uid in population}

    catalog = []
    for t in trainings:
        modified = parse_ts(t.get("lo_modified_dt"))
        effective = parse_ts(t.get("training_version_effective_dt"))
        latest_change = max([d for d in (modified, effective) if d], default=None)
        since = days_between(latest_change, now)
        catalog.append({
            "object_id": t.get("object_id"),
            "title": t.get("lo_title"),
            "type": t.get("lo_type") or t.get("lo_object_type"),
            "training_reference": t.get("lo_training_ref"),
            "course_code": t.get("course_code"),
            "version": t.get("lo_version"),
            "active": t.get("lo_active"),
            "catalog_status": t.get("lo_status"),
            "is_latest_version": t.get("is_latest_training_version"),
            "created_at": _iso(parse_ts(t.get("lo_create_dt"))),
            "last_modified_at": _iso(modified),
            "version_effective_at": _iso(effective),
            "days_since_content_change": since,
            "content_changed_within_review_interval": (None if since is None else since <= review_days),
        })

    ordered = sorted(users.values(), key=lambda u: str(u["user_id"]))
    entry = {
        "name": name,
        "resolved": measurable,
        "trainings": catalog,
        "summary": {**_summary(ordered, measurable),
                    "removed_registrations_excluded": removed if measurable else None,
                    "users_outside_population_excluded": (outside if measurable and population is not None
                                                          else None)},
        "users": ordered,
    }
    return entry, users


def _finish(client: CsodClient, group: Dict[str, str], names: List[str], retrain_days: int, review_days: int,
            population_filter: Optional[str], data: Optional[Dict[str, Any]],
            collection: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    failures = list(client.api_failures)
    base: Dict[str, Any] = {
        "retrieved_at": current_timestamp(),
        "portal": provenance(client),
        "training_group": group,
        "config": {
            "courses": names,
            "retraining_interval_days": retrain_days,
            "content_review_interval_days": review_days,
            "user_population_filter": population_filter,
            "population_source": ("vw_rpt_user rows matching user_population_filter" if population_filter
                                  else "users holding the course on their transcript (assigned or registered)"),
        },
        "collection": collection,
        "api_failures": failures,
    }
    if data is None:
        reason = failures[0]["message"] if failures else "collection stopped"
        return {**base, "status": "error", "error_code": "partial_failure",
                "message": f"collection incomplete: {reason}",
                "metadata": {"partial_failure": True, "api_failures": failures, "complete": False,
                             "incomplete_reason": reason}}

    resolved: Dict[str, List[Dict[str, Any]]] = data["resolved"]
    unmatched = [n for n in names if not resolved.get(n)]
    courses: List[Dict[str, Any]] = []
    per_course_users: List[Dict[Any, Dict[str, Any]]] = []
    for name in names:
        entry, users = _course_entry(name, resolved.get(name, []), data["transcript"], data["population"],
                                     now, retrain_days, review_days)
        courses.append(entry)
        if entry["resolved"]:
            per_course_users.append(users)

    all_resolved = not unmatched
    overall_users = sorted({uid for users in per_course_users for uid in users})
    current_all = [uid for uid in overall_users
                   if all(users.get(uid, {}).get("current") for users in per_course_users)]
    overdue_any = [uid for uid in overall_users
                   if any(users.get(uid, {}).get("status") == "overdue" for users in per_course_users)]
    measurable = all_resolved

    def metric(value: Any) -> Any:
        return value if measurable else None

    summary = {
        "courses_configured": len(names),
        "courses_resolved": len(names) - len(unmatched),
        "users_in_scope": metric(len(overall_users)),
        "users_current_on_all_courses": metric(len(current_all)),
        "users_needing_retraining_on_any_course": metric(len(overall_users) - len(current_all)),
        "users_overdue_on_any_course": metric(len(overdue_any)),
        "completion_rate_pct": (None if not measurable or not overall_users
                                else round(len(current_all) * 100.0 / len(overall_users), 2)),
        "transcript_rows_read": len(data["transcript"]),
        "population_size": metric(len(data["population"])) if data["population"] is not None else None,
    }
    resolution_status = "resolved" if all_resolved else ("unresolved" if len(unmatched) == len(names) else "partial")
    has_rows = bool(overall_users)
    if not all_resolved:
        message = ("course name(s) not found in the Cornerstone catalog: " + ", ".join(unmatched)
                   + "; their metrics, and the overall summary, are null (not measured)")
    elif not has_rows:
        message = "the configured course(s) exist but no user holds them on a transcript"
    else:
        message = None
    out = {
        **base,
        "status": "success" if all_resolved and has_rows else "partial_or_empty",
        "config_resolution": {
            "status": resolution_status,
            "matched": [n for n in names if resolved.get(n)],
            "unmatched": unmatched,
            "match_rule": "exact lo_title, lo_training_ref or course_code; or the training object_id",
        },
        "summary": summary,
        "courses": courses,
        "metadata": {"partial_failure": bool(failures), "api_failures": failures,
                     "complete": not failures and all(c.get("complete") for c in collection),
                     "incomplete_reason": None if not failures else failures[0]["message"]},
    }
    if message:
        out["message"] = message
    return out
