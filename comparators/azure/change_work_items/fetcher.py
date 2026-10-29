#!/usr/bin/env python3
"""
KSI-CMT-RMV / KSI-CMT-LMC: direct Azure changes and the work items that record them

Reads azure_change_provenance and azure_devops_work_items from the same run and
matches each direct change (an edit made outside any deployment or pipeline) to
the record work items that name its caller and were open when it was made. A
change is excluded when its caller is a configured excluded caller, matched to
one record, ambiguous between several, unmatched, not_a_person when an
application made it, or no_caller when Azure recorded no caller for it.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))  # comparators/_lib
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "fetchers" / "_lib"))

from comparator_inputs import run  # noqa: E402
from fetcher_status import report_failure  # noqa: E402

CHANGES = "azure_change_provenance"
WORK_ITEMS = "azure_devops_work_items"
OUTPUT = "azure_change_work_items.json"

STATUSES = ("matched", "ambiguous", "unmatched", "excluded", "not_a_person", "no_caller")
RECORDED = ("matched", "ambiguous")
PEOPLE = ("assigned_to", "created_by", "changed_by", "resolved_by", "closed_by", "state_history", "approver")
DEFAULT_PEOPLE = "assigned_to,created_by,resolved_by,closed_by,state_history"
NO_CALLER = {"system", "unspecified"}
# change_provenance gives a callerless row the origin of the nearest named change to the same resource this close.
SAME_RESOURCE = timedelta(minutes=10)

SUMMARY_KEYS = (
    "changes_checked", "changes_excluded", "changes_needing_record",
    "changes_matched", "changes_ambiguous", "changes_unmatched", "changes_not_by_a_person", "changes_without_caller",
    "changes_recorded", "changes_without_record", "changes_without_approved_record", "percent_recorded",
    "changes_without_record_by_caller", "changes_excluded_by_caller",
    "record_types", "record_types_not_selected", "record_work_items", "work_items_cover_changes",
)


def csv_env(env, default=""):
    return [v.strip() for v in os.environ.get(env, default).split(",") if v.strip()]


def hours_env(env, default):
    raw = os.environ.get(env, "").strip() or str(default)
    if not raw.isdigit():
        raise ValueError(f"{env} must be a whole number of hours, 0 or more, got {raw!r}")
    return timedelta(hours=int(raw))


def settings():
    people = [p.lower() for p in csv_env("CHANGE_RECORD_PEOPLE", DEFAULT_PEOPLE)]
    unknown = sorted(set(people) - set(PEOPLE))
    if unknown or not people:
        raise ValueError(f"CHANGE_RECORD_PEOPLE names {unknown or 'nothing'}; use any of {', '.join(PEOPLE)}")
    return {
        "origins": {o.lower() for o in csv_env("CHANGE_RECORD_ORIGINS", "direct")},
        "excluded": {c.lower() for c in csv_env("CHANGE_RECORD_EXCLUDED_CALLERS")},
        "environments": {e.lower() for e in csv_env("CHANGE_RECORD_ENVIRONMENTS")},
        "types": [t.lower() for t in csv_env("CHANGE_RECORD_TYPES")],
        "people": people,
        "before": hours_env("CHANGE_RECORD_HOURS_BEFORE", 24),
        "after": hours_env("CHANGE_RECORD_HOURS_AFTER", 24),
    }


def when(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def named(change):
    who = {str(change.get("changed_by") or "").strip().lower(), str(change.get("changed_by_type") or "").lower()}
    return bool(change.get("changed_by")) and not who & NO_CALLER


def resource(change):
    return str(change.get("target_resource_id") or "").lower()


def caller_of(change, by_resource):
    """(caller, caller type, where the caller came from), taking a callerless row's caller from the same resource."""
    if named(change):
        return change["changed_by"], change.get("changed_by_type"), "changed_by"
    at = when(change.get("timestamp"))
    near = [(abs(when(c["timestamp"]) - at), c) for c in by_resource.get(resource(change), [])
            if at and when(c.get("timestamp"))]
    near = [(gap, c) for gap, c in near if gap <= SAME_RESOURCE]
    if not near:
        return None, None, None
    partner = min(near, key=lambda pair: (pair[0], str(pair[1].get("change_id"))))[1]
    return partner["changed_by"], partner.get("changed_by_type"), "same_resource"


def logins(item, fields):
    found = []
    for field in fields:
        if field == "state_history":
            found += [(h.get("by") or {}).get("login") for h in item.get("state_history") or []]
        elif field == "approver":
            found.append(((item.get("approval") or {}).get("by") or {}).get("login"))
        else:
            found.append((item.get(field) or {}).get("login"))
    return {str(f).lower() for f in found if f}


def finished_at(item):
    """When the item reached its current, finished state."""
    entered = [when(h.get("at")) for h in item.get("state_history") or [] if h.get("to") == item.get("state")]
    for at in (when(item.get("closed_date")), when(item.get("resolved_date")),
               max((t for t in entered if t), default=None), when(item.get("changed_date"))):
        if at:
            return at
    return None


def records(files, cfg):
    """Each record work item with its people and the window it covers; Removed items never count."""
    out, types, unselected, cover_from = [], set(), set(), []
    for f in files:
        results = f.payload.get("results") or {}
        selected = [t.lower() for t in (results.get("selection") or {}).get("work_item_types") or []]
        wanted = cfg["types"] or selected
        types.update(wanted)
        unselected.update(set(wanted) - set(selected))
        start = when((results.get("window") or {}).get("start"))
        cover_from.append(start + cfg["after"] if start else None)
        org = (f.target or {}).get("organization_url") or (f.metadata.get("target") or {}).get("organization_url")
        for item in results.get("work_items") or []:
            if str(item.get("type")).lower() not in wanted or item.get("state_category") == "Removed":
                continue
            created = when(item.get("created_date"))
            if created is None:
                continue
            end = None if item.get("open") is not False else finished_at(item)
            approval = item.get("approval")
            out.append({
                "logins": logins(item, cfg["people"]),
                "from": created - cfg["before"],
                "to": end + cfg["after"] if end else None,
                "ref": {
                    "organization": org, "project": item.get("project"), "id": item.get("id"),
                    "type": item.get("type"), "state": item.get("state"),
                    "approved": bool(approval) if item.get("approval_read") else None,
                    "approved_at": (approval or {}).get("at"),
                },
            })
    return out, sorted(types), sorted(unselected), cover_from


def check_with(cfg):
    def check(inputs):
        changes = [c for f in inputs[CHANGES].files
                   if not cfg["environments"] or str((f.target or {}).get("environment") or "").lower()
                   in cfg["environments"]
                   for c in (f.payload.get("results") or {}).get("changes") or []]
        by_resource = {}
        for c in changes:
            if named(c):
                by_resource.setdefault(resource(c), []).append(c)
        items, types, unselected, cover_from = records(inputs[WORK_ITEMS].files, cfg)

        results = []
        for c in changes:
            if str(c.get("origin") or "").lower() not in cfg["origins"]:
                continue
            caller, caller_type, source = caller_of(c, by_resource)
            at = when(c.get("timestamp"))
            found = []
            if caller is None:
                status = "no_caller"
            elif caller.lower() in cfg["excluded"]:
                status = "excluded"
            elif caller_type != "User":
                status = "not_a_person"
            else:
                found = [i["ref"] for i in items if caller.lower() in i["logins"] and at and i["from"] <= at
                         and (i["to"] is None or at <= i["to"])]
                status = "unmatched" if not found else "matched" if len(found) == 1 else "ambiguous"
            results.append({
                "change_id": c.get("change_id"), "timestamp": c.get("timestamp"),
                "target_resource_id": c.get("target_resource_id"), "operation": c.get("operation"),
                "client_type": c.get("client_type"), "origin": c.get("origin"),
                "caller": caller, "caller_type": caller_type, "caller_from": source,
                "status": status, "work_items": found,
                # Several candidates count as approved only when every one of them is.
                "approved": all(w["approved"] for w in found) if found else None,
            })
        results.sort(key=lambda r: (str(r["timestamp"]), str(r["change_id"])))
        return results, summarize(results, items, types, unselected, cover_from)
    return check


def summarize(results, items, types, unselected, cover_from):
    count = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
    needing = len(results) - count["excluded"]
    recorded = count["matched"] + count["ambiguous"]
    approved = sum(1 for r in results if r["status"] in RECORDED and r["approved"])
    earliest = min((when(r["timestamp"]) for r in results if r["status"] != "excluded" and when(r["timestamp"])),
                   default=None)
    return {
        "changes_checked": len(results),
        "changes_excluded": count["excluded"],
        "changes_needing_record": needing,
        "changes_matched": count["matched"],
        "changes_ambiguous": count["ambiguous"],
        "changes_unmatched": count["unmatched"],
        "changes_not_by_a_person": count["not_a_person"],
        "changes_without_caller": count["no_caller"],
        "changes_recorded": recorded,
        "changes_without_record": needing - recorded,
        "changes_without_approved_record": needing - approved,
        "percent_recorded": recorded * 100 // needing if needing else 0,
        "changes_without_record_by_caller": by_caller(r for r in results
                                                      if r["status"] not in RECORDED + ("excluded",)),
        "changes_excluded_by_caller": by_caller(r for r in results if r["status"] == "excluded"),
        "record_types": types,
        # Selected by tag at most, so the work items fetcher may have left some out.
        "record_types_not_selected": unselected,
        "record_work_items": len(items),
        "work_items_cover_changes": bool(cover_from) and (
            earliest is None or all(start is not None and start <= earliest for start in cover_from)),
    }


def by_caller(results):
    counts = {}
    for r in results:
        key = r["caller"] or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def main():
    try:
        cfg = settings()
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1
    return run(check_with(cfg), output=OUTPUT, summary_keys=SUMMARY_KEYS)


if __name__ == "__main__":
    raise SystemExit(main())
