#!/usr/bin/env python3
"""Azure changes made outside a pipeline, each matched to the Azure DevOps work items that record it."""

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

ORIGINS = ("direct", "manual_deployment", "deployment", "pipeline", "platform", "unattributed")
STATUSES = ("matched", "ambiguous", "unmatched", "excluded", "application", "no_caller")
RECORDED = ("matched", "ambiguous")
WITHOUT_RECORD = ("unmatched", "no_caller")
PEOPLE = ("assigned_to", "created_by", "changed_by", "resolved_by", "closed_by", "state_history", "approver")
DEFAULT_PEOPLE = "assigned_to,created_by,closed_by"
NO_CALLER = {"system", "unspecified"}
# change_provenance gives a callerless row the origin of the nearest named change to the same resource this close.
SAME_RESOURCE = timedelta(minutes=10)

SUMMARY_KEYS = (
    "changes_read", "change_lookback_days", "origins",
    "changes_checked", "changes_excluded", "changes_by_application", "changes_needing_record",
    "changes_matched", "changes_ambiguous", "changes_unmatched", "changes_without_caller",
    "changes_recorded", "changes_without_record", "changes_recorded_without_approval",
    "changes_without_approved_record", "changes_approved_after_change", "percent_recorded",
    "changes_needing_record_by_origin", "changes_without_record_by_origin", "changes_without_approved_record_by_origin",
    "changes_without_record_by_caller", "changes_by_application_by_caller", "changes_excluded_by_caller",
    "record_types", "record_types_not_selected", "record_work_items", "work_items_cover_changes",
)


def csv_env(env, default=""):
    return [v.strip() for v in os.environ.get(env, default).split(",") if v.strip()]


def listed_env(env, default, allowed):
    values = [v.lower() for v in csv_env(env, default)]
    unknown = sorted(set(values) - set(allowed))
    if unknown or not values:
        raise ValueError(f"{env} names {unknown or 'nothing'}; use any of {', '.join(allowed)}")
    return values


def span_env(env, default, unit="hours"):
    raw = os.environ.get(env, "").strip() or str(default)
    if not raw.isdigit():
        raise ValueError(f"{env} must be a whole number of {unit}, 0 or more, got {raw!r}")
    return timedelta(**{unit: int(raw)})


def settings():
    return {
        "origins": set(listed_env("CHANGE_RECORD_ORIGINS", "direct,manual_deployment", ORIGINS)),
        "excluded": {c.lower() for c in csv_env("CHANGE_RECORD_EXCLUDED_CALLERS")},
        "environments": {e.lower() for e in csv_env("CHANGE_RECORD_ENVIRONMENTS")},
        "types": [t.lower() for t in csv_env("CHANGE_RECORD_TYPES")],
        "emergency_types": {t.lower() for t in csv_env("CHANGE_RECORD_EMERGENCY_TYPES", "Hotfix")},
        "people": listed_env("CHANGE_RECORD_PEOPLE", DEFAULT_PEOPLE, PEOPLE),
        "before": span_env("CHANGE_RECORD_HOURS_BEFORE", 24),
        "emergency_before": span_env("CHANGE_RECORD_EMERGENCY_HOURS_BEFORE", 72),
        "after": span_env("CHANGE_RECORD_HOURS_AFTER", 24),
        "open_days": span_env("CHANGE_RECORD_OPEN_ITEM_DAYS", 30, "days"),
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


def nearest(change, candidates, within=None):
    at = when(change.get("timestamp"))
    near = [(abs(when(c["timestamp"]) - at), str(c.get("change_id")), c) for c in candidates
            if at and when(c.get("timestamp"))]
    near = [n for n in near if within is None or n[0] <= within]
    return min(near, key=lambda n: n[:2])[2] if near else None


def caller_of(change, by_resource, by_deployment):
    """(caller, caller type, where it came from). A callerless row takes the caller of the nearest named change to
    the same resource, as change_provenance takes its origin, or else of the deployment it was attributed to."""
    if named(change):
        return change["changed_by"], change.get("changed_by_type"), "changed_by"
    partner = nearest(change, by_resource.get(resource(change), []), SAME_RESOURCE)
    source = "same_resource"
    if partner is None and change.get("deployment_id"):
        partner, source = nearest(change, by_deployment.get(change["deployment_id"], [])), "deployment"
    if partner is None:
        return None, None, None
    return partner["changed_by"], partner.get("changed_by_type"), source


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
            kind = str(item.get("type")).lower()
            if kind not in wanted or item.get("state_category") == "Removed":
                continue
            created = when(item.get("created_date"))
            if created is None:
                continue
            # An emergency record may be filed after the change it records.
            before = max(cfg["before"], cfg["emergency_before"]) if kind in cfg["emergency_types"] else cfg["before"]
            end = finished_at(item) if item.get("open") is False else None
            # An open item, or one in a state the fetcher couldn't place, covers changes only so long after it last moved.
            last = max(t for t in (created, when(item.get("changed_date"))) if t)
            approval = item.get("approval")
            out.append({
                "logins": logins(item, cfg["people"]),
                "from": created - before,
                "to": end + cfg["after"] if end else last + cfg["open_days"],
                "ref": {
                    "organization": org, "project": item.get("project"), "id": item.get("id"),
                    "type": item.get("type"), "state": item.get("state"),
                    "approved": bool(approval) if item.get("approval_read") else None,
                    "approved_at": (approval or {}).get("at"),
                },
            })
    return out, sorted(types), sorted(unselected), cover_from


def approved_after(found, at, emergency_types):
    """Whether a record approved after the change isn't an emergency type, which may be approved after the fact."""
    return any(str(w["type"]).lower() not in emergency_types and when(w["approved_at"]) and at
               and when(w["approved_at"]) > at for w in found)


def check_with(cfg):
    def check(inputs):
        files = [f for f in inputs[CHANGES].files
                 if not cfg["environments"] or str((f.target or {}).get("environment") or "").lower()
                 in cfg["environments"]]
        changes = [c for f in files for c in (f.payload.get("results") or {}).get("changes") or []]
        lookbacks = [(f.payload.get("results") or {}).get("lookback_days") for f in files]
        by_resource, by_deployment = {}, {}
        for c in changes:
            if named(c):
                by_resource.setdefault(resource(c), []).append(c)
                if c.get("deployment_id"):
                    by_deployment.setdefault(c["deployment_id"], []).append(c)
        items, types, unselected, cover_from = records(inputs[WORK_ITEMS].files, cfg)

        results = []
        for c in changes:
            if str(c.get("origin") or "").lower() not in cfg["origins"]:
                continue
            caller, caller_type, source = caller_of(c, by_resource, by_deployment)
            at = when(c.get("timestamp"))
            found = []
            if caller is None:
                status = "no_caller"
            elif caller.lower() in cfg["excluded"]:
                status = "excluded"
            elif str(caller_type or "").lower() not in ("", "user"):
                status = "application"
            else:
                found = [i["ref"] for i in items if caller.lower() in i["logins"] and at and i["from"] <= at <= i["to"]]
                status = "unmatched" if not found else "matched" if len(found) == 1 else "ambiguous"
            # Several candidates count as approved only when every one of them is.
            approved = all(w["approved"] for w in found) if found else None
            results.append({
                "change_id": c.get("change_id"), "timestamp": c.get("timestamp"),
                "target_resource_id": c.get("target_resource_id"), "operation": c.get("operation"),
                "client_type": c.get("client_type"), "origin": c.get("origin"), "deployment_id": c.get("deployment_id"),
                "caller": caller, "caller_type": caller_type, "caller_from": source,
                "status": status, "work_items": found, "approved": approved,
                "approved_after_change": approved_after(found, at, cfg["emergency_types"]) if approved else None,
            })
        results.sort(key=lambda r: (str(r["timestamp"]), str(r["change_id"])))
        read = {
            "changes_read": len(changes),
            # The shortest window any change file covers; null when none was read or one doesn't say.
            "change_lookback_days": min(lookbacks) if lookbacks and all(isinstance(n, int) for n in lookbacks)
            else None,
            "origins": sorted(cfg["origins"]),
        }
        return results, {**read, **summarize(results, items, types, unselected, cover_from, cfg["origins"])}
    return check


def needs_record(r):
    return r["status"] not in ("excluded", "application")


def approved_record(r):
    return r["status"] in RECORDED and bool(r["approved"])


def summarize(results, items, types, unselected, cover_from, origins):
    count = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
    needing = [r for r in results if needs_record(r)]
    recorded = count["matched"] + count["ambiguous"]
    approved = sum(1 for r in needing if approved_record(r))
    earliest = min((when(r["timestamp"]) for r in needing if when(r["timestamp"])), default=None)

    def by_origin(keep):
        counts = dict.fromkeys(sorted(origins), 0)
        for r in needing:
            if keep(r):
                key = str(r["origin"]).lower()
                counts[key] = counts.get(key, 0) + 1
        return counts

    return {
        "changes_checked": len(results),
        "changes_excluded": count["excluded"],
        "changes_by_application": count["application"],
        "changes_needing_record": len(needing),
        "changes_matched": count["matched"],
        "changes_ambiguous": count["ambiguous"],
        "changes_unmatched": count["unmatched"],
        "changes_without_caller": count["no_caller"],
        "changes_recorded": recorded,
        "changes_without_record": count["unmatched"] + count["no_caller"],
        "changes_recorded_without_approval": recorded - approved,
        "changes_without_approved_record": len(needing) - approved,
        "changes_approved_after_change": sum(1 for r in needing if r["approved_after_change"]),
        "percent_recorded": recorded * 100 // len(needing) if needing else 0,
        "changes_needing_record_by_origin": by_origin(lambda r: True),
        "changes_without_record_by_origin": by_origin(lambda r: r["status"] in WITHOUT_RECORD),
        "changes_without_approved_record_by_origin": by_origin(lambda r: not approved_record(r)),
        "changes_without_record_by_caller": by_caller(r for r in results if r["status"] in WITHOUT_RECORD),
        "changes_by_application_by_caller": by_caller(r for r in results if r["status"] == "application"),
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
