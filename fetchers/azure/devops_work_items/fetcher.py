#!/usr/bin/env python3
"""Azure DevOps work items of chosen types or tags: state, owner, planned dates, approval and the changes linked to them."""

import html
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Pattern,
    Sequence,
    Tuple,
)
from urllib.parse import quote, unquote

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import sorted_counts  # noqa: E402
from devops_rest import (  # noqa: E402
    DevOpsClient,
    DevOpsCollector,
    DevOpsError,
    iso,
    list_projects,
    parse_time,
    run_org,
)

NAME = "azure_devops_work_items"
TYPES_ENV = "AZURE_DEVOPS_WORK_ITEM_TYPES"
TAGS_ENV = "AZURE_DEVOPS_WORK_ITEM_TAGS"
LOOKBACK_ENV = "AZURE_DEVOPS_LOOKBACK_DAYS"
APPROVAL_STATES_ENV = "AZURE_DEVOPS_APPROVAL_STATES"
APPROVAL_PATTERN_ENV = "AZURE_DEVOPS_APPROVAL_PATTERN"
DEFAULT_TYPES = ("Change Request",)
DEFAULT_TAGS = ("Security",)
DEFAULT_LOOKBACK_DAYS = 90
DEFAULT_APPROVAL_STATES = ("Approved",)
# A line starting "Approved" with no question mark, so "Approved?" doesn't count.
DEFAULT_APPROVAL_PATTERN = r"^\W*approved\b[^?\n]*$"
COMMENTS_API = "7.1-preview.4"
BATCH_SIZE = 200
UPDATES_PAGE = 200
DONE_CATEGORIES = frozenset({"completed", "removed"})
CATEGORY_ORDER = {"proposed": 0, "inprogress": 1, "resolved": 2, "completed": 3, "removed": 4}
REJECTED = re.compile(r"reject", re.IGNORECASE)

SCOPE_WORK = "Work Items (Read)"
SCOPE_CODE = "Code (Read)"

PEOPLE = {"created_by": "System.CreatedBy", "changed_by": "System.ChangedBy", "assigned_to": "System.AssignedTo",
          "resolved_by": "Microsoft.VSTS.Common.ResolvedBy", "closed_by": "Microsoft.VSTS.Common.ClosedBy"}
DATES = {"created_date": "System.CreatedDate", "changed_date": "System.ChangedDate",
         "activated_date": "Microsoft.VSTS.Common.ActivatedDate", "resolved_date": "Microsoft.VSTS.Common.ResolvedDate",
         "closed_date": "Microsoft.VSTS.Common.ClosedDate", "due_date": "Microsoft.VSTS.Scheduling.DueDate",
         "target_date": "Microsoft.VSTS.Scheduling.TargetDate", "finish_date": "Microsoft.VSTS.Scheduling.FinishDate"}
# Processes name the planned date differently; the first one set is the item's planned date.
PLANNED = ("due_date", "target_date", "finish_date")
ARTIFACTS = {("git", "pullrequestid"): "pull_requests", ("git", "commit"): "commits",
             ("versioncontrol", "changeset"): "changesets", ("build", "build"): "builds"}
WORK_ITEM_LINKS = {"System.LinkTypes.Hierarchy-Reverse": "parent", "System.LinkTypes.Hierarchy-Forward": "children",
                   "System.LinkTypes.Related": "related"}

# Keyed by area, not a list, so an evidence sample keeps every entry.
NOT_COLLECTED = {
    "text": "Descriptions, comment text, discussion history and attachments are never written; a comment counts as "
            "an approval when a line of its text, quoted text left out, matches approval_pattern, and only its "
            "author and time are kept.",
    "git_change_dates": "Linked Git commits and pull requests are recorded by id only; only TFVC changesets are "
                        "read for their date and author, so an item linked to a commit or pull request isn't "
                        "checked for changes made before approval or by its approver.",
    "items_outside_selection": "Work items of other types and without the configured tags, and finished items not "
                               "changed in the window.",
    "projects_not_visible": "Projects and work items the collecting identity (metadata.collecting_identity) "
                            "cannot see.",
}

logger = logging.getLogger(NAME)


def csv_config(env: str, default: Sequence[str]) -> List[str]:
    """Comma-separated values; unset or blank keeps the default, and "none" clears it."""
    raw = (os.environ.get(env) or "").strip()
    if not raw:
        return list(default)
    if raw.lower() == "none":
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def lookback_days() -> int:
    raw = (os.environ.get(LOOKBACK_ENV) or "").strip()
    if not raw:
        return DEFAULT_LOOKBACK_DAYS
    try:
        days = int(raw)
    except ValueError:
        raise ValueError(f"{LOOKBACK_ENV} must be an integer, got {raw!r}") from None
    if days < 1:
        raise ValueError(f"{LOOKBACK_ENV} must be at least 1, got {days}")
    return days


def approval_pattern() -> Pattern[str]:
    raw = os.environ.get(APPROVAL_PATTERN_ENV) or DEFAULT_APPROVAL_PATTERN
    try:
        return re.compile(raw, re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"{APPROVAL_PATTERN_ENV} is not a valid regular expression: {exc}") from None


def call(collector: DevOpsCollector, operation: str, scope: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """collector.guard, naming the PAT scope (or, for an Entra identity, the read access) on an auth refusal."""
    def scoped():
        try:
            return fn()
        except DevOpsError as exc:
            if exc.status in (401, 403) or exc.failure_code == "not_authorized":
                hint = (f"PAT scope needed: {scope}" if collector.auth_mode == "pat"
                        else f"the Entra identity lacks permission for this read; PAT equivalent: {scope}")
                exc.args = (f"{exc} [{hint}]",)
            raise
    return collector.guard(operation, scoped, default)


def wiql_text(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def person(value: Any) -> Optional[Dict[str, Any]]:
    """An identity field; the login key marks it as a person's record, so sample redaction replaces the name too."""
    if isinstance(value, dict):
        name, login = value.get("displayName"), value.get("uniqueName")
        return {"display_name": name, "login": login} if name or login else None
    if isinstance(value, str) and value.strip():
        # Some payloads give "Name <login>".
        found = re.fullmatch(r"(.*?)\s*<([^<>]+)>", value.strip())
        return {"display_name": found.group(1), "login": found.group(2)} if found else \
            {"display_name": value.strip(), "login": None}
    return None


def same_person(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> bool:
    la, lb = (a or {}).get("login"), (b or {}).get("login")
    return bool(la and lb and str(la).lower() == str(lb).lower())


def when(value: Any) -> Optional[datetime]:
    parsed = parse_time(value) if isinstance(value, str) else None
    return parsed.astimezone(timezone.utc) if parsed else None


def item_id(url: Any) -> Optional[int]:
    found = re.search(r"/workItems/(\d+)$", str(url or ""), re.IGNORECASE)
    return int(found.group(1)) if found else None


def links(relations: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"pull_requests": [], "commits": [], "changesets": [], "builds": [], "parent": None,
                           "children": [], "related": [], "other_work_items": 0, "hyperlinks": 0, "attachments": 0,
                           "other_artifacts": 0}
    for rel in relations if isinstance(relations, list) else []:
        if not isinstance(rel, dict):
            continue
        kind, url = rel.get("rel") or "", str(rel.get("url") or "")
        if kind == "ArtifactLink":
            found = re.fullmatch(r"vstfs:///([^/]+)/([^/]+)/(.+)", url, re.IGNORECASE)
            key = ARTIFACTS.get((found.group(1).lower(), found.group(2).lower())) if found else None
            if not found or not key:
                out["other_artifacts"] += 1
                continue
            # Git artifacts are "{project}/{repository}/{id}", escaped once or twice.
            parts = unquote(unquote(found.group(3))).split("/")
            if key == "pull_requests":
                out[key].append({"repository_id": parts[-2] if len(parts) > 1 else None, "id": _int(parts[-1])})
            elif key == "commits":
                out[key].append({"repository_id": parts[-2] if len(parts) > 1 else None, "commit": parts[-1]})
            else:
                out[key].append(_int(parts[-1]))
        elif kind in WORK_ITEM_LINKS:
            target = item_id(url)
            if WORK_ITEM_LINKS[kind] == "parent":
                out["parent"] = target
            else:
                out[WORK_ITEM_LINKS[kind]].append(target)
        elif kind.startswith("System.LinkTypes.") or kind.startswith("Microsoft.VSTS."):
            out["other_work_items"] += 1
        elif kind == "Hyperlink":
            out["hyperlinks"] += 1
        elif kind == "AttachedFile":
            out["attachments"] += 1
        else:
            out["other_artifacts"] += 1
    return out


def _int(value: Any) -> Any:
    return int(value) if str(value).isdigit() else value


def comment_text(raw: Any) -> str:
    """The comment's plain text without quoted text: a blockquote, or a line starting ">"."""
    text, before = str(raw or ""), None
    while text != before:  # innermost blockquote first, so nested quotes go too
        before, text = text, re.sub(r"<blockquote\b[^>]*>(?:(?!<blockquote\b).)*?</blockquote>", "\n", text,
                                    flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<br\s*/?>|</(?:div|p|li)>", "\n", text, flags=re.IGNORECASE)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(">"))


def state_history(updates: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    history = []
    for update in updates:
        fields = update.get("fields") if isinstance(update, dict) else None
        change = (fields or {}).get("System.State")
        if not isinstance(change, dict) or "newValue" not in change:
            continue
        at = when(((fields or {}).get("System.ChangedDate") or {}).get("newValue")) or when(update.get("revisedDate"))
        reason = (fields or {}).get("System.Reason")
        history.append({"from": change.get("oldValue"), "to": change.get("newValue"),
                        "reason": reason.get("newValue") if isinstance(reason, dict) else None, "at": iso(at),
                        "by": person(update.get("revisedBy"))})
    return history


def current_approval(history: Optional[List[Dict[str, Any]]], comments: Optional[List[Dict[str, Any]]],
                     states: Sequence[str], ranks: Dict[str, Tuple[int, int]]) -> Optional[Dict[str, Any]]:
    """The approval in effect: the earliest move into an approval state, or comment matching the approval pattern,
    since the last reversal (a move back before the approval states, or to a state or with a reason naming Rejected)."""
    wanted = {s.lower() for s in states}
    found = [{"at": h["at"], "by": h["by"], "source": "state", "state": h["to"]}
             for h in history or [] if str(h["to"] or "").lower() in wanted and h["at"]]
    found += [{"at": c["at"], "by": c["by"], "source": "comment", "state": None}
              for c in comments or [] if c["approval"] and c["at"]]
    first = min((ranks[s] for s in wanted if s in ranks), default=None)

    def reverses(h: Dict[str, Any]) -> bool:
        old, new = str(h["from"] or "").lower(), str(h["to"] or "").lower()
        if new in wanted:
            return False
        back = first is not None and old in ranks and new in ranks and ranks[old] >= first > ranks[new]
        return back or bool(REJECTED.search(new) or REJECTED.search(str(h["reason"] or "")))

    last = max((h["at"] for h in history or [] if h["at"] and reverses(h)), default="")
    standing = [a for a in found if a["at"] > last]
    return min(standing, key=lambda a: a["at"]) if standing else None


def read_updates(client: DevOpsClient, pid: str, wid: int) -> List[Dict[str, Any]]:
    updates: List[Dict[str, Any]] = []
    while True:
        body = client.get(f"{pid}/_apis/wit/workItems/{wid}/updates",
                          params={"$top": UPDATES_PAGE, "$skip": len(updates)})
        page = [u for u in (body.get("value") if isinstance(body, dict) else body) or [] if isinstance(u, dict)]
        updates += page
        if len(page) < UPDATES_PAGE:
            return updates


def read_comments(client: DevOpsClient, pid: str, wid: int, pattern: Pattern[str]) -> List[Dict[str, Any]]:
    comments = client.list(f"{pid}/_apis/wit/workItems/{wid}/comments", COMMENTS_API, item_key="comments")
    return sorted(({"at": iso(when(c.get("createdDate"))), "by": person(c.get("createdBy")),
                    "approval": bool(pattern.search(comment_text(c.get("text"))))}
                   for c in comments if isinstance(c, dict) and not c.get("isDeleted")),
                  key=lambda c: c["at"] or "")


def project_types(client: DevOpsClient, pid: str) -> Dict[str, Dict[str, Any]]:
    """Each work item type by lower-cased name: its name and its states' categories by lower-cased state name."""
    types: Dict[str, Dict[str, Any]] = {}
    for raw in client.list(f"{pid}/_apis/wit/workitemtypes"):
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        states = raw.get("states")
        if not isinstance(states, list):
            states = client.list(f"{pid}/_apis/wit/workitemtypes/{quote(raw['name'])}/states")
        named = [s for s in states if isinstance(s, dict) and s.get("name")]
        types[raw["name"].lower()] = {
            "name": raw["name"],
            "states": {str(s["name"]).lower(): s.get("category") or "" for s in named},
            "state_names": [str(s["name"]) for s in named],
            # Workflow order: by category, then as the type lists its states.
            "ranks": {str(s["name"]).lower(): (CATEGORY_ORDER.get(str(s.get("category") or "").lower(),
                                                                  len(CATEGORY_ORDER)), n)
                      for n, s in enumerate(named)},
        }
    return types


class Selection(NamedTuple):
    types: List[str]
    tags: List[str]
    approval_states: List[str]
    pattern: Pattern[str]


def query(types: Dict[str, Dict[str, Any]], pname: str, selection: Selection, days: int) -> str:
    present = [types[t.lower()]["name"] for t in selection.types if t.lower() in types]
    chosen = [f"[System.WorkItemType] IN ({', '.join(wiql_text(t) for t in present)})"] if present else []
    chosen += [f"[System.Tags] CONTAINS {wiql_text(t)}" for t in selection.tags]
    # A state open in any type is queried; each record's own type decides whether it is open.
    open_states = sorted({name for t in types.values() for name, cat in t["states"].items()
                          if cat.lower() not in DONE_CATEGORIES})
    recent = f"[System.ChangedDate] >= @Today - {days}"
    window = f"({recent} OR [System.State] IN ({', '.join(wiql_text(s) for s in open_states)}))" \
        if open_states else recent
    return (f"SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = {wiql_text(pname)} "
            f"AND ({' OR '.join(chosen)}) AND {window} ORDER BY [System.Id]")


def high_priority(priority: Any, severity: Any) -> Optional[bool]:
    if priority in (None, "") and severity in (None, ""):
        return None
    return str(priority).strip() in ("1", "2") or str(severity or "").strip()[:1] in ("1", "2")


def item_record(raw: Dict[str, Any], pname: str, types: Dict[str, Dict[str, Any]], selection: Selection,
                now: datetime) -> Dict[str, Any]:
    fields = raw.get("fields") or {}
    kind, state = fields.get("System.WorkItemType"), fields.get("System.State")
    category = ((types.get(str(kind).lower()) or {}).get("states") or {}).get(str(state).lower())
    tags = [t.strip() for t in str(fields.get("System.Tags") or "").split(";") if t.strip()]
    selected = (["type"] if str(kind).lower() in {t.lower() for t in selection.types} else []) + \
        (["tag"] if {t.lower() for t in tags} & {t.lower() for t in selection.tags} else [])
    dates = {key: iso(when(fields.get(name))) for key, name in DATES.items()}
    planned = next((dates[k] for k in PLANNED if dates[k]), None)
    is_open = None if category is None else category.lower() not in DONE_CATEGORIES
    planned_at = when(planned)
    priority, severity = fields.get("Microsoft.VSTS.Common.Priority"), fields.get("Microsoft.VSTS.Common.Severity")
    return {
        "id": raw.get("id"),
        "project": pname,
        "type": kind,
        "title": fields.get("System.Title"),
        "state": state,
        "state_category": category,
        "reason": fields.get("System.Reason"),
        "open": is_open,
        "priority": priority,
        "severity": severity,
        "high_priority": high_priority(priority, severity),
        "tags": tags,
        "selected_by": selected,
        "area_path": fields.get("System.AreaPath"),
        "iteration_path": fields.get("System.IterationPath"),
        **{key: person(fields.get(name)) for key, name in PEOPLE.items()},
        **dates,
        "planned_date": planned,
        "overdue": None if is_open is None else bool(is_open and planned_at and planned_at < now),
        "links": links(raw.get("relations")),
    }


def collect_project(client: DevOpsClient, collector: DevOpsCollector, project: Dict[str, Any], selection: Selection,
                    days: int, now: datetime) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    pid, pname = project["id"], project["name"]
    record: Dict[str, Any] = {"id": pid, "name": pname, "work_item_types_missing": None, "work_items": None,
                              "states_by_type": None, "undefined_states": None}
    types = call(collector, f"wit.workitemtypes.list({pname})", SCOPE_WORK, lambda: project_types(client, pid))
    if types is None:
        return record, []
    record["work_item_types_missing"] = [t for t in selection.types if t.lower() not in types]
    if not selection.tags and len(record["work_item_types_missing"]) == len(selection.types):
        record.update(work_items=0, states_by_type={}, undefined_states=[])
        return record, []
    found = call(collector, f"wit.wiql({pname})", SCOPE_WORK, lambda: client.post(
        f"{pid}/_apis/wit/wiql", {"query": query(types, pname, selection, days)}))
    if found is None:
        return record, []
    ids = [w["id"] for w in (found.get("workItems") or []) if isinstance(w, dict) and w.get("id") is not None]
    raws: List[Dict[str, Any]] = []
    complete = True
    for start in range(0, len(ids), BATCH_SIZE):
        chunk = ids[start:start + BATCH_SIZE]
        body = call(collector, f"wit.workitemsbatch({pname}, {start // BATCH_SIZE + 1})", SCOPE_WORK,
                    partial(client.post, f"{pid}/_apis/wit/workitemsbatch",
                            {"ids": chunk, "$expand": "Relations", "errorPolicy": "Omit"}))
        if body is None:
            complete = False
            continue
        got = [w for w in body.get("value") or [] if isinstance(w, dict) and w.get("id") is not None]
        raws += got
        # errorPolicy "Omit" answers null for an item it can't return, such as one deleted since the query.
        for wid in sorted(set(chunk) - {w["id"] for w in got}):
            complete = False
            collector.record(f"wit.workitemsbatch({pname}/{wid})", DevOpsError(
                None, "WorkItemNotReturned", f"work item {wid} was listed by the query but not returned"))

    items = []
    for raw in raws:
        item = item_record(raw, pname, types, selection, now)
        wid = item["id"]
        updates = call(collector, f"wit.updates({pname}/{wid})", SCOPE_WORK,
                       partial(read_updates, client, pid, wid))
        comments = call(collector, f"wit.comments({pname}/{wid})", SCOPE_WORK,
                        partial(read_comments, client, pid, wid, selection.pattern))
        item["state_history"] = None if updates is None else state_history(updates)
        item["comments"] = None if comments is None else len(comments)
        ranks = (types.get(str(item["type"]).lower()) or {}).get("ranks") or {}
        item["approval"] = current_approval(item["state_history"], comments, selection.approval_states, ranks)
        item["approval_read"] = updates is not None and comments is not None
        item["approved_by_requester"] = None if not item["approval"] else \
            same_person(item["approval"]["by"], item["created_by"])
        items.append(item)
    record["work_items"] = len(items) if complete else None
    shown = {t.lower() for t in selection.types} | {str(i["type"]).lower() for i in items}
    record["states_by_type"] = {types[t]["name"]: {n: types[t]["states"][n.lower()] for n in types[t]["state_names"]}
                                for t in sorted(shown) if t in types}
    record["undefined_states"] = undefined_states(items)
    return record, items


def read_changesets(client: DevOpsClient, collector: DevOpsCollector,
                    ids: Iterable[int]) -> Dict[int, Optional[Dict[str, Any]]]:
    out: Dict[int, Optional[Dict[str, Any]]] = {}
    for cid in sorted(set(ids)):
        body = call(collector, f"tfvc.changesets.get({cid})", SCOPE_CODE,
                    partial(client.get, f"_apis/tfvc/changesets/{cid}"))
        out[cid] = None if not isinstance(body, dict) else {
            "id": cid,
            "created_date": iso(when(body.get("createdDate"))),
            "author": person(body.get("author")),
            "checked_in_by": person(body.get("checkedInBy")),
        }
    return out


def link_changes(item: Dict[str, Any], changesets: Dict[int, Optional[Dict[str, Any]]]) -> None:
    """When the item's linked changesets were made, against when it was approved and by whom."""
    linked = [changesets.get(c) for c in item["links"]["changesets"] if isinstance(c, int)]
    known = [c for c in linked if c]
    # Git commits and pull requests aren't read, so an item linked to one can't be checked.
    complete = bool(linked) and len(known) == len(item["links"]["changesets"]) and \
        not item["links"]["commits"] and not item["links"]["pull_requests"]
    approval = item["approval"]
    item["first_linked_change"] = min((c["created_date"] for c in known if c["created_date"]), default=None)
    item["changed_before_approval"] = None if not approval or not complete else any(
        bool(c["created_date"]) and c["created_date"] < approval["at"] for c in known)
    item["approved_by_change_author"] = None if not approval or not complete else any(
        same_person(approval["by"], c["author"]) or same_person(approval["by"], c["checked_in_by"]) for c in known)


def undefined_states(items: Iterable[Dict[str, Any]]) -> List[str]:
    """Item states, as "type: state", that the item's type doesn't define now (a process change leaves these)."""
    return sorted({f"{i['type']}: {i['state']}" for i in items if i["state_category"] is None})


def has_change(item: Dict[str, Any]) -> bool:
    return any(item["links"][k] for k in ("changesets", "commits", "pull_requests"))


def ids_of(items: Iterable[Dict[str, Any]]) -> List[Any]:
    return sorted((i["id"] for i in items), key=lambda v: (str(type(v)), v))


def summarize(items: List[Dict[str, Any]], projects: List[Dict[str, Any]], listed: bool, selection: Selection,
              days: int) -> Dict[str, Any]:
    """Counts read null when a project's items couldn't be listed; approval figures when an item's history couldn't."""
    queried = listed and all(p["work_items"] is not None for p in projects)

    def known(value: Any, ok: bool = True) -> Any:
        return value if queried and ok else None

    change = [i for i in items if "type" in i["selected_by"]]
    finished = [i for i in change if str(i["state_category"] or "").lower() == "completed"]
    tagged = [i for i in items if "tag" in i["selected_by"]]
    tagged_open = [i for i in tagged if i["open"]]
    history = all(i["approval_read"] for i in change)
    # Approved items with linked changes, and those whose every linked change was read.
    linked = [i for i in change if i["approval"] and has_change(i)]
    checked = [i for i in linked if i["changed_before_approval"] is not None]
    every = history and len(checked) == len(linked)
    return {
        "lookback_days": days,
        "work_item_types": selection.types,
        "work_item_tags": selection.tags,
        "projects_collected": sum(1 for p in projects if p["work_items"] is not None),
        "work_item_types_missing": known(sorted({t for p in projects for t in p["work_item_types_missing"] or []})),
        "work_items_total": known(len(items)),
        "work_items_by_type": known(sorted_counts(Counter(str(i["type"] or "unknown") for i in items))),
        "work_items_by_state_category": known(sorted_counts(Counter(i["state_category"] or "unknown" for i in items))),
        "work_item_states_undefined": known(undefined_states(items)),
        "work_items_open": known(sum(1 for i in items if i["open"])),
        "approval_history_collected": queried and all(i["approval_read"] for i in items),
        "change_items": known(len(change)),
        "change_items_finished": known(len(finished)),
        "change_items_approved": known(sum(1 for i in change if i["approval"]), history),
        "finished_change_items_without_approval": known(ids_of(i for i in finished if not i["approval"]), history),
        "change_items_approved_by_requester": known(ids_of(i for i in change if i["approved_by_requester"]), history),
        "change_items_with_linked_changes": known(sum(1 for i in change if has_change(i))),
        "finished_change_items_without_linked_change": known(ids_of(i for i in finished if not has_change(i))),
        "change_items_linked_changes_checked": known(len(checked), history),
        "change_items_changed_before_approval": known(ids_of(i for i in change if i["changed_before_approval"]), every),
        "change_items_approved_by_change_author": known(
            ids_of(i for i in change if i["approved_by_change_author"]), every),
        "tagged_items_open": known(len(tagged_open)),
        "tagged_items_open_by_priority": known(sorted_counts(Counter(
            "unset" if i["priority"] in (None, "") else str(i["priority"]) for i in tagged_open))),
        "tagged_items_overdue": known(ids_of(i for i in tagged if i["overdue"])),
        "tagged_items_overdue_high_priority": known(ids_of(i for i in tagged if i["overdue"] and i["high_priority"])),
        "tagged_items_open_unassigned": known(ids_of(i for i in tagged_open if not i["assigned_to"])),
        "tagged_items_open_without_planned_date": known(sum(1 for i in tagged_open if not i["planned_date"])),
        "not_collected": dict(NOT_COLLECTED),
    }


def collect(client: DevOpsClient, collector: DevOpsCollector) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    days = lookback_days()
    selection = Selection(csv_config(TYPES_ENV, DEFAULT_TYPES), csv_config(TAGS_ENV, DEFAULT_TAGS),
                          csv_config(APPROVAL_STATES_ENV, DEFAULT_APPROVAL_STATES), approval_pattern())
    if not selection.types and not selection.tags:
        raise ValueError(f"{TYPES_ENV} and {TAGS_ENV} are both empty, so no work item is selected")
    now = datetime.now(timezone.utc)
    listed_projects = list_projects(client, collector)
    listed = not any(f["operation"] == "core.projects.list" for f in collector.failures)
    projects: List[Dict[str, Any]] = []
    items: List[Dict[str, Any]] = []
    for project in listed_projects:
        done = collector.guard(f"collect({project.get('name')})",
                               partial(collect_project, client, collector, project, selection, days, now))
        if done is None:
            projects.append({"id": project.get("id"), "name": project.get("name"), "work_item_types_missing": None,
                             "work_items": None, "states_by_type": None, "undefined_states": None})
            continue
        projects.append(done[0])
        items += done[1]

    changesets = read_changesets(client, collector, (c for i in items for c in i["links"]["changesets"]
                                                     if isinstance(c, int)))
    for item in items:
        link_changes(item, changesets)
    items.sort(key=lambda i: (str(i["project"]), str(i["id"]).zfill(12)))
    results = {
        "window": {"start": iso(now - timedelta(days=days)), "end": iso(now), "lookback_days": days},
        "selection": {"work_item_types": selection.types, "work_item_tags": selection.tags,
                      "approval_states": selection.approval_states, "approval_pattern": selection.pattern.pattern},
        "projects": projects,
        "work_items": items,
        "changesets": [c for _, c in sorted(changesets.items()) if c],
    }
    return results, summarize(items, projects, listed, selection, days)


if __name__ == "__main__":
    sys.exit(run_org(fetcher=NAME, logger=logger, collect=collect))


