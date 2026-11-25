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
from azure_common import coverage_percentage, sorted_counts  # noqa: E402
from devops_rest import (  # noqa: E402
    DevOpsClient,
    DevOpsCollector,
    DevOpsError,
    iso,
    list_projects,
    parse_time,
    run_org,
)
from scope_exclusions import excluded_item, parse_patterns  # noqa: E402

NAME = "azure_devops_work_items"
TYPES_ENV = "AZURE_DEVOPS_WORK_ITEM_TYPES"
TAGS_ENV = "AZURE_DEVOPS_WORK_ITEM_TAGS"
LOOKBACK_ENV = "AZURE_DEVOPS_LOOKBACK_DAYS"
APPROVAL_STATES_ENV = "AZURE_DEVOPS_APPROVAL_STATES"
APPROVAL_PATTERN_ENV = "AZURE_DEVOPS_APPROVAL_PATTERN"
APPROVAL_TYPES_ENV = "AZURE_DEVOPS_APPROVAL_TYPES"
APPROVAL_MENTIONS_ENV = "AZURE_DEVOPS_APPROVAL_MENTIONS"
APPROVAL_FIELD_ENV = "AZURE_DEVOPS_APPROVAL_FIELD"
APPROVAL_SOURCE_ENV = "AZURE_DEVOPS_APPROVAL_SOURCE"
APPROVAL_FIELD_FROM_ENV = "AZURE_DEVOPS_APPROVAL_FIELD_FROM"
APPROVAL_BEFORE_FIELD_ENV = "AZURE_DEVOPS_APPROVAL_BEFORE_FIELD"
EMERGENCY_TYPES_ENV = "AZURE_DEVOPS_EMERGENCY_TYPES"
INCLUSIONS_ENV = "AZURE_DEVOPS_CHANGESET_INCLUSIONS"
DEFAULT_TYPES = ("Change Request",)
DEFAULT_TAGS = ("Security",)
DEFAULT_LOOKBACK_DAYS = 90
DEFAULT_APPROVAL_STATES = ("Approved",)
# Where an approval is read from: state moves and comments (as before the approval field), the field, or either.
HISTORY, FIELD, BOTH, EXCLUDE = "states_and_comments", "field", "both", "exclude"
APPROVAL_SOURCES = (HISTORY, FIELD, BOTH)
BEFORE_FIELD_ROUTES = (HISTORY, BOTH, EXCLUDE)
REFERENCE_NAME = re.compile(r"[A-Za-z_]\w*(?:\.\w+)+")
# A line starting "Approved" with no question mark, so "Approved?" doesn't count.
DEFAULT_APPROVAL_PATTERN = r"^\W*approved\b[^?\n]*$"
MENTION = "@mention"
# The mention picker's link, a markdown comment's @<identity id>, and an @word typed without the picker.
# A link must close before the next link or block tag, so an unclosed one can't swallow text.
MENTION_LINK = re.compile(r"<a\b[^>]*\sdata-vss-mention\s*=[^>]*>(?:(?!</?(?:a|div|p|li)\b|<br).)*?</a>"
                          r"|@<[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}>", re.IGNORECASE | re.DOTALL)
MENTION_WORD = re.compile(r"(?<![\w.@])@\w+(?:[.'-]\w+)*")
LEADING_MENTIONS = re.compile(r"^(?:\W*@mention\b)+")
COMMENTS_API = "7.1-preview.4"
BATCH_SIZE = 200
UPDATES_PAGE = 200
DONE_CATEGORIES = frozenset({"completed", "removed"})
CATEGORY_ORDER = {"proposed": 0, "inprogress": 1, "resolved": 2, "completed": 3, "removed": 4}
REJECTED = re.compile(r"reject", re.IGNORECASE)
# A changeset read returns at most 100 changes; the rest are paged from its change list.
CHANGES_PAGE = 100
MAX_CHANGE_PAGES = 500
NOT_INCLUDED, NOT_READABLE = "not_included", "not_readable"
NOT_READABLE_DETAIL = ("not readable; the included paths were readable this run, so it is outside them or in a "
                       "sub-folder the app can't read")
WILDCARDS = re.compile(r"[*?]")

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
            "an approval when a line of its text, quoted text left out (and, with approval_mentions on, the "
            "@mentions it starts with), matches approval_pattern, and only its author and time are kept.",
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


def approval_mentions() -> bool:
    raw = (os.environ.get(APPROVAL_MENTIONS_ENV) or "").strip().lower()
    if raw in ("", "false", "0", "no", "off"):
        return False
    if raw in ("true", "1", "yes", "on"):
        return True
    raise ValueError(f"{APPROVAL_MENTIONS_ENV} must be true or false, got {raw!r}")


def named_types(env: str, types: Sequence[str], meaning: str, none: bool = False) -> List[str]:
    """Selected change types an env names, as the selection spells them; a name outside the selection is bad_config.
    With none, "none" names no type."""
    spelt = {t.lower(): t for t in types}
    raw = (os.environ.get(env) or "").strip()
    named = [] if none and raw.lower() == "none" else \
        list(dict.fromkeys(v.strip().lower() for v in raw.split(",") if v.strip()))
    unknown = [n for n in named if n not in spelt]
    if unknown:
        raise ValueError(f"{env} names {unknown}, which aren't in {TYPES_ENV}, so the type meant would {meaning}; "
                         f"selected types are {', '.join(types) or 'none'}")
    return [spelt[n] for n in named]


def approval_types(types: Sequence[str]) -> List[str]:
    """Selected change types that need an approval; none named means every one."""
    return named_types(APPROVAL_TYPES_ENV, types, "need no approval") or list(types)


def emergency_types(types: Sequence[str]) -> List[str]:
    """Selected change types whose approval may come after the change; none by default."""
    return named_types(EMERGENCY_TYPES_ENV, types, "still need its approval before the change", none=True)


def choice(env: str, allowed: Sequence[str]) -> str:
    raw = (os.environ.get(env) or "").strip().lower() or allowed[0]
    if raw not in allowed:
        raise ValueError(f"{env} must be one of {', '.join(allowed)}, got {raw!r}")
    return raw


def approval_field_settings() -> Tuple[Optional[str], str, Optional[datetime], str]:
    """The approval field's reference name, the approval source, the date the field counts from, and the route for
    items finished before it."""
    field = (os.environ.get(APPROVAL_FIELD_ENV) or "").strip() or None
    if field and not REFERENCE_NAME.fullmatch(field):
        raise ValueError(f"{APPROVAL_FIELD_ENV} must be a field's reference name, such as Custom.ChangeApprover, not its "
                         f"display name; got {field!r}")
    source = choice(APPROVAL_SOURCE_ENV, APPROVAL_SOURCES)
    if source != HISTORY and not field:
        raise ValueError(f"{APPROVAL_SOURCE_ENV} is {source}, which needs {APPROVAL_FIELD_ENV}")
    raw = (os.environ.get(APPROVAL_FIELD_FROM_ENV) or "").strip()
    since = None
    if raw:
        since = parse_time(f"{raw}T00:00:00Z" if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw) else raw)
        if since is None:
            raise ValueError(f"{APPROVAL_FIELD_FROM_ENV} must be a date such as 2026-01-31, got {raw!r}")
        if source == HISTORY:
            raise ValueError(f"{APPROVAL_FIELD_FROM_ENV} is set but {APPROVAL_SOURCE_ENV} is {HISTORY}, so the field "
                             f"never counts")
    before = choice(APPROVAL_BEFORE_FIELD_ENV, BEFORE_FIELD_ROUTES)
    if before != HISTORY and since is None:
        raise ValueError(f"{APPROVAL_BEFORE_FIELD_ENV} is {before}, which needs {APPROVAL_FIELD_FROM_ENV}")
    return field, source, since, before


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


def tfvc_key(path: Any) -> str:
    # TFVC compares server paths without case; "$/" (the whole collection) reads "$".
    return str(path or "").replace('"', "").strip().lower().rstrip("/")


class ChangesetScope:
    """changeset_inclusions: literal path:<TFVC server path> patterns, each taking in that path and all under it."""

    def __init__(self, patterns: Iterable[str] = ()):
        self.patterns = list(patterns)
        self.paths: List[str] = []
        bad = []
        for pattern in self.patterns:
            kind, sep, path = pattern.partition(":")
            path = path.replace('"', "").strip()
            # A wildcard's read check couldn't prove every path it covers, so paths are literal.
            if not sep or kind.strip().lower() != "path" or not path.startswith("$/") or WILDCARDS.search(path):
                bad.append(pattern)
            self.paths.append("$/" if path.rstrip("/") == "$" else path.rstrip("/"))
        if bad:
            raise ValueError(f"{INCLUSIONS_ENV} patterns {bad} need path: and a literal TFVC server path starting $/, "
                             f"without * or ?, such as path:$/ProjectA/Production")
        self._keys = [tfvc_key(p) for p in self.paths]

    @classmethod
    def from_env(cls) -> "ChangesetScope":
        return cls(parse_patterns(os.environ.get(INCLUSIONS_ENV)))

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def includes(self, path: Any) -> bool:
        """Whether a server path is an included path or under one, at folder boundaries."""
        key = tfvc_key(path)
        return bool(key) and any(key == k or key.startswith(f"{k}/") for k in self._keys)

    def checks(self) -> List[Tuple[str, str]]:
        """(pattern, path to read) for each pattern."""
        return list(zip(self.patterns, self.paths))


def check_included_path(client: DevOpsClient, path: str, found: Dict[str, Any]) -> None:
    """Reads the path's latest changeset; none, a refusal or a 404 (ADO's answer for an unreadable path) is denial."""
    try:
        body = client.get("_apis/tfvc/changesets", params={"searchCriteria.itemPath": path, "$top": 1})
        listed = [c.get("changesetId") for c in (body.get("value") if isinstance(body, dict) else None) or []
                  if isinstance(c, dict)]
        if not listed or not isinstance(listed[0], int):
            raise PermissionError(f"included TFVC path {path} listed no changeset, so it is empty or can't be read")
        found["latest_changeset"] = listed[0]
        client.get(f"_apis/tfvc/changesets/{listed[0]}")
    except DevOpsError as exc:
        if exc.status == 404 or exc.failure_code == "not_authorized":
            raise PermissionError(f"included TFVC path {path} is missing or can't be read ({SCOPE_CODE} needed): "
                                  f"{exc}") from exc
        raise
    found["readable"] = True


def check_inclusions(client: DevOpsClient, collector: DevOpsCollector, scope: ChangesetScope,
                     operation: str = "tfvc.inclusion_check") -> List[Dict[str, Any]]:
    """Each included path's read check, so a changeset refused later can be told apart from lost access."""
    out, done = [], {}
    for pattern, path in scope.checks():
        if tfvc_key(path) not in done:
            found = done[tfvc_key(path)] = {"readable": False, "latest_changeset": None}
            collector.guard(f"{operation}({path})", partial(check_included_path, client, path, found))
        out.append({"pattern": pattern, "path": path, **done[tfvc_key(path)]})
    return out


def access_refused(exc: DevOpsError) -> bool:
    return exc.code == "TF14098" or exc.status in (401, 403)


def changed_paths(changes: Any) -> List[str]:
    """Each change's server path, and a rename's source path."""
    out = []
    for change in changes if isinstance(changes, list) else []:
        if isinstance(change, dict):
            out += [p for p in ((change.get("item") or {}).get("path"), change.get("sourceServerItem")) if p]
    return out


def every_path_named(changes: Any) -> bool:
    return isinstance(changes, list) and all(isinstance(c, dict) and (c.get("item") or {}).get("path") for c in changes)


def changes_included(client: DevOpsClient, cid: int, scope: ChangesetScope) -> Optional[bool]:
    """Pages a changeset's whole change list to an empty page; None unless every changed path was read."""
    named, skip, last = False, 0, None
    for _ in range(MAX_CHANGE_PAGES):
        body = client.get(f"_apis/tfvc/changesets/{cid}/changes", params={"$top": CHANGES_PAGE, "$skip": skip})
        page = body.get("value") if isinstance(body, dict) else None
        if not isinstance(page, list):
            return None
        paths = changed_paths(page)
        if any(scope.includes(p) for p in paths):
            return True
        if not page:
            return False if named else None
        if not every_path_named(page) or paths == last:  # an unnamed change, or $skip ignored
            return None
        named, skip, last = True, skip + len(page), paths
    return None


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


def comment_text(raw: Any, mentions: bool = False) -> str:
    """Plain text without quoted text (a blockquote, or a line starting ">"); with mentions, each reads @mention
    and the ones a line starts with are dropped."""
    text, before = str(raw or ""), None
    if mentions:
        text = MENTION_LINK.sub(f" {MENTION} ", text)
    while text != before:  # innermost blockquote first, so nested quotes go too
        before, text = text, re.sub(r"<blockquote\b[^>]*>(?:(?!<blockquote\b).)*?</blockquote>", "\n", text,
                                    flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<br\s*/?>|</(?:div|p|li)>", "\n", text, flags=re.IGNORECASE)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    lines = [line for line in text.splitlines() if not line.lstrip().startswith(">")]
    if mentions:
        lines = [LEADING_MENTIONS.sub("", MENTION_WORD.sub(MENTION, line)) for line in lines]
    return "\n".join(lines)


def update_time(update: Dict[str, Any]) -> Optional[datetime]:
    return when(((update.get("fields") or {}).get("System.ChangedDate") or {}).get("newValue")) or \
        when(update.get("revisedDate"))


def field_value(fields: Any, ref: str) -> Any:
    """A field by reference name, matched without regard to case."""
    return next((v for k, v in (fields if isinstance(fields, dict) else {}).items() if k.lower() == ref.lower()), None)


def state_history(updates: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    history = []
    for update in updates:
        fields = update.get("fields") if isinstance(update, dict) else None
        change = (fields or {}).get("System.State")
        if not isinstance(change, dict) or "newValue" not in change:
            continue
        at = update_time(update)
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


def names_same(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> bool:
    """Same person by login, or by display name where neither value carries a login."""
    if a and b and not a.get("login") and not b.get("login"):
        return bool(a.get("display_name")) and a.get("display_name") == b.get("display_name")
    return same_person(a, b)


def field_approval(updates: Optional[List[Dict[str, Any]]], ref: str, value: Any) -> Optional[Dict[str, Any]]:
    """The person the approval field names now, approving from the last update that set it to that person; when, and
    who made that update (set_by), are unknown if the updates weren't read. The field is a name anyone with edit rights
    can type, so set_by is what says whether the named person filled it in."""
    by = person(value)
    if not by:
        return None
    at = set_by = None
    for update in updates or []:
        change = field_value(update.get("fields"), ref)
        if isinstance(change, dict) and names_same(person(change.get("newValue")), by) and \
                not names_same(person(change.get("oldValue")), by):
            at, set_by = update_time(update), person(update.get("revisedBy"))
    return {"at": iso(at), "by": by, "set_by": set_by, "source": "field", "state": None}


def finished_at(item: Dict[str, Any]) -> Optional[datetime]:
    """When a finished item reached its current state, as azure_change_work_items reads it."""
    entered = [when(h.get("at")) for h in item.get("state_history") or [] if h.get("to") == item.get("state")]
    for at in (when(item.get("closed_date")), when(item.get("resolved_date")),
               max((t for t in entered if t), default=None), when(item.get("changed_date"))):
        if at:
            return at
    return None


def approval_route(item: Dict[str, Any], selection: "Selection") -> str:
    """How an item's approval is judged: approval_before_field if it finished before field_from, else approval_source
    (an open item, or one in a state its type no longer defines, included)."""
    if selection.field_from and item.get("open") is False:
        done = finished_at(item)
        if done and done < selection.field_from:
            return selection.before_field
    return selection.approval_source


def chosen_approval(route: str, history: Optional[Dict[str, Any]],
                    field: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The earliest approval the route counts; one whose time is unknown comes last."""
    found = [a for a in ((history if route in (HISTORY, BOTH) else None), (field if route in (FIELD, BOTH) else None))
             if a]
    return min(found, key=lambda a: (a["at"] is None, a["at"] or "")) if found else None


def read_updates(client: DevOpsClient, pid: str, wid: int) -> List[Dict[str, Any]]:
    updates: List[Dict[str, Any]] = []
    while True:
        body = client.get(f"{pid}/_apis/wit/workItems/{wid}/updates",
                          params={"$top": UPDATES_PAGE, "$skip": len(updates)})
        page = [u for u in (body.get("value") if isinstance(body, dict) else body) or [] if isinstance(u, dict)]
        updates += page
        if len(page) < UPDATES_PAGE:
            return updates


def read_comments(client: DevOpsClient, pid: str, wid: int, pattern: Pattern[str],
                  mentions: bool) -> List[Dict[str, Any]]:
    comments = client.list(f"{pid}/_apis/wit/workItems/{wid}/comments", COMMENTS_API, item_key="comments")
    return sorted(({"at": iso(when(c.get("createdDate"))), "by": person(c.get("createdBy")),
                    "approval": bool(pattern.search(comment_text(c.get("text"), mentions)))}
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
        listed = [raw[key] for key in ("fields", "fieldInstances") if isinstance(raw.get(key), list)]
        types[raw["name"].lower()] = {
            "name": raw["name"],
            # Reference names of the fields it defines; None when the listing didn't give them.
            "fields": {str(f.get("referenceName")).lower() for found in listed for f in found if isinstance(f, dict)}
            if listed else None,
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
    approval_types: List[str]
    mentions: bool
    approval_field: Optional[str] = None
    approval_source: str = HISTORY
    field_from: Optional[datetime] = None
    before_field: str = HISTORY
    emergency_types: Sequence[str] = ()
    changeset_inclusions: Sequence[str] = ()


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
        "approval_required": "type" in selected and str(kind).lower() in {t.lower() for t in selection.approval_types},
        "emergency_type": "type" in selected and str(kind).lower() in {t.lower() for t in selection.emergency_types},
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
                              "states_by_type": None, "undefined_states": None, "approval_field_types_missing": None}
    types = call(collector, f"wit.workitemtypes.list({pname})", SCOPE_WORK, lambda: project_types(client, pid))
    if types is None:
        return record, []
    record["work_item_types_missing"] = [t for t in selection.types if t.lower() not in types]
    if selection.approval_field:
        defined = [types[t.lower()] for t in selection.approval_types if t.lower() in types]
        record["approval_field_types_missing"] = None if any(t["fields"] is None for t in defined) else \
            [t["name"] for t in defined if selection.approval_field.lower() not in t["fields"]]
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
                        partial(read_comments, client, pid, wid, selection.pattern, selection.mentions))
        item["state_history"] = None if updates is None else state_history(updates)
        item["comments"] = None if comments is None else len(comments)
        ranks = (types.get(str(item["type"]).lower()) or {}).get("ranks") or {}
        history = current_approval(item["state_history"], comments, selection.approval_states, ranks)
        item["field_approval"] = None if not selection.approval_field else field_approval(
            updates, selection.approval_field, field_value(raw.get("fields"), selection.approval_field))
        item["approval_route"] = approval_route(item, selection)
        item["approval"] = chosen_approval(item["approval_route"], history, item["field_approval"])
        if selection.field_from:
            # What the older route finds, for azure_change_work_items to judge a change made before the date.
            item["before_field_approval"] = chosen_approval(selection.before_field, history, item["field_approval"])
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


def read_changeset(client: DevOpsClient, collector: DevOpsCollector, cid: int, scope: ChangesetScope,
                   left_out: Dict[int, str]) -> Optional[Dict[str, Any]]:
    """The changeset's date and authors, or None with its id in left_out when the inclusions leave it out."""
    def read():
        try:
            return client.get(f"_apis/tfvc/changesets/{cid}", params={
                "maxChangeCount": CHANGES_PAGE, "includeSourceRename": "true"} if scope else None)
        except DevOpsError as exc:
            if scope and access_refused(exc):
                left_out[cid] = NOT_READABLE
                return None
            raise

    body = call(collector, f"tfvc.changesets.get({cid})", SCOPE_CODE, read)
    if not isinstance(body, dict):
        return None
    if scope:
        changes = body.get("changes")
        included = any(scope.includes(p) for p in changed_paths(changes))
        named = every_path_named(changes)
        if not included and not (named and changes and not body.get("hasMoreChanges")
                                 and len(changes) < CHANGES_PAGE):
            # The read didn't list every changed path: page them all from the start, as the order may differ.
            included = call(collector, f"tfvc.changesets.changes({cid})", SCOPE_CODE, partial(
                changes_included, client, cid, scope)) is not False
        if not included:
            left_out[cid] = NOT_INCLUDED
            return None
    return {
        "id": cid,
        "created_date": iso(when(body.get("createdDate"))),
        "author": person(body.get("author")),
        "checked_in_by": person(body.get("checkedInBy")),
    }


def read_changesets(client: DevOpsClient, collector: DevOpsCollector, ids: Iterable[int],
                    scope: Optional[ChangesetScope] = None) -> Tuple[Dict[int, Optional[Dict[str, Any]]], Dict[int, str]]:
    """In-scope changesets by id (None when unread), and the ids left out with their reason."""
    scope = scope or ChangesetScope()
    out: Dict[int, Optional[Dict[str, Any]]] = {}
    left_out: Dict[int, str] = {}
    for cid in sorted(set(ids)):
        record = read_changeset(client, collector, cid, scope, left_out)
        if cid not in left_out:
            out[cid] = record
    return out, left_out


def link_changes(item: Dict[str, Any], changesets: Dict[int, Optional[Dict[str, Any]]],
                 left_out: Optional[Dict[int, str]] = None) -> None:
    """When the item's in-scope linked changesets were made, against when it was approved and by whom."""
    ids = [c for c in item["links"]["changesets"] if c not in (left_out or {})]
    linked = [changesets.get(c) for c in ids if isinstance(c, int)]
    known = [c for c in linked if c]
    # Git commits and pull requests aren't read, so an item linked to one can't be checked.
    complete = bool(linked) and len(known) == len(ids) and \
        not item["links"]["commits"] and not item["links"]["pull_requests"]
    approval = item["approval"]
    item["first_linked_change"] = min((c["created_date"] for c in known if c["created_date"]), default=None)
    item["changed_before_approval"] = None if not approval or not approval["at"] or not complete else any(
        bool(c["created_date"]) and c["created_date"] < approval["at"] for c in known)
    item["approved_by_change_author"] = None if not approval or not complete else any(
        same_person(approval["by"], c["author"]) or same_person(approval["by"], c["checked_in_by"]) for c in known)
    # The checks above can't see a refused changeset, so the item says it links one.
    item["unreadable_linked_changesets"] = None if left_out is None else any(
        left_out.get(c) == NOT_READABLE for c in item["links"]["changesets"])


def undefined_states(items: Iterable[Dict[str, Any]]) -> List[str]:
    """Item states, as "type: state", that the item's type doesn't define now (a process change leaves these)."""
    return sorted({f"{i['type']}: {i['state']}" for i in items if i["state_category"] is None})


def has_change(item: Dict[str, Any], left_out: Optional[Dict[int, str]] = None) -> bool:
    """Linked to a changeset, commit or pull request; with left_out, to a changeset not left out of scope."""
    return any(c not in (left_out or {}) for c in item["links"]["changesets"]) or \
        any(item["links"][k] for k in ("commits", "pull_requests"))


def refused(item: Dict[str, Any]) -> bool:
    """Finished as refused: its state or reason names Rejected, or its state is named Removed."""
    state = str(item["state"] or "")
    return bool(REJECTED.search(state) or REJECTED.search(str(item["reason"] or "")) or state.lower() == "removed")


def ids_of(items: Iterable[Dict[str, Any]]) -> List[Any]:
    return sorted((i["id"] for i in items), key=lambda v: (str(type(v)), v))


def summarize(items: List[Dict[str, Any]], projects: List[Dict[str, Any]], listed: bool, selection: Selection,
              days: int, changesets: Optional[Dict[int, Optional[Dict[str, Any]]]] = None,
              left_out: Optional[Dict[int, str]] = None, rechecked: bool = False) -> Dict[str, Any]:
    """Counts read null when a project's items couldn't be listed; approval figures when an item's history couldn't."""
    queried = listed and all(p["work_items"] is not None for p in projects)
    left_out = left_out or {}
    included = bool(selection.changeset_inclusions)

    def known(value: Any, ok: bool = True) -> Any:
        return value if queried and ok else None

    change = [i for i in items if "type" in i["selected_by"]]
    finished = [i for i in change if str(i["state_category"] or "").lower() == "completed"]
    tagged = [i for i in items if "tag" in i["selected_by"]]
    tagged_open = [i for i in tagged if i["open"]]
    history = all(i["approval_read"] for i in change)
    judged_finished = [i for i in finished if i["approval_route"] != EXCLUDE]
    # An open item may still be waiting on its approval, and a refused one was never meant to get one.
    needing = [i for i in judged_finished if i["approval_required"] and not refused(i)]
    needing_approved = sum(1 for i in needing if i["approval"])
    # Approved items with in-scope linked changes, and those whose every one was read.
    linked = [i for i in change if i["approval"] and has_change(i, left_out)]
    checked = [i for i in linked if i["changed_before_approval"] is not None]
    every = history and len(checked) == len(linked)
    field_missing = [p.get("approval_field_types_missing") for p in projects]
    field_approved = [i for i in change if (i["approval"] or {}).get("source") == FIELD]
    return {
        "lookback_days": days,
        "work_item_types": selection.types,
        "work_item_tags": selection.tags,
        "approval_types": selection.approval_types,
        "approval_mentions": selection.mentions,
        "approval_source": selection.approval_source,
        "approval_field": selection.approval_field,
        "approval_field_from": iso(selection.field_from),
        "approval_before_field": selection.before_field if selection.field_from else None,
        "emergency_types": list(selection.emergency_types),
        "changeset_inclusion_patterns": list(selection.changeset_inclusions),
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
        "change_items_approved_by_field": known(sum(1 for i in change if (i["approval"] or {}).get("source") == FIELD),
                                                history),
        "change_items_left_out_of_approval": known(sum(1 for i in change if i["approval_route"] == EXCLUDE)),
        "approval_field_types_missing": known(sorted({t for m in field_missing for t in m or []}),
                                              bool(selection.approval_field) and None not in field_missing),
        "finished_change_items_needing_approval": known(len(needing)),
        "finished_change_items_needing_approval_approved": known(needing_approved, history),
        "finished_change_items_approved_percentage": known(coverage_percentage(needing_approved, len(needing)),
                                                           history),
        "finished_change_items_without_approval": known(ids_of(i for i in judged_finished if not i["approval"]),
                                                        history),
        "change_items_approved_by_requester": known(ids_of(i for i in change if i["approved_by_requester"]), history),
        "change_items_approval_field_set_by_someone_else": known(
            ids_of(i for i in field_approved if not names_same(i["approval"]["set_by"], i["approval"]["by"])),
            history and all(i["approval"]["set_by"] for i in field_approved)),
        "change_items_with_linked_changes": known(sum(1 for i in change if has_change(i))),
        "finished_change_items_without_linked_change": known(ids_of(i for i in finished if not has_change(i))),
        "in_scope_changesets": known(sum(1 for c in (changesets or {}).values() if c),
                                     all((changesets or {}).values())),
        "not_included_changesets": known(sum(1 for r in left_out.values() if r == NOT_INCLUDED), included),
        "not_readable_changesets": known(sum(1 for r in left_out.values() if r == NOT_READABLE), included),
        "changeset_inclusions_rechecked": rechecked if included else None,
        "change_items_linked_changes_checked": known(len(checked), history),
        "change_items_changed_before_approval": known(
            ids_of(i for i in change if i["changed_before_approval"] and not i["emergency_type"]), every),
        "emergency_items_approved_after_change": known(
            ids_of(i for i in change if i["changed_before_approval"] and i["emergency_type"]), every),
        "change_items_approved_by_change_author": known(
            ids_of(i for i in change if i["approved_by_change_author"]), every),
        "change_items_with_unreadable_changesets": known(
            ids_of(i for i in change if i.get("unreadable_linked_changesets")), included),
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
    types = csv_config(TYPES_ENV, DEFAULT_TYPES)
    selection = Selection(types, csv_config(TAGS_ENV, DEFAULT_TAGS),
                          csv_config(APPROVAL_STATES_ENV, DEFAULT_APPROVAL_STATES), approval_pattern(),
                          approval_types(types), approval_mentions(), *approval_field_settings(),
                          emergency_types(types))
    if not selection.types and not selection.tags:
        raise ValueError(f"{TYPES_ENV} and {TAGS_ENV} are both empty, so no work item is selected")
    scope = ChangesetScope.from_env()
    selection = selection._replace(changeset_inclusions=scope.patterns)
    checks = check_inclusions(client, collector, scope)
    if not all(c["readable"] for c in checks):
        # A refused changeset can't be told from lost access to included code, so nothing is judged.
        collector.withhold("an included TFVC path couldn't be read, so no changeset's scope is known")
        return {}, {}
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
                             "work_items": None, "states_by_type": None, "undefined_states": None,
                             "approval_field_types_missing": None})
            continue
        projects.append(done[0])
        items += done[1]

    changesets, left_out = read_changesets(client, collector, (c for i in items for c in i["links"]["changesets"]
                                                               if isinstance(c, int)), scope)
    recheck = None
    if NOT_READABLE in left_out.values():
        # A refusal can also be access lost mid-run, so every included path must still read at the end.
        recheck = check_inclusions(client, collector, scope, "tfvc.inclusion_recheck")
        if not all(c["readable"] for c in recheck):
            collector.withhold("an included TFVC path no longer reads, so a refused changeset can't be told from "
                               "lost access")
            return {}, {}
    for item in items:
        link_changes(item, changesets, left_out if scope else None)
    items.sort(key=lambda i: (str(i["project"]), str(i["id"]).zfill(12)))
    excluded = [excluded_item("changeset", None, None, reason, id=cid,
                              work_items=ids_of(i for i in items if cid in i["links"]["changesets"]),
                              **({"detail": NOT_READABLE_DETAIL} if reason == NOT_READABLE else {}))
                for cid, reason in sorted(left_out.items())]
    results = {
        "window": {"start": iso(now - timedelta(days=days)), "end": iso(now), "lookback_days": days},
        "selection": {"work_item_types": selection.types, "work_item_tags": selection.tags,
                      "approval_states": selection.approval_states, "approval_pattern": selection.pattern.pattern,
                      "approval_types": selection.approval_types, "approval_mentions": selection.mentions,
                      "approval_source": selection.approval_source, "approval_field": selection.approval_field,
                      "approval_field_from": iso(selection.field_from),
                      "approval_before_field": selection.before_field if selection.field_from else None,
                      "emergency_types": list(selection.emergency_types),
                      "changeset_inclusions": list(selection.changeset_inclusions)},
        "projects": projects,
        "work_items": items,
        "changesets": [c for _, c in sorted(changesets.items()) if c],
        "changeset_inclusion_checks": checks,
        "changeset_inclusion_recheck": recheck,
        "excluded": excluded,
    }
    return results, summarize(items, projects, listed, selection, days, changesets, left_out, recheck is not None)


if __name__ == "__main__":
    sys.exit(run_org(fetcher=NAME, logger=logger, collect=collect))


