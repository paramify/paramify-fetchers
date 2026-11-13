"""azure_devops_work_items, driven without Azure DevOps.

FakeADO stands in for requests.Session and serves one organization with one
project: its work item types and states, a WIQL query, the work items batch,
each item's updates and comments, and TFVC changesets. Bodies follow the Azure
DevOps REST 7.1 reference samples.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_DIR = REPO_ROOT / "fetchers" / "azure" / "devops_work_items"
spec = importlib.util.spec_from_file_location("azure_devops_work_items_under_test", FETCHER_DIR / "fetcher.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
dr = sys.modules["devops_rest"]

ORG = "https://dev.azure.com/contoso"
P = "p-web"
NOW = datetime.now(timezone.utc)
COMMENT_TEXT = "<div>Approved by the change board, ticket CAB-42</div>"


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def later(**kw):
    return (NOW + timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body = status, body
        self.headers = headers or {}
        self.text = json.dumps(body)
        self.reason = "OK" if status < 400 else "Error"

    def json(self):
        return self._body


def err(status, message, type_key="Exception"):
    return Resp(status, {"$id": "1", "message": message, "typeKey": type_key, "errorCode": 0})


def who(name):
    return {"displayName": name.split("@")[0].title(), "uniqueName": name, "id": f"id-{name}"}


def states(*pairs):
    return [{"name": n, "color": "000000", "category": c} for n, c in pairs]


TYPES = [
    {"name": "Change Request", "states": states(("Proposed", "Proposed"), ("Approved", "InProgress"),
                                                ("Active", "InProgress"), ("Closed", "Completed"))},
    {"name": "Bug", "states": states(("New", "Proposed"), ("Active", "InProgress"), ("Resolved", "Resolved"),
                                     ("Closed", "Completed"), ("Removed", "Removed"))},
    {"name": "Task", "states": states(("To Do", "Proposed"), ("Doing", "InProgress"), ("Done", "Completed"))},
]


def item(wid, kind, state, tags="", relations=None, **fields):
    base = {"System.WorkItemType": kind, "System.State": state, "System.Title": f"Item {wid}",
            "System.Reason": "New", "System.AreaPath": "Web", "System.IterationPath": "Web\\Sprint 1",
            "System.CreatedDate": ago(days=40), "System.CreatedBy": who("alice@example.com"),
            "System.ChangedDate": ago(days=2), "System.ChangedBy": who("alice@example.com"), "System.Tags": tags}
    return {"id": wid, "rev": 3, "fields": {**base, **fields}, "relations": relations or [],
            "url": f"{ORG}/_apis/wit/workItems/{wid}"}


def artifact(url, name):
    return {"rel": "ArtifactLink", "url": url, "attributes": {"name": name}}


ITEMS = {
    # Approved in its state history, then a changeset made after approval by someone else.
    101: item(101, "Change Request", "Closed", relations=[
        artifact("vstfs:///VersionControl/Changeset/501", "Fixed in Changeset"),
        {"rel": "System.LinkTypes.Hierarchy-Reverse", "url": f"{ORG}/_apis/wit/workItems/100", "attributes": {}},
        {"rel": "Hyperlink", "url": "https://wiki.example.com/cab", "attributes": {}},
    ], **{"Microsoft.VSTS.Common.ClosedDate": ago(days=3), "Microsoft.VSTS.Common.ClosedBy": who("bob@example.com"),
          "Microsoft.VSTS.Common.Priority": 2}),
    # Approved by a comment, but its changeset predates the approval and is by the approver.
    102: item(102, "Change Request", "Active", relations=[
        artifact("vstfs:///VersionControl/Changeset/502", "Fixed in Changeset"),
        artifact("vstfs:///Build/Build/9001", "Integrated in build"),
    ], **{"System.AssignedTo": who("carol@example.com")}),
    # Finished with no approval and nothing linked.
    103: item(103, "Change Request", "Closed", **{"Microsoft.VSTS.Common.ClosedDate": ago(days=1)}),
    # Security bug: open, overdue, high severity, unassigned, fixed in Git.
    201: item(201, "Bug", "Active", tags="Security; Web", relations=[
        artifact("vstfs:///Git/Commit/p-web%2Frepo-1%2Fabc123", "Fixed in Commit"),
        artifact("vstfs:///Git/PullRequestId/p-web%252Frepo-1%252F77", "Pull Request"),
    ], **{
        "Microsoft.VSTS.Common.Priority": 3, "Microsoft.VSTS.Common.Severity": "2 - High",
        "Microsoft.VSTS.Scheduling.DueDate": ago(days=5)}),
    # Security task: open, not yet due, assigned, no priority.
    202: item(202, "Task", "Doing", tags="security", **{
        "System.AssignedTo": who("dave@example.com"), "Microsoft.VSTS.Scheduling.TargetDate": later(days=10)}),
    # Security bug, done.
    203: item(203, "Bug", "Closed", tags="Security", **{"Microsoft.VSTS.Common.Priority": 1,
                                                        "Microsoft.VSTS.Scheduling.DueDate": ago(days=20)}),
}


def update(n, old, new, at, by="bob@example.com", **fields):
    changed = {"System.State": {"oldValue": old, "newValue": new}, "System.ChangedDate": {"newValue": at}}
    return {"id": n, "rev": n, "revisedBy": who(by), "revisedDate": at, "fields": {**changed, **fields}}


UPDATES = {
    101: [{"id": 1, "rev": 1, "revisedBy": who("alice@example.com"), "fields": {"System.Title": {"newValue": "x"}}},
          update(2, "Proposed", "Approved", ago(days=20)), update(3, "Approved", "Closed", ago(days=3))],
    102: [update(1, "Proposed", "Active", ago(days=15), by="carol@example.com")],
    103: [update(1, "Proposed", "Closed", ago(days=1))],
    201: [update(1, "New", "Active", ago(days=30))],
    202: [],
    203: [update(1, "New", "Closed", ago(days=25))],
}

COMMENTS = {
    102: [{"id": 1, "text": "<p>Looks fine to me</p>", "createdBy": who("erin@example.com"),
           "createdDate": ago(days=14), "isDeleted": False},
          {"id": 2, "text": COMMENT_TEXT, "createdBy": who("carol@example.com"), "createdDate": ago(days=12),
           "isDeleted": False},
          {"id": 3, "text": "Approved", "createdBy": who("erin@example.com"), "createdDate": ago(days=13),
           "isDeleted": True}],
    101: [{"id": 1, "text": "Not approved yet", "createdBy": who("erin@example.com"), "createdDate": ago(days=25),
           "isDeleted": False}],
}

CHANGESETS = {
    501: {"changesetId": 501, "author": who("dave@example.com"), "checkedInBy": who("dave@example.com"),
          "createdDate": ago(days=10), "comment": "fix config for the change board"},
    502: {"changesetId": 502, "author": who("carol@example.com"), "checkedInBy": who("carol@example.com"),
          "createdDate": ago(days=13), "comment": "hotfix"},
}


class FakeADO:
    """Routes by host, method and path; a route is a Resp or a callable taking (params, json)."""

    def __init__(self):
        self.calls = []
        self.routes = {
            ("GET", "/contoso/_apis/connectionData"): Resp(body={"authenticatedUser": {
                "id": "u0", "providerDisplayName": "Evidence Reader",
                "properties": {"Account": {"$type": "System.String", "$value": "reader@example.com"}}}}),
            ("GET", "/contoso/_apis/projects"): Resp(body={"value": [{"id": P, "name": "Web"}]}),
            ("GET", f"/contoso/{P}/_apis/wit/workitemtypes"): Resp(body={"count": len(TYPES), "value": TYPES}),
            ("POST", f"/contoso/{P}/_apis/wit/wiql"): Resp(body={"queryType": "flat", "workItems": [
                {"id": i, "url": f"{ORG}/_apis/wit/workItems/{i}"} for i in ITEMS]}),
            ("POST", f"/contoso/{P}/_apis/wit/workitemsbatch"): lambda params, body: Resp(body={
                "count": len(body["ids"]), "value": [ITEMS[i] for i in body["ids"] if i in ITEMS]}),
        }
        for wid in ITEMS:
            self.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/{wid}/updates")] = \
                lambda params, body, wid=wid: Resp(body={"count": len(UPDATES[wid]), "value": UPDATES[wid][
                    int(params.get("$skip", 0)):int(params.get("$skip", 0)) + int(params["$top"])]})
            self.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/{wid}/comments")] = Resp(body={
                "totalCount": len(COMMENTS.get(wid, [])), "count": len(COMMENTS.get(wid, [])),
                "comments": COMMENTS.get(wid, [])})
        for cid, body in CHANGESETS.items():
            self.routes[("GET", f"/contoso/_apis/tfvc/changesets/{cid}")] = Resp(body=body)

    def request(self, method, url, headers=None, params=None, timeout=None, allow_redirects=True, json=None):
        params = dict(params or {})
        parts = urlsplit(url)
        assert parts.netloc == "dev.azure.com", url
        self.calls.append((method, parts.path, params, json))
        route = self.routes.get((method, parts.path))
        if route is None:
            raise AssertionError(f"unexpected request {method} {parts.path} {params}")
        return route(params, json) if callable(route) else route


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    for name in (mod.TYPES_ENV, mod.TAGS_ENV, mod.LOOKBACK_ENV, mod.APPROVAL_STATES_ENV, mod.APPROVAL_PATTERN_ENV,
                 mod.APPROVAL_TYPES_ENV, mod.APPROVAL_MENTIONS_ENV, mod.APPROVAL_FIELD_ENV, mod.APPROVAL_SOURCE_ENV,
                 mod.APPROVAL_FIELD_FROM_ENV, mod.APPROVAL_BEFORE_FIELD_ENV, mod.EMERGENCY_TYPES_ENV,
                 "AZURE_DEVOPS_PROJECTS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AZURE_DEVOPS_ORG_URL", ORG)
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "pat-do-not-write")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(dr.time, "sleep", lambda s: None)


def run(tmp_path, fake=None):
    fake = fake or FakeADO()
    code = dr.run_org(fetcher=mod.NAME, logger=mod.logger, collect=mod.collect, session=fake)
    text = (tmp_path / "azure_devops_work_items_contoso.json").read_text()
    status = tmp_path / "status.json"
    return code, json.loads(text), json.loads(status.read_text()) if status.exists() else None, fake, text


def work_item(evidence, wid):
    return next(i for i in evidence["results"]["work_items"] if i["id"] == wid)


def with_items(fake, extra, updates=None, comments=None):
    """Adds work items to the query and the batch, with their updates and comments."""
    everything = {**ITEMS, **extra}
    fake.routes[("POST", f"/contoso/{P}/_apis/wit/wiql")] = Resp(body={"workItems": [{"id": i} for i in everything]})
    fake.routes[("POST", f"/contoso/{P}/_apis/wit/workitemsbatch")] = lambda params, body: Resp(body={
        "value": [everything[i] for i in body["ids"]]})
    for wid in extra:
        fake.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/{wid}/updates")] = Resp(body={
            "value": (updates or {}).get(wid, [])})
        fake.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/{wid}/comments")] = Resp(body={
            "comments": (comments or {}).get(wid, [])})
    return fake


def test_fetcher_yaml_follows_the_shape():
    spec_ = yaml.safe_load((FETCHER_DIR / "fetcher.yaml").read_text())
    assert spec_["name"] == mod.NAME and spec_["version"] == "0.3.0" and spec_["category"] == "azure"
    assert spec_["ksis"] == ["KSI-CMT-LMC", "KSI-PIY-RES"]
    assert spec_["evidence_set"]["reference_id"] == "EVD-AZURE-DEVOPS-WORK-ITEMS"
    config = spec_["config_schema"]
    assert {k: v["env"] for k, v in config.items()} == {
        "work_item_types": mod.TYPES_ENV, "work_item_tags": mod.TAGS_ENV, "lookback_days": mod.LOOKBACK_ENV,
        "approval_states": mod.APPROVAL_STATES_ENV, "approval_pattern": mod.APPROVAL_PATTERN_ENV,
        "approval_types": mod.APPROVAL_TYPES_ENV, "approval_mentions": mod.APPROVAL_MENTIONS_ENV,
        "approval_field": mod.APPROVAL_FIELD_ENV, "approval_source": mod.APPROVAL_SOURCE_ENV,
        "approval_field_from": mod.APPROVAL_FIELD_FROM_ENV, "approval_before_field": mod.APPROVAL_BEFORE_FIELD_ENV,
        "emergency_types": mod.EMERGENCY_TYPES_ENV}
    assert config["approval_source"]["default"] == mod.HISTORY == config["approval_before_field"]["default"]
    assert "default" not in config["approval_field"] and "default" not in config["emergency_types"]
    assert config["approval_mentions"]["default"] is False and config["approval_mentions"]["type"] == "boolean"
    assert config["work_item_types"]["default"] == ",".join(mod.DEFAULT_TYPES)
    assert config["work_item_tags"]["default"] == ",".join(mod.DEFAULT_TAGS)
    assert config["lookback_days"]["default"] == mod.DEFAULT_LOOKBACK_DAYS
    assert config["approval_states"]["default"] == ",".join(mod.DEFAULT_APPROVAL_STATES)
    assert config["approval_pattern"]["default"] == mod.DEFAULT_APPROVAL_PATTERN
    assert spec_["secrets"][0]["env"] == "AZURE_DEVOPS_PAT" and spec_["secrets"][0]["required"] is False
    summary_fields = [line.split(" — ")[0].strip("- ").strip()
                      for line in spec_["evidence_set"]["instructions"].split("Summary fields:")[1].splitlines()
                      if line.startswith("- ")]
    selection = mod.Selection([], [], [], mod.approval_pattern(), [], False)
    assert summary_fields == list(mod.summarize([], [], True, selection, 1))


def test_every_summary_field_is_documented(tmp_path, assert_summary_documented):
    _, evidence, _, _, _ = run(tmp_path)
    assert_summary_documented("azure/devops_work_items", evidence["summary"])


def test_collects_change_and_security_items_and_exits_zero(tmp_path):
    code, evidence, status, _, _ = run(tmp_path)
    assert code == 0 and status is None and evidence["metadata"]["partial_failure"] is False
    s = evidence["summary"]
    assert (s["work_item_types"], s["work_item_tags"], s["lookback_days"]) == (["Change Request"], ["Security"], 90)
    assert s["projects_collected"] == 1 and s["work_item_types_missing"] == []
    assert s["work_items_total"] == 6 and s["work_items_by_type"] == {"Bug": 2, "Change Request": 3, "Task": 1}
    assert s["work_items_by_state_category"] == {"Completed": 3, "InProgress": 3}
    assert s["work_item_states_undefined"] == []
    assert s["work_items_open"] == 3 and s["approval_history_collected"] is True
    assert (s["change_items"], s["change_items_finished"], s["change_items_approved"]) == (3, 2, 2)
    # Every selected type needs an approval when approval_types is empty.
    assert s["approval_types"] == ["Change Request"]
    # Only finished items are judged: 102 is approved but still open, so it's left out.
    assert (s["finished_change_items_needing_approval"], s["finished_change_items_needing_approval_approved"]) == (2, 1)
    assert s["finished_change_items_approved_percentage"] == 50
    assert s["finished_change_items_without_approval"] == [103] and s["change_items_approved_by_requester"] == []
    assert s["change_items_with_linked_changes"] == 2
    assert s["finished_change_items_without_linked_change"] == [103]
    assert s["change_items_linked_changes_checked"] == 2
    assert s["change_items_changed_before_approval"] == [102]
    assert s["change_items_approved_by_change_author"] == [102]
    assert s["tagged_items_open"] == 2 and s["tagged_items_open_by_priority"] == {"3": 1, "unset": 1}
    assert s["tagged_items_overdue"] == [201] and s["tagged_items_overdue_high_priority"] == [201]
    assert s["tagged_items_open_unassigned"] == [201] and s["tagged_items_open_without_planned_date"] == 0
    assert set(s["not_collected"]) == set(mod.NOT_COLLECTED)


def test_approval_comes_from_the_state_history_or_a_matching_comment(tmp_path):
    _, evidence, _, _, text = run(tmp_path)
    by_state = work_item(evidence, 101)
    assert by_state["approval"]["source"] == "state" and by_state["approval"]["state"] == "Approved"
    assert by_state["approval"]["by"] == {"display_name": "Bob", "login": "bob@example.com"}
    assert by_state["state_history"][0]["from"] == "Proposed" and len(by_state["state_history"]) == 2
    assert by_state["changed_before_approval"] is False and by_state["approved_by_change_author"] is False
    # "Not approved yet" doesn't start with "approved"; a deleted comment never counts.
    assert by_state["comments"] == 1
    by_comment = work_item(evidence, 102)
    assert by_comment["approval"] == {"at": by_comment["approval"]["at"], "by": {"display_name": "Carol",
                                      "login": "carol@example.com"}, "source": "comment", "state": None}
    assert by_comment["comments"] == 2 and by_comment["changed_before_approval"] is True
    assert "change board" not in text and "CAB-42" not in text and "Looks fine" not in text
    assert "pat-do-not-write" not in text


def test_an_item_carries_its_fields_and_links(tmp_path):
    _, evidence, _, _, _ = run(tmp_path)
    cr = work_item(evidence, 102)
    assert cr["links"]["changesets"] == [502] and cr["links"]["builds"] == [9001]
    assert cr["assigned_to"]["login"] == "carol@example.com" and cr["selected_by"] == ["type"]
    assert cr["first_linked_change"] == evidence["results"]["changesets"][1]["created_date"]
    closed = work_item(evidence, 101)
    assert closed["links"]["parent"] == 100 and closed["links"]["hyperlinks"] == 1
    assert closed["closed_by"]["login"] == "bob@example.com" and closed["closed_date"] and closed["open"] is False
    bug = work_item(evidence, 201)
    assert bug["links"]["commits"] == [{"repository_id": "repo-1", "commit": "abc123"}]
    assert bug["links"]["pull_requests"] == [{"repository_id": "repo-1", "id": 77}]
    assert bug["tags"] == ["Security", "Web"] and bug["selected_by"] == ["tag"]
    assert bug["planned_date"] == bug["due_date"] and bug["overdue"] is True and bug["high_priority"] is True
    task = work_item(evidence, 202)
    assert task["planned_date"] == task["target_date"] and task["overdue"] is False and task["high_priority"] is None
    assert {c["id"] for c in evidence["results"]["changesets"]} == {501, 502}
    assert "comment" not in evidence["results"]["changesets"][0]


def test_the_query_selects_types_tags_the_window_and_open_states(tmp_path):
    _, _, _, fake, _ = run(tmp_path)
    wiql = next(body["query"] for method, path, _, body in fake.calls if path.endswith("/wiql"))
    assert "[System.TeamProject] = 'Web'" in wiql
    assert "[System.WorkItemType] IN ('Change Request')" in wiql and "[System.Tags] CONTAINS 'Security'" in wiql
    assert "[System.ChangedDate] >= @Today - 90" in wiql
    assert "[System.State] IN ('active', 'approved', 'doing', 'new', 'proposed', 'resolved', 'to do')" in wiql
    batch = next(body for method, path, _, body in fake.calls if path.endswith("/workitemsbatch"))
    assert batch["$expand"] == "Relations" and batch["errorPolicy"] == "Omit"
    assert all(method == "GET" for method, path, _, _ in fake.calls if "/wiql" not in path and "batch" not in path)


def test_configured_types_tags_and_approval(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.TYPES_ENV, "Task, Release")
    monkeypatch.setenv(mod.TAGS_ENV, "none")
    monkeypatch.setenv(mod.APPROVAL_STATES_ENV, "none")
    monkeypatch.setenv(mod.APPROVAL_PATTERN_ENV, r"\bcab ok\b")
    monkeypatch.setenv(mod.LOOKBACK_ENV, "30")
    fake = FakeADO()
    fake.routes[("POST", f"/contoso/{P}/_apis/wit/wiql")] = Resp(body={"workItems": [{"id": 202}]})
    COMMENTS_202 = [{"id": 1, "text": "<b>CAB OK</b>", "createdBy": who("erin@example.com"),
                     "createdDate": ago(days=1), "isDeleted": False}]
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/202/comments")] = Resp(body={"comments": COMMENTS_202})
    _, evidence, _, fake, _ = run(tmp_path, fake)
    wiql = next(body["query"] for _, path, _, body in fake.calls if path.endswith("/wiql"))
    assert "IN ('Task')" in wiql and "CONTAINS" not in wiql and "@Today - 30" in wiql
    s = evidence["summary"]
    assert s["work_item_types_missing"] == ["Release"] and s["change_items"] == 1 and s["tagged_items_open"] == 0
    assert work_item(evidence, 202)["approval"]["source"] == "comment"
    assert evidence["results"]["selection"]["approval_states"] == []


def test_no_selected_type_and_no_tag_skips_the_query(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.TYPES_ENV, "Release")
    monkeypatch.setenv(mod.TAGS_ENV, "none")
    code, evidence, _, fake, _ = run(tmp_path)
    assert code == 0 and not any(path.endswith("/wiql") for _, path, _, _ in fake.calls)
    assert evidence["summary"]["work_items_total"] == 0 and evidence["summary"]["work_item_types_missing"] == ["Release"]


@pytest.mark.parametrize("env_name, value", [(mod.APPROVAL_PATTERN_ENV, "(unclosed"), (mod.LOOKBACK_ENV, "soon"),
                                             (mod.TYPES_ENV, "none"), (mod.APPROVAL_MENTIONS_ENV, "sometimes")])
def test_bad_config_fails_with_bad_config(tmp_path, monkeypatch, env_name, value):
    monkeypatch.setenv(env_name, value)
    if env_name == mod.TYPES_ENV:
        monkeypatch.setenv(mod.TAGS_ENV, "none")
    code, _, status, _, _ = run(tmp_path)
    assert code == 1 and status["code"] == "bad_config"


def test_updates_and_comments_are_paged(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "UPDATES_PAGE", 1)
    fake = FakeADO()
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/102/comments")] = lambda params, body: Resp(body={
        "comments": COMMENTS[102][:1], "continuationToken": "c2"} if "continuationToken" not in params else {
        "comments": COMMENTS[102][1:], "continuationToken": None})
    _, evidence, _, fake, _ = run(tmp_path, fake)
    skips = [p["$skip"] for _, path, p, _ in fake.calls if path.endswith("/101/updates")]
    assert skips == [0, 1, 2, 3]
    assert len(work_item(evidence, 101)["state_history"]) == 2
    assert work_item(evidence, 102)["approval"]["source"] == "comment"


def test_unread_history_leaves_the_approval_figures_unknown(tmp_path):
    fake = FakeADO()
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/103/updates")] = err(500, "boom")
    code, evidence, status, _, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "internal_error"
    s = evidence["summary"]
    assert s["approval_history_collected"] is False and s["change_items_approved"] is None
    assert s["finished_change_items_without_approval"] is None and s["change_items_changed_before_approval"] is None
    assert s["change_items"] == 3 and s["tagged_items_overdue"] == [201]
    assert work_item(evidence, 103)["state_history"] is None and work_item(evidence, 103)["approval_read"] is False


def test_an_unread_changeset_leaves_the_change_order_unknown(tmp_path):
    fake = FakeADO()
    # TFVC answers 500, not 403, when an item in the changeset can't be read.
    fake.routes[("GET", "/contoso/_apis/tfvc/changesets/502")] = err(
        500, "TF14098: Access Denied: User x needs Read permission(s) for at least one item in changeset 502.")
    code, evidence, status, fake, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "not_authorized" and "Code (Read)" in status["error"]
    assert sum(1 for _, path, _, _ in fake.calls if path.endswith("/changesets/502")) == 1
    assert work_item(evidence, 102)["changed_before_approval"] is None
    assert evidence["summary"]["change_items_changed_before_approval"] is None
    assert evidence["summary"]["change_items_with_linked_changes"] == 2


def test_an_item_the_batch_omits_is_a_failure_and_leaves_the_counts_unknown(tmp_path):
    fake = FakeADO()
    # errorPolicy "Omit" answers null for an item deleted since the query.
    fake.routes[("POST", f"/contoso/{P}/_apis/wit/workitemsbatch")] = lambda params, body: Resp(body={
        "count": len(body["ids"]), "value": [None if i == 103 else ITEMS[i] for i in body["ids"]]})
    code, evidence, status, _, _ = run(tmp_path, fake)
    assert code == 1 and evidence["metadata"]["partial_failure"] is True and status["code"] == "internal_error"
    assert [f["operation"] for f in evidence["metadata"]["api_failures"]] == ["wit.workitemsbatch(Web/103)"]
    assert "work item 103" in evidence["metadata"]["api_failures"][0]["message"]
    s = evidence["summary"]
    assert s["projects_collected"] == 0 and s["work_items_total"] is None
    assert s["finished_change_items_without_approval"] is None and s["change_items"] is None


def test_a_change_linked_only_to_git_leaves_the_change_checks_unknown(tmp_path):
    git_only = item(104, "Change Request", "Closed", relations=[
        artifact("vstfs:///Git/Commit/p-web%2Frepo-1%2Fdef456", "Fixed in Commit"),
        artifact("vstfs:///Git/PullRequestId/p-web%252Frepo-1%252F78", "Pull Request")])
    fake = with_items(FakeADO(), {104: git_only}, updates={104: [
        update(1, "Proposed", "Approved", ago(days=9)), update(2, "Approved", "Closed", ago(days=1))]})
    code, evidence, _, _, _ = run(tmp_path, fake)
    assert code == 0
    git = work_item(evidence, 104)
    assert git["approval"]["source"] == "state"
    assert git["changed_before_approval"] is None and git["approved_by_change_author"] is None
    s = evidence["summary"]
    assert s["change_items_with_linked_changes"] == 3 and s["change_items_linked_changes_checked"] == 2
    assert s["change_items_changed_before_approval"] is None and s["change_items_approved_by_change_author"] is None


@pytest.mark.parametrize("text, approves", [
    ("<blockquote>Approved</blockquote><div>I don't think this should be approved yet.</div>", False),
    ("<blockquote><div>x</div><blockquote>Approved</blockquote>y</blockquote>Not yet", False),
    ("&gt; Approved<br>Not yet", False),
    ("> Approved\n\nNot yet", False),
    ("<div>Approved?</div>", False),
    ("Approved, right?", False),
    ("<div>Checked the plan.</div><div>Approved - deploy Friday</div>", True),
    ("APPROVED", True),
])
def test_quoted_text_and_questions_are_not_approval(text, approves):
    assert bool(mod.approval_pattern().search(mod.comment_text(text))) is approves


def test_a_comment_approval_skips_quotes_and_questions_and_flags_the_requester(tmp_path):
    def comment(n, text, by, days):
        return {"id": n, "text": text, "createdBy": who(by), "createdDate": ago(days=days), "isDeleted": False}
    # alice@example.com created both items.
    fake = with_items(FakeADO(), {104: item(104, "Change Request", "Closed"), 105: item(105, "Change Request", "Active")},
                      updates={104: [update(1, "Proposed", "Closed", ago(days=1))]},
                      comments={104: [comment(1, "<blockquote>Approved</blockquote><div>I don't think this should "
                                                 "be approved yet.</div>", "alice@example.com", 5),
                                      comment(2, "Approved?", "erin@example.com", 4)],
                                105: [comment(1, "<div>Approved</div>", "alice@example.com", 3)]})
    code, evidence, _, _, _ = run(tmp_path, fake)
    assert code == 0
    assert work_item(evidence, 104)["approval"] is None and work_item(evidence, 104)["approved_by_requester"] is None
    assert work_item(evidence, 105)["approval"]["by"]["login"] == "alice@example.com"
    assert work_item(evidence, 105)["approved_by_requester"] is True
    assert work_item(evidence, 101)["approved_by_requester"] is False
    s = evidence["summary"]
    assert s["finished_change_items_without_approval"] == [103, 104] and s["change_items_approved_by_requester"] == [105]


def rejected(n, old, new, at, reason="Rejected"):
    return update(n, old, new, at, **{"System.Reason": {"oldValue": "Approved", "newValue": reason}})


@pytest.mark.parametrize("moves, approving", [
    # Back to Proposed, marked Rejected.
    ([update(1, "Proposed", "Approved", ago(days=9)), rejected(2, "Approved", "Proposed", ago(days=6)),
      update(3, "Proposed", "Closed", ago(days=1))], None),
    # Into a Rejected state.
    ([update(1, "Proposed", "Approved", ago(days=9)), rejected(2, "Approved", "Rejected", ago(days=6)),
      update(3, "Rejected", "Closed", ago(days=1))], None),
    # Back before the approval state after work started, with no reason naming rejection.
    ([update(1, "Proposed", "Approved", ago(days=9)), update(2, "Approved", "Active", ago(days=8)),
      rejected(3, "Active", "Proposed", ago(days=6), reason="Returned"), update(4, "Proposed", "Closed", ago(days=1))],
     None),
    # Approved again after the reversal: the later approval is the one in effect.
    ([update(1, "Proposed", "Approved", ago(days=9)), rejected(2, "Approved", "Proposed", ago(days=6)),
      update(3, "Proposed", "Approved", ago(days=4)), update(4, "Approved", "Closed", ago(days=1))], 2),
    # Moving on from Approved isn't a reversal.
    ([update(1, "Proposed", "Approved", ago(days=9)), update(2, "Approved", "Active", ago(days=8)),
      update(3, "Active", "Closed", ago(days=1))], 0),
])
def test_a_withdrawn_approval_does_not_count(tmp_path, moves, approving):
    fake = with_items(FakeADO(), {104: item(104, "Change Request", "Closed")}, updates={104: moves})
    types = [dict(t) for t in TYPES]
    types[0] = {**types[0], "states": types[0]["states"] + states(("Rejected", "Removed"))}
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workitemtypes")] = Resp(body={"value": types})
    _, evidence, _, _, _ = run(tmp_path, fake)
    approval = work_item(evidence, 104)["approval"]
    s = evidence["summary"]
    if approving is None:
        assert approval is None and s["finished_change_items_without_approval"] == [103, 104]
        assert s["change_items_approved"] == 2
    else:
        assert approval["at"] == work_item(evidence, 104)["state_history"][approving]["at"]
        assert s["finished_change_items_without_approval"] == [103] and s["change_items_approved"] == 3


def test_a_removed_item_is_not_finished_and_an_undefined_state_is_named(tmp_path):
    fake = FakeADO()
    types = [dict(t) for t in TYPES]
    types[0] = {**types[0], "states": types[0]["states"] + states(("Removed", "Removed"))}
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workitemtypes")] = Resp(body={"value": types})
    with_items(fake, {104: item(104, "Change Request", "Removed"), 105: item(105, "Change Request", "Awaiting Sign-off")})
    code, evidence, _, _, _ = run(tmp_path, fake)
    s = evidence["summary"]
    assert code == 0 and (s["change_items"], s["change_items_finished"]) == (5, 2)
    assert s["finished_change_items_without_approval"] == [103]
    assert s["finished_change_items_without_linked_change"] == [103]
    assert s["work_items_by_state_category"] == {"Completed": 3, "InProgress": 3, "Removed": 1, "unknown": 1}
    assert s["work_item_states_undefined"] == ["Change Request: Awaiting Sign-off"] and s["work_items_open"] == 3
    assert work_item(evidence, 104)["open"] is False and work_item(evidence, 105)["open"] is None
    project = evidence["results"]["projects"][0]
    assert project["undefined_states"] == ["Change Request: Awaiting Sign-off"]
    assert list(project["states_by_type"]) == ["Bug", "Change Request", "Task"]
    assert project["states_by_type"]["Change Request"] == {"Proposed": "Proposed", "Approved": "InProgress",
                                                           "Active": "InProgress", "Closed": "Completed",
                                                           "Removed": "Removed"}


@pytest.mark.parametrize("route", [("POST", f"/contoso/{P}/_apis/wit/wiql"),
                                   ("GET", f"/contoso/{P}/_apis/wit/workitemtypes"),
                                   ("POST", f"/contoso/{P}/_apis/wit/workitemsbatch"),
                                   ("GET", "/contoso/_apis/projects")])
def test_an_unlisted_project_leaves_every_count_unknown(tmp_path, route):
    fake = FakeADO()
    fake.routes[route] = err(403, "TF401019: no access")
    code, evidence, status, _, _ = run(tmp_path, fake)
    s = evidence["summary"]
    assert code == 1 and status["code"] == "not_authorized"
    assert s["work_items_total"] is None and s["tagged_items_overdue"] is None and s["change_items"] is None
    assert s["approval_history_collected"] is False


def test_links_reads_every_kind():
    found = mod.links([
        artifact("vstfs:///VersionControl/Changeset/12", "Fixed in Changeset"),
        artifact("vstfs:///Git/Ref/p%2Fr%2FGBmain", "Branch"),
        {"rel": "System.LinkTypes.Hierarchy-Forward", "url": f"{ORG}/_apis/wit/workItems/7"},
        {"rel": "System.LinkTypes.Related", "url": f"{ORG}/_apis/wit/workItems/8"},
        {"rel": "System.LinkTypes.Dependency-Forward", "url": f"{ORG}/_apis/wit/workItems/9"},
        {"rel": "AttachedFile", "url": "https://dev.azure.com/contoso/_apis/wit/attachments/x"},
        "not a relation",
    ])
    assert found["changesets"] == [12] and found["other_artifacts"] == 1
    assert (found["children"], found["related"], found["other_work_items"], found["attachments"]) == ([7], [8], 1, 1)


@pytest.mark.parametrize("value, expected", [
    ({"displayName": "Ann", "uniqueName": "ann@example.com"}, {"display_name": "Ann", "login": "ann@example.com"}),
    ("Ann Lee <ann@example.com>", {"display_name": "Ann Lee", "login": "ann@example.com"}),
    ("Build Service", {"display_name": "Build Service", "login": None}),
    ({}, None), ("", None), (None, None),
])
def test_person(value, expected):
    assert mod.person(value) == expected


def mention(name, guid="1b2c3d4e-0000-4000-8000-000000000001"):
    return f'<a href="#" data-vss-mention="version:2.0,{guid}">@{name}</a>'


MENTION_CASES = [
    (f"<div>{mention('Jane Doe')} approved</div>", True),
    (f"<div>{mention('Ann Lee')} {mention('Bo Li')} approved</div>", True),
    (f"<div>{mention('Jane Doe')}, approved</div>", True),
    (f"<div>{mention('Jane Doe')}&nbsp;Approved - deploy Friday</div>", True),
    (f"<div>Checked the plan.</div><div>{mention('Jane Doe')} approved</div>", True),
    ("@jane approved", True),
    ("@jane.doe, @bo-li: approved", True),
    ("@<1B2C3D4E-0000-4000-8000-000000000001> approved", True),
    (f"<div>{mention('Jane Doe')} not approved</div>", False),
    (f"<div>{mention('Jane Doe')} approved?</div>", False),
    (f"<div>{mention('Jane Doe')} please approve</div>", False),
    ("approved by nobody yet?", False),
    (f"<blockquote>{mention('Jane Doe')} approved</blockquote><div>Not yet</div>", False),
    ("&gt; @jane approved<br>Not yet", False),
    ("Hi @jane approved", False),
    # Typed without the picker, a mention is one word long, so the rest of a name stays text.
    ("@Jane Doe approved", False),
    ("jane@example.com approved", False),
]


@pytest.mark.parametrize("text, approves", MENTION_CASES)
def test_with_mentions_on_a_line_starting_with_mentions_then_approved_is_approval(text, approves):
    assert bool(mod.approval_pattern().search(mod.comment_text(text, True))) is approves


@pytest.mark.parametrize("text", [text for text, _ in MENTION_CASES if not text.startswith("@<")])
def test_with_mentions_off_no_mention_line_is_approval(text):
    assert not mod.approval_pattern().search(mod.comment_text(text))


def test_with_mentions_off_a_markdown_mention_still_reads_as_before():
    # Its @<id> is stripped as a tag, leaving "@", which the default pattern skips; so it counted before the setting.
    assert mod.comment_text("@<1B2C3D4E-0000-4000-8000-000000000001> approved") == "@  approved"


def test_mentions_read_as_one_token_only_when_on():
    raw = f"<div>{mention('Jane Doe')} and @bo, mail jane@example.com</div>"
    assert mod.comment_text(raw, True).split() == ["and", "@mention,", "mail", "jane@example.com"]
    assert mod.comment_text(raw).split() == ["@Jane", "Doe", "and", "@bo,", "mail", "jane@example.com"]


def test_an_unclosed_mention_link_does_not_swallow_the_text_after_it():
    raw = "<div><a data-vss-mention=\"v\">@X please</div><div>hold, <a href='y'>doc</a> approved</div>"
    assert not mod.approval_pattern().search(mod.comment_text(raw, True))
    # Only the attribute counts, not the words inside another attribute's value.
    assert "@mention" not in mod.comment_text('<a title="data-vss-mention">@X</a> approved', True)


def comment(n, text, by, days):
    return {"id": n, "text": text, "createdBy": who(by), "createdDate": ago(days=days), "isDeleted": False}


@pytest.mark.parametrize("setting", ["true", "false", None])
def test_a_mention_approval_counts_only_when_on_and_a_later_rejection_withdraws_it(tmp_path, monkeypatch, setting):
    if setting is not None:
        monkeypatch.setenv(mod.APPROVAL_MENTIONS_ENV, setting)
    approving = f"<div>{mention('Erin Example')} approved</div>"
    fake = with_items(FakeADO(), {104: item(104, "Change Request", "Closed"), 105: item(105, "Change Request", "Closed")},
                      updates={104: [update(1, "Proposed", "Closed", ago(days=1))],
                               105: [rejected(1, "Proposed", "Rejected", ago(days=6)),
                                     update(2, "Rejected", "Closed", ago(days=1))]},
                      comments={104: [comment(1, approving, "frank@example.com", 4)],
                                105: [comment(1, approving, "frank@example.com", 9)]})
    types = [dict(t) for t in TYPES]
    types[0] = {**types[0], "states": types[0]["states"] + states(("Rejected", "Removed"))}
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workitemtypes")] = Resp(body={"value": types})
    code, evidence, _, _, text = run(tmp_path, fake)
    on = setting == "true"
    assert code == 0 and "Erin" not in text
    assert evidence["results"]["selection"]["approval_mentions"] is on and evidence["summary"]["approval_mentions"] is on
    approval = work_item(evidence, 104)["approval"]
    if on:
        assert approval["source"] == "comment" and approval["by"]["login"] == "frank@example.com"
    else:
        assert approval is None
    assert work_item(evidence, 105)["approval"] is None
    s = evidence["summary"]
    assert s["finished_change_items_without_approval"] == ([103, 105] if on else [103, 104, 105])
    assert (s["finished_change_items_needing_approval"],
            s["finished_change_items_needing_approval_approved"]) == (4, 2 if on else 1)
    assert s["finished_change_items_approved_percentage"] == (50 if on else 25)


@pytest.mark.parametrize("mentions, pattern, approves", [
    # On, a pattern of its own matches what follows the mentions, and never sees a name.
    ("true", r"^\W*cab ok\b", True),
    ("true", r"jane", False),
    # Off, the line is matched as today, name included.
    (None, r"^\W*cab ok\b", False),
    (None, r"jane", True),
])
def test_a_custom_pattern_with_mentions_on_and_off(tmp_path, monkeypatch, mentions, pattern, approves):
    monkeypatch.setenv(mod.APPROVAL_PATTERN_ENV, pattern)
    if mentions:
        monkeypatch.setenv(mod.APPROVAL_MENTIONS_ENV, mentions)
    fake = with_items(FakeADO(), {104: item(104, "Change Request", "Active")},
                      comments={104: [comment(1, f"<div>{mention('Jane Doe')} CAB OK</div>", "erin@example.com", 2)]})
    _, evidence, _, _, _ = run(tmp_path, fake)
    assert (work_item(evidence, 104)["approval"] is not None) is approves
    assert evidence["results"]["selection"]["approval_pattern"] == pattern


def test_only_approval_types_count_toward_the_percentage(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.TYPES_ENV, "Normal Change, Emergency Change, Standard Change")
    monkeypatch.setenv(mod.TAGS_ENV, "none")
    monkeypatch.setenv(mod.APPROVAL_TYPES_ENV, "normal change ,EMERGENCY CHANGE, Normal Change")
    extra = {301: item(301, "Normal Change", "Closed"), 302: item(302, "Normal Change", "Active"),
             303: item(303, "Emergency Change", "Closed"), 304: item(304, "Emergency Change", "Closed"),
             305: item(305, "Standard Change", "Closed")}
    fake = with_items(FakeADO(), extra,
                      updates={301: [update(1, "Proposed", "Approved", ago(days=5))]},
                      comments={303: [comment(1, "Approved", "erin@example.com", 3)],
                                305: [comment(1, "Approved", "erin@example.com", 3)]})
    types = [{"name": n, "states": TYPES[0]["states"]} for n in ("Normal Change", "Emergency Change", "Standard Change")]
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workitemtypes")] = Resp(body={"value": types})
    fake.routes[("POST", f"/contoso/{P}/_apis/wit/wiql")] = Resp(body={"workItems": [{"id": i} for i in extra]})
    code, evidence, _, _, _ = run(tmp_path, fake)
    assert code == 0
    assert [work_item(evidence, i)["approval_required"] for i in extra] == [True, True, True, True, False]
    s = evidence["summary"]
    assert s["approval_types"] == ["Normal Change", "Emergency Change"]
    assert evidence["results"]["selection"]["approval_types"] == ["Normal Change", "Emergency Change"]
    # The approved standard change counts in change_items_approved but not toward the percentage, nor does open 302.
    assert (s["change_items"], s["change_items_approved"]) == (5, 3)
    assert (s["finished_change_items_needing_approval"], s["finished_change_items_needing_approval_approved"]) == (3, 2)
    assert s["finished_change_items_approved_percentage"] == 66


def test_a_tag_only_item_never_needs_approval(tmp_path):
    _, evidence, _, _, _ = run(tmp_path)
    assert [work_item(evidence, i)["approval_required"] for i in (101, 201, 202)] == [True, False, False]


@pytest.mark.parametrize("types, approval_types", [("Change Request", "Change Request, Release"),
                                                   ("none", "Change Request")])
def test_an_approval_type_that_is_not_selected_is_bad_config(tmp_path, monkeypatch, types, approval_types):
    monkeypatch.setenv(mod.TYPES_ENV, types)
    monkeypatch.setenv(mod.APPROVAL_TYPES_ENV, approval_types)
    code, _, status, fake, _ = run(tmp_path)
    assert code == 1 and status["code"] == "bad_config"
    assert mod.APPROVAL_TYPES_ENV in status["error"] and not any(p.endswith("/wiql") for _, p, _, _ in fake.calls)


def test_no_item_needing_approval_reads_zero_percent(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.TYPES_ENV, "Change Request, Release")
    monkeypatch.setenv(mod.APPROVAL_TYPES_ENV, "Release")
    _, evidence, _, _, _ = run(tmp_path)
    s = evidence["summary"]
    assert (s["change_items"], s["finished_change_items_needing_approval"]) == (3, 0)
    assert (s["finished_change_items_needing_approval_approved"], s["finished_change_items_approved_percentage"]) == (0, 0)


def test_unread_history_leaves_the_percentage_unknown_not_zero(tmp_path):
    fake = FakeADO()
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/101/comments")] = err(500, "boom")
    code, evidence, _, _, _ = run(tmp_path, fake)
    s = evidence["summary"]
    assert code == 1 and s["approval_history_collected"] is False
    assert s["finished_change_items_needing_approval"] == 2
    assert s["finished_change_items_needing_approval_approved"] is None
    assert s["finished_change_items_approved_percentage"] is None


def test_an_unlisted_project_leaves_the_percentage_unknown(tmp_path):
    fake = FakeADO()
    fake.routes[("POST", f"/contoso/{P}/_apis/wit/wiql")] = err(403, "TF401019: no access")
    _, evidence, _, _, _ = run(tmp_path, fake)
    s = evidence["summary"]
    assert s["finished_change_items_needing_approval"] is None and s["finished_change_items_approved_percentage"] is None


def test_a_refused_finished_item_is_left_out_of_the_percentage(tmp_path):
    def finished(wid, state, reason):
        return item(wid, "Change Request", state, **{"System.Reason": reason})
    fake = with_items(FakeADO(), {104: finished(104, "Closed", "Rejected"), 105: finished(105, "Rejected", "Rejected"),
                                  106: finished(106, "Removed", "Cut"), 107: finished(107, "Closed", "Completed")})
    types = [dict(t) for t in TYPES]
    # A process whose Rejected and Removed states finish the item (Completed category).
    types[0] = {**types[0], "states": types[0]["states"] + states(("Rejected", "Completed"), ("Removed", "Completed"))}
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workitemtypes")] = Resp(body={"value": types})
    code, evidence, _, _, _ = run(tmp_path, fake)
    s = evidence["summary"]
    assert code == 0 and s["change_items_finished"] == 6
    # Refused 104-106 are still listed as finished without approval, but only 101, 103 and 107 are judged.
    assert s["finished_change_items_without_approval"] == [103, 104, 105, 106, 107]
    assert (s["finished_change_items_needing_approval"], s["finished_change_items_needing_approval_approved"]) == (3, 1)
    assert s["finished_change_items_approved_percentage"] == 33


# The approval field: a person (identity) field holding the approver.
FIELD = "Custom.ChangeApprover"
GUID = "d291b0c4-a05c-4ea6-8df1-4b41d5f39eff"


def identity(name, login):
    """An identity field's value as workitemsbatch returns it."""
    return {"displayName": name, "url": f"https://spsprodcus1.vssps.visualstudio.com/A0/_apis/Identities/{GUID}",
            "_links": {"avatar": {"href": f"{ORG}/_apis/GraphProfile/MemberAvatars/aad.ZmFrZQ"}},
            "id": GUID, "uniqueName": login, "imageUrl": f"{ORG}/_apis/GraphProfile/MemberAvatars/aad.ZmFrZQ",
            "descriptor": "aad.ZmFrZQ"}


FRANK = identity("Frank Approver", "frank@example.com")
GRACE = identity("Grace Approver", "grace@example.com")


def filled(n, at, value, old=None, by="bob@example.com"):
    """An update that sets the approval field, or clears it when value is None."""
    change = {**({"oldValue": old} if old else {}), **({"newValue": value} if value else {})}
    return {"id": n, "rev": n, "revisedBy": who(by), "revisedDate": at,
            "fields": {"System.ChangedDate": {"newValue": at}, FIELD: change}}


def iso_ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def with_field_types(fake, missing=(), names=("Change Request", "Bug", "Task")):
    """Type listings that name their fields, the approval field on every type but the missing ones."""
    base = {t["name"]: t for t in TYPES}
    types = [{**base.get(n, TYPES[0]), "name": n, "fields": [{"referenceName": "System.Id", "name": "ID"}] + (
        [] if n in missing else [{"referenceName": FIELD, "name": "Change Approver"}])} for n in names]
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workitemtypes")] = Resp(body={"value": types})
    return fake


def field_fake():
    """104: approved only by the field, filled 8 days ago; 105: filled, emptied, filled again; 106: emptied since."""
    fake = with_items(FakeADO(), {
        104: item(104, "Change Request", "Closed", **{FIELD: FRANK}),
        105: item(105, "Change Request", "Closed", **{FIELD: GRACE}),
        106: item(106, "Change Request", "Closed")},
        updates={104: [{"id": 1, "rev": 1, "revisedBy": who("alice@example.com"),
                        "fields": {"System.Title": {"newValue": "x"}}},
                       filled(2, ago(days=8), FRANK), update(3, "Proposed", "Closed", ago(days=1))],
                 105: [filled(1, ago(days=10), FRANK), filled(2, ago(days=9), None, old=FRANK),
                       filled(3, ago(days=6), FRANK), filled(4, ago(days=5), GRACE, old=FRANK)],
                 106: [filled(1, ago(days=10), FRANK), filled(2, ago(days=9), None, old=FRANK)]})
    return with_field_types(fake)


@pytest.mark.parametrize("source", [None, "field", "both"])
def test_the_approval_field_counts_by_approval_source(tmp_path, monkeypatch, source):
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    if source:
        monkeypatch.setenv(mod.APPROVAL_SOURCE_ENV, source)
    code, evidence, _, _, text = run(tmp_path, field_fake())
    assert code == 0
    by_field = work_item(evidence, 104)
    # Who it names now, from the first update that filled it; the rest of the identity isn't written.
    assert by_field["field_approval"] == {"at": iso_ago(days=8), "by": {"display_name": "Frank Approver",
                                          "login": "frank@example.com"}, "source": "field", "state": None}
    assert "aad.ZmFrZQ" not in text and GUID not in text
    # Emptied and filled again: the approval runs from the refill, and a change of person doesn't restart it.
    assert work_item(evidence, 105)["field_approval"]["at"] == iso_ago(days=6)
    assert work_item(evidence, 105)["field_approval"]["by"]["login"] == "grace@example.com"
    # Emptied since: no approval.
    assert work_item(evidence, 106)["field_approval"] is None
    s = evidence["summary"]
    assert s["approval_field"] == FIELD and s["approval_source"] == (source or "states_and_comments")
    assert evidence["results"]["selection"]["approval_field"] == FIELD
    if source is None:
        # Read and recorded, but only states and comments count, as before.
        assert by_field["approval"] is None and work_item(evidence, 101)["approval"]["source"] == "state"
        assert (s["change_items_approved"], s["change_items_approved_by_field"]) == (2, 0)
        assert s["finished_change_items_without_approval"] == [103, 104, 105, 106]
    elif source == "field":
        assert by_field["approval"] == by_field["field_approval"] and by_field["approval_route"] == "field"
        # The state approval of 101 and the comment approval of 102 no longer count.
        assert work_item(evidence, 101)["approval"] is None and work_item(evidence, 102)["approval"] is None
        assert (s["change_items_approved"], s["change_items_approved_by_field"]) == (2, 2)
        assert s["finished_change_items_without_approval"] == [101, 103, 106]
        assert s["finished_change_items_approved_percentage"] == 40
    else:
        assert by_field["approval"]["source"] == "field" and work_item(evidence, 101)["approval"]["source"] == "state"
        assert (s["change_items_approved"], s["change_items_approved_by_field"]) == (4, 2)
        assert s["finished_change_items_without_approval"] == [103, 106]


def test_with_both_the_earlier_approval_is_in_effect(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, "custom.changeapprover")
    monkeypatch.setenv(mod.APPROVAL_SOURCE_ENV, "both")
    fake = with_items(FakeADO(), {104: item(104, "Change Request", "Closed", **{FIELD: FRANK}),
                                  105: item(105, "Change Request", "Closed", **{FIELD: FRANK})},
                      updates={104: [update(1, "Proposed", "Approved", ago(days=9)), filled(2, ago(days=5), FRANK)],
                               105: [filled(1, ago(days=9), FRANK), update(2, "Proposed", "Approved", ago(days=5))]})
    _, evidence, _, _, _ = run(tmp_path, with_field_types(fake))
    assert work_item(evidence, 104)["approval"]["source"] == "state"
    # The reference name matches without regard to case.
    assert work_item(evidence, 105)["approval"] == {"at": iso_ago(days=9), "by": {
        "display_name": "Frank Approver", "login": "frank@example.com"}, "source": "field", "state": None}


def test_with_both_an_approval_of_unknown_time_comes_after_one_of_known_time(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    monkeypatch.setenv(mod.APPROVAL_SOURCE_ENV, "both")
    # The field is filled, but no update read shows it filled.
    fake = with_items(FakeADO(), {104: item(104, "Change Request", "Closed", **{FIELD: FRANK})},
                      updates={104: [update(1, "Proposed", "Approved", ago(days=5))]})
    _, evidence, _, _, _ = run(tmp_path, with_field_types(fake))
    assert work_item(evidence, 104)["field_approval"]["at"] is None
    assert work_item(evidence, 104)["approval"]["source"] == "state"


@pytest.mark.parametrize("before, approved_105, left_out", [
    (None, False, 0), ("states_and_comments", False, 0), ("both", True, 0), ("exclude", None, 4)])
def test_items_created_before_the_field_follow_approval_before_field(tmp_path, monkeypatch, before, approved_105,
                                                                     left_out):
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    monkeypatch.setenv(mod.APPROVAL_SOURCE_ENV, "field")
    monkeypatch.setenv(mod.APPROVAL_FIELD_FROM_ENV, (NOW - timedelta(days=30)).strftime("%Y-%m-%d"))
    if before:
        monkeypatch.setenv(mod.APPROVAL_BEFORE_FIELD_ENV, before)
    # 104 is new and approved by the field; 105 is old (created 50 days ago) and approved by the field since.
    fake = with_items(FakeADO(), {
        104: item(104, "Change Request", "Closed", **{FIELD: FRANK, "System.CreatedDate": ago(days=5)}),
        105: item(105, "Change Request", "Closed", **{FIELD: FRANK, "System.CreatedDate": ago(days=50)})},
        updates={104: [filled(1, ago(days=4), FRANK)], 105: [filled(1, ago(days=3), FRANK)]})
    code, evidence, _, _, _ = run(tmp_path, with_field_types(fake))
    assert code == 0
    old = work_item(evidence, 101)
    assert work_item(evidence, 104)["approval_route"] == "field" and work_item(evidence, 104)["approval"]
    assert old["approval_route"] == (before or "states_and_comments")
    s = evidence["summary"]
    assert s["approval_field_from"] == (NOW - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z")
    assert s["approval_before_field"] == (before or "states_and_comments")
    assert s["change_items_left_out_of_approval"] == left_out
    if before == "exclude":
        # 101, 102, 103 and 105 were created 40 or 50 days ago, so only 104 is judged.
        assert old["approval"] is None and work_item(evidence, 105)["approval"] is None
        assert s["finished_change_items_without_approval"] == [] and s["change_items_approved"] == 1
        assert (s["finished_change_items_needing_approval"], s["finished_change_items_approved_percentage"]) == (1, 100)
    else:
        # Old items keep their state and comment approvals.
        assert old["approval"]["source"] == "state" and work_item(evidence, 102)["approval"]["source"] == "comment"
        assert bool(work_item(evidence, 105)["approval"]) is approved_105
        assert s["finished_change_items_without_approval"] == ([103] if approved_105 else [103, 105])


def test_without_approval_field_from_every_item_follows_approval_source(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    monkeypatch.setenv(mod.APPROVAL_SOURCE_ENV, "field")
    _, evidence, _, _, _ = run(tmp_path, field_fake())
    s = evidence["summary"]
    assert s["approval_field_from"] is None and s["approval_before_field"] is None
    assert s["change_items_left_out_of_approval"] == 0 and work_item(evidence, 101)["approval_route"] == "field"


@pytest.mark.parametrize("emergency", [None, "emergency change", "none"])
def test_an_emergency_type_approved_after_its_change_is_listed_apart(tmp_path, monkeypatch, emergency):
    monkeypatch.setenv(mod.TYPES_ENV, "Change Request, Emergency Change")
    if emergency:
        monkeypatch.setenv(mod.EMERGENCY_TYPES_ENV, emergency)
    fake = with_items(FakeADO(), {104: item(104, "Emergency Change", "Closed", relations=[
        artifact("vstfs:///VersionControl/Changeset/503", "Fixed in Changeset")])},
        updates={104: [update(1, "Proposed", "Approved", ago(days=3))]})
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workitemtypes")] = Resp(body={
        "value": TYPES + [{"name": "Emergency Change", "states": TYPES[0]["states"]}]})
    fake.routes[("GET", "/contoso/_apis/tfvc/changesets/503")] = Resp(body={
        "changesetId": 503, "author": who("dave@example.com"), "checkedInBy": who("dave@example.com"),
        "createdDate": ago(days=6)})
    code, evidence, _, _, _ = run(tmp_path, fake)
    on = emergency == "emergency change"
    hot = work_item(evidence, 104)
    assert code == 0 and hot["changed_before_approval"] is True and hot["emergency_type"] is on
    assert work_item(evidence, 102)["emergency_type"] is False
    s = evidence["summary"]
    assert s["emergency_types"] == (["Emergency Change"] if on else [])
    assert evidence["results"]["selection"]["emergency_types"] == s["emergency_types"]
    assert s["change_items_changed_before_approval"] == ([102] if on else [102, 104])
    assert s["emergency_items_approved_after_change"] == ([104] if on else [])
    # Still a change item needing an approval.
    assert s["finished_change_items_needing_approval_approved"] == 2


def test_an_approval_type_without_the_field_is_named(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.TYPES_ENV, "Change Request, Bug")
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    _, evidence, _, _, _ = run(tmp_path, with_field_types(FakeADO(), missing=("Bug",)))
    assert evidence["summary"]["approval_field_types_missing"] == ["Bug"]
    assert evidence["results"]["projects"][0]["approval_field_types_missing"] == ["Bug"]
    monkeypatch.setenv(mod.APPROVAL_TYPES_ENV, "Change Request")
    _, evidence, _, _, _ = run(tmp_path, with_field_types(FakeADO(), missing=("Bug",)))
    assert evidence["summary"]["approval_field_types_missing"] == []


def test_the_field_check_is_unknown_without_the_setting_or_a_field_listing(tmp_path, monkeypatch):
    _, evidence, _, _, _ = run(tmp_path, with_field_types(FakeADO()))
    assert evidence["summary"]["approval_field_types_missing"] is None
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    # The default fake's type listing doesn't name fields.
    _, evidence, _, _, _ = run(tmp_path)
    assert evidence["summary"]["approval_field_types_missing"] is None


def test_a_field_approval_of_unknown_time_leaves_the_change_order_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    monkeypatch.setenv(mod.APPROVAL_SOURCE_ENV, "both")
    # Filled, but no update read shows it being filled.
    fake = with_items(FakeADO(), {104: item(104, "Change Request", "Closed", relations=[
        artifact("vstfs:///VersionControl/Changeset/501", "Fixed in Changeset")], **{FIELD: FRANK})})
    code, evidence, _, _, _ = run(tmp_path, with_field_types(fake))
    unknown = work_item(evidence, 104)
    assert code == 0 and unknown["approval"]["at"] is None and unknown["approval"]["source"] == "field"
    assert unknown["changed_before_approval"] is None and unknown["approved_by_change_author"] is False
    s = evidence["summary"]
    assert s["change_items_linked_changes_checked"] == 2
    assert s["change_items_changed_before_approval"] is None and s["emergency_items_approved_after_change"] is None


def test_unread_updates_leave_the_field_approval_figures_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.APPROVAL_FIELD_ENV, FIELD)
    monkeypatch.setenv(mod.APPROVAL_SOURCE_ENV, "field")
    fake = field_fake()
    fake.routes[("GET", f"/contoso/{P}/_apis/wit/workItems/104/updates")] = err(500, "boom")
    code, evidence, _, _, _ = run(tmp_path, fake)
    assert code == 1 and work_item(evidence, 104)["field_approval"]["at"] is None
    s = evidence["summary"]
    assert s["change_items_approved_by_field"] is None and s["finished_change_items_approved_percentage"] is None


@pytest.mark.parametrize("settings", [
    {mod.APPROVAL_SOURCE_ENV: "field"},
    {mod.APPROVAL_SOURCE_ENV: "both"},
    {mod.APPROVAL_SOURCE_ENV: "approvals", mod.APPROVAL_FIELD_ENV: FIELD},
    {mod.APPROVAL_FIELD_ENV: "Change Approver"},
    {mod.APPROVAL_FIELD_ENV: FIELD, mod.APPROVAL_SOURCE_ENV: "field", mod.APPROVAL_FIELD_FROM_ENV: "last week"},
    {mod.APPROVAL_FIELD_ENV: FIELD, mod.APPROVAL_FIELD_FROM_ENV: "2026-01-31"},
    {mod.APPROVAL_FIELD_ENV: FIELD, mod.APPROVAL_SOURCE_ENV: "field", mod.APPROVAL_BEFORE_FIELD_ENV: "skip"},
    {mod.APPROVAL_FIELD_ENV: FIELD, mod.APPROVAL_SOURCE_ENV: "field", mod.APPROVAL_BEFORE_FIELD_ENV: "exclude"},
    {mod.APPROVAL_FIELD_ENV: FIELD, mod.APPROVAL_SOURCE_ENV: "both", mod.APPROVAL_BEFORE_FIELD_ENV: "both"},
    {mod.EMERGENCY_TYPES_ENV: "Emergency Change"},
])
def test_bad_approval_field_settings_fail_with_bad_config(tmp_path, monkeypatch, settings):
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    code, _, status, fake, _ = run(tmp_path)
    assert code == 1 and status["code"] == "bad_config" and not any(p.endswith("/wiql") for _, p, _, _ in fake.calls)
    assert any(name in status["error"] for name in settings)


def test_by_default_no_field_is_read_and_approval_is_as_before(tmp_path):
    _, evidence, _, _, _ = run(tmp_path, field_fake())
    s = evidence["summary"]
    assert (s["approval_source"], s["approval_field"], s["approval_field_from"]) == ("states_and_comments", None, None)
    assert (s["approval_before_field"], s["emergency_types"], s["approval_field_types_missing"]) == (None, [], None)
    assert work_item(evidence, 104)["field_approval"] is None and work_item(evidence, 104)["approval"] is None
    assert work_item(evidence, 101)["approval_route"] == "states_and_comments"
    assert (s["change_items_approved"], s["change_items_approved_by_field"]) == (2, 0)
