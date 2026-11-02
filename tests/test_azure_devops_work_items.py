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
    assert spec_["name"] == mod.NAME and spec_["version"] == "0.1.0" and spec_["category"] == "azure"
    assert spec_["ksis"] == ["KSI-CMT-LMC", "KSI-PIY-RES"]
    assert spec_["evidence_set"]["reference_id"] == "EVD-AZURE-DEVOPS-WORK-ITEMS"
    config = spec_["config_schema"]
    assert {k: v["env"] for k, v in config.items()} == {
        "work_item_types": mod.TYPES_ENV, "work_item_tags": mod.TAGS_ENV, "lookback_days": mod.LOOKBACK_ENV,
        "approval_states": mod.APPROVAL_STATES_ENV, "approval_pattern": mod.APPROVAL_PATTERN_ENV}
    assert config["work_item_types"]["default"] == ",".join(mod.DEFAULT_TYPES)
    assert config["work_item_tags"]["default"] == ",".join(mod.DEFAULT_TAGS)
    assert config["lookback_days"]["default"] == mod.DEFAULT_LOOKBACK_DAYS
    assert config["approval_states"]["default"] == ",".join(mod.DEFAULT_APPROVAL_STATES)
    assert config["approval_pattern"]["default"] == mod.DEFAULT_APPROVAL_PATTERN
    assert spec_["secrets"][0]["env"] == "AZURE_DEVOPS_PAT" and spec_["secrets"][0]["required"] is False
    summary_fields = [line.split(" — ")[0].strip("- ").strip()
                      for line in spec_["evidence_set"]["instructions"].split("Summary fields:")[1].splitlines()
                      if line.startswith("- ")]
    assert summary_fields == list(mod.summarize([], [], True, mod.Selection([], [], [], mod.approval_pattern()), 1))


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
                                             (mod.TYPES_ENV, "none")])
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
