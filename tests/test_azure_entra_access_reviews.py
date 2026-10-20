"""azure_entra_access_reviews: schedule and auto-removal settings, last-cycle decisions, and the unlicensed and denied paths."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_access_reviews" / "fetcher.py"

spec = importlib.util.spec_from_file_location("azure_entra_access_reviews_under_test", FETCHER)
ar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ar)

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
GROUP_QUERY = "/groups/g-finance/transitiveMembers"


def _scope(query, odata="accessReviewQueryScope", **extra):
    return ns(odata_type=f"#microsoft.graph.{odata}", query=query, query_type="MicrosoftGraph", query_root=None, **extra)


def _definition(def_id, name, *, pattern="absoluteMonthly", interval=1, default_enabled=True, default="Deny",
                auto_apply=True, reviewers=("/users/u-owner",), query=GROUP_QUERY, status="InProgress",
                enumeration=None):
    recurrence = None if pattern is None else ns(
        pattern=ns(type=pattern, interval=interval),
        range=ns(type="noEnd", start_date="2026-01-01", end_date=None, number_of_occurrences=0),
    )
    return ar.project_definition(ns(
        id=def_id,
        display_name=name,
        status=status,
        created_date_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_modified_date_time=None,
        created_by=ns(user_principal_name="admin@contoso.test", display_name="Admin"),
        scope=_scope(query),
        instance_enumeration_scope=enumeration,
        reviewers=[_scope(r) for r in reviewers],
        fallback_reviewers=[],
        stage_settings=None,
        settings=ns(
            recurrence=recurrence,
            instance_duration_in_days=7,
            default_decision_enabled=default_enabled,
            default_decision=default,
            auto_apply_decisions_enabled=auto_apply,
            apply_actions=[ns(odata_type="#microsoft.graph.removeAccessApplyAction")],
            justification_required_on_approval=True,
            mail_notifications_enabled=True,
            reminder_notifications_enabled=True,
            recommendations_enabled=False,
        ),
    ))


def _instance(inst_id, status, end, start=None):
    return ar.project_instance(ns(
        id=inst_id, status=status, start_date_time=start or end - timedelta(days=7), end_date_time=end,
        scope=_scope(GROUP_QUERY),
    ))


def _decision(dec_id, decision, apply_result="AppliedSuccessfully"):
    return ar.project_decision(ns(
        id=dec_id, decision=decision, recommendation="Deny", justification=None,
        reviewed_by=ns(odata_type=None, id="r1", display_name="Reviewer", user_principal_name="r@contoso.test"),
        reviewed_date_time=NOW, apply_result=apply_result, applied_by=None, applied_date_time=NOW,
        principal=ns(odata_type="#microsoft.graph.userIdentity", id="u1", display_name="User One",
                     user_principal_name="u1@contoso.test"),
        resource=ns(id="g-finance", display_name="Finance", type="group"),
    ))


SEPT = datetime(2026, 9, 30, 17, 0, tzinfo=timezone.utc)
AUG = datetime(2026, 8, 31, 17, 0, tzinfo=timezone.utc)


def test_the_policy_is_monthly_default_deny_and_auto_apply():
    good = _definition("d-good", "Finance monthly")
    weekly = _definition("d-weekly", "Admins weekly", pattern="weekly")
    quarterly = _definition("d-quarterly", "Quarterly", interval=3)
    approve = _definition("d-approve", "Default approve", default="Approve")
    manual = _definition("d-manual", "Manual apply", auto_apply=False)
    one_time = _definition("d-once", "One time", pattern=None)
    ended = _definition("d-ended", "Old series", status="Completed", interval=3)
    defs = [good, weekly, quarterly, approve, manual, one_time, ended]
    results, summary = ar.build(defs, {d["id"]: [] for d in defs}, {}, [], NOW)

    by_id = {r["id"]: r for r in results["review_definitions"]}
    assert by_id["d-good"]["recurrence_period_days"] == 30
    assert by_id["d-good"]["monthly_auto_removal"] is True
    assert by_id["d-weekly"]["monthly_auto_removal"] is True
    assert by_id["d-quarterly"]["recurrence_period_days"] == 90
    assert by_id["d-quarterly"]["recurs_at_least_monthly"] is False
    assert by_id["d-approve"]["default_decision_deny"] is False
    assert by_id["d-manual"]["auto_applies_decisions"] is False
    assert by_id["d-once"]["recurring"] is False
    assert by_id["d-ended"]["active"] is False

    assert summary["collection_complete"] is True
    assert summary["review_definitions"] == 7
    assert summary["active_review_definitions"] == 6
    assert summary["active_definitions_recurring_at_least_monthly"] == 4
    assert summary["active_definitions_default_deny"] == 5
    assert summary["active_definitions_auto_applying"] == 5
    assert summary["active_definitions_monthly_auto_removal"] == 2
    assert summary["monthly_auto_removal_percentage"] == 33
    assert summary["active_definitions_without_monthly_auto_removal"] == [
        "Default approve", "Manual apply", "One time", "Quarterly",
    ]
    assert summary["all_active_definitions_monthly_auto_removal"] is False


def test_no_active_review_is_not_compliance():
    _, summary = ar.build([], {}, {}, [], NOW)
    assert summary["active_review_definitions"] == 0
    assert summary["monthly_auto_removal_percentage"] == 0
    assert summary["all_active_definitions_monthly_auto_removal"] is False
    assert summary["max_days_since_last_completed_cycle"] is None


def test_what_is_reviewed_is_read_from_the_scope():
    assert ar.scope_type(_definition("d", "g")) == "group_membership"
    assert ar.scope_type(_definition("d", "a", query="/servicePrincipals/sp-1/appRoleAssignedTo")) == "application"
    assert ar.scope_type(_definition(
        "d", "r", query="/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal")) == "entra_role"
    assert ar.scope_type(_definition(
        "d", "p", query="/identityGovernance/entitlementManagement/accessPackageAssignments")) == "access_package"
    assert ar.scope_type(_definition(
        "d", "m", query="./members", enumeration=_scope("/groups?$filter=(groupTypes/any(c:c+eq+'Unified'))"))) == "group_membership"
    assert ar.scope_type(_definition("d", "u", query="/users")) == "other"


def test_self_review_is_flagged():
    _, summary = ar.build([_definition("d-self", "Self review", reviewers=())], {"d-self": []}, {}, [], NOW)
    assert summary["active_self_review_definitions"] == ["Self review"]


def test_the_last_cycle_is_every_instance_that_ended_on_the_latest_day():
    instances = [
        _instance("i-aug", "Applied", AUG),
        _instance("i-sep-a", "Applied", SEPT),
        _instance("i-sep-b", "Completed", SEPT + timedelta(minutes=5)),
        _instance("i-oct", "InProgress", NOW + timedelta(days=5)),
    ]
    assert [i["id"] for i in ar.last_cycle(instances)] == ["i-sep-a", "i-sep-b"]
    assert ar.last_cycle([_instance("i-oct", "InProgress", NOW + timedelta(days=5))]) == []


def test_last_cycle_decisions_and_whether_denials_were_applied():
    definition = _definition("d-good", "Finance monthly")
    instances = {"d-good": [
        _instance("i-sep-a", "Applied", SEPT),
        _instance("i-sep-b", "Applied", SEPT),
        _instance("i-oct", "InProgress", NOW + timedelta(days=5)),
    ]}
    decisions = {
        "i-sep-a": [_decision("1", "Approve", "New"), _decision("2", "Deny")],
        "i-sep-b": [_decision("3", "Deny", "AppliedWithUnknownFailure"), _decision("4", "Deny",
                                                                              "AppliedSuccessfullyButObjectNotFound")],
    }
    results, summary = ar.build([definition], instances, decisions, [], NOW)
    (record,) = results["review_definitions"]

    assert record["instances_read"] == 3
    assert record["instances_in_progress"] == 1
    assert record["last_completed_cycle_end"] == "2026-09-30T17:00:00Z"
    assert record["days_since_last_completed_cycle"] == 19
    assert record["last_cycle"]["decisions"] == 4
    assert record["last_cycle_instances"][0]["decision_counts"]["decisions"] == 2

    assert summary["max_days_since_last_completed_cycle"] == 19
    assert summary["active_recurring_definitions_without_completed_cycle"] == []
    assert summary["last_cycle_decisions"] == 4
    assert summary["last_cycle_decisions_by_result"] == {"Approve": 1, "Deny": 3, "NotReviewed": 0, "DontKnow": 0}
    assert summary["last_cycle_denied_decisions_applied"] == 2
    assert summary["last_cycle_denied_decisions_not_applied"] == 1


def test_a_series_without_a_completed_cycle_is_listed():
    instances = {"d-new": [_instance("i-1", "InProgress", NOW + timedelta(days=3))]}
    _, summary = ar.build([_definition("d-new", "New series")], instances, {}, [], NOW)
    assert summary["active_recurring_definitions_without_completed_cycle"] == ["New series"]


def test_an_ended_series_decisions_are_not_read_and_read_as_unknown():
    definition = _definition("d-ended", "Old series", status="Completed")
    results, summary = ar.build([definition], {"d-ended": [_instance("i-1", "Applied", AUG)]}, {}, [], NOW)
    (record,) = results["review_definitions"]
    assert record["last_cycle"] is None
    assert record["last_cycle_instances"][0]["decision_counts"] is None
    assert summary["last_cycle_decisions"] == 0


def test_a_failed_read_gives_no_figures():
    definition = _definition("d-good", "Finance monthly")
    results, summary = ar.build([definition], {"d-good": None}, {}, [], NOW)
    assert summary == {"access_reviews_available": None, "collection_complete": False}
    assert results["access_reviews_available"] is None
    assert results["review_definitions"][0]["instances_read"] == 0

    _, summary = ar.build([definition], {"d-good": [_instance("i-1", "Applied", SEPT)]}, {"i-1": None}, [], NOW)
    assert summary == {"access_reviews_available": None, "collection_complete": False}

    results, summary = ar.build(None, {}, {}, [], NOW)
    assert summary == {"access_reviews_available": None, "collection_complete": False}
    assert results["review_definitions"] is None


class _Builder:
    def __init__(self, exc=None, items=()):
        self.exc, self.items = exc, list(items)

    async def get(self, request_configuration=None):
        if self.exc:
            raise self.exc
        return ns(value=self.items, odata_next_link=None)

    def with_url(self, url):
        return self


class _ODataError(Exception):
    """Stands in for msgraph's ODataError, whose str() is '<message> (status <code>)'."""


def _read(builder):
    collector, unlicensed = ar.Collector(logging.getLogger("test")), []
    items = asyncio.run(ar._read(collector, unlicensed, "graph.op", builder))
    return items, collector, unlicensed


def test_a_licence_refusal_is_a_state_not_a_failure():
    items, collector, unlicensed = _read(_Builder(_ODataError(
        "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license. (status 403)"
    )))
    assert collector.ok
    assert items is None
    assert len(unlicensed) == 1

    results, summary = ar.build(None, {}, {}, unlicensed, NOW)
    assert summary == {"access_reviews_available": False, "collection_complete": False}
    assert results["access_reviews_available"] is False
    assert results["notes"][1].startswith("graph.op:")


def test_a_graph_403_is_recorded_and_classified_not_authorized():
    items, collector, unlicensed = _read(_Builder(_ODataError(
        "Insufficient privileges to complete the operation. (status 403)"
    )))
    assert items is None
    assert unlicensed == []
    assert ar.classify_failure_code(collector.failures) == "not_authorized"


class _Definitions(_Builder):
    """definitions → by id → instances → by id → decisions, recording which were read."""

    def __init__(self, definitions, instances, decisions):
        super().__init__(items=definitions)
        self.instances, self.decisions, self.read = instances, decisions, []

    def by_access_review_schedule_definition_id(self, def_id):
        outer = self

        class _Instances(_Builder):
            def by_access_review_instance_id(self, inst_id):
                outer.read.append(inst_id)
                return ns(decisions=_Builder(items=outer.decisions.get(inst_id, [])))

        return ns(instances=_Instances(items=self.instances.get(def_id, [])))


def _raw_definition(def_id, status):
    return ns(id=def_id, display_name=def_id, status=status, scope=_scope(GROUP_QUERY), reviewers=[],
              settings=ns(recurrence=ns(pattern=ns(type="absoluteMonthly", interval=1), range=None)))


def _raw_instance(inst_id, status, end):
    return ns(id=inst_id, status=status, start_date_time=end - timedelta(days=7), end_date_time=end, scope=None)


def test_decisions_are_read_only_for_active_series_latest_cycle(monkeypatch):
    graph = _Definitions(
        [_raw_definition("d-active", "InProgress"), _raw_definition("d-ended", "Completed")],
        {
            "d-active": [_raw_instance("i-aug", "Applied", AUG), _raw_instance("i-sep", "Applied", SEPT)],
            "d-ended": [_raw_instance("i-old", "Applied", AUG)],
        },
        {"i-sep": [ns(id="x", decision="Deny", apply_result="AppliedSuccessfully")]},
    )
    client = ns(identity_governance=ns(access_reviews=ns(definitions=graph)))

    async def fake_with_graph_client(collector, cred, work, default=None):
        return await work(client)

    async def fake_tenant(collector, client):
        return {"tenant_id": "t-1", "tenant_source": "env"}

    monkeypatch.setattr(ar, "with_graph_client", fake_with_graph_client)
    monkeypatch.setattr(ar, "resolve_tenant", fake_tenant)
    collector = ar.Collector(logging.getLogger("test"))
    _, definitions, instances, decisions, unlicensed = asyncio.run(ar._collect(collector, object()))

    assert collector.ok
    assert graph.read == ["i-sep"]
    assert set(instances) == {"d-active", "d-ended"}
    assert decisions["i-sep"][0]["decision"] == "Deny"
    _, summary = ar.build(definitions, instances, decisions, unlicensed, NOW)
    assert summary["last_cycle_denied_decisions_applied"] == 1


def test_a_credential_failure_writes_null_figures_and_fails_the_run(tmp_path, monkeypatch):
    def no_credential():
        raise RuntimeError("DefaultAzureCredential failed to retrieve a token")

    monkeypatch.setattr(ar, "credential", no_credential)
    monkeypatch.setattr(ar, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_TENANT_ID", "t-1")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))

    assert ar.main() == 1
    evidence = json.loads((tmp_path / "azure_entra_access_reviews_t-1.json").read_text())
    assert evidence["summary"] == {"access_reviews_available": None, "collection_complete": False}
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "auth_failed"


def test_an_inactive_users_duration_renders_as_iso_days():
    scope = ar.project_query(_scope("/groups/g/members", "accessReviewInactiveUsersQueryScope",
                                    inactive_duration=timedelta(days=30)))
    assert scope["inactive_duration"] == "P30D"
    assert scope["type"] == "accessReviewInactiveUsersQueryScope"


def test_graph_unauthorized_text_classifies_by_its_status():
    failures = [{"operation": "graph.op", "type": "ODataError",
                 "message": "Attempted to perform an unauthorized operation. (status 403)"}]
    assert ar.classify_failure_code(failures) == "not_authorized"
