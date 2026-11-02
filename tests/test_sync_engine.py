"""Tests for the generic plan/apply engine (framework/sync).

The engine knows nothing about Paramify. These tests drive it with small fake
providers that record what they were asked to do and return fixed outcomes.
"""

from __future__ import annotations

import json
import subprocess
import sys
import typing
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest

from framework.sync import engine
from framework.sync.model import (
    UNKNOWN,
    Action,
    Outcome,
    Plan,
    Ref,
    SyncContext,
    Unknown,
    Verb,
    ensure_superset,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class FatalError(Exception):
    """Stands in for any exception that marks the whole run as unrecoverable."""

    fatal = True


class FakeProvider:
    """Records each apply call; returns or raises what the test scripted."""

    def __init__(
        self,
        name: str,
        runs_after: tuple[str, ...] = (),
        actions: Optional[List[Action]] = None,
        results: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.runs_after = runs_after
        self._actions = actions or []
        # action id -> Outcome-shaped dict, or an exception to raise
        self._results = results or {}
        self.applied: List[Action] = []
        self.calls: List[str] = []

    def desired(self, ctx: SyncContext) -> list:
        self.calls.append("desired")
        return [a.key for a in self._actions]

    def observe(self, desired: list, reader: Any) -> dict:
        self.calls.append("observe")
        return {"seen": reader}

    def diff(self, desired: list, observed: dict) -> List[Action]:
        self.calls.append("diff")
        return list(self._actions)

    def apply(self, action: Action, resources: Any, resolve: Callable[[Any], Any]) -> Outcome:
        self.applied.append(action)
        scripted = self._results.get(action.id, {"status": "applied", "result": {}})
        if isinstance(scripted, BaseException):
            raise scripted
        return Outcome(action_id=action.id, **scripted)


def _action(id: str, verb: Verb = "create", **kw: Any) -> Action:
    provider, _, key = id.partition("/")
    return Action(id=id, provider=provider, key=key, verb=verb, summary=f"{verb} {key}", **kw)


def _by_id(outcomes: List[Outcome]) -> Dict[str, Outcome]:
    return {o.action_id: o for o in outcomes}


# --- model -----------------------------------------------------------------


def test_no_delete_verb() -> None:
    assert not {"delete", "destroy", "remove"} & set(typing.get_args(Verb))


def test_unknown_is_a_falsy_singleton() -> None:
    assert Unknown() is UNKNOWN
    assert not UNKNOWN
    assert repr(UNKNOWN) == "unknown"


def test_action_defaults_are_not_shared() -> None:
    a, b = _action("p/a"), _action("p/b")
    a.changes["x"] = 1
    a.warnings.append("w")
    a.payload["y"] = 2
    assert b.changes == {} and b.warnings == [] and b.payload == {}
    assert a.on_failure == "continue" and a.fix is None


def test_plan_json_round_trip_with_ref_and_unknown() -> None:
    plan = Plan(
        actions=[
            _action("p/x", changes={"name": {"from": UNKNOWN, "to": "X"}}),
            _action(
                "q/y",
                verb="deliver",
                payload={
                    "evidence_id": Ref("p/x", "id"),
                    "files": [{"set": Ref("p/x", "id"), "seen": UNKNOWN}],
                },
                warnings=["late"],
                on_failure="stop",
            ),
            _action("q/z", verb="refuse", fix="add a request"),
        ]
    )
    data = plan.to_json()
    text = json.dumps(data)  # JSON-serialisable, nothing custom left in it
    assert '{"$ref": ["p/x", "id"]}' in text
    assert '{"$unknown": true}' in text
    back = Plan.from_json(json.loads(text))
    assert back.actions == plan.actions
    assert back.actions[1].payload["evidence_id"] == Ref("p/x", "id")
    assert back.actions[0].changes["name"]["from"] is UNKNOWN


def test_ensure_superset_rejects_removal() -> None:
    with pytest.raises(ValueError, match="p2"):
        ensure_superset({"p1", "p2"}, {"p1"})


def test_ensure_superset_allows_additions() -> None:
    ensure_superset({"p1"}, {"p1", "p2"})


def test_sync_context_defaults() -> None:
    a = SyncContext(run_dir=None, upload_cfg={})
    b = SyncContext(run_dir=None, upload_cfg={})
    a.options["p"] = {"force": True}
    assert b.options == {}
    assert a.stack_override is None and a.only_file is None


# --- order -----------------------------------------------------------------


def test_order_by_runs_after() -> None:
    a, b = FakeProvider("a"), FakeProvider("b", runs_after=("a",))
    assert [p.name for p in engine.order([b, a])] == ["a", "b"]


def test_order_keeps_input_order_when_independent() -> None:
    a, b, c = FakeProvider("a"), FakeProvider("b"), FakeProvider("c", runs_after=("a",))
    assert [p.name for p in engine.order([b, c, a])] == ["b", "a", "c"]


def test_order_rejects_a_cycle() -> None:
    a, b = FakeProvider("a", runs_after=("b",)), FakeProvider("b", runs_after=("a",))
    with pytest.raises(ValueError, match="cycle"):
        engine.order([a, b])


def test_order_ignores_absent_providers() -> None:
    a, b = FakeProvider("a"), FakeProvider("b", runs_after=("a", "z"))
    assert [p.name for p in engine.order([b, a])] == ["a", "b"]


# --- plan ------------------------------------------------------------------


def test_plan_collects_actions_in_provider_order() -> None:
    a = FakeProvider("a", actions=[_action("a/1"), _action("a/2")])
    b = FakeProvider("b", runs_after=("a",), actions=[_action("b/1")])
    ctx = SyncContext(run_dir=None, upload_cfg={})
    plan = engine.plan([b, a], ctx, reader="R")
    assert [x.id for x in plan.actions] == ["a/1", "a/2", "b/1"]
    assert a.calls == ["desired", "observe", "diff"]
    assert a.applied == [] and b.applied == []  # planning has no side effects


# --- apply -----------------------------------------------------------------


def test_ref_resolves_from_earlier_outcome() -> None:
    p = FakeProvider("p", results={"p/x": {"status": "applied", "result": {"id": "e1"}}})
    q = FakeProvider("q")
    plan = Plan(
        actions=[
            _action("p/x"),
            _action("q/y", verb="deliver", payload={"evidence_id": Ref("p/x", "id"),
                                                    "nested": [{"set": Ref("p/x", "id")}]}),
        ]
    )
    outcomes = engine.apply(plan, [p, q], resources=None)
    assert [o.status for o in outcomes] == ["applied", "applied"]
    seen = q.applied[0]
    assert seen.payload == {"evidence_id": "e1", "nested": [{"set": "e1"}]}
    # The plan itself still holds the Ref.
    assert plan.actions[1].payload["evidence_id"] == Ref("p/x", "id")


def test_ref_resolves_from_a_noop_outcome() -> None:
    p = FakeProvider("p", results={"p/x": {"status": "noop", "result": {"id": "e9"}}})
    q = FakeProvider("q")
    plan = Plan(actions=[_action("p/x", verb="noop"),
                         _action("q/y", payload={"id": Ref("p/x", "id")})])
    outcomes = engine.apply(plan, [p, q], resources=None)
    assert [o.status for o in outcomes] == ["noop", "applied"]
    assert p.applied[0].id == "p/x"  # noop still reaches the provider
    assert q.applied[0].payload == {"id": "e9"}


def test_failed_dependency_skips_dependent() -> None:
    p = FakeProvider("p", results={"p/x": RuntimeError("boom")})
    q = FakeProvider("q")
    plan = Plan(
        actions=[
            _action("p/x"),
            _action("q/y", payload={"id": Ref("p/x", "id")}),
            _action("q/z"),  # independent: still runs
        ]
    )
    outcomes = _by_id(engine.apply(plan, [p, q], resources=None))
    assert outcomes["p/x"].status == "failed"
    assert outcomes["p/x"].message == "boom"
    assert outcomes["q/y"].status == "skipped"
    assert outcomes["q/y"].message == "skipped: p/x did not complete"
    assert outcomes["q/z"].status == "applied"
    assert [a.id for a in q.applied] == ["q/z"]


def test_ref_to_an_action_that_never_ran_is_skipped() -> None:
    q = FakeProvider("q")
    plan = Plan(actions=[_action("q/y", payload={"id": Ref("p/missing", "id")})])
    [out] = engine.apply(plan, [q], resources=None)
    assert out.status == "skipped"
    assert out.message == "skipped: p/missing did not complete"
    assert q.applied == []


def test_ref_to_a_missing_result_field_fails_clearly() -> None:
    p = FakeProvider("p", results={"p/x": {"status": "applied", "result": {}}})
    q = FakeProvider("q")
    plan = Plan(actions=[_action("p/x"), _action("q/y", payload={"id": Ref("p/x", "id")})])
    outcomes = engine.apply(plan, [p, q], resources=None)
    assert outcomes[1].status == "failed"
    assert outcomes[1].message == "p/x has no result field 'id'"
    assert q.applied == []


def test_refuse_is_never_applied() -> None:
    q = FakeProvider("q")
    plan = Plan(actions=[_action("q/y", verb="refuse", fix="create a request first")])
    [out] = engine.apply(plan, [q], resources=None)
    assert out.status == "refused"
    assert out.message == "create a request first"
    assert q.applied == []


def test_unknown_provider_fails_the_action() -> None:
    plan = Plan(actions=[_action("nope/y"), _action("q/z")])
    q = FakeProvider("q")
    outcomes = _by_id(engine.apply(plan, [q], resources=None))
    assert outcomes["nope/y"].status == "failed"
    assert outcomes["nope/y"].message == "no provider named nope"
    assert outcomes["q/z"].status == "applied"


def test_fatal_stops_everything_after() -> None:
    p = FakeProvider("p", results={"p/2": FatalError("token rejected")})
    plan = Plan(actions=[_action("p/1"), _action("p/2"), _action("p/3"),
                         _action("p/4", verb="refuse", fix="x")])
    outcomes = engine.apply(plan, [p], resources=None)
    assert [o.action_id for o in outcomes] == ["p/1", "p/2", "p/3", "p/4"]
    assert [o.status for o in outcomes] == ["applied", "failed", "skipped", "skipped"]
    assert outcomes[1].message == "token rejected"
    assert outcomes[2].message == "stopped: token rejected"
    assert outcomes[3].message == "stopped: token rejected"
    assert [a.id for a in p.applied] == ["p/1", "p/2"]


def test_on_failure_stop_stops_everything_after() -> None:
    p = FakeProvider("p", results={"p/1": {"status": "failed", "message": "bad set"}})
    plan = Plan(actions=[_action("p/1", on_failure="stop"), _action("p/2")])
    outcomes = engine.apply(plan, [p], resources=None)
    assert [o.status for o in outcomes] == ["failed", "skipped"]
    assert outcomes[1].message == "stopped: bad set"
    assert [a.id for a in p.applied] == ["p/1"]


def test_on_failure_stop_also_applies_to_raised_errors() -> None:
    p = FakeProvider("p", results={"p/1": RuntimeError("nope")})
    plan = Plan(actions=[_action("p/1", on_failure="stop"), _action("p/2")])
    outcomes = engine.apply(plan, [p], resources=None)
    assert [o.status for o in outcomes] == ["failed", "skipped"]
    assert outcomes[1].message == "stopped: nope"


def test_on_failure_continue_does_not_stop() -> None:
    p = FakeProvider("p", results={"p/1": {"status": "failed", "message": "bad"}})
    plan = Plan(actions=[_action("p/1"), _action("p/2")])
    outcomes = engine.apply(plan, [p], resources=None)
    assert [o.status for o in outcomes] == ["failed", "applied"]


def test_resolve_callable_is_given_to_the_provider() -> None:
    seen: List[Any] = []

    class Resolving(FakeProvider):
        def apply(self, action: Action, resources: Any, resolve: Callable[[Any], Any]) -> Outcome:
            seen.append(resolve({"k": [Ref("p/x", "id")]}))
            seen.append(resources)
            return Outcome(action_id=action.id, status="applied")

    p = FakeProvider("p", results={"p/x": {"status": "applied", "result": {"id": "e1"}}})
    plan = Plan(actions=[_action("p/x"), _action("r/y")])
    engine.apply(plan, [p, Resolving("r")], resources="RES")
    assert seen == [{"k": ["e1"]}, "RES"]


def test_events_bracket_each_action() -> None:
    events: List[dict] = []
    p = FakeProvider("p", results={"p/2": FatalError("dead")})
    plan = Plan(actions=[_action("p/1"), _action("p/2"), _action("p/3")])
    engine.apply(plan, [p], resources=None, on_event=events.append)
    assert events == [
        {"event": "action_start", "action_id": "p/1"},
        {"event": "action_end", "action_id": "p/1", "status": "applied", "message": ""},
        {"event": "action_start", "action_id": "p/2"},
        {"event": "action_end", "action_id": "p/2", "status": "failed", "message": "dead"},
        {"event": "action_end", "action_id": "p/3", "status": "skipped",
         "message": "stopped: dead"},
    ]


# --- boundary --------------------------------------------------------------


def test_sync_imports_nothing_paramify_specific() -> None:
    out = subprocess.run(
        [sys.executable, "-c",
         "import framework.sync.engine, sys; print('framework.paramify' in sys.modules)"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "False"
