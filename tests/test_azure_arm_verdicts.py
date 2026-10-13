"""Azure Resource Manager verdict logic: change attribution and residual-resource records. Pure functions, no SDK or network."""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cp = _load("change_provenance")
rr = _load("residual_resources")
Collector = sys.modules["azure_common"].Collector

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-paramify-arm-sbx"
NSG_DEPLOYED = f"{RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-sbx-deployed"
NSG_DRIFT = f"{RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-sbx-drift"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet-sbx"
IDENTITY = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-sbx-orphan"
NIC = f"{RG}/providers/Microsoft.Network/networkInterfaces/nic-sbx-orphan"
OPERATOR = "operator@example.com"
PIPELINE_APP = "11111111-2222-3333-4444-555555555555"
BASELINE = "0e375d1a-59e7-4ee0-acaf-a10b01247cba"
RGS = "182b2a7e-01c8-44ea-85eb-45d28f6eba82"
REUSED = "b12a0b82-de60-490b-859d-14ce5bebd576"

_ids = iter(range(1, 10_000))


def change(target, when, *, by=OPERATOR, by_type="User", client="CLI", corr=None, kind="Update", table="resourcechanges"):
    return cp.change_record(
        {
            "changeId": f"c{next(_ids):04d}",
            "targetResourceId": target,
            "targetResourceType": target.split("/providers/")[-1].rsplit("/", 1)[0].lower() if "/providers/" in target else "microsoft.resources/subscriptions/resourcegroups",
            "changeType": kind,
            "timestamp": when,
            "changedBy": by,
            "changedByType": by_type,
            "clientType": client,
            "correlationId": corr,
            "changesCount": 1,
            "changedProperties": [],
        },
        table,
    )


def callerless(target, when, by="System", **kw):
    return change(target, when, by=by, by_type=by, client="Unspecified", **kw)


def deployment(name, corr, started, finished, outputs, scope="resource_group"):
    rid = f"{RG}/providers/Microsoft.Resources/deployments/{name}" if scope == "resource_group" else f"{SUB}/providers/Microsoft.Resources/deployments/{name}"
    return {
        "id": rid,
        "name": name,
        "scope": scope,
        "resource_group": "rg-paramify-arm-sbx" if scope == "resource_group" else None,
        "provisioning_state": "Succeeded",
        "started": started,
        "timestamp": finished,
        "duration": None,
        "correlation_id": corr,
        "mode": "Incremental",
        "template_hash": None,
        "template_link": None,
        "output_resource_ids": outputs,
    }


DEP_RGS = deployment("dep-sbx-rgs", RGS, "2026-10-12T20:53:48Z", "2026-10-12T20:53:52Z", [RG, f"{RG}-empty"], scope="subscription")
DEP_BASELINE = deployment("dep-sbx-baseline", BASELINE, "2026-10-12T20:54:24Z", "2026-10-12T20:54:32Z", [NSG_DEPLOYED, VNET])


def seeded():
    """The sandbox scenario as Resource Graph returned it, timestamps after drift included."""
    return [
        callerless(NSG_DEPLOYED, "2026-10-12T20:54:27.341Z", corr=REUSED, kind="Create"),
        change(NSG_DEPLOYED, "2026-10-12T20:54:32.238Z", corr=BASELINE),
        change(VNET, "2026-10-12T20:54:33.69Z", corr=BASELINE),
        change(NSG_DEPLOYED, "2026-10-12T20:55:02.243Z", corr="6c490306-f491-46f8-9b52-9892666c64f9"),
        callerless(NSG_DRIFT, "2026-10-12T20:55:02.248Z", corr=REUSED, kind="Create"),
        change(IDENTITY, "2026-10-12T20:55:11.01Z", corr="46b9da0f-9156-48ef-9a4f-55456ea25ac8", kind="Create"),
        change(IDENTITY, "2026-10-12T20:56:24.646Z", corr="79133486-ba50-4188-8364-74f69f72b338", kind="Delete"),
        change(RG, "2026-10-12T21:03:52.091Z", corr=RGS, kind="Create", table="resourcecontainerchanges"),
        change(f"{RG}-empty", "2026-10-12T21:03:52.201Z", corr=RGS, kind="Create", table="resourcecontainerchanges"),
        change(VNET, "2026-10-12T21:04:29.616Z", corr=BASELINE, kind="Create"),
        change(NSG_DRIFT, "2026-10-12T21:05:02.318Z", corr="04057bee-a598-43b0-956c-e3137bb17e47"),
        change(NIC, "2026-10-12T21:05:05.394Z", corr="1ccfc7de-e179-4bc4-bbaa-63f508fe69da", kind="Create"),
    ]


def by_target(attributed):
    return [((c["target_resource_id"].rsplit("/", 1)[-1]), c["change_type"], c["origin"], c["attribution"]) for c in attributed]


# --- attribute(): the seeded sandbox ----------------------------------------

def test_seeded_scenario_with_the_operator_as_pipeline_principal():
    out = cp.attribute(seeded(), [DEP_RGS, DEP_BASELINE], frozenset({OPERATOR}))
    assert by_target(out) == [
        ("nsg-sbx-deployed", "Create", "deployment", "same_resource"),
        ("nsg-sbx-deployed", "Update", "deployment", "correlation_id"),
        ("vnet-sbx", "Update", "deployment", "correlation_id"),
        ("nsg-sbx-deployed", "Update", "pipeline", None),
        # its named partner was restamped 10 minutes later, past the slack
        ("nsg-sbx-drift", "Create", "platform", None),
        ("id-sbx-orphan", "Create", "pipeline", None),
        ("id-sbx-orphan", "Delete", "pipeline", None),
        ("rg-paramify-arm-sbx", "Create", "deployment", "correlation_id"),
        ("rg-paramify-arm-sbx-empty", "Create", "deployment", "correlation_id"),
        ("vnet-sbx", "Create", "deployment", "correlation_id"),
        ("nsg-sbx-drift", "Update", "pipeline", None),
        ("nic-sbx-orphan", "Create", "pipeline", None),
    ]


def test_seeded_scenario_run_by_hand_is_manual_deployment_and_direct():
    out = cp.attribute(seeded(), [DEP_RGS, DEP_BASELINE])
    origins = [c["origin"] for c in out]
    assert origins.count("manual_deployment") == 6
    assert origins.count("direct") == 5
    assert origins.count("platform") == 1
    assert all(c["via_deployment"] for c in out if c["origin"] == "manual_deployment")
    summary = cp.summarize(out, [DEP_RGS, DEP_BASELINE], [])
    assert summary["percent_redeployed"] == 0
    assert summary["manual_deployment_changes_by_changed_by"] == {OPERATOR: 5, "System": 1}


# --- attribute(): one rule at a time ----------------------------------------

def test_deployment_run_by_an_application_is_a_redeployment():
    out = cp.attribute([change(VNET, "2026-10-12T20:54:30Z", by=PIPELINE_APP, by_type="Application", corr=BASELINE)], [DEP_BASELINE])
    assert (out[0]["origin"], out[0]["attribution"], out[0]["deployment_id"]) == ("deployment", "correlation_id", DEP_BASELINE["id"])


def test_portal_client_makes_a_deployment_manual():
    out = cp.attribute([change(VNET, "2026-10-12T20:54:30Z", by=PIPELINE_APP, by_type="Application", client="Azure Portal", corr=BASELINE)], [DEP_BASELINE])
    assert out[0]["origin"] == "manual_deployment"


@pytest.mark.parametrize("name", ["Microsoft.Web-WebApp-Portal-0a1b2c3d-4e5f", "Microsoft.Template-20261012120000", "CreateVm-MicrosoftWindowsServer-20261012"])
def test_portal_named_deployment_is_manual_even_for_an_application(name):
    dep = {**DEP_BASELINE, "name": name}
    out = cp.attribute([change(VNET, "2026-10-12T20:54:30Z", by=PIPELINE_APP, by_type="Application", corr=BASELINE)], [dep])
    assert out[0]["origin"] == "manual_deployment"


def test_pipeline_principal_overrides_portal_signals():
    out = cp.attribute(
        [change(VNET, "2026-10-12T20:54:30Z", by=PIPELINE_APP, by_type="Application", client="Azure Portal", corr=BASELINE)],
        [DEP_BASELINE],
        frozenset({PIPELINE_APP}),
    )
    assert out[0]["origin"] == "deployment"


def test_named_change_during_a_deployment_with_another_correlation_is_direct():
    out = cp.attribute([change(VNET, "2026-10-12T20:54:30Z", corr="other")], [DEP_BASELINE])
    assert (out[0]["origin"], out[0]["via_deployment"]) == ("direct", False)


def test_pipeline_principal_matches_case_insensitively():
    out = cp.attribute([change(NIC, "2026-10-12T21:00:00Z", by="Deployer@Example.com")], [], frozenset({"deployer@example.com"}))
    assert out[0]["origin"] == "pipeline"


def test_callerless_row_inherits_the_nearest_named_change_inside_the_slack():
    rows = [
        change(NIC, "2026-10-12T21:00:00Z", corr="a"),
        change(NIC, "2026-10-12T21:08:00Z", by=PIPELINE_APP, by_type="Application"),
        callerless(NIC, "2026-10-12T21:07:00Z", by="Unspecified", corr=REUSED),
    ]
    out = cp.attribute(rows, [], frozenset({PIPELINE_APP}))
    inherited = next(c for c in out if c["changed_by"] == "Unspecified")
    assert (inherited["origin"], inherited["attribution"]) == ("pipeline", "same_resource")


def test_callerless_row_ignores_named_changes_outside_the_slack():
    later = (datetime(2026, 10, 12, 21, 0, tzinfo=timezone.utc) + cp.WINDOW_SLACK + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = cp.attribute([change(NIC, later), callerless(NIC, "2026-10-12T21:00:00Z", by="Unspecified")], [])
    assert next(c for c in out if c["changed_by"] == "Unspecified")["origin"] == "unattributed"


def test_callerless_row_on_a_deployment_output_falls_back_to_the_deployment_window():
    app_run = {**DEP_BASELINE}
    out = cp.attribute([callerless(VNET, "2026-10-12T20:55:00Z", corr=REUSED)], [app_run])
    assert (out[0]["origin"], out[0]["attribution"], out[0]["deployment_id"]) == ("deployment", "deployment_window", DEP_BASELINE["id"])


def test_deployment_window_takes_the_origin_of_the_deployments_named_changes():
    rows = [change(NSG_DEPLOYED, "2026-10-12T20:54:31Z", corr=BASELINE), callerless(VNET, "2026-10-12T20:56:00Z")]
    out = cp.attribute(rows, [DEP_BASELINE])
    assert [(c["origin"], c["attribution"]) for c in out] == [("manual_deployment", "correlation_id"), ("manual_deployment", "deployment_window")]


def test_deployment_window_needs_the_change_inside_the_run_plus_slack():
    too_late = (datetime(2026, 10, 12, 20, 54, 32, tzinfo=timezone.utc) + cp.WINDOW_SLACK + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = cp.attribute([callerless(VNET, too_late)], [DEP_BASELINE])
    assert out[0]["origin"] == "platform"


@pytest.mark.parametrize("by, origin", [("System", "platform"), ("Unspecified", "unattributed")])
def test_callerless_row_with_nothing_to_inherit(by, origin):
    out = cp.attribute([callerless(NIC, "2026-10-12T21:00:00Z", by=by)], [])
    assert (out[0]["origin"], out[0]["attribution"], out[0]["via_deployment"]) == (origin, None, False)


def test_empty_caller_counts_as_callerless():
    out = cp.attribute([change(NIC, "2026-10-12T21:00:00Z", by="", by_type="", client="")], [])
    assert out[0]["origin"] == "unattributed"


# --- summarize() --------------------------------------------------------------

def _origins(*origins):
    return [{"origin": o, "attribution": None, "deployment_id": None, "changed_by": OPERATOR, "changed_by_type": "User",
             "client_type": "CLI", "target_resource_type": "t", "resource_group": "rg"} for o in origins]


def test_unattributed_changes_lower_only_the_conservative_percentage():
    summary = cp.summarize(_origins("deployment", "unattributed"), [], [])
    assert (summary["percent_redeployed"], summary["percent_redeployed_conservative"]) == (100, 50)


def test_manual_deployments_count_against_the_redeployed_percentage():
    summary = cp.summarize(_origins("deployment", "pipeline", "manual_deployment", "direct", "platform"), [], [])
    assert summary["percent_redeployed"] == 50
    assert summary["percent_redeployed_conservative"] == 50
    assert (summary["manual_deployment_changes"], summary["platform_changes"]) == (1, 1)


def test_summary_with_no_changes_is_zero_not_an_error():
    summary = cp.summarize([], [], [])
    assert (summary["percent_redeployed"], summary["percent_redeployed_conservative"], summary["total_changes"]) == (0, 0, 0)


def test_direct_changes_in_deleted_resource_groups():
    rows = _origins("direct", "direct", "deployment")
    rows[0]["resource_group"] = "Gone-RG"
    summary = cp.summarize(rows, [], [], {"rg"})
    assert summary["direct_changes_in_deleted_resource_groups"] == 1
    assert cp.summarize(rows, [], [], None)["direct_changes_in_deleted_resource_groups"] is None


def test_deployment_runs_records_who_ran_each_deployment():
    out = cp.attribute(seeded(), [DEP_RGS, DEP_BASELINE])
    runs = {d["name"]: d for d in cp.deployment_runs([DEP_RGS, DEP_BASELINE, deployment("dep-unused", "x", None, None, [])], out)}
    assert (runs["dep-sbx-baseline"]["origin"], runs["dep-sbx-baseline"]["run_by"]) == ("manual_deployment", [OPERATOR])
    assert (runs["dep-unused"]["origin"], runs["dep-unused"]["run_by"]) == (None, [])


@pytest.mark.parametrize("raw, days, warned", [("7", 7, False), ("30", 14, True), ("0", 1, True)])
def test_lookback_is_clamped_with_a_warning(monkeypatch, caplog, raw, days, warned):
    monkeypatch.setenv("AZURE_CHANGE_LOOKBACK_DAYS", raw)
    collector = Collector(logging.getLogger("test"))
    with caplog.at_level(logging.WARNING):
        assert cp.lookback_days(collector) == days
    assert ("outside 1-14" in caplog.text) is warned
    assert collector.ok


def test_parse_duration():
    assert cp.parse_duration("PT8.1234567S") == timedelta(seconds=8.1234567)
    assert cp.parse_duration("P1DT2H3M") == timedelta(days=1, hours=2, minutes=3)
    assert cp.parse_duration("P") is None and cp.parse_duration(None) is None


# --- residual_resources records -----------------------------------------------

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def slot(state, modified):
    return {"id": f"{RG}/providers/Microsoft.Web/sites/app/slots/staging", "name": "app/staging", "type": "microsoft.web/sites/slots",
            "resourceGroup": "rg", "location": "eastus", "tags": None, "state": state, "lastModified": modified}


@pytest.mark.parametrize("state, age_days, reasons", [
    ("Running", 10, None),
    ("Stopped", 10, ["not_running"]),
    ("Running", 91, ["not_modified_in_90_days"]),
    ("Stopped", 91, ["not_running", "not_modified_in_90_days"]),
    ("Running", None, None),
])
def test_slot_record(state, age_days, reasons):
    modified = (NOW - timedelta(days=age_days)).strftime("%Y-%m-%dT%H:%M:%S.1234567") if age_days is not None else ""
    record = rr.slot_record(slot(state, modified), 90, NOW)
    assert (record["stale_reasons"] if record else None) == reasons
    if record:
        assert (record["orphan_kind"], record["tags"]) == ("stale_deployment_slot", {})


@pytest.mark.parametrize("attached, roles, federated, unused", [
    (0, 0, 0, True),
    (1, 0, None, False),
    (0, 1, None, False),
    (0, 0, 1, False),
    # the federated-credential read failed: unknown is not unused
    (0, 0, None, False),
])
def test_identity_record(attached, roles, federated, unused):
    record = rr.identity_record({"id": IDENTITY, "name": "id", "principalId": "p", "clientId": "c"}, attached, roles, federated)
    assert (record["orphan_kind"] == "unused_identity") is unused
    assert record["federated_credentials"] == federated


ROLE = "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/ACDD72A7-3385-48EF-BD42-F606FBA81AE7"


def assignment(principal="P1", principal_type="User"):
    return {"id": "a1", "principalId": principal, "principalType": principal_type, "roleDefinitionId": ROLE, "scope": SUB, "createdOn": "2026-10-12T00:00:00Z"}


def test_assignment_record_when_graph_failed_is_unknown_not_deleted():
    record = rr.assignment_record(assignment(), {}, None)
    assert (record["principal_exists"], record["orphan_kind"]) == (None, None)


def test_assignment_record_deleted_and_present_principals():
    names = {"acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader"}
    gone = rr.assignment_record(assignment(), names, set())
    there = rr.assignment_record(assignment(), names, {"p1"})
    assert (gone["principal_exists"], gone["orphan_kind"], gone["role_name"]) == (False, "deleted_principal_assignment", "Reader")
    assert (there["principal_exists"], there["orphan_kind"]) == (True, None)


def test_foreign_group_is_never_flagged_as_deleted():
    record = rr.assignment_record(assignment(principal_type="ForeignGroup"), {}, set())
    assert (record["principal_exists"], record["orphan_kind"], record["foreign_principal"]) == (None, None, True)
    summary = rr.summarize([], [record], "complete", {})
    assert (summary["foreign_principal_assignments"], summary["deleted_principal_assignments"]) == (1, 0)


def test_empty_groups_compare_names_case_insensitively():
    groups = [{"id": f"{SUB}/resourceGroups/RG-A", "name": "RG-A", "resourceGroup": "RG-A"}, {"id": f"{SUB}/resourceGroups/rg-b", "name": "rg-b", "resourceGroup": "rg-b"}]
    assert [r["name"] for r in rr.empty_groups(groups, [{"id": "rg-a", "resources": 3}])] == ["rg-b"]


# --- residual_resources principal lookup --------------------------------------

class FakeGraph:
    def __init__(self, tenant, present=()):
        self.lookups = []

        async def org_get():
            return SimpleNamespace(value=[SimpleNamespace(id=tenant)])

        async def post(body):
            self.lookups.append(list(body.ids))
            return SimpleNamespace(value=[SimpleNamespace(id=i) for i in body.ids if i in present])

        self.organization = SimpleNamespace(get=org_get)
        self.directory_objects = SimpleNamespace(get_by_ids=SimpleNamespace(post=post))


def _with(graph):
    async def fake(collector, cred, work, default=None):
        return await work(graph)

    return fake


def test_principal_lookup_in_the_subscriptions_tenant(monkeypatch):
    graph = FakeGraph("TENANT-A", present={"p1"})
    monkeypatch.setattr(rr, "with_graph_client", _with(graph))
    collector = Collector(logging.getLogger("test"))
    assert asyncio.run(rr.existing_principals(collector, object(), ["p1", "p2"], "tenant-a")) == {"p1"}
    assert collector.ok and graph.lookups == [["p1", "p2"]]


def test_principal_lookup_refuses_another_tenant(monkeypatch):
    graph = FakeGraph("tenant-b")
    monkeypatch.setattr(rr, "with_graph_client", _with(graph))
    collector = Collector(logging.getLogger("test"))
    assert asyncio.run(rr.existing_principals(collector, object(), ["p1"], "tenant-a")) is None
    assert not collector.ok and "tenant-a" in collector.failures[0]["message"]
    assert graph.lookups == []
