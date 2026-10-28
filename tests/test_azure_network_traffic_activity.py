"""azure_network_traffic_activity: flow summaries, Front Door requests, origin bypass, workspace reads. Synthetic, no network."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_network_traffic_activity_under_test",
                                               AZURE / "network_traffic_activity" / "fetcher.py")
nta = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nta)
azure_rest = sys.modules["azure_rest"]
Collector = sys.modules["azure_common"].Collector

SUB_ID = "00000000-0000-0000-0000-000000000001"
SUB = f"/subscriptions/{SUB_ID}"
RG = f"{SUB}/resourceGroups/rg1"
LAW = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law"
LAW2 = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law2"
WATCHER = f"{RG}/providers/Microsoft.Network/networkWatchers/nw"
NSG = f"{RG}/providers/Microsoft.Network/networkSecurityGroups/nsg1"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet1"
PROFILE = f"{RG}/providers/Microsoft.Cdn/profiles/fd1"
SITE = f"{RG}/providers/Microsoft.Web/sites/app1"


def logger():
    import logging
    return logging.getLogger("test")


def flow_log(target=NSG, enabled=True, ta=True, workspace=LAW):
    return {"id": f"{WATCHER}/flowLogs/fl-{target.rsplit('/', 1)[-1]}", "name": "fl",
            "properties": {"enabled": enabled, "targetResourceId": target,
                           "flowAnalyticsConfiguration": {"networkWatcherFlowAnalyticsConfiguration": {
                               "enabled": ta, "workspaceResourceId": workspace, "trafficAnalyticsInterval": 10}}}}


def setting(workspace=LAW, category=None, group=None, enabled=True):
    return {"name": "s", "properties": {"workspaceId": workspace,
                                        "logs": [{"category": category, "categoryGroup": group, "enabled": enabled}]}}


def day_row(day, period, flows=0, allowed=0, denied=0, direction="I", ftype="IntraVNet"):
    return {"Day": f"{day}T00:00:00Z", "Period": period, "Direction": direction, "FlowType": ftype,
            "Flows": flows, "Allowed": allowed, "Denied": denied}


# --- config and records ---

@pytest.mark.parametrize("raw, expected", [
    ("80,443", [80, 443]),
    ("443 80, 22", [22, 80, 443]),
    ("443,https,70000,0", [443]),
    ("", []),
])
def test_expected_ports(raw, expected):
    assert nta.expected_ports(raw) == expected


def test_lookback_is_clamped(monkeypatch):
    monkeypatch.setenv(nta.LOOKBACK_ENV, "90")
    assert nta.lookback_days() == nta.MAX_LOOKBACK_DAYS
    monkeypatch.setenv(nta.LOOKBACK_ENV, "3")
    assert nta.lookback_days() == 3


@pytest.mark.parametrize("target, kind, table", [
    (NSG, "network_security_group", nta.NSG_TABLE),
    (VNET, "virtual_network", nta.VNET_TABLE),
    (f"{VNET}/subnets/s1", "subnet", nta.VNET_TABLE),
    (f"{RG}/providers/Microsoft.Network/networkInterfaces/nic1", "network_interface", nta.VNET_TABLE),
])
def test_flow_log_record_picks_the_traffic_table(target, kind, table):
    record = nta.flow_log_record(flow_log(target))
    assert (record["target_type"], record["traffic_table"]) == (kind, table)
    assert record["traffic_analytics_enabled"] is True
    assert record["traffic_analytics_workspace_id"] == LAW


def test_traffic_analytics_on_a_disabled_flow_log_does_not_count():
    assert nta.flow_log_record(flow_log(enabled=False))["traffic_analytics_enabled"] is False
    assert nta.flow_log_record(flow_log(ta=False))["traffic_analytics_enabled"] is False


@pytest.mark.parametrize("settings, category, expected", [
    ([setting(category="FrontDoorAccessLog")], nta.FD_CATEGORY, [LAW]),
    ([setting(group="allLogs")], nta.FD_CATEGORY, [LAW]),
    ([setting(group="audit")], nta.FD_CATEGORY, []),
    ([setting(category="FrontDoorAccessLog", enabled=False)], nta.FD_CATEGORY, []),
    ([setting(workspace=None, category="FrontDoorAccessLog")], nta.FD_CATEGORY, []),
    ([setting(category="appservicehttplogs"), setting(workspace=LAW.upper(), group="allLogs")], nta.HTTP_CATEGORY, [LAW]),
    (None, nta.HTTP_CATEGORY, []),
])
def test_exporting_workspaces(settings, category, expected):
    assert nta.exporting_workspaces(settings, category) == expected


def test_tag_prefixes_split_by_version():
    tags = {"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["1.0.0.0/8"]}},
                       {"name": nta.FRONT_DOOR_TAG, "properties": {"addressPrefixes": ["147.243.0.0/16", "2a01:111:2050::/44", "bad"]}}]}
    assert nta.split_prefixes(nta.tag_prefixes(tags, nta.FRONT_DOOR_TAG)) == (["147.243.0.0/16"], ["2a01:111:2050::/44"])
    assert nta.tag_prefixes(tags, nta.PLATFORM_TAG) == []
    assert nta.tag_prefixes({}, nta.FRONT_DOOR_TAG) == []


def test_an_empty_range_list_reads_false():
    assert nta.range_test("ipv6_is_in_any_range", []) == "false"
    assert nta.range_test("ipv4_is_in_any_range", ["10.0.0.0/8"]) == 'ipv4_is_in_any_range(Ip, dynamic(["10.0.0.0/8"]))'


@pytest.mark.parametrize("exc, status", [
    (azure_rest.ArmError(403, "AuthorizationFailed", "no"), nta.WS_NOT_AUTHORIZED),
    (azure_rest.ArmError(404, "SubscriptionNotFound", "no"), nta.WS_NOT_AUTHORIZED),
    (azure_rest.ArmError(404, "ResourceNotFound", "403 in the message"), nta.WS_NOT_FOUND),
    (azure_rest.QueryError("(403) InsufficientAccessError", "no"), nta.WS_NOT_AUTHORIZED),
    (azure_rest.QueryError("(400) BadArgumentError", "forbidden"), nta.WS_ERROR),
    (RuntimeError("401"), nta.WS_ERROR),
])
def test_ws_status_goes_by_status_and_code(exc, status):
    assert nta.ws_status(exc) == status


@pytest.mark.parametrize("value, expected", [
    ("app.example.net", "app.example.net"),
    ("app.azurewebsites.net:443", "app.azurewebsites.net:443"),
    ("<script>", None),
    ("a b", None),
    (None, None),
])
def test_host_name(value, expected):
    assert nta.host_name(value) == expected


# --- traffic ---

def test_traffic_totals_spikes_and_internet_flows():
    daily = [
        day_row("2026-01-01", "prior", flows=100, allowed=0, denied=100),
        day_row("2026-01-08", "current", flows=50, allowed=50, denied=0),
        day_row("2026-01-09", "current", flows=400, allowed=0, denied=400),
        day_row("2026-01-09", "current", flows=10, allowed=10, ftype="ExternalPublic"),
        day_row("2026-01-09", "current", flows=3, allowed=2, denied=1, ftype="MaliciousFlow"),
        day_row("2026-01-09", "current", flows=5, allowed=5, direction="O", ftype="ExternalPublic"),
    ]
    t = nta.traffic_record([{"flow_daily": daily}], days=7, ports_expected=[443], spike_factor=3, sample=5)
    assert t["baseline_available"] is True
    assert (t["flows"], t["allowed_flows"], t["denied_flows"]) == (468, 67, 401)
    assert t["internet_inbound_allowed_flows"] == 12
    assert t["malicious_allowed_flows"] == 2
    assert t["baseline_daily_denied_flows"] == 100.0
    assert t["denied_spike_threshold"] == 300
    assert t["denied_spike_days"] == ["2026-01-09"]
    assert t["denied_flows_per_day"] == {"2026-01-08": 0, "2026-01-09": 401}


def test_a_quiet_baseline_uses_the_floor():
    daily = [day_row("2026-01-01", "prior", flows=1, denied=1), day_row("2026-01-09", "current", flows=250, denied=250)]
    t = nta.traffic_record([{"flow_daily": daily}], days=7, ports_expected=[], spike_factor=3, sample=5)
    assert t["denied_spike_threshold"] == 300
    assert t["denied_spike_days"] == []



def test_the_baseline_averages_only_prior_days_with_records():
    daily = [day_row("2026-01-01", "prior", flows=400, denied=400), day_row("2026-01-02", "prior", flows=200, denied=200),
             day_row("2026-01-09", "current", flows=800, denied=800)]
    t = nta.traffic_record([{"flow_daily": daily}], days=7, ports_expected=[], spike_factor=3, sample=5)
    assert t["baseline_daily_denied_flows"] == 300.0
    assert t["denied_spike_threshold"] == 900
    assert t["denied_spike_days"] == []

def test_without_a_baseline_new_counts_and_spikes_are_unknown():
    daily = [day_row("2026-01-09", "current", flows=900, denied=900)]
    ports = [{"Direction": "I", "Protocol": "T", "DestPort": 22, "Internet": True, "CurrentAllowed": 4,
              "PriorAllowed": 0, "Sources": 2}]
    dests = [{"FlowType": "ExternalPublic", "Destinations": 3, "NewDestinations": 3, "NewTop": "[]"}]
    t = nta.traffic_record([{"flow_daily": daily, "flow_ports": ports, "flow_destinations": dests}],
                           days=7, ports_expected=[443], spike_factor=3, sample=5)
    assert t["baseline_available"] is False
    assert t["denied_spike_days"] is None
    assert t["new_ports"] is None and t["new_ports_count"] is None
    assert t["new_outbound_destinations"] is None and t["new_outbound_destinations_top"] is None
    assert t["outbound_destinations"] == 3
    assert t["unexpected_inbound_ports"] == [22]


def test_ports_new_and_unexpected():
    daily = [day_row("2026-01-01", "prior", flows=1, allowed=1)]
    ports = [
        {"Direction": "I", "Protocol": "T", "DestPort": 443, "Internet": True, "CurrentAllowed": 90, "PriorAllowed": 80, "Sources": 9},
        {"Direction": "I", "Protocol": "T", "DestPort": 3389, "Internet": True, "CurrentAllowed": 2, "PriorAllowed": 0, "Sources": 1},
        {"Direction": "I", "Protocol": "T", "DestPort": 8080, "Internet": False, "CurrentAllowed": 5, "PriorAllowed": 0, "Sources": 1},
        {"Direction": "O", "Protocol": "U", "DestPort": 53, "Internet": False, "CurrentAllowed": 0, "PriorAllowed": 7, "Sources": 0},
    ]
    t = nta.traffic_record([{"flow_daily": daily, "flow_ports": ports}, {"flow_daily": [], "flow_ports": ports[:1]}],
                           days=7, ports_expected=[443], spike_factor=3, sample=5)
    assert t["allowed_ports"] == 3
    assert t["top_allowed_ports"][0] == {"direction": "I", "protocol": "T", "port": 443, "from_internet": True,
                                         "allowed_flows": 180, "distinct_sources": 18, "new": False}
    assert [p["port"] for p in t["new_ports"]] == [8080, 3389]
    assert t["unexpected_inbound_ports"] == [3389]
    assert t["unexpected_inbound_ports_count"] == 1


def test_new_destinations_parse_json_text_and_drop_non_addresses():
    daily = [day_row("2026-01-01", "prior", flows=1, allowed=1)]
    top = [{"destination": "203.0.113.9", "flows": 4, "first_seen": "2026-01-09T01:00:00Z"},
           {"destination": "<img src=x>", "flows": 99, "first_seen": None},
           {"destination": "198.51.100.7", "flows": 11, "first_seen": "2026-01-08T01:00:00Z"}]
    dests = [{"FlowType": "ExternalPublic", "Destinations": 40, "NewDestinations": 3, "NewTop": json.dumps(top)},
             {"FlowType": "AzurePublic", "Destinations": 10, "NewDestinations": 0, "NewTop": []}]
    t = nta.traffic_record([{"flow_daily": daily, "flow_destinations": dests}], days=7, ports_expected=[], spike_factor=3,
                           sample=5)
    assert t["outbound_destinations"] == 50
    assert t["new_outbound_destinations"] == 3
    assert t["new_outbound_destinations_by_flow_type"] == {"AzurePublic": 0, "ExternalPublic": 3}
    assert [d["destination"] for d in t["new_outbound_destinations_top"]] == ["198.51.100.7", "203.0.113.9"]


def test_top_flows_keep_addresses_only():
    rows = [{"Direction": "I", "FlowType": "ExternalPublic", "Src": "203.0.113.5", "Dest": "", "DestPort": 443,
             "Protocol": "T", "Flows": 10, "Allowed": 10, "Denied": 0, "LastSeen": "2026-01-09T00:00:00Z"},
            {"Direction": "O", "FlowType": "IntraVNet", "Src": "10.0.0.4", "Dest": "not-an-ip", "DestPort": 1433,
             "Protocol": "T", "Flows": 30, "Allowed": 30, "Denied": 0, "LastSeen": None}]
    top = nta.traffic_record([{"flow_top": rows}], days=7, ports_expected=[], spike_factor=3, sample=5)["top_flows"]
    assert [(f["source"], f["destination"], f["flows"]) for f in top] == [("10.0.0.4", None, 30), ("203.0.113.5", None, 10)]


# --- front door and origins ---

def fd_ws(status=nta.WS_QUERIED, read=(nta.FD_TABLE,), **rows):
    return {"status": status, "read_tables": list(read), **rows}


def test_profile_counts_come_from_the_fuller_copy():
    rid = PROFILE.lower()
    profile = {"id": PROFILE, "name": "fd1", "sku": {"name": "Premium_AzureFrontDoor"}}
    workspaces = {
        LAW.lower(): fd_ws(fd_profiles=[{"ResourceId": rid, "Requests": 10, "Status2xx": 9, "Status3xx": 0, "Status4xx": 0,
                                         "Status5xx": 1, "ClientIps": 4, "FirstRequest": "2026-01-02T00:00:00Z",
                                         "LastRequest": "2026-01-09T00:00:00Z"}]),
        LAW2.lower(): fd_ws(fd_profiles=[{"ResourceId": rid, "Requests": 3}],
                            fd_hosts=[{"ResourceId": rid, "Host": "x", "Requests": 3}]),
    }
    workspaces[LAW.lower()]["fd_hosts"] = [{"ResourceId": rid, "Host": "www.example.com", "Requests": 6, "Status5xx": 1},
                                           {"ResourceId": rid, "Host": "' or 1=1", "Requests": 4}]
    workspaces[LAW.lower()]["fd_clients"] = [{"ResourceId": rid, "ClientIp": "203.0.113.1", "Requests": 7},
                                             {"ResourceId": rid, "ClientIp": "junk", "Requests": 3}]
    rec = nta.profile_record(profile, [setting(category="FrontDoorAccessLog"), setting(workspace=LAW2, group="allLogs")],
                             [{}], workspaces, sample=5)
    assert rec["access_log_workspaces"] == [LAW, LAW2]
    assert rec["requests"] == 10
    assert rec["status_classes"] == {"2xx": 9, "3xx": 0, "4xx": 0, "5xx": 1}
    assert rec["first_request"] == "2026-01-02T00:00:00Z"
    assert rec["top_hosts"] == [{"name": "www.example.com", "requests": 6, "status_5xx": 1}]
    assert rec["top_clients"] == [{"client_ip": "203.0.113.1", "requests": 7}]
    assert rec["access_logs_arriving"] is True



def test_profile_lists_are_null_when_the_counts_failed():
    rid = PROFILE.lower()
    workspaces = {LAW.lower(): fd_ws(status=nta.WS_ERROR, read=(), fd_hosts=[{"ResourceId": rid, "Host": "www.example.com",
                                                                               "Requests": 6}],
                                     fd_clients=[{"ResourceId": rid, "ClientIp": "203.0.113.1", "Requests": 7}])}
    rec = nta.profile_record({"id": PROFILE, "name": "fd1"}, [setting(category="FrontDoorAccessLog")], [], workspaces, sample=5)
    assert rec["requests"] is None and rec["access_logs_arriving"] is None
    assert (rec["top_hosts"], rec["top_origins"], rec["top_clients"]) == (None, None, None)
    assert (rec["first_request"], rec["last_request"]) == (None, None)

@pytest.mark.parametrize("settings, workspaces, arriving, requests", [
    ([], {}, None, None),
    (None, {}, None, None),
    ([setting(category="FrontDoorAccessLog")], {LAW.lower(): fd_ws(fd_profiles=[])}, False, 0),
    ([setting(category="FrontDoorAccessLog")], {LAW.lower(): fd_ws(status=nta.WS_NOT_AUTHORIZED, read=())}, None, None),
    ([setting(category="FrontDoorAccessLog")], {LAW.lower(): fd_ws(status=nta.WS_NOT_FOUND, read=())}, False, 0),
])
def test_profile_without_readable_logs_reads_unknown(settings, workspaces, arriving, requests):
    rec = nta.profile_record({"id": PROFILE, "name": "fd1"}, settings, [], workspaces, sample=5)
    assert rec["access_logs_arriving"] is arriving
    assert rec["requests"] == requests


def test_match_origin_apps_by_host_and_by_resource():
    sites = [{"id": SITE, "name": "app1", "properties": {"enabledHostNames": ["app1.azurewebsites.net", "app1.scm.azurewebsites.net"]}},
             {"id": f"{SITE}2", "name": "app2", "properties": {"defaultHostName": "app2.azurewebsites.net"}}]
    origins = [{"profile": "fd1", "host_name": "APP1.azurewebsites.net", "azure_origin_id": None},
               {"profile": "fd2", "host_name": "custom.example.com", "azure_origin_id": f"{SITE}2".upper(), "private_link": True},
               {"profile": "fd1", "host_name": "storage.blob.core.windows.net", "azure_origin_id": None}]
    matched = nta.match_origin_apps(origins, sites)
    assert sorted(matched) == [SITE.lower(), f"{SITE}2".lower()]
    assert matched[SITE.lower()]["profiles"] == {"fd1"}
    assert matched[f"{SITE}2".lower()]["origins"] == ["custom.example.com"]
    assert nta.connection(matched[SITE.lower()]["private_link"]) == "public"
    assert nta.connection(matched[f"{SITE}2".lower()]["private_link"]) == "private_link"
    assert nta.connection({True, False}) == "mixed"


def app_entry():
    return {"site": {"id": SITE, "name": "app1", "properties": {"state": "Running"}},
            "origins": ["app1.azurewebsites.net"], "profiles": {"fd1"}, "private_link": {True}}


def test_origin_bypass_counts_public_requests():
    rid = SITE.lower()
    workspaces = {LAW.lower(): {"status": nta.WS_QUERIED, "read_tables": [nta.HTTP_TABLE],
                                "origin_sources": [
                                    {"ResourceId": rid, "Source": "front_door", "Requests": 900, "Served": 880, "ClientIps": 30},
                                    {"ResourceId": rid, "Source": "internal", "Requests": 20, "Served": 20, "ClientIps": 1},
                                    {"ResourceId": rid, "Source": "platform", "Requests": 40, "Served": 40, "ClientIps": 1},
                                    {"ResourceId": rid, "Source": "public", "Requests": 12, "Served": 2, "ClientIps": 3,
                                     "LastRequest": "2026-01-09T00:00:00Z"}],
                                "origin_public_clients": [{"ResourceId": rid, "Ip": "198.51.100.2", "Requests": 10, "Served": 2},
                                                          {"ResourceId": rid, "Ip": "x", "Requests": 2, "Served": 0}]}}
    rec = nta.origin_app_record(app_entry(), [setting(category="AppServiceHTTPLogs")], workspaces, True, sample=5)
    assert rec["requests_by_source"] == {"front_door": 900, "internal": 20, "platform": 40, "public": 12, "unknown": 0}
    assert rec["front_door_connection"] == "private_link"
    assert (rec["requests_outside_front_door"], rec["requests_outside_front_door_served"]) == (12, 2)
    assert rec["top_clients_outside_front_door"] == [{"client_ip": "198.51.100.2", "requests": 10, "served": 2}]
    assert rec["http_logs_arriving"] is True


@pytest.mark.parametrize("settings, ranges_known", [
    ([setting(category="AppServiceHTTPLogs")], False),
    ([], True),
    (None, True),
])
def test_origin_bypass_unknown_without_logs_or_ranges(settings, ranges_known):
    workspaces = {LAW.lower(): {"status": nta.WS_QUERIED, "read_tables": [nta.HTTP_TABLE], "origin_sources": []}}
    rec = nta.origin_app_record(app_entry(), settings, workspaces, ranges_known, sample=5)
    assert rec["requests_by_source"] is None
    assert rec["requests_outside_front_door"] is None
    assert rec["top_clients_outside_front_door"] is None and rec["last_request"] is None



def test_a_caller_that_is_not_an_address_is_unknown_not_public():
    assert "isnotnull(parse_ipv4(Ip)), 'public'" in nta._HTTP
    assert "isnotnull(parse_ipv6(Ip)), 'public', 'unknown')" in nta._HTTP
    unclassified = {"http_logs_exported": True, "front_door_connection": "public",
                    "requests_by_source": {"front_door": 5, "internal": 0, "platform": 0, "public": 0, "unknown": 2},
                    "requests_outside_front_door": 0, "requests_outside_front_door_served": 0}
    summary = nta.summarize([], nta.traffic_record([], 7, [], 3, 5), [], [], [unclassified], [], 7, [443])
    assert summary["origin_apps_bypass_unknown"] == 1

def test_summary_totals_are_null_when_any_app_is_unknown():
    known = {"http_logs_exported": True, "front_door_connection": "private_link", "requests_by_source": {},
             "requests_outside_front_door": 0, "requests_outside_front_door_served": 0}
    unknown = {"http_logs_exported": True, "front_door_connection": "public", "requests_by_source": None,
               "requests_outside_front_door": None, "requests_outside_front_door_served": None}
    summary = nta.summarize([], nta.traffic_record([], 7, [], 3, 5), [], [], [known, unknown], [], 7, [443])
    assert summary["origin_requests_outside_front_door"] is None
    assert summary["origin_apps_bypass_unknown"] == 1
    assert summary["origin_apps_private_link"] == 1
    assert summary["flows"] is None and summary["traffic_baseline_available"] is None


# --- workspace reads ---

class FakeClient:
    def __init__(self, tables=None, fail=None, arm=None, lists=None):
        self.tables = tables or {}
        self.fail = fail or {}
        self.arm = arm or {}
        self.lists = lists or {}
        self.queries, self.searches = [], []

    def get(self, path, api_version):
        if path in self.arm:
            value = self.arm[path]
            if isinstance(value, Exception):
                raise value
            return value
        if "/tables/" in path:
            name = path.rsplit("/", 1)[-1]
            if name not in self.tables:
                raise azure_rest.ArmError(404, "ResourceNotFound", "no table")
            return {"properties": {"plan": self.tables[name], "retentionInDays": 30}}
        if "/workspaces/" in path:
            return {"properties": {"customerId": "cid-" + path.rsplit("/", 1)[-1]}}
        raise AssertionError(f"unexpected GET {path}")

    def list(self, path, api_version, params=None):
        value = self.lists.get(path, [])
        if isinstance(value, Exception):
            raise value
        return value

    def _run(self, store, customer_id, kql, timespan):
        store.append((customer_id, kql, timespan))
        for marker, exc in self.fail.items():
            if marker in kql:
                raise exc
        return [{"kql": kql}]

    def query(self, customer_id, kql, timespan):
        return self._run(self.queries, customer_id, kql, timespan)

    def search(self, customer_id, kql, timespan):
        return self._run(self.searches, customer_id, kql, timespan)


def test_basic_tables_are_skipped_unless_opted_in():
    jobs = [(nta.NSG_TABLE, "a", f"{nta.NSG_TABLE} | count", 14), (nta.FD_TABLE, "b", "AzureDiagnostics | count", 7)]
    client = FakeClient(tables={nta.NSG_TABLE: "Basic", nta.FD_TABLE: "Analytics"})
    out = nta.read_workspace(client, LAW, jobs, False, Collector(logger()))
    assert out["skipped_tables"] == [nta.NSG_TABLE]
    assert out["read_tables"] == [nta.FD_TABLE]
    assert "a" not in out and len(client.queries) == 1 and client.queries[0][2] == "P7D"
    client = FakeClient(tables={nta.NSG_TABLE: "Basic", nta.FD_TABLE: "Analytics"})
    out = nta.read_workspace(client, LAW, jobs, True, Collector(logger()))
    assert out["skipped_tables"] == [] and out["read_tables"] == [nta.FD_TABLE, nta.NSG_TABLE]
    assert [s[2] for s in client.searches] == ["P14D"]


def test_missing_tables_read_as_no_records():
    jobs = [(nta.HTTP_TABLE, "h", f"{nta.HTTP_TABLE} | count", 7), (nta.FD_TABLE, "f", "AzureDiagnostics | count", 7)]
    client = FakeClient(tables={nta.FD_TABLE: "Analytics"},
                        fail={"AzureDiagnostics": azure_rest.QueryError("(400) BadArgumentError",
                                                                         "Failed to resolve table expression named 'AzureDiagnostics'")})
    collector = Collector(logger())
    out = nta.read_workspace(client, LAW, jobs, False, collector)
    assert out["h"] == [] and out["f"] == []
    assert out["read_tables"] == [nta.HTTP_TABLE, nta.FD_TABLE]
    assert collector.ok


def test_a_refused_query_leaves_the_workspace_unread_without_failing():
    jobs = [(nta.FD_TABLE, "f", "AzureDiagnostics | count", 7)]
    client = FakeClient(tables={nta.FD_TABLE: "Analytics"},
                        fail={"AzureDiagnostics": azure_rest.QueryError("(403) InsufficientAccessError", "denied")})
    collector = Collector(logger())
    out = nta.read_workspace(client, LAW, jobs, False, collector)
    assert out["status"] == nta.WS_NOT_AUTHORIZED and out["read_tables"] == []
    assert collector.ok


def test_another_query_failure_fails_the_run_but_keeps_other_tables():
    jobs = [(nta.FD_TABLE, "f", "AzureDiagnostics | count", 7), (nta.HTTP_TABLE, "h", f"{nta.HTTP_TABLE} | count", 7)]
    client = FakeClient(tables={nta.FD_TABLE: "Analytics", nta.HTTP_TABLE: "Analytics"},
                        fail={"AzureDiagnostics": azure_rest.QueryError("(400) BadArgumentError", "syntax")})
    collector = Collector(logger())
    out = nta.read_workspace(client, LAW, jobs, False, collector)
    assert out["status"] == nta.WS_ERROR and out["failed_queries"] == ["f"]
    assert out["read_tables"] == [nta.HTTP_TABLE]
    assert not collector.ok
    assert nta.flow_table_status(out, nta.HTTP_TABLE) == nta.WS_QUERIED


def test_a_refused_workspace_get_reads_not_authorized():
    client = FakeClient(arm={LAW: azure_rest.ArmError(403, "AuthorizationFailed", "no")})
    collector = Collector(logger())
    out = nta.read_workspace(client, LAW, [(nta.FD_TABLE, "f", "x", 7)], False, collector)
    assert out["status"] == nta.WS_NOT_AUTHORIZED and collector.ok


# --- collect ---

def _arm(**extra):
    base = {
        f"{SUB}/providers/Microsoft.Network/locations/eastus/serviceTags": {"values": [
            {"name": nta.FRONT_DOOR_TAG, "properties": {"addressPrefixes": ["147.243.0.0/16", "2a01:111:2050::/44"]}},
            {"name": nta.PLATFORM_TAG, "properties": {"addressPrefixes": ["203.0.113.0/24"]}}]},
    }
    base.update(extra)
    return base


def _lists():
    return {
        f"{SUB}/providers/Microsoft.Network/networkWatchers": [{"id": WATCHER, "name": "nw"}],
        f"{WATCHER}/flowLogs": [flow_log(NSG), flow_log(VNET, workspace=LAW2), flow_log(f"{VNET}2", ta=False)],
        f"{SUB}/providers/Microsoft.Cdn/profiles": [
            {"id": PROFILE, "name": "fd1", "sku": {"name": "Standard_AzureFrontDoor"}},
            {"id": f"{RG}/providers/Microsoft.Cdn/profiles/cdn", "name": "cdn", "sku": {"name": "Standard_Microsoft"}}],
        f"{PROFILE}/originGroups": [{"id": f"{PROFILE}/originGroups/og", "name": "og"}],
        f"{PROFILE}/originGroups/og/origins": [{"properties": {"hostName": "app1.azurewebsites.net",
                                                               "sharedPrivateLinkResource": {"groupId": "sites"}}}],
        f"{SUB}/providers/Microsoft.Web/sites": [{"id": SITE, "name": "app1", "location": "East US",
                                                  "properties": {"enabledHostNames": ["app1.azurewebsites.net"]}}],
        f"{PROFILE}/providers/Microsoft.Insights/diagnosticSettings": [setting(category="FrontDoorAccessLog")],
        f"{SITE}/providers/Microsoft.Insights/diagnosticSettings": [setting(group="allLogs")],
    }


def test_collect_wires_flows_front_door_and_origins(monkeypatch):
    monkeypatch.setenv(nta.LOOKBACK_ENV, "5")
    client = FakeClient(tables={nta.NSG_TABLE: "Analytics", nta.FD_TABLE: "Analytics", nta.HTTP_TABLE: "Analytics"},
                        arm=_arm(), lists=_lists())
    collector = Collector(logger())
    results, summary = nta.collect(client, SUB_ID, collector)
    assert collector.ok, collector.failures
    assert summary["flow_logs"] == 3 and summary["flow_logs_with_traffic_analytics"] == 2
    assert [(t["table"], t["status"]) for t in results["traffic_tables"]] == [
        (nta.NSG_TABLE, nta.WS_QUERIED), (nta.VNET_TABLE, "not_present")]
    assert summary["front_door_profiles"] == 1 and summary["origin_apps"] == 1
    assert results["front_door_backend_prefixes"] == 2 and results["app_service_platform_prefixes"] == 1
    assert results["origin_apps"][0]["front_door_connection"] == "private_link" and summary["origin_apps_private_link"] == 1
    kql = [q[1] for q in client.queries]
    flow_kql = [k for k in kql if k.startswith(nta.NSG_TABLE)]
    assert len(flow_kql) == len(nta.FLOW_QUERIES)
    assert all("ago(10d)" in k and "ago(5d)" in k and f"'{SUB_ID}'" in k for k in flow_kql)
    http_kql = [k for k in kql if k.startswith(nta.HTTP_TABLE)]
    assert len(http_kql) == 2 and all(f"'{SITE.lower()}'" in k and "147.243.0.0/16" in k and "2a01:111:2050::/44" in k
                                      and "203.0.113.0/24" in k for k in http_kql)
    for k in kql:
        assert not re.search(r"\{[a-z_0-9]+\}", k), k
    assert {q[2] for q in client.queries} == {"P10D", "P5D"}


def test_collect_skips_the_bypass_when_no_front_door_ranges(monkeypatch):
    arm = _arm(**{f"{SUB}/providers/Microsoft.Network/locations/eastus/serviceTags": {"values": []}})
    client = FakeClient(tables={nta.NSG_TABLE: "Analytics", nta.FD_TABLE: "Analytics", nta.HTTP_TABLE: "Analytics"},
                        arm=arm, lists=_lists())
    collector = Collector(logger())
    results, summary = nta.collect(client, SUB_ID, collector)
    assert not collector.ok
    assert not any(q[1].startswith(nta.HTTP_TABLE) for q in client.queries)
    assert summary["origin_apps_bypass_unknown"] == 1


def test_collect_treats_unregistered_providers_as_empty():
    unregistered = azure_rest.ArmError(409, "MissingSubscriptionRegistration", "not registered")
    lists = {f"{SUB}/providers/Microsoft.Network/networkWatchers": [],
             f"{SUB}/providers/Microsoft.Cdn/profiles": unregistered}
    collector = Collector(logger())
    results, summary = nta.collect(FakeClient(lists=lists), SUB_ID, collector)
    assert collector.ok
    assert summary["front_door_profiles"] == 0 and summary["flows"] is None
    assert results["workspaces"] == []


def test_filled_queries_have_no_stray_placeholders():
    fmt = {"days": 7, "span": 14, "subscription_id": SUB_ID, "sample": 10}
    for key, kql in nta.filled_queries(fmt).items():
        left = set(re.findall(r"\{([a-z_0-9]+)\}", kql))
        assert left <= {"app_ids", "fd_v4_test", "fd_v6_test", "platform_v4_test", "platform_v6_test"}, (key, left)
