"""azure_app_service_deployments, driven by fake WebSiteManagementClient and Activity Log clients: Kudu history,
deployment events, deployment source and slot drift, and that a failed read is unknown rather than "no deployments".
No SDK, no credentials, no network."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploys = _load("app_service_deployments")

SUB = "00000000-0000-0000-0000-000000000001"
SITES = f"/subscriptions/{SUB}/resourceGroups/rg-web/providers/Microsoft.Web/sites"
DENIED = Exception("(AuthorizationFailed) The client does not have authorization to perform action")
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
COMPLETE = {"days": 90, "complete": True}


class ResourceNotFoundError(Exception):
    pass


def at(day, hour=0):
    return datetime(2026, 10, day, hour, tzinfo=timezone.utc)


def site(name, kind="app", https_only=True, public="Enabled"):
    return ns(id=f"{SITES}/{name}", name=name, kind=kind, location="eastus", state="Running",
              https_only=https_only, client_cert_enabled=None, public_network_access=public)


def slot(app, name, **kwargs):
    s = site(f"{app}/{name}", **kwargs)
    s.id = f"{SITES}/{app}/slots/{name}"
    return s


def deployment(app, deployment_id, status=4, start=at(1), active=False, deployer="ZipDeploy", author="N/A"):
    return ns(id=f"{SITES}/{app}/deployments/{deployment_id}", name=f"{app}/{deployment_id}", status=status,
              active=active, author=author, deployer=deployer, message="Created via a push deployment",
              start_time=start, end_time=start)


def rule(priority, address, action="Allow", name="rule"):
    return ns(name=name, priority=priority, action=action, ip_address=address, subnet_mask=None,
              vnet_subnet_resource_id=None, tag="Default", headers=None)


def config(**overrides):
    base = dict(min_tls_version="1.2", scm_min_tls_version="1.2", min_tls_cipher_suite=None, ftps_state="FtpsOnly",
                http20_enabled=True, remote_debugging_enabled=None, linux_fx_version="", windows_fx_version=None,
                net_framework_version="v8.0", java_version=None, java_container=None, java_container_version=None,
                php_version="", python_version="", node_version="",
                ip_security_restrictions=[rule(100, "10.0.0.0/8", name="office"), rule(200, "192.168.0.0/16")],
                ip_security_restrictions_default_action="Deny", scm_ip_security_restrictions=[],
                scm_ip_security_restrictions_default_action=None, scm_ip_security_restrictions_use_main=True)
    return ns(**(base | overrides))


def per_site(values, default=None):
    """A web_apps call answering per app (or app/slot); an Exception value is raised."""
    def fn(resource_group_name, name, slot=None):
        assert resource_group_name == "rg-web"
        value = (values or {}).get(f"{name}/{slot}" if slot else name, default)
        if isinstance(value, Exception):
            raise value
        return value() if callable(value) else value
    return fn


def web_client(deployments=None, slot_deployments=None, sources=None, slots=None, configs=None, slot_configs=None):
    return ns(web_apps=ns(
        list=lambda: [site("web-a"), site("web-b"), site("func", kind="functionapp")],
        list_deployments=per_site(deployments if deployments is not None else {
            "web-a": [deployment("web-a", "c0ffee", active=True, start=at(3)),
                      deployment("web-a", "bad1", status=3, start=at(2))],
        }, []),
        list_deployments_slot=per_site(slot_deployments, []),
        get_source_control=per_site(sources, ns(repo_url=None, branch=None, is_manual_integration=None,
                                                is_git_hub_action=None, deployment_rollback_enabled=None)),
        get_source_control_slot=per_site({}, ResourceNotFoundError("(404) Not Found")),
        list_slots=per_site(slots if slots is not None else {"web-a": [slot("web-a", "staging"),
                                                                       slot("web-a", "qa", https_only=False)]}, []),
        get_configuration=per_site(configs or {"web-a": config()}),
        get_configuration_slot=per_site(slot_configs or {
            "web-a/staging": config(ip_security_restrictions=[rule(200, "192.168.0.0/16", name="b"),
                                                            rule(100, "10.0.0.0/8", name="a")]),
            "web-a/qa": config(min_tls_version="1.0", net_framework_version="v6.0", http20_enabled=None),
        }),
    ))


def event(operation, resource, status="Succeeded", caller="releaser@example.com", idtyp="user",
          correlation="corr-1", when=at(10)):
    return ns(operation_name=ns(value=operation), status=ns(value=status), caller=caller,
              claims={"idtyp": idtyp, "ipaddr": "203.0.113.7"} if idtyp else {"ipaddr": "203.0.113.7"},
              resource_id=f"{SITES}/{resource}", correlation_id=correlation, event_data_id=f"ev-{correlation}-{status}",
              event_timestamp=when)


SWAP = "Microsoft.Web/sites/slots/slotsSwap/action"
PUBLISH = "Microsoft.Web/sites/publishxml/action"
SLOT_PUBLISH = "Microsoft.Web/sites/slots/publishxml/action"

# One swap logs the caller's request (Started, Accepted, Succeeded) and the platform's own events.
DEFAULT_EVENTS = [
    event(SWAP, "web-a/slots/staging", "Started", when=at(10, 9)),
    event(SWAP, "web-a/slots/staging", "Accepted", when=at(10, 9)),
    event(SWAP, "web-a/slots/staging", "Succeeded", when=at(10, 9)),
    event(SWAP, "web-a/slots/staging", "Succeeded", caller="Microsoft.Web", idtyp=None, when=at(10, 10)),
    event(SWAP, "WEB-A/slots/Staging", "Failed", caller="Microsoft.Web", idtyp=None, correlation="corr-2", when=at(12)),
    event(SWAP, "web-a/slots/staging", "Started", caller="ci@example.com", idtyp="app", correlation="corr-2",
          when=at(12)),
    event(PUBLISH, "web-a", "Started", correlation="corr-3", when=at(11)),
    event(PUBLISH, "web-a", "Succeeded", correlation="corr-3", when=at(11)),
    event(SLOT_PUBLISH, "web-a/slots/qa", correlation="corr-4", when=at(13)),
    event("Microsoft.Web/sites/extensions/write", "web-b/extensions/MSDeploy", caller="pipeline-sp",
          idtyp="app", correlation="corr-5", when=at(14)),
    event("Microsoft.Web/sites/extensions/sessions/action", "web-a/extensions/daas/sessions/list",
          correlation="corr-6"),
    event("Microsoft.Web/sites/config/write", "web-a/config/web", correlation="corr-7"),
]


def activity_client(events=None, fail_after=None):
    seen = {}

    def listing(filter, select=None):
        seen["filter"], seen["select"] = filter, select
        for i, e in enumerate(DEFAULT_EVENTS if events is None else events):
            if fail_after is not None and i == fail_after:
                raise DENIED
            yield e

    return ns(activity_logs=ns(list=listing)), seen


def collect(monkeypatch, client, events=None):
    monkeypatch.setattr(deploys, "web_client", lambda *a: client)
    collector = deploys.Collector(logging.getLogger("test"))
    apps, excluded = deploys.collect_web_apps(SUB, object(), collector)
    deploys.attach_activity(apps, [deploys.project_event(e) for e in (DEFAULT_EVENTS if events is None else events)])
    return {a["name"]: a for a in apps}, excluded, collector


def summary_of(apps, window=COMPLETE):
    return deploys.summarize(list(apps.values()), 1, window)


# --- Kudu deployment records ---

def test_kudu_history_is_newest_first_with_counts_and_active(monkeypatch):
    apps, excluded, collector = collect(monkeypatch, web_client())
    assert collector.ok and excluded == 1
    history = apps["web-a"]["kudu_deployments"]
    assert history["count"] == 2
    assert history["by_status"] == {"Failed": 1, "Success": 1}
    assert history["latest"]["deployment_id"] == "c0ffee"
    assert history["active"]["deployment_id"] == "c0ffee"
    assert history["records"][1]["status"] == "Failed"
    assert apps["web-b"]["kudu_deployments"] == {"count": 0, "by_status": {}, "by_deployer": {}, "latest": None,
                                                 "active": None, "records": []}


def test_failed_kudu_read_is_unknown_not_empty(monkeypatch):
    apps, _, collector = collect(monkeypatch, web_client(deployments={"web-a": DENIED}), events=[])
    assert not collector.ok
    assert apps["web-a"]["kudu_deployments"] is None
    summary = summary_of(apps)
    assert summary["apps_kudu_deployment_records_unknown"] == 1
    assert summary["apps_without_kudu_deployment_records"] == 1
    assert summary["apps_without_deployment_evidence"] == 1
    assert deploys.classify_failure_code(collector.failures) == "not_authorized"


def test_slot_history_counts_toward_the_app(monkeypatch):
    client = web_client(deployments={}, slots={"web-b": [slot("web-b", "stage")]},
                        configs={"web-b": config()}, slot_configs={"web-b/stage": config()},
                        slot_deployments={"web-b/stage": [deployment("web-b", "s1", deployer="OneDeploy")]})
    apps, _, _ = collect(monkeypatch, client, events=[])
    summary = summary_of(apps)
    assert summary["apps_with_kudu_deployment_records"] == 1
    assert summary["apps_without_kudu_deployment_records"] == 1
    assert summary["kudu_deployments_by_deployer"] == {"OneDeploy": 1}
    assert summary["slots_matching_production"] == 1


def test_history_keeps_the_newest_records_and_the_full_count():
    many = [deploys.project_deployment(deployment("web-a", f"d{i:03}", start=at(1) + timedelta(minutes=i)))
            for i in range(120)]
    history = deploys.deployment_history(many)
    assert history["count"] == 120 and len(history["records"]) == deploys.HISTORY_LIMIT
    assert history["records"][0]["deployment_id"] == "d119"


def test_unknown_status_integer_is_kept():
    assert deploys.deployment_record({"status": 9})["status"] == "9"
    assert deploys.deployment_record({"status": None})["status"] is None


# --- Activity Log deployment events ---

def test_swap_is_one_record_with_the_requester_and_final_status(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client())
    staging = next(s for s in apps["web-a"]["slots"] if s["name"] == "staging")
    swaps = staging["activity"]["slot_swaps"]
    assert swaps["count"] == 2 and swaps["failed"] == 1
    assert swaps["latest"] == {"time": at(12).isoformat(), "status": "Failed", "caller": "ci@example.com",
                               "caller_type": "app", "correlation_id": "corr-2"}
    assert swaps["records"][1] == {"time": at(10, 9).isoformat(), "status": "Succeeded",
                                   "caller": "releaser@example.com", "caller_type": "user", "correlation_id": "corr-1"}


def test_publish_profile_downloads_land_on_the_app_or_slot(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client())
    assert apps["web-a"]["activity"]["publish_profile_downloads"]["count"] == 1
    assert apps["web-a"]["activity"]["slot_swaps"]["count"] == 0
    qa = next(s for s in apps["web-a"]["slots"] if s["name"] == "qa")
    assert qa["activity"]["publish_profile_downloads"]["latest"]["caller"] == "releaser@example.com"


def test_only_package_extension_writes_count_as_deployments(monkeypatch):
    other = event("Microsoft.Web/sites/extensions/write", "web-b/extensions/somethingelse", correlation="x")
    apps, _, _ = collect(monkeypatch, web_client(), events=DEFAULT_EVENTS + [other])
    assert apps["web-b"]["activity"]["package_deployments"]["count"] == 1
    assert apps["web-b"]["activity"]["package_deployments"]["latest"]["caller_type"] == "app"


def test_caller_types_count_every_request_not_just_the_kept_records(monkeypatch):
    swaps = [event("Microsoft.Web/sites/slots/slotsswap/action", "web-b/slots/staging", correlation=f"s{i}",
                   idtyp="app" if i % 2 else "user") for i in range(deploys.ACTIVITY_LIMIT + 10)]
    apps, _, _ = collect(monkeypatch, web_client(slots={"web-b": [slot("web-b", "staging")]}), events=swaps)
    staging = apps["web-b"]["slots"][0]["activity"]["slot_swaps"]
    assert len(staging["records"]) == deploys.ACTIVITY_LIMIT
    assert staging["by_caller_type"] == {"app": 55, "user": 55}
    assert summary_of(apps)["deployment_activity_by_caller_type"] == {"app": 55, "user": 55}


def test_swap_requested_on_production_counts_on_the_app(monkeypatch):
    prod = [event("Microsoft.Web/sites/slotsSwap/action", "web-a", status, correlation="p1", when=at(15))
            for status in ("Started", "Accepted", "Succeeded")]
    prod.append(event("Microsoft.Web/sites/slotsSwap/action", "web-a", caller="Microsoft.Web", idtyp=None,
                      correlation="p1", when=at(15, 1)))
    apps, _, _ = collect(monkeypatch, web_client(), events=prod)
    swaps = apps["web-a"]["activity"]["slot_swaps"]
    assert swaps["count"] == 1 and swaps["latest"]["caller"] == "releaser@example.com"
    assert all(s["activity"]["slot_swaps"]["count"] == 0 for s in apps["web-a"]["slots"])
    assert summary_of(apps)["slot_swaps"] == 1


def test_only_the_publishing_credentials_config_list_is_a_credentials_read(monkeypatch):
    listing = "Microsoft.Web/sites/config/list/action"
    events = [
        event(listing, "web-a/config/publishingcredentials", "Started", correlation="c1"),
        event(listing, "web-a/config/publishingcredentials", "Succeeded", correlation="c1"),
        event(listing, "web-a/config/appsettings", correlation="c2"),
        event("Microsoft.Web/sites/slots/config/list/action", "web-a/slots/qa/config/publishingcredentials",
              correlation="c3"),
    ]
    apps, _, _ = collect(monkeypatch, web_client(), events=events)
    assert apps["web-a"]["activity"]["publishing_credential_reads"]["count"] == 1
    qa = next(s for s in apps["web-a"]["slots"] if s["name"] == "qa")
    assert qa["activity"]["publishing_credential_reads"]["count"] == 1
    summary = summary_of(apps)
    assert summary["publishing_credential_reads"] == 2 and summary["apps_with_publishing_credential_reads"] == 1


def test_requests_on_unlisted_sites_are_counted_not_dropped(monkeypatch):
    monkeypatch.setattr(deploys, "web_client", lambda *a: web_client())
    collector = deploys.Collector(logging.getLogger("test"))
    apps, _ = deploys.collect_web_apps(SUB, object(), collector)
    events = DEFAULT_EVENTS + [event(SWAP, "func/slots/staging", correlation="f1"),
                               event(PUBLISH, "deleted-app", correlation="d1")]
    unlisted = deploys.attach_activity(apps, [deploys.project_event(e) for e in events])
    assert unlisted == {"slot_swaps": 1, "publish_profile_downloads": 1, "publishing_credential_reads": 0,
                        "package_deployments": 0}
    summary = deploys.summarize(apps, 1, {**COMPLETE, "requests_on_unlisted_sites": unlisted})
    assert summary["deployment_activity_on_unlisted_sites"] == 2
    assert summary["slot_swaps"] == 2


def test_diagnostics_and_config_writes_are_not_deployment_events(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client())
    counts = [c["count"] for s in [apps["web-a"], *apps["web-a"]["slots"]] for c in s["activity"].values()]
    assert sum(counts) == 4


def test_evidence_keeps_no_claims_beyond_the_identity_type(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client())
    assert "203.0.113.7" not in json.dumps(list(apps.values()), default=str)


def test_unread_activity_log_leaves_activity_null_and_evidence_unknown(monkeypatch):
    monkeypatch.setattr(deploys, "web_client", lambda *a: web_client(deployments={}))
    collector = deploys.Collector(logging.getLogger("test"))
    apps, _ = deploys.collect_web_apps(SUB, object(), collector)
    assert deploys.attach_activity(apps, None) is None
    assert all(a["activity"] is None for a in apps)
    summary = deploys.summarize(apps, 1, {"days": 90, "complete": False, "cut_reason": "read_failed"})
    assert summary["apps_without_kudu_deployment_records"] == 2
    assert summary["apps_without_deployment_evidence"] is None
    assert summary["activity_log_complete"] is False
    assert summary["slot_swaps"] is None and summary["deployment_activity_by_caller_type"] is None


def test_read_activity_log_sends_both_bounds_and_pages_to_the_end(monkeypatch):
    client, seen = activity_client()
    monkeypatch.setattr(deploys, "monitor_client", lambda *a: client)
    collector = deploys.Collector(logging.getLogger("test"))
    events, window = deploys.read_activity_log(SUB, object(), collector, 90, NOW)
    assert collector.ok and window["complete"] is True and window["cut_reason"] is None
    assert window["events_read"] == len(DEFAULT_EVENTS)
    assert "eventTimestamp ge '2026-08-01T12:05:00Z'" in seen["filter"]
    assert "eventTimestamp le '2026-10-30T12:00:00Z'" in seen["filter"]
    assert "resourceProvider eq 'Microsoft.Web'" in seen["filter"]
    assert len(events) == len(DEFAULT_EVENTS) - 2


def test_activity_log_read_failing_partway_is_unknown_not_partial(monkeypatch):
    client, _ = activity_client(fail_after=3)
    monkeypatch.setattr(deploys, "monitor_client", lambda *a: client)
    collector = deploys.Collector(logging.getLogger("test"))
    events, window = deploys.read_activity_log(SUB, object(), collector, 90, NOW)
    assert not collector.ok
    assert window["complete"] is False and window["cut_reason"] == "read_failed"
    assert window["events_read"] == 3 and events is None


def test_a_shorter_window_starts_exactly_that_many_days_back(monkeypatch):
    client, seen = activity_client(events=[])
    monkeypatch.setattr(deploys, "monitor_client", lambda *a: client)
    _, window = deploys.read_activity_log(SUB, object(), deploys.Collector(logging.getLogger("t")), 14, NOW)
    assert "eventTimestamp ge '2026-10-16T12:00:00Z'" in seen["filter"] and window["days"] == 14


def test_activity_log_cut_at_the_event_cap(monkeypatch):
    client, _ = activity_client()
    monkeypatch.setattr(deploys, "monitor_client", lambda *a: client)
    monkeypatch.setattr(deploys, "ACTIVITY_LOG_MAX_EVENTS", 2)
    events, window = deploys.read_activity_log(SUB, object(), deploys.Collector(logging.getLogger("t")), 90, NOW)
    assert window["complete"] is False and window["cut_reason"] == "max_events" and window["events_read"] == 2


def test_activity_log_days_is_clamped(monkeypatch):
    monkeypatch.setenv("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS", "365")
    assert deploys.activity_log_days() == 90
    monkeypatch.setenv("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS", "14")
    assert deploys.activity_log_days() == 14
    monkeypatch.setenv("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS", "0")
    assert deploys.activity_log_days() == 1


def test_non_integer_activity_log_days_falls_back_to_90(monkeypatch, caplog):
    monkeypatch.setenv("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS", "ninety")
    assert deploys.activity_log_days() == 90
    assert "not a whole number" in caplog.text


def test_window_cut_at_the_cap_keeps_counts_and_leaves_no_evidence_unknown(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client(deployments={}), events=[])
    summary = summary_of(apps, {"days": 90, "complete": False, "cut_reason": "max_events",
                                "requests_on_unlisted_sites": {c: 0 for c in deploys.ACTIVITY_CATEGORIES}})
    assert summary["slot_swaps"] == 0 and summary["deployment_activity_on_unlisted_sites"] == 0
    assert summary["activity_log_complete"] is False
    assert summary["apps_without_deployment_evidence"] is None


# --- deployment source and slot drift ---

def test_slot_matching_production_ignores_rule_order_and_names(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client())
    staging, qa = sorted(apps["web-a"]["slots"], key=lambda s: s["name"] != "staging")
    assert staging["matches_production"] is True and staging["configuration_differences"] == []
    assert qa["matches_production"] is False
    assert {d["field"]: (d["production"], d["slot"]) for d in qa["configuration_differences"]} == {
        "min_tls_version": ("1.2", "1.0"),
        "net_framework_version": ("v8.0", "v6.0"),
        "http20_enabled": (True, False),
        "https_only": (True, False),
    }


def test_slot_without_source_control_404_is_not_configured(monkeypatch):
    apps, _, collector = collect(monkeypatch, web_client())
    assert collector.ok
    assert apps["web-a"]["slots"][0]["source_control"]["configured"] is False


def test_source_control_credentials_are_stripped(monkeypatch):
    source = ns(repo_url="https://deploy:hunter2@git.example.com/team/app.git", branch="main",
                is_manual_integration=False, is_git_hub_action=True, deployment_rollback_enabled=None)
    apps, _, _ = collect(monkeypatch, web_client(sources={"web-b": source}))
    record = apps["web-b"]["source_control"]
    assert record["repo_url"] == "https://git.example.com/team/app.git"
    assert record["configured"] is True and record["is_git_hub_action"] is True
    assert "hunter2" not in json.dumps(list(apps.values()), default=str)


def test_failed_slot_config_read_leaves_comparison_unknown(monkeypatch):
    apps, _, collector = collect(monkeypatch, web_client(slot_configs={"web-a/staging": DENIED,
                                                                       "web-a/qa": config()}))
    assert not collector.ok
    by_name = {s["name"]: s for s in apps["web-a"]["slots"]}
    assert by_name["staging"]["matches_production"] is None
    assert by_name["staging"]["configuration_differences"] is None
    assert [d["field"] for d in by_name["qa"]["configuration_differences"]] == ["https_only"]


# --- summary and main ---

def test_summary_over_the_default_estate(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client())
    summary = summary_of(apps)
    assert summary["total_web_apps"] == 2 and summary["total_deployment_slots"] == 2
    assert summary["apps_with_slots"] == 1
    assert summary["kudu_deployment_records"] == 2 and summary["failed_kudu_deployment_records"] == 1
    assert summary["kudu_deployments_by_deployer"] == {"ZipDeploy": 2}
    assert summary["latest_kudu_deployment_time"] == at(3).isoformat()
    assert summary["apps_with_kudu_deployment_records"] == 1
    assert summary["slot_swaps"] == 2 and summary["failed_slot_swaps"] == 1 and summary["apps_with_slot_swaps"] == 1
    assert summary["latest_slot_swap_time"] == at(12).isoformat()
    assert summary["publish_profile_downloads"] == 2 and summary["apps_with_publish_profile_downloads"] == 1
    assert summary["package_deployments"] == 1 and summary["apps_with_package_deployments"] == 1
    assert summary["deployment_activity_by_caller_type"] == {"app": 2, "user": 3}
    assert summary["apps_with_deployment_evidence"] == 2 and summary["apps_without_deployment_evidence"] == 0
    assert summary["slots_matching_production"] == 1 and summary["slots_differing_from_production"] == 1
    assert summary["activity_log_complete"] is True and summary["activity_log_days"] == 90


def test_main_writes_window_and_limitations_and_exits_zero(monkeypatch, tmp_path):
    client, _ = activity_client()
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS", raising=False)
    monkeypatch.setattr(deploys, "resolve_subscription", lambda c: {"subscription_id": SUB, "subscription_source": "env"})
    monkeypatch.setattr(deploys, "credential", lambda: object())
    monkeypatch.setattr(deploys, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(deploys, "web_client", lambda *a: web_client())
    monkeypatch.setattr(deploys, "monitor_client", lambda *a: client)
    assert deploys.main() == 0
    [path] = tmp_path.glob("azure_app_service_deployments_*.json")
    evidence = json.loads(path.read_text())
    assert evidence["results"]["limitations"] == deploys.LIMITATIONS
    assert evidence["results"]["activity_log"]["complete"] is True
    assert evidence["summary"]["slot_swaps"] == 2


def test_source_control_read_failure_is_unknown_in_the_summary(monkeypatch):
    apps, _, collector = collect(monkeypatch, web_client(sources={"web-a": DENIED}), events=[])
    assert not collector.ok and apps["web-a"]["source_control"] is None
    summary = summary_of(apps)
    assert summary["apps_source_control_unknown"] == 1 and summary["apps_with_source_control"] == 0
    assert summary["slots_source_control_unknown"] == 0


def test_main_with_the_activity_log_denied_leaves_activity_unknown(monkeypatch, tmp_path):
    client, _ = activity_client(fail_after=0)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.delenv("AZURE_APP_SERVICE_ACTIVITY_LOG_DAYS", raising=False)
    monkeypatch.setattr(deploys, "resolve_subscription", lambda c: {"subscription_id": SUB, "subscription_source": "env"})
    monkeypatch.setattr(deploys, "credential", lambda: object())
    monkeypatch.setattr(deploys, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(deploys, "web_client", lambda *a: web_client(deployments={}))
    monkeypatch.setattr(deploys, "monitor_client", lambda *a: client)
    monkeypatch.setattr(deploys, "report_failure", lambda *a: None)
    assert deploys.main() == 1
    [path] = tmp_path.glob("azure_app_service_deployments_*.json")
    evidence = json.loads(path.read_text())
    window = evidence["results"]["activity_log"]
    assert window["cut_reason"] == "read_failed" and window["requests_on_unlisted_sites"] is None
    apps = evidence["results"]["web_apps"]
    assert all(s["activity"] is None for a in apps for s in [a, *a["slots"]])
    summary = evidence["summary"]
    assert summary["slot_swaps"] is None and summary["publish_profile_downloads"] is None
    assert summary["apps_without_deployment_evidence"] is None
    assert summary["apps_with_deployment_evidence"] == 0


# --- review fixes ---

# The $select properties the SDK documents for activity_logs.list; `caller` isn't one.
SELECTABLE = {"authorization", "claims", "correlationId", "description", "eventDataId", "eventName", "eventTimestamp",
              "httpRequest", "level", "operationId", "operationName", "properties", "resourceGroupName",
              "resourceProviderName", "resourceId", "status", "submissionTimestamp", "subStatus", "subscriptionId"}


def test_the_activity_log_read_asks_only_for_documented_properties(monkeypatch):
    client, seen = activity_client()
    monkeypatch.setattr(deploys, "monitor_client", lambda *a: client)
    events, _ = deploys.read_activity_log(SUB, object(), deploys.Collector(logging.getLogger("t")), 90, NOW)
    assert seen["select"] is None or set(seen["select"].split(",")) <= SELECTABLE
    assert events[0]["caller"] == "releaser@example.com"


def test_a_swap_logged_on_the_slot_and_production_counts_once_on_the_requesters_site(monkeypatch):
    events = [event(SWAP, "web-a/slots/staging", "Started", correlation="w1", when=at(16)),
              event(SWAP, "web-a/slots/staging", "Succeeded", correlation="w1", when=at(16, 1)),
              event("Microsoft.Web/sites/slotsSwap/action", "web-a", "Succeeded", idtyp=None, correlation="w1",
                    when=at(16, 1))]
    apps, _, _ = collect(monkeypatch, web_client(), events=events)
    staging = next(s for s in apps["web-a"]["slots"] if s["name"] == "staging")
    assert apps["web-a"]["activity"]["slot_swaps"]["count"] == 0
    assert staging["activity"]["slot_swaps"]["latest"] == {
        "time": at(16).isoformat(), "status": "Succeeded", "caller": "releaser@example.com", "caller_type": "user",
        "correlation_id": "w1"}
    assert summary_of(apps)["slot_swaps"] == 1


def test_a_callerless_failure_under_a_reused_correlation_id_does_not_flip_a_finished_request(monkeypatch):
    events = [event(SWAP, "web-a/slots/staging", "Started", correlation="r1"),
              event(SWAP, "web-a/slots/staging", "Succeeded", correlation="r1"),
              event(SWAP, "web-a/slots/staging", "Failed", caller=None, idtyp=None, correlation="r1"),
              event(PUBLISH, "web-a", "Succeeded", caller=None, idtyp=None, correlation="r2"),
              event(PUBLISH, "web-b", "Succeeded", caller=None, idtyp=None, correlation="r2")]
    apps, _, _ = collect(monkeypatch, web_client(), events=events)
    staging = next(s for s in apps["web-a"]["slots"] if s["name"] == "staging")
    swaps = staging["activity"]["slot_swaps"]
    assert (swaps["count"], swaps["failed"], swaps["latest"]["status"]) == (1, 0, "Succeeded")
    # Callerless rows alone stay with their own site rather than merging across sites.
    assert [apps[a]["activity"]["publish_profile_downloads"]["count"] for a in ("web-a", "web-b")] == [1, 1]


def test_kudu_author_and_message_are_capped_and_marked():
    long = "m" * 20_000
    record = deploys.deployment_record({"status": 4, "author": long, "message": long})
    for text in (record["author"], record["message"]):
        assert text.startswith("m" * deploys.MAX_TEXT) and len(text) < deploys.MAX_TEXT + 40 and "truncated" in text
    assert deploys.deployment_record({"author": "dev@example.com", "message": "fix"})["message"] == "fix"


def test_deployment_evidence_counts_add_up_to_the_apps(monkeypatch):
    apps, _, _ = collect(monkeypatch, web_client(deployments={"web-a": DENIED}), events=[])
    keys = ("apps_with_deployment_evidence", "apps_without_deployment_evidence", "apps_deployment_evidence_unknown")
    assert [summary_of(apps)[k] for k in keys] == [0, 1, 1]
    unread = summary_of(apps, {"days": 90, "complete": False, "cut_reason": "read_failed"})
    assert [unread[k] for k in keys] == [0, None, 2]


def test_source_control_url_tokens_are_stripped():
    assert deploys.redact_url("https://git.example.com/team/app.git?token=s3cret&ref=main") == (
        "https://git.example.com/team/app.git")
    assert deploys.redact_url("https://u:p@git.example.com/app.git?access_token=s3cret#x") == "https://git.example.com/app.git"
    assert deploys.redact_url("https://git.example.com/app.git") == "https://git.example.com/app.git"
