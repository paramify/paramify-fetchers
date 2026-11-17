#!/usr/bin/env python3
"""Customer-facing availability: Application Insights availability tests and their results, and Standard load balancers' data-path and health-probe availability."""

import html
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import Collector, arm_id_key, resource_group_from_id  # noqa: E402
from azure_rest import bounded_int_config, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_endpoint_availability"
logger = logging.getLogger(NAME)

WEBTESTS_API = "2022-06-15"
NETWORK_API = "2023-09-01"
METRICS_API = "2023-10-01"
AVAILABILITY_METRIC = "availabilityResults/availabilityPercentage"
DATA_PATH_METRIC = "VipAvailability"
HEALTH_PROBE_METRIC = "DipAvailability"

LOOKBACK_ENV = "AZURE_ENDPOINT_AVAILABILITY_LOOKBACK_DAYS"
TARGET_ENV = "AZURE_AVAILABILITY_TARGET_PERCENTAGE"
DEFAULT_LOOKBACK_DAYS = 7
MAX_LOOKBACK_DAYS = 30

READ, ERROR, NOT_APPLICABLE = "read", "error", "not_applicable"
LB_METRICS = ("data_path", "health_probe")


# --- pure transforms ---

def component_of(tags: Optional[Dict[str, str]]) -> Optional[str]:
    """The Application Insights component a web test reports to, from its hidden-link tag."""
    for key, value in (tags or {}).items():
        if key.lower().startswith("hidden-link:") and (value or "").lower() == "resource":
            return key.split(":", 1)[1]
    return None


def validation(props: Dict[str, Any]) -> Dict[str, Optional[bool]]:
    """What a test checks beyond reachability: standard tests carry ValidationRules; classic ping tests carry rules in their XML."""
    rules = props.get("ValidationRules")
    if isinstance(rules, dict):
        content = ((rules.get("ContentValidation") or {}).get("ContentMatch") or "").strip()
        return {"checks_status_code": bool(rules.get("ExpectedHttpStatusCode")), "checks_content": bool(content),
                "checks_ssl": bool(rules.get("SSLCheck"))}
    xml = ((props.get("Configuration") or {}).get("WebTest") or "")
    if xml:
        return {"checks_status_code": bool(re.search(r'ExpectedHttpStatusCode="[1-9]', xml)),
                "checks_content": "ValidationRuleFindText" in xml and bool(re.search(r'Name="FindText" Value="[^"]+"', xml)),
                "checks_ssl": False}
    return {"checks_status_code": False, "checks_content": False, "checks_ssl": False}


def classic_url(props: Dict[str, Any]) -> Optional[str]:
    """A classic URL ping test keeps its URL in the Url attribute of the Request element of its WebTest XML."""
    xml = ((props.get("Configuration") or {}).get("WebTest") or "")
    found = re.search(r'<Request\b[^>]*\bUrl="([^"]+)"', xml)
    return html.unescape(found.group(1)) if found else None


def test_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    request = props.get("Request") or {}
    return {**validation(props),
        "id": raw.get("id"),
        "name": raw.get("name"),
        "test_name": props.get("Name") or raw.get("name"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "kind": (props.get("Kind") or raw.get("kind") or "").lower() or None,
        "enabled": bool(props.get("Enabled")),
        "url": request.get("RequestUrl") or classic_url(props),
        "frequency_seconds": props.get("Frequency"),
        "locations": len(props.get("Locations") or []),
        "component_id": component_of(raw.get("tags")),
    }


def load_balancer_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    frontends = props.get("frontendIPConfigurations") or []
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "sku": (raw.get("sku") or {}).get("name"),
        "standard": ((raw.get("sku") or {}).get("name") or "").lower() == "standard",
        "public": any((f.get("properties") or {}).get("publicIPAddress") for f in frontends),
        "frontends": len(frontends),
        # Data-path availability is measured on load-balancing rules and health-probe status on probes: a load balancer
        # without them (an outbound-only one, say) reports no data for that metric, which is not a gap in measurement.
        "load_balancing_rules": len(props.get("loadBalancingRules") or []),
        "inbound_nat_rules": len(props.get("inboundNatRules") or []),
        "probes": len(props.get("probes") or []),
    }


def hourly_points(metrics: List[Dict[str, Any]], name: str) -> List[Tuple[str, float]]:
    """(time, average) for every hour with data, across the metric's series."""
    points: Dict[str, List[float]] = {}
    for metric in metrics or []:
        if ((metric.get("name") or {}).get("value") or "").lower() != name.lower():
            continue
        for series in metric.get("timeseries") or []:
            for p in series.get("data") or []:
                if p.get("average") is not None:
                    points.setdefault(p.get("timeStamp"), []).append(float(p["average"]))
    return [(t, sum(v) / len(v)) for t, v in sorted(points.items())]


def judged(points: List[Tuple[str, float]], status: str, target: Optional[float], hours_expected: int = 0) -> Dict[str, Any]:
    """Average over the hours with data, lowest and latest hour, and coverage of the window. Below target is null (unknown)
    unless every hour of the window was measured and a target is set, so a few good hours never stand for a whole window."""
    has = status == READ and bool(points)
    values = [v for _, v in points]
    average = round(sum(values) / len(values), 3) if has else None
    measured = len(points) if status == READ else None
    complete = status == READ and hours_expected > 0 and measured >= hours_expected
    return {"metric_status": status, "hours_expected": hours_expected if status == READ else None, "hours_with_data": measured,
            "hours_missing": max(hours_expected - measured, 0) if status == READ else None,
            "measurement_coverage_percentage": round(100 * min(measured, hours_expected) / hours_expected, 1) if status == READ and hours_expected else None,
            "measurement_complete": complete if status == READ else None,
            "availability_percentage": average, "lowest_hour_percentage": round(min(values), 3) if has else None,
            "latest_hour_percentage": round(values[-1], 3) if has else None,
            "below_target": (average < target) if complete and average is not None and target is not None else None}


def _lowest(values: List[Optional[float]]) -> Optional[float]:
    known = [v for v in values if v is not None]
    return min(known) if known else None


def summarize(tests: List[Dict[str, Any]], balancers: List[Dict[str, Any]], settings: Dict[str, Any],
              tests_listed: bool = True, balancers_listed: bool = True) -> Dict[str, Any]:
    enabled = [t for t in tests if t["enabled"]]
    tests_complete = tests_listed and all(t["metric_status"] == READ for t in enabled)
    standard = [b for b in balancers if b["standard"]]
    lb_complete = balancers_listed and all(b[k]["metric_status"] in (READ, NOT_APPLICABLE) for b in standard for k in LB_METRICS)
    target = settings["target"]

    def t_known(value):
        return value if tests_complete else None

    def applicable(b):
        return [b[k] for k in LB_METRICS if b[k]["metric_status"] != NOT_APPLICABLE]

    # Each test or load balancer is judged against the target only once every hour of the lookback was measured. The
    # below-target counts are over the items that could be judged, and the rest are counted as not judged, so one new
    # or unread item never leaves the verdict on the others unknown.
    tests_judged = [t for t in enabled if t["below_target"] is not None]
    lbs_judged = [b for b in standard if applicable(b) and all(m["below_target"] is not None for m in applicable(b))]

    def t_target(value):
        return value if tests_listed and target is not None else None

    def lb_target(value):
        return value if balancers_listed and target is not None else None

    def _coverage(items):
        known = [c for c in items if c is not None]
        return min(known) if known else None

    def lb_known(value):
        return value if lb_complete else None

    return {
        "availability_tests_enabled": len(enabled) if tests_listed else None,
        "availability_tests_results_unread": sum(1 for t in enabled if t["metric_status"] == ERROR) if tests_listed else None,
        "endpoints_tested": len({t["url"] for t in enabled if t["url"]}) if tests_listed else None,
        "availability_tests_checking_application": sum(1 for t in enabled if t["checks_status_code"] and t["checks_content"]) if tests_listed else None,
        "availability_tests_reachability_only": sum(1 for t in enabled if not (t["checks_status_code"] and t["checks_content"])) if tests_listed else None,
        "availability_tests_with_missing_measurements": t_known(sum(1 for t in enabled if not t["measurement_complete"])),
        "lowest_measurement_coverage_percentage": t_known(_coverage([t["measurement_coverage_percentage"] for t in enabled])),
        "availability_tests_without_data": t_known(sum(1 for t in enabled if t["availability_percentage"] is None)),
        "lowest_availability_percentage": t_known(_lowest([t["availability_percentage"] for t in enabled])),
        "availability_tests_below_target": t_target(sum(1 for t in tests_judged if t["below_target"])),
        "availability_tests_not_judged": t_target(len(enabled) - len(tests_judged)),
        "availability_tests_below_target_latest_hour": t_target(sum(
            1 for t in enabled if t["latest_hour_percentage"] is not None and t["latest_hour_percentage"] < (target or 0))),
        "load_balancers_standard": len(standard) if balancers_listed else None,
        "load_balancers_public": sum(1 for b in balancers if b["public"]) if balancers_listed else None,
        "load_balancers_metrics_unread": sum(1 for b in standard if ERROR in (b["data_path"]["metric_status"], b["health_probe"]["metric_status"]))
        if balancers_listed else None,
        "lowest_data_path_availability": lb_known(_lowest([b["data_path"]["availability_percentage"] for b in standard])),
        "lowest_health_probe_availability": lb_known(_lowest([b["health_probe"]["availability_percentage"] for b in standard])),
        "load_balancers_below_target": lb_target(sum(1 for b in lbs_judged if any(m["below_target"] for m in applicable(b)))),
        "load_balancers_not_judged": lb_target(sum(1 for b in standard if applicable(b)) - len(lbs_judged)),
        "load_balancers_without_measured_traffic": sum(1 for b in standard if not applicable(b)) if balancers_listed else None,
        "load_balancers_with_missing_measurements": lb_known(sum(1 for b in standard if any(not m["measurement_complete"] for m in applicable(b)))),
        "lowest_load_balancer_measurement_coverage_percentage": lb_known(_coverage(
            [b[k]["measurement_coverage_percentage"] for b in standard for k in ("data_path", "health_probe")])),
        "lookback_days": settings["lookback_days"],
        "availability_target_percentage": settings["target"],
    }


def settings_from_env(collector: Collector) -> Dict[str, Any]:
    days, _ = bounded_int_config(collector, LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS, MAX_LOOKBACK_DAYS)
    raw = (os.environ.get(TARGET_ENV) or "").strip()
    target: Optional[float] = None  # unset until the offering adopts an availability objective
    if raw:
        try:
            value = float(raw)
            if not 0 < value <= 100:
                raise ValueError
            target = value
        except ValueError:
            collector.record(f"config {TARGET_ENV}", ValueError(
                f"invalid setting {TARGET_ENV}={raw!r}: expected a number above 0 and up to 100; left unset"))
    return {"lookback_days": days, "target": target}


# --- collection ---

def metric_points(client, collector: Collector, resource_id: str, namespace: str, metric: str, window: Tuple[datetime, datetime],
                  label: str, flt: Optional[str] = None) -> Tuple[List[Tuple[str, float]], str]:
    params = {"metricnames": metric, "metricnamespace": namespace, "aggregation": "Average", "interval": "PT1H",
              "timespan": f"{window[0].strftime('%Y-%m-%dT%H:%M:%SZ')}/{window[1].strftime('%Y-%m-%dT%H:%M:%SZ')}"}
    if flt:
        params["$filter"] = flt
    metrics = collector.guard(f"insights.metrics.list({metric}, {label})",
                              lambda: client.list(f"{resource_id}/providers/Microsoft.Insights/metrics", METRICS_API, params), default=None)
    return (hourly_points(metrics or [], metric), ERROR if metrics is None else READ)


def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None,
            now: Optional[datetime] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    # End at the last complete hour: Azure Monitor publishes each hour a few minutes after it closes.
    now = (now or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    settings = settings_from_env(collector)
    window = (now - timedelta(days=settings["lookback_days"]), now)
    hours = settings["lookback_days"] * 24
    excluded: List[dict] = []

    raw_tests = collector.guard("insights.webtests.list", lambda: client.list(
        f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/webtests", WEBTESTS_API), default=None)
    tests_listed = raw_tests is not None
    tests = sorted((test_record(t) for t in raw_tests or []), key=lambda t: arm_id_key(t["id"]))
    tests, out = exclusions.split(tests, "availability_test")
    excluded += out
    for t in tests:
        if not t["enabled"]:
            t.update(judged([], NOT_APPLICABLE, settings["target"], hours))
        elif not t["component_id"]:
            collector.record(f"insights.webtests.component ({t['name']})", ValueError("the test has no hidden-link tag naming its Application Insights component"))
            t.update(judged([], ERROR, settings["target"], hours))
        else:
            name = (t["test_name"] or "").replace("'", "''")
            points, status = metric_points(client, collector, t["component_id"], "microsoft.insights/components", AVAILABILITY_METRIC,
                                           window, t["name"], f"availabilityResult/name eq '{name}'")
            t.update(judged(points, status, settings["target"], hours))

    raw_lbs = collector.guard("network.loadBalancers.list", lambda: client.list(
        f"/subscriptions/{subscription_id}/providers/Microsoft.Network/loadBalancers", NETWORK_API), default=None)
    balancers_listed = raw_lbs is not None
    balancers = sorted((load_balancer_record(b) for b in raw_lbs or []), key=lambda b: arm_id_key(b["id"]))
    balancers, out = exclusions.split(balancers, "load_balancer")
    excluded += out
    for b in balancers:
        for key, metric in (("data_path", DATA_PATH_METRIC), ("health_probe", HEALTH_PROBE_METRIC)):
            measured = b["load_balancing_rules"] if key == "data_path" else b["probes"]
            if not b["standard"] or not measured:  # Basic SKU emits neither metric; no rules or probes, nothing to measure
                b[key] = judged([], NOT_APPLICABLE, settings["target"], hours)
                continue
            points, status = metric_points(client, collector, b["id"], "Microsoft.Network/loadBalancers", metric, window, b["name"])
            # The metrics report 0-100 per hour; Basic SKU load balancers emit none.
            b[key] = judged(points, status, settings["target"], hours)

    exclusions.record_invalid(collector)
    if not (tests_listed and balancers_listed):
        exclusions.mark_unread()
    exclusions.warn_unmatched(logger)
    results = {"availability_tests": tests, "load_balancers": balancers,
               "window": {"start": window[0].strftime("%Y-%m-%dT%H:%M:%SZ"), "end": window[1].strftime("%Y-%m-%dT%H:%M:%SZ")},
               "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id")))}
    summary = {**summarize(tests, balancers, settings, tests_listed, balancers_listed),
               **exclusions.summary(excluded, ("availability_test", "load_balancer"), {
                   "availability_tests": len(tests) if tests_listed else None,
                   "load_balancers": len(balancers) if balancers_listed else None})}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
