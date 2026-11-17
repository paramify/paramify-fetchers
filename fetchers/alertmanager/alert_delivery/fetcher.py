"""Alertmanager alert delivery: whether alerts are routed somewhere real, and whether notifications are delivered.

Reads Alertmanager's v2 API and its Prometheus metrics endpoint, GET only. It keeps three things apart that are
easy to blur: a route being configured, a notification being accepted by the integration's API (the metrics), and a
person receiving it, which Alertmanager cannot see. Receiver settings hold secrets (webhook URLs, API keys), so only
receiver names and integration types are kept, never the configuration text.

Collection-failure convention (docs/authoring_fetcher_guide.md, step 3): a failed GET is recorded in `api_failures`
and leaves the fields that depend on it null; the run exits non-zero when `api_failures` is non-empty.
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

NAME = "alertmanager_alert_delivery"
OUTPUT = "alertmanager_alert_delivery.json"
TIMEOUT = 30
MAX_RETRIES = 3
RETRY_STATUS = {429, 500, 502, 503, 504}
CODES = {401: "auth_failed", 403: "not_authorized", 404: "bad_config", 429: "rate_limited"}
# Receiver config keys that name an integration (Alertmanager's *_configs); any other key is not an integration.
INTEGRATION_SUFFIX = "_configs"
METRIC = re.compile(r'^(alertmanager_notifications_(?:failed_)?total)\{([^}]*)\}\s+([0-9.eE+-]+)\s*$')
LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

logger = logging.getLogger(NAME)


# --- pure transforms ---

def receiver_records(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Each receiver's name and integration types (such as webhook or slack), with how many of each; nothing else."""
    out = []
    for r in config.get("receivers") or []:
        types = {k[: -len(INTEGRATION_SUFFIX)]: len(v or []) for k, v in r.items() if k.endswith(INTEGRATION_SUFFIX) and v}
        out.append({"name": r.get("name"), "integration_types": sorted(types), "integrations": sum(types.values())})
    return out


def route_records(route: Dict[str, Any], depth: int = 0) -> List[Dict[str, Any]]:
    """Every route in the tree, depth first: its receiver, matchers and whether matching continues to siblings."""
    out = [{"depth": depth, "receiver": route.get("receiver"),
            "matchers": [str(m) for m in route.get("matchers") or []] or None,
            "continue": bool(route.get("continue"))}]
    for child in route.get("routes") or []:
        child = {**child, "receiver": child.get("receiver") or route.get("receiver")}  # a child inherits its parent's
        out.extend(route_records(child, depth + 1))
    return out


def parse_metrics(text: str) -> Dict[str, Any]:
    """Notification attempts and failures from Alertmanager's metrics, by receiver when the metrics carry receiver
    names (the receiver-name-in-metrics feature), otherwise by integration type."""
    attempts: Dict[str, float] = {}
    failures: Dict[str, float] = {}
    by_receiver = False
    for line in (text or "").splitlines():
        m = METRIC.match(line.strip())
        if not m:
            continue
        labels = dict(LABEL.findall(m.group(2)))
        by_receiver = by_receiver or "receiver_name" in labels
        key = labels.get("receiver_name") or labels.get("integration") or "unknown"
        target = failures if m.group(1).endswith("failed_total") else attempts
        target[key] = target.get(key, 0) + float(m.group(3))
    return {"by": "receiver" if by_receiver else "integration", "attempts": attempts, "failures": failures}


def summarize(status: Optional[Dict[str, Any]], alerts: Optional[List[Dict[str, Any]]],
              silences: Optional[List[Dict[str, Any]]], metrics: Optional[Dict[str, Any]],
              now: Optional[datetime] = None) -> Dict[str, Any]:
    """What is configured and what happened, never a verdict. Each group is null when the call behind it failed."""
    now = now or datetime.now(timezone.utc)
    config = None
    if status is not None:
        try:
            config = yaml.safe_load(((status.get("config") or {}).get("original")) or "") or {}
        except yaml.YAMLError:
            config = None
    receivers = receiver_records(config) if config is not None else None
    routes = route_records(config.get("route") or {}) if config is not None else None
    empty = {r["name"] for r in receivers or [] if not r["integrations"]}
    default = routes[0]["receiver"] if routes else None
    cluster = (status or {}).get("cluster") or {}
    started = _time((status or {}).get("uptime"))
    active = [a for a in alerts or [] if (a.get("status") or {}).get("state") == "active"]
    suppressed = [a for a in alerts or [] if (a.get("status") or {}).get("state") == "suppressed"]
    m = metrics or {}
    failed = {k: v for k, v in (m.get("failures") or {}).items() if v}
    cfg = config is not None
    al = alerts is not None
    met = metrics is not None
    return {
        # Routing: is anything configured to deliver?
        "config_read": cfg if status is not None else None,
        "receivers_total": len(receivers) if cfg else None,
        "receivers_without_integrations": len(empty) if cfg else None,
        "receivers_without_integrations_names": sorted(empty) if cfg else None,
        "integration_types": sorted({t for r in receivers or [] for t in r["integration_types"]}) if cfg else None,
        "default_receiver": default if cfg else None,
        "default_receiver_has_integrations": (bool(default) and default not in empty) if cfg else None,
        "routes_total": len(routes) - 1 if cfg and routes else (0 if cfg else None),
        "routes_to_receivers_without_integrations": sum(1 for r in (routes or [])[1:] if r["receiver"] in empty) if cfg else None,
        "inhibit_rules": len(config.get("inhibit_rules") or []) if cfg else None,
        # Alerts: what is firing, and where does it go?
        "alerts_active": len(active) if al else None,
        "alerts_suppressed": len(suppressed) if al else None,
        "alerts_silenced": sum(1 for a in suppressed if (a["status"].get("silencedBy") or [])) if al else None,
        "alerts_inhibited": sum(1 for a in suppressed if (a["status"].get("inhibitedBy") or [])) if al else None,
        "alerts_active_to_receivers_without_integrations": (sum(
            1 for a in active if a.get("receivers") and all(r.get("name") in empty for r in a["receivers"]))
            if al and cfg else None),
        "silences_active": sum(1 for s in silences or [] if (s.get("status") or {}).get("state") == "active") if silences is not None else None,
        # Delivery: what the integrations accepted, not what a person received.
        "notifications_attempted": int(sum((m.get("attempts") or {}).values())) if met else None,
        "notifications_failed": int(sum(failed.values())) if met else None,
        "notification_failures_by": m.get("by") if met else None,
        "notification_failures": sorted(failed) if met else None,
        "counters_since": started.strftime("%Y-%m-%dT%H:%M:%SZ") if started else None,
        "hours_since_counters_started": round((now - started).total_seconds() / 3600, 1) if started else None,
        "cluster_status": cluster.get("status") if status is not None else None,
        "cluster_peers": len(cluster.get("peers") or []) if status is not None else None,
    }


def _time(value: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


# --- collection ---

class AlertmanagerClient:
    def __init__(self, base_url: str, token: Optional[str] = None, session: Any = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.api_failures: List[Dict[str, Any]] = []
        self.failure_codes: List[str] = []

    def get(self, operation: str, path: str, as_json: bool = True) -> Any:
        """GET only; None (and a recorded failure) when it cannot be read."""
        url = f"{self.base_url}{path}"
        response = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, timeout=TIMEOUT, allow_redirects=False, headers=self.headers)
            except requests.RequestException as exc:
                if attempt == MAX_RETRIES:
                    return self._fail(operation, type(exc).__name__, str(exc), "target_unreachable")
                time.sleep(min(2 ** attempt, 30))
                continue
            if response.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 30))
                continue
            break
        if response.status_code != 200:
            return self._fail(operation, f"HTTP {response.status_code}", (response.text or "")[:300],
                              CODES.get(response.status_code, "partial_failure"))
        if not as_json:
            return response.text
        try:
            return response.json()
        except ValueError as exc:
            return self._fail(operation, "ValueError", f"response was not JSON: {exc}", "partial_failure")

    def _fail(self, operation: str, kind: str, message: str, code: str) -> None:
        self.api_failures.append({"operation": operation, "type": kind, "message": message})
        self.failure_codes.append(code)
        logger.error("%s failed: %s", operation, kind)
        return None


def collect(client: AlertmanagerClient, now: Optional[datetime] = None) -> Dict[str, Any]:
    status = client.get("status", "/api/v2/status")
    alerts = client.get("alerts", "/api/v2/alerts")
    silences = client.get("silences", "/api/v2/silences")
    text = client.get("metrics", "/metrics", as_json=False)
    metrics = parse_metrics(text) if text is not None else None
    config = None
    if status is not None:
        try:
            config = yaml.safe_load(((status.get("config") or {}).get("original")) or "") or {}
        except yaml.YAMLError as exc:
            client._fail("status configuration", "YAMLError", str(exc)[:300], "partial_failure")
    results = {
        "version": ((status or {}).get("versionInfo") or {}).get("version"),
        "receivers": receiver_records(config) if config is not None else None,
        "routes": route_records(config.get("route") or {}) if config is not None else None,
        "alerts": [{"alertname": (a.get("labels") or {}).get("alertname"), "severity": (a.get("labels") or {}).get("severity"),
                    "state": (a.get("status") or {}).get("state"), "starts_at": a.get("startsAt"),
                    "silenced": bool((a.get("status") or {}).get("silencedBy")),
                    "inhibited": bool((a.get("status") or {}).get("inhibitedBy")),
                    "receivers": [r.get("name") for r in a.get("receivers") or []]} for a in alerts] if alerts is not None else None,
        "silences": [{"state": (s.get("status") or {}).get("state"), "ends_at": s.get("endsAt"),
                      "matchers": [m.get("name") for m in s.get("matchers") or []]} for s in silences] if silences is not None else None,
        "notifications": metrics,
    }
    return {"results": results, "summary": summarize(status, alerts, silences, metrics, now)}


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api_failures": []}
    evidence: Dict[str, Any] = {"results": {}, "summary": summarize(None, None, None, None)}
    code = None
    base_url = (os.environ.get("ALERTMANAGER_BASE_URL") or "").strip()
    if not base_url:
        metadata["api_failures"] = [{"operation": "config", "type": "ValueError", "message": "Missing required setting: ALERTMANAGER_BASE_URL"}]
        code = "bad_config"
    else:
        metadata["base_url"] = base_url.rstrip("/")
        client = AlertmanagerClient(base_url, os.environ.get("ALERTMANAGER_TOKEN") or None)
        evidence = collect(client)
        metadata["api_failures"] = client.api_failures
        code = client.failure_codes[0] if client.failure_codes else None
    metadata["partial_failure"] = bool(metadata["api_failures"])
    path = out_dir / OUTPUT
    path.write_text(json.dumps({"metadata": metadata, **evidence}, indent=2, sort_keys=True))
    logger.info("Evidence saved to %s", path)
    if metadata["api_failures"]:
        first = metadata["api_failures"][0]
        report_failure(f"Alertmanager {first['operation']} failed: {first['type']}", code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
