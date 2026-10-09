"""ARM, Microsoft Graph and Log Analytics query REST client shared by the Sentinel and Log Analytics REST fetchers."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from azure_common import (
    Collector,
    arm_endpoint,
    basename,
    build_payload,
    classify_failure_code,
    dig,
    failure_reason,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from entra_graph import graph_host

SI_API = "2025-09-01"
# NRT and other rule kinds exist only in preview specs; bump when this one retires.
SI_PREVIEW_API = "2025-10-01-preview"
LAW_API = "2023-09-01"
DIAG_API = "2021-05-01-preview"
HTTP_TIMEOUT = 60
QUERY_TIMEOUT = 600
# Throttling and transient server errors, retried as azure-core's policy does for the SDK fetchers.
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
MAX_RETRIES = 4
MAX_RETRY_WAIT = 120
# Sent as x-ms-app so LAQueryLogs can tell this collector's queries from people's.
CLIENT_APP = "paramify-fetchers"
WORKSPACES_ENV = "SENTINEL_WORKSPACES"
REPO_ROOT = Path(__file__).resolve().parents[3]

_LOGGER = logging.getLogger("azure_rest")

LOGS_ENDPOINT_PUBLIC = "https://api.loganalytics.io"
_ARM_TO_LOGS_ENDPOINT = {
    "https://management.azure.com": LOGS_ENDPOINT_PUBLIC,
    "https://management.usgovcloudapi.net": "https://api.loganalytics.us",
    "https://management.chinacloudapi.cn": "https://api.loganalytics.azure.cn",
}


def logs_endpoint() -> str:
    """Log Analytics query endpoint for the cloud arm_endpoint() resolved to."""
    return _ARM_TO_LOGS_ENDPOINT.get(arm_endpoint(), LOGS_ENDPOINT_PUBLIC)


class ArmError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code = status, code
        super().__init__(f"({status}) {code}: {message}")


class QueryError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def retry_wait(response, attempt: int) -> float:
    """Seconds to wait: the service's Retry-After (seconds or HTTP date) when given, else exponential backoff."""
    headers = getattr(response, "headers", None) or {}
    raw = headers.get("x-ms-retry-after-ms")
    if raw:
        try:
            return min(float(raw) / 1000, MAX_RETRY_WAIT)
        except ValueError:
            pass
    raw = headers.get("Retry-After")
    if raw:
        try:
            return min(max(float(raw), 0.0), MAX_RETRY_WAIT)
        except ValueError:
            from email.utils import parsedate_to_datetime

            try:
                return min(max((parsedate_to_datetime(raw) - datetime.now(timezone.utc)).total_seconds(), 0.0), MAX_RETRY_WAIT)
            except (TypeError, ValueError):
                pass
    return float(min(2 ** attempt, MAX_RETRY_WAIT))


def _error_parts(response) -> tuple:
    try:
        err = response.json().get("error") or {}
    except ValueError:
        err = {}
    return err.get("code") or response.reason or "Error", err.get("message") or response.text[:500]


class AzureRestClient:
    """Bearer-token REST calls to ARM, Microsoft Graph and the Log Analytics query API."""

    def __init__(self, cred: Any, session: Any = None):
        import requests  # lazy

        self.cred = cred
        self.session = session or requests.Session()
        self.arm = arm_endpoint()
        self.logs = logs_endpoint()
        self.graph = graph_host()
        self._tokens: Dict[str, Any] = {}

    def _token(self, resource: str) -> str:
        cached = self._tokens.get(resource)
        if cached is None or cached.expires_on - 120 < time.time():
            cached = self.cred.get_token(f"{resource}/.default")
            self._tokens[resource] = cached
        return cached.token

    def _send(self, method: str, url: str, resource: str, headers: Optional[Dict[str, str]] = None, **kwargs: Any):
        """One request, retried on throttling, transient 5xx and dropped connections."""
        import requests  # lazy

        for attempt in range(MAX_RETRIES + 1):
            sent = {"Authorization": f"Bearer {self._token(resource)}", **(headers or {})}
            try:
                response = getattr(self.session, method)(url, headers=sent, **kwargs)
            except requests.ConnectionError:
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(float(min(2 ** attempt, MAX_RETRY_WAIT)))
                continue
            if response.status_code not in RETRY_STATUSES or attempt == MAX_RETRIES:
                return response
            wait = retry_wait(response, attempt)
            _LOGGER.warning("%s %s answered %s; retrying in %.0fs", method.upper(), url.split("?")[0], response.status_code, wait)
            time.sleep(wait)
        raise AssertionError("unreachable")

    def _get(self, url: str, params: Optional[Dict[str, str]] = None, resource: Optional[str] = None) -> Dict[str, Any]:
        response = self._send("get", url, resource or self.arm, params=params, timeout=HTTP_TIMEOUT)
        if response.status_code >= 400:
            raise ArmError(response.status_code, *_error_parts(response))
        return response.json()

    def get(self, path: str, api_version: str) -> Dict[str, Any]:
        return self._get(f"{self.arm}{path}", {"api-version": api_version})

    def list(self, path: str, api_version: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Every page: ARM documents no page size for these lists, so stopping early truncates silently."""
        body = self._get(f"{self.arm}{path}", {"api-version": api_version, **(params or {})})
        items = list(body.get("value") or [])
        while body.get("nextLink"):
            body = self._get(body["nextLink"])
            items.extend(body.get("value") or [])
        return items

    def graph_post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        response = self._send("post", f"{self.graph}/v1.0{path}", self.graph, json=body, timeout=HTTP_TIMEOUT)
        if response.status_code >= 400:
            raise ArmError(response.status_code, *_error_parts(response))
        return response.json()

    def query(self, customer_id: str, kql: str, timespan: str) -> List[Dict[str, Any]]:
        """Rows of the primary table; a partial result raises rather than returning short."""
        response = self._send(
            "post",
            f"{self.logs}/v1/workspaces/{customer_id}/query",
            self.logs,
            headers={"Prefer": f"wait={QUERY_TIMEOUT}", "x-ms-app": CLIENT_APP},
            json={"query": kql, "timespan": timespan},
            timeout=QUERY_TIMEOUT + 30,
        )
        if response.status_code >= 400:
            code, message = _error_parts(response)
            raise QueryError(f"({response.status_code}) {code}", _innermost(response) or message)
        body = response.json()
        if body.get("error"):
            raise QueryError("PartialError", _innermost_error(body["error"]))
        tables = body.get("tables") or []
        if not tables:
            return []
        columns = [c["name"] for c in tables[0].get("columns") or []]
        return [dict(zip(columns, row)) for row in tables[0].get("rows") or []]


def _innermost_error(err: Dict[str, Any]) -> str:
    while err.get("innererror"):
        err = err["innererror"]
    return err.get("message") or err.get("code") or "partial result"


def _innermost(response) -> Optional[str]:
    try:
        err = response.json().get("error")
    except ValueError:
        return None
    return _innermost_error(err) if err else None


def table_missing(exc: BaseException, table: str) -> bool:
    """A workspace that never received a table answers 'Failed to resolve table' for it."""
    text = str(exc).lower()
    return isinstance(exc, QueryError) and "failed to resolve" in text and table.lower() in text


def requested_workspaces() -> List[str]:
    raw = os.environ.get(WORKSPACES_ENV) or ""
    return [w.strip() for w in raw.split(",") if w.strip()]


def _matches(ws: Dict[str, Any], wanted: str) -> bool:
    wanted = wanted.lower().rstrip("/")
    return wanted in ((ws.get("id") or "").lower(), (ws.get("name") or "").lower())


_NOT_ONBOARDED_CODES = {"missingsubscriptionregistration", "resourcenotfound", "notfound"}


def sentinel_onboarded(client: AzureRestClient, workspace_id: str) -> bool:
    try:
        states = client.list(f"{workspace_id}/providers/Microsoft.SecurityInsights/onboardingStates", SI_API)
    except ArmError as exc:
        # Unregistered provider or a workspace Sentinel never touched: not onboarded, not a failure.
        if exc.code.lower() == "subscriptionnotfound":
            raise
        if exc.status == 404 or exc.code.lower() in _NOT_ONBOARDED_CODES:
            return False
        raise
    return any((s.get("name") or "").lower() == "default" for s in states)


def discover_workspaces(client: AzureRestClient, subscription_id: str, collector: Collector) -> List[Dict[str, Any]]:
    listed = collector.guard(
        "operationalinsights.workspaces.list",
        lambda: client.list(f"/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces", LAW_API),
    )
    if listed is None:
        return []
    wanted = requested_workspaces()
    for name in wanted:
        if not any(_matches(ws, name) for ws in listed):
            collector.record(
                f"{WORKSPACES_ENV} lookup",
                LookupError(f"workspace {name!r} not found in subscription {subscription_id}"),
            )
    selected = [ws for ws in listed if not wanted or any(_matches(ws, n) for n in wanted)]
    out = []
    for ws in sorted(selected, key=lambda w: (w.get("id") or "").lower()):
        onboarded = collector.guard(
            f"securityinsights.onboardingStates.list({ws.get('name')})",
            lambda ws=ws: sentinel_onboarded(client, ws["id"]),
        )
        out.append({
            "id": ws.get("id"),
            "name": ws.get("name") or basename(ws.get("id")),
            "resource_group": resource_group_from_id(ws.get("id")),
            "location": ws.get("location"),
            "customer_id": dig(ws, "properties", "customerId"),
            "retention_in_days": dig(ws, "properties", "retentionInDays"),
            "sentinel_onboarded": onboarded,
        })
    return out


def workspace_identity(ws: Dict[str, Any]) -> Dict[str, Any]:
    return {k: ws.get(k) for k in ("id", "name", "resource_group", "location", "retention_in_days", "sentinel_onboarded")}


def table_retention_days(client: AzureRestClient, workspace_id: str, table: str, default: Optional[int]) -> Optional[int]:
    """Interactive (queryable) retention of one table; older rows are gone, not absent."""
    try:
        days = dig(client.get(f"{workspace_id}/tables/{table}", LAW_API), "properties", "retentionInDays")
    except ArmError as exc:
        if exc.status == 404:
            return default
        raise
    return days if isinstance(days, int) and days > 0 else default


def int_config(env: str, default: int) -> int:
    raw = (os.environ.get(env) or "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        _LOGGER.warning("%s=%r is not an integer; using %d", env, raw, default)
        return default
    return value if value > 0 else default


def iso_duration_days(days: int) -> str:
    return f"P{days}D"


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    # ARM and KQL emit 1-7 fractional digits; Python 3.10's fromisoformat takes exactly 3 or 6.
    if "." in text:
        head, _, tail = text.partition(".")
        frac = tail[: len(tail) - len(tail.lstrip("0123456789"))]
        text = f"{head}.{frac[:6].ljust(6, '0')}{tail[len(frac):]}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


_EXPLICIT_IDENTITY_ENV = ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN_FILE", "IDENTITY_ENDPOINT", "MSI_ENDPOINT")


def pinned_credential(subscription_id: Optional[str]):
    """DefaultAzureCredential, except a CLI login is asked for the account that holds the target subscription."""
    from azure.identity import (  # lazy
        AzureCliCredential,
        ChainedTokenCredential,
        DefaultAzureCredential,
    )

    if not subscription_id or any(os.environ.get(v) for v in _EXPLICIT_IDENTITY_ENV):
        return DefaultAzureCredential()
    # Unpinned, the CLI mints a token for its default account, which another tenant refuses.
    return ChainedTokenCredential(AzureCliCredential(subscription=subscription_id), DefaultAzureCredential())


def _start(logger: logging.Logger) -> Path:
    from dotenv import load_dotenv  # lazy

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    for noisy in ("azure", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # The working directory's .env, then the repo's; neither overrides the real env. Parent folders are not searched.
    load_dotenv(Path.cwd() / ".env")
    load_dotenv(REPO_ROOT / ".env")
    return Path(os.environ.get("EVIDENCE_DIR", "./evidence"))


def _finish(logger: logging.Logger, collector: Collector, output_dir: Path, filename: str, evidence: Dict[str, Any]) -> int:
    path = write_evidence(output_dir, filename, evidence)
    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


Collect = Callable[[AzureRestClient, str, Collector], tuple]


def run_subscription(*, fetcher: str, logger: logging.Logger, collect: Collect, session: Any = None) -> int:
    """Resolve the subscription, run `collect(client, subscription_id, collector) -> (results, summary)`, write evidence."""
    output_dir = _start(logger)
    collector = Collector(logger)
    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", lambda: pinned_credential(subscription_id))

    results: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}
    if subscription_id and cred is not None:
        client = AzureRestClient(cred, session)
        results, summary = collect(client, subscription_id, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results=results,
        summary=summary,
    )
    return _finish(logger, collector, output_dir, f"{fetcher}_{sanitize_for_filename(subscription_id or 'unknown')}.json", evidence)


def run_workspaces(
    *,
    fetcher: str,
    logger: logging.Logger,
    collect: Callable[[AzureRestClient, Dict[str, Any], Collector], Dict[str, Any]],
    summarize: Callable[[List[Dict[str, Any]]], Dict[str, Any]],
    sentinel_only: bool = True,
    session: Any = None,
) -> int:
    """Find the subscription's (Sentinel) workspaces and collect each into one evidence file."""

    def per_workspace(client: AzureRestClient, subscription_id: str, collector: Collector) -> tuple:
        workspaces: List[Dict[str, Any]] = []
        without_sentinel: List[str] = []
        for ws in discover_workspaces(client, subscription_id, collector):
            if sentinel_only and not ws["sentinel_onboarded"]:
                without_sentinel.append(ws["name"])
                continue
            detail = collector.guard(f"collect({ws['name']})", lambda ws=ws: collect(client, ws, collector), default={})
            workspaces.append({**workspace_identity(ws), **(detail or {})})
        results: Dict[str, Any] = {"workspaces": workspaces, "workspace_filter": requested_workspaces() or None}
        summary: Dict[str, Any] = {"workspaces_collected": len(workspaces), **summarize(workspaces)}
        if sentinel_only:
            results["workspaces_without_sentinel"] = without_sentinel
            summary["workspaces_without_sentinel"] = len(without_sentinel)
        return results, summary

    return run_subscription(fetcher=fetcher, logger=logger, collect=per_workspace, session=session)

