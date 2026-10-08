"""ARM, Microsoft Graph and Log Analytics query REST client shared by the Sentinel, Log Analytics and Entra REST fetchers."""

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
# Sent as x-ms-app so LAQueryLogs can tell this collector's queries from people's.
CLIENT_APP = "paramify-fetchers"
WORKSPACES_ENV = "SENTINEL_WORKSPACES"

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

    def _get(self, url: str, params: Optional[Dict[str, str]] = None, resource: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token(resource or self.arm)}"}
        response = self.session.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
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

    def graph_get(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return self._get(f"{self.graph}/v1.0{path}", params, self.graph)

    def graph_list(self, path: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Every page of a Microsoft Graph v1.0 collection, following @odata.nextLink."""
        body = self._get(f"{self.graph}/v1.0{path}", params, self.graph)
        items = list(body.get("value") or [])
        while body.get("@odata.nextLink"):
            body = self._get(body["@odata.nextLink"], None, self.graph)
            items.extend(body.get("value") or [])
        return items

    def graph_post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.graph}/v1.0{path}",
            json=body,
            headers={"Authorization": f"Bearer {self._token(self.graph)}"},
            timeout=HTTP_TIMEOUT,
        )
        if response.status_code >= 400:
            raise ArmError(response.status_code, *_error_parts(response))
        return response.json()

    def token_tenant(self) -> Optional[str]:
        """The `tid` claim of the ARM token: which tenant this run actually authenticated into."""
        import base64
        import json

        try:
            claims = self._token(self.arm).split(".")[1]
            return json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4))).get("tid")
        except (IndexError, ValueError):
            return None

    def query(self, customer_id: str, kql: str, timespan: str) -> List[Dict[str, Any]]:
        """Rows of the primary table; a partial result raises rather than returning short."""
        response = self.session.post(
            f"{self.logs}/v1/workspaces/{customer_id}/query",
            json={"query": kql, "timespan": timespan},
            headers={
                "Authorization": f"Bearer {self._token(self.logs)}",
                "Prefer": f"wait={QUERY_TIMEOUT}",
                "x-ms-app": CLIENT_APP,
            },
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
    from azure.identity import AzureCliCredential, ChainedTokenCredential, DefaultAzureCredential  # lazy

    if not subscription_id or any(os.environ.get(v) for v in _EXPLICIT_IDENTITY_ENV):
        return DefaultAzureCredential()
    # Unpinned, the CLI mints a token for its default account, which another tenant refuses.
    return ChainedTokenCredential(AzureCliCredential(subscription=subscription_id), DefaultAzureCredential())


def _start(logger: logging.Logger) -> Path:
    from dotenv import find_dotenv, load_dotenv  # lazy

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    for noisy in ("azure", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # The working directory's .env first, so a per-client folder overrides the repo's; neither overrides the real env.
    load_dotenv(find_dotenv(usecwd=True))
    load_dotenv()
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


def run_tenant(
    *,
    fetcher: str,
    logger: logging.Logger,
    collect: Callable[[AzureRestClient, Collector], tuple],
    session: Any = None,
) -> int:
    """Tenant-scoped evidence (Entra): one file per tenant, named for AZURE_TENANT_ID or the token's tenant."""
    output_dir = _start(logger)
    collector = Collector(logger)
    subscription_id = (os.environ.get("AZURE_SUBSCRIPTION_ID") or "").strip() or None
    cred = collector.guard("azure.identity.DefaultAzureCredential", lambda: pinned_credential(subscription_id))

    results: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}
    tenant_id = (os.environ.get("AZURE_TENANT_ID") or "").strip() or None
    tenant_source = "target" if tenant_id else "unresolved"
    if cred is not None:
        client = AzureRestClient(cred, session)
        token_tenant = collector.guard("azure.identity token", client.token_tenant)
        if token_tenant and tenant_id and token_tenant.lower() != tenant_id.lower():
            collector.record(
                "tenant check",
                RuntimeError(f"credential authenticated into tenant {token_tenant}, not the target tenant {tenant_id}"),
            )
        elif collector.ok:
            tenant_id, tenant_source = tenant_id or token_tenant, tenant_source if tenant_id else "token"
            results, summary = collect(client, collector)
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source="target_correlation_only" if subscription_id else "not_applicable",
        collector=collector,
        results=results,
        summary=summary,
    )
    evidence["metadata"].update({"tenant_id": tenant_id, "tenant_source": tenant_source})
    return _finish(logger, collector, output_dir, f"{fetcher}_{sanitize_for_filename(tenant_id or 'unknown')}.json", evidence)
