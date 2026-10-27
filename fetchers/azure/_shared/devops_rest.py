"""Azure DevOps REST client and entry point shared by the azure_devops_* fetchers."""

from __future__ import annotations

import base64
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from azure_common import (
    Collector,
    classify_failure_code,
    current_timestamp,
    failure_reason,
    report_failure,
    sanitize_for_filename,
    write_evidence,
)

ORG_URL_ENV = "AZURE_DEVOPS_ORG_URL"
PAT_ENV = "AZURE_DEVOPS_PAT"
# Azure DevOps' first-party application, the audience of an Entra token for it.
ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"
PROJECTS_ENV = "AZURE_DEVOPS_PROJECTS"
API_VERSION = "7.1"
CONNECTION_DATA_API = "7.1-preview.1"
HTTP_TIMEOUT = 60
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_RETRIES = 4
MAX_RETRY_WAIT = 120
REPO_ROOT = Path(__file__).resolve().parents[3]
_ADO_CODE = re.compile(r"\b((?:TF|VS)\d{5,6})\b")
# "Not found" answers ADO gives when the caller may not see the thing.
_PERMISSION_MASKING_CODES = {"VS800075", "TF401019", "TF200016"}

_LOGGER = logging.getLogger("devops_rest")


class DevOpsError(Exception):
    """An ADO error answer: HTTP status, the TF/VS code (else typeKey) and the service's message."""

    def __init__(self, status: Optional[int], code: str, message: str, type_key: Optional[str] = None):
        self.status, self.code, self.type_key = status, code, type_key
        message = re.sub(rf"^{re.escape(code)}:\s*", "", message or "")
        super().__init__(f"({status}) {code}: {message}" if status else f"{code}: {message}")

    @property
    def failure_code(self) -> str:
        if self.status in (203, 401) or self.code == "Redirect":
            return "auth_failed"
        if self.status == 403 or self.code in _PERMISSION_MASKING_CODES:
            return "not_authorized"
        if self.status == 429:
            return "rate_limited"
        return "internal_error"


def failure_code(exc: BaseException) -> str:
    import requests  # lazy

    if isinstance(exc, DevOpsError):
        return exc.failure_code
    if isinstance(exc, (requests.ConnectionError, requests.Timeout)):
        return "target_unreachable"
    if isinstance(exc, ValueError):
        return "bad_config"
    # ARM and Log Analytics errors, for fetchers that also read Azure.
    code = classify_failure_code([{"type": type(exc).__name__, "message": str(exc)}])
    return "internal_error" if code == "partial_failure" else code


class DevOpsCollector(Collector):
    """Collector that also keeps each failure's contract code."""

    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self.codes: List[str] = []
        self.auth_mode = "pat"

    def record(self, operation: str, exc: BaseException) -> None:
        super().record(operation, exc)
        self.codes.append(failure_code(exc))

    def failure_code(self) -> str:
        return self.codes[0] if len(set(self.codes)) == 1 else "partial_failure"


def parse_org_url(raw: str) -> Tuple[str, str]:
    """(organization, base URL) from https://dev.azure.com/{org}, https://{org}.visualstudio.com or a bare name."""
    raw = (raw or "").strip().rstrip("/")
    if not raw:
        raise ValueError(f"{ORG_URL_ENV} is not set")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", raw):
        return raw, f"https://dev.azure.com/{raw}"
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise ValueError(f"{ORG_URL_ENV} must be an https URL, got {raw!r}")
    if host == "dev.azure.com":
        org = parts.path.strip("/").split("/")[0]
        if org:
            return org, f"https://dev.azure.com/{org}"
    elif host.endswith(".visualstudio.com") and host.count(".") == 2:
        org = host.split(".")[0]
        return org, f"https://{org}.visualstudio.com"
    raise ValueError(f"{ORG_URL_ENV} is not an Azure DevOps Services organization URL: {raw!r}")


def _retry_wait(response: Any, attempt: int) -> float:
    raw = (getattr(response, "headers", None) or {}).get("Retry-After")
    try:
        if raw:
            return min(max(float(raw), 0.0), MAX_RETRY_WAIT)
    except ValueError:
        pass
    return float(min(2 ** attempt, MAX_RETRY_WAIT))


def _error(response: Any) -> DevOpsError:
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        body = {}
    if isinstance(body.get("error"), dict):
        body = body["error"]
    type_key = body.get("typeKey")
    message = body.get("message") or (response.text or "")[:300] or response.reason or ""
    found = _ADO_CODE.search(message)
    code = found.group(1) if found else type_key or body.get("code") or response.reason or "Error"
    return DevOpsError(response.status_code, code, message, type_key)


class DevOpsClient:
    """Reads against one Azure DevOps Services organization, as a PAT or as an Entra identity."""

    def __init__(self, org_url: str, pat: Optional[str], session: Any = None, credential: Any = None):
        import requests  # lazy

        self.org, self.base = parse_org_url(org_url)
        self.session = session or requests.Session()
        if not pat and credential is None:
            raise ValueError(f"{PAT_ENV} is not set and no Entra credential was given")
        self.auth_mode = "pat" if pat else "entra"
        self._auth = "Basic " + base64.b64encode(f":{pat}".encode()).decode() if pat else ""
        self._credential = None if pat else credential
        self._token: Any = None

    def _authorization(self) -> str:
        if self._credential is None:
            return self._auth
        if self._token is None or self._token.expires_on - 120 < time.time():
            self._token = self._credential.get_token(f"{ADO_RESOURCE}/.default")
        return f"Bearer {self._token.token}"

    def service_url(self, service: Optional[str] = None) -> str:
        """The org's root on another ADO service host, e.g. "auditservice" or "vsrm"."""
        if not service:
            return self.base
        if self.base.startswith("https://dev.azure.com/"):
            return f"https://{service}.dev.azure.com/{self.org}"
        return f"https://{self.org}.{service}.visualstudio.com"

    def url(self, path: str, service: Optional[str] = None) -> str:
        return f"{self.service_url(service)}/{path.lstrip('/')}"

    def _send(self, method: str, url: str, **kwargs: Any) -> Any:
        """One request, retried on throttling, transient 5xx and dropped connections. Redirects are never followed."""
        import requests  # lazy

        for attempt in range(MAX_RETRIES + 1):
            headers = {"Authorization": self._authorization(), "Accept": "application/json"}
            try:
                response = self.session.request(
                    method, url, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=False, **kwargs
                )
            except requests.ConnectionError:
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(float(min(2 ** attempt, MAX_RETRY_WAIT)))
                continue
            if response.status_code not in RETRY_STATUSES or attempt == MAX_RETRIES:
                break
            wait = _retry_wait(response, attempt)
            _LOGGER.warning("%s %s answered %s; retrying in %.0fs", method, url.split("?")[0], response.status_code, wait)
            time.sleep(wait)
        if 300 <= response.status_code < 400:
            location = (response.headers or {}).get("Location") or ""
            # A read API redirects only to sign-in, i.e. the PAT or token was not accepted.
            raise DevOpsError(response.status_code, "Redirect", f"redirected to {urlsplit(location).hostname}")
        if response.status_code >= 400:
            raise _error(response)
        return response

    @staticmethod
    def _json(response: Any) -> Any:
        # A rejected or missing PAT can come back 203 with the HTML sign-in page.
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.status_code == 203 or body is None:
            raise DevOpsError(response.status_code, "NonJsonResponse", (response.text or "")[:200] or "empty body")
        return body

    def get(self, path: str, api_version: str = API_VERSION, params: Optional[Dict[str, Any]] = None,
            service: Optional[str] = None) -> Any:
        return self._json(self._send("GET", self.url(path, service), params={**(params or {}), "api-version": api_version}))

    def post(self, path: str, body: Dict[str, Any], api_version: str = API_VERSION,
             service: Optional[str] = None) -> Any:
        """A POST that reads, such as a pipeline preview run."""
        return self._json(self._send("POST", self.url(path, service), params={"api-version": api_version}, json=body))

    def get_text(self, path: str, api_version: str = API_VERSION, params: Optional[Dict[str, Any]] = None,
                 service: Optional[str] = None) -> str:
        response = self._send("GET", self.url(path, service), params={**(params or {}), "api-version": api_version})
        if response.status_code == 203:
            raise DevOpsError(203, "NonJsonResponse", "sign-in page instead of content")
        return response.text

    def iter(self, path: str, api_version: str = API_VERSION, params: Optional[Dict[str, Any]] = None,
             service: Optional[str] = None, item_key: Union[str, Sequence[str]] = "value") -> Iterator[Dict[str, Any]]:
        """Every item across pages: x-ms-continuationtoken or a body continuationToken, else a same-host nextLink.
        With several item keys, each page is read from the first one it fills."""
        keys = (item_key,) if isinstance(item_key, str) else tuple(item_key)
        url: Optional[str] = self.url(path, service)
        base_params = {**(params or {}), "api-version": api_version}
        query: Optional[Dict[str, Any]] = base_params
        seen = set()
        while url:
            response = self._send("GET", url, params=query)
            body = self._json(response)
            items = body if isinstance(body, list) else next((body[k] for k in keys if body.get(k)), [])
            yield from items
            token = (response.headers or {}).get("x-ms-continuationtoken")
            if not token and isinstance(body, dict) and body.get("hasMore") is not False:
                token = body.get("continuationToken")
            link = (body.get("nextLink") or body.get("@odata.nextLink")) if isinstance(body, dict) else None
            if token:
                if token in seen:
                    raise DevOpsError(None, "ContinuationLoop", f"{path} returned continuation token {token!r} twice")
                seen.add(token)
                query = {**base_params, "continuationToken": token}
            elif link:
                _require_same_host(link, url)
                url, query = link, None
            else:
                url = None

    def list(self, path: str, api_version: str = API_VERSION, params: Optional[Dict[str, Any]] = None,
             service: Optional[str] = None, item_key: Union[str, Sequence[str]] = "value") -> List[Dict[str, Any]]:
        return list(self.iter(path, api_version, params, service, item_key))


def _require_same_host(link: str, current: str) -> None:
    """The PAT goes only where the paged request went."""
    target, origin = urlsplit(link), urlsplit(current)
    if target.scheme != "https" or (target.hostname or "").lower() != (origin.hostname or "").lower():
        raise DevOpsError(None, "UntrustedNextLink", f"next link points to {target.scheme}://{target.hostname}, "
                                                     f"not {origin.hostname}")


def parse_time(value: Optional[str]) -> Optional[datetime]:
    """An ADO timestamp (up to 7 fractional digits) as an aware datetime; None when absent or unparseable."""
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    match = re.match(r"^(.*?\.)(\d+)(.*)$", text)
    if match:
        head, frac, tail = match.groups()
        text = f"{head}{frac[:6].ljust(6, '0')}{tail}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def requested_projects() -> List[str]:
    return [p.strip() for p in (os.environ.get(PROJECTS_ENV) or "").split(",") if p.strip()]


def list_projects(client: DevOpsClient, collector: DevOpsCollector) -> List[Dict[str, Any]]:
    """Every well-formed project the PAT can read, narrowed to AZURE_DEVOPS_PROJECTS; a named one missing is a failure."""
    def read():
        try:
            return client.list("_apis/projects", params={"stateFilter": "wellFormed", "$top": 500})
        except DevOpsError as exc:
            if exc.status == 404:  # the organization itself does not exist
                raise ValueError(f"organization {client.org!r} not found at {client.base}: {exc}") from exc
            raise

    listed = collector.guard("core.projects.list", read)
    if listed is None:
        return []
    wanted = requested_projects()
    known = {(p.get("name") or "").lower() for p in listed} | {(p.get("id") or "").lower() for p in listed}
    for name in wanted:
        if name.lower() not in known:
            collector.record(f"{PROJECTS_ENV} lookup",
                             ValueError(f"project {name!r} not found or not readable with this PAT"))
    lowered = {w.lower() for w in wanted}
    selected = [p for p in listed if not wanted or {(p.get("name") or "").lower(), (p.get("id") or "").lower()} & lowered]
    return sorted(selected, key=lambda p: (p.get("name") or "").lower())


def collecting_identity(client: DevOpsClient, collector: DevOpsCollector) -> Optional[Dict[str, Any]]:
    """Who the organization authenticated; every list the fetcher reads is what this identity may see."""
    body = collector.guard("location.connectionData", lambda: client.get("_apis/connectionData", CONNECTION_DATA_API))
    user = (body or {}).get("authenticatedUser") if isinstance(body, dict) else None
    if not isinstance(user, dict):
        return None
    account = ((user.get("properties") or {}).get("Account") or {}).get("$value")
    # "login" marks this as a person's record, so sample redaction replaces the display name too.
    return {"id": user.get("id"), "display_name": user.get("providerDisplayName"), "login": account}


def _start() -> Path:
    from dotenv import load_dotenv  # lazy

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    load_dotenv(Path.cwd() / ".env")
    load_dotenv(REPO_ROOT / ".env")
    return Path(os.environ.get("EVIDENCE_DIR", "./evidence"))


def entra_credential() -> Any:
    """The ambient Entra identity (az login, managed or workload identity, service principal), used when there is no PAT."""
    from azure.identity import DefaultAzureCredential  # lazy

    return DefaultAzureCredential()


Collect = Callable[[DevOpsClient, DevOpsCollector], Tuple[Dict[str, Any], Dict[str, Any]]]


def run_org(*, fetcher: str, logger: logging.Logger, collect: Collect, session: Any = None) -> int:
    """Build the client from the environment, run `collect(client, collector) -> (results, summary)`, write evidence."""
    output_dir = _start()
    collector = DevOpsCollector(logger)
    client: Optional[DevOpsClient] = None
    try:
        pat = os.environ.get(PAT_ENV)
        client = DevOpsClient(os.environ.get(ORG_URL_ENV, ""), pat, session,
                              credential=None if pat else entra_credential())
        collector.auth_mode = client.auth_mode
    except Exception as exc:  # noqa: BLE001 - bad config or a missing azure-identity still leaves evidence
        collector.record("configuration", exc)

    results: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}
    identity = None
    if client is not None:
        identity = collecting_identity(client, collector)
        try:
            results, summary = collect(client, collector)
        except Exception as exc:  # noqa: BLE001 - an unexpected answer must still leave evidence and a reason
            logger.exception("collection failed")
            collector.record("collect", exc)

    evidence = {
        "metadata": {
            "organization": client.org if client else None,
            "organization_url": client.base if client else None,
            "auth_mode": client.auth_mode if client else None,
            "collecting_identity": identity,
            "projects_filter": requested_projects() or None,
            "datetime": current_timestamp(),
            "partial_failure": not collector.ok,
            "api_failures": collector.failures,
        },
        "results": results,
        "summary": summary,
    }
    name = sanitize_for_filename(client.org if client else "unknown")
    path = write_evidence(output_dir, f"{fetcher}_{name}.json", evidence)
    logger.info("Evidence saved to %s", path)
    if not collector.ok:
        report_failure(failure_reason(collector.failures), collector.failure_code())
        return 1
    return 0
