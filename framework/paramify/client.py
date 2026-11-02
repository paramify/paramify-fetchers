"""One HTTP client for the Paramify REST API.

Every call goes through `Client._call`, which classifies a failed response
into an `ErrorKind` and retries the temporary ones inside a shared time budget.
"""
from __future__ import annotations

import json
import time
from enum import Enum
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

import requests

_BACKOFF_CAP_S = 30.0


class ErrorKind(str, Enum):
    FATAL = "fatal"
    PERMANENT = "permanent"
    TEMPORARY = "temporary"
    MISSING = "missing"
    CONFLICT = "conflict"
    WARNING = "warning"
    REJECTED = "rejected"  # a write the API refused: that action fails, the run goes on


class ApiError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: Optional[int],
        kind: ErrorKind,
        method: str,
        path: str,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.kind = kind
        self.method = method
        self.path = path

    @property
    def fatal(self) -> bool:
        """True when no further call in this run can succeed (read by generic code)."""
        return self.kind is ErrorKind.FATAL


def classify(method: str, path: str, status: int, body: str, is_upload: bool) -> ErrorKind:
    """Map a failed response to an ErrorKind.

    Only a 401, a 403 outside tags and uploads, and a refused read stop the
    run. A refused write (400, 405, 415, 422, ...) fails its own action. A
    tag write never breaks an upload, so its refusals are warnings.
    """
    if status == 401:
        return ErrorKind.FATAL
    if path.startswith("/custom-tags") and 400 <= status < 500 and status != 429:
        return ErrorKind.WARNING
    if status == 403:
        if is_upload and "requestId" not in body:
            # The production WAF rejects the file itself; it carries no requestId.
            return ErrorKind.PERMANENT
        return ErrorKind.FATAL
    if status == 404:
        return ErrorKind.MISSING
    if status == 409:
        return ErrorKind.CONFLICT
    if status == 429 or status >= 500:
        return ErrorKind.TEMPORARY
    if is_upload and 400 <= status < 500:
        return ErrorKind.PERMANENT
    if method != "GET" and 400 <= status < 500:
        return ErrorKind.REJECTED
    return ErrorKind.FATAL


def base_url_error(base_url: str) -> Optional[str]:
    """A message when the base URL would send the token over plain http."""
    parsed = urlparse(base_url)
    if parsed.scheme != "https" and (parsed.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
        return (
            "base_url must be https to protect the API token "
            f"(got {base_url!r}); only localhost may use http"
        )
    return None


def _retry_after(headers: Any) -> Optional[float]:
    try:
        value = headers.get("Retry-After")
    except AttributeError:
        return None
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


class Client:
    def __init__(
        self,
        token: str,
        base_url: str,
        *,
        session: Any = None,
        timeout: int = 30,
        retry_budget_s: float = 300.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        error = base_url_error(base_url)
        if error:
            raise ValueError(error)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._sleep = sleep
        self._budget_left = retry_budget_s
        self.session = session if session is not None else requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._call("GET", path, params=params)

    def post_json(self, path: str, body: Dict[str, Any]) -> Any:
        return self._call("POST", path, json_body=body)

    def post_file(self, path: str, filename: str, content: bytes, meta: Dict[str, Any]) -> Any:
        files = {
            "file": (filename, content, "application/json"),
            "artifact": ("artifact.json", json.dumps(meta), "application/json"),
        }
        return self._call("POST", path, files=files, is_upload=True)

    def _call(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        is_upload: bool = False,
    ) -> Any:
        attempt = 0
        # A POST may already be committed server-side when it times out or
        # answers 500/502/504; retrying would duplicate the create or upload.
        # Only a refusal (429/503) or a failed connection is safe to repeat.
        safe_to_retry = method == "GET"
        while True:
            status: Optional[int] = None
            retry_after: Optional[float] = None
            retryable = True
            try:
                resp = self.session.request(
                    method,
                    f"{self.base_url}{path}",
                    params=params,
                    json=json_body,
                    files=files,
                    timeout=self.timeout,
                )
            except requests.ConnectionError as exc:
                reason = f"{type(exc).__name__}: {exc}"
            except requests.RequestException as exc:
                reason = f"{type(exc).__name__}: {exc}"
                retryable = safe_to_retry and isinstance(exc, requests.Timeout)
            else:
                status = resp.status_code
                if status < 400:
                    try:
                        return _decode(resp)
                    except ValueError as exc:
                        raise ApiError(
                            f"{method} {path} returned a body that is not valid JSON",
                            status=status, kind=ErrorKind.FATAL, method=method, path=path,
                        ) from exc
                body = resp.text or ""
                kind = classify(method, path, status, body, is_upload)
                reason = f"HTTP {status}: {body[:300]}"
                if kind is not ErrorKind.TEMPORARY:
                    raise ApiError(
                        f"{method} {path} failed ({reason})",
                        status=status, kind=kind, method=method, path=path,
                    )
                retryable = safe_to_retry or status in (429, 503)
                retry_after = _retry_after(resp.headers)
            if not retryable:
                raise ApiError(
                    f"{method} {path} failed, not retried because it may have taken effect ({reason})",
                    status=status, kind=ErrorKind.TEMPORARY, method=method, path=path,
                )
            delay = retry_after if retry_after is not None else min(2.0**attempt, _BACKOFF_CAP_S)
            if not delay >= 1.0:  # also catches NaN: every retry costs at least 1 s of budget
                delay = 1.0
            if delay > self._budget_left:
                raise ApiError(
                    f"{method} {path} failed after retrying ({reason})",
                    status=status, kind=ErrorKind.TEMPORARY, method=method, path=path,
                )
            self._budget_left -= delay
            self._sleep(delay)
            attempt += 1


def _decode(resp: Any) -> Any:
    if not (resp.text or "").strip():
        return None
    return resp.json()
