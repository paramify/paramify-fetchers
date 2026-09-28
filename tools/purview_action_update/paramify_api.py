"""Paramify v0 client — solution capabilities, the audit log, and evidence upload.

Reads are the bulk of it; the only writes are the opt-in evidence-set upload.

Three things about this API that are not obvious from the documentation:

* `/solution-capabilities` was enriched in v0.9.2 and now returns
  `implementationStatus` and `functions[].narrative` alongside the identity
  fields. Notes elsewhere in this repo describing it as name-only are out of date.

* `/audit-logs` is absent from the published OpenAPI document (v0.9.2, 51 paths)
  but IS served: a genuinely nonexistent path returns 404 even unauthenticated,
  while `/audit-logs` returns 401 — so routing precedes auth and the route
  exists. A 404 is still handled as "degraded, not fatal" in case a deployment
  lacks it.

* **There are two auth schemes.** The spec declares `authorization`
  (`Authorization: Bearer <token>`) and `apiKey_DEPRECATED` — an API key in a
  header literally named `Bearer`. Older tokens want the second. This client
  tries the current scheme, falls back to the legacy one on 401, and pins
  whichever authenticated so the rest of the run uses it directly.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Iterator, Optional
from urllib.parse import quote

import requests

from config import base_url as default_base_url

logger = logging.getLogger("purview_action_update.api")


class ParamifyError(RuntimeError):
    """A Paramify call failed."""


class ParamifyAuthError(ParamifyError):
    """Both auth schemes were rejected."""


class AuditLogUnavailable(ParamifyError):
    """`/audit-logs` is not served by this deployment. Dates are underivable."""


#: `Authorization: Bearer <token>` — the current scheme.
SCHEME_BEARER = "authorization"
#: A header named `Bearer` carrying the raw token — `apiKey_DEPRECATED`.
SCHEME_LEGACY = "apiKey_DEPRECATED"
SCHEMES = (SCHEME_BEARER, SCHEME_LEGACY)

MAX_LIMIT = 500
#: Runaway guard: at 500 per page this is 100k events, far beyond one
#: workspace's relevant history. Without it a server echoing one cursor pages
#: forever.
MAX_PAGES = 200


class ParamifyClient:
    def __init__(self, token: Optional[str] = None, *, base_url: Optional[str] = None,
                 timeout: float = 60.0, auth_scheme: Optional[str] = None) -> None:
        self._token = (token or os.environ.get("PARAMIFY_API_TOKEN") or "").strip()
        if not self._token:
            raise ParamifyError(
                "PARAMIFY_API_TOKEN is not set. Export it in this shell:\n"
                "    export PARAMIFY_API_TOKEN='...'"
            )
        # Resolved here, not as a default argument: a default binds at function
        # definition time, which is before .env is loaded.
        self._base_url = (base_url or default_base_url()).rstrip("/")
        self._timeout = timeout
        self._scheme = auth_scheme
        self._session = requests.Session()

    def __enter__(self) -> "ParamifyClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self._session.close()

    # --- auth -------------------------------------------------------------- #

    @property
    def auth_scheme(self) -> Optional[str]:
        """Which scheme authenticated, once one has. `None` until first success."""
        return self._scheme

    def _headers(self, scheme: str) -> dict[str, str]:
        if scheme == SCHEME_BEARER:
            return {"Authorization": f"Bearer {self._token}"}
        return {"Bearer": self._token}

    def _request(self, method: str, path: str,
                 build_kwargs: Optional[Callable[[], dict[str, Any]]] = None) -> Any:
        """One call, trying the legacy auth scheme if the current one is rejected.

        `build_kwargs` is a callable rather than a dict so a retry re-opens any
        file handle; a consumed upload stream would otherwise retry as empty.
        """
        url = f"{self._base_url}/{path.lstrip('/')}"
        attempts = [self._scheme] if self._scheme else list(SCHEMES)
        last_body = ""
        for index, scheme in enumerate(attempts):
            kwargs = build_kwargs() if build_kwargs else {}
            response = self._session.request(
                method, url, headers=self._headers(scheme), timeout=self._timeout, **kwargs
            )
            if response.status_code == 401:
                last_body = response.text[:300]
                if index + 1 < len(attempts):
                    logger.info("auth scheme %s rejected; trying %s",
                                scheme, attempts[index + 1])
                    continue
                raise ParamifyAuthError(
                    "Paramify rejected the token under "
                    f"{'both auth schemes' if len(attempts) > 1 else attempts[0]}.\n"
                    "  Check: the token is complete (no truncation or stray whitespace), "
                    "has not been revoked or expired, and belongs to this workspace.\n"
                    f"  Base URL in use: {self._base_url} "
                    "(override with PARAMIFY_API_BASE_URL)\n"
                    f"  Server said: {last_body}"
                )
            if response.status_code == 404 and path.strip("/") == "audit-logs":
                raise AuditLogUnavailable(
                    "GET /audit-logs returned 404 — this deployment does not serve the "
                    "audit log, so Implementation Date cannot be derived"
                )
            if response.status_code >= 400:
                # The token travels in a header, so neither the URL nor this
                # message can carry it.
                raise ParamifyError(
                    f"{method} {path} -> {response.status_code}: {response.text[:300]}"
                )
            if self._scheme != scheme:
                logger.info("authenticated using the %s scheme", scheme)
                self._scheme = scheme
            return response.json() if response.content else None
        raise ParamifyError(f"{method} {path}: no auth scheme succeeded")

    def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        return self._request("GET", path, lambda: {"params": params})

    def check_auth(self) -> dict[str, Any]:
        """One cheap authenticated GET, so a token can be validated in a second."""
        capabilities = self.solution_capabilities()
        return {
            "authenticated": True,
            "auth_scheme": self._scheme,
            "base_url": self._base_url,
            "solution_capabilities_visible": len(capabilities),
        }

    # --- solution capabilities --------------------------------------------- #

    def solution_capabilities(self) -> list[dict[str, Any]]:
        """Every SolCap in the program. The endpoint takes no parameters."""
        payload = self._get("/solution-capabilities") or {}
        return payload.get("solutionCapabilities", [])

    # --- evidence sets (the only writes this tool makes) -------------------- #

    def find_evidence(self, reference_id: str) -> Optional[dict[str, Any]]:
        """Look up an Evidence Set by reference id.

        `GET /evidence` filters on `id[]` and `referenceId[]` only — there is no
        name filter — which is why the reference id is the idempotency key.
        """
        payload = self._get("/evidence", {"referenceId": [reference_id]}) or {}
        return next(
            (e for e in payload.get("evidences", []) if e.get("referenceId") == reference_id),
            None,
        )

    def create_evidence(self, *, name: str, reference_id: str, description: str = "",
                        instructions: str = "") -> dict[str, Any]:
        body = {"name": name, "referenceId": reference_id, "description": description,
                "instructions": instructions, "frequency": "NOT_SET"}
        return self._request("POST", "/evidence", lambda: {"json": body})

    def ensure_evidence(self, *, name: str, reference_id: str, description: str = "",
                        instructions: str = "") -> tuple[dict[str, Any], bool]:
        """Find by reference id, create only if absent. Returns (evidence, created)."""
        existing = self.find_evidence(reference_id)
        if existing:
            return existing, False
        return self.create_evidence(name=name, reference_id=reference_id,
                                    description=description, instructions=instructions), True

    def upload_artifact(self, evidence_id: str, *, path: Path, title: str, note: str,
                        effective_date: str, content_type: str) -> Any:
        """Attach a file to an Evidence Set.

        multipart/form-data with two parts: the file, and an `artifact` JSON part
        carrying its metadata. The filename is URL-encoded because certain
        special characters cause upload errors; Paramify decodes it on receipt.
        """
        metadata = json.dumps(
            {"title": title, "note": note, "effectiveDate": effective_date}
        )

        def build() -> dict[str, Any]:
            # Re-opened per attempt so an auth retry does not send an empty body.
            return {"files": {
                "file": (quote(path.name), path.open("rb"), content_type),
                "artifact": (None, metadata, "application/json"),
            }}

        return self._request("POST", f"/evidence/{evidence_id}/artifacts/upload", build)

    def artifacts(self, evidence_id: str) -> list[dict[str, Any]]:
        payload = self._get(f"/evidence/{evidence_id}/artifacts") or {}
        return payload.get("artifacts", [])

    def delete_artifact(self, evidence_id: str, artifact_id: str) -> Any:
        return self._request("DELETE", f"/evidence/{evidence_id}/artifacts/{artifact_id}")

    def delete_evidence(self, evidence_id: str) -> Any:
        return self._request("DELETE", f"/evidence/{evidence_id}")

    # --- audit log ----------------------------------------------------------- #

    def audit_log_events(
        self,
        *,
        activity_types: tuple[str, ...] = ("HISTORY",),
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        page_limit: int = MAX_LIMIT,
        max_pages: int = MAX_PAGES,
    ) -> Iterator[dict[str, Any]]:
        """Walk the audit log newest-first, following `nextCursor` to the end.

        One workspace-wide pass indexed by resource id — not one call per
        capability, which would be 463 requests for the same data.
        """
        params: dict[str, Any] = {
            "activityTypes": list(activity_types),
            "limit": min(page_limit, MAX_LIMIT),
        }
        if start_date:
            params["startDate"] = start_date
        if end_date:
            params["endDate"] = end_date

        cursor: Optional[str] = None
        for _ in range(max_pages):
            page_params = dict(params)
            if cursor:
                page_params["cursor"] = cursor
            payload = self._get("/audit-logs", page_params) or {}
            events = payload.get("data")
            if events is None and isinstance(payload, list):
                events = payload
            yield from (events or [])
            cursor = _next_cursor(payload)
            if not cursor:
                return


def _next_cursor(payload: Any) -> Optional[str]:
    """Find the paging cursor, tolerating where the envelope puts it.

    The endpoint is absent from the published spec, so the exact envelope is
    known only from the API reference UI. Checked in the documented spelling
    first, then the usual nestings, rather than assuming one.
    """
    if not isinstance(payload, dict):
        return None
    for key in ("nextCursor", "next_cursor"):
        value = payload.get(key)
        if value:
            return str(value)
    for container in ("meta", "pagination", "page"):
        nested = payload.get(container)
        if isinstance(nested, dict):
            for key in ("nextCursor", "next_cursor", "cursor"):
                value = nested.get(key)
                if value:
                    return str(value)
    return None
