"""Whether Cloud SIEM is active for a Datadog organization, in one place.

Datadog documents one explicit signal: on
`GET /api/v2/security_monitoring/content_packs/states`, "When Cloud SIEM is
inactive for the requesting organization, `onboarding` is returned instead of
the content pack's usual type." The endpoint is in preview.

The rule every Datadog SIEM fetcher follows: Cloud SIEM reads as not active
only on that signal. A 403 or 404 from any other SIEM endpoint is never enough
on its own, because a missing permission or a wrong path answers the same way.

Import it from a fetcher the same way as `datadog_paging`:

    sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
    from datadog_siem_state import read_siem_state  # noqa: E402
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests
from datadog_paging import request_json

CONTENT_PACKS_PATH = "/api/v2/security_monitoring/content_packs/states"

NOT_ACTIVE_MESSAGE = (
    "Cloud SIEM is not active for this organization "
    "(content pack states report onboarding)"
)


def unknown_siem_state(error: Optional[str], status_code: Optional[int] = None) -> Dict[str, Any]:
    """The state when the content pack states read failed: unknown, never False."""
    return {
        "enabled": None,
        "basis": "content_pack_states",
        "sku": None,
        "content_pack_detail_types": [],
        "error": error,
        "status_code": status_code,
    }


def siem_state_from_content_packs(payload: Dict[str, Any]) -> Dict[str, Any]:
    """`enabled` is True, False, or None (unknown). Never False without the signal."""
    state = unknown_siem_state(error=None)
    state["sku"] = (payload.get("meta") or {}).get("sku")
    detail_types = sorted({
        ((item.get("attributes") or {}).get("details") or {}).get("type") or "unknown"
        for item in payload.get("data") or []
    })
    state["content_pack_detail_types"] = detail_types
    if not detail_types:
        state["error"] = "content pack states returned no content packs; Cloud SIEM state unknown"
    elif detail_types == ["onboarding"]:
        state["enabled"] = False
    elif "onboarding" not in detail_types:
        state["enabled"] = True
    else:
        state["error"] = "content pack states mix onboarding and active types; Cloud SIEM state unknown"
    return state


def read_siem_state(base_url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """Read the content pack states through the shared request helper."""
    try:
        payload = request_json("GET", f"{base_url}{CONTENT_PACKS_PATH}", headers)
    except requests.exceptions.RequestException as e:
        response = getattr(e, "response", None)
        return unknown_siem_state(f"{CONTENT_PACKS_PATH}: {e}", getattr(response, "status_code", None))
    except ValueError as e:
        return unknown_siem_state(f"{CONTENT_PACKS_PATH}: response is not JSON ({e})")
    if not isinstance(payload, dict):
        return unknown_siem_state(f"{CONTENT_PACKS_PATH}: response is not a JSON object")
    return siem_state_from_content_packs(payload)
