"""The incidents walk shared by `datadog_incidents_list` and
`datadog_incident_timelines`.

`GET /api/v2/incidents` documents `include`, `page[size]` and `page[offset]`.
It does not document a date filter. The walk still sends
`filter[created][start]` and `filter[created][end]`, which may cut the pages
read, and the fetcher then drops each incident created before the window with
`drop_incidents_before`. The result is the same whether the API applies the
filter or ignores it.

Import it from a fetcher the same way as `datadog_paging`:

    sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
    from datadog_incidents import drop_incidents_before, walk_incidents  # noqa: E402
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from datadog_paging import PagedRecords, paginate_offset

INCIDENTS_PATH = "/api/v2/incidents"
PAGE_SIZE = 100


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse a Datadog ISO 8601 timestamp, with or without fractional seconds.

    The v2 incidents API returns values such as ``2019-09-19T10:00:00.000Z``.
    A value with no offset is read as UTC.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def walk_incidents(base_url: str, headers: Dict[str, str], from_ts: str, to_ts: str) -> PagedRecords:
    """Every incident page. The incidents `meta.pagination` has no total, so the
    walk stops on a short page. Raises PagingError if the first page fails; a
    later failure comes back on the returned list's `.error`."""
    return paginate_offset(
        f"{base_url}{INCIDENTS_PATH}",
        headers,
        operation="Datadog list incidents",
        page_size=PAGE_SIZE,
        params={
            "filter[created][start]": from_ts,
            "filter[created][end]": to_ts,
        },
    )


def drop_incidents_before(
    incidents: List[Dict[str, Any]], from_dt: datetime
) -> Tuple[List[Dict[str, Any]], int]:
    """(incidents in the window, number dropped).

    An incident whose `attributes.created` is earlier than `from_dt` is
    dropped. An incident with no readable `created` is kept, because the
    fetcher cannot show that it is outside the window.
    """
    kept: List[Dict[str, Any]] = []
    for incident in incidents:
        created = parse_timestamp((incident.get("attributes") or {}).get("created"))
        if created is not None and created < from_dt:
            continue
        kept.append(incident)
    return kept, len(incidents) - len(kept)
