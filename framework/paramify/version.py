"""API capability check: batches arrived in Paramify API 0.14.0, behind a workspace flag."""
from dataclasses import dataclass
from typing import Optional

from framework.paramify.client import ApiError, Client, ErrorKind

# Stage, 2026-11-02: the 403 body of /batches and /artifact-requests on a workspace
# whose batches flag is off.
FLAG_OFF = "Artifact requests are not enabled for this workspace."

NO_ROUTES = "the API has no batch routes"


@dataclass(frozen=True)
class Capability:
    batches: bool
    reason: Optional[str] = None  # None when batches is True


def delivery_capability(client: Client) -> Capability:
    """Can this workspace take batches? Any error other than "no routes" or "flag off" is raised."""
    try:
        client.get("/batches", {"pageSize": 1})
    except ApiError as exc:
        if exc.kind is ErrorKind.MISSING:
            return Capability(False, NO_ROUTES)
        if exc.status == 403 and FLAG_OFF in exc.message:
            return Capability(False, FLAG_OFF)
        raise
    return Capability(True, None)


def require_batches(client: Client) -> None:
    """Raise FATAL when batches are unavailable. Kept for the uploader until direct delivery replaces it."""
    cap = delivery_capability(client)
    if cap.batches:
        return
    if cap.reason == FLAG_OFF:
        raise ApiError(
            "batches are not turned on for this workspace (the API answered "
            f"\"{FLAG_OFF}\"); ask Paramify to turn on artifact requests for it",
            status=403, kind=ErrorKind.FATAL, method="GET", path="/batches",
        )
    raise ApiError(
        "this workspace's API has no batches; 0.14.0 or later is required",
        status=404, kind=ErrorKind.FATAL, method="GET", path="/batches",
    )
