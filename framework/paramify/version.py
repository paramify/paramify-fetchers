"""API capability check: batches arrived in Paramify API 0.14.0, behind a workspace flag."""
import json
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
    """Can this workspace take batches? Any error other than "no routes" or "flag off" is raised.

    Flag off is a 403 with the known text, or any 403 that says "not enabled".
    """
    try:
        client.get("/batches", {"pageSize": 1})
    except ApiError as exc:
        if exc.kind is ErrorKind.MISSING:
            return Capability(False, NO_ROUTES)
        if exc.status == 403 and FLAG_OFF in exc.message:
            return Capability(False, FLAG_OFF)
        if exc.status == 403 and "not enabled" in exc.message.lower():
            return Capability(False, _server_message(exc.message))
        raise
    return Capability(True, None)


def _server_message(message: str) -> str:
    """The `error.message` of the JSON body in an ApiError message, else the whole message."""
    start, end = message.find("{"), message.rfind("}")
    if start != -1 and end > start:
        try:
            text = json.loads(message[start:end + 1])["error"]["message"]
        except (ValueError, KeyError, TypeError):
            text = None
        if isinstance(text, str) and text:
            return text
    return message

