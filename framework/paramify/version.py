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
    """Can this workspace take batches? Any error other than a 404 or a 403 is raised.

    A 404 means the API has no batch routes. Any 403 turns batches off with the
    server's message as the reason: the flag is off ("not enabled"), or the
    token may not list batches. Either way every entry is sent direct, and a
    token that cannot upload at all fails on its own uploads, not here. A 401
    is still raised (FATAL): no call in the run can succeed.
    """
    try:
        client.get("/batches", {"pageSize": 1})
    except ApiError as exc:
        if exc.kind is ErrorKind.MISSING:
            return Capability(False, NO_ROUTES)
        if exc.status == 403 and FLAG_OFF in exc.message:
            return Capability(False, FLAG_OFF)
        if exc.status == 403:
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

