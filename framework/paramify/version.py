"""API version check: batches arrived in Paramify API 0.14.0."""
from framework.paramify.client import ApiError, Client, ErrorKind

# Stage, 2026-11-02: the 403 body of /batches and /artifact-requests on a workspace
# whose batches flag is off.
FLAG_OFF = "Artifact requests are not enabled for this workspace."


def require_batches(client: Client) -> None:
    try:
        client.get("/batches", {"pageSize": 1})
    except ApiError as exc:
        if exc.kind is ErrorKind.MISSING:
            raise ApiError(
                "this workspace's API has no batches; 0.14.0 or later is required",
                status=exc.status, kind=ErrorKind.FATAL, method=exc.method, path=exc.path,
            ) from exc
        if exc.status == 403 and FLAG_OFF in exc.message:
            raise ApiError(
                "batches are not turned on for this workspace (the API answered "
                f"\"{FLAG_OFF}\"); ask Paramify to turn on artifact requests for it",
                status=exc.status, kind=ErrorKind.FATAL, method=exc.method, path=exc.path,
            ) from exc
        raise
