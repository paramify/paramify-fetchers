"""API version check: batches arrived in Paramify API 0.14.0."""
from framework.paramify.client import ApiError, Client, ErrorKind


def require_batches(client: Client) -> None:
    try:
        client.get("/batches", {"pageSize": 1})
    except ApiError as exc:
        if exc.kind is ErrorKind.MISSING:
            raise ApiError(
                "this workspace's API has no batches; 0.14.0 or later is required",
                status=exc.status, kind=ErrorKind.FATAL, method=exc.method, path=exc.path,
            ) from exc
        raise
