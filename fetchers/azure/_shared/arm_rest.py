"""Raw ARM GETs through the SDKs' auth and retry policies, for lists azure-mgmt-monitor 6.x reads wrong or not at all."""

from __future__ import annotations

from typing import Any, Dict, List

from azure_common import arm_endpoint

# A guard, not a cap: reaching it means ARM kept handing back nextLinks.
MAX_PAGES = 1000


def arm_rest_client(cred):
    from azure.core.pipeline import policies  # lazy
    from azure.mgmt.core import ARMPipelineClient
    from azure.mgmt.core.policies import ARMChallengeAuthenticationPolicy

    endpoint = arm_endpoint()
    return ARMPipelineClient(
        base_url=endpoint,
        policies=[
            policies.RequestIdPolicy(),
            policies.HeadersPolicy(),
            policies.UserAgentPolicy(sdk_moniker="paramify-fetchers"),
            policies.RetryPolicy(),
            ARMChallengeAuthenticationPolicy(cred, f"{endpoint}/.default"),
            policies.ContentDecodePolicy(),
            policies.DistributedTracingPolicy(),
        ],
    )


def get_json(client, url: str) -> Dict[str, Any]:
    endpoint = arm_endpoint().rstrip("/").lower()
    relative = url.startswith("/") and not url.startswith("//")
    if not relative and not url.lower().startswith(endpoint + "/"):
        raise ValueError(f"refusing to send the ARM token outside {endpoint}: {url[:120]}")

    from azure.core.exceptions import HttpResponseError  # lazy
    from azure.core.rest import HttpRequest
    from azure.mgmt.core.exceptions import ARMErrorFormat

    # send_request does not resolve a relative path against base_url; nextLinks are already absolute.
    response = client.send_request(HttpRequest("GET", client.format_url(url)))
    if response.status_code >= 400:
        raise HttpResponseError(response=response, error_format=ARMErrorFormat)
    return response.json()


def list_all(client, path: str, api_version: str) -> Dict[str, Any]:
    """Every item under `path`, following nextLink to the end; returns items and pages read."""
    url = f"{path}?api-version={api_version}"
    items: List[dict] = []
    pages = 0
    seen = set()
    while url:
        body = get_json(client, url)
        pages += 1
        items.extend(body.get("value") or [])
        url = body.get("nextLink")
        if url and (url in seen or pages >= MAX_PAGES):
            raise RuntimeError(f"ARM paging of {path} did not terminate after {pages} page(s)")
        if url:
            seen.add(url)
    return {"items": items, "pages": pages}
