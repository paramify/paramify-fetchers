"""Opt-in source read boundaries shared by native SDK and REST transports."""

from __future__ import annotations

import json
import os
from typing import Optional
from urllib.parse import unquote, urlsplit


def target_subscription_scope() -> Optional[str]:
    """Require an explicit subscription for optional strict reads."""
    strict = os.environ.get("AZURE_TARGET_SUBSCRIPTION_ONLY", "false").strip().lower()
    if strict not in ("true", "false"):
        raise ValueError("AZURE_TARGET_SUBSCRIPTION_ONLY must be true or false")
    scope = (os.environ.get("AZURE_SUBSCRIPTION_ID") or "").strip()
    if strict == "true" and not scope:
        raise ValueError(
            "AZURE_SUBSCRIPTION_ID is required with AZURE_TARGET_SUBSCRIPTION_ONLY"
        )
    return scope if strict == "true" else None


def validate_read_url(
    url: str, resource: str, subscription_scope: Optional[str] = None,
    *, allow_subscription_root: bool = False,
) -> None:
    """Validate an authenticated read before a native transport obtains a token."""
    target, origin = urlsplit(url), urlsplit(resource)
    if (
        target.scheme != "https"
        or target.netloc.lower() != origin.netloc.lower()
        or target.username is not None
        or target.password is not None
        or target.fragment
    ):
        raise ValueError("Read origin is untrusted")
    if subscription_scope is not None:
        path = unquote(target.path)
        scope = subscription_scope
        if (
            not scope
            or any(
                c
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
                for c in scope
            )
            or not (
                path.lower().startswith(f"/subscriptions/{scope}/".lower())
                or (allow_subscription_root and path.lower() == f"/subscriptions/{scope}".lower())
            )
            or any(part in (".", "..") for part in path.split("/"))
            or "\\" in path
            or "%" in path
        ):
            raise ValueError(
                "ARM read scope: path is outside the explicit subscription"
            )


def validate_sdk_arm_request(request, endpoint: str, scope: str) -> None:
    """Resource Graph is a root read POST with an explicit subscription body."""
    url = request.url
    if (
        request.method.upper() == "POST"
        and urlsplit(url).path.lower() == "/providers/microsoft.resourcegraph/resources"
    ):
        validate_read_url(url, endpoint)
        body = request.body
        if isinstance(body, (str, bytes, bytearray)):
            body = json.loads(body)
        if (
            not isinstance(body, dict)
            or body.get("subscriptions") != [scope]
            or body.get("managementGroups") not in (None, [])
        ):
            raise ValueError(
                "ARM read scope: Resource Graph requires exactly the explicit subscription"
            )
        return
    if request.method.upper() != "GET":
        raise ValueError(
            "ARM read boundary permits GET or the explicit Resource Graph read POST only"
        )
    validate_read_url(url, endpoint, scope)


def sdk_arm_boundary_options(endpoint: str, scope: str) -> dict:
    """Use the SDK's pre-auth policy hook and existing redirect implementation."""
    from azure.core.pipeline.policies import RedirectPolicy, SansIOHTTPPolicy

    class ScopedArmReadPolicy(SansIOHTTPPolicy):
        def on_request(self, request):
            validate_sdk_arm_request(request.http_request, endpoint, scope)

        def on_response(self, request, response):
            if 300 <= response.http_response.status_code < 400:
                raise ValueError("ARM read returned a redirect; not followed")

    return {
        "per_call_policies": [ScopedArmReadPolicy()],
        "redirect_policy": RedirectPolicy(permit_redirects=False),
    }
