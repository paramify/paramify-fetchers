"""Shared reads for the Azure App Service web-app fetchers."""

from __future__ import annotations

from azure_common import Collector, arm_client_kwargs

# `kind` is comma-joined: "app", "app,linux", "app,linux,container", "functionapp",
# "functionapp,linux". Prowler's split.
WEB_APP_KIND_PREFIX = "app"
FUNCTION_APP_KIND_PREFIX = "functionapp"


def is_web_app(kind) -> bool:
    """Prowler's split: `kind` starting with "app" is a web app, not a function app.

    No `kind` counts as a web app — Prowler's default (`getattr(app, "kind", "app")`),
    and the API omits `kind` only for plain Windows web apps.
    """
    text = str(kind or WEB_APP_KIND_PREFIX).lower()
    return text.startswith(WEB_APP_KIND_PREFIX) and not text.startswith(
        FUNCTION_APP_KIND_PREFIX
    )


def is_not_authorized(exc: BaseException) -> bool:
    """A 403: the caller lacks an opt-in permission such as config/list, not a broken call."""
    message = str(exc).lower()
    return getattr(exc, "status_code", None) == 403 or "authorizationfailed" in message


def web_client(subscription_id, cred, collector: Collector):
    def _client():
        from azure.mgmt.web import WebSiteManagementClient  # lazy

        return WebSiteManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    return collector.guard("web.WebSiteManagementClient (init)", _client)
