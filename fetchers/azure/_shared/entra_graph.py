"""Microsoft Graph plumbing shared by the tenant-scoped Entra fetchers.

Graph evidence is per TENANT, not per subscription, and never asks
`azure_common.provider_registration_status()` — Graph is not an ARM provider, so
there is no `Microsoft.*` namespace to ask about and asking would 404. Client
construction follows prowler/providers/azure/lib/service/service.py (Apache-2.0).
msgraph imports are lazy, keeping the pure transforms standard-library-only.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import date, datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional
from uuid import UUID

_LOGGER = logging.getLogger("entra_graph")

# --------------------------------------------------------------------------- #
# Which Graph cloud to talk to
# --------------------------------------------------------------------------- #
#
# The Graph host is DERIVED from AZURE_AUTHORITY_HOST (already the declared
# sovereign-cloud selector) rather than a second knob that could disagree with the
# credential's authority. Hosts are the values of msgraph_core.NationalClouds.
GRAPH_HOST_GLOBAL = "https://graph.microsoft.com"

_AUTHORITY_TO_GRAPH_HOST = {
    "login.microsoftonline.com": GRAPH_HOST_GLOBAL,
    "login.microsoftonline.us": "https://graph.microsoft.us",
    "login.microsoftonline.de": "https://graph.microsoft.de",
    "login.chinacloudapi.cn": "https://microsoftgraph.chinacloudapi.cn",
    "login.partner.microsoftonline.cn": "https://microsoftgraph.chinacloudapi.cn",
}


def graph_host() -> str:
    """Graph host for the cloud the credential's authority points at.

    Falls back to the public cloud when AZURE_AUTHORITY_HOST is unset or unmapped —
    warning in the latter case, since silently collecting against the wrong cloud
    produces empty evidence that looks valid. GCC High (graph.microsoft.us) and DoD
    (dod-graph.microsoft.us) both authenticate against login.microsoftonline.us;
    GCC High is chosen as the far more common, so a DoD tenant is a known gap.
    """
    authority = (os.environ.get("AZURE_AUTHORITY_HOST") or "").strip()
    if not authority:
        return GRAPH_HOST_GLOBAL
    host = authority.replace("https://", "").replace("http://", "").strip("/").lower()
    mapped = _AUTHORITY_TO_GRAPH_HOST.get(host)
    if mapped is None:
        _LOGGER.warning(
            "AZURE_AUTHORITY_HOST %r is not a recognized sovereign authority; "
            "collecting against the public Graph host %s",
            authority,
            GRAPH_HOST_GLOBAL,
        )
        return GRAPH_HOST_GLOBAL
    return mapped


def graph_scope() -> str:
    """OAuth scope for the Graph host. Always `<host>/.default` for app auth."""
    return f"{graph_host()}/.default"


# --------------------------------------------------------------------------- #
# The Graph model boundary
# --------------------------------------------------------------------------- #

def graph_attr(model: Any, name: str) -> Any:
    """Read ONE attribute off a Graph (kiota) model, normalized to a plain value.

    The Graph analogue of `azure_common.model_attr()`; absent reads as None. Two
    normalizations the ARM models never need:

    - Graph enums are plain `Enum`s, NOT `str` subclasses, so
      `str(ConditionalAccessGrantControl.Mfa)` is "ConditionalAccessGrantControl.Mfa"
      — the source of a real bug in Prowler's conditional-access projection (see
      entra_conditional_access_policies/fetcher.py). Unwrapped to `.value` here.
    - kiota deserializes Graph timestamps into `datetime`, and
      `json.dump(default=str)` would write "2026-08-14 12:00:00+00:00" — neither the
      shape Graph sent nor one a validator regex written against the API matches.
      Rendered ISO-8601 with a `Z` instead; UUIDs render as their string form.
    """
    return _plain(getattr(model, name, None))


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        # Graph timestamps are UTC; "+00:00" is spelled "Z" on the wire.
        rendered = value.isoformat()
        return rendered[:-6] + "Z" if rendered.endswith("+00:00") else rendered
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def graph_list(model: Any, name: str) -> List[Any]:
    """Read a list-valued Graph attribute, normalizing each element.

    Graph omits empty collections rather than sending `[]`, so an absent list must
    read as `[]`, not None.
    """
    values = getattr(model, name, None) or []
    return [_plain(v) for v in values]


# --------------------------------------------------------------------------- #
# Client construction + async failure guarding
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def graph_service_client(cred):
    """A `GraphServiceClient` wired to the right Graph host, transport closed on exit.

    `GraphServiceClient(credentials, scopes=[...])` is NOT enough: `scopes` only
    reaches the OAuth token request while the httpx client keeps its default
    graph.microsoft.com base URL, so the host has to be set by building the request
    adapter — as Prowler does in `__set_clients__`. Closing the httpx client avoids
    leaking a connection pool and an "unclosed client" warning on the runner's stderr.
    """
    from kiota_authentication_azure.azure_identity_authentication_provider import (
        AzureIdentityAuthenticationProvider,
    )
    from msgraph import GraphServiceClient
    from msgraph.graph_request_adapter import GraphRequestAdapter
    from msgraph_core import GraphClientFactory

    scope, host = graph_scope(), graph_host()
    _LOGGER.info("Microsoft Graph: host=%s scope=%s", host, scope)
    # allowed_hosts is deliberately left at its default: kiota treats an empty
    # allow-list as "any host", which is what lets the sovereign hosts above work.
    auth_provider = AzureIdentityAuthenticationProvider(cred, scopes=[scope])
    http_client = GraphClientFactory.create_with_default_middleware(host=host)
    try:
        yield GraphServiceClient(
            request_adapter=GraphRequestAdapter(auth_provider, client=http_client)
        )
    finally:
        try:
            await http_client.aclose()
        except Exception as exc:  # noqa: BLE001 — closing must never fail the run
            _LOGGER.debug("closing the Graph transport raised %s", exc)


async def aguard(collector, operation: str, fn: Callable[[], Awaitable[Any]], default: Any = None):
    """`Collector.guard()` for a coroutine: record the failure, return `default`.

    `Collector.guard` would return the un-awaited coroutine — the call would appear
    to succeed and the evidence would contain a coroutine object.
    """
    try:
        return await fn()
    except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
        collector.record(operation, exc)
        return default


async def with_graph_client(collector, cred, work, default=None):
    """Build the Graph client, run `await work(client)`, always close the transport.

    Only construction- and transport-level failures land here; per-call failures are
    recorded by `aguard` inside `work`, so one denied endpoint doesn't erase the rest.
    """
    if cred is None:
        return default
    try:
        async with graph_service_client(cred) as client:
            return await work(client)
    except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash the run
        collector.record("msgraph.GraphServiceClient (init)", exc)
        return default


# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #

async def paginate(
    collector,
    operation: str,
    builder,
    request_configuration=None,
    page_limit: int = 1000,
) -> List[Any]:
    """Follow `@odata.nextLink` to the end and return every item.

    msgraph-sdk has no `ItemPaged` equivalent: `.get()` returns ONE page whose
    `odata_next_link` is the absolute URL of the next, re-issued through
    `builder.with_url(next_link).get()`. That link already carries the original
    `$select`/`$filter`, so the request configuration goes on the first call only.
    Prowler paginates by hand the same way.

    A failure part-way through is recorded and the items gathered so far returned, so
    a tenant that 429s on page 40 still yields 39 pages *and* a non-zero exit.
    `page_limit` is a runaway guard, not a paging cap: a server echoing the same
    nextLink back would otherwise loop forever inside the fetcher's timeout.
    """
    items: List[Any] = []
    try:
        response = await builder.get(request_configuration=request_configuration)
        pages = 0
        while response is not None:
            items.extend(getattr(response, "value", None) or [])
            next_link = getattr(response, "odata_next_link", None)
            pages += 1
            if not next_link:
                break
            if pages >= page_limit:
                collector.record(
                    operation,
                    RuntimeError(
                        f"stopped after {pages} pages with a nextLink still present; "
                        "refusing to keep paging"
                    ),
                )
                break
            response = await builder.with_url(next_link).get()
    except Exception as exc:  # noqa: BLE001 — boundary: record, keep what we have
        collector.record(operation, exc)
    return items


# --------------------------------------------------------------------------- #
# Tenant identity — the Graph fetchers' equivalent of `resolve_subscription`
# --------------------------------------------------------------------------- #

TENANT_UNRESOLVED = "unresolved"


async def resolve_tenant(collector, client) -> Dict[str, Any]:
    """Identify the tenant this Graph evidence came from — provenance, not evidence.

    `organization.get()` first (the authoritative answer, and the only source of the
    default verified domain), then AZURE_TENANT_ID. A failing `organization.get()`
    falls through WITHOUT being recorded as an API failure: `Organization.Read.All`
    can be absent from an app registration that still holds every permission the
    actual evidence needs. Only BOTH sources coming up empty is recorded — then the
    tenant genuinely is unknown, which does invalidate the evidence.
    """
    env_tenant = (os.environ.get("AZURE_TENANT_ID") or "").strip() or None

    org = None
    try:
        response = await client.organization.get()
        orgs = getattr(response, "value", None) or []
        org = orgs[0] if orgs else None
    except Exception as exc:  # noqa: BLE001 — provenance, not evidence: warn and fall back
        _LOGGER.warning(
            "organization.get() failed (%s: %s); falling back to AZURE_TENANT_ID for "
            "the tenant identity",
            type(exc).__name__,
            " ".join(str(exc).split())[:200],
        )

    if org is not None:
        domains = getattr(org, "verified_domains", None) or []
        default_domain = next(
            (graph_attr(d, "name") for d in domains if graph_attr(d, "is_default")),
            None,
        )
        return {
            "tenant_id": graph_attr(org, "id") or env_tenant,
            "tenant_name": graph_attr(org, "display_name"),
            "tenant_domain": default_domain
            or next((graph_attr(d, "name") for d in domains), None),
            "tenant_source": "organization",
        }

    if env_tenant:
        return {
            "tenant_id": env_tenant,
            "tenant_name": None,
            "tenant_domain": None,
            "tenant_source": "environment",
        }

    collector.record(
        "resolve_tenant",
        RuntimeError(
            "could not identify the tenant (organization.get() failed and "
            "AZURE_TENANT_ID is unset), so the collected evidence has no provenance"
        ),
    )
    return {
        "tenant_id": None,
        "tenant_name": None,
        "tenant_domain": None,
        "tenant_source": TENANT_UNRESOLVED,
    }


def tenant_payload(build_payload, *, tenant: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    """`azure_common.build_payload()` with the tenant added to its metadata block.

    The subscription fields are kept so Graph evidence can be correlated with the ARM
    evidence from the same manifest entry; they never scope the collection.
    """
    payload = build_payload(**kwargs)
    payload["metadata"].update(
        {
            "tenant_id": tenant.get("tenant_id"),
            "tenant_name": tenant.get("tenant_name"),
            "tenant_domain": tenant.get("tenant_domain"),
            "tenant_source": tenant.get("tenant_source"),
        }
    )
    return payload


def tenant_scoping() -> Dict[str, Optional[str]]:
    """What the runner told us about scoping, for the payload's metadata block.

    Graph data is tenant-wide, so `subscription_id` never narrows a query; it is
    still reported (`not_applicable` when absent) so the evidence says so plainly.
    """
    subscription_id = (os.environ.get("AZURE_SUBSCRIPTION_ID") or "").strip() or None
    return {
        "subscription_id": subscription_id,
        "subscription_source": "target_correlation_only" if subscription_id else "not_applicable",
    }


def tenant_filename_key(tenant: Dict[str, Any]) -> str:
    """The per-target discriminator for a Graph fetcher's output filename.

    The runner gives every target invocation the SAME `EVIDENCE_DIR` and works out
    what an invocation produced by diffing the directory listing, so two targets
    writing the same filename look like the second produced nothing. AZURE_TENANT_ID
    (what the target named) wins over the id from `organization.get()`, keeping the
    name stable on a run where the organization read was denied. `subscription_id`
    deliberately does not appear: in tenant-wide evidence it would imply a
    per-subscription scope that does not exist.
    """
    from azure_common import sanitize_for_filename

    key = (os.environ.get("AZURE_TENANT_ID") or "").strip() or tenant.get("tenant_id")
    return sanitize_for_filename(str(key) if key else "unknown")
