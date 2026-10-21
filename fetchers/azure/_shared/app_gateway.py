"""Application Gateway listing, completeness check, ARM-id joins and run loop for the app_gateway_* fetchers."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from azure_common import (
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from dotenv import load_dotenv

GATEWAY_TYPE = "microsoft.network/applicationgateways"
# Resource Graph can lag list_all by minutes around a create or delete.
RECOUNT_DELAY_SECONDS = 30
ENCRYPTED_PROTOCOLS = ("Https", "Tls")


def arm_id_key(resource_id: Optional[str]) -> str:
    """ARM ids are case-insensitive and Azure does not keep one spelling."""
    return str(resource_id or "").lower()


def ref_id(model: Any, name: str) -> Optional[str]:
    """Id of a SubResource reference attribute, or None."""
    return model_attr(model_attr(model, name), "id")


def enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def index_by_id(items: Any) -> Dict[str, Any]:
    return {arm_id_key(model_attr(i, "id")): i for i in (items or []) if model_attr(i, "id")}


def gateway_identity(gateway: Any) -> Dict[str, Any]:
    """The per-gateway fields every app_gateway_* record starts with."""
    resource_id = model_attr(gateway, "id")
    sku = model_attr(gateway, "sku")
    return {
        "id": resource_id,
        "name": model_attr(gateway, "name"),
        "resource_group": resource_group_from_id(resource_id),
        "location": model_attr(gateway, "location"),
        "sku_name": model_attr(sku, "name"),
        "sku_tier": model_attr(sku, "tier"),
        "operational_state": model_attr(gateway, "operational_state"),
        "provisioning_state": model_attr(gateway, "provisioning_state"),
    }


def frontend_ports(gateway: Any) -> Dict[str, Optional[int]]:
    return {k: model_attr(p, "port") for k, p in index_by_id(model_attr(gateway, "frontend_ports")).items()}


def frontend_ip_types(gateway: Any) -> Dict[str, str]:
    """Frontend IP config id -> "public" when it carries a public IP, else "private"."""
    return {
        k: "public" if ref_id(c, "public_ip_address") else "private"
        for k, c in index_by_id(model_attr(gateway, "frontend_ip_configurations")).items()
    }


def rules_by_listener(gateway: Any) -> Dict[str, List[Any]]:
    """Listener id -> its L7 request routing rules and L4 routing rules."""
    rules: Dict[str, List[Any]] = {}
    for rule in model_attr(gateway, "request_routing_rules") or []:
        rules.setdefault(arm_id_key(ref_id(rule, "http_listener")), []).append(rule)
    for rule in model_attr(gateway, "routing_rules") or []:
        rules.setdefault(arm_id_key(ref_id(rule, "listener")), []).append(rule)
    return rules


def list_gateways(subscription_id: str, cred: Any, collector: Collector) -> Optional[List[Any]]:
    """Every gateway in the subscription; ItemPaged follows nextLink. None if the call failed."""

    def _list() -> List[Any]:
        from azure.mgmt.network import NetworkManagementClient  # lazy

        client = NetworkManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )
        return list(client.application_gateways.list_all())

    return collector.guard("network.application_gateways.list_all", _list)


def resource_graph_gateway_count(subscription_id: str, cred: Any, collector: Collector) -> Optional[int]:
    """The subscription's gateway count from Resource Graph, a path independent of list_all."""

    def _count() -> int:
        from azure.mgmt.resourcegraph import ResourceGraphClient  # lazy
        from azure.mgmt.resourcegraph.models import (  # lazy
            QueryRequest,
            QueryRequestOptions,
        )

        client = ResourceGraphClient(credential=cred, **arm_client_kwargs())
        response = client.resources(
            QueryRequest(
                subscriptions=[subscription_id],
                query=f"resources | where type =~ '{GATEWAY_TYPE}' | count",
                options=QueryRequestOptions(result_format="objectArray"),
            )
        )
        rows = model_attr(response, "data") or []
        return int(rows[0]["Count"]) if rows else 0

    return collector.guard("resourcegraph.resources (application gateway count)", _count)


def completeness(
    listed: Optional[int], true_count: Optional[int], collector: Collector, recounted: bool = False
) -> Dict[str, Any]:
    """Compare the listed count to the independent one; a mismatch is a collection failure."""
    match = None if listed is None or true_count is None else listed == true_count
    if match is False:
        collector.record(
            "completeness (application_gateways.list_all vs Resource Graph)",
            RuntimeError(
                f"list_all returned {listed} application gateways but Resource Graph "
                f"counts {true_count} in the subscription"
            ),
        )
    return {"listed": listed, "resource_graph_count": true_count, "match": match, "recounted": recounted}


def collect_gateways(
    subscription_id: str, cred: Any, collector: Collector, logger: logging.Logger, sleep: Callable[[float], None] = time.sleep
) -> Tuple[Optional[List[Any]], Dict[str, Any]]:
    """List the gateways and check the count, listing and counting once more after a delay on a mismatch."""
    raw = list_gateways(subscription_id, cred, collector)
    true_count = resource_graph_gateway_count(subscription_id, cred, collector)
    recounted = raw is not None and true_count is not None and len(raw) != true_count
    if recounted:
        logger.warning(
            "list_all returned %d gateways, Resource Graph counts %d; recounting in %ds",
            len(raw), true_count, RECOUNT_DELAY_SECONDS,
        )
        sleep(RECOUNT_DELAY_SECONDS)
        raw = list_gateways(subscription_id, cred, collector)
        true_count = resource_graph_gateway_count(subscription_id, cred, collector)
    return raw, completeness(None if raw is None else len(raw), true_count, collector, recounted)


Build = Callable[[List[Any], Collector, Optional[str], Any], Tuple[Dict[str, Any], Dict[str, Any]]]


def run_fetcher(name: str, logger: logging.Logger, build: Build) -> int:
    """List the subscription's gateways, hand them to `build`, write the evidence, exit 0/1."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    gateways: List[Any] = []
    coverage: Dict[str, Any] = {"listed": None, "resource_graph_count": None, "match": None, "recounted": False}
    registration = REGISTRATION_UNKNOWN
    live = bool(subscription_id and cred is not None)
    if live:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Network is not registered on subscription %s", subscription_id)
        raw, coverage = collect_gateways(subscription_id, cred, collector, logger)
        gateways = raw or []
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    results, summary = build(gateways, collector, subscription_id if live else None, cred if live else None)
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={**results, "completeness": coverage, "provider_registration_status": registration},
        summary={**summary, "completeness_match": coverage["match"], "provider_registration_status": registration},
    )
    path = write_evidence(output_dir, f"{name}_{sanitize_for_filename(subscription_id or 'unknown')}.json", evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0
