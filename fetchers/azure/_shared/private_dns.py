"""Private DNS zone pieces shared by the DNS and private DNS zone fetchers."""

from __future__ import annotations

from azure_common import basename, model_attr


def project_vnet_link(link) -> dict:
    """A private DNS zone's virtual network link: the VNet it resolves for and the link's state."""
    vnet_id = model_attr(model_attr(link, "virtual_network"), "id")
    return {
        "id": model_attr(link, "id"),
        "name": model_attr(link, "name"),
        "virtual_network_id": vnet_id,
        "virtual_network_name": basename(vnet_id),
        "registration_enabled": bool(model_attr(link, "registration_enabled") or False),
        "resolution_policy": model_attr(link, "resolution_policy"),
        "virtual_network_link_state": model_attr(link, "virtual_network_link_state"),
        "provisioning_state": model_attr(link, "provisioning_state"),
    }


def project_zone_group(group) -> dict:
    """A private endpoint's private DNS zone group: the zones it publishes the endpoint in, and the records it keeps there."""
    configs = []
    for cfg in model_attr(group, "private_dns_zone_configs") or []:
        zone_id = model_attr(cfg, "private_dns_zone_id")
        configs.append(
            {
                "private_dns_zone_id": zone_id,
                "private_dns_zone_name": basename(zone_id),
                "record_sets": [
                    {
                        "fqdn": model_attr(r, "fqdn"),
                        "record_type": model_attr(r, "record_type"),
                        "ip_addresses": model_attr(r, "ip_addresses") or [],
                        "provisioning_state": model_attr(r, "provisioning_state"),
                    }
                    for r in model_attr(cfg, "record_sets") or []
                ],
            }
        )
    return {
        "name": model_attr(group, "name"),
        "provisioning_state": model_attr(group, "provisioning_state"),
        "private_dns_zone_configs": configs,
    }
