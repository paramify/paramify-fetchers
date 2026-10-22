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
