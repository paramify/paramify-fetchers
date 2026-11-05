"""Which DDoS protection covers a public IP: its own IP Protection, or Network Protection from the plan on the virtual
network its resource sits in. Pure transforms over flat dicts, plus projections of the REST wire shape into them."""

from azure_common import arm_id_key, dig, vnet_id_of

ATTACHMENT_TYPES = {
    "networkinterfaces": "network_interface",
    "loadbalancers": "load_balancer",
    "bastionhosts": "bastion_host",
    "azurefirewalls": "azure_firewall",
    "virtualnetworkgateways": "virtual_network_gateway",
    "applicationgateways": "application_gateway",
}
NETWORK_PROTECTION = "network_protection"
IP_PROTECTION = "ip_protection"
EFFECTIVE_PROTECTION = (NETWORK_PROTECTION, IP_PROTECTION, "none", "disabled", "not_supported", "unknown")


def resource_of(child_id):
    """(attachment type, owning resource id) for an ARM child id such as an IP configuration."""
    parts = str(child_id or "").split("/")
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return None, None
    i = lowered.index("providers")
    if len(parts) < i + 4:
        return None, None
    return ATTACHMENT_TYPES.get(lowered[i + 2], "other"), "/".join(parts[: i + 4])


def attachment(ip: dict):
    if ip.get("ip_configuration_id"):
        return resource_of(ip["ip_configuration_id"])
    if ip.get("nat_gateway_id"):
        return "nat_gateway", ip["nat_gateway_id"]
    return "unattached", None


def _nic_of(config_id) -> str:
    """The NIC id of a NIC IP configuration id (VM or scale-set instance)."""
    key = arm_id_key(config_id)
    return key.rsplit("/ipconfigurations/", 1)[0] if "/networkinterfaces/" in key else ""


def vnet_by_resource(vnets: list[dict], nics: list[dict], load_balancers: list[dict] = ()) -> dict:
    """Lower-cased resource id -> lower-cased VNet id, from subnet back-references, NIC subnets, then a load
    balancer's backend pools (whose IP configurations or addresses must all sit in one VNet)."""
    index, by_config = {}, {}
    for vnet in vnets:
        for config_id in vnet.get("subnet_ip_configuration_ids") or []:
            by_config[arm_id_key(config_id)] = arm_id_key(vnet["id"])
            _, resource_id = resource_of(config_id)
            if resource_id:
                index.setdefault(arm_id_key(resource_id), arm_id_key(vnet["id"]))
    for nic in nics:
        vnet_ids = {vnet_id_of(s) for s in nic.get("subnet_ids") or [] if vnet_id_of(s)}
        if len(vnet_ids) == 1:
            index.setdefault(arm_id_key(nic["id"]), vnet_ids.pop())
    for lb in load_balancers:
        backends = {arm_id_key(v) for v in lb.get("backend_virtual_network_ids") or []}
        for config_id in lb.get("backend_ip_configuration_ids") or []:
            backends.add(by_config.get(arm_id_key(config_id)) or index.get(_nic_of(config_id)))
        if len(backends) == 1 and None not in backends:
            index.setdefault(arm_id_key(lb["id"]), backends.pop())
    return index


def vnet_has_plan(vnet) -> bool:
    return bool(vnet and vnet.get("enable_ddos_protection") and vnet.get("ddos_protection_plan_id"))


def effective_protection(ip: dict, attached_to: str, vnet) -> str:
    if attached_to == "nat_gateway":
        return "not_supported"
    mode = (ip.get("protection_mode") or "VirtualNetworkInherited").lower()
    if mode == "enabled":
        return IP_PROTECTION
    if mode == "disabled":
        return "disabled"
    if attached_to == "unattached":
        return "none"
    if vnet is None:
        return "unknown"
    return NETWORK_PROTECTION if vnet_has_plan(vnet) else "none"


# --- REST wire shape -> the flat dicts above ---

def _ref_ids(items) -> list:
    return [i["id"] for i in items or [] if isinstance(i, dict) and i.get("id")]


def rest_virtual_network(raw: dict) -> dict:
    props = raw.get("properties") or {}
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "enable_ddos_protection": props.get("enableDdosProtection"),
        "ddos_protection_plan_id": dig(props, "ddosProtectionPlan", "id"),
        "subnet_ip_configuration_ids": [
            i
            for s in props.get("subnets") or []
            for i in _ref_ids(dig(s, "properties", "ipConfigurations"))
            + _ref_ids(dig(s, "properties", "applicationGatewayIPConfigurations"))
        ],
    }


def rest_public_ip(raw: dict) -> dict:
    props = raw.get("properties") or {}
    return {
        "id": raw.get("id"),
        "ip_configuration_id": dig(props, "ipConfiguration", "id"),
        "nat_gateway_id": dig(props, "natGateway", "id"),
        "protection_mode": dig(props, "ddosSettings", "protectionMode"),
    }


def rest_network_interface(raw: dict) -> dict:
    return {
        "id": raw.get("id"),
        "subnet_ids": [dig(c, "properties", "subnet", "id") for c in dig(raw, "properties", "ipConfigurations") or []],
    }


def rest_load_balancer(raw: dict) -> dict:
    pools = dig(raw, "properties", "backendAddressPools") or []
    addresses = [a for p in pools for a in dig(p, "properties", "loadBalancerBackendAddresses") or []]
    return {
        "id": raw.get("id"),
        "backend_ip_configuration_ids": [i for p in pools for i in _ref_ids(dig(p, "properties", "backendIPConfigurations"))]
        + [i for a in addresses if (i := dig(a, "properties", "networkInterfaceIPConfiguration", "id"))],
        "backend_virtual_network_ids": [
            i for i in [
                *(dig(p, "properties", "virtualNetwork", "id") for p in pools),
                *(dig(a, "properties", "virtualNetwork", "id") for a in addresses),
                *(vnet_id_of(dig(a, "properties", "subnet", "id")) for a in addresses),
            ] if i
        ],
    }
