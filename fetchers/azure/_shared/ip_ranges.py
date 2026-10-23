"""IPv4 firewall-range width: how many distinct addresses a set of start/end rules admits together."""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Tuple

IPV4_ADDRESSES = 2**32
# Wider than a /8 is "broad": no single organisation's egress needs a range that size.
BROAD_ADDRESS_COUNT = 2**24


def ipv4_range(start, end) -> Optional[Tuple[int, int]]:
    """(first, last) as integers, or None for an unparseable or reversed range."""
    try:
        first, last = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
    except (ipaddress.AddressValueError, TypeError, ValueError):
        return None
    return (first, last) if last >= first else None


def cidr_range(text) -> Optional[Tuple[int, int]]:
    """(first, last) for an IPv4 address or CIDR ("10.0.0.0/8", "1.2.3.4"); None for IPv6 or unparseable."""
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except (TypeError, ValueError):
        return None
    if net.version != 4:
        return None
    return int(net.network_address), int(net.broadcast_address)


def cidrs_allow_all(entries) -> bool:
    """True when the IPv4 addresses/CIDRs together admit every IPv4 address (e.g. 0.0.0.0/0)."""
    return union_address_count(cidr_range(e) for e in entries or []) >= IPV4_ADDRESSES


def union_address_count(ranges: Iterable[Optional[Tuple[int, int]]]) -> int:
    """Distinct addresses covered by the ranges together, overlaps merged."""
    covered, end = 0, -1
    for first, last in sorted(r for r in ranges if r):
        if last > end:
            covered += last - max(first, end + 1) + 1
            end = last
    return covered


def coverage_percentage(count: int) -> float:
    return round(count * 100 / IPV4_ADDRESSES, 4)
