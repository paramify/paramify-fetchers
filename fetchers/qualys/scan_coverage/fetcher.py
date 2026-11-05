#!/usr/bin/env python3
"""Qualys scan coverage: last scan and last authenticated scan per host, and subscription IPs with no host record."""

import bisect
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from qualys_client import QualysError, text  # noqa: E402
from qualys_evidence import (  # noqa: E402
    NOT_RETURNED,
    PAGE_SIZE,
    days_between,
    host_identity,
    int_config,
    parse_time,
    run,
)

OUTPUT_FILE = "qualys_scan_coverage.json"
HOST_PATH = "/api/5.0/fo/asset/host/"
IP_PATH = "/api/2.0/fo/asset/ip/"
EXCLUDED_PATH = "/api/2.0/fo/asset/excluded_ip/"
IP_TAGS = ("IP", "IP_RANGE", "IPV6", "IPV6_RANGE")
TRACKING_KEYS = ("ip", "dns", "netbios", "cloud_agent", "cloud_instance", "other", NOT_RETURNED)


def tracking_key(method):
    m = (method or "").strip().lower()
    if not m:
        return NOT_RETURNED
    if m in ("ip", "dns", "netbios"):
        return m
    if "agent" in m:
        return "cloud_agent"
    if any(k in m for k in ("ec2", "azure", "gcp", "oci", "instance")):
        return "cloud_instance"
    return "other"


def latest(*values):
    parsed = [p for p in (parse_time(v) for v in values) if p is not None]
    return max(parsed) if parsed else None


def host_item(host, now, window):
    vm_raw = (text(host, "LAST_VM_SCANNED_DATE"), text(host, "LAST_VULN_SCAN_DATETIME"))
    auth_raw = text(host, "LAST_VM_AUTH_SCANNED_DATE")
    vm_at, auth_at = latest(*vm_raw), parse_time(auth_raw)
    vm_days, auth_days = days_between(vm_at, now), days_between(auth_at, now)
    return {
        **host_identity(host),
        "ipv6": text(host, "IPV6"),
        "last_vm_scanned_date": vm_raw[0],
        "last_vuln_scan_datetime": vm_raw[1],
        "last_vm_auth_scanned_date": auth_raw,
        "days_since_vm_scan": vm_days,
        "days_since_auth_scan": auth_days,
        "has_vm_scan_date": any(vm_raw),
        "scan_date_readable": vm_at is not None or not any(vm_raw),
        "has_auth_scan_date": auth_raw is not None,
        "auth_date_readable": auth_at is not None or auth_raw is None,
        "scanned_within_window": None if vm_at is None and any(vm_raw) else vm_days is not None and vm_days <= window,
        "auth_scanned_within_window": None if auth_at is None and auth_raw else auth_days is not None and auth_days <= window,
    }


def ip_ranges(client, path, operation):
    """(start, end) ip_address pairs from an IP_SET of IP and IP_RANGE elements."""
    ranges = []
    for elem in client.records(path, {"action": "list"}, IP_TAGS, operation):
        value = (elem.text or "").strip()
        if not value:
            continue
        start, _, end = value.partition("-")
        try:
            first = ipaddress.ip_address(start.strip())
            last = ipaddress.ip_address(end.strip()) if end else first
        except ValueError as e:
            raise QualysError(f"{operation}: unreadable address {value!r}", "internal_error", operation) from e
        ranges.append((first, last) if first <= last else (last, first))
    return ranges


def render(first, last):
    return str(first) if first == last else f"{first}-{last}"


def intervals(ranges, version):
    """Sorted, merged (lo, hi) integer intervals of one IP version."""
    merged = []
    for lo, hi in sorted((int(a), int(b)) for a, b in ranges if a.version == version):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def subtract(spans, removed):
    """Parts of `spans` outside `removed`; both sorted and merged."""
    out = []
    for lo, hi in spans:
        cursor = lo
        for rlo, rhi in removed:
            if rhi < cursor or rlo > hi:
                continue
            if rlo > cursor:
                out.append((cursor, rlo - 1))
            cursor = max(cursor, rhi + 1)
        if cursor <= hi:
            out.append((cursor, hi))
    return out


def without_host(spans, host_values):
    """Parts of `spans` holding none of the sorted `host_values`."""
    out = []
    for lo, hi in spans:
        cursor = lo
        for value in host_values[bisect.bisect_left(host_values, lo):bisect.bisect_right(host_values, hi)] + [hi + 1]:
            if value > cursor:
                out.append((cursor, value - 1))
            cursor = max(cursor, value + 1)
    return out


def ip_coverage(ranges, excluded, host_ips):
    """IPv4 counted by address, IPv6 by range, so no count can exceed 2^53; excluded ranges are not gaps."""
    hosts = {v: sorted(int(ip) for ip in host_ips if ip.version == v) for v in (4, 6)}
    v4 = intervals(ranges, 4)
    v6 = sorted({(a, b) for a, b in ranges if a.version == 6})
    result = {
        "subscription_ipv4_addresses": sum(hi - lo + 1 for lo, hi in v4),
        "subscription_ipv6_ranges": len(v6),
        "ipv4_without_host": None,
        "ipv6_without_host": None,
    }
    if excluded is not None:
        open_v4 = subtract(v4, intervals(excluded, 4))
        result["ipv4_without_host"] = [(ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi))
                                       for lo, hi in without_host(open_v4, hosts[4])]
        excluded_v6, v6_gaps = intervals(excluded, 6), []
        for a, b in v6:
            open_v6 = subtract([(int(a), int(b))], excluded_v6)
            if open_v6 and without_host(open_v6, hosts[6]) == open_v6:
                v6_gaps.append((a, b))
        result["ipv6_without_host"] = v6_gaps
    return result


def collect(client, ledger, now):
    window = int_config("QUALYS_SCAN_WINDOW_DAYS", 31)
    hosts = [host_item(h, now, window) for h in client.records(
        HOST_PATH, {"action": "list", "details": "All", "show_tags": "0", "truncation_limit": PAGE_SIZE},
        "HOST", "list_hosts")]
    host_ips = set()
    for h in hosts:
        for value in (h["ip"], h["ipv6"]):
            try:
                host_ips.add(ipaddress.ip_address(value))
            except (TypeError, ValueError):
                pass

    ranges = None
    try:
        ranges = ip_ranges(client, IP_PATH, "list_ips")
    except QualysError as e:
        ledger.add(e)
    excluded_ranges = None
    try:
        excluded_ranges = ip_ranges(client, EXCLUDED_PATH, "list_excluded_ips")
    except QualysError as e:
        ledger.add(e)
    ips = {"subscription_ipv4_addresses": None, "subscription_ipv6_ranges": None,
           "ipv4_without_host": None, "ipv6_without_host": None}
    if ranges is not None:
        ips = ip_coverage(ranges, excluded_ranges, host_ips)
    v4_gaps, v6_gaps = ips["ipv4_without_host"], ips["ipv6_without_host"]

    by_method = {key: 0 for key in TRACKING_KEYS}
    for h in hosts:
        by_method[tracking_key(h["tracking_method"])] += 1
    vm_days = [h["days_since_vm_scan"] for h in hosts if h["days_since_vm_scan"] is not None]
    summary = {
        "total_hosts": len(hosts),
        "hosts_by_tracking_method": by_method,
        "scan_window_days": window,
        "hosts_scanned_within_window": sum(1 for h in hosts if h["scanned_within_window"] is True),
        "hosts_not_scanned_within_window": sum(1 for h in hosts if h["scanned_within_window"] is False),
        "hosts_without_vm_scan_date": sum(1 for h in hosts if not h["has_vm_scan_date"]),
        "hosts_scan_date_unreadable": sum(1 for h in hosts if not h["scan_date_readable"]),
        "max_days_since_vm_scan": max(vm_days) if vm_days else None,
        "hosts_auth_scanned_within_window": sum(1 for h in hosts if h["auth_scanned_within_window"] is True),
        "hosts_auth_scan_older_than_window": sum(
            1 for h in hosts if h["has_auth_scan_date"] and h["auth_scanned_within_window"] is False),
        "hosts_never_auth_scanned": sum(1 for h in hosts if not h["has_auth_scan_date"]),
        "hosts_auth_date_unreadable": sum(1 for h in hosts if not h["auth_date_readable"]),
        "subscription_ipv4_addresses": ips["subscription_ipv4_addresses"],
        "subscription_ipv4_addresses_without_host_record":
            None if v4_gaps is None else sum(int(b) - int(a) + 1 for a, b in v4_gaps),
        "subscription_ipv6_ranges": ips["subscription_ipv6_ranges"],
        "subscription_ipv6_ranges_without_host_record": None if v6_gaps is None else len(v6_gaps),
        "excluded_ipv4_addresses": None if excluded_ranges is None else sum(
            hi - lo + 1 for lo, hi in intervals(excluded_ranges, 4)),
        "excluded_ipv6_ranges": None if excluded_ranges is None else len(
            {(a, b) for a, b in excluded_ranges if a.version == 6}),
    }
    body = {
        "hosts": hosts,
        "ipv4_ranges_without_host_record": None if v4_gaps is None else [render(a, b) for a, b in v4_gaps],
        "ipv6_ranges_without_host_record": None if v6_gaps is None else [render(a, b) for a, b in v6_gaps],
        "excluded_ip_ranges": None if excluded_ranges is None else [render(a, b) for a, b in excluded_ranges],
    }
    return body, summary, len(hosts)


if __name__ == "__main__":
    raise SystemExit(run("qualys_scan_coverage", OUTPUT_FILE, collect))
