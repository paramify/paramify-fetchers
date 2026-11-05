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


def size(ranges):
    return sum(int(last) - int(first) + 1 for first, last in ranges)


def render(first, last):
    return str(first) if first == last else f"{first}-{last}"


def uncovered(ranges, host_ips):
    """Parts of `ranges` holding no host IP, as 'a-b' strings, and how many addresses that is."""
    gaps, count = [], 0
    sorted_ips = {v: sorted(int(ip) for ip in host_ips if ip.version == v) for v in (4, 6)}
    for first, last in sorted(ranges, key=lambda r: (r[0].version, int(r[0]))):
        ips = sorted_ips[first.version]
        inside = ips[bisect.bisect_left(ips, int(first)):bisect.bisect_right(ips, int(last))]
        cursor = int(first)
        for value in inside + [int(last) + 1]:
            if value > cursor:
                lo, hi = ipaddress.ip_address(cursor), ipaddress.ip_address(value - 1)
                gaps.append(render(lo, hi))
                count += value - cursor
            cursor = max(cursor, value + 1)
    return gaps, count


def collect(client, ledger, now):
    window = int_config("QUALYS_SCAN_WINDOW_DAYS", 30)
    hosts = [host_item(h, now, window) for h in client.records(
        HOST_PATH, {"action": "list", "details": "All", "show_tags": "0", "truncation_limit": PAGE_SIZE},
        "HOST", "list_hosts")]
    host_ips = set()
    for h in hosts:
        try:
            host_ips.add(ipaddress.ip_address(h["ip"]))
        except (TypeError, ValueError):
            pass

    gaps, gap_count, subscription_ips = None, None, None
    try:
        ranges = ip_ranges(client, IP_PATH, "list_ips")
        gaps, gap_count = uncovered(ranges, host_ips)
        subscription_ips = size(ranges)
    except QualysError as e:
        ledger.add(e)
    excluded, excluded_count = None, None
    try:
        excluded_ranges = ip_ranges(client, EXCLUDED_PATH, "list_excluded_ips")
        excluded, excluded_count = [render(a, b) for a, b in excluded_ranges], size(excluded_ranges)
    except QualysError as e:
        ledger.add(e)

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
        "subscription_ips": subscription_ips,
        "subscription_ips_without_host_record": gap_count,
        "excluded_ips": excluded_count,
    }
    body = {"hosts": hosts, "ips_without_host_record": gaps, "excluded_ip_ranges": excluded}
    return body, summary, len(hosts)


if __name__ == "__main__":
    raise SystemExit(run("qualys_scan_coverage", OUTPUT_FILE, collect))
