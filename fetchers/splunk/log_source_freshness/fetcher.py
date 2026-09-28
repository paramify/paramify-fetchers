#!/usr/bin/env python3
"""Splunk hosts and forwarders, with when each last delivered data and whether it has gone silent."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from splunk_client import (  # noqa: E402
    SplunkClient,
    env_int,
    finish,
    iso,
    minutes_since,
    now_epoch,
    report_failure,
    target_from_env,
    to_epoch,
    write_evidence,
)

FETCHER = "splunk_log_source_freshness"
logger = logging.getLogger(FETCHER)

HOSTS_SPL = ("| tstats count min(_time) as first_event max(_time) as last_event "
             "max(_indextime) as last_indexed where index=* OR index=_* by host")
HOST_COUNT_SPL = "| tstats dc(host) as hosts where index=* OR index=_*"
FORWARDERS_SPL = ("search index=_internal source=*metrics.log group=tcpin_connections "
                  "| stats max(_time) as last_connected latest(fwdType) as fwd_type "
                  "latest(version) as version latest(sourceIp) as source_ip by hostname")
SEARCHABLE_INDEXES_SPL = "| eventcount summarize=false index=* index=_* | stats values(index) as indexes"


def judge(epoch, now, window):
    since = minutes_since(epoch, now)
    return {"minutes_since": since, "max_silence_minutes": window, "silent": since is None or since > window}


def collect_hosts(client, now, window):
    rows = client.search(HOSTS_SPL)
    if rows is None:
        return None
    count = client.search(HOST_COUNT_SPL)
    if count is not None:
        true_count = int(count[0]["hosts"]) if count else 0
        if true_count != len(rows):
            client.fail("search " + HOSTS_SPL, "IncompleteCollection",
                        f"collected {len(rows)} hosts, tstats dc(host) reports {true_count}", "partial_failure")
    hosts = []
    for r in sorted(rows, key=lambda r: r["host"].lower()):
        last_indexed = to_epoch(r.get("last_indexed"))
        verdict = judge(last_indexed, now, window)
        hosts.append({
            "host": r["host"],
            "event_count": int(r.get("count") or 0),
            "first_event": iso(to_epoch(r.get("first_event"))),
            "last_event": iso(to_epoch(r.get("last_event"))),
            "last_indexed": iso(last_indexed),
            "minutes_since_last_indexed": verdict["minutes_since"],
            "max_silence_minutes": window,
            "silent": verdict["silent"],
        })
    return hosts


def collect_forwarders(client, now, window, lookback_days):
    rows = client.search(FORWARDERS_SPL, earliest=f"-{lookback_days}d")
    if rows is None:
        return None
    forwarders = []
    for r in sorted(rows, key=lambda r: r["hostname"].lower()):
        last = to_epoch(r.get("last_connected"))
        verdict = judge(last, now, window)
        forwarders.append({
            "hostname": r["hostname"],
            "fwd_type": r.get("fwd_type"),
            "version": r.get("version"),
            "source_ip": r.get("source_ip"),
            "last_connected": iso(last),
            "minutes_since_last_connected": verdict["minutes_since"],
            "max_silence_minutes": window,
            "silent": verdict["silent"],
        })
    return forwarders


def check_index_visibility(client):
    """Searchable indexes must equal enabled indexes, or hosts sending only to a hidden index go unseen."""
    entries = client.list("services/data/indexes", datatype="all")
    rows = client.search(SEARCHABLE_INDEXES_SPL)
    if entries is None or rows is None:
        return None
    enabled = {e["name"] for e in entries if not e["content"].get("disabled")}
    values = rows[0].get("indexes", []) if rows else []
    searchable = set([values] if isinstance(values, str) else values)
    hidden, unlisted = sorted(enabled - searchable), sorted(searchable - enabled)
    if hidden or unlisted:
        client.fail("search " + SEARCHABLE_INDEXES_SPL, "IncompleteCollection",
                    f"enabled indexes the token cannot search: {hidden}; searchable but not listed: {unlisted}",
                    "not_authorized")
    return {"enabled_indexes": len(enabled), "searchable_indexes": len(searchable),
            "unsearchable_indexes": hidden}


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = target_from_env()
        window = env_int("SPLUNK_MAX_SILENCE_MINUTES", 60)
        lookback_days = env_int("SPLUNK_FORWARDER_LOOKBACK_DAYS", 30)
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = SplunkClient(target["base_url"], target["token"], target["verify_ssl"])
    now = now_epoch()
    hosts = forwarders = visibility = None
    version = client.server_version()
    if client.require_capabilities(["search"]):
        visibility = check_index_visibility(client)
        hosts = collect_hosts(client, now, window)
        forwarders = collect_forwarders(client, now, window, lookback_days)

    evidence = {
        "metadata": {
            "collected_at": iso(now),
            "target": target["name"],
            "base_url": target["base_url"],
            "splunk_version": version,
            "max_silence_minutes": window,
            "forwarder_lookback_days": lookback_days,
            **client.failure_metadata(),
        },
        "summary": {
            "hosts_total": len(hosts or []),
            "hosts_silent": sum(h["silent"] for h in hosts or []),
            "forwarders_total": len(forwarders or []),
            "forwarders_silent": sum(f["silent"] for f in forwarders or []),
            **(visibility or {}),
        },
        "hosts": hosts or [],
        "forwarders": forwarders or [],
    }
    return finish(logger, write_evidence(FETCHER, target["name"], evidence), client)


if __name__ == "__main__":
    sys.exit(main())
