#!/usr/bin/env python3
"""Whether the hosts and forwarders that send data to Splunk are still sending."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from splunk_client import as_int, iso, now_epoch, run, silence, to_epoch  # noqa: E402

NAME = "splunk_log_source_freshness"
CAPABILITIES = ["search", "rest_properties_get"]
CONFIG = {"max_silence_minutes": ("SPLUNK_MAX_SILENCE_MINUTES", 60),
          "forwarder_lookback_days": ("SPLUNK_FORWARDER_LOOKBACK_DAYS", 30)}

# Every host with events in any index, and when Splunk last received data from it.
HOSTS_SPL = ("| tstats count min(_time) as first_event max(_time) as last_event "
             "max(_indextime) as last_indexed where index=* OR index=_* by host")
HOST_COUNT_SPL = "| tstats dc(host) as hosts where index=* OR index=_*"
# Every forwarder that connected over the lookback, from the receiver's own metrics.
FORWARDERS_SPL = ("search index=_internal source=*metrics.log group=tcpin_connections "
                  "| stats max(_time) as last_connected latest(fwdType) as fwd_type "
                  "latest(version) as version latest(sourceIp) as source_ip by hostname")


def host_row(r, now, window):
    last_indexed = to_epoch(r.get("last_indexed"))
    minutes, silent = silence(last_indexed, now, window)
    return {
        "host": r.get("host"),
        "event_count": as_int(r.get("count")) or 0,
        "first_event": iso(to_epoch(r.get("first_event"))),
        "last_event": iso(to_epoch(r.get("last_event"))),
        "last_indexed": iso(last_indexed),
        "minutes_since_last_indexed": minutes,
        "max_silence_minutes": window,
        "silent": silent,
    }


def forwarder_row(r, now, window):
    last_connected = to_epoch(r.get("last_connected"))
    minutes, silent = silence(last_connected, now, window)
    return {
        "hostname": r.get("hostname"),
        "fwd_type": r.get("fwd_type"),
        "version": r.get("version"),
        "source_ip": r.get("source_ip"),
        "last_connected": iso(last_connected),
        "minutes_since_last_connected": minutes,
        "max_silence_minutes": window,
        "silent": silent,
    }


def collect(client, config):
    window = config["max_silence_minutes"]
    # A host that sends only to an index the token cannot search would be missing, so every index must be searchable.
    indexes = client.list_indexes(require_searchable=True)
    hosts = client.search(HOSTS_SPL)
    host_count = client.search(HOST_COUNT_SPL)
    forwarders = client.search(FORWARDERS_SPL, earliest=f"-{config['forwarder_lookback_days']}d")
    if None in (indexes, hosts, host_count, forwarders):
        return None
    client.expect("hosts", len(hosts), as_int(host_count[0].get("hosts")) if host_count else 0)
    now = now_epoch()
    host_rows = [host_row(r, now, window) for r in sorted(hosts, key=lambda r: str(r.get("host")).lower())]
    forwarder_rows = [forwarder_row(r, now, window)
                      for r in sorted(forwarders, key=lambda r: str(r.get("hostname")).lower())]
    return {
        "summary": {
            "hosts_total": len(host_rows),
            "hosts_silent": sum(h["silent"] for h in host_rows),
            "forwarders_total": len(forwarder_rows),
            "forwarders_silent": sum(f["silent"] for f in forwarder_rows),
        },
        "hosts": host_rows,
        "forwarders": forwarder_rows,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES, CONFIG))
