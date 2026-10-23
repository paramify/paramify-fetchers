#!/usr/bin/env python3
"""What a Splunk instance is configured to collect, and every host, index and sourcetype the deployment receives.

Advanced: matching data/inputs entries to inputs.conf stanzas depends on details of Splunk's REST encoding
that are only proven on Splunk Enterprise 10.4. Simplify it against a live instance before copying it.
"""

import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote, unquote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from splunk_client import (  # noqa: E402
    as_bool,
    as_int,
    iso,
    now_epoch,
    run,
    silence,
    to_epoch,
)

NAME = "splunk_data_inputs"
CAPABILITIES = ["search", "list_inputs", "rest_properties_get"]
CONFIG = {"max_silence_minutes": ("SPLUNK_MAX_SILENCE_MINUTES", 60), "indexes": ("SPLUNK_INDEXES", "")}

INPUTS = "servicesNS/-/-/data/inputs/all"
INPUT_STANZAS = "services/properties/inputs"
INPUTS_CONF = "servicesNS/-/-/configs/conf-inputs"
DEFAULT_INDEX = "services/properties/indexes/default/defaultDatabase"
# inputs.conf.spec forms written <type>:<value> rather than <type>://<value>.
SINGLE_COLON_TYPES = {"fschange", "tcp", "tcp-ssl", "udp", "splunktcp", "splunktcp-ssl", "remote_queue"}
NOT_INPUT_TYPES = {"splunktcptoken"}
# data/inputs collection -> inputs.conf types it lists; batch inputs are listed under monitor.
REST_TYPES = {"monitor": ["monitor", "batch"], "tcp/cooked": ["splunktcp", "splunktcp-ssl"],
              "tcp/raw": ["tcp", "tcp-ssl"], "tcp/ssl": ["SSL"]}
ALL_INDEXES = "index=* OR index=_*"
# Letters, digits, _ and -: a name from SPLUNK_INDEXES goes into SPL, so anything else (a wildcard too) is refused.
INDEX_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")


def received_spl(where):
    return ("| tstats count dc(source) as sources min(_time) as first_event max(_time) as last_event "
            f"max(_indextime) as last_indexed where {where} by host index sourcetype")


def received_check_spl(where):
    return f"| tstats dc(sourcetype) as sourcetypes where {where} by host index"


RECEIVED_SPL, RECEIVED_CHECK_SPL = received_spl(ALL_INDEXES), received_check_spl(ALL_INDEXES)


def input_type(stanza):
    """The input type of an inputs.conf stanza, or None for settings, deny lists, filters and type defaults."""
    if "://" in stanza:
        kind = stanza.split("://", 1)[0]
        return None if kind in NOT_INPUT_TYPES else kind
    kind, sep, _ = stanza.partition(":")
    return kind if sep and kind in SINGLE_COLON_TYPES else None


def stanza_of(entry, stanzas):
    c = entry["content"]
    collection = (c.get("eai:location") or "").replace("/data/inputs/", "", 1)
    # The id's last segment is the stanza value URL-encoded twice.
    value = unquote(unquote(entry["id"].rstrip("/").rsplit("/", 1)[-1])) if entry.get("name") else ""
    kinds = REST_TYPES.get(collection) or [k for k in (c.get("eai:type"), collection) if k]
    names = [f"{k}{sep}{value}" for k in kinds for sep in ("://", ":")] if value else kinds
    if input_type(value):
        names.insert(0, value)
    found = [n for n in dict.fromkeys(names) if n in stanzas]
    return found[0] if len(found) == 1 else None


def resolve_index(index, kind, content, default_index):
    if kind == "fschange" and as_bool(content.get("signedaudit")):
        return "_audit"
    # Forwarded data keeps the index its forwarder set; a receiver's index setting does not place it.
    if kind in ("splunktcp", "splunktcp-ssl"):
        return None
    return default_index if index in (None, "", "default") else index


def input_row(stanza, content, app, listed, collection, default_index, server_host):
    kind = input_type(stanza)
    index = content.get("index")
    host = content.get("host")
    return {
        "stanza": stanza,
        "type": kind,
        "enabled": not as_bool(content.get("disabled")),
        "index": index,
        "index_resolved": resolve_index(index, kind, content, default_index),
        "sourcetype": content.get("sourcetype") or None,
        "host": host,
        "host_resolved": content.get("host_resolved") if listed else (server_host if host == "$decideOnStartup" else host),
        "app": app,
        "listed_by_rest": listed,
        "rest_collection": collection,
    }


def conf_stanza(client, stanza):
    body = client.get(f"{INPUT_STANZAS}/{quote(stanza, safe='')}")
    return None if body is None else {e["name"]: e["content"] for e in body.get("entry", [])}


def collect_inputs(client, default_index, server_host):
    body = client.get(INPUT_STANZAS)
    entries = client.list(INPUTS)
    if body is None or entries is None:
        return None
    stanzas = {e["name"] for e in body.get("entry", [])}
    wanted = {s for s in stanzas if input_type(s)}
    rows, unmatched, settings = {}, [], []
    for e in entries:
        stanza = stanza_of(e, stanzas)
        if stanza is None or stanza in rows:
            unmatched.append(f"{e['content'].get('eai:location')}/{e['name']}")
        elif stanza not in wanted:
            settings.append(stanza)
        else:
            rows[stanza] = input_row(stanza, e["content"], (e.get("acl") or {}).get("app"), True,
                                     e["content"].get("eai:location"), default_index, server_host)
    if unmatched:
        client.fail(f"GET {INPUTS}", "IncompleteCollection",
                    f"data inputs matching no single inputs.conf stanza: {sorted(unmatched)}", "partial_failure")
    missing = sorted(wanted - set(rows))
    apps = {}
    if missing:
        conf = client.list(INPUTS_CONF) or []
        for c in conf:
            apps.setdefault(c["name"], set()).add((c.get("acl") or {}).get("app"))
    for stanza in missing:
        content = conf_stanza(client, stanza)
        if content is not None:
            defined_in = apps.get(stanza, set())
            app = next(iter(defined_in)) if len(defined_in) == 1 else None
            rows[stanza] = input_row(stanza, content, app, False, None, default_index, server_host)
    if len(rows) != len(wanted):
        return None
    return [rows[s] for s in sorted(rows, key=str.lower)], len(entries), sorted(settings)


def index_scope(client, raw):
    """The indexes named in SPLUNK_INDEXES, [] for every index, or None (recorded) when a name is not an index name."""
    names = sorted({n.strip() for n in raw.split(",") if n.strip()})
    invalid = [n for n in names if not INDEX_NAME.match(n)]
    if invalid:
        client.fail("config SPLUNK_INDEXES", "InvalidIndexName",
                    f"not index names (list each index; wildcards are not accepted): {invalid}", "bad_config")
        return None
    return names


def collect_received(client, window, scope):
    if scope:
        # The index list is not read: Splunk Cloud's REST API does not serve it. An index the token cannot search
        # answers like an empty one, so each named index must return events.
        where, indexes = " OR ".join(f"index={i}" for i in scope), []
    else:
        # A stream sent only to an index the token cannot search would be missing, so every index must be searchable.
        where, indexes = ALL_INDEXES, client.list_indexes(require_searchable=True)
    bound = str(int(now_epoch()))
    rows = client.search(received_spl(where), latest=bound)
    check = client.search(received_check_spl(where), latest=bound)
    if None in (indexes, rows, check):
        return None
    client.expect("host/index/sourcetype streams", len(rows), sum(as_int(r.get("sourcetypes")) or 0 for r in check))
    empty = sorted(set(scope) - {r["index"] for r in rows})
    if empty:
        client.fail("search | tstats", "NoEventsInIndex",
                    f"no events, or the token cannot search: {', '.join(empty)}", "partial_failure")
    now = now_epoch()
    out = []
    for r in sorted(rows, key=lambda r: (r["host"].lower(), r["index"], r["sourcetype"].lower())):
        last_indexed = to_epoch(r.get("last_indexed"))
        since, silent = silence(last_indexed, now, window)
        out.append({
            "host": r["host"],
            "index": r["index"],
            "internal": r["index"].startswith("_"),
            "sourcetype": r["sourcetype"],
            "event_count": as_int(r.get("count")) or 0,
            "source_count": as_int(r.get("sources")) or 0,
            "first_event": iso(to_epoch(r.get("first_event"))),
            "last_event": iso(to_epoch(r.get("last_event"))),
            "last_indexed": iso(last_indexed),
            "minutes_since_last_indexed": since,
            "max_silence_minutes": window,
            "silent": silent,
        })
    return out


def by_sourcetype(received):
    """One row per index and sourcetype, adding up its hosts' streams. Silent only when every host's stream is."""
    groups = {}
    for r in received:
        groups.setdefault((r["index"], r["sourcetype"]), []).append(r)
    out = []
    for (index, sourcetype), streams in groups.items():
        newest = max(streams, key=lambda r: r["last_indexed"] or "")
        out.append({
            "index": index,
            "internal": index.startswith("_"),
            "sourcetype": sourcetype,
            "event_count": sum(r["event_count"] for r in streams),
            "host_count": len(streams),
            "hosts_silent": sum(r["silent"] for r in streams),
            "first_event": min((r["first_event"] for r in streams if r["first_event"]), default=None),
            "last_event": max((r["last_event"] for r in streams if r["last_event"]), default=None),
            "last_indexed": newest["last_indexed"],
            "minutes_since_last_indexed": newest["minutes_since_last_indexed"],
            "max_silence_minutes": newest["max_silence_minutes"],
            "silent": all(r["silent"] for r in streams),
        })
    return sorted(out, key=lambda r: (r["index"], -r["event_count"], r["sourcetype"].lower()))


def summarize(inputs, rest_entries, settings, received, sourcetypes):
    return {
        "inputs_total": len(inputs),
        "inputs_enabled": sum(r["enabled"] for r in inputs),
        "inputs_by_type": dict(sorted(Counter(r["type"] for r in inputs).items())),
        "inputs_not_listed_by_rest": [r["stanza"] for r in inputs if not r["listed_by_rest"]],
        "rest_entries": rest_entries,
        "rest_settings_entries": settings,
        "received_streams": len(received),
        "received_streams_silent": sum(r["silent"] for r in received),
        "received_hosts": sorted({r["host"] for r in received}, key=str.lower),
        "received_indexes": sorted({r["index"] for r in received}),
        "received_sourcetypes": len({r["sourcetype"] for r in received}),
        "index_sourcetypes": len(sourcetypes),
        "index_sourcetypes_silent": sum(r["silent"] for r in sourcetypes),
    }


def collect(client, config):
    scope = index_scope(client, config["indexes"])
    if scope is None:
        return None
    default_index = (client.get_text(DEFAULT_INDEX) or "").strip() or None
    configured = collect_inputs(client, default_index, client.info.get("host"))
    received = collect_received(client, config["max_silence_minutes"], scope)
    if configured is None or received is None:
        return None
    inputs, rest_entries, settings = configured
    sourcetypes = by_sourcetype(received)
    return {
        "metadata": {"server_host": client.info.get("host"), "server_roles": client.info.get("server_roles", []),
                     "default_index": default_index, "indexes": scope or "all"},
        "summary": summarize(inputs, rest_entries, settings, received, sourcetypes),
        "inputs": inputs,
        "sourcetypes": sourcetypes,
        "received": received,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES, CONFIG))
