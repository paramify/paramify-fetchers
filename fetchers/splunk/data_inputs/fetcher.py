#!/usr/bin/env python3
"""Every data input configured on a Splunk instance, and every host, index and sourcetype the deployment actually receives."""

import logging
import os
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote, unquote

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
    truthy,
    write_evidence,
)

FETCHER = "splunk_data_inputs"
logger = logging.getLogger(FETCHER)

REQUIRED_CAPABILITIES = ["search", "list_inputs", "rest_properties_get"]
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
RECEIVED_SPL = ("| tstats count dc(source) as sources min(_time) as first_event max(_time) as last_event "
                "max(_indextime) as last_indexed where index=* OR index=_* by host index sourcetype")
RECEIVED_CHECK_SPL = "| tstats dc(sourcetype) as sourcetypes where index=* OR index=_* by host index"


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
    if kind == "fschange" and truthy(content.get("signedaudit")):
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
        "enabled": not truthy(content.get("disabled")),
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


def collect_received(client, window):
    searchable = client.searchable_indexes()
    index_entries = client.list_indexes(searchable)
    if index_entries is not None and searchable is not None:
        client.require_searchable_indexes([e["name"] for e in index_entries if not e["content"].get("disabled")],
                                          searchable)
    bound = str(int(now_epoch()))
    rows = client.search(RECEIVED_SPL, latest=bound)
    check = client.search(RECEIVED_CHECK_SPL, latest=bound)
    now = now_epoch()
    if rows is None:
        return None, now
    if check is not None:
        expected = sum(int(r.get("sourcetypes") or 0) for r in check)
        if expected != len(rows):
            client.fail("search " + RECEIVED_SPL, "IncompleteCollection",
                        f"collected {len(rows)} host/index/sourcetype rows, tstats dc(sourcetype) by host index "
                        f"sums to {expected}", "partial_failure")
    out = []
    for r in sorted(rows, key=lambda r: (r["host"].lower(), r["index"], r["sourcetype"].lower())):
        last_indexed = to_epoch(r.get("last_indexed"))
        since = minutes_since(last_indexed, now)
        out.append({
            "host": r["host"],
            "index": r["index"],
            "internal": r["index"].startswith("_"),
            "sourcetype": r["sourcetype"],
            "event_count": int(r.get("count") or 0),
            "source_count": int(r.get("sources") or 0),
            "first_event": iso(to_epoch(r.get("first_event"))),
            "last_event": iso(to_epoch(r.get("last_event"))),
            "last_indexed": iso(last_indexed),
            "minutes_since_last_indexed": since,
            "max_silence_minutes": window,
            "silent": since is None or since > window,
        })
    return out, now


def summarize(inputs, rest_entries, settings, received):
    s = {}
    if inputs is not None:
        s.update({
            "inputs_total": len(inputs),
            "inputs_enabled": sum(r["enabled"] for r in inputs),
            "inputs_not_listed_by_rest": [r["stanza"] for r in inputs if not r["listed_by_rest"]],
            "rest_entries": rest_entries,
            "rest_settings_entries": settings,
        })
    if received is not None:
        s.update({
            "received_streams": len(received),
            "received_streams_silent": sum(r["silent"] for r in received),
            "received_hosts": sorted({r["host"] for r in received}, key=str.lower),
            "received_sourcetypes": len({r["sourcetype"] for r in received}),
        })
    if inputs is not None:
        s["inputs_by_type"] = dict(sorted(Counter(r["type"] for r in inputs).items()))
    return s


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = target_from_env()
        window = env_int("SPLUNK_MAX_SILENCE_MINUTES", 60)
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = SplunkClient(target["base_url"], target["token"], target["verify_ssl"])
    info = client.get("services/server/info")
    server = info["entry"][0]["content"] if info else {}
    inputs = received = settings = rest_entries = judged_at = default_index = None
    if client.require_capabilities(REQUIRED_CAPABILITIES):
        default_index = client.get_text(DEFAULT_INDEX)
        default_index = default_index.strip() if default_index else None
        result = collect_inputs(client, default_index, server.get("host"))
        if result is not None:
            inputs, rest_entries, settings = result
        received, judged_at = collect_received(client, window)

    evidence = {
        "metadata": {
            "collected_at": iso(judged_at or now_epoch()),
            "target": target["name"],
            "base_url": target["base_url"],
            "splunk_version": server.get("version"),
            "server_host": server.get("host"),
            "server_roles": server.get("server_roles", []),
            "default_index": default_index,
            "max_silence_minutes": window,
            **client.failure_metadata(),
        },
        "summary": summarize(inputs, rest_entries, settings, received),
        "inputs": inputs or [],
        "received": received or [],
    }
    return finish(logger, write_evidence(FETCHER, target["name"], evidence), client)


if __name__ == "__main__":
    sys.exit(main())
